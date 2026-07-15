"""Collector package. `observe(name)` wraps a collector body with the
self-observability the monolith applied to each collector inline: duration,
last-successful timestamp, scrape-error counter, and a consecutive-failure gauge.
It swallows exceptions so one failing collector can't abort the whole poll cycle,
but publishes the per-attempt outcome for the scheduler. It is the single source
of truth for failure counts and success/failure state.

Collectors raise CollectorFailed when a primary API call returns no data, so an
unreachable endpoint counts as a failure (and does NOT bump last_successful_scrape)
rather than masquerading as a healthy scrape."""
import logging
import time
from contextlib import contextmanager

from .. import metrics
from ..snapshots import (
    commit_metric_snapshots,
    snapshot_lock,
    stage_metric_snapshots,
)

logger = logging.getLogger(__name__)
_failures = {}
_outcomes = {}
_failure_reasons = {}


def source(name):
    if name.startswith("dataconnect_") or name == "tacacs_activity":
        return "dataconnect"
    if name.startswith("mnt_"):
        return "mnt"
    return "rest"


class CollectorFailed(Exception):
    """Raised by a collector when a primary API call yields no usable data."""

    def __init__(self, message, *, reason="no_data"):
        super().__init__(message)
        self.reason = reason


def failures(name):
    return _failures.get(name, 0)


def begin_attempt(name):
    """Clear the prior result so the scheduler can observe this attempt only."""
    _outcomes[name] = None


def outcome(name):
    """Return True/False for an observed attempt, or None for an unwrapped callback."""
    return _outcomes.get(name)


def record_failure(name, error_type):
    """Bump the scrape-error counter + consecutive-failure gauge for a failed collect."""
    with snapshot_lock:
        metrics.ise_scrape_errors_total.labels(
            collector=name, error_type=error_type).inc()
        _failures[name] = _failures.get(name, 0) + 1
        metrics.ise_consecutive_failures.labels(
            collector=name).set(_failures[name])
        dataset_source = source(name)
        previous_reason = _failure_reasons.get(name)
        if previous_reason and previous_reason != error_type:
            metrics.ise_dataset_last_failure_info.remove(
                name, dataset_source, previous_reason)
        metrics.ise_dataset_last_failure_info.labels(
            dataset=name, source=dataset_source, reason=error_type).set(1)
        _failure_reasons[name] = error_type
        _outcomes[name] = False
        metrics.ise_dataset_up.labels(
            dataset=name, source=dataset_source).set(0)


@contextmanager
def observe(name):
    # Wall clock is required for exported completion timestamps, but elapsed
    # duration must not go negative when NTP corrects the system clock.
    start = time.monotonic()
    with stage_metric_snapshots() as replacements:
        try:
            yield
            completed = time.time()
            dataset_source = source(name)
            previous_reason = _failure_reasons.get(name)

            def publish_success():
                metrics.ise_last_successful_scrape.labels(
                    collector=name).set(completed)
                metrics.ise_dataset_up.labels(
                    dataset=name, source=dataset_source).set(1)
                metrics.ise_dataset_fresh.labels(
                    dataset=name, source=dataset_source).set(1)
                metrics.ise_dataset_last_success_timestamp.labels(
                    dataset=name, source=dataset_source).set(completed)
                metrics.ise_consecutive_failures.labels(collector=name).set(0)
                if previous_reason:
                    metrics.ise_dataset_last_failure_info.remove(
                        name, dataset_source, previous_reason)

            commit_metric_snapshots(
                replacements,
                (
                    metrics.ise_last_successful_scrape,
                    metrics.ise_dataset_up,
                    metrics.ise_dataset_fresh,
                    metrics.ise_dataset_last_success_timestamp,
                    metrics.ise_consecutive_failures,
                    metrics.ise_dataset_last_failure_info,
                ),
                (publish_success,),
            )
            if previous_reason:
                _failure_reasons.pop(name, None)
            _outcomes[name] = True
            _failures[name] = 0
        except CollectorFailed as e:
            logger.warning("%s: %s", name, e)
            record_failure(name, e.reason)
        except Exception as e:
            logger.error("%s collection error: %s", name, e)
            record_failure(name, "exception")
        finally:
            duration = max(0.0, time.monotonic() - start)
            with snapshot_lock:
                metrics.ise_collector_duration_seconds.labels(
                    collector=name).set(duration)
                metrics.ise_scrape_duration_seconds.observe(duration)
