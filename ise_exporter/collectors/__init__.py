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
import re
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
_failure_details = {}

_GENERIC_FAILURE_DETAILS = {
    "authentication_backoff": "Requests are paused by the shared authentication safety backoff",
    "authentication_failed": "The configured credentials were rejected",
    "authorization_failed": "The configured account lacks required access",
    "connection_backoff": "Database reconnects are paused after repeated connection failures",
    "connection_failed": "The configured collection host could not be reached",
    "database_failed": "The Data Connect database operation failed",
    "invalid_response": "ISE returned a response the exporter could not parse",
    "state_unavailable": "Required shared safety state is unavailable or inaccessible",
    "tls_failed": "TLS certificate or protocol validation failed",
    "timeout": "The collection request exceeded its bounded timeout",
    "unexpected_error": "The collector failed unexpectedly; inspect the exporter journal",
    "worker_exception": "The serialized collection worker failed unexpectedly",
    "unhandled_exception": "The scheduled collector failed unexpectedly",
}


def failure_detail(reason, detail=None):
    """Return a bounded, single-line operator explanation safe for a metric label."""
    value = detail or _GENERIC_FAILURE_DETAILS.get(
        reason, str(reason).replace("_", " "))
    return re.sub(r"\s+", " ", str(value)).strip()[:240] or "No detail available"


def source(name):
    if name.startswith("dataconnect_") or name == "tacacs_activity":
        return "dataconnect"
    if name.startswith("mnt_"):
        return "mnt"
    return "rest"


class CollectorFailed(Exception):
    """Raised by a collector when a primary API call yields no usable data."""

    def __init__(self, message, *, reason=None):
        super().__init__(message)
        self.reason = reason or _failure_reason(message)


def _failure_reason(message):
    """Turn a collector-owned failure description into a bounded metric label."""
    reason = re.sub(r"[^a-z0-9]+", "_", str(message).lower()).strip("_")
    return reason[:96] or "no_usable_data"


def _exception_reason(error):
    """Classify arbitrary exceptions without exporting their unbounded text."""
    explicit = getattr(error, "reason", None)
    if isinstance(explicit, str) and re.fullmatch(r"[a-z0-9_]{1,96}", explicit):
        return explicit
    name = type(error).__name__.lower()
    message = str(error).lower()
    if ("authentication guard unavailable" in message
            or "pacing gate unavailable" in message
            or "state unavailable" in message):
        return "state_unavailable"
    if "suppressed by the shared authentication guard" in message:
        return "authentication_backoff"
    if "reconnect suppressed for" in message:
        return "connection_backoff"
    if ("401" in message or "authentication" in message or "credential" in message
            or "invalid username/password" in message
            or any(code in message for code in (
                "ora-01005", "ora-01017", "ora-28000", "ora-28001", "dpy-4001"))):
        return "authentication_failed"
    if ("403" in message or "authorization" in message or "permission" in message
            or "ora-01031" in message):
        return "authorization_failed"
    if "certificate" in message or "ssl" in message or "tls" in message:
        return "tls_failed"
    if "timeout" in name or "timed out" in message:
        return "timeout"
    if ("connection" in name or "connection" in message
            or any(code in message for code in (
                "ora-12170", "ora-12514", "ora-12541", "dpy-6005"))):
        return "connection_failed"
    if ("database" in name or "oracle" in name or "database" in message
            or "ora-" in message or "dpy-" in message):
        return "database_failed"
    if "json" in name or "decode" in name:
        return "invalid_response"
    return "unexpected_error"


def failures(name):
    return _failures.get(name, 0)


def begin_attempt(name):
    """Clear the prior result so the scheduler can observe this attempt only."""
    _outcomes[name] = None


def outcome(name):
    """Return True/False for an observed attempt, or None for an unwrapped callback."""
    return _outcomes.get(name)


def last_failure(name):
    """Return the bounded reason and detail for the latest failed attempt."""
    return _failure_reasons.get(name), _failure_details.get(name)


def record_failure(name, error_type, detail=None):
    """Bump the scrape-error counter + consecutive-failure gauge for a failed collect."""
    with snapshot_lock:
        metrics.ise_scrape_errors_total.labels(
            collector=name, error_type=error_type).inc()
        _failures[name] = _failures.get(name, 0) + 1
        metrics.ise_consecutive_failures.labels(
            collector=name).set(_failures[name])
        dataset_source = source(name)
        previous_reason = _failure_reasons.get(name)
        previous_detail = _failure_details.get(name)
        if previous_reason and previous_reason != error_type:
            metrics.ise_dataset_last_failure_info.remove(
                name, dataset_source, previous_reason)
        if previous_reason and previous_detail:
            metrics.ise_dataset_last_failure_detail_info.remove(
                name, dataset_source, previous_reason, previous_detail)
        bounded_detail = failure_detail(error_type, detail)
        metrics.ise_dataset_last_failure_info.labels(
            dataset=name, source=dataset_source, reason=error_type).set(1)
        metrics.ise_dataset_last_failure_detail_info.labels(
            dataset=name, source=dataset_source, reason=error_type,
            detail=bounded_detail).set(1)
        _failure_reasons[name] = error_type
        _failure_details[name] = bounded_detail
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
            previous_detail = _failure_details.get(name)

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
                if previous_reason and previous_detail:
                    metrics.ise_dataset_last_failure_detail_info.remove(
                        name, dataset_source, previous_reason, previous_detail)

            commit_metric_snapshots(
                replacements,
                (
                    metrics.ise_last_successful_scrape,
                    metrics.ise_dataset_up,
                    metrics.ise_dataset_fresh,
                    metrics.ise_dataset_last_success_timestamp,
                    metrics.ise_consecutive_failures,
                    metrics.ise_dataset_last_failure_info,
                    metrics.ise_dataset_last_failure_detail_info,
                ),
                (publish_success,),
            )
            if previous_reason:
                _failure_reasons.pop(name, None)
                _failure_details.pop(name, None)
            _outcomes[name] = True
            _failures[name] = 0
        except CollectorFailed as e:
            logger.warning("%s: %s", name, e)
            record_failure(name, e.reason, str(e))
        except Exception as e:
            logger.error("%s collection error: %s", name, e)
            record_failure(
                name, _exception_reason(e), getattr(e, "detail", None))
        finally:
            duration = max(0.0, time.monotonic() - start)
            with snapshot_lock:
                metrics.ise_collector_duration_seconds.labels(
                    collector=name).set(duration)
                metrics.ise_scrape_duration_seconds.observe(duration)
