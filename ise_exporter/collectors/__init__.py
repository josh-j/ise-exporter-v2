"""Collector package. `observe(name)` wraps a collector body with the
self-observability the monolith applied to each collector inline: duration,
last-successful timestamp, scrape-error counter, and a consecutive-failure gauge.
It swallows exceptions so one failing collector can't abort the whole poll cycle,
and is the single source of truth for failure counts (the scheduler reads
`failures(name)` for its MAX_CONSECUTIVE_FAILURES gating).

Collectors raise CollectorFailed when a primary API call returns no data, so an
unreachable endpoint counts as a failure (and does NOT bump last_successful_scrape)
rather than masquerading as a healthy scrape."""
import logging
import time
from contextlib import contextmanager

from .. import metrics

logger = logging.getLogger(__name__)
_failures = {}


def _source(name):
    return "dataconnect" if name.startswith("dataconnect_") or name == "tacacs_activity" else "rest"


class CollectorFailed(Exception):
    """Raised by a collector when a primary API call yields no usable data."""


def failures(name):
    return _failures.get(name, 0)


def _record_failure(name, error_type):
    """Bump the scrape-error counter + consecutive-failure gauge for a failed collect."""
    metrics.ise_scrape_errors_total.labels(collector=name, error_type=error_type).inc()
    _failures[name] = _failures.get(name, 0) + 1
    metrics.ise_consecutive_failures.labels(collector=name).set(_failures[name])
    metrics.ise_dataset_up.labels(dataset=name, source=_source(name)).set(0)


@contextmanager
def observe(name):
    start = time.time()
    try:
        yield
        completed = time.time()
        metrics.ise_last_successful_scrape.labels(collector=name).set(completed)
        metrics.ise_dataset_up.labels(dataset=name, source=_source(name)).set(1)
        metrics.ise_dataset_last_success_timestamp.labels(
            dataset=name, source=_source(name)).set(completed)
        _failures[name] = 0
        metrics.ise_consecutive_failures.labels(collector=name).set(0)
    except CollectorFailed as e:
        logger.warning("%s: %s", name, e)
        _record_failure(name, "no_data")
    except Exception as e:
        logger.error("%s collection error: %s", name, e)
        _record_failure(name, "exception")
    finally:
        duration = time.time() - start
        metrics.ise_collector_duration_seconds.labels(collector=name).set(duration)
        metrics.ise_scrape_duration_seconds.observe(duration)
