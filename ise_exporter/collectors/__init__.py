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


class CollectorFailed(Exception):
    """Raised by a collector when a primary API call yields no usable data."""


def failures(name):
    return _failures.get(name, 0)


@contextmanager
def observe(name):
    start = time.time()
    try:
        yield
        metrics.ise_last_successful_scrape.labels(collector=name).set(time.time())
        _failures[name] = 0
        metrics.ise_consecutive_failures.labels(collector=name).set(0)
    except CollectorFailed as e:
        logger.warning("%s: %s", name, e)
        metrics.ise_scrape_errors_total.labels(collector=name, error_type="no_data").inc()
        _failures[name] = _failures.get(name, 0) + 1
        metrics.ise_consecutive_failures.labels(collector=name).set(_failures[name])
    except Exception as e:
        logger.error("%s collection error: %s", name, e)
        metrics.ise_scrape_errors_total.labels(collector=name, error_type="exception").inc()
        _failures[name] = _failures.get(name, 0) + 1
        metrics.ise_consecutive_failures.labels(collector=name).set(_failures[name])
    finally:
        metrics.ise_collector_duration_seconds.labels(collector=name).set(time.time() - start)
