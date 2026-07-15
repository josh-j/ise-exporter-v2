"""Small normalization helpers shared by Data Connect domain collectors."""
from datetime import datetime, timezone
import math

from ..snapshots import replace_metric_snapshot
from ..util import metric_label


def label(value, default="unknown"):
    return metric_label(value, default)


def number(value, default=0.0):
    try:
        result = float(value)
    except (TypeError, ValueError):
        return default
    return result if math.isfinite(result) else default


def integer(value):
    result = number(value)
    if result < 0 or not result.is_integer():
        raise ValueError("Data Connect count must be a non-negative integer")
    return int(result)


def group_limit(cfg):
    return max(1, min(1000, int(getattr(cfg, "dataconnect_max_groups", 1000))))


def event_window_hours(cfg, interval_seconds):
    """Match a scan to its cadence without exceeding the production ceiling."""
    try:
        ceiling = int(getattr(cfg, "dataconnect_event_window_hours", 6))
    except (TypeError, ValueError):
        ceiling = 6
    try:
        interval_seconds = int(interval_seconds)
    except (TypeError, ValueError):
        interval_seconds = 3600
    ceiling = max(1, min(6, ceiling))
    cadence = max(1, math.ceil(interval_seconds / 3600))
    return min(ceiling, cadence)


def hourly_rollup_window_hours(cfg, interval_seconds):
    """Keep hourly reporting rollups visible when polling more than hourly."""
    try:
        interval_seconds = int(interval_seconds)
    except (TypeError, ValueError):
        interval_seconds = 3600
    # ISE reporting rows are hourly and may be timestamped in the reporting
    # timezone. Retain the bounded production lookback even when operators poll
    # frequently, otherwise the newest valid rollup can fall outside a 1h scan.
    return event_window_hours(cfg, max(21600, interval_seconds))


def recent_event_predicate(column, hours):
    """Build an index-friendly Oracle timestamp lower bound from a safe integer."""
    hours = max(1, min(6, int(hours)))
    return f"{column} >= SYSTIMESTAMP - NUMTODSINTERVAL({hours}, 'HOUR')"


def query_set(dataconnect, statements, parameters=None):
    """Execute an atomic domain's small statement set under one client lease."""
    query_many = getattr(dataconnect, "query_many", None)
    if callable(query_many):
        return query_many(statements, parameters)
    parameter_sets = parameters or {}
    return {
        name: (dataconnect.query(sql, parameter_sets[name])
               if name in parameter_sets else dataconnect.query(sql))
        for name, sql in statements.items()
    }


def epoch(value):
    if isinstance(value, datetime):
        parsed = value
    else:
        text = str(value or "").strip()
        if not text:
            return 0.0
        try:
            parsed = datetime.fromisoformat(text.replace("Z", "+00:00"))
        except ValueError:
            return number(value)
    if parsed.tzinfo is None:
        parsed = parsed.replace(tzinfo=timezone.utc)
    return parsed.timestamp()


def replace_snapshot(metric_families, writers):
    """Publish a complete domain snapshot only after all rows were normalized.

    Prometheus collection and replacement share one lock. A writer failure rolls
    every family back to the previous snapshot before the lock is released.
    """
    replace_metric_snapshot(metric_families, writers)
