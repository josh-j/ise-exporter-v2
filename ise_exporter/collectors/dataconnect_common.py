"""Small normalization helpers shared by Data Connect domain collectors."""
from datetime import datetime, timezone
import math

from ..snapshots import replace_metric_snapshot


def label(value, default="unknown"):
    text = str(value or "").strip()
    return text or default


def number(value, default=0.0):
    try:
        result = float(value)
    except (TypeError, ValueError):
        return default
    return result if math.isfinite(result) else default


def integer(value):
    return int(number(value))


def group_limit(cfg):
    return max(1, min(1000, int(getattr(cfg, "dataconnect_max_groups", 1000))))


def event_window_hours(cfg, interval_seconds):
    """Match a scan to its cadence without exceeding the production ceiling."""
    ceiling = max(1, min(24, int(getattr(
        cfg, "dataconnect_event_window_hours", 24))))
    cadence = max(1, math.ceil(int(interval_seconds) / 3600))
    return min(ceiling, cadence)


def recent_event_predicate(column, hours):
    """Build an index-friendly Oracle timestamp lower bound from a safe integer."""
    hours = max(1, min(24, int(hours)))
    return f"{column} >= SYSTIMESTAMP - NUMTODSINTERVAL({hours}, 'HOUR')"


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
