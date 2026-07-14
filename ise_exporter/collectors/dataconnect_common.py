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
    return max(1, min(10000, int(getattr(cfg, "dataconnect_max_groups", 5000))))


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
