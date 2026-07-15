"""Low-pressure reporting-view presence and source-event freshness.

Collector success timestamps prove that a query completed; they do not prove that
ISE is still inserting current rows.  This collector publishes the event-time
newest event of every timestamped Data Connect view so operators can distinguish
an empty, stale, and genuinely current reporting plane without exact row counts.
"""
from __future__ import annotations

from datetime import datetime, timezone
import math
import time

from .. import metrics
from ..dataconnect_schema import VIEW_CONTRACTS
from ..snapshots import replace_metric_snapshot
from ..util import parse_ise_date
from . import observe
from .dataconnect_common import event_window_hours, recent_event_predicate


_METRICS = (
    metrics.ise_dataconnect_view_has_rows,
    metrics.ise_dataconnect_view_newest_event_timestamp,
)


def _timestamp(value):
    if value is None:
        return 0.0
    if isinstance(value, datetime):
        if value.tzinfo is None:
            value = value.replace(tzinfo=timezone.utc)
        return value.timestamp()
    if isinstance(value, (int, float)):
        numeric = float(value)
        return numeric / 1000.0 if numeric > 10_000_000_000 else numeric
    text = str(value).strip()
    try:
        numeric = float(text)
    except ValueError:
        numeric = None
    if numeric is not None:
        if not math.isfinite(numeric):
            return 0.0
        return numeric / 1000.0 if numeric > 10_000_000_000 else numeric
    parsed = parse_ise_date(text)
    if not parsed:
        return 0.0
    if parsed.tzinfo is None:
        parsed = parsed.replace(tzinfo=timezone.utc)
    return parsed.timestamp()


def _timestamped_views(include_tacacs=True):
    return tuple((name, contract) for name, contract in VIEW_CONTRACTS.items()
                 if contract.time_column
                 and (include_tacacs or contract.domain != "tacacs"))


def _query(cfg, now=None):
    """Build one bounded statement for every source-view freshness marker."""
    window = event_window_hours(
        cfg, getattr(cfg, "dataconnect_freshness_interval", 86400))
    minimum_epoch = int(time.time() if now is None else now) - window * 3600
    branches = []
    views = _timestamped_views(getattr(cfg, "collect_tacacs", True))
    for view, contract in views:
        column = contract.time_column
        if view.startswith("TACACS_"):
            predicate = f"{column} >= {minimum_epoch}"
            projection = f"TO_CHAR({column})"
        else:
            predicate = recent_event_predicate(column, window)
            projection = f"TO_CHAR({column}, 'YYYY-MM-DD\"T\"HH24:MI:SS.FF')"
        branches.append(f"""
            SELECT '{view.lower()}' AS view_name,
                   '{contract.domain}' AS domain, newest_event
            FROM (
                SELECT {projection} AS newest_event
                FROM {view}
                WHERE {predicate}
                ORDER BY {column} DESC NULLS LAST FETCH FIRST 1 ROWS ONLY
            )
        """)
    return "/* ise_exporter:dataconnect_freshness */\n" + \
        "\nUNION ALL\n".join(branches)


def collect(dataconnect, cfg):
    """Atomically replace low-pressure row-presence and newest-event probes."""
    with observe("dataconnect_freshness"):
        result = dataconnect.query(_query(cfg))
        by_view = {str(row.get("view_name") or "").lower(): row for row in result}
        rows = []
        for view, contract in _timestamped_views(getattr(cfg, "collect_tacacs", True)):
            name = view.lower()
            row = by_view.get(name, {})
            rows.append({
                "view": name,
                "domain": contract.domain,
                "has_rows": int(bool(row)),
                "newest": _timestamp(row.get("newest_event")),
            })

        writers = []
        for row in rows:
            labels = {"view": row["view"], "domain": row["domain"]}
            writers.extend((
                lambda row=row, labels=labels:
                    metrics.ise_dataconnect_view_has_rows.labels(
                        **labels).set(row["has_rows"]),
                lambda row=row, labels=labels:
                    metrics.ise_dataconnect_view_newest_event_timestamp.labels(
                        **labels).set(row["newest"]),
            ))
        replace_metric_snapshot(_METRICS, writers)
