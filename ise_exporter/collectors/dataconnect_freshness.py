"""Low-pressure reporting-view presence and source-event freshness.

Collector success timestamps prove that a query completed; they do not prove that
ISE is still inserting current rows.  This collector publishes the event-time
newest event of every timestamped Data Connect view so operators can distinguish
an empty, stale, and genuinely current reporting plane without exact row counts.
"""
from __future__ import annotations

from datetime import datetime, timezone

from .. import metrics
from ..dataconnect_schema import VIEW_CONTRACTS
from ..snapshots import replace_metric_snapshot
from ..util import parse_ise_date
from . import observe


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
    parsed = parse_ise_date(str(value))
    if not parsed:
        return 0.0
    if parsed.tzinfo is None:
        parsed = parsed.replace(tzinfo=timezone.utc)
    return parsed.timestamp()


def _timestamped_views():
    return tuple((name, contract) for name, contract in VIEW_CONTRACTS.items()
                 if contract.time_column)


def collect(dataconnect, cfg):
    """Atomically replace low-pressure row-presence and newest-event probes."""
    del cfg
    with observe("dataconnect_freshness"):
        rows = []
        for view, contract in _timestamped_views():
            column = contract.time_column
            # Cisco's TACACS views are already hard-bounded to two days and expose
            # numeric Unix EPOCH_TIME rather than an Oracle timestamp. Applying a
            # SYSTIMESTAMP predicate to that column is both invalid and redundant.
            predicate = (f"WHERE {column} IS NOT NULL" if view.startswith("TACACS_") else
                         f"WHERE {column} >= SYSTIMESTAMP - INTERVAL '2' DAY")
            result = dataconnect.query(f"""
                SELECT {column} AS newest_event
                FROM {view}
                {predicate}
                ORDER BY {column} DESC NULLS LAST FETCH FIRST 1 ROWS ONLY
            """)
            row = result[0] if result else {}
            rows.append({
                "view": view.lower(),
                "domain": contract.domain,
                "has_rows": int(bool(result)),
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
