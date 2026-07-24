"""Low-pressure recent reporting-view activity and source-event freshness.

Collector success timestamps prove that a query completed; they do not prove that
ISE is still inserting current rows. This collector publishes whether every
timestamped view has a row in the bounded recent window and that window's newest
event. It deliberately makes no claim about older rows because proving global
emptiness would require an unsafe full-history probe on a large production MnT.
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
from .dataconnect_common import event_window_hours, query_set, recent_event_predicate
from .dataconnect_common import schema_columns


# Each view branch is a cheap index-descending top-1 probe, but the client enforces
# one hard statement timeout (15s max) across every branch in a statement. Capping
# branches per statement keeps a single freshness probe well inside that budget even
# when a branch lands on an unindexed or unusually large partition. Roughly 16
# timestamped views -> 4 statements of 4 branches, comfortably under the client's
# 5-statement batch ceiling (MAX_BATCH_QUERIES).
_MAX_PROBE_BRANCHES_PER_STATEMENT = 4
_MAX_PROBE_STATEMENTS = 5


_METRICS = (
    metrics.ise_dataconnect_view_has_recent_rows,
    metrics.ise_dataconnect_view_newest_recent_event_timestamp,
    metrics.ise_dataconnect_view_freshness_expected,
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


def _timestamped_views(include_tacacs=True, schema=None):
    views = []
    for name, contract in VIEW_CONTRACTS.items():
        if not contract.time_column or not contract.freshness_probe:
            continue
        if not include_tacacs and contract.domain == "tacacs":
            continue
        columns = schema_columns(schema, name)
        if columns is not None and contract.time_column not in columns and not (
                contract.time_column != "EPOCH_TIME"
                and "TIMESTAMP_TIMEZONE" in columns):
            continue
        views.append((name, contract))
    return tuple(views)


def _freshness_column(view, contract, schema):
    columns = schema_columns(schema, view)
    if (contract.time_column != "EPOCH_TIME" and columns is not None
            and "TIMESTAMP_TIMEZONE" in columns):
        return "TIMESTAMP_TIMEZONE", True
    return contract.time_column, False


def _branch_sql(view, contract, window, minimum_epoch, schema):
    column, timezone_aware = _freshness_column(view, contract, schema)
    if view.startswith("TACACS_"):
        predicate = f"{column} >= {minimum_epoch}"
        projection = f"TO_CHAR({column})"
    else:
        predicate = recent_event_predicate(
            column, window, timezone_aware=timezone_aware)
        if timezone_aware:
            projection = (
                f"TO_CHAR({column}, "
                "'YYYY-MM-DD\"T\"HH24:MI:SS.FFTZH:TZM')"
            )
        else:
            projection = (
                "TO_CHAR(FROM_TZ(CAST("
                f"{column} AS TIMESTAMP), TO_CHAR(SYSTIMESTAMP, 'TZH:TZM')) "
                "AT TIME ZONE 'UTC', "
                "'YYYY-MM-DD\"T\"HH24:MI:SS.FFTZH:TZM')"
            )
    return f"""
        SELECT '{view.lower()}' AS view_name,
               '{contract.domain}' AS domain, newest_event
        FROM (
            SELECT {projection} AS newest_event
            FROM {view}
            WHERE {predicate}
            ORDER BY {column} DESC NULLS LAST FETCH FIRST 1 ROWS ONLY
        )
    """


def _chunk_views(views):
    """Split views into statement-sized groups within the client's batch ceiling.

    Defaults to _MAX_PROBE_BRANCHES_PER_STATEMENT branches per statement. If the
    view set is large enough that this would need more than _MAX_PROBE_STATEMENTS
    statements, grow the chunk size just enough to fit the batch ceiling instead of
    exceeding it -- fewer, slightly larger statements are still far below the
    single-statement timeout that motivated chunking in the first place.
    """
    if not views:
        return []
    chunk_size = max(
        _MAX_PROBE_BRANCHES_PER_STATEMENT,
        math.ceil(len(views) / _MAX_PROBE_STATEMENTS))
    return [views[index:index + chunk_size]
            for index in range(0, len(views), chunk_size)]


def _statements(cfg, now=None, schema=None):
    """Build the chunked, batch-shared statement set for every timestamped view."""
    window = event_window_hours(
        cfg, getattr(cfg, "dataconnect_freshness_interval", 1800))
    minimum_epoch = int(time.time() if now is None else now) - window * 3600
    views = _timestamped_views(getattr(cfg, "collect_tacacs", True), schema)
    if not views:
        raise ValueError("no Data Connect reporting view has a freshness timestamp")
    statements = {}
    for chunk_index, chunk in enumerate(_chunk_views(views)):
        branches = [
            _branch_sql(view, contract, window, minimum_epoch, schema)
            for view, contract in chunk
        ]
        statements[f"chunk_{chunk_index}"] = (
            "/* ise_exporter:dataconnect_freshness */\n" +
            "\nUNION ALL\n".join(branches))
    return statements


def _query(cfg, now=None, schema=None):
    """Build one bounded statement for every source-view freshness marker.

    Retained for callers/tests that want a single combined statement (for example
    to assert on branch content irrespective of chunking); production collection
    goes through _statements()/query_set() instead.
    """
    return "\nUNION ALL\n".join(_statements(cfg, now=now, schema=schema).values())


def collect(dataconnect, cfg):
    """Atomically replace low-pressure row-presence and newest-event probes."""
    with observe("dataconnect_freshness"):
        schema = getattr(dataconnect, "schema", None)
        views = _timestamped_views(getattr(cfg, "collect_tacacs", True), schema)
        chunks = query_set(dataconnect, _statements(cfg, schema=schema))
        result = [row for chunk_rows in chunks.values() for row in chunk_rows]
        by_view = {str(row.get("view_name") or "").lower(): row for row in result}
        rows = []
        for view, contract in views:
            name = view.lower()
            row = by_view.get(name, {})
            rows.append({
                "view": name,
                "domain": contract.domain,
                "has_rows": int(bool(row)),
                "newest": _timestamp(row.get("newest_event")),
                "expected": int(contract.freshness_expected),
            })

        writers = []
        for row in rows:
            labels = {"view": row["view"], "domain": row["domain"]}
            writers.extend((
                lambda row=row, labels=labels:
                    metrics.ise_dataconnect_view_has_recent_rows.labels(
                        **labels).set(row["has_rows"]),
                lambda row=row, labels=labels:
                    metrics.ise_dataconnect_view_newest_recent_event_timestamp.labels(
                        **labels).set(row["newest"]),
                lambda row=row, labels=labels:
                    metrics.ise_dataconnect_view_freshness_expected.labels(
                        **labels).set(row["expected"]),
            ))
        replace_metric_snapshot(_METRICS, writers)
