"""Generic incremental id-tailing: fold new event rows into monotonic counters.

Shared by the RADIUS-accounting and posture-assessment counter collectors (and any
future id-tailed view). Each Data Connect reporting view exposes a global monotonic
``ID`` assigned by MnT on insert -- verified GLOBAL, not per-PSN, on a multi-PSN
cluster (docs/incremental-tailing-plan.md) -- so a single cursor per view tails only
the rows added since the last cycle. The exporter accumulates counters and Prometheus
owns the windowing (rate/increase), instead of the exporter re-summing a fixed
server-side window every cycle.

Correctness (carried over from the accounting review hardening):
- The cursor advances only through the CONTIGUOUS SETTLED PREFIX: rows are counted
  only up to the first still-unsettled id, so a settled high id can never advance the
  cursor past a not-yet-settled lower id and drop it.
- A source-side sequence reset is caught by a drop in the persisted low-water anchor
  (purge only ever raises the minimum id), plus the reset-then-quiet case.
- The cursor is committed BEFORE the counter is incremented, so a failed/retry cycle
  re-scans rather than double-counts. Counters reset on boot; Prometheus rate() is
  reset-aware.
- The backfill floor bounds cold-start / long-downtime cost and logs any dropped rows
  (floor_skipped) instead of dropping them silently.
"""
import logging
import time

from .. import metrics
from ..state import StateStore
from .dataconnect_common import (
    integer,
    label,
    number,
    query_set,
    schema_expression,
)

logger = logging.getLogger(__name__)


def meta_query(view):
    """Cheap absolute id bounds for cold-start seeding and reset detection."""
    return f"SELECT MIN(id) AS min_id, MAX(id) AS max_id FROM {view}"


def tail_query(view, label_columns, schema=None):
    """Count new, settled rows of ``view`` in the contiguous id prefix above the cursor.

    ``label_columns`` is an ordered sequence of ``(label, column, fallback)`` that
    becomes the grouped label set. ``view`` and every column/fallback are collector
    constants, never caller input.
    """
    settled = ("CASE WHEN timestamp < CAST(SYSTIMESTAMP"
               " - NUMTODSINTERVAL(:settle_seconds, 'SECOND') AS TIMESTAMP)"
               " THEN 1 ELSE 0 END")
    floor_cut = ("CAST(SYSTIMESTAMP - NUMTODSINTERVAL(:floor_hours, 'HOUR')"
                 " AS TIMESTAMP)")
    upper = view.upper()
    names = [name for name, _column, _fallback in label_columns]
    projections = ",\n                   ".join(
        f"NVL({schema_expression(schema, upper, column, fallback)}, 'unknown') AS {name}"
        for name, column, fallback in label_columns)
    select_names = ", ".join(f"nr.{name} AS {name}" for name in names)
    group_names = ", ".join(f"nr.{name}" for name in names)
    return f"""
        WITH new_rows AS (
            SELECT id,
                   {projections},
                   {settled} AS settled
            FROM {view}
            WHERE id > :hwm AND timestamp >= {floor_cut}
        ), boundary AS (
            SELECT NVL(MIN(CASE WHEN settled = 0 THEN id END),
                       MAX(id) + 1) AS first_unsettled
            FROM new_rows
        )
        SELECT {select_names},
               COUNT(*) AS events, MAX(nr.id) AS max_id,
               (SELECT COUNT(*) FROM {view}
                WHERE id > :hwm AND timestamp < {floor_cut}) AS floor_skipped
        FROM new_rows nr CROSS JOIN boundary b
        WHERE nr.settled = 1 AND nr.id < b.first_unsettled
        GROUP BY {group_names}
    """


def _id_bounds(meta_rows):
    """(min_id, max_id) from the metadata query; each None if the view is empty."""
    row = meta_rows[0] if meta_rows else {}
    min_id = row.get("min_id")
    max_id = row.get("max_id")
    return (number(min_id) if min_id is not None else None,
            number(max_id) if max_id is not None else None)


def tail_counters(dataconnect, cfg, *, dataset, view, label_columns, counter):
    """Fold new settled rows of ``view`` into ``counter``; caller wraps in observe().

    ``label_columns`` maps the grouped columns to counter labels; ``counter`` is the
    prometheus Counter to increment. Shared ``ise_dataconnect_tail_*`` cursor/reset
    telemetry is published per ``view``.
    """
    settle = max(0, int(getattr(cfg, "dataconnect_tail_settle_seconds", 30)))
    floor_hours = max(1, min(24, int(getattr(
        cfg, "dataconnect_tail_max_backfill_hours", 6))))
    schema = getattr(dataconnect, "schema", None)
    now = time.time()
    label_names = [name for name, _column, _fallback in label_columns]
    store = StateStore(getattr(cfg, "state_db_path", ":memory:"))
    try:
        cursor = store.tail_cursor(view)
        if cursor is None:
            # Cold start: seed at the current tip and count strictly forward.
            min_id, max_id = _id_bounds(dataconnect.query(meta_query(view)))
            seed = max_id or 0.0
            store.set_tail_cursor(view, "id", seed, now=now, anchor=(min_id or 0.0))
            store.commit()
            metrics.ise_dataconnect_tail_cursor_id.labels(view=view).set(seed)
            metrics.ise_dataconnect_tail_events_last_cycle.labels(view=view).set(0)
            logger.info(
                "collector detail dataset=%s source=dataconnect outcome=cold_start "
                "seed_id=%d action=count_forward", dataset, int(seed))
            return

        hwm = cursor["value"]
        prev_anchor = cursor["anchor"]
        combined = query_set(dataconnect, {
            "meta": meta_query(view),
            "tail": tail_query(view, label_columns, schema),
        }, {"tail": {"hwm": hwm, "settle_seconds": settle, "floor_hours": floor_hours}})
        min_id, max_id = _id_bounds(combined["meta"])
        rows = combined["tail"]

        # Sequence reset: purge only ever raises the minimum id, so a drop below the
        # anchor means the id space was rebuilt. Also cover the reset-then-quiet case
        # (absolute max now below the cursor). Re-seed to the new bottom and re-scan;
        # do not trust this cycle's rows.
        reset = (min_id is not None and prev_anchor > 0 and min_id < prev_anchor)
        if not reset and not rows and max_id is not None and max_id < hwm:
            reset = True
        if reset:
            reseed = max(0.0, (min_id if min_id is not None else 0.0) - 1.0)
            store.set_tail_cursor(view, "id", reseed, now=now,
                                  anchor=(min_id if min_id is not None else 0.0))
            store.commit()
            metrics.ise_dataconnect_tail_resets_total.labels(view=view).inc()
            metrics.ise_dataconnect_tail_cursor_id.labels(view=view).set(reseed)
            metrics.ise_dataconnect_tail_events_last_cycle.labels(view=view).set(0)
            logger.warning(
                "collector detail dataset=%s source=dataconnect outcome=cursor_reset "
                "previous_id=%d reseed_id=%d action=rescan_new_sequence",
                dataset, int(hwm), int(reseed))
            return

        if not rows:
            # Nothing settled to advance through yet (quiet, or the lowest new row has
            # not settled). Keep the cursor; refresh the reset anchor.
            if min_id is not None:
                store.set_tail_cursor(view, "id", hwm, now=now, anchor=min_id)
                store.commit()
            metrics.ise_dataconnect_tail_events_last_cycle.labels(view=view).set(0)
            return

        increments = []
        new_hwm = hwm
        total = 0
        floor_skipped = 0
        for row in rows:
            events = integer(row.get("events"))
            values = tuple(label(row.get(name), "unknown") for name in label_names)
            increments.append((values, events))
            total += events
            new_hwm = max(new_hwm, number(row.get("max_id")))
            floor_skipped = max(floor_skipped, integer(row.get("floor_skipped") or 0))

        # Commit the cursor advance (and refreshed anchor) BEFORE incrementing counters
        # so a failed/retry cycle re-scans rather than double-counts.
        new_anchor = min_id if min_id is not None else prev_anchor
        store.set_tail_cursor(view, "id", new_hwm, now=now, anchor=new_anchor)
        store.commit()
    finally:
        store.close()

    if floor_skipped:
        logger.warning(
            "collector detail dataset=%s source=dataconnect outcome=floor_backfill_gap "
            "skipped_rows=%d floor_hours=%d "
            "action=raise_tail_max_backfill_hours_or_accept_gap",
            dataset, floor_skipped, floor_hours)
    for values, events in increments:
        if events:
            counter.labels(**dict(zip(label_names, values))).inc(events)
    metrics.ise_dataconnect_tail_cursor_id.labels(view=view).set(new_hwm)
    metrics.ise_dataconnect_tail_events_last_cycle.labels(view=view).set(total)
