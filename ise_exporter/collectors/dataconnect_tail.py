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
    schema_has,
)

logger = logging.getLogger(__name__)


def meta_min_query(view):
    """Lowest id, split from the max probe -- Oracle only applies the single-aggregate
    MIN/MAX index optimization when a statement contains exactly one such aggregate;
    a combined SELECT MIN(id), MAX(id) forces an index fast full scan on a 100M-row
    MnT table, every cycle."""
    return f"SELECT MIN(id) AS min_id FROM {view}"


def meta_max_query(view):
    """Highest id, split from the min probe for the same single-aggregate reason."""
    return f"SELECT MAX(id) AS max_id FROM {view}"


def _label_projection(schema, upper, entry):
    """SQL for one grouped label.

    ``entry`` is ``(label, column, fallback)`` or ``(label, column, fallback, expr)``.
    With ``expr``, that derived SQL is used when ``column`` is present (e.g. mapping a
    numeric ``FAILED`` flag to a ``'passed'``/``'failed'`` string), falling back to
    ``fallback`` when the column is absent. Every fragment is a collector constant.
    """
    name, column, fallback = entry[0], entry[1], entry[2]
    expr = entry[3] if len(entry) > 3 else None
    base = (expr if expr is not None and schema_has(schema, upper, column)
            else schema_expression(schema, upper, column, fallback))
    return f"NVL({base}, 'unknown') AS {name}"


def tail_query(view, label_columns, schema=None, *, include_floor_audit=True):
    """Count new, settled rows of ``view`` in the contiguous id prefix above the cursor.

    ``label_columns`` is an ordered sequence of ``(label, column, fallback[, expr])``
    that becomes the grouped label set. ``view`` and every column/fallback/expr are
    collector constants, never caller input.

    ``include_floor_audit`` controls the ``floor_skipped`` projection. The audit is a
    correlated COUNT(*) subquery with an unbounded-below timestamp range -- it only
    carries information when the cursor has stalled long enough for rows older than
    the backfill floor to exist above the cursor. In steady state it is pure risk: the
    optimizer can drive the subquery from the timestamp predicate alone and scan the
    whole table every cycle. The caller only turns it on when the cursor is stale
    enough for the audit to matter; :floor_hours stays bound in both variants since the
    main WHERE floor cut always needs it.
    """
    settled = ("CASE WHEN timestamp < CAST(SYSTIMESTAMP"
               " - NUMTODSINTERVAL(:settle_seconds, 'SECOND') AS TIMESTAMP)"
               " THEN 1 ELSE 0 END")
    floor_cut = ("CAST(SYSTIMESTAMP - NUMTODSINTERVAL(:floor_hours, 'HOUR')"
                 " AS TIMESTAMP)")
    upper = view.upper()
    names = [entry[0] for entry in label_columns]
    projections = ",\n                   ".join(
        _label_projection(schema, upper, entry) for entry in label_columns)
    select_names = ", ".join(f"nr.{name} AS {name}" for name in names)
    group_names = ", ".join(f"nr.{name}" for name in names)
    floor_skipped_projection = (
        f"(SELECT COUNT(*) FROM {view}\n"
        f"                WHERE id > :hwm AND timestamp < {floor_cut}) AS floor_skipped"
        if include_floor_audit else "0 AS floor_skipped")
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
               {floor_skipped_projection}
        FROM new_rows nr CROSS JOIN boundary b
        WHERE nr.settled = 1 AND nr.id < b.first_unsettled
        GROUP BY {group_names}
    """


def _id_bounds(min_rows, max_rows):
    """(min_id, max_id) from the two split metadata queries; None each if empty."""
    min_row = min_rows[0] if min_rows else {}
    max_row = max_rows[0] if max_rows else {}
    min_id = min_row.get("min_id")
    max_id = max_row.get("max_id")
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
    label_names = [entry[0] for entry in label_columns]
    # An id-tail is meaningless without the ID column. If the live schema is known and
    # this view lacks ID, self-skip instead of failing every cycle on ORA-00904. When
    # the schema is not yet discovered (None) the engine stays permissive as before.
    if schema is not None and not schema_has(schema, view.upper(), "id"):
        logger.warning(
            "collector detail dataset=%s source=dataconnect outcome=skipped_no_id "
            "view=%s action=id_tail_requires_id_column", dataset, view)
        metrics.ise_dataconnect_tail_events_last_cycle.labels(view=view).set(0)
        return
    store = StateStore(getattr(cfg, "state_db_path", ":memory:"))
    try:
        cursor = store.tail_cursor(view)
        if cursor is None:
            # Cold start: seed at the current tip and count strictly forward.
            meta = query_set(dataconnect, {
                "meta_min": meta_min_query(view),
                "meta_max": meta_max_query(view),
            })
            min_id, max_id = _id_bounds(meta["meta_min"], meta["meta_max"])
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
        cursor_updated_at = cursor.get("updated_at", 0.0)
        # The floor-audit subquery only carries information once the cursor has
        # stalled past the backfill floor (rows older than the floor with id above the
        # cursor can then exist); in steady state it is pure risk that the optimizer
        # scans the whole table every cycle, so it is skipped unless the cursor is
        # stale (or its age is unknown -- treat that as maximally stale, not exempt).
        cursor_age = now - cursor_updated_at
        include_floor_audit = (
            cursor_updated_at <= 0 or cursor_age > floor_hours * 3600)
        combined = query_set(dataconnect, {
            "meta_min": meta_min_query(view),
            "meta_max": meta_max_query(view),
            "tail": tail_query(view, label_columns, schema,
                                include_floor_audit=include_floor_audit),
        }, {"tail": {"hwm": hwm, "settle_seconds": settle, "floor_hours": floor_hours}})
        min_id, max_id = _id_bounds(combined["meta_min"], combined["meta_max"])
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
