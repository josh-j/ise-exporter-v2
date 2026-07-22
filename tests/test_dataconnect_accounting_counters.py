import types

import pytest

from ise_exporter import metrics
from ise_exporter.collectors import dataconnect_radius
from ise_exporter.state import StateStore
from ise_exporter.util import clear_metric


_METRICS = (
    metrics.ise_dataconnect_radius_accounting_tail_total,
    metrics.ise_dataconnect_tail_cursor_id,
    metrics.ise_dataconnect_tail_events_last_cycle,
    metrics.ise_dataconnect_tail_resets_total,
)


@pytest.fixture(autouse=True)
def _clear():
    for metric in _METRICS:
        clear_metric(metric)


def _counter(event_type, psn):
    # Counters expose both _total and _created samples; read the value directly.
    return metrics.ise_dataconnect_radius_accounting_tail_total.labels(
        event_type=event_type, psn=psn)._value.get()


def _cursor_gauge():
    return metrics.ise_dataconnect_tail_cursor_id.labels(
        view="radius_accounting")._value.get()


def _events_last_cycle():
    return metrics.ise_dataconnect_tail_events_last_cycle.labels(
        view="radius_accounting")._value.get()


class FakeAccounting:
    """Fake RADIUS_ACCOUNTING that models the meta + contiguous-prefix tail SQL.

    Rows carry ``added_ago`` (seconds since the DB "now") so the fake applies the
    same settle and backfill-floor windows the real SQL does, and reproduces the
    "advance only through the contiguous settled prefix" rule so the tests exercise
    the actual watermark logic rather than a stub.
    """

    def __init__(self, rows=None):
        self.rows = list(rows or [])
        self.schema = None
        self.queries = []

    def query(self, sql, parameters=None):
        self.queries.append((sql, parameters))
        if "with new_rows" in sql.lower():
            p = parameters or {}
            return self._tail(p["hwm"], p["settle_seconds"], p["floor_hours"] * 3600)
        ids = [r["id"] for r in self.rows]
        return [{"min_id": min(ids) if ids else None,
                 "max_id": max(ids) if ids else None}]

    def _tail(self, hwm, settle, floor_seconds):
        new_rows = [r for r in self.rows
                    if r["id"] > hwm and r["added_ago"] <= floor_seconds]
        settled = [r for r in new_rows if r["added_ago"] > settle]
        unsettled_ids = [r["id"] for r in new_rows if r["added_ago"] <= settle]
        if unsettled_ids:
            first_unsettled = min(unsettled_ids)
        elif new_rows:
            first_unsettled = max(r["id"] for r in new_rows) + 1
        else:
            return []
        counted = [r for r in settled if r["id"] < first_unsettled]
        floor_skipped = sum(1 for r in self.rows
                            if r["id"] > hwm and r["added_ago"] > floor_seconds)
        groups = {}
        for r in counted:
            bucket = groups.setdefault((r["event_type"], r["psn"]),
                                       {"events": 0, "max_id": 0})
            bucket["events"] += 1
            bucket["max_id"] = max(bucket["max_id"], r["id"])
        return [{"event_type": et, "psn": psn, "events": b["events"],
                 "max_id": b["max_id"], "floor_skipped": floor_skipped}
                for (et, psn), b in groups.items()]


def _cfg(tmp_path, **overrides):
    values = {
        "state_db_path": str(tmp_path / "state.sqlite3"),
        "dataconnect_tail_settle_seconds": 30,
        "dataconnect_tail_max_backfill_hours": 6,
    }
    values.update(overrides)
    return types.SimpleNamespace(**values)


def _row(id_, event_type="Start", psn="psn-1", added_ago=600):
    return {"id": id_, "event_type": event_type, "psn": psn, "added_ago": added_ago}


def _collect(fake, cfg):
    dataconnect_radius.collect_accounting_counters(fake, cfg)


def test_cold_start_seeds_at_the_tip_and_counts_nothing(tmp_path):
    fake = FakeAccounting([_row(100)])
    cfg = _cfg(tmp_path)

    _collect(fake, cfg)

    assert _counter("Start", "psn-1") == 0
    assert _cursor_gauge() == 100
    store = StateStore(cfg.state_db_path)
    cursor = store.tail_cursor("radius_accounting")
    assert cursor["kind"] == "id"
    assert cursor["value"] == 100.0
    assert cursor["anchor"] == 100.0
    store.close()


def test_tail_increments_counters_and_advances_cursor_idempotently(tmp_path):
    fake = FakeAccounting([_row(100)])
    cfg = _cfg(tmp_path)
    _collect(fake, cfg)  # seed at 100

    fake.rows += [_row(101, "Start"), _row(102, "Start"), _row(103, "Stop")]
    _collect(fake, cfg)

    assert _counter("Start", "psn-1") == 2
    assert _counter("Stop", "psn-1") == 1
    assert _events_last_cycle() == 3
    assert _cursor_gauge() == 103

    # No new rows: cursor already past them, so no double count.
    _collect(fake, cfg)
    assert _counter("Start", "psn-1") == 2
    assert _counter("Stop", "psn-1") == 1
    assert _events_last_cycle() == 0


def test_settled_high_id_never_skips_an_unsettled_lower_id(tmp_path):
    # Out-of-commit-order hazard [P1]: cursor 100, id 101 fresh (unsettled), id 102
    # old (settled). Advancing to 102 would drop 101 forever. The contiguous-prefix
    # watermark must refuse to advance past the still-unsettled 101.
    fake = FakeAccounting([_row(100)])
    cfg = _cfg(tmp_path)
    _collect(fake, cfg)  # seed 100

    fresh101 = _row(101, "Start", added_ago=5)
    fake.rows += [fresh101, _row(102, "Stop", added_ago=600)]
    _collect(fake, cfg)

    assert _counter("Start", "psn-1") == 0  # 101 not settled
    assert _counter("Stop", "psn-1") == 0   # 102 withheld behind unsettled 101
    assert _cursor_gauge() == 100           # cursor did not advance

    # 101 settles: now the contiguous prefix covers both and the cursor advances.
    fresh101["added_ago"] = 600
    _collect(fake, cfg)
    assert _counter("Start", "psn-1") == 1
    assert _counter("Stop", "psn-1") == 1
    assert _cursor_gauge() == 102


def test_fresh_rows_wait_for_the_settle_delay(tmp_path):
    fake = FakeAccounting([_row(199)])
    cfg = _cfg(tmp_path)
    _collect(fake, cfg)  # seed 199

    fresh = _row(200, "Start", added_ago=5)
    fake.rows.append(fresh)
    _collect(fake, cfg)
    assert _counter("Start", "psn-1") == 0
    assert _cursor_gauge() == 199

    fresh["added_ago"] = 120
    _collect(fake, cfg)
    assert _counter("Start", "psn-1") == 1
    assert _cursor_gauge() == 200


def test_reset_then_quiet_reseeds_from_the_new_bottom(tmp_path, caplog):
    cfg = _cfg(tmp_path)
    store = StateStore(cfg.state_db_path)
    store.set_tail_cursor("radius_accounting", "id", 5000, now=1000.0, anchor=4000)
    store.commit()
    store.close()

    # The view now holds only a low id (rebuild dropped the sequence, then quiet).
    fake = FakeAccounting([_row(10, "Start")])
    with caplog.at_level("WARNING"):
        _collect(fake, cfg)

    assert metrics.ise_dataconnect_tail_resets_total.labels(
        view="radius_accounting")._value.get() == 1
    assert _cursor_gauge() == 9  # reseed to min_id - 1 to rescan the new sequence
    assert "outcome=cursor_reset" in caplog.text
    store = StateStore(cfg.state_db_path)
    assert store.tail_cursor("radius_accounting")["value"] == 9.0
    store.close()


def test_fast_refilling_reset_is_caught_by_min_id_drop(tmp_path, caplog):
    # Fast-refill reset hazard [P1]: a rebuilt sequence climbs past the old cursor
    # before the next poll, so `id > hwm` is non-empty and the empty-tail check never
    # fires. The MIN(id) drop below the anchor catches it and no rows are lost.
    cfg = _cfg(tmp_path)
    store = StateStore(cfg.state_db_path)
    store.set_tail_cursor("radius_accounting", "id", 5000, now=1000.0, anchor=4000)
    store.commit()
    store.close()

    fake = FakeAccounting([
        _row(1, "Start"), _row(5500, "Start"), _row(6000, "Stop")])
    with caplog.at_level("WARNING"):
        _collect(fake, cfg)

    # Reset detected despite the non-empty tail (ids 5500/6000 above the old cursor).
    assert metrics.ise_dataconnect_tail_resets_total.labels(
        view="radius_accounting")._value.get() == 1
    assert _cursor_gauge() == 0            # reseed to min_id - 1 = 0
    assert _counter("Start", "psn-1") == 0  # this cycle's rows are not trusted
    assert "outcome=cursor_reset" in caplog.text

    # Next cycle rescans the whole new incarnation from the bottom.
    _collect(fake, cfg)
    assert _counter("Start", "psn-1") == 2  # ids 1 and 5500
    assert _counter("Stop", "psn-1") == 1   # id 6000
    assert _cursor_gauge() == 6000


def test_backfill_floor_gap_is_logged_not_silent(tmp_path, caplog):
    fake = FakeAccounting([_row(100)])
    cfg = _cfg(tmp_path, dataconnect_tail_max_backfill_hours=1)
    _collect(fake, cfg)  # seed 100

    # Stale the cursor past the floor window so the floor-audit subquery runs this
    # cycle -- in steady state (fresh cursor) it is skipped, so a dropped row above
    # the cursor would go unaudited.
    store = StateStore(cfg.state_db_path)
    cursor = store.tail_cursor("radius_accounting")
    store.set_tail_cursor("radius_accounting", "id", cursor["value"],
                           now=1.0, anchor=cursor["anchor"])
    store.commit()
    store.close()

    # A recent settled row advances the cursor, but an older-than-floor row above
    # the cursor is dropped. That drop must be visible.
    fake.rows += [_row(101, "Start", added_ago=7200),   # 2h old, floor is 1h
                  _row(102, "Start", added_ago=600)]
    with caplog.at_level("WARNING"):
        _collect(fake, cfg)

    assert _counter("Start", "psn-1") == 1  # only the in-window row
    assert "outcome=floor_backfill_gap" in caplog.text
    assert "skipped_rows=1" in caplog.text
    tail_sql = next(sql for sql, _p in fake.queries if "with new_rows" in sql.lower())
    assert "floor_skipped" in tail_sql
    assert "select count(*) from radius_accounting" in tail_sql.lower()


def test_steady_state_tail_omits_the_floor_audit_subquery(tmp_path):
    # A fresh cursor (just seeded, well within the floor window) must not carry the
    # correlated floor_skipped COUNT(*) subquery -- that is pure scan risk on a
    # 100M-row table when the cursor has not stalled.
    fake = FakeAccounting([_row(100)])
    cfg = _cfg(tmp_path)
    _collect(fake, cfg)  # seed 100

    fake.rows.append(_row(101))
    _collect(fake, cfg)

    tail_sql = next(sql for sql, _p in fake.queries if "with new_rows" in sql.lower())
    assert "select count(*) from" not in tail_sql.lower()
    assert "0 as floor_skipped" in tail_sql.lower()


def test_stale_cursor_tail_includes_the_floor_audit_subquery(tmp_path):
    fake = FakeAccounting([_row(100)])
    cfg = _cfg(tmp_path, dataconnect_tail_max_backfill_hours=1)
    _collect(fake, cfg)  # seed 100

    store = StateStore(cfg.state_db_path)
    cursor = store.tail_cursor("radius_accounting")
    store.set_tail_cursor("radius_accounting", "id", cursor["value"],
                           now=1.0, anchor=cursor["anchor"])
    store.commit()
    store.close()

    fake.rows.append(_row(101))
    _collect(fake, cfg)

    tail_sql = next(sql for sql, _p in fake.queries if "with new_rows" in sql.lower())
    assert "select count(*) from radius_accounting" in tail_sql.lower()


def test_metadata_probe_is_two_single_aggregate_statements(tmp_path):
    fake = FakeAccounting([_row(100)])
    cfg = _cfg(tmp_path)
    _collect(fake, cfg)  # seed
    fake.rows.append(_row(101))
    _collect(fake, cfg)

    meta_sqls = [sql for sql, _p in fake.queries if "with new_rows" not in sql.lower()]
    assert any("min(id)" in sql.lower() and "max(id)" not in sql.lower()
               for sql in meta_sqls)
    assert any("max(id)" in sql.lower() and "min(id)" not in sql.lower()
               for sql in meta_sqls)


def test_tail_batch_carries_meta_and_cursor_settle_floor_binds(tmp_path):
    fake = FakeAccounting([_row(100)])
    cfg = _cfg(tmp_path)
    _collect(fake, cfg)  # seed
    fake.rows.append(_row(101))
    _collect(fake, cfg)

    assert any("min(id)" in sql.lower() and "with new_rows" not in sql.lower()
               for sql, _p in fake.queries)
    tail_sql, params = next(
        (sql, p) for sql, p in fake.queries if "with new_rows" in sql.lower())
    assert "id > :hwm" in tail_sql
    assert "NUMTODSINTERVAL(:settle_seconds, 'SECOND')" in tail_sql
    assert "NUMTODSINTERVAL(:floor_hours, 'HOUR')" in tail_sql
    assert params == {"hwm": 100.0, "settle_seconds": 30, "floor_hours": 6}
