import types

import pytest

from ise_exporter import metrics
from ise_exporter.collectors import dataconnect_radius
from ise_exporter.state import StateStore
from ise_exporter.util import clear_metric


_VIEW = "radius_authentications"
_METRICS = (
    metrics.ise_dataconnect_radius_authentication_tail_total,
    metrics.ise_dataconnect_tail_cursor_id,
    metrics.ise_dataconnect_tail_events_last_cycle,
    metrics.ise_dataconnect_tail_resets_total,
)


@pytest.fixture(autouse=True)
def _clear():
    for metric in _METRICS:
        clear_metric(metric)


def _counter(result, psn):
    # Counters expose both _total and _created samples; read the value directly.
    return metrics.ise_dataconnect_radius_authentication_tail_total.labels(
        result=result, psn=psn)._value.get()


def _cursor_gauge():
    return metrics.ise_dataconnect_tail_cursor_id.labels(view=_VIEW)._value.get()


def _events_last_cycle():
    return metrics.ise_dataconnect_tail_events_last_cycle.labels(view=_VIEW)._value.get()


class FakeAuth:
    """Fake RADIUS_AUTHENTICATIONS modeling the meta + contiguous-prefix tail.

    Rows carry the numeric ``failed`` flag and ``added_ago`` seconds. ``_tail``
    reproduces the SQL's FAILED -> passed/failed mapping and the "advance only through
    the contiguous settled prefix" rule, grouped by the ``result x psn`` label set.
    ``schema`` defaults to None (permissive), like the other tail collectors' fakes.
    """

    def __init__(self, rows=None, schema=None):
        self.rows = list(rows or [])
        self.schema = schema
        self.queries = []

    def query(self, sql, parameters=None):
        self.queries.append((sql, parameters))
        if "with new_rows" in sql.lower():
            p = parameters or {}
            return self._tail(p["hwm"], p["settle_seconds"], p["floor_hours"] * 3600)
        ids = [r["id"] for r in self.rows]
        return [{"min_id": min(ids) if ids else None,
                 "max_id": max(ids) if ids else None}]

    @staticmethod
    def _result(failed):
        return "failed" if failed == 1 else "passed" if failed == 0 else "unknown"

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
            key = (self._result(r["failed"]), r["psn"])
            bucket = groups.setdefault(key, {"events": 0, "max_id": 0})
            bucket["events"] += 1
            bucket["max_id"] = max(bucket["max_id"], r["id"])
        return [{"result": result, "psn": psn, "events": b["events"],
                 "max_id": b["max_id"], "floor_skipped": floor_skipped}
                for (result, psn), b in groups.items()]


def _cfg(tmp_path, **overrides):
    values = {
        "state_db_path": str(tmp_path / "state.sqlite3"),
        "dataconnect_tail_settle_seconds": 30,
        "dataconnect_tail_max_backfill_hours": 6,
    }
    values.update(overrides)
    return types.SimpleNamespace(**values)


def _row(id_, failed=0, psn="psn-1", added_ago=600):
    return {"id": id_, "failed": failed, "psn": psn, "added_ago": added_ago}


def _collect(fake, cfg):
    dataconnect_radius.collect_authentication_counters(fake, cfg)


def test_cold_start_seeds_at_the_tip_and_counts_nothing(tmp_path):
    fake = FakeAuth([_row(100)])
    cfg = _cfg(tmp_path)

    _collect(fake, cfg)

    assert _counter("passed", "psn-1") == 0
    assert _cursor_gauge() == 100
    store = StateStore(cfg.state_db_path)
    cursor = store.tail_cursor(_VIEW)
    assert cursor["kind"] == "id"
    assert cursor["value"] == 100.0
    assert cursor["anchor"] == 100.0
    store.close()


def test_tail_maps_failed_flag_to_result_and_advances(tmp_path):
    fake = FakeAuth([_row(100)])
    cfg = _cfg(tmp_path)
    _collect(fake, cfg)  # seed at 100

    fake.rows += [
        _row(101, failed=0, psn="psn-1"),   # passed
        _row(102, failed=1, psn="psn-1"),   # failed
        _row(103, failed=0, psn="psn-2"),   # passed on another PSN
    ]
    _collect(fake, cfg)

    assert _counter("passed", "psn-1") == 1
    assert _counter("failed", "psn-1") == 1
    assert _counter("passed", "psn-2") == 1
    assert _events_last_cycle() == 3
    assert _cursor_gauge() == 103

    # No new rows: cursor already past them, so no double count.
    _collect(fake, cfg)
    assert _counter("passed", "psn-1") == 1
    assert _counter("failed", "psn-1") == 1
    assert _events_last_cycle() == 0


def test_settled_high_id_never_skips_an_unsettled_lower_id(tmp_path):
    # The shared contiguous-prefix watermark reached through the auth entry point.
    fake = FakeAuth([_row(100)])
    cfg = _cfg(tmp_path)
    _collect(fake, cfg)  # seed 100

    fresh101 = _row(101, failed=0, added_ago=5)
    fake.rows += [fresh101, _row(102, failed=1, added_ago=600)]
    _collect(fake, cfg)

    assert _counter("passed", "psn-1") == 0  # 101 not settled
    assert _counter("failed", "psn-1") == 0  # 102 withheld behind unsettled 101
    assert _cursor_gauge() == 100            # cursor did not advance

    fresh101["added_ago"] = 600
    _collect(fake, cfg)
    assert _counter("passed", "psn-1") == 1
    assert _counter("failed", "psn-1") == 1
    assert _cursor_gauge() == 102


def test_result_label_is_a_derived_case_expression_in_sql(tmp_path):
    fake = FakeAuth([_row(100)])
    cfg = _cfg(tmp_path)
    _collect(fake, cfg)  # seed
    fake.rows.append(_row(101))
    _collect(fake, cfg)

    tail_sql, _params = next(
        (sql, p) for sql, p in fake.queries if "with new_rows" in sql.lower())
    lowered = tail_sql.lower()
    assert "from radius_authentications" in lowered
    # result comes from a CASE over FAILED, not a raw column projection.
    assert "case when failed = 1 then 'failed'" in lowered
    assert " as result" in lowered
    assert " as psn" in lowered


def test_self_skips_when_live_schema_shows_no_id_column(tmp_path):
    # A discovered schema whose RADIUS_AUTHENTICATIONS has no ID must not run an
    # id-tail (which would fail every cycle on ORA-00904); the engine self-skips.
    schema = {"RADIUS_AUTHENTICATIONS": {"TIMESTAMP": {}, "FAILED": {}, "ISE_NODE": {}}}
    fake = FakeAuth([_row(100), _row(101, failed=1)], schema=schema)
    cfg = _cfg(tmp_path)

    _collect(fake, cfg)

    assert _counter("passed", "psn-1") == 0
    assert _counter("failed", "psn-1") == 0
    assert _events_last_cycle() == 0
    # No cursor was created and no tail/meta query was issued.
    store = StateStore(cfg.state_db_path)
    assert store.tail_cursor(_VIEW) is None
    store.close()
    assert fake.queries == []


def test_runs_when_live_schema_has_the_id_column(tmp_path):
    schema = {"RADIUS_AUTHENTICATIONS": {
        "ID": {}, "TIMESTAMP": {}, "FAILED": {}, "ISE_NODE": {}}}
    fake = FakeAuth([_row(100)], schema=schema)
    cfg = _cfg(tmp_path)

    _collect(fake, cfg)  # seed at the tip
    fake.rows.append(_row(101, failed=1))
    _collect(fake, cfg)

    assert _counter("failed", "psn-1") == 1
    assert _cursor_gauge() == 101
