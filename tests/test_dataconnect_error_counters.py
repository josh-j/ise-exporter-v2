import types

import pytest

from ise_exporter import metrics
from ise_exporter.collectors import dataconnect_radius
from ise_exporter.state import StateStore
from ise_exporter.util import clear_metric


_VIEW = "radius_errors_view"
_METRICS = (
    metrics.ise_dataconnect_radius_error_tail_total,
    metrics.ise_dataconnect_tail_cursor_id,
    metrics.ise_dataconnect_tail_events_last_cycle,
    metrics.ise_dataconnect_tail_resets_total,
)


@pytest.fixture(autouse=True)
def _clear():
    for metric in _METRICS:
        clear_metric(metric)


def _counter(message_code, psn):
    # Counters expose both _total and _created samples; read the value directly.
    return metrics.ise_dataconnect_radius_error_tail_total.labels(
        message_code=message_code, psn=psn)._value.get()


def _cursor_gauge():
    return metrics.ise_dataconnect_tail_cursor_id.labels(view=_VIEW)._value.get()


def _events_last_cycle():
    return metrics.ise_dataconnect_tail_events_last_cycle.labels(view=_VIEW)._value.get()


class FakeErrors:
    """Fake RADIUS_ERRORS_VIEW modeling the meta + contiguous-prefix tail, grouped by
    the ``message_code x psn`` label set. ``schema`` defaults to None (permissive)."""

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
            bucket = groups.setdefault((r["message_code"], r["psn"]),
                                       {"events": 0, "max_id": 0})
            bucket["events"] += 1
            bucket["max_id"] = max(bucket["max_id"], r["id"])
        return [{"message_code": code, "psn": psn, "events": b["events"],
                 "max_id": b["max_id"], "floor_skipped": floor_skipped}
                for (code, psn), b in groups.items()]


def _cfg(tmp_path, **overrides):
    values = {
        "state_db_path": str(tmp_path / "state.sqlite3"),
        "dataconnect_tail_settle_seconds": 30,
        "dataconnect_tail_max_backfill_hours": 6,
    }
    values.update(overrides)
    return types.SimpleNamespace(**values)


def _row(id_, message_code="5411", psn="psn-1", added_ago=600):
    return {"id": id_, "message_code": message_code, "psn": psn, "added_ago": added_ago}


def _collect(fake, cfg):
    dataconnect_radius.collect_error_counters(fake, cfg)


def test_cold_start_seeds_at_the_tip_and_counts_nothing(tmp_path):
    fake = FakeErrors([_row(100)])
    cfg = _cfg(tmp_path)

    _collect(fake, cfg)

    assert _counter("5411", "psn-1") == 0
    assert _cursor_gauge() == 100
    store = StateStore(cfg.state_db_path)
    assert store.tail_cursor(_VIEW) == {"kind": "id", "value": 100.0, "anchor": 100.0}
    store.close()


def test_empty_view_seeds_at_zero_and_counts_forward(tmp_path):
    # RADIUS_ERRORS_VIEW is often empty (no errors); MIN/MAX(id) are NULL -> seed 0.
    fake = FakeErrors([])
    cfg = _cfg(tmp_path)
    _collect(fake, cfg)
    assert _cursor_gauge() == 0

    fake.rows.append(_row(1, "5440"))
    _collect(fake, cfg)
    assert _counter("5440", "psn-1") == 1
    assert _cursor_gauge() == 1


def test_tail_increments_message_code_psn_counters_and_advances(tmp_path):
    fake = FakeErrors([_row(100)])
    cfg = _cfg(tmp_path)
    _collect(fake, cfg)  # seed at 100

    fake.rows += [
        _row(101, "5411", "psn-1"),
        _row(102, "5411", "psn-1"),
        _row(103, "5440", "psn-2"),
    ]
    _collect(fake, cfg)

    assert _counter("5411", "psn-1") == 2
    assert _counter("5440", "psn-2") == 1
    assert _events_last_cycle() == 3
    assert _cursor_gauge() == 103

    _collect(fake, cfg)  # no new rows
    assert _counter("5411", "psn-1") == 2
    assert _events_last_cycle() == 0


def test_targets_its_own_view_and_labels(tmp_path):
    fake = FakeErrors([_row(100)])
    cfg = _cfg(tmp_path)
    _collect(fake, cfg)
    fake.rows.append(_row(101))
    _collect(fake, cfg)

    tail_sql, _params = next(
        (sql, p) for sql, p in fake.queries if "with new_rows" in sql.lower())
    lowered = tail_sql.lower()
    assert "from radius_errors_view" in lowered
    assert " as message_code" in lowered
    assert " as psn" in lowered


def test_self_skips_when_live_schema_shows_no_id_column(tmp_path):
    schema = {"RADIUS_ERRORS_VIEW": {"TIMESTAMP": {}, "MESSAGE_CODE": {}, "ISE_NODE": {}}}
    fake = FakeErrors([_row(100), _row(101, "5440")], schema=schema)
    cfg = _cfg(tmp_path)

    _collect(fake, cfg)

    assert _counter("5411", "psn-1") == 0
    assert _events_last_cycle() == 0
    store = StateStore(cfg.state_db_path)
    assert store.tail_cursor(_VIEW) is None
    store.close()
    assert fake.queries == []
