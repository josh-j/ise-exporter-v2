import types

import pytest

from ise_exporter import metrics
from ise_exporter.collectors import dataconnect_posture
from ise_exporter.state import StateStore
from ise_exporter.util import clear_metric


_VIEW = "posture_assessment_by_endpoint"
_METRICS = (
    metrics.ise_dataconnect_posture_assessment_tail_total,
    metrics.ise_dataconnect_tail_cursor_id,
    metrics.ise_dataconnect_tail_events_last_cycle,
    metrics.ise_dataconnect_tail_resets_total,
)


@pytest.fixture(autouse=True)
def _clear():
    for metric in _METRICS:
        clear_metric(metric)


def _counter(status, psn):
    # Counters expose both _total and _created samples; read the value directly.
    return metrics.ise_dataconnect_posture_assessment_tail_total.labels(
        status=status, psn=psn)._value.get()


def _cursor_gauge():
    return metrics.ise_dataconnect_tail_cursor_id.labels(view=_VIEW)._value.get()


def _events_last_cycle():
    return metrics.ise_dataconnect_tail_events_last_cycle.labels(view=_VIEW)._value.get()


class FakePosture:
    """Fake POSTURE_ASSESSMENT_BY_ENDPOINT modeling the meta + contiguous-prefix tail.

    Mirrors the accounting fake: rows carry ``added_ago`` so the fake applies the same
    settle/backfill-floor windows and the "advance only through the contiguous settled
    prefix" rule, grouped by the posture ``status x psn`` label set.
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
            bucket = groups.setdefault((r["status"], r["psn"]),
                                       {"events": 0, "max_id": 0})
            bucket["events"] += 1
            bucket["max_id"] = max(bucket["max_id"], r["id"])
        return [{"status": status, "psn": psn, "events": b["events"],
                 "max_id": b["max_id"], "floor_skipped": floor_skipped}
                for (status, psn), b in groups.items()]


def _cfg(tmp_path, **overrides):
    values = {
        "state_db_path": str(tmp_path / "state.sqlite3"),
        "dataconnect_tail_settle_seconds": 30,
        "dataconnect_tail_max_backfill_hours": 6,
    }
    values.update(overrides)
    return types.SimpleNamespace(**values)


def _row(id_, status="Compliant", psn="psn-1", added_ago=600):
    return {"id": id_, "status": status, "psn": psn, "added_ago": added_ago}


def _collect(fake, cfg):
    dataconnect_posture.collect_posture_counters(fake, cfg)


def test_cold_start_seeds_at_the_tip_and_counts_nothing(tmp_path):
    fake = FakePosture([_row(100)])
    cfg = _cfg(tmp_path)

    _collect(fake, cfg)

    assert _counter("Compliant", "psn-1") == 0
    assert _cursor_gauge() == 100
    store = StateStore(cfg.state_db_path)
    cursor = store.tail_cursor(_VIEW)
    assert cursor["kind"] == "id"
    assert cursor["value"] == 100.0
    assert cursor["anchor"] == 100.0
    store.close()


def test_tail_increments_status_psn_counters_and_advances_idempotently(tmp_path):
    fake = FakePosture([_row(100)])
    cfg = _cfg(tmp_path)
    _collect(fake, cfg)  # seed at 100

    fake.rows += [
        _row(101, "Compliant", "psn-1"),
        _row(102, "NonCompliant", "psn-1"),
        _row(103, "Compliant", "psn-2"),
    ]
    _collect(fake, cfg)

    assert _counter("Compliant", "psn-1") == 1
    assert _counter("NonCompliant", "psn-1") == 1
    assert _counter("Compliant", "psn-2") == 1
    assert _events_last_cycle() == 3
    assert _cursor_gauge() == 103

    # No new rows: cursor already past them, so no double count.
    _collect(fake, cfg)
    assert _counter("Compliant", "psn-1") == 1
    assert _counter("NonCompliant", "psn-1") == 1
    assert _events_last_cycle() == 0


def test_settled_high_id_never_skips_an_unsettled_lower_id(tmp_path):
    # The shared contiguous-prefix watermark must refuse to advance past a still-
    # unsettled lower id, even reached through the posture entry point.
    fake = FakePosture([_row(100)])
    cfg = _cfg(tmp_path)
    _collect(fake, cfg)  # seed 100

    fresh101 = _row(101, "Compliant", added_ago=5)
    fake.rows += [fresh101, _row(102, "NonCompliant", added_ago=600)]
    _collect(fake, cfg)

    assert _counter("Compliant", "psn-1") == 0    # 101 not settled
    assert _counter("NonCompliant", "psn-1") == 0  # 102 withheld behind unsettled 101
    assert _cursor_gauge() == 100                  # cursor did not advance

    fresh101["added_ago"] = 600
    _collect(fake, cfg)
    assert _counter("Compliant", "psn-1") == 1
    assert _counter("NonCompliant", "psn-1") == 1
    assert _cursor_gauge() == 102


def test_posture_tail_targets_its_own_view_and_labels(tmp_path):
    fake = FakePosture([_row(100)])
    cfg = _cfg(tmp_path)
    _collect(fake, cfg)  # seed
    fake.rows.append(_row(101))
    _collect(fake, cfg)

    # The cursor telemetry is keyed by the posture view, separate from accounting.
    store = StateStore(cfg.state_db_path)
    assert store.tail_cursor(_VIEW)["value"] == 101.0
    assert store.tail_cursor("radius_accounting") is None
    store.close()

    tail_sql, _params = next(
        (sql, p) for sql, p in fake.queries if "with new_rows" in sql.lower())
    assert "from posture_assessment_by_endpoint" in tail_sql.lower()
    assert " as status" in tail_sql.lower()
    assert " as psn" in tail_sql.lower()
