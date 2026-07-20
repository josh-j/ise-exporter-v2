from datetime import datetime, timezone
import types

import pytest

from ise_exporter import metrics
from ise_exporter.collectors import nad_health
from ise_exporter.util import clear_metric, metric_label


@pytest.fixture(autouse=True)
def _clear():
    for metric in nad_health._METRICS:
        clear_metric(metric)


def _rows(metric, *labels):
    return {tuple(sample.labels[label] for label in labels): sample.value
            for sample in metric.collect()[0].samples}


DEVICES = [{"name": "campus-corp-wired"}, {"name": "branch-switch"}]


class DataConnect:
    def query(self, sql):
        assert "NUMTODSINTERVAL(6, 'HOUR')" in sql
        assert "FROM radius_authentication_summary" in sql
        assert "FROM radius_authentications" not in sql
        return [
            {"nad": "CAMPUS-CORP-WIRED", "passed_events": 132, "failed_events": 29,
             "last_event": datetime(2026, 7, 14, 4, 30, tzinfo=timezone.utc),
             "total_groups": 2},
            {"nad": "unknown-client", "passed_events": 2, "failed_events": 5,
             "last_event": datetime(2026, 7, 14, 4, 20, tzinfo=timezone.utc),
             "total_groups": 2},
        ]


def test_joins_configured_nads_to_activity_without_exporting_unconfigured_names():
    nad_health.collect(DEVICES, DataConnect(), types.SimpleNamespace())

    assert _rows(metrics.ise_nad_seen_recently, "nad") == {
        ("campus-corp-wired",): 1,
        ("branch-switch",): 0,
    }
    assert _rows(metrics.ise_nad_authentication_events, "nad", "status") == {
        ("campus-corp-wired", "passed"): 132,
        ("campus-corp-wired", "failed"): 29,
    }
    assert _rows(metrics.ise_nad_last_authentication_timestamp, "nad")[
        ("campus-corp-wired",)] == pytest.approx(1784003400)
    assert _rows(metrics.ise_nad_last_authentication_timestamp, "nad")[
        ("branch-switch",)] == 0
    assert metrics.ise_nad_unconfigured_authentication_events_topk._value.get() == 7
    assert metrics.ise_nad_inventory_selected._value.get() == 2
    assert metrics.ise_nad_inventory_total._value.get() == 2
    assert metrics.ise_nad_inventory_truncated._value.get() == 0
    assert metrics.ise_nad_activity_groups_returned._value.get() == 2
    assert metrics.ise_nad_activity_groups_total._value.get() == 2
    assert metrics.ise_nad_activity_groups_truncated._value.get() == 0


class SettableActivity:
    """Fake Data Connect returning a settable top-K activity batch per cycle."""

    def __init__(self):
        self.rows = []

    def query(self, _sql):
        return list(self.rows)


def _activity_row(nad, last_event, passed=1, failed=0, total_groups=1):
    return {"nad": nad, "passed_events": passed, "failed_events": failed,
            "last_event": last_event, "total_groups": total_groups}


def test_accumulator_gives_full_inventory_dead_switch_coverage_across_cycles(tmp_path):
    devices = [{"name": "switch-a"}, {"name": "switch-b"}, {"name": "switch-c"}]
    cfg = types.SimpleNamespace(state_db_path=str(tmp_path / "state.sqlite3"))
    client = SettableActivity()
    now = datetime.now(timezone.utc).timestamp()

    def at(days_ago):
        return datetime.fromtimestamp(now - days_ago * 86400, tz=timezone.utc)

    # Cycle 1: only switch-a authenticates, 10 days ago.
    client.rows = [_activity_row("SWITCH-A", at(10))]
    nad_health.collect(devices, client, cfg)

    activity = _rows(metrics.ise_nad_activity_last_authentication_timestamp, "nad")
    assert activity[("switch-a",)] == pytest.approx(now - 10 * 86400, abs=5)
    assert activity[("switch-b",)] == 0
    assert activity[("switch-c",)] == 0
    assert metrics.ise_nad_activity_tracked_total._value.get() == 1
    assert metrics.ise_nad_activity_never_authenticated_total._value.get() == 2

    # Cycle 2: only switch-b authenticates (1 day ago). switch-a has dropped out of
    # the top-K window, but its accumulated last-auth must persist — that is the
    # whole point of the cache versus the bounded per-cycle top-K signal.
    client.rows = [_activity_row("SWITCH-B", at(1))]
    nad_health.collect(devices, client, cfg)

    activity = _rows(metrics.ise_nad_activity_last_authentication_timestamp, "nad")
    assert activity[("switch-a",)] == pytest.approx(now - 10 * 86400, abs=5)
    assert activity[("switch-b",)] == pytest.approx(now - 1 * 86400, abs=5)
    assert activity[("switch-c",)] == 0
    assert metrics.ise_nad_activity_tracked_total._value.get() == 2
    assert metrics.ise_nad_activity_never_authenticated_total._value.get() == 1
    assert _rows(metrics.ise_nad_activity_silent, "threshold_days") == {
        ("7",): 1,   # switch-a (10d) is silent past 7d; switch-b (1d) is not
        ("30",): 0,
    }

    # Cycle 3: switch-a reappears with an OLDER timestamp; the high-water wins.
    client.rows = [_activity_row("SWITCH-A", at(40))]
    nad_health.collect(devices, client, cfg)
    activity = _rows(metrics.ise_nad_activity_last_authentication_timestamp, "nad")
    assert activity[("switch-a",)] == pytest.approx(now - 10 * 86400, abs=5)


def test_accumulator_prunes_decommissioned_nads(tmp_path):
    cfg = types.SimpleNamespace(state_db_path=str(tmp_path / "state.sqlite3"))
    client = SettableActivity()
    event = datetime(2026, 7, 14, tzinfo=timezone.utc)

    client.rows = [_activity_row("OLD-SWITCH", event)]
    nad_health.collect([{"name": "old-switch"}], client, cfg)
    assert metrics.ise_nad_activity_cache_entries._value.get() == 1

    # old-switch leaves the inventory; the accumulator row is pruned with it.
    client.rows = [_activity_row("NEW-SWITCH", event)]
    nad_health.collect([{"name": "new-switch"}], client, cfg)
    assert metrics.ise_nad_activity_cache_entries._value.get() == 1
    activity = _rows(metrics.ise_nad_activity_last_authentication_timestamp, "nad")
    assert set(activity) == {("new-switch",)}


def test_inventory_failure_does_not_publish_plausible_empty_health():
    nad_health.collect(None, DataConnect(), types.SimpleNamespace())
    assert not _rows(metrics.ise_nad_seen_recently, "nad")


def test_raw_configured_nad_name_is_bounded_only_at_metric_boundary():
    raw_name = "switch-" + "x" * 400

    class LongNameActivity:
        def query(self, _sql):
            return [{
                "nad": raw_name.upper(), "passed_events": 1, "failed_events": 0,
                "last_event": datetime(2026, 7, 14, tzinfo=timezone.utc),
                "total_groups": 1,
            }]

    nad_health.collect(
        [{"name": raw_name}], LongNameActivity(), types.SimpleNamespace())

    bounded = metric_label(raw_name)
    assert len(bounded.encode("utf-8")) <= 256
    assert _rows(metrics.ise_nad_authentication_events, "nad", "status") == {
        (bounded, "passed"): 1,
        (bounded, "failed"): 0,
    }


def test_nad_health_bounds_query_and_per_device_series_to_group_ceiling():
    devices = [{"name": f"switch-{index}"} for index in range(4)]

    class BoundedActivity:
        def query(self, sql):
            assert "COUNT(*) OVER () AS total_groups" in sql
            assert "WHERE group_rank <= 2" in sql
            return [
                {"nad": "switch-3", "passed_events": 10, "failed_events": 0,
                 "last_event": datetime(2026, 7, 14, tzinfo=timezone.utc),
                 "total_groups": 3},
                {"nad": "unknown-client", "passed_events": 5, "failed_events": 1,
                 "last_event": datetime(2026, 7, 14, tzinfo=timezone.utc),
                 "total_groups": 3},
            ]

    nad_health.collect(
        devices, BoundedActivity(),
        types.SimpleNamespace(dataconnect_max_groups=2))

    assert set(_rows(metrics.ise_nad_seen_recently, "nad")) == {
        ("switch-3",), ("switch-0",)}
    assert metrics.ise_nad_inventory_selected._value.get() == 2
    assert metrics.ise_nad_inventory_total._value.get() == 4
    assert metrics.ise_nad_inventory_truncated._value.get() == 1
    assert metrics.ise_nad_activity_groups_returned._value.get() == 2
    assert metrics.ise_nad_activity_groups_total._value.get() == 3
    assert metrics.ise_nad_activity_groups_truncated._value.get() == 1
    assert metrics.ise_nad_unconfigured_authentication_events_topk._value.get() == 6
