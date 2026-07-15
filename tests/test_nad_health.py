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
