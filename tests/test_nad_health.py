from datetime import datetime, timezone
import types

import pytest

from ise_exporter import metrics
from ise_exporter.collectors import nad_health
from ise_exporter.util import clear_metric


@pytest.fixture(autouse=True)
def _clear():
    for metric in nad_health._METRICS:
        clear_metric(metric)


def _rows(metric, *labels):
    return {tuple(sample.labels[label] for label in labels): sample.value
            for sample in metric.collect()[0].samples}


class Rest:
    def get_ers(self, path, params=None, get_all=False, api_name="ers"):
        assert path == "/config/networkdevice"
        assert get_all is True
        return [{"name": "campus-corp-wired"}, {"name": "branch-switch"}]


class DataConnect:
    def query(self, sql):
        assert "INTERVAL '2' DAY" in sql
        return [
            {"nad": "CAMPUS-CORP-WIRED", "status": "passed", "events": 132,
             "last_event": datetime(2026, 7, 14, 4, 30, tzinfo=timezone.utc)},
            {"nad": "campus-corp-wired", "status": "failed", "events": 29,
             "last_event": datetime(2026, 7, 14, 4, 29, tzinfo=timezone.utc)},
            {"nad": "unknown-client", "status": "failed", "events": 7,
             "last_event": datetime(2026, 7, 14, 4, 20, tzinfo=timezone.utc)},
        ]


def test_joins_configured_nads_to_activity_without_exporting_unconfigured_names():
    nad_health.collect(Rest(), DataConnect(), types.SimpleNamespace())

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
    assert metrics.ise_nad_unconfigured_authentication_events_total._value.get() == 7


def test_inventory_failure_does_not_publish_plausible_empty_health():
    class FailedRest(Rest):
        def get_ers(self, *args, **kwargs):
            return None

    nad_health.collect(FailedRest(), DataConnect(), types.SimpleNamespace())
    assert not _rows(metrics.ise_nad_seen_recently, "nad")
