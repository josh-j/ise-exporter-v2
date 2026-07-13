import types

import pytest

from ise_exporter import metrics
from ise_exporter.collectors import dataconnect_radius
from ise_exporter.util import clear_metric


@pytest.fixture(autouse=True)
def _clear():
    for metric in dataconnect_radius._METRICS:
        clear_metric(metric)


def _rows(metric, *labels):
    return {tuple(sample.labels[name] for name in labels): sample.value
            for sample in metric.collect()[0].samples}


class DataConnect:
    def __init__(self):
        self.sql = []

    def query(self, sql):
        self.sql.append(sql)
        lowered = sql.lower()
        if "from radius_authentications" in lowered:
            return [{"status": "failed", "authentication_method": "MSCHAPv2",
                     "authentication_protocol": "PEAP", "device_name": "nad-1",
                     "policy_set_name": "Wired", "ise_node": "psn-1", "events": 7,
                     "avg_response_ms": 125, "max_response_ms": 900}]
        if "group by acct_status_type" in lowered:
            return [{"acct_status_type": "Start", "device_name": "nad-1",
                     "authorization_policy": "Employee", "ise_node": "psn-1",
                     "events": 4}]
        if "avg(nvl(acct_session_time" in lowered:
            return [{"device_name": "nad-1", "ise_node": "psn-1",
                     "avg_session_seconds": 60, "max_session_seconds": 300}]
        if "dense_rank last" in lowered:
            return [{"device_name": "nad-1", "ise_node": "psn-1", "sessions": 12}]
        return [{"message_code": "5440", "network_device_name": "nad-1",
                 "authentication_method": "MSCHAPv2", "ise_node": "psn-1",
                 "events": 3}]


def test_collects_bounded_aggregated_radius_metrics():
    client = DataConnect()
    dataconnect_radius.collect(client, types.SimpleNamespace(dataconnect_max_groups=25))

    assert len(client.sql) == 5
    assert all("INTERVAL '2' DAY" in sql for sql in client.sql)
    assert all("FETCH FIRST 25" in sql for sql in client.sql)
    assert _rows(metrics.ise_dataconnect_radius_authentication_events,
                 "status", "nad") == {("failed", "nad-1"): 7}
    assert _rows(metrics.ise_dataconnect_radius_response_time_seconds,
                 "stat", "nad") == {("avg", "nad-1"): .125, ("max", "nad-1"): .9}
    assert _rows(metrics.ise_dataconnect_radius_accounting_events,
                 "event_type", "nad") == {("Start", "nad-1"): 4}
    assert _rows(metrics.ise_dataconnect_radius_accounting_session_seconds,
                 "stat", "nad") == {("avg", "nad-1"): 60, ("max", "nad-1"): 300}
    assert _rows(metrics.ise_dataconnect_radius_active_sessions,
                 "nad", "psn") == {("nad-1", "psn-1"): 12}
    assert _rows(metrics.ise_dataconnect_radius_errors,
                 "message_code", "nad") == {("5440", "nad-1"): 3}


def test_query_failure_preserves_previous_snapshot():
    metrics.ise_dataconnect_radius_errors.labels(
        message_code="old", nad="old", authentication_method="old", psn="old").set(9)

    class Broken(DataConnect):
        def query(self, sql):
            if self.sql:
                raise RuntimeError("database unavailable")
            return super().query(sql)

    dataconnect_radius.collect(Broken(), types.SimpleNamespace(dataconnect_max_groups=25))

    assert _rows(metrics.ise_dataconnect_radius_errors,
                 "message_code", "nad") == {("old", "old"): 9}
