import types

import pytest

from ise_exporter import metrics
from ise_exporter.collectors import dataconnect_radius
from ise_exporter.util import clear_metric


@pytest.fixture(autouse=True)
def _clear():
    for metric in dataconnect_radius._METRICS:
        clear_metric(metric)
    for metric in (
        metrics.ise_dataconnect_radius_authentication_events_total,
        metrics.ise_dataconnect_radius_accounting_events_total,
        metrics.ise_dataconnect_radius_active_sessions_total,
        metrics.ise_dataconnect_radius_active_session_stale_cutoff_seconds,
        metrics.ise_dataconnect_radius_errors_total,
    ):
        metric.set(0)


def _rows(metric, *labels):
    return {tuple(sample.labels[name] for name in labels): sample.value
            for sample in metric.collect()[0].samples}


class DataConnect:
    def __init__(self):
        self.sql = []

    def query(self, sql):
        self.sql.append(sql)
        lowered = sql.lower()
        if "count(distinct calling_station_id)" in lowered:
            return [{"distinct_endpoints": 81, "distinct_users": 54}]
        if "as failure_class" in lowered:
            return [{"failure_class": "credentials", "policy_set_name": "Wired",
                     "location": "Campus", "events": 9}]
        if "sum(events)" in lowered and "failure_reason" in lowered:
            return [{"total_events": 11, "total_groups": 2}]
        if "sum(events)" in lowered and "radius_authentications" in lowered:
            return [{"total_events": 107, "total_groups": 30}]
        if "count(*) as total_groups" in lowered and "response_time is not null" in lowered:
            return [{"total_groups": 1}]
        if "count(response_time)" in lowered:
            return [{"status": "failed", "device_name": "nad-1", "ise_node": "psn-1",
                     "samples": 4, "avg_response_ms": 200, "max_response_ms": 900}]
        if "from radius_authentications" in lowered:
            return [
                {"status": "failed", "authentication_method": "MSCHAPv2",
                 "authentication_protocol": "PEAP", "device_name": "nad-1",
                 "policy_set_name": "Wired", "ise_node": "psn-1", "events": 7},
                {"status": "failed", "authentication_method": "EAP-TLS",
                 "authentication_protocol": "EAP-TLS", "device_name": "nad-1",
                 "policy_set_name": "Wired", "ise_node": "psn-1", "events": 3},
            ]
        if "sum(events)" in lowered and "radius_accounting" in lowered:
            return [{"total_events": 200, "total_groups": 2}]
        if "group by acct_status_type" in lowered:
            return [{"acct_status_type": "Start", "device_name": "nad-1",
                     "authorization_policy": "Employee", "ise_node": "psn-1",
                     "events": 4}]
        if "count(*) as total_groups" in lowered and "acct_session_time" in lowered:
            return [{"total_groups": 1}]
        if "avg(acct_session_time" in lowered:
            return [{"device_name": "nad-1", "ise_node": "psn-1",
                     "avg_session_seconds": 60, "max_session_seconds": 300}]
        if "count(*) as total_sessions" in lowered:
            return [{"total_sessions": 37, "total_groups": 1}]
        if "active_accounting" in lowered:
            return [{"device_name": "nad-1", "ise_node": "psn-1", "sessions": 12}]
        if "sum(events)" in lowered and "radius_errors_view" in lowered:
            return [{"total_events": 12, "total_groups": 3}]
        return [{"message_code": "5440", "network_device_name": "nad-1",
                 "authentication_method": "MSCHAPv2", "ise_node": "psn-1",
                 "events": 3}]


def test_collects_bounded_aggregated_radius_metrics():
    client = DataConnect()
    dataconnect_radius.collect(client, types.SimpleNamespace(dataconnect_max_groups=25))

    assert len(client.sql) == 15
    assert all("INTERVAL '2' DAY" in sql for sql in client.sql)
    assert sum("FETCH FIRST 25" in sql for sql in client.sql) == 7
    assert _rows(metrics.ise_dataconnect_radius_authentication_events,
                 "authentication_method", "nad") == {
        ("MSCHAPv2", "nad-1"): 7, ("EAP-TLS", "nad-1"): 3}
    assert _rows(metrics.ise_dataconnect_radius_response_time_seconds,
                 "stat", "nad") == {("avg", "nad-1"): .2, ("max", "nad-1"): .9}
    assert _rows(metrics.ise_dataconnect_radius_response_time_samples,
                 "status", "nad") == {("failed", "nad-1"): 4}
    assert _rows(metrics.ise_dataconnect_radius_accounting_events,
                 "event_type", "nad") == {("Start", "nad-1"): 4}
    assert _rows(metrics.ise_dataconnect_radius_accounting_session_seconds,
                 "stat", "nad") == {("avg", "nad-1"): 60, ("max", "nad-1"): 300}
    assert _rows(metrics.ise_dataconnect_radius_active_sessions,
                 "nad", "psn") == {("nad-1", "psn-1"): 12}
    assert _rows(metrics.ise_dataconnect_radius_errors,
                 "message_code", "nad") == {("5440", "nad-1"): 3}
    assert metrics.ise_dataconnect_radius_authentication_events_total._value.get() == 107
    assert metrics.ise_dataconnect_radius_distinct_endpoints_total._value.get() == 81
    assert metrics.ise_dataconnect_radius_distinct_users_total._value.get() == 54
    assert _rows(metrics.ise_dataconnect_radius_failure_events,
                 "failure_class", "policy_set", "location") == {
        ("credentials", "Wired", "Campus"): 9}
    assert metrics.ise_dataconnect_radius_accounting_events_total._value.get() == 200
    assert metrics.ise_dataconnect_radius_active_sessions_total._value.get() == 37
    assert metrics.ise_dataconnect_radius_active_session_stale_cutoff_seconds._value.get() == 3600
    assert metrics.ise_dataconnect_radius_errors_total._value.get() == 12
    assert _rows(metrics.ise_dataconnect_radius_topk_groups_returned,
                 "breakdown")[("authentication",)] == 2
    assert _rows(metrics.ise_dataconnect_radius_topk_groups_total,
                 "breakdown")[("authentication",)] == 30
    assert _rows(metrics.ise_dataconnect_radius_topk_truncated,
                 "breakdown")[("authentication",)] == 1

    active_sql = next(sql for sql in client.sql
                      if "select device_name, ise_node, count(*) as sessions" in sql.lower())
    assert "audit_session_id" in active_sql
    assert "session_id" in active_sql
    assert "nas_ip_address" in active_sql
    assert "NUMTODSINTERVAL(60, 'MINUTE')" in active_sql


def test_latency_query_uses_one_matching_group_and_excludes_nulls():
    queries = dataconnect_radius._queries(25)

    assert "NVL(response_time, 0)" not in queries["latency"]
    assert "response_time IS NOT NULL" in queries["latency"]
    assert "authentication_method" not in queries["latency"].split("GROUP BY", 1)[1]
    assert "policy_set_name" not in queries["latency"].split("GROUP BY", 1)[1]


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
