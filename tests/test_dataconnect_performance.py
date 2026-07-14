import types

import pytest

from ise_exporter import metrics
from ise_exporter.collectors import dataconnect_performance
from ise_exporter.util import clear_metric


@pytest.fixture(autouse=True)
def _clear():
    for metric in dataconnect_performance._METRICS:
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
        if "key_performance_metrics" in lowered:
            return [{"ise_node": "psn-1", "radius_requests_hr": 2000,
                     "logged_to_mnt_hr": 1900, "noise_hr": 30, "suppression_hr": 70,
                     "avg_load": 25, "max_load": 60, "avg_latency_per_req": 80,
                     "avg_tps": 22}]
        if "system_summary" in lowered:
            return [{"ise_node": "psn-1", "cpu_utilization": 35,
                     "memory_utilization": 55, "diskspace_root": 20,
                     "diskspace_boot": 10, "diskspace_opt": 40,
                     "diskspace_storedconfig": 15, "diskspace_tmp": 5,
                     "diskspace_runtime": 8}]
        return [{"ise_node": "psn-1", "message_severity": "WARN",
                 "category": "RADIUS", "message_code": "5100", "events": 3,
                 "total_events": 11, "total_groups": 4}]


def test_collects_latest_node_samples_and_bounded_diagnostics():
    client = DataConnect()
    dataconnect_performance.collect(client, types.SimpleNamespace(dataconnect_max_groups=100))

    assert _rows(metrics.ise_dataconnect_psn_radius_requests_per_hour, "node") == {
        ("psn-1",): 2000}
    assert _rows(metrics.ise_dataconnect_psn_average_latency_seconds, "node") == {
        ("psn-1",): .08}
    assert _rows(metrics.ise_dataconnect_psn_load_percent, "node", "stat") == {
        ("psn-1", "avg"): 25, ("psn-1", "max"): 60}
    assert _rows(metrics.ise_dataconnect_node_cpu_utilization_percent, "node") == {
        ("psn-1",): 35}
    assert _rows(metrics.ise_dataconnect_node_disk_utilization_percent,
                 "node", "partition")[("psn-1", "/opt")] == 40
    assert _rows(metrics.ise_dataconnect_diagnostic_events,
                 "source", "message_code") == {
        ("aaa", "5100"): 3, ("system", "5100"): 3}
    assert _rows(metrics.ise_dataconnect_diagnostic_events_total, "source") == {
        ("aaa",): 11, ("system",): 11}
    assert _rows(metrics.ise_dataconnect_diagnostic_topk_groups_returned, "source") == {
        ("aaa",): 1, ("system",): 1}
    assert _rows(metrics.ise_dataconnect_diagnostic_topk_groups_total, "source") == {
        ("aaa",): 4, ("system",): 4}
    assert _rows(metrics.ise_dataconnect_diagnostic_topk_truncated, "source") == {
        ("aaa",): 1, ("system",): 1}
    assert all("INTERVAL '2' DAY" in sql for sql in client.sql)
    assert all("ROW_NUMBER()" in sql for sql in client.sql[:2])
    assert all("SUM(events) OVER () AS total_events" in sql for sql in client.sql[2:])
