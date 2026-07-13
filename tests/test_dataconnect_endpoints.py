import types

import pytest

from ise_exporter import metrics
from ise_exporter.collectors import dataconnect_endpoints
from ise_exporter.util import clear_metric


@pytest.fixture(autouse=True)
def _clear():
    for metric in dataconnect_endpoints._METRICS:
        clear_metric(metric)
    metrics.ise_dataconnect_endpoints_total.set(0)


def _rows(metric, *labels):
    return {tuple(sample.labels[name] for name in labels): sample.value
            for sample in metric.collect()[0].samples}


class DataConnect:
    def __init__(self):
        self.sql = []

    def query(self, sql):
        self.sql.append(sql)
        lowered = sql.lower()
        if "count(*) as endpoints from endpoints_data" in lowered:
            return [{"endpoints": 80000}]
        if "group by endpoint_policy" in lowered:
            return [{"endpoint_policy": "Windows10-Workstation", "endpoints": 40000}]
        if "group by identity_group_id" in lowered:
            return [{"identity_group_id": "group-1", "endpoints": 50000}]
        if "posture_applicable" in lowered:
            return [{"applicable": "yes", "endpoints": 60000}]
        return [{"endpoint_profile": "Windows10-Workstation", "source": "RADIUS Probe",
                 "endpoint_action_name": "Profiled", "identity_group": "Workstations",
                 "endpoints": 1000}]


def test_collects_current_inventory_and_bounded_profile_activity():
    client = DataConnect()
    dataconnect_endpoints.collect(client, types.SimpleNamespace(dataconnect_max_groups=50))

    assert metrics.ise_dataconnect_endpoints_total._value.get() == 80000
    assert _rows(metrics.ise_dataconnect_endpoints_by_profile, "profile") == {
        ("Windows10-Workstation",): 40000}
    assert _rows(metrics.ise_dataconnect_endpoints_by_identity_group,
                 "identity_group") == {("group-1",): 50000}
    assert _rows(metrics.ise_dataconnect_endpoints_by_posture_applicable,
                 "applicable") == {("yes",): 60000}
    assert _rows(metrics.ise_dataconnect_profile_events,
                 "profile", "source") == {("Windows10-Workstation", "RADIUS Probe"): 1000}
    profile_sql = next(sql for sql in client.sql if "profiled_endpoints_summary" in sql.lower())
    assert "INTERVAL '2' DAY" in profile_sql
    assert "FETCH FIRST 50" in profile_sql
