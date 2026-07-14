import types

import pytest

from ise_exporter import metrics
from ise_exporter.collectors import dataconnect_endpoints
from ise_exporter.util import clear_metric


@pytest.fixture(autouse=True)
def _clear():
    for metric in dataconnect_endpoints._METRICS:
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
        if "as stale_30" in lowered:
            return [{"endpoints": 80000, "hostname": 72000, "ip": 64000,
                     "custom_attributes": 40000, "portal_user": 20000,
                     "mdm": 16000, "udid": 8000, "unknown_profile": 50,
                     "stale_30": 12000, "stale_90": 7000, "stale_180": 3000}]
        if "count(*) as endpoints from endpoints_data" in lowered:
            return [{"endpoints": 80000}]
        if "grouped_profiles" in lowered:
            return [{"endpoint_policy": "Windows10-Workstation", "endpoints": 40000,
                     "total_groups": 51}]
        if "grouped_identity" in lowered:
            return [{"identity_group_id": "group-1", "endpoints": 50000,
                     "total_groups": 12}]
        if "posture_applicable" in lowered:
            return [{"applicable": "yes", "endpoints": 60000}]
        return [{"endpoint_profile": "Windows10-Workstation", "source": "RADIUS Probe",
                 "endpoint_action_name": "Profiled", "identity_group": "Workstations",
                 "endpoints": 1000, "total_memberships": 81000, "total_groups": 75}]


def test_collects_current_inventory_and_bounded_profile_activity():
    client = DataConnect()
    dataconnect_endpoints.collect(client, types.SimpleNamespace(dataconnect_max_groups=50))

    assert metrics.ise_dataconnect_endpoints_total._value.get() == 80000
    assert metrics.ise_dataconnect_endpoints_unknown_profile_total._value.get() == 50
    assert _rows(metrics.ise_dataconnect_endpoints_by_profile, "profile") == {
        ("Windows10-Workstation",): 40000}
    assert _rows(metrics.ise_dataconnect_endpoints_by_identity_group,
                 "identity_group") == {("group-1",): 50000}
    assert _rows(metrics.ise_dataconnect_endpoints_by_posture_applicable,
                 "applicable") == {("yes",): 60000}
    assert _rows(metrics.ise_dataconnect_profile_events,
                 "profile", "source") == {("Windows10-Workstation", "RADIUS Probe"): 1000}
    assert metrics.ise_dataconnect_profiled_endpoint_group_memberships_total._value.get() == 81000
    assert _rows(metrics.ise_dataconnect_endpoint_field_populated, "field") == {
        ("hostname",): 72000.0, ("ip",): 64000.0,
        ("custom_attributes",): 40000.0, ("portal_user",): 20000.0,
        ("mdm",): 16000.0, ("udid",): 8000.0,
    }
    assert _rows(metrics.ise_dataconnect_endpoint_field_coverage_ratio, "field")[
        ("hostname",)] == 0.9
    assert _rows(metrics.ise_dataconnect_endpoints_stale, "age_days") == {
        ("30",): 12000.0, ("90",): 7000.0, ("180",): 3000.0}
    assert _rows(metrics.ise_dataconnect_endpoint_topk_groups_total, "breakdown") == {
        ("profile",): 51.0, ("identity_group",): 12.0, ("profiling",): 75.0}
    assert _rows(metrics.ise_dataconnect_endpoint_topk_truncated, "breakdown") == {
        ("profile",): 1.0, ("identity_group",): 1.0, ("profiling",): 1.0}
    profile_sql = next(sql for sql in client.sql if "profiled_endpoints_summary" in sql.lower())
    assert "NUMTODSINTERVAL(24, 'HOUR')" in profile_sql
    assert "FETCH FIRST 50" in profile_sql
    coverage_sql = next(sql for sql in client.sql if "AS stale_180" in sql)
    assert "NUMTODSINTERVAL(180, 'DAY')" in coverage_sql
    assert "AS unknown_profile" in coverage_sql
    assert len(client.sql) == 6
