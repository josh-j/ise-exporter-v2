import types

import pytest

from ise_exporter import metrics
from ise_exporter.collectors import dataconnect_posture
from ise_exporter.util import clear_metric


@pytest.fixture(autouse=True)
def _clear():
    for metric in dataconnect_posture._METRICS:
        clear_metric(metric)
    for metric in (
        metrics.ise_dataconnect_posture_assessed_endpoints_total,
        metrics.ise_dataconnect_posture_compliant_endpoints_total,
        metrics.ise_dataconnect_posture_failed_endpoints_total,
        metrics.ise_dataconnect_posture_compliance_ratio,
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
        if "grouped_conditions" in lowered:
            return [{"policy": "Firewall", "policy_status": "Failed",
                     "condition_name": "Firewall enabled", "condition_status": "Failed",
                     "enforcement_name": "Optional", "endpoints": 2,
                     "total_groups": 4}]
        return [
            {"breakdown": "endpoints", "posture_status": "Compliant",
             "endpoint_operating_system": "Windows",
             "posture_agent_version": "5.1.18.314",
             "posture_policy_matched": "Corporate posture", "ise_node": "psn-1",
             "endpoints": 8, "total_endpoints": 12, "compliant_endpoints": 8,
             "failed_endpoints": 2, "total_groups": 3},
            {"breakdown": "endpoints", "posture_status": "NonCompliant",
             "endpoint_operating_system": "Windows",
             "posture_agent_version": "5.1.18.314",
             "posture_policy_matched": "Corporate posture", "ise_node": "psn-1",
             "endpoints": 2, "total_endpoints": 12, "compliant_endpoints": 8,
             "failed_endpoints": 2, "total_groups": 3},
            {"breakdown": "endpoints", "posture_status": "NotApplicable",
             "endpoint_operating_system": "Linux",
             "posture_agent_version": None, "posture_policy_matched": None,
             "ise_node": "psn-1", "endpoints": 2, "total_endpoints": 12,
             "compliant_endpoints": 8, "failed_endpoints": 2, "total_groups": 3},
            {"breakdown": "failures", "message_code": "8701",
             "posture_status": "NonCompliant",
             "posture_policy_matched": "Firewall", "ise_node": "psn-1",
             "endpoints": 2, "total_groups": 2},
            {"breakdown": "coverage", "eligible_endpoints": 10,
             "recently_assessed": 8, "without_recent_assessment": 2},
        ]


def test_collects_posture_without_endpoint_identity_labels():
    client = DataConnect()
    dataconnect_posture.collect(client, types.SimpleNamespace(dataconnect_max_groups=20))

    assert len(client.sql) == 2

    assert _rows(metrics.ise_dataconnect_posture_endpoint_assessments,
                 "status", "os", "agent_version") == {
        ("Compliant", "Windows", "5.1.18.314"): 8,
        ("NonCompliant", "Windows", "5.1.18.314"): 2,
        ("NotApplicable", "Linux", "Unknown"): 2,
    }
    assert _rows(metrics.ise_dataconnect_posture_condition_assessments,
                 "policy", "condition", "condition_status") == {
        ("Firewall", "Firewall enabled", "Failed"): 2}
    assert _rows(metrics.ise_dataconnect_posture_failures,
                 "message_code", "status") == {("8701", "NonCompliant"): 2}
    assert metrics.ise_dataconnect_posture_assessed_endpoints_total._value.get() == 12
    assert metrics.ise_dataconnect_posture_eligible_endpoints_total._value.get() == 10
    assert metrics.ise_dataconnect_posture_eligible_recently_assessed_total._value.get() == 8
    assert metrics.ise_dataconnect_posture_eligible_without_recent_assessment_total._value.get() == 2
    assert metrics.ise_dataconnect_posture_eligible_recent_assessment_ratio._value.get() == .8
    assert metrics.ise_dataconnect_posture_compliant_endpoints_total._value.get() == 8
    assert metrics.ise_dataconnect_posture_failed_endpoints_total._value.get() == 2
    assert metrics.ise_dataconnect_posture_compliance_ratio._value.get() == .8
    assert _rows(metrics.ise_dataconnect_posture_topk_truncated,
                 "breakdown") == {
        ("endpoints",): 0, ("conditions",): 1, ("failures",): 1}
    for metric in dataconnect_posture._METRICS:
        assert "endpoint" not in metric._labelnames
        assert "username" not in metric._labelnames


def test_posture_uses_latest_endpoint_state_and_explicit_failure_statuses():
    queries = dataconnect_posture._queries(20)

    assert all("NUMTODSINTERVAL(6, 'HOUR')" in sql for sql in queries.values())
    assert set(queries) == {"snapshot", "conditions"}
    assert "ROW_NUMBER() OVER" in queries["snapshot"]
    assert "PARTITION BY CASE" in queries["snapshot"]
    assert "/*+ MATERIALIZE */" in queries["snapshot"]
    assert "GROUP BY GROUPING SETS" in queries["snapshot"]
    assert "'mac:' || UPPER(REPLACE(REPLACE(REPLACE(" in queries["snapshot"]
    assert "p.endpoint_mac_address = e.mac_address" not in queries["snapshot"]
    assert queries["snapshot"].count("UPPER(REPLACE(REPLACE(REPLACE(") >= 3
    assert "failure_reason" not in queries["snapshot"].lower()
    assert "('noncompliant', 'failed', 'error')" in queries["snapshot"]
