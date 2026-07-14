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
    def query(self, sql):
        lowered = sql.lower()
        if "eligible_endpoints" in lowered:
            return [{"eligible_endpoints": 10, "recently_assessed": 8,
                     "without_recent_assessment": 2}]
        if "total_endpoints" in lowered:
            return [{"total_endpoints": 12, "compliant_endpoints": 8,
                     "failed_endpoints": 2, "total_groups": 3}]
        if "count(*) as total_groups" in lowered and "posture_assessment_by_condition" in lowered:
            return [{"total_groups": 4}]
        if "count(*) as total_groups" in lowered and "latest_posture" in lowered:
            return [{"total_groups": 2}]
        if "condition_name" in lowered:
            return [{"policy": "Firewall", "policy_status": "Failed",
                     "condition_name": "Firewall enabled", "condition_status": "Failed",
                     "enforcement_name": "Optional", "endpoints": 2}]
        if "in ('noncompliant', 'failed', 'error')" in lowered:
            return [{"message_code": "8701", "posture_status": "NonCompliant",
                     "posture_policy_matched": "Firewall", "ise_node": "psn-1",
                     "endpoints": 2}]
        return [
            {"posture_status": "Compliant", "endpoint_operating_system": "Windows",
             "posture_agent_version": "5.1.18.314",
             "posture_policy_matched": "Corporate posture", "ise_node": "psn-1",
             "endpoints": 8},
            {"posture_status": "NonCompliant", "endpoint_operating_system": "Windows",
             "posture_agent_version": "5.1.18.314",
             "posture_policy_matched": "Corporate posture", "ise_node": "psn-1",
             "endpoints": 2},
            {"posture_status": "NotApplicable", "endpoint_operating_system": "Linux",
             "posture_agent_version": None, "posture_policy_matched": None,
             "ise_node": "psn-1", "endpoints": 2},
        ]


def test_collects_posture_without_endpoint_identity_labels():
    dataconnect_posture.collect(DataConnect(), types.SimpleNamespace(dataconnect_max_groups=20))

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

    assert "ROW_NUMBER() OVER" in queries["endpoints"]
    assert "PARTITION BY CASE" in queries["endpoints"]
    assert "failure_reason" not in queries["failures"].lower()
    assert "('noncompliant', 'failed', 'error')" in queries["failures"]
