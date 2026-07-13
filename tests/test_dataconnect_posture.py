import types

import pytest

from ise_exporter import metrics
from ise_exporter.collectors import dataconnect_posture
from ise_exporter.util import clear_metric


@pytest.fixture(autouse=True)
def _clear():
    for metric in dataconnect_posture._METRICS:
        clear_metric(metric)


def _rows(metric, *labels):
    return {tuple(sample.labels[name] for name in labels): sample.value
            for sample in metric.collect()[0].samples}


class DataConnect:
    def query(self, sql):
        lowered = sql.lower()
        if "condition_name" in lowered:
            return [{"policy": "Firewall", "policy_status": "Failed",
                     "condition_name": "Firewall enabled", "condition_status": "Failed",
                     "enforcement_name": "Optional", "endpoints": 2}]
        if "lower(nvl(posture_status" in lowered:
            return [{"message_code": "8701", "posture_status": "NonCompliant",
                     "posture_policy_matched": "Firewall", "ise_node": "psn-1",
                     "endpoints": 2}]
        return [{"posture_status": "Compliant", "endpoint_operating_system": "Windows",
                 "posture_agent_version": "5.1.18.314",
                 "posture_policy_matched": "Corporate posture", "ise_node": "psn-1",
                 "endpoints": 10}]


def test_collects_posture_without_endpoint_identity_labels():
    dataconnect_posture.collect(DataConnect(), types.SimpleNamespace(dataconnect_max_groups=20))

    assert _rows(metrics.ise_dataconnect_posture_endpoint_assessments,
                 "status", "os", "agent_version") == {
        ("Compliant", "Windows", "5.1.18.314"): 10}
    assert _rows(metrics.ise_dataconnect_posture_condition_assessments,
                 "policy", "condition", "condition_status") == {
        ("Firewall", "Firewall enabled", "Failed"): 2}
    assert _rows(metrics.ise_dataconnect_posture_failures,
                 "message_code", "status") == {("8701", "NonCompliant"): 2}
    for metric in dataconnect_posture._METRICS:
        assert "endpoint" not in metric._labelnames
        assert "username" not in metric._labelnames
