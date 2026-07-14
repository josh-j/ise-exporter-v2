import types

import pytest

from ise_exporter import collectors, metrics
from ise_exporter.collectors import mnt_active_posture


@pytest.fixture(autouse=True)
def _clear():
    collectors._failures.clear()
    collectors._outcomes.clear()
    for metric in mnt_active_posture._METRICS:
        if hasattr(metric, "_metrics"):
            metric._metrics.clear()
        elif hasattr(metric, "_value"):
            metric.set(0)


def _rows(metric, *labels):
    return {tuple(sample.labels[name] for name in labels): sample.value
            for sample in metric.collect()[0].samples}


class MnT:
    def __init__(self):
        self.calls = []

    def get_mnt_xml(self, path, api_name="mnt"):
        self.calls.append((path, api_name))
        if path == "/Session/ActiveList":
            return {
                "total": 4,
                "sessions": [
                    {"calling_station_id": "AA-BB-CC-DD-EE-01"},
                    {"calling_station_id": "AA:BB:CC:DD:EE:01"},
                    {"calling_station_id": "AA:BB:CC:DD:EE:02"},
                    {"calling_station_id": "not-a-mac"},
                ],
            }
        details = {
            "AA:BB:CC:DD:EE:01": {
                "execution_steps": "1001,1002,not-a-code",
                "acs_server": "laba-ise-001",
                "other_attr_string": (
                    "PostureAgentVersion=Posture Agent for Windows 5.1.18.314:!:"
                    "PostureApplicable=Yes:!:PostureAssessmentStatus=NotApplicable:!:"
                    "PostureStatus=Compliant:!:"
                    "PostureReport=C2CP-WIN-FIREWALL\\;Passed\\;(details), "
                    "C2CP-WIN-AM\\;Failed\\;(details):!:"
                    "StepLatency=1=20;2=40;3=999:!:TotalAuthenLatency=120"
                ),
            },
            "AA:BB:CC:DD:EE:02": {
                # Live ISE 3.3 can expose self-keyed StepLatency without a
                # matching ExecutionSteps attribute.
                "other_attr_string": "PostureApplicable=No:!:StepLatency=1=10;2=30"
            },
        }
        mac = path.rsplit("/", 1)[-1]
        return {"total": 1, "sessions": [details[mac]]}


def _cfg(**overrides):
    values = dict(mnt_active_posture_max_sessions=10, mnt_active_posture_workers=2)
    values.update(overrides)
    return types.SimpleNamespace(**values)


def test_collects_bounded_posture_and_latency_without_identity_labels():
    client = MnT()
    mnt_active_posture.collect(client, _cfg())

    assert len([path for path, _ in client.calls if "MACAddress" in path]) == 2
    assert metrics.ise_mnt_active_sessions_total._value.get() == 4
    assert metrics.ise_mnt_active_posture_candidate_endpoints_total._value.get() == 2
    assert metrics.ise_mnt_active_posture_detail_endpoints._value.get() == 2
    assert metrics.ise_mnt_active_posture_detail_coverage_ratio._value.get() == 1
    assert _rows(metrics.ise_mnt_active_posture_endpoints, "status", "os", "psn") == {
        ("Compliant", "Windows", "laba-ise-001"): 1,
        ("Unknown", "Unknown", "Unknown"): 1,
    }
    assert _rows(metrics.ise_mnt_active_posture_applicable_endpoints, "applicable") == {
        ("true",): 1, ("false",): 1}
    assert _rows(metrics.ise_mnt_active_secure_client_endpoints, "agent_version") == {
        ("Windows 5.1.18.314",): 1, ("Unknown",): 1}
    assert _rows(metrics.ise_mnt_active_posture_policy_results, "policy", "result") == {
        ("C2CP-WIN-FIREWALL", "Passed"): 1,
        ("C2CP-WIN-AM", "Failed"): 1,
    }
    assert _rows(metrics.ise_mnt_active_step_latency_seconds, "step", "stat") == {
        ("1001", "sum"): pytest.approx(.02),
        ("1001", "avg"): pytest.approx(.02),
        ("1001", "max"): pytest.approx(.02),
        ("1002", "sum"): pytest.approx(.04),
        ("1002", "avg"): pytest.approx(.04),
        ("1002", "max"): pytest.approx(.04),
        ("1", "sum"): pytest.approx(.01),
        ("1", "avg"): pytest.approx(.01),
        ("1", "max"): pytest.approx(.01),
        ("2", "sum"): pytest.approx(.03),
        ("2", "avg"): pytest.approx(.03),
        ("2", "max"): pytest.approx(.03),
    }
    assert _rows(metrics.ise_mnt_active_total_authentication_latency_seconds, "stat") == {
        ("sum",): pytest.approx(.12),
        ("avg",): pytest.approx(.12),
        ("max",): pytest.approx(.12),
    }
    coverage = _rows(metrics.ise_mnt_active_posture_field_coverage_ratio, "field")
    assert coverage[("other_attr_string",)] == 1
    assert coverage[("posture_report",)] == .5
    assert coverage[("step_latency",)] == 1
    # Prometheus dimensions stay aggregated; no MAC, endpoint, user, or custom
    # OTHER_ATTR_STRING keys become labels.
    label_names = {name for metric in mnt_active_posture._METRICS
                   for name in getattr(metric, "_labelnames", ())}
    assert not {"mac", "endpoint", "username", "Ops Owner"} & label_names


def test_bound_is_explicit_and_failed_full_sample_preserves_previous_snapshot():
    client = MnT()
    mnt_active_posture.collect(client, _cfg(mnt_active_posture_max_sessions=1))
    assert metrics.ise_mnt_active_posture_detail_requests._value.get() == 1
    assert metrics.ise_mnt_active_posture_detail_truncated._value.get() == 1
    previous = _rows(metrics.ise_mnt_active_posture_endpoints, "status")

    class Failed(MnT):
        def get_mnt_xml(self, path, api_name="mnt"):
            if path == "/Session/ActiveList":
                return super().get_mnt_xml(path, api_name)
            return None

    mnt_active_posture.collect(Failed(), _cfg(mnt_active_posture_max_sessions=1))

    assert collectors.outcome("mnt_active_posture") is False
    assert _rows(metrics.ise_mnt_active_posture_endpoints, "status") == previous


def test_valid_empty_active_list_publishes_an_empty_snapshot():
    class Empty:
        def get_mnt_xml(self, path, api_name="mnt"):
            return {"total": 0, "sessions": []}

    mnt_active_posture.collect(Empty(), _cfg())
    assert collectors.outcome("mnt_active_posture") is True
    assert metrics.ise_mnt_active_sessions_total._value.get() == 0
    assert metrics.ise_mnt_active_posture_detail_coverage_ratio._value.get() == 1
    assert not _rows(metrics.ise_mnt_active_posture_endpoints, "status")


def test_persistent_cache_bounds_cold_start_and_survives_restart(tmp_path):
    cfg = _cfg(
        state_db_path=str(tmp_path / "state.sqlite3"),
        mnt_active_posture_max_requests_per_cycle=1,
        mnt_active_posture_refresh_ttl=3600,
        mnt_active_posture_interval=900,
        mnt_active_posture_request_interval_ms=0,
    )

    first = MnT()
    mnt_active_posture.collect(first, cfg)
    assert len([path for path, _ in first.calls if "MACAddress" in path]) == 1
    assert metrics.ise_mnt_active_posture_detail_endpoints._value.get() == 1
    assert metrics.ise_mnt_active_posture_refresh_deferred._value.get() == 1

    second = MnT()
    mnt_active_posture.collect(second, cfg)
    assert len([path for path, _ in second.calls if "MACAddress" in path]) == 1
    assert metrics.ise_mnt_active_posture_detail_endpoints._value.get() == 2
    assert metrics.ise_mnt_active_posture_cache_entries._value.get() == 2
    assert metrics.ise_mnt_active_posture_detail_coverage_ratio._value.get() == 1
    assert (tmp_path / "state.sqlite3").stat().st_mode & 0o077 == 0
