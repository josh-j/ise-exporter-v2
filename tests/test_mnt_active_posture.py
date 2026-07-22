import hashlib
import json
import sqlite3
import threading
import types

import pytest

from ise_exporter import collectors, metrics
from ise_exporter.collectors import mnt_active_posture


@pytest.fixture(autouse=True)
def _clear():
    collectors._failures.clear()
    collectors._outcomes.clear()
    operational = (
        metrics.ise_mnt_session_list_preflight_count,
        metrics.ise_mnt_session_list_ceiling,
        metrics.ise_mnt_session_list_skipped,
    )
    for metric in mnt_active_posture._METRICS + operational:
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
        if path == "/Session/ActiveCount":
            return {"total": 1, "sessions": [{"count": "4"}]}
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
                "username": "must-not-enter-cache",
                "framed_ip_address": "192.0.2.10",
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
    values = dict(
        mnt_active_posture_max_active_list_sessions=10000,
        mnt_active_posture_max_sessions=10,
        mnt_active_posture_workers=2,
    )
    values.update(overrides)
    return types.SimpleNamespace(**values)


def test_detail_request_pacing_is_interruptible_during_shutdown():
    shutdown = threading.Event()
    shutdown.set()
    pacer = mnt_active_posture._RequestPacer(60, shutdown)
    pacer.next_at = mnt_active_posture.time.monotonic() + 60

    with pytest.raises(RuntimeError, match="cancelled during exporter shutdown"):
        pacer.wait()


@pytest.mark.parametrize("count", ("-1", -999, 1_000_000_001, "9" * 1000))
def test_out_of_range_active_count_is_invalid_not_an_empty_snapshot(count):
    assert mnt_active_posture._active_count({
        "total": 1, "sessions": [{"count": count}],
    }) is None


def test_unknown_posture_statuses_are_bounded_at_the_metric_boundary():
    raw_status = "unexpected-" + "x" * 400
    aggregates = mnt_active_posture._aggregate([{
        "posture_status": raw_status,
        "posture_assessment_status": raw_status,
    }])
    statuses, *_rest = aggregates

    status = next(iter(statuses))[0]
    assert status.startswith("unexpected-")
    assert len(status.encode("utf-8")) <= 128


def test_malformed_active_identity_and_detail_are_bounded_before_processing():
    assert mnt_active_posture._active_mac({"calling_station_id": "x" * 100_000}) == ""

    signature = mnt_active_posture._session_signature({
        "session_id": {"nested": "x" * 100_000},
        "calling_station_id": "AA:BB:CC:DD:EE:FF",
    })
    assert len(signature) == 64

    compact = mnt_active_posture._compact_detail({
        "other_attr_string": "PostureReport=" + "x" * 200_000,
    })
    assert len(compact["posture_report"].encode("utf-8")) <= 65_536


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


def test_unmapped_latency_accepts_real_five_digit_ise_step_codes():
    assert mnt_active_posture._step_samples("", "11001=17;15049=2;100000=3") == [
        ("11001", 0.017), ("15049", 0.002)]


def test_latency_aggregate_caps_distinct_step_label_domain():
    details = [{"step_latency": f"{code}=1"} for code in range(1, 301)]

    steps = mnt_active_posture._aggregate(details)[4]

    assert len(steps) == mnt_active_posture.MAX_STEP_CODES
    assert set(steps) == {str(code) for code in range(1, 257)}


def test_active_posture_aggregates_cap_free_form_label_domains(monkeypatch):
    monkeypatch.setattr(mnt_active_posture, "MAX_STATUS_GROUPS", 3)
    monkeypatch.setattr(mnt_active_posture, "MAX_AGENT_GROUPS", 3)
    monkeypatch.setattr(mnt_active_posture, "MAX_POLICY_GROUPS", 3)
    details = [{
        "posture_status": f"status-{index}",
        "posture_assessment_status": f"assessment-{index}",
        "posture_agent_version": f"custom-os {index}",
        "posture_report": f"policy-{index}\\;Passed\\;(details)",
    } for index in range(5)]

    statuses, agents, policies, *_rest = (
        mnt_active_posture._aggregate(details))

    assert sum(statuses.values()) == 5
    assert sum(agents.values()) == 5
    assert sum(policies.values()) == 5
    assert len(statuses) <= 3 and ("Other", "Unknown", "Unknown") in statuses
    assert len(agents) <= 3 and "Other" in agents
    assert len(policies) <= 3 and ("Other", "Passed") in policies


def test_compact_posture_fields_are_bounded_by_utf8_bytes():
    compact = mnt_active_posture._compact_detail({
        "posture_report": "ä" * 65_536,
        "execution_steps": "ä" * 16_384,
    })

    assert len(compact["posture_report"].encode("utf-8")) <= 65_536
    assert len(compact["execution_steps"].encode("utf-8")) <= 16_384


def test_bound_is_explicit_and_failed_full_sample_preserves_previous_snapshot():
    client = MnT()
    mnt_active_posture.collect(client, _cfg(mnt_active_posture_max_sessions=1))
    assert metrics.ise_mnt_active_posture_detail_requests._value.get() == 1
    assert metrics.ise_mnt_active_posture_detail_truncated._value.get() == 1
    previous = _rows(metrics.ise_mnt_active_posture_endpoints, "status")

    class Failed(MnT):
        def get_mnt_xml(self, path, api_name="mnt"):
            if path in ("/Session/ActiveCount", "/Session/ActiveList"):
                return super().get_mnt_xml(path, api_name)
            return None

    mnt_active_posture.collect(Failed(), _cfg(mnt_active_posture_max_sessions=1))

    assert collectors.outcome("mnt_active_posture") is False
    assert _rows(metrics.ise_mnt_active_posture_endpoints, "status") == previous


def test_valid_empty_active_list_publishes_an_empty_snapshot():
    class Empty:
        def __init__(self):
            self.calls = []

        def get_mnt_xml(self, path, api_name="mnt"):
            self.calls.append(path)
            return {"total": 1, "sessions": [{"count": "0"}]}

    client = Empty()
    mnt_active_posture.collect(client, _cfg())
    assert collectors.outcome("mnt_active_posture") is True
    assert client.calls == ["/Session/ActiveCount"]
    assert metrics.ise_mnt_active_sessions_total._value.get() == 0
    assert metrics.ise_mnt_active_posture_detail_coverage_ratio._value.get() == 1
    assert not _rows(metrics.ise_mnt_active_posture_endpoints, "status")


def test_large_unpaged_active_list_is_refused_after_small_count_preflight():
    class Large:
        def __init__(self):
            self.calls = []

        def get_mnt_xml(self, path, api_name="mnt"):
            self.calls.append(path)
            if path == "/Session/ActiveCount":
                return {"total": 1, "sessions": [{"count": "100001"}]}
            raise AssertionError("unbounded ActiveList must not be requested")

    client = Large()
    mnt_active_posture.collect(
        client, _cfg(mnt_active_posture_max_active_list_sessions=10000))

    assert collectors.outcome("mnt_active_posture") is False
    assert client.calls == ["/Session/ActiveCount"]
    assert metrics.ise_mnt_session_list_preflight_count._value.get() == 100001
    assert metrics.ise_mnt_session_list_ceiling._value.get() == 10000
    assert metrics.ise_mnt_session_list_skipped._value.get() == 1


def test_active_list_growth_past_preflight_ceiling_fails_closed():
    class GrewAfterPreflight:
        def get_mnt_xml(self, path, api_name="mnt"):
            if path == "/Session/ActiveCount":
                return {"total": 1, "sessions": [{"count": "1"}]}
            if path == "/Session/ActiveList":
                return {"total": 2, "sessions": [
                    {"calling_station_id": "AA:BB:CC:DD:EE:01"},
                    {"calling_station_id": "AA:BB:CC:DD:EE:02"},
                ]}
            raise AssertionError("oversized list must not trigger detail requests")

    mnt_active_posture.collect(
        GrewAfterPreflight(), _cfg(mnt_active_posture_max_active_list_sessions=1))

    assert collectors.outcome("mnt_active_posture") is False
    assert not _rows(metrics.ise_mnt_active_posture_endpoints, "status")


def test_programmatic_config_keeps_count_ceilings_but_honors_request_pacing(monkeypatch):
    sessions = [{"calling_station_id": f"00:00:00:{index >> 16:02X}:"
                 f"{(index >> 8) & 255:02X}:{index & 255:02X}"}
                for index in range(1001)]

    class LargeConfigClient:
        def get_mnt_xml(self, path, api_name="mnt"):
            if path == "/Session/ActiveCount":
                return {"total": 1, "sessions": [{"count": "1001"}]}
            if path == "/Session/ActiveList":
                return {"total": 1001, "sessions": sessions}
            raise AssertionError("detail requests are captured before transport")

    captured = {}

    def bounded(_client, macs, workers, request_interval=0):
        captured.update(count=len(macs), workers=workers, interval=request_interval)
        return {mac: {"posture_status": "Compliant"} for mac in macs}

    monkeypatch.setattr(mnt_active_posture, "_bounded_details", bounded)
    mnt_active_posture.collect(LargeConfigClient(), _cfg(
        mnt_active_posture_max_active_list_sessions=999999,
        mnt_active_posture_max_sessions=999999,
        mnt_active_posture_workers=999,
        mnt_active_posture_max_requests_per_cycle=999999,
        mnt_active_posture_request_interval_ms=0,
    ))

    assert metrics.ise_mnt_session_list_ceiling._value.get() == 250000
    assert metrics.ise_mnt_active_posture_candidate_endpoints_total._value.get() == 1001
    assert captured == {"count": 250, "workers": 4, "interval": 0}


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

    db = sqlite3.connect(tmp_path / "state.sqlite3")
    cached = [json.loads(row[0]) for row in db.execute(
        "SELECT detail_json FROM mnt_posture_cache")]
    db.close()
    assert cached
    assert all("username" not in detail for detail in cached)
    assert all("framed_ip_address" not in detail for detail in cached)
    assert any(detail.get("posture_report") for detail in cached)


def _hash_selected(macs, limit):
    return sorted(macs, key=lambda mac: hashlib.sha256(mac.encode()).hexdigest())[:limit]


def test_detail_sampling_selects_the_same_subset_regardless_of_activelist_order():
    macs = [f"AA:BB:CC:DD:EE:{index:02X}" for index in range(50)]
    limit = 10

    forward = _hash_selected(macs, limit)
    reversed_order = _hash_selected(list(reversed(macs)), limit)

    assert forward == reversed_order
    assert set(forward) <= set(macs)
    assert len(forward) == limit


def test_detail_sampling_is_deterministic_across_calls():
    macs = [f"AA:BB:CC:DD:EE:{index:02X}" for index in range(50)]

    first = _hash_selected(macs, 10)
    second = _hash_selected(macs, 10)

    assert first == second


def test_detail_sampling_selects_all_candidates_when_under_the_limit():
    macs = [f"AA:BB:CC:DD:EE:{index:02X}" for index in range(5)]

    selected = _hash_selected(macs, 1000)

    assert set(selected) == set(macs)
    assert len(selected) == len(macs)


class _OrderedActiveList:
    """MnT stub whose ActiveList order is caller-controlled and whose detail
    endpoint just echoes an empty, bounded posture record for any requested
    MAC, so the collector's sampling logic (not the parsing/detail logic) is
    what's under test."""

    def __init__(self, macs):
        self.macs = macs
        self.requested_macs = []

    def get_mnt_xml(self, path, api_name="mnt"):
        if path == "/Session/ActiveCount":
            return {"total": 1, "sessions": [{"count": str(len(self.macs))}]}
        if path == "/Session/ActiveList":
            return {
                "total": len(self.macs),
                "sessions": [{"calling_station_id": mac} for mac in self.macs],
            }
        mac = path.rsplit("/", 1)[-1]
        self.requested_macs.append(mac)
        return {"total": 1, "sessions": [{}]}


def test_different_activelist_orderings_select_the_same_detail_subset(tmp_path):
    macs = [f"AA:BB:CC:DD:EE:{index:02X}" for index in range(50)]
    cfg = _cfg(
        mnt_active_posture_max_sessions=10,
        state_db_path=str(tmp_path / "forward.sqlite3"),
    )

    forward_client = _OrderedActiveList(macs)
    mnt_active_posture.collect(forward_client, cfg)

    reversed_client = _OrderedActiveList(list(reversed(macs)))
    mnt_active_posture.collect(reversed_client, _cfg(
        mnt_active_posture_max_sessions=10,
        state_db_path=str(tmp_path / "reversed.sqlite3"),
    ))

    assert set(forward_client.requested_macs) == set(reversed_client.requested_macs)
    assert len(forward_client.requested_macs) == 10


class ScriptedMnT:
    """MnT stand-in whose ActiveList membership changes between collect() calls."""

    def __init__(self, active_macs, details):
        self.active_macs = active_macs
        self.details = details
        self.calls = []

    def get_mnt_xml(self, path, api_name="mnt"):
        self.calls.append((path, api_name))
        if path == "/Session/ActiveCount":
            return {"total": 1, "sessions": [{"count": str(len(self.active_macs))}]}
        if path == "/Session/ActiveList":
            return {
                "total": len(self.active_macs),
                "sessions": [{"calling_station_id": mac} for mac in self.active_macs],
            }
        mac = path.rsplit("/", 1)[-1]
        return {"total": 1, "sessions": [self.details[mac]]}


def test_grace_window_retains_cache_across_a_missing_cycle_and_avoids_a_forced_refetch(
        tmp_path):
    mac1, mac2, mac3 = (
        "AA:BB:CC:DD:EE:01", "AA:BB:CC:DD:EE:02", "AA:BB:CC:DD:EE:03")
    # No session-id fields, so _session_signature falls back to a hash of the
    # MAC alone -- stable across cycles for a "continuing" endpoint.
    details = {
        mac1: {"other_attr_string": "PostureStatus=Compliant"},
        mac2: {"other_attr_string": "PostureStatus=Compliant"},
        mac3: {"other_attr_string": "PostureStatus=Compliant"},
    }
    state_db_path = str(tmp_path / "state.sqlite3")

    # Cycle 1: both endpoints are new, both get a mandatory detail fetch.
    first = ScriptedMnT([mac1, mac2], details)
    mnt_active_posture.collect(first, _cfg(
        state_db_path=state_db_path,
        mnt_active_posture_max_requests_per_cycle=10,
        mnt_active_posture_refresh_ttl=3600,
        mnt_active_posture_interval=300,
        mnt_active_posture_request_interval_ms=0,
    ))
    assert any(mac2 in path for path, _ in first.calls if "MACAddress" in path)

    # Cycle 2: mac2 momentarily drops out of MnT's ActiveList (an MnT hiccup
    # or transient session drop), so it isn't even a candidate this cycle.
    second = ScriptedMnT([mac1], details)
    mnt_active_posture.collect(second, _cfg(
        state_db_path=state_db_path,
        mnt_active_posture_max_requests_per_cycle=10,
        mnt_active_posture_refresh_ttl=3600,
        mnt_active_posture_interval=300,
        mnt_active_posture_request_interval_ms=0,
    ))
    assert not any("MACAddress" in path and mac2 in path for path, _ in second.calls)

    # mac2's cached row must survive the missing cycle instead of being
    # deleted by exact pruning.
    db = sqlite3.connect(state_db_path)
    remaining = {row[0] for row in db.execute("SELECT mac FROM mnt_posture_cache")}
    db.close()
    assert mac2 in remaining

    # Cycle 3: mac2 reappears with the SAME session signature (mac-only
    # fallback, unchanged), alongside a genuinely new mac3 that consumes the
    # single request budget slot. If mac2 had been evicted in cycle 2 it
    # would now be "mandatory" and would compete with mac3 for that slot;
    # since it was retained, it is classified "unchanged" and served from
    # cache with zero additional detail requests.
    third = ScriptedMnT([mac1, mac2, mac3], details)
    mnt_active_posture.collect(third, _cfg(
        state_db_path=state_db_path,
        mnt_active_posture_max_requests_per_cycle=1,
        mnt_active_posture_refresh_ttl=3600,
        mnt_active_posture_interval=300,
        mnt_active_posture_request_interval_ms=0,
    ))
    assert not any("MACAddress" in path and mac2 in path for path, _ in third.calls)
    assert any("MACAddress" in path and mac3 in path for path, _ in third.calls)
    assert metrics.ise_mnt_active_posture_cache_entries._value.get() == 3
    assert metrics.ise_mnt_active_posture_refresh_deferred._value.get() >= 1
