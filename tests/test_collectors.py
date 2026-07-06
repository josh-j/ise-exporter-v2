"""observe()/CollectorFailed failure-accounting: a no-data API response must count
as a failure (feeding the scheduler's MAX_CONSECUTIVE_FAILURES gating) and must NOT
bump last_successful_scrape; a real success resets the count."""
import types

from ise_exporter import collectors
from ise_exporter.collectors import sessions


def test_no_data_counts_as_failure_then_resets():
    cfg = types.SimpleNamespace()
    mappings = {"hostname": {}, "location": {}, "ops_owner": {}}

    class Dead:
        def get_mnt_xml(self, path, api_name="x"):
            return None

    for _ in range(3):
        sessions.collect(Dead(), cfg, mappings)
    assert collectors.failures("sessions") == 3

    class Live:
        def get_mnt_xml(self, path, api_name="x"):
            return {"total": 0, "sessions": []}

    sessions.collect(Live(), cfg, mappings)
    assert collectors.failures("sessions") == 0


def _label_set(metric, label):
    return {s.labels[label]: s.value for s in metric.collect()[0].samples}


def test_sessions_stream_mode_emits_psn_only():
    """In stream mode the sessions collector fills ise_radius_sessions_by_psn (the one
    gauge the pxGrid topic can't) and leaves the projector-owned gauges alone."""
    from ise_exporter import metrics
    from ise_exporter.util import clear_metric

    cfg = types.SimpleNamespace(collect_pxgrid_stream=True)
    mappings = {"hostname": {"10.0.0.1": "sw1"}, "location": {"10.0.0.1": "SiteA"},
                "ops_owner": {"10.0.0.1": "TeamA"}}

    class Client:
        def get_mnt_xml(self, path, api_name="x"):
            return {"total": 2, "sessions": [
                {"nas_ip_address": "10.0.0.1", "server": "psn-a"},
                {"nas_ip_address": "10.0.0.1", "server": "psn-b"},
            ]}

    # projector-owned gauges pre-set by the "streamer" — stream-mode sessions must not wipe them
    clear_metric(metrics.ise_radius_sessions_by_nad)
    metrics.ise_radius_sessions_by_nad.labels(nas_hostname="sw1", location="SiteA").set(99)
    metrics.ise_active_sessions.set(99)

    sessions.collect(Client(), cfg, mappings)

    assert _label_set(metrics.ise_radius_sessions_by_psn, "psn") == {"psn-a": 1.0, "psn-b": 1.0}
    assert metrics.ise_radius_sessions_by_nad.labels(
        nas_hostname="sw1", location="SiteA")._value.get() == 99
    assert metrics.ise_active_sessions._value.get() == 99


def test_poll_authz_emits_posture_status():
    """In poll mode authz derives posture compliance from session detail
    (posture_status / other_attr_string) onto ise_session_posture_status."""
    from ise_exporter import metrics
    from ise_exporter.collectors import authz
    from ise_exporter.util import clear_metric

    cfg = types.SimpleNamespace(collect_pxgrid_stream=False, session_detail_cache_ttl=100,
                                max_detail_fetches_per_cycle=10, max_workers=2)
    mappings = {"hostname": {"10.0.0.1": "sw1"}, "location": {"10.0.0.1": "SiteA"},
                "ops_owner": {"10.0.0.1": "TeamA"}}
    detail = {"passed": "true", "failed": "false", "nas_ip_address": "10.0.0.1",
              "authentication_method": "dot1x", "posture_status": "NonCompliant",
              "other_attr_string": ""}

    class Client:
        def get_mnt_xml(self, path, api_name="x"):
            if path == "/Session/ActiveList":
                return {"total": 1, "sessions": [{"calling_station_id": "aa:bb:cc:00:00:22",
                                                  "nas_ip_address": "10.0.0.1"}]}
            return {"total": 1, "sessions": [dict(detail)]}

    clear_metric(metrics.ise_session_posture_status)
    authz.collect(Client(), cfg, mappings)

    posture = {(s.labels["status"], s.labels["location"]): s.value
               for s in metrics.ise_session_posture_status.collect()[0].samples}
    assert posture[("NonCompliant", "SiteA")] == 1.0


def test_authz_parses_posture_report_and_agent_version():
    """PostureReport (per-policy pass/fail) and PostureAgentVersion come from the MnT
    session detail's other_attr_string — authz owns them in BOTH modes."""
    from ise_exporter import metrics
    from ise_exporter.collectors import authz
    from ise_exporter.util import clear_metric

    cfg = types.SimpleNamespace(collect_pxgrid_stream=True, session_detail_cache_ttl=100,
                                max_detail_fetches_per_cycle=10, max_workers=2)
    mappings = {"hostname": {"10.0.0.1": "sw1"}, "location": {"10.0.0.1": "SiteA"},
                "ops_owner": {"10.0.0.1": "TeamA"}}
    report = ("C2CP-WIN-FIREWALL\\;Passed\\;(C2CR-WIN-FIREWALL:Optional:Passed:"
              "Passed_Conditions[A]:Failed_Conditions[]:Skipped_Conditions[]), "
              "C2CP-WIN-AM\\;Failed\\;(C2CR-WIN-AM:Mandatory:Failed:Passed_Conditions[]:"
              "Failed_Conditions[am]:Skipped_Conditions[])")
    detail = {"passed": "true", "failed": "false", "nas_ip_address": "10.0.0.1",
              "other_attr_string": ("PostureReport=" + report +
                                    ":!:PostureAgentVersion=Posture Agent for Windows 5.1.17.3394")}

    class Client:
        def get_mnt_xml(self, path, api_name="x"):
            if path == "/Session/ActiveList":
                return {"total": 1, "sessions": [{"calling_station_id": "aa:bb:cc:00:00:33",
                                                  "nas_ip_address": "10.0.0.1"}]}
            return {"total": 1, "sessions": [dict(detail)]}

    clear_metric(metrics.ise_posture_policy_result)
    clear_metric(metrics.ise_posture_agent_version)
    authz.collect(Client(), cfg, mappings)

    pol = {(s.labels["policy"], s.labels["result"], s.labels["ops_owner"]): s.value
           for s in metrics.ise_posture_policy_result.collect()[0].samples}
    assert pol[("C2CP-WIN-FIREWALL", "Passed", "TeamA")] == 1.0
    assert pol[("C2CP-WIN-AM", "Failed", "TeamA")] == 1.0

    ver = {s.labels["version"]: s.value
           for s in metrics.ise_posture_agent_version.collect()[0].samples}
    assert ver["Windows 5.1.17.3394"] == 1.0


def test_streaming_authz_emits_only_topic_uncoverable_signals():
    """In stream mode authz must feed failure-reason / matched-rule / policy-set but
    NOT touch the projector-owned status / methods / profiles gauges."""
    from ise_exporter import metrics
    from ise_exporter.collectors import authz

    cfg = types.SimpleNamespace(collect_pxgrid_stream=True, session_detail_cache_ttl=100,
                                max_detail_fetches_per_cycle=10, max_workers=2)
    mappings = {"hostname": {"10.0.0.1": "sw1"}, "location": {"10.0.0.1": "L"},
                "ops_owner": {"10.0.0.1": "TeamA"}}
    detail = {"passed": "false", "failed": "true", "nas_ip_address": "10.0.0.1",
              "failure_reason": "11512 Auth failed", "authentication_method": "mab",
              "selected_azn_profiles": "DenyAccess",
              "other_attr_string": "ISEPolicySetName=Wired Closed Mode:!:"
                                   "AuthorizationPolicyMatchedRule=Default"}

    class Client:
        def get_mnt_xml(self, path, api_name="x"):
            if path == "/Session/ActiveList":
                return {"total": 1, "sessions": [{"calling_station_id": "aa:bb:cc:00:00:09",
                                                  "nas_ip_address": "10.0.0.1"}]}
            return {"total": 1, "sessions": [dict(detail)]}

    # projector-owned gauge pre-set by the "streamer" — authz must not wipe it
    metrics.ise_session_status_endpoints.labels(
        nad_hostname="sw1", location="L", ops_owner="TeamA", status="passed").set(42)

    authz.collect(Client(), cfg, mappings)

    assert _label_set(metrics.ise_session_failure_reasons, "reason_code") == {"11512": 1.0}
    assert _label_set(metrics.ise_session_policy_set_endpoints, "policy_set") == {"Wired Closed Mode": 1.0}
    # projector-owned series untouched
    assert metrics.ise_session_status_endpoints.labels(
        nad_hostname="sw1", location="L", ops_owner="TeamA", status="passed")._value.get() == 42
