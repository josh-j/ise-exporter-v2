"""observe()/CollectorFailed failure-accounting: a no-data API response must count
as a failure (feeding the scheduler's MAX_CONSECUTIVE_FAILURES gating) and must NOT
bump last_successful_scrape; a real success resets the count."""
import types
from ipaddress import ip_network

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
    metrics.ise_pxgrid_connected.set(1)   # stream is UP -> collector self-limits to PSN

    sessions.collect(Client(), cfg, mappings)

    assert _label_set(metrics.ise_radius_sessions_by_psn, "psn") == {"psn-a": 1.0, "psn-b": 1.0}
    assert metrics.ise_radius_sessions_by_nad.labels(
        nas_hostname="sw1", location="SiteA")._value.get() == 99
    assert metrics.ise_active_sessions._value.get() == 99


def test_sessions_falls_back_to_full_poll_when_stream_down():
    """Streaming configured but the stream is DOWN (ise_pxgrid_connected=0) -> the
    sessions collector must emit the full poll (active/by_nad/by_ops_owner), not PSN-only."""
    from ise_exporter import metrics
    from ise_exporter.util import clear_metric

    cfg = types.SimpleNamespace(collect_pxgrid_stream=True)
    mappings = {"hostname": {"10.0.0.1": "sw1"}, "location": {"10.0.0.1": "SiteA"},
                "ops_owner": {"10.0.0.1": "TeamA"}}

    class Client:
        def get_mnt_xml(self, path, api_name="x"):
            return {"total": 2, "sessions": [
                {"nas_ip_address": "10.0.0.1", "server": "psn-a"},
                {"nas_ip_address": "10.0.0.1", "server": "psn-a"},
            ]}

    clear_metric(metrics.ise_radius_sessions_by_nad)
    metrics.ise_active_sessions.set(0)
    metrics.ise_pxgrid_connected.set(0)   # stream is DOWN -> full poll fallback

    sessions.collect(Client(), cfg, mappings)

    assert metrics.ise_active_sessions._value.get() == 2
    assert metrics.ise_radius_sessions_by_nad.labels(
        nas_hostname="sw1", location="SiteA")._value.get() == 2


def test_sessions_resolves_nad_subnet_mappings():
    """Lab NADs can be registered as subnets; session source IPs should still
    inherit the NAD hostname/location/ops-owner labels."""
    from ise_exporter import metrics
    from ise_exporter.util import clear_metric

    cfg = types.SimpleNamespace(collect_pxgrid_stream=False)
    mappings = {
        "hostname": {"10.83.0.0": "adlab-workstations"},
        "location": {"10.83.0.0": "All Locations"},
        "ops_owner": {"10.83.0.0": "AD Lab"},
        "networks": [(ip_network("10.83.0.0/24"), "adlab-workstations",
                      "All Locations", "AD Lab")],
    }

    class Client:
        def get_mnt_xml(self, path, api_name="x"):
            return {"total": 1, "sessions": [
                {"nas_ip_address": "10.83.0.161", "server": "psn-a"},
            ]}

    clear_metric(metrics.ise_radius_sessions_by_nad)
    clear_metric(metrics.ise_radius_sessions_by_ops_owner)
    metrics.ise_pxgrid_connected.set(0)

    sessions.collect(Client(), cfg, mappings)

    assert metrics.ise_radius_sessions_by_nad.labels(
        nas_hostname="adlab-workstations", location="All Locations")._value.get() == 1
    assert metrics.ise_radius_sessions_by_ops_owner.labels(ops_owner="AD Lab")._value.get() == 1


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


def _authz_posture_client(other_attr_string):
    detail = {"passed": "true", "failed": "false", "nas_ip_address": "10.0.0.1",
              "authentication_method": "dot1x", "other_attr_string": other_attr_string}

    class Client:
        def get_mnt_xml(self, path, api_name="x"):
            if path == "/Session/ActiveList":
                return {"total": 1, "sessions": [{"calling_station_id": "aa:bb:cc:00:00:33",
                                                  "nas_ip_address": "10.0.0.1"}]}
            return {"total": 1, "sessions": [dict(detail)]}
    return Client()


_OAS_POSTURE = (
    "ISEPolicySetName=Default:!:"
    "PostureAgentVersion=Posture Agent for Windows 5.1.18.314:!:"
    "PostureApplicable=Yes:!:PostureAssessmentStatus=NotApplicable:!:"
    r"PostureReport=C2CP-WIN-FIREWALL\;Passed\;(C2CR:Audit:Skipped:"
    r"Passed_Conditions[a]:Failed_Conditions[inner_failure]:Skipped_Conditions[])"
    r"C2CP-WIN-AM\;Failed\;(C2CR-AM:Mandatory:Failed:Passed_Conditions[]:"
    r"Failed_Conditions[x]:Skipped_Conditions[]):!:PostureStatus=Compliant")


def test_authz_emits_posture_report_and_secureclient_from_other_attr_when_getendpoints_empty():
    """When pxGrid getEndpoints delivered nothing, authz emits per-policy PostureReport +
    Secure Client version from the MnT session other_attr_string (the real source)."""
    from ise_exporter import metrics
    from ise_exporter.collectors import authz, endpoint_attributes, models
    from ise_exporter.util import clear_metric

    cfg = types.SimpleNamespace(collect_pxgrid_stream=False, session_detail_cache_ttl=100,
                                max_detail_fetches_per_cycle=10, max_workers=2)
    mappings = {"hostname": {"10.0.0.1": "sw1"}, "location": {"10.0.0.1": "SiteA"},
                "ops_owner": {"10.0.0.1": "TeamA"}}
    metrics.ise_endpoints_pxgrid_total.set(0)          # getEndpoints empty -> authz owns
    models._posture_report_present = False
    models._secureclient_version_present = False
    endpoint_attributes._posture_report_present = False
    endpoint_attributes._secureclient_version_present = False
    authz._cache = None
    clear_metric(metrics.ise_posture_policy_result)
    clear_metric(metrics.ise_endpoints_by_secureclient_version)

    authz.collect(_authz_posture_client(_OAS_POSTURE), cfg, mappings)

    policies = {(s.labels["policy"], s.labels["result"], s.labels["ops_owner"]): s.value
                for s in metrics.ise_posture_policy_result.collect()[0].samples}
    assert policies[("C2CP-WIN-FIREWALL", "Passed", "TeamA")] == 1.0
    assert policies[("C2CP-WIN-AM", "Failed", "TeamA")] == 1.0
    scv = {s.labels["version"]: s.value
           for s in metrics.ise_endpoints_by_secureclient_version.collect()[0].samples}
    assert scv == {"Windows 5.1.18.314": 1.0}
    posture = {(s.labels["status"], s.labels["location"]): s.value
               for s in metrics.ise_session_posture_status.collect()[0].samples}
    # PostureStatus is authoritative when AssessmentStatus says NotApplicable.
    assert posture[("Compliant", "SiteA")] == 1.0


def test_authz_uses_recent_auth_status_failures():
    """Access-Reject records live in MnT AuthStatus, not necessarily in active
    Session/MACAddress detail. The failure gauges should include those records."""
    from ise_exporter import metrics
    from ise_exporter.collectors import authz
    from ise_exporter.util import clear_metric

    cfg = types.SimpleNamespace(collect_pxgrid_stream=False, session_detail_cache_ttl=100,
                                max_detail_fetches_per_cycle=10, max_workers=2)
    mappings = {"hostname": {"10.0.0.0": "lab-nad"}, "location": {"10.0.0.0": "Lab"},
                "ops_owner": {"10.0.0.0": "AD Lab"},
                "networks": [(ip_network("10.0.0.0/24"), "lab-nad", "Lab", "AD Lab")]}

    class Client:
        def get_mnt_xml(self, path, api_name="x"):
            if path == "/Session/ActiveList":
                return {"total": 1, "sessions": [{"calling_station_id": "aa:bb:cc:00:00:44",
                                                  "nas_ip_address": "10.0.0.44"}]}
            if path == "/Session/MACAddress/AA:BB:CC:00:00:44":
                return {"total": 1, "sessions": [{
                    "passed": "true", "failed": "false", "nas_ip_address": "10.0.0.44",
                    "authentication_method": "dot1x",
                }]}
            if path == "/AuthStatus/MACAddress/AA:BB:CC:00:00:44/600/20/All":
                return {"total": 1, "sessions": [{
                    "passed": "false", "failed": "true", "nas_ip_address": "10.0.0.44",
                    "network_device_name": "lab-nad", "authentication_method": "dot1x",
                    "failure_reason": "24408 User authentication failed",
                }]}
            return {"total": 0, "sessions": []}

    clear_metric(metrics.ise_session_failure_reasons)
    clear_metric(metrics.ise_session_failure_auth_methods)
    clear_metric(metrics.ise_session_status_endpoints)
    authz._cache = None

    authz.collect(Client(), cfg, mappings)

    failures = {(s.labels["reason_code"], s.labels["ops_owner"]): s.value
                for s in metrics.ise_session_failure_reasons.collect()[0].samples}
    assert failures[("24408", "AD Lab")] == 1.0
    failure_methods = {(s.labels["method"], s.labels["ops_owner"]): s.value
                       for s in metrics.ise_session_failure_auth_methods.collect()[0].samples}
    assert failure_methods[("dot1x", "AD Lab")] == 1.0
    assert metrics.ise_session_status_endpoints.labels(
        nad_hostname="lab-nad", location="Lab", ops_owner="AD Lab", status="failed"
    )._value.get() == 1


def test_authz_scans_ers_endpoint_macs_for_recent_failures():
    """Recent rejects can be for endpoint MACs that are no longer active sessions;
    bounded ERS endpoint scanning keeps failure triage populated."""
    from ise_exporter import metrics
    from ise_exporter.collectors import authz
    from ise_exporter.util import clear_metric

    cfg = types.SimpleNamespace(collect_pxgrid_stream=False, session_detail_cache_ttl=100,
                                max_detail_fetches_per_cycle=10, max_workers=2)
    mappings = {"hostname": {"10.0.0.0": "lab-nad"}, "location": {"10.0.0.0": "Lab"},
                "ops_owner": {"10.0.0.0": "AD Lab"},
                "networks": [(ip_network("10.0.0.0/24"), "lab-nad", "Lab", "AD Lab")]}

    class Client:
        def get_ers(self, path, params=None, get_all=False, api_name="x"):
            return [{"name": "AA:BB:CC:00:00:55"}] if path == "/config/endpoint" else []

        def get_mnt_xml(self, path, api_name="x"):
            if path == "/Session/ActiveList":
                return {"total": 0, "sessions": []}
            if path == "/AuthStatus/MACAddress/AA:BB:CC:00:00:55/600/20/All":
                return {"total": 1, "sessions": [{
                    "passed": "false", "failed": "true", "nas_ip_address": "10.0.0.55",
                    "network_device_name": "lab-nad", "authentication_method": "dot1x",
                    "failure_reason": "24408 User authentication failed",
                }]}
            return {"total": 0, "sessions": []}

    clear_metric(metrics.ise_session_failure_reasons)
    clear_metric(metrics.ise_session_status_endpoints)
    authz._cache = None

    authz.collect(Client(), cfg, mappings)

    failures = {(s.labels["reason_code"], s.labels["ops_owner"]): s.value
                for s in metrics.ise_session_failure_reasons.collect()[0].samples}
    assert failures[("24408", "AD Lab")] == 1.0


def test_recent_auth_latency_is_observed_once_per_transaction():
    from ise_exporter import metrics
    from ise_exporter.collectors import authz
    from ise_exporter.util import clear_metric

    clear_metric(metrics.ise_radius_auth_latency_by_psn_seconds)
    clear_metric(metrics.ise_radius_client_latency_seconds)
    clear_metric(metrics.ise_radius_step_latency_seconds)
    authz._observed_recent_auth_ids.clear()
    detail = {
        "auth_id": "txn-1", "passed": "false", "failed": "true",
        "acs_server": "psn-a", "execution_steps": "11001,24408",
    }
    other = {"TotalAuthenLatency": "64", "ClientLatency": "3",
             "StepLatency": "1=4;2=60"}

    authz._observe_recent_latency_once(detail, other, "nad-a", "Lab", "Team")
    authz._observe_recent_latency_once(detail, other, "nad-a", "Lab", "Team")

    samples = metrics.ise_radius_auth_latency_by_psn_seconds.collect()[0].samples
    count = next(s.value for s in samples
                 if s.name.endswith("_count") and s.labels["psn"] == "psn-a")
    assert count == 1


def test_authz_uses_other_attrs_when_getendpoints_lacks_posture_fields():
    """Endpoint rows alone must not suppress richer MnT posture attributes."""
    from ise_exporter import metrics
    from ise_exporter.collectors import authz, endpoint_attributes, models
    from ise_exporter.util import clear_metric

    cfg = types.SimpleNamespace(collect_pxgrid_stream=False, session_detail_cache_ttl=100,
                                max_detail_fetches_per_cycle=10, max_workers=2)
    mappings = {"hostname": {"10.0.0.1": "sw1"}, "location": {"10.0.0.1": "SiteA"},
                "ops_owner": {"10.0.0.1": "TeamA"}}
    metrics.ise_endpoints_pxgrid_total.set(7)
    models._posture_report_present = False
    models._secureclient_version_present = False
    endpoint_attributes._posture_report_present = False
    endpoint_attributes._secureclient_version_present = False
    authz._cache = None
    clear_metric(metrics.ise_posture_policy_result)
    clear_metric(metrics.ise_endpoints_by_secureclient_version)

    authz.collect(_authz_posture_client(_OAS_POSTURE), cfg, mappings)

    policies = {(s.labels["policy"], s.labels["result"]): s.value
                for s in metrics.ise_posture_policy_result.collect()[0].samples}
    assert policies[("C2CP-WIN-FIREWALL", "Passed")] == 1.0
    versions = {s.labels["version"]: s.value
                for s in metrics.ise_endpoints_by_secureclient_version.collect()[0].samples}
    assert versions == {"Windows 5.1.18.314": 1.0}


def test_authz_posture_ownership_is_independent_per_attribute():
    """A pxGrid agent version must not suppress an MnT PostureReport."""
    from ise_exporter import metrics
    from ise_exporter.collectors import authz, endpoint_attributes, models
    from ise_exporter.util import clear_metric

    cfg = types.SimpleNamespace(collect_pxgrid_stream=False, session_detail_cache_ttl=100,
                                max_detail_fetches_per_cycle=10, max_workers=2)
    mappings = {"hostname": {"10.0.0.1": "sw1"}, "location": {"10.0.0.1": "SiteA"},
                "ops_owner": {"10.0.0.1": "TeamA"}}
    models._posture_report_present = False
    models._secureclient_version_present = True
    endpoint_attributes._posture_report_present = False
    endpoint_attributes._secureclient_version_present = False
    authz._cache = None
    clear_metric(metrics.ise_posture_policy_result)
    clear_metric(metrics.ise_endpoints_by_secureclient_version)
    metrics.ise_endpoints_by_secureclient_version.labels(version="pxGrid-owned").set(7)

    authz.collect(_authz_posture_client(_OAS_POSTURE), cfg, mappings)

    policies = {(s.labels["policy"], s.labels["result"]): s.value
                for s in metrics.ise_posture_policy_result.collect()[0].samples}
    versions = {s.labels["version"]: s.value
                for s in metrics.ise_endpoints_by_secureclient_version.collect()[0].samples}
    assert policies[("C2CP-WIN-FIREWALL", "Passed")] == 1.0
    assert versions == {"pxGrid-owned": 7.0}


def test_streaming_authz_emits_failed_status_without_wiping_passed():
    """In stream mode authz feeds failure-reason / matched-rule / policy-set AND the
    status='failed' slice (its own, since failed auths aren't sessions) but must NOT
    touch the projector-owned status='passed' / methods / profiles series."""
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

    # projector-owned passed series pre-set by the "streamer" — authz must not wipe it
    metrics.ise_session_status_endpoints.labels(
        nad_hostname="sw1", location="L", ops_owner="TeamA", status="passed").set(42)
    metrics.ise_pxgrid_connected.set(1)   # stream is UP -> authz self-limits

    authz.collect(Client(), cfg, mappings)

    assert _label_set(metrics.ise_session_failure_reasons, "reason_code") == {"11512": 1.0}
    assert _label_set(metrics.ise_session_policy_set_endpoints, "policy_set") == {"Wired Closed Mode": 1.0}
    # authz now emits the failed slice in stream mode (the failure-rate panels need it)
    assert metrics.ise_session_status_endpoints.labels(
        nad_hostname="sw1", location="L", ops_owner="TeamA", status="failed")._value.get() == 1
    # ...without wiping the projector-owned passed series
    assert metrics.ise_session_status_endpoints.labels(
        nad_hostname="sw1", location="L", ops_owner="TeamA", status="passed")._value.get() == 42
