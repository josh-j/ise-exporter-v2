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
