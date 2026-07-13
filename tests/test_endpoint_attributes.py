import types

import pytest

from ise_exporter import metrics
from ise_exporter.collectors import endpoint_attributes
from ise_exporter.collectors import models
from ise_exporter.util import clear_metric


@pytest.fixture(autouse=True)
def _reset_state():
    endpoint_attributes._records.clear()
    endpoint_attributes._group_cache.clear()
    endpoint_attributes._profile_cache.clear()
    endpoint_attributes._next_page = 1
    endpoint_attributes._cache_loaded = False
    models._hierarchy = {}
    models._ers_profile_cache = {}
    for metric in (
        metrics.ise_endpoint_attribute_fetch_errors,
        metrics.ise_endpoint_attribute_coverage,
        metrics.ise_endpoints_by_policy,
        metrics.ise_endpoints_by_profile_all,
        metrics.ise_endpoints_by_hardware_model,
        metrics.ise_endpoints_by_manufacturer,
        metrics.ise_endpoints_by_endpoint_type,
        metrics.ise_endpoints_by_os,
        metrics.ise_endpoint_mfc_coverage,
        metrics.ise_endpoints_by_profiled_policy,
        metrics.ise_endpoints_by_identity_group,
        metrics.ise_endpoint_static_assignment,
        metrics.ise_endpoint_custom_attribute_value,
    ):
        clear_metric(metric)
    metrics.ise_endpoint_attribute_cache_entries.set(0)
    metrics.ise_endpoint_attribute_scan_last_count.set(0)
    metrics.ise_endpoints_pxgrid_total.set(0)
    metrics.ise_endpoints_total.set(0)
    yield


def _cfg(**overrides):
    base = dict(
        ers_endpoint_attribute_page_size=100,
        ers_endpoint_attribute_cache_ttl=604800,
        ers_endpoint_attribute_cache_file="",
        ers_endpoint_attribute_value_max_len=80,
        ers_endpoint_custom_attribute_keys=("asset_tag", "ops_owner"),
        max_workers=2,
    )
    base.update(overrides)
    return types.SimpleNamespace(**base)


def _rows(metric, *labels):
    return {tuple(s.labels[label] for label in labels): s.value
            for s in metric.collect()[0].samples}


class FakeClient:
    def __init__(self):
        self.calls = []

    def get_ers(self, path, params=None, get_all=False, api_name="x"):
        self.calls.append(("get_ers", path, params))
        if path == "/config/endpoint":
            return [{"id": "e1"}, {"id": "e2"}]
        if path == "/config/endpoint/e1":
            return {"ERSEndPoint": {
                "profileId": "p-win",
                "groupId": "g-workstations",
                # ISE JSON returns real booleans for these, not strings.
                "staticProfileAssignment": False,
                "staticGroupAssignment": True,
                "customAttributes": {"customAttributes": {
                    "asset_tag": "A-100",
                    "ops_owner": "Workplace",
                }},
                # ISE MFC classification, learned by the profiler.
                "mfcAttributes": {
                    "mfcHardwareManufacturer": ["Dell Inc."],
                    "mfcHardwareModel": [],
                    "mfcOperatingSystem": ["Windows"],
                    "mfcDeviceType": ["Workstation"],
                },
            }}
        if path == "/config/endpoint/e2":
            return {"ERSEndPoint": {
                "profileId": "p-phone",
                "staticProfileAssignment": True,
                "staticGroupAssignment": False,
                # ISE splits the manufacturer on commas -> the exporter rejoins it.
                "mfcAttributes": {
                    "mfcHardwareManufacturer": ["Cisco Systems", " Inc."],
                    "mfcHardwareModel": [],
                    "mfcOperatingSystem": [],
                    "mfcDeviceType": [],
                },
            }}
        if path == "/config/endpointgroup/g-workstations":
            return {"EndPointGroup": {"name": "Workstations"}}
        # profiler policy tree (name + parentId) for the ERS hierarchy walk:
        #   Windows-Workstation -> Microsoft-Workstation (root)
        #   Cisco-IP-Phone      -> Cisco-Device (root)
        if path == "/config/profilerprofile/p-win":
            return {"ProfilerProfile": {"name": "Windows-Workstation", "parentId": "p-msft"}}
        if path == "/config/profilerprofile/p-msft":
            return {"ProfilerProfile": {"name": "Microsoft-Workstation", "parentId": ""}}
        if path == "/config/profilerprofile/p-phone":
            return {"ProfilerProfile": {"name": "Cisco-IP-Phone", "parentId": "p-cisco"}}
        if path == "/config/profilerprofile/p-cisco":
            return {"ProfilerProfile": {"name": "Cisco-Device", "parentId": ""}}
        return None

    def get_ers_total(self, path, params=None, api_name="x"):
        self.calls.append(("get_ers_total", path, params))
        if path == "/config/endpoint":
            return 2
        return None

    def get_pan_api(self, path, api_name="x", unwrap=True):
        self.calls.append(("get_pan_api", path))
        if path == "/endpoint/deviceType/summary":
            return [{"deviceType": "windows10-workstation", "total": "5"},
                    {"deviceType": "android", "total": "3"}]
        return None


def test_collects_profile_and_object_fields_from_ers_endpoint_sweep():
    # MFC/OS/OUI/source/certainty/MDM attributes are pxGrid-only (no REST source),
    # so this collector emits what the ERS endpoint object provides: profile (via
    # profileId), identity group, static assignment, custom attributes.
    client = FakeClient()

    endpoint_attributes.collect(client, _cfg())

    assert metrics.ise_endpoint_attribute_cache_entries._value.get() == 2
    assert metrics.ise_endpoint_attribute_scan_last_count._value.get() == 2
    assert metrics.ise_endpoints_total._value.get() == 2
    assert _rows(metrics.ise_endpoints_by_policy, "policy") == {
        ("Windows-Workstation",): 1.0,
        ("Cisco-IP-Phone",): 1.0,
    }
    assert _rows(metrics.ise_endpoints_by_profiled_policy, "policy") == {
        ("Windows-Workstation",): 1.0,
        ("Cisco-IP-Phone",): 1.0,
    }
    assert _rows(metrics.ise_endpoints_by_identity_group, "group") == {
        ("Workstations",): 1.0,
        ("unknown",): 1.0,
    }
    assert _rows(metrics.ise_endpoint_static_assignment, "assignment", "value") == {
        ("staticProfileAssignment", "false"): 1.0,
        ("staticGroupAssignment", "true"): 1.0,
        ("staticProfileAssignment", "true"): 1.0,
        ("staticGroupAssignment", "false"): 1.0,
    }
    assert _rows(metrics.ise_endpoint_custom_attribute_value, "key", "value") == {
        ("asset_tag", "A-100"): 1.0,
        ("ops_owner", "Workplace"): 1.0,
    }
    # neither fake endpoint carries a learned model -> unknown; manufacturer/OS
    # coverage is asserted in test_mfc_manufacturer_and_os_from_ers_mfc_attributes.
    assert _rows(metrics.ise_endpoints_by_hardware_model, "model") == {("unknown",): 2.0}
    coverage = _rows(metrics.ise_endpoint_attribute_coverage, "attribute")
    assert coverage[("policy",)] == 1.0
    assert coverage[("identity_group",)] == 0.5
    assert ("get_ers", "/config/profilerprofile/p-win", None) in client.calls


def test_mfc_manufacturer_and_os_from_ers_mfc_attributes():
    # ise_endpoints_by_manufacturer/os come from the ERS endpoint object's
    # mfcAttributes (ISE's MFC classification) — no pxGrid getEndpoints required.
    client = FakeClient()
    endpoint_attributes.collect(client, _cfg())
    assert _rows(metrics.ise_endpoints_by_manufacturer, "manufacturer") == {
        ("Dell Inc.",): 1.0,
        ("Cisco Systems, Inc.",): 1.0,     # rejoined from ["Cisco Systems", " Inc."]
    }
    assert _rows(metrics.ise_endpoints_by_os, "os") == {
        ("Windows",): 1.0,
        ("unknown",): 1.0,                 # e2 has no learned OS
    }
    cov = _rows(metrics.ise_endpoint_mfc_coverage, "attribute")
    assert cov[("manufacturer",)] == 1.0   # both endpoints carry a manufacturer
    assert cov[("os",)] == 0.5             # only e1


def test_endpoint_type_populated_from_openapi_device_type_summary():
    # ise_endpoints_by_endpoint_type comes from the server-aggregated OpenAPI
    # deviceType summary (works without pxGrid), not the "unknown" placeholder.
    client = FakeClient()
    endpoint_attributes.collect(client, _cfg())
    assert _rows(metrics.ise_endpoints_by_endpoint_type, "endpoint_type") == {
        ("windows10-workstation",): 5.0,
        ("android",): 3.0,
    }


def test_endpoint_type_falls_back_to_unknown_when_summary_unavailable():
    client = FakeClient()
    client.get_pan_api = lambda *a, **k: None      # summary endpoint returns nothing
    endpoint_attributes.collect(client, _cfg())
    assert _rows(metrics.ise_endpoints_by_endpoint_type, "endpoint_type") == {("unknown",): 2.0}


def test_profile_all_categories_come_from_ers_hierarchy_without_pxgrid():
    # With no pxGrid catalog, ise_endpoints_by_profile_all still gets real
    # category/parent by walking ERS profilerprofile parentId chains.
    client = FakeClient()
    endpoint_attributes.collect(client, _cfg())
    assert _rows(metrics.ise_endpoints_by_profile_all, "category", "parent", "profile") == {
        ("Microsoft-Workstation", "Microsoft-Workstation", "Windows-Workstation"): 1.0,
        ("Cisco-Device", "Cisco-Device", "Cisco-IP-Phone"): 1.0,
    }
    assert metrics.ise_profiler_policies_total._value.get() == 2


def test_fresh_cache_entries_are_not_refetched():
    client = FakeClient()

    endpoint_attributes.collect(client, _cfg())
    client.calls.clear()
    endpoint_attributes.collect(client, _cfg())

    assert not any(call[0] == "attrs" for call in client.calls)
    assert metrics.ise_endpoint_attribute_scan_last_count._value.get() == 0


def test_persists_cache_between_collector_instances(tmp_path):
    cache = tmp_path / "endpoint-attrs.json"
    client = FakeClient()

    endpoint_attributes.collect(client, _cfg(ers_endpoint_attribute_cache_file=str(cache)))
    endpoint_attributes._records.clear()
    endpoint_attributes._group_cache.clear()
    endpoint_attributes._profile_cache.clear()
    endpoint_attributes._next_page = 1
    endpoint_attributes._cache_loaded = False
    client.calls.clear()

    endpoint_attributes.collect(client, _cfg(ers_endpoint_attribute_cache_file=str(cache)))

    assert metrics.ise_endpoint_attribute_cache_entries._value.get() == 2
    assert not any(call[0] == "attrs" for call in client.calls)


class PagingClient:
    """Models ISE's /config/endpoint list: a single request is capped at size=100
    (ISE 3.3 answers size>100 with HTTP 400, which the real client surfaces as None)."""

    def __init__(self, total):
        self.total = total
        self.calls = []
        self._ids = [f"e{i}" for i in range(total)]

    def get_ers(self, path, params=None, get_all=False, api_name="x"):
        self.calls.append(("get_ers", path, params))
        if path == "/config/endpoint":
            size, page = params["size"], params["page"]
            if size > 100:
                return None          # ISE 3.3 rejects size>100 (HTTP 400)
            start = (page - 1) * size
            return [{"id": eid} for eid in self._ids[start:start + size]]
        if path.startswith("/config/endpoint/"):
            return {"ERSEndPoint": {"profileId": "p", "staticProfileAssignment": "false",
                                    "staticGroupAssignment": "false"}}
        if path.startswith("/config/profilerprofile/"):
            return {"ProfilerProfile": {"name": "SomeProfile"}}
        return None

    def get_ers_total(self, path, params=None, api_name="x"):
        self.calls.append(("get_ers_total", path, params))
        return self.total if path == "/config/endpoint" else None

    def get_pan_api(self, path, api_name="x", unwrap=True):
        return None          # no deviceType summary -> endpoint_type falls back to "unknown"


def _endpoint_list_sizes(client):
    return [call[2]["size"] for call in client.calls
            if call[0] == "get_ers" and call[1] == "/config/endpoint"]


def test_endpoint_list_request_never_exceeds_ers_size_cap():
    # A large refresh budget must not be passed straight through as the ERS size
    # param — ISE 3.3 caps /config/endpoint list requests at 100 (regression).
    client = FakeClient()
    endpoint_attributes.collect(client, _cfg(ers_endpoint_attribute_page_size=500))
    sizes = _endpoint_list_sizes(client)
    assert sizes and all(s <= 100 for s in sizes)


def test_refresh_budget_gathered_across_100_row_ers_pages():
    # 250 endpoints, budget 500 -> three <=100-row pages (100, 100, 50) refreshed
    # in one cycle, gathered across ISE's size cap.
    client = PagingClient(total=250)
    endpoint_attributes.collect(client, _cfg(ers_endpoint_attribute_page_size=500))
    sizes = _endpoint_list_sizes(client)
    assert all(s <= 100 for s in sizes)
    assert metrics.ise_endpoint_attribute_scan_last_count._value.get() == 250
    # a short final page wraps the cursor back to the start for the next cycle
    assert endpoint_attributes._next_page == 1
