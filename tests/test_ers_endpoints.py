"""ERS endpoint fallback: counts endpoints per profiling policy, only when pxGrid
getEndpoints came back empty, picking the cheaper of per-endpoint / per-profile."""
import types

import pytest

from ise_exporter import metrics
from ise_exporter.collectors import ers_endpoints, models
from ise_exporter.util import clear_metric


@pytest.fixture(autouse=True)
def _reset_caches():
    ers_endpoints._name_cache.clear()
    ers_endpoints._catalog = []
    ers_endpoints._catalog_at = 0.0
    yield


class FakeClient:
    """Per-profile shape: a profile catalog + a profileId->endpoint-count map."""
    def __init__(self, total, profiles, counts):
        self.total = total
        self.profiles = profiles        # catalog [{id, name}]
        self.counts = counts            # profileId -> endpoint count
        self.calls = []

    def get_ers_total(self, path, params=None, api_name="x"):
        self.calls.append((path, params))
        if path == "/config/profilerprofile":
            return len(self.profiles)
        if path == "/config/endpoint" and params and "filter" in params:
            pid = params["filter"].split(".EQ.", 1)[1]
            return self.counts.get(pid, 0)
        if path == "/config/endpoint":
            return self.total
        return None

    def get_ers(self, path, params=None, get_all=False, api_name="x"):
        self.calls.append((path, params))
        return self.profiles if path == "/config/profilerprofile" else None


def _cfg(**over):
    base = dict(ers_endpoint_profile_max=1500, max_workers=2, max_detail_fetches_per_cycle=2000)
    base.update(over)
    return types.SimpleNamespace(**base)


def _by(metric, label):
    return {s.labels[label]: s.value for s in metric.collect()[0].samples}


def test_ers_fallback_skips_when_pxgrid_endpoints_present():
    metrics.ise_endpoints_pxgrid_total.set(500)
    client = FakeClient(total=0, profiles=[], counts={})
    ers_endpoints.collect(client, _cfg())
    assert client.calls == []


def test_ers_fallback_counts_per_profile_when_endpoints_outnumber_profiles():
    metrics.ise_endpoints_pxgrid_total.set(0)
    profiles = [{"id": "p1", "name": "Microsoft-Workstation"},
                {"id": "p2", "name": "Apple-iPhone"},
                {"id": "p3", "name": "Unused-Profile"}]
    # total (150) > catalog (3) -> per-profile
    client = FakeClient(total=150, profiles=profiles, counts={"p1": 120, "p2": 30, "p3": 0})
    clear_metric(metrics.ise_endpoints_by_policy)

    ers_endpoints.collect(client, _cfg())

    assert _by(metrics.ise_endpoints_by_policy, "policy") == {
        "Microsoft-Workstation": 120.0, "Apple-iPhone": 30.0}
    assert metrics.ise_endpoints_total._value.get() == 150
    assert _by(metrics.ise_endpoints_by_hardware_model, "model") == {"unknown": 150.0}
    assert _by(metrics.ise_endpoints_by_manufacturer, "manufacturer") == {"unknown": 150.0}
    assert _by(metrics.ise_endpoints_by_endpoint_type, "endpoint_type") == {"unknown": 150.0}
    assert _by(metrics.ise_endpoints_by_os, "os") == {"unknown": 150.0}
    assert _by(metrics.ise_endpoint_mfc_coverage, "attribute") == {
        "model": 0.0, "manufacturer": 0.0, "endpoint_type": 0.0, "os": 0.0}


def test_ers_fallback_joins_getprofiles_hierarchy_when_cached():
    metrics.ise_endpoints_pxgrid_total.set(0)
    models._hierarchy = {"Apple-iPhone": ("Apple-Device", "Apple-iDevice")}
    try:
        client = FakeClient(total=50, profiles=[{"id": "p2", "name": "Apple-iPhone"}],
                            counts={"p2": 50})
        clear_metric(metrics.ise_endpoints_by_profile_all)
        ers_endpoints.collect(client, _cfg())
        rows = {(s.labels["category"], s.labels["parent"], s.labels["profile"]): s.value
                for s in metrics.ise_endpoints_by_profile_all.collect()[0].samples}
        assert rows[("Apple-Device", "Apple-iDevice", "Apple-iPhone")] == 50.0
    finally:
        models._hierarchy = {}


def test_ers_fallback_caps_profile_queries():
    metrics.ise_endpoints_pxgrid_total.set(0)
    profiles = [{"id": f"p{i}", "name": f"Profile-{i}"} for i in range(10)]
    client = FakeClient(total=100, profiles=profiles, counts={"p0": 1})   # 100 > 10 -> per-profile
    clear_metric(metrics.ise_endpoints_by_policy)

    ers_endpoints.collect(client, _cfg(ers_endpoint_profile_max=3))

    assert sum(1 for c in client.calls if c[0] == "/config/endpoint" and c[1] and "filter" in c[1]) == 3


def test_ers_fallback_uses_per_endpoint_when_endpoints_fewer_than_profiles():
    """Lab shape: 2 endpoints, 2 profiles -> read each endpoint's profileId and resolve
    the name lazily, never enumerating the (slow) full catalog."""
    metrics.ise_endpoints_pxgrid_total.set(0)

    class EpClient:
        def __init__(self):
            self.calls = []

        def get_ers_total(self, path, params=None, api_name="x"):
            self.calls.append(("total", path, params))
            if path == "/config/profilerprofile":
                return 2                       # catalog size (cheap)
            if path == "/config/endpoint":
                return 2                       # 2 endpoints
            return None

        def get_ers(self, path, params=None, get_all=False, api_name="x"):
            self.calls.append(("get", path))
            if path == "/config/endpoint":
                return [{"id": "e1"}, {"id": "e2"}]
            if path in ("/config/endpoint/e1", "/config/endpoint/e2"):
                return {"ERSEndPoint": {"profileId": "u-ws"}}
            if path == "/config/profilerprofile/u-ws":
                return {"ProfilerProfile": {"name": "Microsoft-Workstation"}}
            return None

    client = EpClient()
    clear_metric(metrics.ise_endpoints_by_policy)
    ers_endpoints.collect(client, _cfg())

    assert _by(metrics.ise_endpoints_by_policy, "policy") == {"Microsoft-Workstation": 2.0}
    assert ("get", "/config/endpoint") in client.calls          # endpoint list
    assert ("get", "/config/endpoint/e1") in client.calls       # detail
    assert ("get", "/config/profilerprofile/u-ws") in client.calls   # lazy name resolve
    # never enumerated the full catalog, and never ran a per-profile filter count
    assert not any(c[0] == "total" and c[2] and "filter" in c[2] for c in client.calls)


def test_ers_fallback_name_resolution_is_cached():
    metrics.ise_endpoints_pxgrid_total.set(0)

    class EpClient:
        def __init__(self):
            self.profile_gets = 0

        def get_ers_total(self, path, params=None, api_name="x"):
            return 3 if path == "/config/endpoint" else (5 if path == "/config/profilerprofile" else None)

        def get_ers(self, path, params=None, get_all=False, api_name="x"):
            if path == "/config/endpoint":
                return [{"id": "e1"}, {"id": "e2"}, {"id": "e3"}]
            if path.startswith("/config/endpoint/"):
                return {"ERSEndPoint": {"profileId": "u-x"}}
            if path == "/config/profilerprofile/u-x":
                self.profile_gets += 1
                return {"ProfilerProfile": {"name": "Profile-X"}}
            return None

    client = EpClient()
    clear_metric(metrics.ise_endpoints_by_policy)
    ers_endpoints.collect(client, _cfg())

    assert _by(metrics.ise_endpoints_by_policy, "policy") == {"Profile-X": 3.0}
    assert client.profile_gets == 1   # 3 endpoints share one profile -> one name lookup
