"""ERS endpoint fallback: counts endpoints per profiling policy via ERS filter
queries, but only when pxGrid getEndpoints came back empty."""
import types

from ise_exporter import metrics
from ise_exporter.collectors import ers_endpoints, models
from ise_exporter.util import clear_metric


class FakeClient:
    def __init__(self, total, profiles, counts):
        self.total = total
        self.profiles = profiles
        self.counts = counts        # profileId -> endpoint count
        self.calls = []

    def get_ers_total(self, path, params=None, api_name="x"):
        self.calls.append((path, params))
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
    base = dict(ers_endpoint_profile_max=800, max_workers=2)
    base.update(over)
    return types.SimpleNamespace(**base)


def _by(metric, label):
    return {s.labels[label]: s.value for s in metric.collect()[0].samples}


def test_ers_fallback_skips_when_pxgrid_endpoints_present():
    metrics.ise_endpoints_pxgrid_total.set(500)   # pxGrid is delivering
    client = FakeClient(total=0, profiles=[], counts={})
    ers_endpoints.collect(client, _cfg())
    assert client.calls == []                      # skipped without touching ERS


def test_ers_fallback_counts_endpoints_per_profile_when_pxgrid_empty():
    metrics.ise_endpoints_pxgrid_total.set(0)      # pxGrid getEndpoints returned nothing
    profiles = [{"id": "p1", "name": "Microsoft-Workstation"},
                {"id": "p2", "name": "Apple-iPhone"},
                {"id": "p3", "name": "Unused-Profile"}]
    client = FakeClient(total=150, profiles=profiles, counts={"p1": 120, "p2": 30, "p3": 0})
    clear_metric(metrics.ise_endpoints_by_policy)
    clear_metric(metrics.ise_endpoints_by_profile_all)

    ers_endpoints.collect(client, _cfg())

    # zero-count profiles are not emitted (keeps cardinality down)
    assert _by(metrics.ise_endpoints_by_policy, "policy") == {
        "Microsoft-Workstation": 120.0, "Apple-iPhone": 30.0}
    assert metrics.ise_endpoints_total._value.get() == 150
    # one filter query per catalog profile, bounded by profile count not endpoint count
    assert sum(1 for c in client.calls if c[1] and "filter" in c[1]) == 3


def test_ers_fallback_joins_getprofiles_hierarchy_when_cached():
    metrics.ise_endpoints_pxgrid_total.set(0)
    models._hierarchy = {"Apple-iPhone": ("Apple-Device", "Apple-iDevice")}
    try:
        client = FakeClient(total=5, profiles=[{"id": "p2", "name": "Apple-iPhone"}],
                            counts={"p2": 5})
        clear_metric(metrics.ise_endpoints_by_profile_all)
        ers_endpoints.collect(client, _cfg())
        rows = {(s.labels["category"], s.labels["parent"], s.labels["profile"]): s.value
                for s in metrics.ise_endpoints_by_profile_all.collect()[0].samples}
        assert rows[("Apple-Device", "Apple-iDevice", "Apple-iPhone")] == 5.0
    finally:
        models._hierarchy = {}


def test_ers_fallback_caps_profile_queries():
    metrics.ise_endpoints_pxgrid_total.set(0)
    profiles = [{"id": f"p{i}", "name": f"Profile-{i}"} for i in range(10)]
    client = FakeClient(total=1, profiles=profiles, counts={"p0": 1})
    clear_metric(metrics.ise_endpoints_by_policy)

    ers_endpoints.collect(client, _cfg(ers_endpoint_profile_max=3))

    # only the first 3 profiles queried
    assert sum(1 for c in client.calls if c[1] and "filter" in c[1]) == 3
