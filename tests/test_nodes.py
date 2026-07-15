import types

from ise_exporter.collectors import nodes


def _cfg():
    return types.SimpleNamespace(medium_interval=300)


def test_deployment_node_cache_rejects_unbounded_inventory(monkeypatch):
    monkeypatch.setattr(nodes, "MAX_DEPLOYMENT_NODES", 2)
    nodes._cache.update(nodes=None, ts=0.0)

    class Client:
        def get_pan_api(self, *args, **kwargs):
            return [{"hostname": "one"}, {"hostname": "two"}, {"hostname": "three"}]

    assert nodes.get_nodes(Client(), _cfg(), force=True) is None
    assert nodes._cache == {"nodes": None, "ts": 0.0}


def test_invalid_refresh_clears_previously_cached_nodes():
    nodes._cache.update(nodes=[{"hostname": "old"}], ts=10.0)

    class Client:
        def get_pan_api(self, *args, **kwargs):
            return "not-a-list"

    assert nodes.get_nodes(Client(), _cfg(), force=True) is None
    assert nodes._cache == {"nodes": None, "ts": 0.0}


def test_node_cache_rejects_hostname_path_injection_and_duplicates():
    nodes._cache.update(nodes=None, ts=0.0)

    class Client:
        responses = iter((
            [{"hostname": "psn-1/../../patch"}],
            [{"hostname": "PSN-1"}, {"hostname": "psn-1"}],
        ))

        def get_pan_api(self, *args, **kwargs):
            return next(self.responses)

    client = Client()
    assert nodes.get_nodes(client, _cfg(), force=True) is None
    assert nodes.get_nodes(client, _cfg(), force=True) is None
    assert nodes._cache == {"nodes": None, "ts": 0.0}
