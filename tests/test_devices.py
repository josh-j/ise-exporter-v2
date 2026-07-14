import types

from ise_exporter.collectors import devices


def test_device_collector_returns_authoritative_inventory_without_duplicate_fetch():
    expected = [{"id": "nad-1", "name": "switch-1"}]

    class Client:
        def __init__(self):
            self.calls = []

        def get_ers(self, path, params=None, get_all=False, api_name="ers"):
            self.calls.append((path, params, get_all, api_name))
            return expected

    client = Client()
    cfg = types.SimpleNamespace(collect_device_details=False)

    assert devices.collect(client, cfg) is expected
    assert client.calls == [
        ("/config/networkdevice", {"size": 100}, True, "ers_devices")]


def test_failed_device_detail_invalidates_inventory_for_nad_join(monkeypatch):
    class Client:
        def get_ers(self, path, params=None, get_all=False, api_name="ers"):
            if path == "/config/networkdevice":
                return [{"id": "nad-1", "name": "switch-1"}]
            return None

    monkeypatch.setattr(devices, "_cache", None)
    cfg = types.SimpleNamespace(collect_device_details=True, device_cache_ttl=3600)

    assert devices.collect(Client(), cfg) is None
