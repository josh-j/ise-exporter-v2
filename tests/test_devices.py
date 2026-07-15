import types

from ise_exporter import metrics
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


def test_device_detail_cache_prunes_removed_inventory_entries(monkeypatch):
    inventories = iter((
        [{"id": "old", "name": "old-switch"}],
        [{"id": "current", "name": "current-switch"}],
    ))

    class Client:
        def get_ers(self, path, params=None, get_all=False, api_name="ers"):
            if path == "/config/networkdevice":
                return next(inventories)
            device_id = path.rsplit("/", 1)[-1]
            return {"NetworkDevice": {"id": device_id, "name": device_id}}

    monkeypatch.setattr(devices, "_cache", None)
    cfg = types.SimpleNamespace(
        collect_device_details=True, device_cache_ttl=3600)
    client = Client()

    devices.collect(client, cfg)
    assert set(devices._cache.cache) == {"old"}
    devices.collect(client, cfg)
    assert set(devices._cache.cache) == {"current"}
    assert set(devices._cache.timestamps) == {"current"}


def test_malformed_device_inventory_does_not_publish_a_count():
    metrics.ise_network_devices_total.set(7)

    class Client:
        def get_ers(self, *args, **kwargs):
            return [{"id": "nad-1", "name": "switch-1"}, None]

    cfg = types.SimpleNamespace(collect_device_details=False)

    assert devices.collect(Client(), cfg) is None
    assert metrics.ise_network_devices_total._value.get() == 7


def test_malformed_device_group_list_invalidates_inventory(monkeypatch):
    class Client:
        def get_ers(self, path, params=None, get_all=False, api_name="ers"):
            if path == "/config/networkdevice":
                return [{"id": "nad-1", "name": "switch-1"}]
            return {"NetworkDevice": {
                "id": "nad-1", "name": "switch-1",
                "NetworkDeviceGroupList": "Location#All Locations#Lab",
            }}

    monkeypatch.setattr(devices, "_cache", None)
    cfg = types.SimpleNamespace(collect_device_details=True, device_cache_ttl=3600)

    assert devices.collect(Client(), cfg) is None


def test_device_group_metric_labels_are_byte_bounded(monkeypatch):
    long_value = "ä" * 300

    class Client:
        def get_ers(self, path, params=None, get_all=False, api_name="ers"):
            if path == "/config/networkdevice":
                return [{"id": "nad-1", "name": "switch-1"}]
            return {"NetworkDevice": {
                "id": "nad-1", "name": "switch-1",
                "NetworkDeviceGroupList": [
                    f"Location#All Locations#{long_value}",
                    f"Ops Owner#All Ops Owners#{long_value}",
                    f"Device Type#All Device Types#{long_value}",
                ],
            }}

    monkeypatch.setattr(devices, "_cache", None)
    cfg = types.SimpleNamespace(collect_device_details=True, device_cache_ttl=3600)

    devices.collect(Client(), cfg)

    for metric in (
            metrics.ise_network_devices_by_location,
            metrics.ise_network_devices_by_ops_owner,
            metrics.ise_network_devices_by_type):
        assert all(len(label.encode("utf-8")) <= 256
                   for labels in metric._metrics for label in labels)
