import types

import pytest

from ise_exporter import metrics
from ise_exporter.collectors import devices
from ise_exporter.state import StateStore


def _cfg(tmp_path, **overrides):
    values = {
        "collect_device_details": True,
        "device_cache_ttl": 3600,
        "device_detail_max_requests": 25,
        "device_detail_request_interval_ms": 100,
        "state_db_path": str(tmp_path / "state.sqlite3"),
    }
    values.update(overrides)
    return types.SimpleNamespace(**values)


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


def test_failed_device_detail_keeps_authoritative_inventory_with_zero_coverage(
        tmp_path, monkeypatch):
    class Client:
        def get_ers(self, path, params=None, get_all=False, api_name="ers"):
            if path == "/config/networkdevice":
                return [{"id": "nad-1", "name": "switch-1"}]
            return None

    monkeypatch.setattr(devices.time, "sleep", lambda _seconds: None)
    cfg = _cfg(tmp_path)

    assert devices.collect(Client(), cfg) == [{"id": "nad-1", "name": "switch-1"}]
    assert metrics.ise_network_device_detail_coverage._value.get() == 0
    assert metrics.ise_network_device_detail_refresh_failures._value.get() == 1


def test_programmatic_config_cannot_relax_device_detail_load_ceilings(
        tmp_path, monkeypatch):
    inventory = [{"id": f"nad-{index}", "name": f"switch-{index}"}
                 for index in range(101)]
    detail_calls = []
    sleeps = []

    class Client:
        def get_ers(self, path, params=None, get_all=False, api_name="ers"):
            if path == "/config/networkdevice":
                return inventory
            device_id = path.rsplit("/", 1)[-1]
            detail_calls.append(device_id)
            return {"NetworkDevice": {"id": device_id, "name": device_id}}

    monkeypatch.setattr(devices.time, "sleep", sleeps.append)
    cfg = _cfg(
        tmp_path,
        device_cache_ttl=0,
        device_detail_max_requests=999999,
        device_detail_request_interval_ms=0,
    )

    assert devices.collect(Client(), cfg) == inventory
    assert len(detail_calls) == 100
    assert sleeps == [0.1] * 99
    assert metrics.ise_network_device_detail_refresh_deferred._value.get() == 1


def test_device_detail_cache_prunes_removed_inventory_entries(tmp_path, monkeypatch):
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

    monkeypatch.setattr(devices.time, "sleep", lambda _seconds: None)
    cfg = _cfg(tmp_path)
    client = Client()

    devices.collect(client, cfg)
    store = StateStore(cfg.state_db_path)
    assert set(store.network_device_entries(["old", "current"])) == {"old"}
    store.close()
    devices.collect(client, cfg)
    store = StateStore(cfg.state_db_path)
    assert set(store.network_device_entries(["old", "current"])) == {"current"}
    store.close()


def test_malformed_device_inventory_does_not_publish_a_count():
    metrics.ise_network_devices_total.set(7)

    class Client:
        def get_ers(self, *args, **kwargs):
            return [{"id": "nad-1", "name": "switch-1"}, None]

    cfg = types.SimpleNamespace(collect_device_details=False)

    assert devices.collect(Client(), cfg) is None
    assert metrics.ise_network_devices_total._value.get() == 7


def test_malformed_device_group_list_is_failed_enrichment_not_inventory_failure(
        tmp_path, monkeypatch):
    class Client:
        def get_ers(self, path, params=None, get_all=False, api_name="ers"):
            if path == "/config/networkdevice":
                return [{"id": "nad-1", "name": "switch-1"}]
            return {"NetworkDevice": {
                "id": "nad-1", "name": "switch-1",
                "NetworkDeviceGroupList": "Location#All Locations#Lab",
            }}

    monkeypatch.setattr(devices.time, "sleep", lambda _seconds: None)
    cfg = _cfg(tmp_path)

    assert devices.collect(Client(), cfg) == [{"id": "nad-1", "name": "switch-1"}]
    assert metrics.ise_network_device_detail_coverage._value.get() == 0


def test_device_group_metric_labels_are_byte_bounded(tmp_path, monkeypatch):
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

    monkeypatch.setattr(devices.time, "sleep", lambda _seconds: None)
    cfg = _cfg(tmp_path)

    devices.collect(Client(), cfg)

    for metric in (
            metrics.ise_network_devices_by_location,
            metrics.ise_network_devices_by_ops_owner,
            metrics.ise_network_devices_by_type):
        assert all(len(label.encode("utf-8")) <= 256
                   for labels in metric._metrics for label in labels)


def test_device_detail_refresh_is_bounded_and_converges_across_restarts(
        tmp_path, monkeypatch):
    calls = []

    class Client:
        def get_ers(self, path, params=None, get_all=False, api_name="ers"):
            if path == "/config/networkdevice":
                return [{"id": f"nad-{number}", "name": f"switch-{number}"}
                        for number in range(5)]
            calls.append(path)
            device_id = path.rsplit("/", 1)[-1]
            return {"NetworkDevice": {
                "id": device_id,
                "NetworkDeviceGroupList": [
                    "Location#All Locations#Production",
                ],
                # This field must never be copied into the local state DB.
                "authenticationSettings": {"networkProtocol": "RADIUS",
                                           "radiusSharedSecret": "do-not-persist"},
            }}

    monkeypatch.setattr(devices.time, "sleep", lambda _seconds: None)
    cfg = _cfg(tmp_path, device_detail_max_requests=2)
    client = Client()

    devices.collect(client, cfg)
    assert len(calls) == 2
    assert metrics.ise_network_device_detail_coverage._value.get() == pytest.approx(2 / 5)
    assert metrics.ise_network_device_detail_refresh_deferred._value.get() == 3

    devices.collect(client, cfg)
    assert len(calls) == 4
    assert metrics.ise_network_device_detail_coverage._value.get() == pytest.approx(4 / 5)

    devices.collect(client, cfg)
    assert len(calls) == 5
    assert metrics.ise_network_device_detail_coverage._value.get() == 1
    assert metrics.ise_network_device_detail_refresh_deferred._value.get() == 0
    assert b"do-not-persist" not in (tmp_path / "state.sqlite3").read_bytes()


def test_device_detail_refresh_stops_after_three_consecutive_failures(
        tmp_path, monkeypatch):
    calls = []

    class Client:
        def get_ers(self, path, params=None, get_all=False, api_name="ers"):
            if path == "/config/networkdevice":
                return [{"id": f"nad-{number}", "name": f"switch-{number}"}
                        for number in range(10)]
            calls.append(path)
            return None

    monkeypatch.setattr(devices.time, "sleep", lambda _seconds: None)
    devices.collect(Client(), _cfg(tmp_path, device_detail_max_requests=10))

    assert len(calls) == 3
    assert metrics.ise_network_device_detail_refresh_failures._value.get() == 3
    assert metrics.ise_network_device_detail_refresh_deferred._value.get() == 10
