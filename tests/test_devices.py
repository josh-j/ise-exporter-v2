from collections import defaultdict
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
        tmp_path, monkeypatch, caplog):
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
    assert "collector detail dataset=devices source=rest" in caplog.text
    assert "outcome=partial" in caplog.text
    assert "refresh_failures=1" in caplog.text
    assert "refresh_deferred=1" in caplog.text
    assert "action=retain_cached_details_and_retry_next_cycle" in caplog.text


def test_programmatic_config_keeps_count_ceiling_but_honors_request_pacing(
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
        device_detail_max_requests=50,
        device_detail_request_interval_ms=0,
    )

    assert devices.collect(Client(), cfg) == inventory
    assert len(detail_calls) == 50
    assert sleeps == []
    assert metrics.ise_network_device_detail_refresh_deferred._value.get() == 51


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


def test_device_ndg_assignment_preserves_nad_to_ops_owner_and_location(
        tmp_path, monkeypatch):
    class Client:
        def get_ers(self, path, params=None, get_all=False, api_name="ers"):
            if path == "/config/networkdevice":
                return [{"id": "nad-1", "name": "switch-1"}]
            return {"NetworkDevice": {
                "id": "nad-1",
                "name": "switch-1",
                "NetworkDeviceGroupList": [
                    "Location#All Locations#Germany#Berlin",
                    "Ops Owner#All Ops Owners#Campus",
                    "Device Type#All Device Types#Switch",
                ],
            }}

    monkeypatch.setattr(devices.time, "sleep", lambda _seconds: None)
    devices.collect(Client(), _cfg(tmp_path))

    assert set(metrics.ise_network_device_ndg_assignment._metrics) == {
        ("switch-1", "Germany#Berlin", "Campus", "Switch")}
    assert metrics.ise_network_device_ndg_assignment.labels(
        nad="switch-1",
        location="Germany#Berlin",
        ops_owner="Campus",
        device_type="Switch",
    )._value.get() == 1


def test_device_classification_groups_are_bounded_with_exact_totals(monkeypatch):
    monkeypatch.setattr(devices, "MAX_CLASSIFICATION_GROUPS", 3)
    counts = defaultdict(int)

    for key in ("one", "two", "three", "four", "five"):
        devices._increment_classification(counts, key)

    assert len(counts) == 3
    assert counts == {"one": 1, "two": 1, "Other": 3}
    assert sum(counts.values()) == 5


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


def test_zero_detail_budget_auto_sizes_to_inventory_in_one_pass(
        tmp_path, monkeypatch):
    inventory = [{"id": f"nad-{index}", "name": f"switch-{index}"}
                 for index in range(7)]
    detail_calls = []

    class Client:
        def get_ers(self, path, params=None, get_all=False, api_name="ers"):
            if path == "/config/networkdevice":
                return inventory
            device_id = path.rsplit("/", 1)[-1]
            detail_calls.append(device_id)
            return {"NetworkDevice": {
                "id": device_id,
                "NetworkDeviceGroupList": ["Location#All Locations#Lab"],
            }}

    monkeypatch.setattr(devices.time, "sleep", lambda _seconds: None)
    cfg = _cfg(tmp_path, device_detail_max_requests=0)

    assert devices.collect(Client(), cfg) == inventory
    # Auto (0) sizes the pass to the whole inventory rather than the old cap.
    assert len(detail_calls) == 7
    assert metrics.ise_network_device_detail_coverage._value.get() == 1
    assert metrics.ise_network_device_detail_refresh_deferred._value.get() == 0


def test_auto_detail_budget_is_bounded_by_the_hard_ceiling(tmp_path, monkeypatch):
    monkeypatch.setattr(devices, "DETAIL_REQUEST_CEILING", 4)
    inventory = [{"id": f"nad-{index}", "name": f"switch-{index}"}
                 for index in range(10)]
    detail_calls = []

    class Client:
        def get_ers(self, path, params=None, get_all=False, api_name="ers"):
            if path == "/config/networkdevice":
                return inventory
            detail_calls.append(path)
            return {"NetworkDevice": {
                "id": path.rsplit("/", 1)[-1],
                "NetworkDeviceGroupList": ["Location#All Locations#Lab"],
            }}

    monkeypatch.setattr(devices.time, "sleep", lambda _seconds: None)
    devices.collect(Client(), _cfg(tmp_path, device_detail_max_requests=0))

    # Auto never exceeds the hard per-pass ceiling even when inventory is larger;
    # the 6 devices left unrefreshed this pass are deferred to the next one.
    assert len(detail_calls) == 4
    assert metrics.ise_network_device_detail_refresh_deferred._value.get() == 6


def test_auto_budget_cold_start_refreshes_whole_small_inventory_in_one_pass(
        tmp_path, monkeypatch):
    # Never-cached devices must still converge at full speed: cold start behavior
    # is unchanged by the rotation-trickle math (uncached dominates the budget).
    inventory = [{"id": f"nad-{index}", "name": f"switch-{index}"}
                 for index in range(9)]
    detail_calls = []

    class Client:
        def get_ers(self, path, params=None, get_all=False, api_name="ers"):
            if path == "/config/networkdevice":
                return inventory
            device_id = path.rsplit("/", 1)[-1]
            detail_calls.append(device_id)
            return {"NetworkDevice": {
                "id": device_id,
                "NetworkDeviceGroupList": ["Location#All Locations#Lab"],
            }}

    monkeypatch.setattr(devices.time, "sleep", lambda _seconds: None)
    cfg = _cfg(tmp_path, device_detail_max_requests=0,
               device_cache_ttl=2592000, slow_interval=21600)

    assert devices.collect(Client(), cfg) == inventory
    assert len(detail_calls) == 9
    assert metrics.ise_network_device_detail_coverage._value.get() == 1
    assert metrics.ise_network_device_detail_refresh_deferred._value.get() == 0


def test_auto_budget_trickles_ttl_rotation_instead_of_a_synchronized_burst(
        tmp_path, monkeypatch):
    # Fully cached inventory whose TTL just expired: the auto budget must only
    # take the rotation-target slice (one inventory pass spread across the TTL
    # window), not re-fetch everything in a single synchronized burst.
    inventory = [{"id": f"nad-{index}", "name": f"switch-{index}"}
                 for index in range(1000)]
    detail_calls = []

    class Client:
        def get_ers(self, path, params=None, get_all=False, api_name="ers"):
            if path == "/config/networkdevice":
                return inventory
            device_id = path.rsplit("/", 1)[-1]
            detail_calls.append(device_id)
            return {"NetworkDevice": {
                "id": device_id,
                "NetworkDeviceGroupList": ["Location#All Locations#Lab"],
            }}

    monkeypatch.setattr(devices.time, "sleep", lambda _seconds: None)
    ttl = 1_000_000
    interval = 10_000
    cfg = _cfg(tmp_path, device_detail_max_requests=0,
               device_cache_ttl=ttl, slow_interval=interval)

    now = 2_000_000
    monkeypatch.setattr(devices.time, "time", lambda: now)
    store = StateStore(cfg.state_db_path)
    stale_at = now - ttl - 1
    for row in inventory:
        store.put_network_device(
            row["id"], {"NetworkDeviceGroupList": ["Location#All Locations#Lab"]},
            now=stale_at)
    store.commit()
    store.close()

    devices.collect(Client(), cfg)

    # rotation_target = ceil(1000 * 10000 / 1000000) == 10
    assert len(detail_calls) == 10
    assert metrics.ise_network_device_detail_refresh_deferred._value.get() == 990


def test_explicit_positive_detail_budget_is_honored_unchanged(tmp_path, monkeypatch):
    # An explicit operator override keeps its exact current behavior -- no
    # rotation shaping, even on a fully-cached, TTL-expired inventory.
    inventory = [{"id": f"nad-{index}", "name": f"switch-{index}"}
                 for index in range(1000)]
    detail_calls = []

    class Client:
        def get_ers(self, path, params=None, get_all=False, api_name="ers"):
            if path == "/config/networkdevice":
                return inventory
            device_id = path.rsplit("/", 1)[-1]
            detail_calls.append(device_id)
            return {"NetworkDevice": {
                "id": device_id,
                "NetworkDeviceGroupList": ["Location#All Locations#Lab"],
            }}

    monkeypatch.setattr(devices.time, "sleep", lambda _seconds: None)
    ttl = 1_000_000
    cfg = _cfg(tmp_path, device_detail_max_requests=17,
               device_cache_ttl=ttl, slow_interval=10_000)

    now = 2_000_000
    monkeypatch.setattr(devices.time, "time", lambda: now)
    store = StateStore(cfg.state_db_path)
    stale_at = now - ttl - 1
    for row in inventory:
        store.put_network_device(
            row["id"], {"NetworkDeviceGroupList": ["Location#All Locations#Lab"]},
            now=stale_at)
    store.commit()
    store.close()

    devices.collect(Client(), cfg)

    assert len(detail_calls) == 17
    assert metrics.ise_network_device_detail_refresh_deferred._value.get() == 983


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
