import sqlite3
import stat

import pytest

import ise_exporter.state as state_module
from ise_exporter.state import STATE_SCHEMA_VERSION, StateStore


def test_database_and_live_wal_sidecars_are_private(tmp_path):
    path = tmp_path / "state.sqlite3"
    store = StateStore(path)
    store.set_value("sensitive", "cached ISE material")

    modes = {
        candidate.name: stat.S_IMODE(candidate.stat().st_mode)
        for candidate in tmp_path.iterdir()
    }

    assert modes["state.sqlite3"] == 0o600
    assert modes["state.sqlite3-wal"] == 0o600
    assert modes["state.sqlite3-shm"] == 0o600
    store.close()


def test_upgrade_removes_obsolete_dataconnect_rollup_history(tmp_path):
    path = tmp_path / "state.sqlite3"
    db = sqlite3.connect(path)
    db.execute("""
        CREATE TABLE dataconnect_rollup (
            dataset TEXT NOT NULL,
            window_start REAL NOT NULL,
            window_end REAL NOT NULL,
            rows_json TEXT NOT NULL,
            PRIMARY KEY (dataset, window_start, window_end)
        )
    """)
    db.execute(
        "INSERT INTO dataconnect_rollup VALUES (?, ?, ?, ?)",
        ("authentication", 1.0, 2.0, '[{"events":100}]'),
    )
    db.commit()
    db.close()

    store = StateStore(path)
    tables = {
        row[0] for row in store.db.execute(
            "SELECT name FROM sqlite_master WHERE type='table'")
    }
    store.close()

    assert "dataconnect_rollup" not in tables
    assert {
        "mnt_posture_cache", "tacacs_internal_user_cache",
        "tacacs_policy_rule_cache", "network_device_group_cache", "exporter_state",
    } <= tables

    db = sqlite3.connect(path)
    assert db.execute("PRAGMA user_version").fetchone()[0] == STATE_SCHEMA_VERSION
    db.close()


def test_newer_state_schema_is_rejected_without_downgrade(tmp_path):
    path = tmp_path / "state.sqlite3"
    db = sqlite3.connect(path)
    db.execute(f"PRAGMA user_version = {STATE_SCHEMA_VERSION + 1}")
    db.close()

    with pytest.raises(RuntimeError, match="newer than supported"):
        StateStore(path)

    db = sqlite3.connect(path)
    assert db.execute("PRAGMA user_version").fetchone()[0] == STATE_SCHEMA_VERSION + 1
    db.close()


def test_state_database_symlink_is_rejected(tmp_path):
    target = tmp_path / "real.sqlite3"
    target.touch()
    link = tmp_path / "state.sqlite3"
    link.symlink_to(target)

    with pytest.raises(OSError):
        StateStore(link)


def test_invalid_cache_rows_are_pruned_and_not_counted(tmp_path):
    store = StateStore(tmp_path / "state.sqlite3")
    store.db.execute(
        "INSERT INTO mnt_posture_cache VALUES (?, ?, ?, ?, ?)",
        ("AA:BB:CC:DD:EE:FF", "signature", "not-json", 10, 10),
    )
    store.db.execute(
        "INSERT INTO tacacs_internal_user_cache VALUES (?, ?, ?, ?)",
        ("u1", '{"name":"one"}', "not-a-time", 10),
    )
    store.db.execute(
        "INSERT INTO network_device_group_cache VALUES (?, ?, ?, ?)",
        ("nad-1", "not-json", 10, 10),
    )
    store.db.execute(
        "INSERT INTO network_device_group_cache VALUES (?, ?, ?, ?)",
        ("nad-2", '{"NetworkDeviceGroupList":"not-a-list"}', 10, 10),
    )
    store.commit()

    assert store.posture_entries(["AA:BB:CC:DD:EE:FF"]) == {}
    assert store.tacacs_user_entries(["u1"]) == {}
    assert store.network_device_entries(["nad-1", "nad-2"]) == {}
    assert store.posture_count() == 0
    assert store.tacacs_user_count() == 0
    assert store.network_device_count() == 0
    store.close()


def test_tacacs_user_cache_is_bounded_to_current_inventory(tmp_path):
    store = StateStore(tmp_path / "state.sqlite3")
    store.put_tacacs_user("u1", {"name": "one"}, now=10)
    store.put_tacacs_user("u2", {"name": "two"}, now=10)
    store.finish_tacacs_user_cycle(["u2"], now=20)

    assert store.tacacs_user_entries(["u1", "u2"]) == {
        "u2": {"detail": {"name": "two"}, "updated_at": 10.0},
    }
    assert store.tacacs_user_count() == 1
    store.close()


def test_tacacs_policy_cache_is_bounded_to_current_inventory(tmp_path):
    store = StateStore(tmp_path / "state.sqlite3")
    store.put_tacacs_policy("p1", 2, 3, now=10)
    store.put_tacacs_policy("p2", 4, 5, now=10)
    store.finish_tacacs_policy_cycle(["p2"], now=20)

    assert store.tacacs_policy_entries(["p1", "p2"]) == {
        "p2": {
            "authentication_rules": 4,
            "authorization_rules": 5,
            "updated_at": 10.0,
        },
    }
    assert store.tacacs_policy_count() == 1
    store.close()


def test_invalid_tacacs_policy_cache_row_is_pruned(tmp_path):
    store = StateStore(tmp_path / "state.sqlite3")
    store.db.execute(
        "INSERT INTO tacacs_policy_rule_cache VALUES (?, ?, ?, ?, ?)",
        ("p1", -1, 3, 10, 10),
    )
    store.commit()

    assert store.tacacs_policy_entries(["p1"]) == {}
    assert store.tacacs_policy_count() == 0
    store.close()


def test_network_device_cache_is_bounded_to_current_inventory(tmp_path):
    store = StateStore(tmp_path / "state.sqlite3")
    store.put_network_device(
        "nad-1", {"NetworkDeviceGroupList": ["Location#All Locations#Old"]}, now=10)
    store.put_network_device(
        "nad-2", {"NetworkDeviceGroupList": ["Location#All Locations#Current"]},
        now=10)
    store.finish_network_device_cycle(["nad-2"], now=20)

    assert store.network_device_entries(["nad-1", "nad-2"]) == {
        "nad-2": {
            "detail": {
                "NetworkDeviceGroupList": ["Location#All Locations#Current"],
            },
            "updated_at": 10.0,
        },
    }
    assert store.network_device_count() == 1
    store.close()


def test_oversized_persisted_dataset_snapshot_is_ignored(tmp_path, monkeypatch):
    store = StateStore(tmp_path / "state.sqlite3")
    store.replace_dataset_snapshot("radius", 10, {"value": "x" * 100})
    monkeypatch.setattr(state_module, "MAX_PERSISTED_SNAPSHOT_BYTES", 32)

    assert store.dataset_snapshot("radius") is None
    assert store.get_value("dataset_snapshot.radius") is None
    store.close()


def test_oversized_dataset_snapshot_is_not_written(tmp_path, monkeypatch):
    store = StateStore(tmp_path / "state.sqlite3")
    monkeypatch.setattr(state_module, "MAX_PERSISTED_SNAPSHOT_BYTES", 32)

    with pytest.raises(ValueError, match="size limit"):
        store.replace_dataset_snapshot("radius", 10, {"value": "x" * 100})

    assert store.get_value("dataset_snapshot.radius") is None
    store.close()


@pytest.mark.parametrize("updated_at", (float("nan"), float("inf"), -1))
def test_dataset_snapshot_rejects_invalid_timestamp(tmp_path, updated_at):
    store = StateStore(tmp_path / "state.sqlite3")

    with pytest.raises(ValueError, match="finite and non-negative"):
        store.replace_dataset_snapshot("radius", updated_at, {})

    assert store.get_value("dataset_snapshot.radius") is None
    store.close()


def test_invalid_dataset_snapshot_is_pruned(tmp_path):
    store = StateStore(tmp_path / "state.sqlite3")
    store.set_value(
        "dataset_snapshot.radius", '{"updated_at":"NaN","payload":{}}')

    assert store.dataset_snapshot("radius") is None
    assert store.get_value("dataset_snapshot.radius") is None
    store.close()


def test_bounded_state_value_is_not_materialized_and_is_pruned(tmp_path):
    store = StateStore(tmp_path / "state.sqlite3")
    store.set_value("bounded", "x" * 100)

    assert store.get_value("bounded", "fallback", max_bytes=32) == "fallback"
    assert store.get_value("bounded") is None
    store.close()


def test_oversized_bounded_state_value_is_not_written(tmp_path):
    store = StateStore(tmp_path / "state.sqlite3")

    with pytest.raises(ValueError, match="size limit"):
        store.set_value("bounded", "x" * 100, max_bytes=32)

    assert store.get_value("bounded") is None
    store.close()


@pytest.mark.parametrize(("method", "table", "message"), (
    ("posture", "mnt_posture_cache", "posture cache detail"),
    ("tacacs", "tacacs_internal_user_cache", "TACACS cache detail"),
))
def test_oversized_cache_detail_is_not_written(
        tmp_path, monkeypatch, method, table, message):
    store = StateStore(tmp_path / "state.sqlite3")
    if method == "posture":
        monkeypatch.setattr(state_module, "MAX_POSTURE_CACHE_DETAIL_BYTES", 32)

        def write():
            store.put_posture(
                "AA:BB:CC:DD:EE:FF", "signature", {"value": "x" * 100}, now=10)
    else:
        monkeypatch.setattr(state_module, "MAX_TACACS_CACHE_DETAIL_BYTES", 32)

        def write():
            store.put_tacacs_user("u1", {"value": "x" * 100}, now=10)

    with pytest.raises(ValueError, match=message):
        write()

    assert store.db.execute(f"SELECT COUNT(*) FROM {table}").fetchone()[0] == 0
    store.close()


@pytest.mark.parametrize(("method", "table", "key"), (
    ("posture", "mnt_posture_cache", "AA:BB:CC:DD:EE:FF"),
    ("tacacs", "tacacs_internal_user_cache", "u1"),
))
def test_oversized_cache_detail_is_not_materialized_and_is_pruned(
        tmp_path, monkeypatch, method, table, key):
    store = StateStore(tmp_path / "state.sqlite3")
    oversized = '{"value":"' + ("x" * 100) + '"}'
    if method == "posture":
        monkeypatch.setattr(state_module, "MAX_POSTURE_CACHE_DETAIL_BYTES", 32)
        store.db.execute(
            "INSERT INTO mnt_posture_cache VALUES (?, ?, ?, ?, ?)",
            (key, "signature", oversized, 10, 10),
        )
        def read():
            return store.posture_entries([key])
    else:
        monkeypatch.setattr(state_module, "MAX_TACACS_CACHE_DETAIL_BYTES", 32)
        store.db.execute(
            "INSERT INTO tacacs_internal_user_cache VALUES (?, ?, ?, ?)",
            (key, oversized, 10, 10),
        )
        def read():
            return store.tacacs_user_entries([key])
    store.commit()

    assert read() == {}
    assert store.db.execute(f"SELECT COUNT(*) FROM {table}").fetchone()[0] == 0
    store.close()


@pytest.mark.parametrize("now", (float("nan"), float("inf"), -1))
@pytest.mark.parametrize("operation", (
    "put_posture", "finish_posture_cycle", "put_tacacs", "finish_tacacs_cycle",
    "put_network_device", "finish_network_device_cycle",
))
def test_cache_operations_reject_invalid_timestamps(tmp_path, operation, now):
    store = StateStore(tmp_path / "state.sqlite3")

    with pytest.raises(ValueError, match="finite and non-negative"):
        if operation == "put_posture":
            store.put_posture("AA:BB:CC:DD:EE:FF", "signature", {}, now=now)
        elif operation == "finish_posture_cycle":
            store.finish_posture_cycle(["AA:BB:CC:DD:EE:FF"], now=now)
        elif operation == "put_tacacs":
            store.put_tacacs_user("u1", {}, now=now)
        elif operation == "finish_tacacs_cycle":
            store.finish_tacacs_user_cycle(["u1"], now=now)
        elif operation == "put_network_device":
            store.put_network_device("nad-1", {}, now=now)
        else:
            store.finish_network_device_cycle(["nad-1"], now=now)

    assert store.posture_count() == 0
    assert store.tacacs_user_count() == 0
    assert store.network_device_count() == 0
    store.close()


@pytest.mark.parametrize(("kind", "table", "key_column"), (
    ("posture", "mnt_posture_cache", "mac"),
    ("tacacs_user", "tacacs_internal_user_cache", "user_id"),
    ("tacacs_policy", "tacacs_policy_rule_cache", "policy_id"),
    ("network_device", "network_device_group_cache", "device_id"),
))
def test_large_cache_cycle_prunes_future_dated_stale_rows(
        tmp_path, kind, table, key_column):
    store = StateStore(tmp_path / "state.sqlite3")
    active = [f"active-{index}" for index in range(1001)]
    if kind == "posture":
        store.db.executemany(
            "INSERT INTO mnt_posture_cache VALUES (?, ?, ?, ?, ?)",
            ((key, "signature", "{}", 10, 10) for key in (active[0], "stale")),
        )
        finish = store.finish_posture_cycle
    elif kind == "tacacs_user":
        store.db.executemany(
            "INSERT INTO tacacs_internal_user_cache VALUES (?, ?, ?, ?)",
            ((key, "{}", 10, 10) for key in (active[0], "stale")),
        )
        finish = store.finish_tacacs_user_cycle
    elif kind == "tacacs_policy":
        store.db.executemany(
            "INSERT INTO tacacs_policy_rule_cache VALUES (?, ?, ?, ?, ?)",
            ((key, 1, 1, 10, 10) for key in (active[0], "stale")),
        )
        finish = store.finish_tacacs_policy_cycle
    else:
        store.db.executemany(
            "INSERT INTO network_device_group_cache VALUES (?, ?, ?, ?)",
            ((key, "{}", 10, 10) for key in (active[0], "stale")),
        )
        finish = store.finish_network_device_cycle
    store.db.execute(
        f"UPDATE {table} SET last_seen=999999 WHERE {key_column}='stale'")
    store.commit()

    finish(active, now=20)

    assert [tuple(row) for row in store.db.execute(
        f"SELECT {key_column}, last_seen FROM {table}").fetchall()] == [
            (active[0], 20),
        ]
    store.close()
