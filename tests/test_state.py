import sqlite3
import stat
from concurrent.futures import ThreadPoolExecutor

import pytest

import ise_exporter.state as state_module
from ise_exporter.state import (
    STATE_SCHEMA_VERSION,
    StateStore,
    acquire_runtime_lock,
    release_runtime_lock,
    reset_exporter_state,
)


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


def test_explicit_state_reset_removes_sqlite_guards_and_pacing(tmp_path):
    path = tmp_path / "state.sqlite3"
    path.write_bytes(b"state")
    path.with_name(f"{path.name}-wal").write_bytes(b"wal")
    path.with_name(f"{path.name}-shm").write_bytes(b"shm")
    pacing = tmp_path / "dataconnect.pacing"
    pacing.write_text("deadline")
    rest_guard = tmp_path / "rest-auth.guard"
    rest_guard.write_text("backoff")
    dc_guard = tmp_path / "dataconnect-auth.guard"
    dc_guard.write_text("backoff")

    removed = reset_exporter_state(path, (rest_guard, dc_guard, pacing))

    assert set(removed) == {
        str(path), f"{path}-wal", f"{path}-shm",
        str(rest_guard), str(dc_guard), str(pacing),
    }
    assert all(not candidate.exists() for candidate in (
        path, rest_guard, dc_guard, pacing))


def test_explicit_state_reset_rejects_symlink_target(tmp_path):
    target = tmp_path / "real.sqlite3"
    target.write_bytes(b"preserve")
    link = tmp_path / "state.sqlite3"
    link.symlink_to(target)

    with pytest.raises(OSError, match="not a regular file"):
        reset_exporter_state(link)

    assert target.read_bytes() == b"preserve"


def test_reset_preflights_all_targets_before_deleting_anything(tmp_path):
    path = tmp_path / "state.sqlite3"
    path.write_bytes(b"preserve state")
    target = tmp_path / "real.guard"
    target.write_bytes(b"preserve guard")
    bad_guard = tmp_path / "auth.guard"
    bad_guard.symlink_to(target)

    with pytest.raises(OSError, match="not a regular file"):
        reset_exporter_state(path, (bad_guard,))

    assert path.read_bytes() == b"preserve state"
    assert target.read_bytes() == b"preserve guard"


def test_reset_normalizes_relative_and_home_paths(tmp_path, monkeypatch):
    state = tmp_path / "state.sqlite3"
    state.write_bytes(b"state")
    guard = tmp_path / "guard"
    guard.write_bytes(b"guard")
    monkeypatch.chdir(tmp_path)
    monkeypatch.setenv("HOME", str(tmp_path))

    removed = reset_exporter_state("state.sqlite3", ("~/guard",))

    assert set(removed) == {str(state), str(guard)}


def test_reset_cannot_delete_its_runtime_lock(tmp_path):
    state = tmp_path / "state.sqlite3"
    runtime_lock = tmp_path / "state.sqlite3.runtime.lock"

    with pytest.raises(ValueError, match="runtime lock"):
        reset_exporter_state(state, (runtime_lock,))


def test_reset_refuses_while_exporter_runtime_owns_state(tmp_path):
    path = tmp_path / "state.sqlite3"
    descriptor = acquire_runtime_lock(path)
    try:
        with pytest.raises(RuntimeError, match="in use"):
            reset_exporter_state(path)
    finally:
        release_runtime_lock(descriptor)


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


def test_incompatible_existing_table_schema_is_rejected_without_rewrite(tmp_path):
    path = tmp_path / "state.sqlite3"
    db = sqlite3.connect(path)
    db.execute("CREATE TABLE exporter_state (key TEXT PRIMARY KEY, payload BLOB)")
    db.execute(f"PRAGMA user_version = {STATE_SCHEMA_VERSION}")
    db.commit()
    db.close()

    with pytest.raises(RuntimeError, match="exporter_state.*incompatible schema"):
        StateStore(path)

    db = sqlite3.connect(path)
    assert [row[1] for row in db.execute("PRAGMA table_info(exporter_state)")] == [
        "key", "payload"]
    assert db.execute("PRAGMA user_version").fetchone()[0] == STATE_SCHEMA_VERSION
    db.close()


def test_state_database_symlink_is_rejected(tmp_path):
    target = tmp_path / "real.sqlite3"
    target.touch()
    link = tmp_path / "state.sqlite3"
    link.symlink_to(target)

    with pytest.raises(OSError):
        StateStore(link)


def test_physically_corrupt_cache_is_quarantined_and_rebuilt(tmp_path, caplog):
    path = tmp_path / "state.sqlite3"
    corrupt = b"not a sqlite database"
    path.write_bytes(corrupt)
    caplog.set_level("WARNING", logger="ise_exporter.state")

    store = StateStore(path)

    assert store.get_value("missing") is None
    assert store.db.execute("PRAGMA user_version").fetchone()[0] == STATE_SCHEMA_VERSION
    store.close()
    quarantined = list(tmp_path.glob("state.sqlite3.corrupt.*"))
    assert len(quarantined) == 1
    assert quarantined[0].read_bytes() == corrupt
    assert stat.S_IMODE(quarantined[0].stat().st_mode) == 0o600
    assert "quarantined corrupt restart-persistent state" in caplog.text


def test_noncorruption_sqlite_error_is_not_quarantined(tmp_path, monkeypatch):
    path = tmp_path / "state.sqlite3"
    path.touch()

    def fail(*args, **kwargs):
        raise sqlite3.OperationalError("database is locked")

    monkeypatch.setattr(state_module.sqlite3, "connect", fail)

    with pytest.raises(sqlite3.OperationalError, match="locked"):
        StateStore(path)

    assert path.exists()
    assert not list(tmp_path.glob("state.sqlite3.corrupt.*"))


def test_concurrent_corruption_recovery_quarantines_only_once(tmp_path):
    path = tmp_path / "state.sqlite3"
    path.write_bytes(b"not a sqlite database")

    def open_and_close(_index):
        store = StateStore(path)
        store.close()

    with ThreadPoolExecutor(max_workers=4) as executor:
        list(executor.map(open_and_close, range(4)))

    assert len(list(tmp_path.glob("state.sqlite3.corrupt.*"))) == 1
    store = StateStore(path)
    assert store.db.execute("PRAGMA user_version").fetchone()[0] == STATE_SCHEMA_VERSION
    store.close()


def test_state_open_retries_only_transient_sqlite_lock_errors(monkeypatch):
    attempts = []

    def initially_locked(self):
        attempts.append(True)
        if len(attempts) < 3:
            raise sqlite3.OperationalError("database is locked")
        self.db = sqlite3.connect(":memory:")

    monkeypatch.setattr(StateStore, "_open_and_initialize", initially_locked)
    monkeypatch.setattr(state_module.time, "sleep", lambda _seconds: None)

    store = StateStore(":memory:")
    store.close()

    assert len(attempts) == 3


def test_state_open_does_not_retry_non_lock_operational_error(monkeypatch):
    attempts = []

    def unavailable(_self):
        attempts.append(True)
        raise sqlite3.OperationalError("unable to open database file")

    monkeypatch.setattr(StateStore, "_open_and_initialize", unavailable)

    with pytest.raises(sqlite3.OperationalError, match="unable to open"):
        StateStore(":memory:")

    assert len(attempts) == 1


def test_corruption_recovery_retains_only_two_newest_generations(tmp_path):
    path = tmp_path / "state.sqlite3"

    for index in range(3):
        path.write_bytes(f"not a sqlite database {index}".encode())
        store = StateStore(path)
        store.close()

    quarantined = sorted(tmp_path.glob("state.sqlite3.corrupt.*"))
    assert len(quarantined) == 2
    assert {candidate.read_bytes() for candidate in quarantined} == {
        b"not a sqlite database 1",
        b"not a sqlite database 2",
    }


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


def test_generic_state_has_absolute_key_and_value_ceilings(tmp_path, monkeypatch):
    store = StateStore(tmp_path / "state.sqlite3")
    monkeypatch.setattr(state_module, "MAX_STATE_VALUE_BYTES", 32)

    with pytest.raises(ValueError, match="state key"):
        store.set_value("k" * 257, "value")
    with pytest.raises(ValueError, match="state value"):
        store.set_value("bounded", "x" * 33)

    assert store.db.execute("SELECT COUNT(*) FROM exporter_state").fetchone()[0] == 0
    store.close()


def test_oversized_generic_state_is_not_materialized_and_is_pruned(
        tmp_path, monkeypatch):
    store = StateStore(tmp_path / "state.sqlite3")
    store.db.execute(
        "INSERT INTO exporter_state(key, value) VALUES (?, ?)",
        ("corrupt", "x" * 100),
    )
    store.commit()
    monkeypatch.setattr(state_module, "MAX_STATE_VALUE_BYTES", 32)

    assert store.get_value("corrupt", "fallback") == "fallback"
    assert store.db.execute("SELECT COUNT(*) FROM exporter_state").fetchone()[0] == 0
    store.close()


@pytest.mark.parametrize("operation", (
    "put_posture", "put_tacacs_user", "put_tacacs_policy", "put_network_device",
))
def test_cache_writes_reject_oversized_identity_keys(tmp_path, operation):
    store = StateStore(tmp_path / "state.sqlite3")
    key = "k" * 257

    with pytest.raises(ValueError, match="state key"):
        if operation == "put_posture":
            store.put_posture(key, "signature", {}, now=10)
        elif operation == "put_tacacs_user":
            store.put_tacacs_user(key, {}, now=10)
        elif operation == "put_tacacs_policy":
            store.put_tacacs_policy(key, 1, 1, now=10)
        else:
            store.put_network_device(
                key, {"NetworkDeviceGroupList": []}, now=10)

    assert store.posture_count() == 0
    assert store.tacacs_user_count() == 0
    assert store.tacacs_policy_count() == 0
    assert store.network_device_count() == 0
    store.close()


def test_posture_cache_rejects_oversized_session_signature(tmp_path):
    store = StateStore(tmp_path / "state.sqlite3")

    with pytest.raises(ValueError, match="state key"):
        store.put_posture("AA:BB:CC:DD:EE:FF", "s" * 257, {}, now=10)

    assert store.posture_count() == 0
    store.close()


def test_cache_cycle_row_ceiling_fails_before_pruning(tmp_path, monkeypatch):
    store = StateStore(tmp_path / "state.sqlite3")
    store.put_tacacs_user("existing", {"name": "existing"}, now=10)
    store.commit()
    monkeypatch.setattr(state_module, "MAX_CACHE_CYCLE_KEYS", 2)

    with pytest.raises(ValueError, match="row limit"):
        store.finish_tacacs_user_cycle(("one", "two", "three"), now=20)

    assert store.tacacs_user_count() == 1
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
