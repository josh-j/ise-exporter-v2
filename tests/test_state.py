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
    assert {"mnt_posture_cache", "tacacs_internal_user_cache", "exporter_state"} <= tables

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
    store.commit()

    assert store.posture_entries(["AA:BB:CC:DD:EE:FF"]) == {}
    assert store.tacacs_user_entries(["u1"]) == {}
    assert store.posture_count() == 0
    assert store.tacacs_user_count() == 0
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


def test_oversized_persisted_dataset_snapshot_is_ignored(tmp_path, monkeypatch):
    store = StateStore(tmp_path / "state.sqlite3")
    store.replace_dataset_snapshot("radius", 10, {"value": "x" * 100})
    monkeypatch.setattr(state_module, "MAX_PERSISTED_SNAPSHOT_BYTES", 32)

    assert store.dataset_snapshot("radius") is None
    store.close()


def test_oversized_dataset_snapshot_is_not_written(tmp_path, monkeypatch):
    store = StateStore(tmp_path / "state.sqlite3")
    monkeypatch.setattr(state_module, "MAX_PERSISTED_SNAPSHOT_BYTES", 32)

    with pytest.raises(ValueError, match="size limit"):
        store.replace_dataset_snapshot("radius", 10, {"value": "x" * 100})

    assert store.get_value("dataset_snapshot.radius") is None
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
