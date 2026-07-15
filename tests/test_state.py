import sqlite3
import stat

import pytest

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
