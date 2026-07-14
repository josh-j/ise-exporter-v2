import sqlite3

from ise_exporter.state import StateStore


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
