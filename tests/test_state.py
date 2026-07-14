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
    assert {"mnt_posture_cache", "exporter_state"} <= tables
