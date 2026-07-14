"""Small durable SQLite state store for load-reducing collector caches.

The database is exporter-private and may contain endpoint/session material copied
from MnT responses.  Callers must place it in a service-owned, non-world-readable
state directory.  SQLite is part of the Python standard library, which keeps the
Ubuntu Noble installation free of additional database dependencies.
"""
from __future__ import annotations

import json
import os
from pathlib import Path
import sqlite3
import time


class StateStore:
    def __init__(self, path):
        self.path = str(path or ":memory:")
        if self.path != ":memory:":
            target = Path(self.path)
            target.parent.mkdir(parents=True, exist_ok=True, mode=0o750)
        self.db = sqlite3.connect(self.path, timeout=5)
        self.db.row_factory = sqlite3.Row
        self.db.execute("PRAGMA busy_timeout = 5000")
        self.db.execute("PRAGMA journal_mode = WAL")
        self.db.execute("PRAGMA synchronous = NORMAL")
        self.db.execute("""
            CREATE TABLE IF NOT EXISTS mnt_posture_cache (
                mac TEXT PRIMARY KEY,
                session_signature TEXT NOT NULL,
                detail_json TEXT NOT NULL,
                updated_at REAL NOT NULL,
                last_seen REAL NOT NULL
            )
        """)
        self.db.execute("""
            CREATE TABLE IF NOT EXISTS exporter_state (
                key TEXT PRIMARY KEY,
                value TEXT NOT NULL
            )
        """)
        # Versions before the reporting/active split cached RADIUS aggregate
        # windows here. They are neither needed nor read anymore; remove the
        # obsolete history during upgrade instead of retaining an abandoned
        # local copy of MnT-derived data indefinitely.
        self.db.execute("DROP TABLE IF EXISTS dataconnect_rollup")
        self.db.commit()
        if self.path != ":memory:":
            os.chmod(self.path, 0o600)

    def close(self):
        self.db.close()

    def posture_entries(self, macs):
        macs = tuple(dict.fromkeys(macs))
        if not macs:
            return {}
        rows = {}
        # Stay below SQLite's normal bind-variable limit for the production cap.
        for offset in range(0, len(macs), 500):
            chunk = macs[offset:offset + 500]
            placeholders = ",".join("?" for _ in chunk)
            for row in self.db.execute(
                    f"SELECT * FROM mnt_posture_cache WHERE mac IN ({placeholders})", chunk):
                try:
                    detail = json.loads(row["detail_json"])
                except (TypeError, ValueError):
                    continue
                if isinstance(detail, dict):
                    rows[row["mac"]] = {
                        "signature": row["session_signature"],
                        "detail": detail,
                        "updated_at": float(row["updated_at"]),
                    }
        return rows

    def put_posture(self, mac, signature, detail, now=None):
        now = time.time() if now is None else float(now)
        self.db.execute("""
            INSERT INTO mnt_posture_cache
                (mac, session_signature, detail_json, updated_at, last_seen)
            VALUES (?, ?, ?, ?, ?)
            ON CONFLICT(mac) DO UPDATE SET
                session_signature=excluded.session_signature,
                detail_json=excluded.detail_json,
                updated_at=excluded.updated_at,
                last_seen=excluded.last_seen
        """, (mac, signature, json.dumps(detail, separators=(",", ":")), now, now))

    def finish_posture_cycle(self, active_macs, now=None):
        now = time.time() if now is None else float(now)
        active_macs = tuple(dict.fromkeys(active_macs))
        if active_macs:
            for offset in range(0, len(active_macs), 500):
                chunk = active_macs[offset:offset + 500]
                placeholders = ",".join("?" for _ in chunk)
                self.db.execute(
                    f"UPDATE mnt_posture_cache SET last_seen=? WHERE mac IN ({placeholders})",
                    (now, *chunk))
            placeholders = ",".join("?" for _ in active_macs)
            if len(active_macs) <= 500:
                self.db.execute(
                    f"DELETE FROM mnt_posture_cache WHERE mac NOT IN ({placeholders})",
                    active_macs)
            else:
                # All active rows were just marked.  A strict older-than cutoff
                # avoids a single statement with more than SQLite's bind limit.
                self.db.execute("DELETE FROM mnt_posture_cache WHERE last_seen < ?", (now,))
        else:
            self.db.execute("DELETE FROM mnt_posture_cache")
        self.db.commit()

    def posture_count(self):
        return int(self.db.execute(
            "SELECT COUNT(*) FROM mnt_posture_cache").fetchone()[0])

    def get_value(self, key, default=None):
        row = self.db.execute(
            "SELECT value FROM exporter_state WHERE key=?", (key,)).fetchone()
        return row[0] if row else default

    def set_value(self, key, value, *, commit=True):
        self.db.execute("""
            INSERT INTO exporter_state(key, value) VALUES (?, ?)
            ON CONFLICT(key) DO UPDATE SET value=excluded.value
        """, (key, str(value)))
        if commit:
            self.db.commit()

    def dataset_snapshot(self, dataset):
        raw = self.get_value(f"dataset_snapshot.{dataset}")
        if not raw:
            return None
        try:
            value = json.loads(raw)
        except (TypeError, ValueError):
            return None
        if not isinstance(value, dict):
            return None
        try:
            updated_at = float(value["updated_at"])
        except (KeyError, TypeError, ValueError):
            return None
        payload = value.get("payload")
        return (updated_at, payload) if isinstance(payload, dict) else None

    def replace_dataset_snapshot(self, dataset, updated_at, payload):
        value = json.dumps({
            "updated_at": float(updated_at), "payload": payload,
        }, separators=(",", ":"), allow_nan=False)
        self.set_value(f"dataset_snapshot.{dataset}", value)
