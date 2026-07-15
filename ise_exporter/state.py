"""Small durable SQLite state store for load-reducing collector caches.

The database is exporter-private and may contain bounded endpoint/session or
internal-account material copied from ISE responses. Callers must place it in a
service-owned, non-world-readable state directory. SQLite is part of the Python
standard library, which keeps Ubuntu Noble free of extra database dependencies.
"""
from __future__ import annotations

import json
import math
import os
from pathlib import Path
import sqlite3
import stat
import time

STATE_SCHEMA_VERSION = 1
MAX_PERSISTED_SNAPSHOT_BYTES = 32 * 1024 * 1024


class StateStore:
    def __init__(self, path):
        self.path = str(path or ":memory:")
        self._file_path = None
        if self.path != ":memory:":
            target = Path(self.path)
            self._file_path = target
            target.parent.mkdir(parents=True, exist_ok=True, mode=0o750)
            flags = os.O_RDWR | os.O_CREAT | getattr(os, "O_CLOEXEC", 0)
            flags |= getattr(os, "O_NOFOLLOW", 0)
            descriptor = os.open(target, flags, 0o600)
            try:
                metadata = os.fstat(descriptor)
                if not stat.S_ISREG(metadata.st_mode):
                    raise OSError(f"state database is not a regular file: {target}")
                os.fchmod(descriptor, 0o600)
            finally:
                os.close(descriptor)
        self.db = sqlite3.connect(self.path, timeout=5)
        self.db.row_factory = sqlite3.Row
        self.db.execute("PRAGMA busy_timeout = 5000")
        self.db.execute("PRAGMA journal_mode = WAL")
        self._secure_files()
        self.db.execute("PRAGMA synchronous = NORMAL")
        schema_version = int(self.db.execute("PRAGMA user_version").fetchone()[0])
        if schema_version > STATE_SCHEMA_VERSION:
            self.db.close()
            raise RuntimeError(
                f"state database schema {schema_version} is newer than supported "
                f"version {STATE_SCHEMA_VERSION}")
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
        self.db.execute("""
            CREATE TABLE IF NOT EXISTS tacacs_internal_user_cache (
                user_id TEXT PRIMARY KEY,
                detail_json TEXT NOT NULL,
                updated_at REAL NOT NULL,
                last_seen REAL NOT NULL
            )
        """)
        if schema_version < 1:
            # Versions before the reporting/active split cached RADIUS aggregate
            # windows here. Run this schema-write migration once, rather than on
            # every short-lived StateStore connection across collector threads.
            self.db.execute("DROP TABLE IF EXISTS dataconnect_rollup")
            self.db.execute("PRAGMA user_version = 1")
        self.commit()

    def _secure_files(self):
        """Keep SQLite's database, WAL, and shared-memory files private."""
        if self._file_path is None:
            return
        for suffix in ("", "-wal", "-shm"):
            try:
                os.chmod(f"{self._file_path}{suffix}", 0o600)
            except FileNotFoundError:
                pass

    def commit(self):
        self.db.commit()
        self._secure_files()

    def close(self):
        self._secure_files()
        self.db.close()

    def posture_entries(self, macs):
        macs = tuple(dict.fromkeys(macs))
        if not macs:
            return {}
        rows = {}
        invalid = []
        # Stay below SQLite's normal bind-variable limit for the production cap.
        for offset in range(0, len(macs), 500):
            chunk = macs[offset:offset + 500]
            placeholders = ",".join("?" for _ in chunk)
            for row in self.db.execute(
                    f"SELECT * FROM mnt_posture_cache WHERE mac IN ({placeholders})", chunk):
                try:
                    detail = json.loads(row["detail_json"])
                    updated_at = float(row["updated_at"])
                    if (not isinstance(detail, dict) or not math.isfinite(updated_at)
                            or updated_at < 0):
                        raise ValueError("invalid posture cache row")
                except (TypeError, ValueError):
                    invalid.append(row["mac"])
                    continue
                rows[row["mac"]] = {
                    "signature": row["session_signature"],
                    "detail": detail,
                    "updated_at": updated_at,
                }
        self._delete_invalid("mnt_posture_cache", "mac", invalid)
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
        self.commit()

    def posture_count(self):
        return int(self.db.execute(
            "SELECT COUNT(*) FROM mnt_posture_cache").fetchone()[0])

    def tacacs_user_entries(self, user_ids):
        """Return cached internal-user details for the bounded active inventory."""
        user_ids = tuple(dict.fromkeys(str(value) for value in user_ids if value))
        if not user_ids:
            return {}
        rows = {}
        invalid = []
        for offset in range(0, len(user_ids), 500):
            chunk = user_ids[offset:offset + 500]
            placeholders = ",".join("?" for _ in chunk)
            for row in self.db.execute(
                    f"SELECT * FROM tacacs_internal_user_cache "
                    f"WHERE user_id IN ({placeholders})", chunk):
                try:
                    detail = json.loads(row["detail_json"])
                    updated_at = float(row["updated_at"])
                    if (not isinstance(detail, dict) or not math.isfinite(updated_at)
                            or updated_at < 0):
                        raise ValueError("invalid TACACS cache row")
                except (TypeError, ValueError):
                    invalid.append(row["user_id"])
                    continue
                rows[row["user_id"]] = {
                    "detail": detail,
                    "updated_at": updated_at,
                }
        self._delete_invalid("tacacs_internal_user_cache", "user_id", invalid)
        return rows

    def _delete_invalid(self, table, key_column, keys):
        """Prune unusable cache rows from a fixed internal table contract."""
        if not keys:
            return
        allowed = {
            ("mnt_posture_cache", "mac"),
            ("tacacs_internal_user_cache", "user_id"),
        }
        if (table, key_column) not in allowed:
            raise ValueError("invalid cache table")
        self.db.executemany(
            f"DELETE FROM {table} WHERE {key_column}=?", ((key,) for key in keys))
        self.commit()

    def put_tacacs_user(self, user_id, detail, now=None):
        now = time.time() if now is None else float(now)
        self.db.execute("""
            INSERT INTO tacacs_internal_user_cache
                (user_id, detail_json, updated_at, last_seen)
            VALUES (?, ?, ?, ?)
            ON CONFLICT(user_id) DO UPDATE SET
                detail_json=excluded.detail_json,
                updated_at=excluded.updated_at,
                last_seen=excluded.last_seen
        """, (str(user_id), json.dumps(detail, separators=(",", ":")), now, now))

    def finish_tacacs_user_cycle(self, active_ids, now=None):
        """Mark active cache rows and prune accounts removed from ISE."""
        now = time.time() if now is None else float(now)
        active_ids = tuple(dict.fromkeys(str(value) for value in active_ids if value))
        if active_ids:
            for offset in range(0, len(active_ids), 500):
                chunk = active_ids[offset:offset + 500]
                placeholders = ",".join("?" for _ in chunk)
                self.db.execute(
                    f"UPDATE tacacs_internal_user_cache SET last_seen=? "
                    f"WHERE user_id IN ({placeholders})", (now, *chunk))
            if len(active_ids) <= 500:
                placeholders = ",".join("?" for _ in active_ids)
                self.db.execute(
                    f"DELETE FROM tacacs_internal_user_cache "
                    f"WHERE user_id NOT IN ({placeholders})", active_ids)
            else:
                self.db.execute(
                    "DELETE FROM tacacs_internal_user_cache WHERE last_seen < ?", (now,))
        else:
            self.db.execute("DELETE FROM tacacs_internal_user_cache")
        self.commit()

    def tacacs_user_count(self):
        return int(self.db.execute(
            "SELECT COUNT(*) FROM tacacs_internal_user_cache").fetchone()[0])

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
            self.commit()

    def dataset_snapshot(self, dataset):
        raw = self.get_value(f"dataset_snapshot.{dataset}")
        if not raw:
            return None
        if (not isinstance(raw, str)
                or len(raw) > MAX_PERSISTED_SNAPSHOT_BYTES
                or len(raw.encode("utf-8")) > MAX_PERSISTED_SNAPSHOT_BYTES):
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
        if (len(value) > MAX_PERSISTED_SNAPSHOT_BYTES
                or len(value.encode("utf-8")) > MAX_PERSISTED_SNAPSHOT_BYTES):
            raise ValueError("dataset snapshot exceeds the persisted size limit")
        self.set_value(f"dataset_snapshot.{dataset}", value)
