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

STATE_SCHEMA_VERSION = 3
MAX_PERSISTED_SNAPSHOT_BYTES = 32 * 1024 * 1024
MAX_POSTURE_CACHE_DETAIL_BYTES = 128 * 1024
MAX_TACACS_CACHE_DETAIL_BYTES = 64 * 1024
MAX_TACACS_POLICY_RULES = 1_000_000
MAX_DEVICE_GROUP_DETAIL_BYTES = 16 * 1024


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
        self.db.execute("""
            CREATE TABLE IF NOT EXISTS tacacs_policy_rule_cache (
                policy_id TEXT PRIMARY KEY,
                authentication_rules INTEGER NOT NULL,
                authorization_rules INTEGER NOT NULL,
                updated_at REAL NOT NULL,
                last_seen REAL NOT NULL
            )
        """)
        self.db.execute("""
            CREATE TABLE IF NOT EXISTS network_device_group_cache (
                device_id TEXT PRIMARY KEY,
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
        if schema_version < STATE_SCHEMA_VERSION:
            self.db.execute(f"PRAGMA user_version = {STATE_SCHEMA_VERSION}")
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
                    f"""
                    SELECT mac, session_signature,
                           CASE WHEN typeof(detail_json) = 'text'
                                     AND length(CAST(detail_json AS BLOB)) <= ?
                                THEN detail_json END AS detail_json,
                           updated_at
                    FROM mnt_posture_cache
                    WHERE mac IN ({placeholders})
                    """, (MAX_POSTURE_CACHE_DETAIL_BYTES, *chunk)):
                try:
                    detail = json.loads(row["detail_json"])
                    updated_at = float(row["updated_at"])
                    if (not isinstance(detail, dict) or not math.isfinite(updated_at)
                            or updated_at < 0):
                        raise ValueError("invalid posture cache row")
                except (RecursionError, TypeError, ValueError):
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
        now = self._valid_timestamp(now)
        encoded = json.dumps(
            detail, separators=(",", ":"), ensure_ascii=False, allow_nan=False)
        if len(encoded.encode("utf-8")) > MAX_POSTURE_CACHE_DETAIL_BYTES:
            raise ValueError("posture cache detail exceeds the persisted size limit")
        self.db.execute("""
            INSERT INTO mnt_posture_cache
                (mac, session_signature, detail_json, updated_at, last_seen)
            VALUES (?, ?, ?, ?, ?)
            ON CONFLICT(mac) DO UPDATE SET
                session_signature=excluded.session_signature,
                detail_json=excluded.detail_json,
                updated_at=excluded.updated_at,
                last_seen=excluded.last_seen
        """, (mac, signature, encoded, now, now))

    def finish_posture_cycle(self, active_macs, now=None):
        now = self._valid_timestamp(now)
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
                    f"""
                    SELECT user_id,
                           CASE WHEN typeof(detail_json) = 'text'
                                     AND length(CAST(detail_json AS BLOB)) <= ?
                                THEN detail_json END AS detail_json,
                           updated_at
                    FROM tacacs_internal_user_cache
                    WHERE user_id IN ({placeholders})
                    """, (MAX_TACACS_CACHE_DETAIL_BYTES, *chunk)):
                try:
                    detail = json.loads(row["detail_json"])
                    updated_at = float(row["updated_at"])
                    if (not isinstance(detail, dict) or not math.isfinite(updated_at)
                            or updated_at < 0):
                        raise ValueError("invalid TACACS cache row")
                except (RecursionError, TypeError, ValueError):
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
            ("tacacs_policy_rule_cache", "policy_id"),
            ("network_device_group_cache", "device_id"),
        }
        if (table, key_column) not in allowed:
            raise ValueError("invalid cache table")
        self.db.executemany(
            f"DELETE FROM {table} WHERE {key_column}=?", ((key,) for key in keys))
        self.commit()

    def put_tacacs_user(self, user_id, detail, now=None):
        now = self._valid_timestamp(now)
        encoded = json.dumps(
            detail, separators=(",", ":"), ensure_ascii=False, allow_nan=False)
        if len(encoded.encode("utf-8")) > MAX_TACACS_CACHE_DETAIL_BYTES:
            raise ValueError("TACACS cache detail exceeds the persisted size limit")
        self.db.execute("""
            INSERT INTO tacacs_internal_user_cache
                (user_id, detail_json, updated_at, last_seen)
            VALUES (?, ?, ?, ?)
            ON CONFLICT(user_id) DO UPDATE SET
                detail_json=excluded.detail_json,
                updated_at=excluded.updated_at,
                last_seen=excluded.last_seen
        """, (str(user_id), encoded, now, now))

    def finish_tacacs_user_cycle(self, active_ids, now=None):
        """Mark active cache rows and prune accounts removed from ISE."""
        now = self._valid_timestamp(now)
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

    def tacacs_policy_entries(self, policy_ids):
        """Return complete cached rule counts for a bounded policy inventory."""
        policy_ids = tuple(dict.fromkeys(str(value) for value in policy_ids if value))
        if not policy_ids:
            return {}
        rows = {}
        invalid = []
        for offset in range(0, len(policy_ids), 500):
            chunk = policy_ids[offset:offset + 500]
            placeholders = ",".join("?" for _ in chunk)
            for row in self.db.execute(f"""
                    SELECT policy_id, authentication_rules, authorization_rules,
                           updated_at
                    FROM tacacs_policy_rule_cache
                    WHERE policy_id IN ({placeholders})
                    """, chunk):
                try:
                    authentication = int(row["authentication_rules"])
                    authorization = int(row["authorization_rules"])
                    updated_at = float(row["updated_at"])
                    if (not 0 <= authentication <= MAX_TACACS_POLICY_RULES
                            or not 0 <= authorization <= MAX_TACACS_POLICY_RULES
                            or not math.isfinite(updated_at) or updated_at < 0):
                        raise ValueError("invalid TACACS policy cache row")
                except (TypeError, ValueError):
                    invalid.append(row["policy_id"])
                    continue
                rows[row["policy_id"]] = {
                    "authentication_rules": authentication,
                    "authorization_rules": authorization,
                    "updated_at": updated_at,
                }
        self._delete_invalid("tacacs_policy_rule_cache", "policy_id", invalid)
        return rows

    def put_tacacs_policy(self, policy_id, authentication, authorization, now=None):
        now = self._valid_timestamp(now)
        policy_id = str(policy_id)
        if not policy_id or len(policy_id.encode("utf-8")) > 256:
            raise ValueError("TACACS policy ID exceeds the persisted size limit")
        authentication = int(authentication)
        authorization = int(authorization)
        if (not 0 <= authentication <= MAX_TACACS_POLICY_RULES
                or not 0 <= authorization <= MAX_TACACS_POLICY_RULES):
            raise ValueError("TACACS policy rule count exceeds the persisted limit")
        self.db.execute("""
            INSERT INTO tacacs_policy_rule_cache
                (policy_id, authentication_rules, authorization_rules,
                 updated_at, last_seen)
            VALUES (?, ?, ?, ?, ?)
            ON CONFLICT(policy_id) DO UPDATE SET
                authentication_rules=excluded.authentication_rules,
                authorization_rules=excluded.authorization_rules,
                updated_at=excluded.updated_at,
                last_seen=excluded.last_seen
        """, (policy_id, authentication, authorization, now, now))

    def finish_tacacs_policy_cycle(self, active_ids, now=None):
        """Mark selected policy rows and prune policies removed from inventory."""
        now = self._valid_timestamp(now)
        active_ids = tuple(dict.fromkeys(str(value) for value in active_ids if value))
        if active_ids:
            for offset in range(0, len(active_ids), 500):
                chunk = active_ids[offset:offset + 500]
                placeholders = ",".join("?" for _ in chunk)
                self.db.execute(
                    f"UPDATE tacacs_policy_rule_cache SET last_seen=? "
                    f"WHERE policy_id IN ({placeholders})", (now, *chunk))
            if len(active_ids) <= 500:
                placeholders = ",".join("?" for _ in active_ids)
                self.db.execute(
                    f"DELETE FROM tacacs_policy_rule_cache "
                    f"WHERE policy_id NOT IN ({placeholders})", active_ids)
            else:
                self.db.execute(
                    "DELETE FROM tacacs_policy_rule_cache WHERE last_seen < ?", (now,))
        else:
            self.db.execute("DELETE FROM tacacs_policy_rule_cache")
        self.commit()

    def tacacs_policy_count(self):
        return int(self.db.execute(
            "SELECT COUNT(*) FROM tacacs_policy_rule_cache").fetchone()[0])

    def network_device_entries(self, device_ids):
        """Return bounded cached group-only detail for the current NAD inventory."""
        device_ids = tuple(dict.fromkeys(str(value) for value in device_ids if value))
        if not device_ids:
            return {}
        rows = {}
        invalid = []
        for offset in range(0, len(device_ids), 500):
            chunk = device_ids[offset:offset + 500]
            placeholders = ",".join("?" for _ in chunk)
            for row in self.db.execute(f"""
                    SELECT device_id,
                           CASE WHEN typeof(detail_json) = 'text'
                                     AND length(CAST(detail_json AS BLOB)) <= ?
                                THEN detail_json END AS detail_json,
                           updated_at
                    FROM network_device_group_cache
                    WHERE device_id IN ({placeholders})
                    """, (MAX_DEVICE_GROUP_DETAIL_BYTES, *chunk)):
                try:
                    detail = json.loads(row["detail_json"])
                    updated_at = float(row["updated_at"])
                    groups = detail.get("NetworkDeviceGroupList") \
                        if isinstance(detail, dict) else None
                    if (not isinstance(groups, list) or len(groups) > 3
                            or any(not isinstance(group, str) for group in groups)
                            or not math.isfinite(updated_at)
                            or updated_at < 0):
                        raise ValueError("invalid network device cache row")
                except (RecursionError, TypeError, ValueError):
                    invalid.append(row["device_id"])
                    continue
                rows[row["device_id"]] = {
                    "detail": detail,
                    "updated_at": updated_at,
                }
        self._delete_invalid("network_device_group_cache", "device_id", invalid)
        return rows

    def put_network_device(self, device_id, detail, now=None):
        """Persist sanitized NAD group detail; callers must not pass credentials."""
        now = self._valid_timestamp(now)
        device_id = str(device_id)
        if not device_id or len(device_id.encode("utf-8")) > 256:
            raise ValueError("network device ID exceeds the persisted size limit")
        encoded = json.dumps(
            detail, separators=(",", ":"), ensure_ascii=False, allow_nan=False)
        if len(encoded.encode("utf-8")) > MAX_DEVICE_GROUP_DETAIL_BYTES:
            raise ValueError("network device cache detail exceeds the persisted size limit")
        self.db.execute("""
            INSERT INTO network_device_group_cache
                (device_id, detail_json, updated_at, last_seen)
            VALUES (?, ?, ?, ?)
            ON CONFLICT(device_id) DO UPDATE SET
                detail_json=excluded.detail_json,
                updated_at=excluded.updated_at,
                last_seen=excluded.last_seen
        """, (device_id, encoded, now, now))

    def finish_network_device_cycle(self, active_ids, now=None):
        """Mark active NAD rows and prune devices removed from ISE."""
        now = self._valid_timestamp(now)
        active_ids = tuple(dict.fromkeys(str(value) for value in active_ids if value))
        if active_ids:
            for offset in range(0, len(active_ids), 500):
                chunk = active_ids[offset:offset + 500]
                placeholders = ",".join("?" for _ in chunk)
                self.db.execute(
                    f"UPDATE network_device_group_cache SET last_seen=? "
                    f"WHERE device_id IN ({placeholders})", (now, *chunk))
            if len(active_ids) <= 500:
                placeholders = ",".join("?" for _ in active_ids)
                self.db.execute(
                    f"DELETE FROM network_device_group_cache "
                    f"WHERE device_id NOT IN ({placeholders})", active_ids)
            else:
                self.db.execute(
                    "DELETE FROM network_device_group_cache WHERE last_seen < ?", (now,))
        else:
            self.db.execute("DELETE FROM network_device_group_cache")
        self.commit()

    def network_device_count(self):
        return int(self.db.execute(
            "SELECT COUNT(*) FROM network_device_group_cache").fetchone()[0])

    @staticmethod
    def _valid_timestamp(value):
        value = time.time() if value is None else float(value)
        if not math.isfinite(value) or value < 0:
            raise ValueError("cache timestamp must be finite and non-negative")
        return value

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
        key = f"dataset_snapshot.{dataset}"
        row = self.db.execute("""
            SELECT CASE WHEN typeof(value) = 'text'
                              AND length(CAST(value AS BLOB)) <= ?
                        THEN value END AS value
            FROM exporter_state WHERE key=?
        """, (MAX_PERSISTED_SNAPSHOT_BYTES, key)).fetchone()
        if row is None:
            return None
        raw = row["value"]
        if not raw:
            self._delete_state_key(key)
            return None
        try:
            value = json.loads(raw)
        except (RecursionError, TypeError, ValueError):
            self._delete_state_key(key)
            return None
        if not isinstance(value, dict):
            self._delete_state_key(key)
            return None
        try:
            updated_at = float(value["updated_at"])
        except (KeyError, TypeError, ValueError):
            self._delete_state_key(key)
            return None
        payload = value.get("payload")
        if (not math.isfinite(updated_at) or updated_at < 0
                or not isinstance(payload, dict)):
            self._delete_state_key(key)
            return None
        return updated_at, payload

    def replace_dataset_snapshot(self, dataset, updated_at, payload):
        updated_at = self._valid_timestamp(updated_at)
        value = json.dumps({
            "updated_at": updated_at, "payload": payload,
        }, separators=(",", ":"), allow_nan=False)
        if (len(value) > MAX_PERSISTED_SNAPSHOT_BYTES
                or len(value.encode("utf-8")) > MAX_PERSISTED_SNAPSHOT_BYTES):
            raise ValueError("dataset snapshot exceeds the persisted size limit")
        self.set_value(f"dataset_snapshot.{dataset}", value)

    def _delete_state_key(self, key):
        self.db.execute("DELETE FROM exporter_state WHERE key=?", (key,))
        self.commit()
