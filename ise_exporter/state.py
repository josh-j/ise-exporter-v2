"""Small durable SQLite state store for load-reducing collector caches.

The database is exporter-private and may contain bounded endpoint/session or
internal-account material copied from ISE responses. Callers must place it in a
service-owned, non-world-readable state directory. SQLite is part of the Python
standard library, which keeps Ubuntu Noble free of extra database dependencies.
"""
from __future__ import annotations

from contextlib import contextmanager
import fcntl
import json
import logging
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
MAX_STATE_KEY_BYTES = 256
MAX_STATE_VALUE_BYTES = 32 * 1024 * 1024
MAX_CACHE_CYCLE_KEYS = 250_000
MAX_CORRUPT_STATE_GENERATIONS = 2
STATE_OPEN_LOCK_RETRIES = 5
STATE_OPEN_LOCK_RETRY_SECONDS = 0.01
_REQUIRED_SCHEMA = {
    "mnt_posture_cache": (
        ("mac", "TEXT", 1),
        ("session_signature", "TEXT", 0),
        ("detail_json", "TEXT", 0),
        ("updated_at", "REAL", 0),
        ("last_seen", "REAL", 0),
    ),
    "exporter_state": (
        ("key", "TEXT", 1),
        ("value", "TEXT", 0),
    ),
    "tacacs_internal_user_cache": (
        ("user_id", "TEXT", 1),
        ("detail_json", "TEXT", 0),
        ("updated_at", "REAL", 0),
        ("last_seen", "REAL", 0),
    ),
    "tacacs_policy_rule_cache": (
        ("policy_id", "TEXT", 1),
        ("authentication_rules", "INTEGER", 0),
        ("authorization_rules", "INTEGER", 0),
        ("updated_at", "REAL", 0),
        ("last_seen", "REAL", 0),
    ),
    "network_device_group_cache": (
        ("device_id", "TEXT", 1),
        ("detail_json", "TEXT", 0),
        ("updated_at", "REAL", 0),
        ("last_seen", "REAL", 0),
    ),
}
_RECOVERABLE_CORRUPTION_MESSAGES = (
    "file is not a database",
    "database disk image is malformed",
    "database schema is corrupt",
)
logger = logging.getLogger(__name__)


def acquire_runtime_lock(state_path):
    """Hold one exporter/reset owner for a state namespace."""
    target = Path(str(state_path or "/var/lib/ise-exporter/state.sqlite3"))
    target.parent.mkdir(parents=True, exist_ok=True, mode=0o750)
    lock_path = Path(f"{target}.runtime.lock")
    flags = os.O_RDWR | os.O_CREAT | getattr(os, "O_CLOEXEC", 0)
    flags |= getattr(os, "O_NOFOLLOW", 0)
    descriptor = os.open(lock_path, flags, 0o600)
    try:
        metadata = os.fstat(descriptor)
        if not stat.S_ISREG(metadata.st_mode):
            raise OSError(f"exporter runtime lock is not a regular file: {lock_path}")
        os.fchmod(descriptor, 0o600)
        try:
            fcntl.flock(descriptor, fcntl.LOCK_EX | fcntl.LOCK_NB)
        except BlockingIOError as error:
            raise RuntimeError(
                "exporter state is in use; stop the running exporter before reset") from error
        return descriptor
    except Exception:
        os.close(descriptor)
        raise


def release_runtime_lock(descriptor):
    if descriptor is None:
        return
    try:
        fcntl.flock(descriptor, fcntl.LOCK_UN)
    finally:
        os.close(descriptor)


def reset_exporter_state(state_path, guard_paths=()):
    """One-shot reset of cache, snapshots, auth guards, and DB pacing state."""
    state_path = str(state_path or "")
    if not state_path or state_path == ":memory:":
        candidates = [Path(str(path)) for path in guard_paths if path]
        runtime_state = "/tmp/ise-exporter-memory-state"
    else:
        target = Path(state_path)
        candidates = [Path(f"{target}{suffix}") for suffix in ("", "-wal", "-shm")]
        candidates.extend(Path(str(path)) for path in guard_paths if path)
        runtime_state = state_path
    descriptor = acquire_runtime_lock(runtime_state)
    removed = []
    try:
        for candidate in dict.fromkeys(candidates):
            try:
                candidate_metadata = candidate.lstat()
            except FileNotFoundError:
                continue
            if not stat.S_ISREG(candidate_metadata.st_mode):
                raise OSError(
                    f"state database reset target is not a regular file: {candidate}")
            candidate.unlink()
            removed.append(str(candidate))
    finally:
        release_runtime_lock(descriptor)
    return tuple(removed)


class StateStore:
    def __init__(self, path):
        self.path = str(path or ":memory:")
        self._file_path = None if self.path == ":memory:" else Path(self.path)
        self._prepare_state_file()
        try:
            self._open_with_lock_retry()
        except sqlite3.DatabaseError as error:
            self._close_quietly()
            if (self._file_path is None
                    or not self._recoverable_corruption(error)):
                raise
            with self._recovery_lock():
                # Another exporter process may have recovered the pathname while
                # this connection still referenced the old corrupt inode.
                try:
                    self._open_with_lock_retry()
                except sqlite3.DatabaseError as retry_error:
                    self._close_quietly()
                    if not self._recoverable_corruption(retry_error):
                        raise
                    self._quarantine_corrupt_files()
                    self._prepare_state_file()
                    self._open_with_lock_retry()
                self._prune_corrupt_files()

    def _open_with_lock_retry(self):
        """Tolerate a brief WAL/schema lock while another connection initializes."""
        for attempt in range(STATE_OPEN_LOCK_RETRIES):
            try:
                self._open_and_initialize()
                return
            except sqlite3.OperationalError as error:
                self._close_quietly()
                if ("locked" not in str(error).casefold()
                        or attempt == STATE_OPEN_LOCK_RETRIES - 1):
                    raise
                time.sleep(STATE_OPEN_LOCK_RETRY_SECONDS * (2 ** attempt))

    def _prepare_state_file(self):
        if self._file_path is None:
            return
        target = self._file_path
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

    def _open_and_initialize(self):
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
        try:
            self._validate_schema()
        except Exception:
            self.db.close()
            raise
        if schema_version < 1:
            # Versions before the reporting/active split cached RADIUS aggregate
            # windows here. Run this schema-write migration once, rather than on
            # every short-lived StateStore connection across collector threads.
            self.db.execute("DROP TABLE IF EXISTS dataconnect_rollup")
        if schema_version < STATE_SCHEMA_VERSION:
            self.db.execute(f"PRAGMA user_version = {STATE_SCHEMA_VERSION}")
        self.commit()

    def _close_quietly(self):
        db = getattr(self, "db", None)
        if db is not None:
            try:
                db.close()
            except Exception:
                pass

    @staticmethod
    def _recoverable_corruption(error):
        message = str(error).casefold()
        return any(marker in message for marker in _RECOVERABLE_CORRUPTION_MESSAGES)

    @contextmanager
    def _recovery_lock(self):
        lock_path = Path(f"{self._file_path}.recovery.lock")
        flags = os.O_RDWR | os.O_CREAT | getattr(os, "O_CLOEXEC", 0)
        flags |= getattr(os, "O_NOFOLLOW", 0)
        descriptor = os.open(lock_path, flags, 0o600)
        try:
            metadata = os.fstat(descriptor)
            if not stat.S_ISREG(metadata.st_mode):
                raise OSError(
                    f"state database recovery lock is not a regular file: {lock_path}")
            os.fchmod(descriptor, 0o600)
            fcntl.flock(descriptor, fcntl.LOCK_EX)
            yield
        finally:
            try:
                fcntl.flock(descriptor, fcntl.LOCK_UN)
            finally:
                os.close(descriptor)

    def _quarantine_corrupt_files(self):
        suffix = f".corrupt.{time.time_ns()}.{os.getpid()}"
        quarantined = []
        for sidecar in ("", "-wal", "-shm"):
            source = Path(f"{self._file_path}{sidecar}")
            try:
                metadata = source.lstat()
            except FileNotFoundError:
                continue
            if not stat.S_ISREG(metadata.st_mode):
                raise OSError(f"state database sidecar is not a regular file: {source}")
            destination = Path(f"{source}{suffix}")
            os.replace(source, destination)
            os.chmod(destination, 0o600)
            quarantined.append(destination)
        if not quarantined:
            raise OSError("corrupt state database disappeared before quarantine")
        logger.warning(
            "quarantined corrupt restart-persistent state at %s; rebuilding empty cache",
            quarantined[0],
        )

    def _prune_corrupt_files(self):
        generations = {}
        for sidecar in ("", "-wal", "-shm"):
            prefix = f"{self._file_path}{sidecar}.corrupt."
            for candidate in self._file_path.parent.glob(
                    f"{self._file_path.name}{sidecar}.corrupt.*"):
                generation = str(candidate)[len(prefix):]
                fields = generation.split(".")
                if len(fields) != 2 or not all(field.isdigit() for field in fields):
                    continue
                generations.setdefault(generation, []).append(candidate)
        ordered = sorted(
            generations,
            key=lambda generation: tuple(int(field) for field in generation.split(".")),
        )
        for generation in ordered[:-MAX_CORRUPT_STATE_GENERATIONS]:
            for candidate in generations[generation]:
                try:
                    metadata = candidate.lstat()
                except FileNotFoundError:
                    continue
                if stat.S_ISREG(metadata.st_mode):
                    candidate.unlink()

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

    @contextmanager
    def immediate_transaction(self):
        """Serialize a read-modify-write sequence across store connections."""
        self.db.execute("BEGIN IMMEDIATE")
        try:
            yield
        except Exception:
            self.db.rollback()
            raise
        else:
            self.commit()

    def _validate_schema(self):
        """Reject name-compatible but structurally foreign/corrupt cache tables."""
        for table, expected in _REQUIRED_SCHEMA.items():
            observed = tuple(
                (str(row["name"]), str(row["type"]).upper(), int(row["pk"]))
                for row in self.db.execute(f"PRAGMA table_info({table})")
            )
            if observed != expected:
                raise RuntimeError(
                    f"state database table {table} has an incompatible schema")

    @staticmethod
    def _state_key(value):
        value = str(value or "")
        if not value or len(value.encode("utf-8")) > MAX_STATE_KEY_BYTES:
            raise ValueError("state key exceeds the persisted size limit")
        return value

    @classmethod
    def _cache_keys(cls, values, description):
        values = tuple(dict.fromkeys(str(value) for value in values if value))
        if len(values) > MAX_CACHE_CYCLE_KEYS:
            raise ValueError(f"{description} exceeds the persisted row limit")
        if any(len(value.encode("utf-8")) > MAX_STATE_KEY_BYTES for value in values):
            raise ValueError(f"{description} key exceeds the persisted size limit")
        return values

    def _finish_cache_cycle(self, table, key_column, active_ids, now):
        """Mark and prune a cache from an exact inventory without bind limits.

        A temporary key set avoids both oversized ``NOT IN`` statements and
        timestamp-marker pruning.  The latter retained removed rows when the
        host clock moved backwards, while a 100k inventory also required
        hundreds of individual UPDATE statements.
        """
        allowed = {
            ("mnt_posture_cache", "mac"),
            ("tacacs_internal_user_cache", "user_id"),
            ("tacacs_policy_rule_cache", "policy_id"),
            ("network_device_group_cache", "device_id"),
        }
        if (table, key_column) not in allowed:
            raise ValueError("invalid cache table")
        self.db.execute("""
            CREATE TEMP TABLE IF NOT EXISTS active_cache_keys (
                cache_key TEXT PRIMARY KEY
            ) WITHOUT ROWID
        """)
        self.db.execute("DELETE FROM active_cache_keys")
        self.db.executemany(
            "INSERT OR IGNORE INTO active_cache_keys(cache_key) VALUES (?)",
            ((value,) for value in active_ids),
        )
        self.db.execute(
            f"UPDATE {table} SET last_seen=? WHERE {key_column} IN "
            "(SELECT cache_key FROM active_cache_keys)",
            (now,),
        )
        self.db.execute(
            f"DELETE FROM {table} WHERE NOT EXISTS "
            f"(SELECT 1 FROM active_cache_keys WHERE cache_key={table}.{key_column})"
        )
        self.commit()

    def close(self):
        try:
            self._secure_files()
        finally:
            self.db.close()

    def posture_entries(self, macs):
        macs = self._cache_keys(macs, "posture cache inventory")
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
        mac = self._state_key(mac)
        signature = self._state_key(signature)
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
        active_macs = self._cache_keys(active_macs, "posture cache inventory")
        self._finish_cache_cycle("mnt_posture_cache", "mac", active_macs, now)

    def posture_count(self):
        return int(self.db.execute(
            "SELECT COUNT(*) FROM mnt_posture_cache").fetchone()[0])

    def tacacs_user_entries(self, user_ids):
        """Return cached internal-user details for the bounded active inventory."""
        user_ids = self._cache_keys(user_ids, "TACACS user inventory")
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
        user_id = self._state_key(user_id)
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
        """, (user_id, encoded, now, now))

    def finish_tacacs_user_cycle(self, active_ids, now=None):
        """Mark active cache rows and prune accounts removed from ISE."""
        now = self._valid_timestamp(now)
        active_ids = self._cache_keys(active_ids, "TACACS user inventory")
        self._finish_cache_cycle(
            "tacacs_internal_user_cache", "user_id", active_ids, now)

    def tacacs_user_count(self):
        return int(self.db.execute(
            "SELECT COUNT(*) FROM tacacs_internal_user_cache").fetchone()[0])

    def tacacs_policy_entries(self, policy_ids):
        """Return complete cached rule counts for a bounded policy inventory."""
        policy_ids = self._cache_keys(policy_ids, "TACACS policy inventory")
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
        policy_id = self._state_key(policy_id)
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
        active_ids = self._cache_keys(active_ids, "TACACS policy inventory")
        self._finish_cache_cycle(
            "tacacs_policy_rule_cache", "policy_id", active_ids, now)

    def tacacs_policy_count(self):
        return int(self.db.execute(
            "SELECT COUNT(*) FROM tacacs_policy_rule_cache").fetchone()[0])

    def network_device_entries(self, device_ids):
        """Return bounded cached group-only detail for the current NAD inventory."""
        device_ids = self._cache_keys(device_ids, "network device inventory")
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
        device_id = self._state_key(device_id)
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
        active_ids = self._cache_keys(active_ids, "network device inventory")
        self._finish_cache_cycle(
            "network_device_group_cache", "device_id", active_ids, now)

    def network_device_count(self):
        return int(self.db.execute(
            "SELECT COUNT(*) FROM network_device_group_cache").fetchone()[0])

    @staticmethod
    def _valid_timestamp(value):
        value = time.time() if value is None else float(value)
        if not math.isfinite(value) or value < 0:
            raise ValueError("cache timestamp must be finite and non-negative")
        return value

    def get_value(self, key, default=None, *, max_bytes=None):
        key = self._state_key(key)
        max_bytes = MAX_STATE_VALUE_BYTES if max_bytes is None else int(max_bytes)
        if max_bytes < 1:
            raise ValueError("state value size limit must be positive")
        max_bytes = min(max_bytes, MAX_STATE_VALUE_BYTES)
        row = self.db.execute("""
            SELECT CASE WHEN typeof(value) = 'text'
                              AND length(CAST(value AS BLOB)) <= ?
                        THEN value END AS value
            FROM exporter_state WHERE key=?
        """, (max_bytes, key)).fetchone()
        if row is None:
            return default
        if row["value"] is None:
            self._delete_state_key(key)
            return default
        return row["value"]

    def set_value(self, key, value, *, commit=True, max_bytes=None):
        key = self._state_key(key)
        value = str(value)
        max_bytes = MAX_STATE_VALUE_BYTES if max_bytes is None else int(max_bytes)
        if max_bytes < 1:
            raise ValueError("state value size limit must be positive")
        max_bytes = min(max_bytes, MAX_STATE_VALUE_BYTES)
        if len(value.encode("utf-8")) > max_bytes:
            raise ValueError("state value exceeds the persisted size limit")
        self.db.execute("""
            INSERT INTO exporter_state(key, value) VALUES (?, ?)
            ON CONFLICT(key) DO UPDATE SET value=excluded.value
        """, (key, value))
        if commit:
            self.commit()

    def dataset_snapshot(self, dataset):
        key = self._state_key(f"dataset_snapshot.{dataset}")
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
        key = self._state_key(f"dataset_snapshot.{dataset}")
        value = json.dumps({
            "updated_at": updated_at, "payload": payload,
        }, separators=(",", ":"), allow_nan=False)
        if (len(value) > MAX_PERSISTED_SNAPSHOT_BYTES
                or len(value.encode("utf-8")) > MAX_PERSISTED_SNAPSHOT_BYTES):
            raise ValueError("dataset snapshot exceeds the persisted size limit")
        self.set_value(key, value)

    def _delete_state_key(self, key):
        key = self._state_key(key)
        self.db.execute("DELETE FROM exporter_state WHERE key=?", (key,))
        self.commit()
