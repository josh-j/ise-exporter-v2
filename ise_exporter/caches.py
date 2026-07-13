"""TTL caches. DeviceCache for NAD detail, SessionDetailCache for the per-MAC
Session/MACAddress authz fan-out (used only by the polling authz collector;
the streaming engine holds its own state instead)."""
import json
import logging
import os
import tempfile
import time
from pathlib import Path
from threading import Lock


logger = logging.getLogger(__name__)


class DeviceCache:
    def __init__(self, ttl_seconds=300):
        self.ttl = ttl_seconds
        self.cache = {}
        self.timestamps = {}
        self.lock = Lock()

    def get(self, key):
        with self.lock:
            if key in self.cache and time.time() - self.timestamps[key] < self.ttl:
                return self.cache[key]
        return None

    def set(self, key, value):
        with self.lock:
            self.cache[key] = value
            self.timestamps[key] = time.time()


class SessionDetailCache:
    """TTL cache for MnT session details with optional restart persistence.

    Session details can contain usernames and policy attributes, so the on-disk
    file is always created mode 0600 and replaced atomically.
    """

    def __init__(self, ttl_seconds=86400, path=""):
        self.ttl = ttl_seconds
        self.path = str(path or "")
        self.cache = {}
        self.lock = Lock()
        self.dirty = False
        self._load()

    def _load(self):
        if not self.path:
            return
        try:
            payload = json.loads(Path(self.path).read_text())
            records = payload.get("records", {}) if isinstance(payload, dict) else {}
            now = time.time()
            self.cache = {
                str(mac): entry for mac, entry in records.items()
                if (isinstance(entry, dict) and isinstance(entry.get("detail"), dict)
                    and isinstance(entry.get("timestamp"), (int, float))
                    and now - entry["timestamp"] < self.ttl)
            }
            logger.info("Session detail cache: loaded %d records from %s",
                        len(self.cache), self.path)
        except FileNotFoundError:
            return
        except (OSError, ValueError, TypeError) as e:
            logger.warning("Session detail cache: failed to load %s: %s", self.path, e)

    def get(self, mac):
        with self.lock:
            entry = self.cache.get(mac)
            if entry and time.time() - entry["timestamp"] < self.ttl:
                return entry["detail"]
        return None

    def set(self, mac, detail):
        with self.lock:
            self.cache[mac] = {"detail": detail, "timestamp": time.time()}
            self.dirty = True

    def cleanup(self, active_macs):
        active = set(active_macs)
        with self.lock:
            stale = set(self.cache) - active
            for mac in stale:
                del self.cache[mac]
            self.dirty = self.dirty or bool(stale)
            return len(stale)

    def save(self):
        if not self.path:
            return
        with self.lock:
            if not self.dirty:
                return
            destination = Path(self.path)
            try:
                destination.parent.mkdir(parents=True, exist_ok=True, mode=0o750)
                fd, temporary = tempfile.mkstemp(
                    prefix=f".{destination.name}.", dir=destination.parent)
                try:
                    os.fchmod(fd, 0o600)
                    with os.fdopen(fd, "w") as handle:
                        json.dump({"version": 1, "records": self.cache}, handle,
                                  separators=(",", ":"))
                        handle.flush()
                        os.fsync(handle.fileno())
                    os.replace(temporary, destination)
                    os.chmod(destination, 0o600)
                except Exception:
                    try:
                        os.unlink(temporary)
                    except FileNotFoundError:
                        pass
                    raise
                self.dirty = False
            except (OSError, TypeError, ValueError) as e:
                logger.warning("Session detail cache: failed to save %s: %s", self.path, e)

    def size(self):
        with self.lock:
            return len(self.cache)
