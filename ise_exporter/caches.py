"""TTL caches. DeviceCache for NAD detail, SessionDetailCache for the per-MAC
Session/MACAddress authz fan-out (used only by the polling authz collector;
the streaming engine holds its own state instead)."""
import time
from threading import Lock


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
    def __init__(self, ttl_seconds=86400):
        self.ttl = ttl_seconds
        self.cache = {}
        self.lock = Lock()

    def get(self, mac):
        with self.lock:
            entry = self.cache.get(mac)
            if entry and time.time() - entry["timestamp"] < self.ttl:
                return entry["detail"]
        return None

    def set(self, mac, detail):
        with self.lock:
            self.cache[mac] = {"detail": detail, "timestamp": time.time()}

    def cleanup(self, active_macs):
        active = set(active_macs)
        with self.lock:
            stale = set(self.cache) - active
            for mac in stale:
                del self.cache[mac]
            return len(stale)

    def size(self):
        with self.lock:
            return len(self.cache)
