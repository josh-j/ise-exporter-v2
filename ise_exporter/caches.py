"""Small in-memory TTL cache for REST network-device detail lookups."""
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
