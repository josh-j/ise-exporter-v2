from ise_exporter import caches


def test_device_cache_evicts_expired_entry(monkeypatch):
    now = [100.0]
    monkeypatch.setattr(caches.time, "time", lambda: now[0])
    cache = caches.DeviceCache(ttl_seconds=10)
    cache.set("removed-nad", {"name": "old"})

    now[0] = 111.0

    assert cache.get("removed-nad") is None
    assert cache.cache == {}
    assert cache.timestamps == {}
