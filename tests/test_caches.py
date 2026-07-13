import json
import stat

from ise_exporter import caches


def test_session_detail_cache_survives_restart_and_is_private(tmp_path):
    path = tmp_path / "session-details.json"
    first = caches.SessionDetailCache(3600, path)
    first.set("AA:BB:CC:DD:EE:FF", {"user_name": "operator", "passed": "true"})
    first.save()

    restarted = caches.SessionDetailCache(3600, path)
    assert restarted.get("AA:BB:CC:DD:EE:FF") == {
        "user_name": "operator", "passed": "true"}
    assert stat.S_IMODE(path.stat().st_mode) == 0o600


def test_session_detail_cache_discards_expired_records(tmp_path, monkeypatch):
    path = tmp_path / "session-details.json"
    path.write_text(json.dumps({"version": 1, "records": {
        "old": {"timestamp": 100.0, "detail": {"passed": "true"}},
        "fresh": {"timestamp": 195.0, "detail": {"passed": "true"}},
    }}))
    monkeypatch.setattr(caches.time, "time", lambda: 200.0)

    restarted = caches.SessionDetailCache(10, path)

    assert restarted.get("old") is None
    assert restarted.get("fresh") == {"passed": "true"}


def test_session_detail_cache_persists_cleanup(tmp_path):
    path = tmp_path / "session-details.json"
    cache = caches.SessionDetailCache(3600, path)
    cache.set("active", {"passed": "true"})
    cache.set("ended", {"passed": "true"})
    assert cache.cleanup({"active"}) == 1
    cache.save()

    restarted = caches.SessionDetailCache(3600, path)
    assert restarted.get("active") == {"passed": "true"}
    assert restarted.get("ended") is None
