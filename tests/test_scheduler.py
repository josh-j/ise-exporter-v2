import types

import pytest

from ise_exporter import collectors, metrics
import ise_exporter.scheduler as scheduler_module
from ise_exporter.scheduler import PollScheduler, _next_deadline


def _cfg(**overrides):
    values = dict(
        collect_certificates=False,
        collect_licensing=False,
        collect_backup_status=False,
        collect_patches=False,
        collect_tacacs=True,
        collect_mnt_active_posture=True,
        mnt_active_posture_interval=300,
        fast_interval=60,
        medium_interval=300,
        slow_interval=3600,
        scrape_interval=60,
    )
    values.update(overrides)
    return types.SimpleNamespace(**values)


@pytest.fixture(autouse=True)
def _reset_collector_runtime_state():
    collectors._failures.clear()
    collectors._outcomes.clear()


def test_collection_plan_has_one_writer_per_reporting_domain(monkeypatch):
    ran = []
    modules = (
        "deployment", "devices", "dataconnect_radius", "dataconnect_performance",
        "dataconnect_posture", "dataconnect_endpoints", "dataconnect_freshness",
        "nad_health", "mnt_active_posture",
    )
    for name in modules:
        monkeypatch.setattr(
            getattr(scheduler_module, name), "collect",
            lambda *args, _name=name, **kwargs: ran.append(_name),
        )
    monkeypatch.setattr(
        scheduler_module.tacacs, "collect_config",
        lambda *args, **kwargs: ran.append("tacacs_config"),
    )
    monkeypatch.setattr(
        scheduler_module.tacacs, "collect_activity",
        lambda *args, **kwargs: ran.append("tacacs_activity"),
    )

    PollScheduler(_cfg(), client=object(), dataconnect=object(), mnt=object()).run_cycle()

    assert set(ran) == {*modules, "tacacs_config", "tacacs_activity"}
    assert len(ran) == len(set(ran))


def test_scheduler_uses_only_the_dedicated_mnt_client(monkeypatch):
    class Client:
        def get_mnt_xml(self, *args, **kwargs):
            raise AssertionError("MnT must not participate in exporter collection")

    for name in (
        "deployment", "devices", "dataconnect_radius", "dataconnect_performance",
        "dataconnect_posture", "dataconnect_endpoints", "dataconnect_freshness",
        "nad_health",
    ):
        monkeypatch.setattr(getattr(scheduler_module, name), "collect", lambda *a, **k: None)

    seen = []
    monkeypatch.setattr(
        scheduler_module.mnt_active_posture, "collect",
        lambda client, cfg: seen.append(client),
    )
    mnt = object()

    PollScheduler(_cfg(collect_tacacs=False), Client(), object(), mnt=mnt).run_cycle()
    assert seen == [mnt]


def test_disabled_control_plane_collectors_do_not_run(monkeypatch):
    for name in ("deployment", "devices", "dataconnect_radius", "dataconnect_performance",
                 "dataconnect_posture", "dataconnect_endpoints", "dataconnect_freshness",
                 "nad_health"):
        monkeypatch.setattr(getattr(scheduler_module, name), "collect", lambda *a, **k: None)
    monkeypatch.setattr(scheduler_module.mnt_active_posture, "collect", lambda *a, **k: None)
    for name in ("certificates", "licensing", "backup", "patches"):
        monkeypatch.setattr(
            getattr(scheduler_module, name), "collect",
            lambda *a, _name=name, **k: (_ for _ in ()).throw(
                AssertionError(f"{_name} should be disabled")),
        )

    PollScheduler(_cfg(collect_tacacs=False), object(), object()).run_cycle()


def test_next_deadline_skips_missed_ticks_instead_of_replaying_them():
    assert _next_deadline(60, 190, 60) == 240
    assert _next_deadline(60, 180, 60) == 240
    assert _next_deadline(60, 119, 60) == 120


def test_failed_dataconnect_attempt_never_retries_faster_than_five_minutes(monkeypatch):
    now = [105.0]
    monkeypatch.setattr(scheduler_module.time, "time", lambda: now[0])
    scheduler = PollScheduler(_cfg(), object(), object())
    attempts = []

    def fail():
        attempts.append(True)
        with collectors.observe("dataconnect_radius"):
            raise RuntimeError("database unavailable")

    scheduler._run("dataconnect_radius", 100.0, 60, fail)

    assert len(attempts) == 1
    assert "dataconnect_radius" not in scheduler.last_run
    assert scheduler.last_attempt["dataconnect_radius"] == 100.0
    assert scheduler.next_run["dataconnect_radius"] == 405.0
    assert collectors.outcome("dataconnect_radius") is False
    assert metrics.ise_dataset_up.labels(
        dataset="dataconnect_radius", source="dataconnect")._value.get() == 0

    scheduler._run("dataconnect_radius", 404.0, 60, fail)
    assert len(attempts) == 1
    now[0] = 410.0
    scheduler._run("dataconnect_radius", 405.0, 60, fail)
    assert len(attempts) == 2


def test_success_schedules_from_completion_and_does_not_catch_up(monkeypatch):
    monkeypatch.setattr(scheduler_module.time, "time", lambda: 400.0)
    scheduler = PollScheduler(_cfg(), object(), object())

    def succeed():
        with collectors.observe("dataconnect_radius"):
            pass

    scheduler._run("dataconnect_radius", 100.0, 60, succeed)

    assert scheduler.last_run["dataconnect_radius"] == 400.0
    assert scheduler.next_run["dataconnect_radius"] == 460.0
    assert scheduler.last_success["dataconnect_radius"] == 400.0


def test_slow_dataconnect_collection_gets_duty_cycle_backoff(monkeypatch):
    monotonic = iter((0.0, 20.0))
    monkeypatch.setattr(scheduler_module.time, "monotonic", lambda: next(monotonic))
    monkeypatch.setattr(scheduler_module.time, "time", lambda: 100.0)
    scheduler = PollScheduler(
        _cfg(dataconnect_max_duty_cycle_percent=5), object(), object())

    def succeed():
        with collectors.observe("dataconnect_radius"):
            pass

    scheduler._run("dataconnect_radius", 100.0, 300, succeed)

    assert scheduler.next_run["dataconnect_radius"] == 500.0
    assert metrics.ise_dataset_effective_interval_seconds.labels(
        dataset="dataconnect_radius", source="dataconnect")._value.get() == 400
    assert metrics.ise_dataconnect_load_backoff_seconds.labels(
        dataset="dataconnect_radius")._value.get() == 100


def test_repeated_failures_use_slow_backoff(monkeypatch):
    monkeypatch.setattr(scheduler_module.time, "time", lambda: 200.0)
    scheduler = PollScheduler(_cfg(), object(), object())
    collectors._failures["dataconnect_radius"] = scheduler_module.MAX_CONSECUTIVE_FAILURES - 1

    def fail():
        with collectors.observe("dataconnect_radius"):
            raise RuntimeError("still unavailable")

    scheduler._run("dataconnect_radius", 100.0, 60, fail)

    assert scheduler.next_run["dataconnect_radius"] == 3800.0


def test_plan_initializes_enabled_disabled_cadence_and_freshness(monkeypatch):
    monkeypatch.setattr(scheduler_module.time, "time", lambda: 100.0)
    scheduler = PollScheduler(_cfg(collect_tacacs=False), object(), object())

    assert metrics.ise_dataset_enabled.labels(
        dataset="certificates", source="rest")._value.get() == 0
    assert metrics.ise_collector_enabled.labels(collector="certificates")._value.get() == 0
    assert metrics.ise_dataset_up.labels(dataset="certificates", source="rest")._value.get() == 0
    assert metrics.ise_dataset_interval_seconds.labels(
        dataset="dataconnect_radius", source="dataconnect")._value.get() == 300
    assert metrics.ise_dataset_enabled.labels(
        dataset="dataconnect_radius", source="dataconnect")._value.get() == 1
    assert metrics.ise_dataset_enabled.labels(
        dataset="pxgrid_streaming", source="pxgrid")._value.get() == 0
    assert metrics.ise_collector_enabled.labels(collector="pxgrid_streaming")._value.get() == 0

    scheduler.last_success["dataconnect_radius"] = 100.0
    scheduler._update_freshness(699.0)
    assert metrics.ise_dataset_fresh.labels(
        dataset="dataconnect_radius", source="dataconnect")._value.get() == 1
    scheduler._update_freshness(701.0)
    assert metrics.ise_dataset_fresh.labels(
        dataset="dataconnect_radius", source="dataconnect")._value.get() == 0
