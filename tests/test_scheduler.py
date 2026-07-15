import threading
import types

import pytest
from prometheus_client import CollectorRegistry, Gauge

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
        "deployment", "devices", "dataconnect_performance",
        "dataconnect_posture", "dataconnect_endpoints", "dataconnect_freshness",
        "nad_health", "mnt_active_posture",
    )
    for name in modules:
        monkeypatch.setattr(
            getattr(scheduler_module, name), "collect",
            lambda *args, _name=name, **kwargs: ran.append(_name),
        )
    monkeypatch.setattr(
        scheduler_module.dataconnect_radius, "collect_reporting",
        lambda *args, **kwargs: ran.append("dataconnect_radius"),
    )
    monkeypatch.setattr(
        scheduler_module.dataconnect_radius, "collect_active",
        lambda *args, **kwargs: ran.append("dataconnect_radius_active"),
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

    assert set(ran) == {
        *modules, "dataconnect_radius", "dataconnect_radius_active",
        "tacacs_config", "tacacs_activity"}
    assert len(ran) == len(set(ran))


def test_scheduler_publishes_cadence_aligned_scan_windows():
    PollScheduler(_cfg(), client=object(), dataconnect=object(), mnt=object())

    samples = {
        sample.labels["dataset"]: sample.value
        for sample in metrics.ise_dataconnect_scan_window_hours.collect()[0].samples
    }
    assert samples["dataconnect_radius"] == 6
    assert samples["dataconnect_performance"] == 6
    assert samples["dataconnect_posture"] == 6
    assert samples["dataconnect_endpoints"] == 6
    assert samples["dataconnect_nad_health"] == 6
    assert samples["tacacs_activity"] == 6


def test_scheduler_freshness_fallback_matches_daily_production_cadence():
    cfg = _cfg()

    scheduler = PollScheduler(cfg, object(), object())

    assert scheduler.dataset_plan["dataconnect_freshness"] == (
        "dataconnect", 86400, True)


def test_unchecked_config_cannot_relax_production_scheduler_cadences():
    scheduler = PollScheduler(_cfg(
        scrape_interval=1,
        medium_interval=1,
        slow_interval=1,
        auth_failure_backoff=1,
        mnt_active_posture_interval=1,
        dataconnect_radius_interval=1,
        dataconnect_radius_active_interval=1,
        dataconnect_performance_interval=1,
        dataconnect_posture_interval=1,
        dataconnect_endpoints_interval=1,
        dataconnect_freshness_interval=1,
        dataconnect_nad_health_interval=1,
        dataconnect_tacacs_interval=1,
    ), object(), object(), mnt=object())

    assert scheduler.scrape_interval == 60
    assert scheduler.auth_failure_backoff == 300
    assert {name: interval for name, (_source, interval, _enabled)
            in scheduler.dataset_plan.items()} == {
        "deployment": 300,
        "devices": 3600,
        "certificates": 3600,
        "licensing": 3600,
        "backup": 3600,
        "patches": 3600,
        "dataconnect_radius": 86400,
        "dataconnect_radius_active": 7200,
        "dataconnect_performance": 21600,
        "dataconnect_posture": 86400,
        "dataconnect_endpoints": 86400,
        "dataconnect_freshness": 86400,
        "dataconnect_nad_health": 86400,
        "mnt_active_posture": 900,
        "tacacs_config": 3600,
        "tacacs_activity": 86400,
    }
    assert metrics.ise_dataconnect_scan_window_hours.labels(
        dataset="dataconnect_radius")._value.get() == 1


def test_scheduler_uses_only_the_dedicated_mnt_client(monkeypatch):
    class Client:
        def get_mnt_xml(self, *args, **kwargs):
            raise AssertionError("MnT must not participate in exporter collection")

    for name in (
        "deployment", "devices", "dataconnect_performance",
        "dataconnect_posture", "dataconnect_endpoints", "dataconnect_freshness",
        "nad_health",
    ):
        monkeypatch.setattr(getattr(scheduler_module, name), "collect", lambda *a, **k: None)
    monkeypatch.setattr(
        scheduler_module.dataconnect_radius, "collect_reporting", lambda *a, **k: None)
    monkeypatch.setattr(
        scheduler_module.dataconnect_radius, "collect_active", lambda *a, **k: None)

    seen = []
    monkeypatch.setattr(
        scheduler_module.mnt_active_posture, "collect",
        lambda client, cfg: seen.append(client),
    )
    mnt = object()

    PollScheduler(_cfg(collect_tacacs=False), Client(), object(), mnt=mnt).run_cycle()
    assert seen == [mnt]


def test_nad_health_reuses_rest_owned_device_inventory(monkeypatch):
    inventory = [{"name": "switch-1"}]
    seen = []
    modules = (
        "deployment", "dataconnect_performance", "dataconnect_posture",
        "dataconnect_endpoints", "dataconnect_freshness", "mnt_active_posture",
    )
    for name in modules:
        monkeypatch.setattr(
            getattr(scheduler_module, name), "collect", lambda *args, **kwargs: None)
    monkeypatch.setattr(scheduler_module.devices, "collect", lambda *_: inventory)
    monkeypatch.setattr(
        scheduler_module.nad_health, "collect",
        lambda devices, dataconnect, cfg: seen.append((devices, dataconnect)),
    )
    monkeypatch.setattr(
        scheduler_module.dataconnect_radius, "collect_reporting", lambda *args: None)
    monkeypatch.setattr(
        scheduler_module.dataconnect_radius, "collect_active", lambda *args: None)
    dataconnect = object()

    PollScheduler(
        _cfg(collect_tacacs=False), client=object(), dataconnect=dataconnect,
        mnt=object()).run_cycle()

    assert seen == [(inventory, dataconnect)]


def test_disabled_control_plane_collectors_do_not_run(monkeypatch):
    for name in ("deployment", "devices", "dataconnect_performance",
                 "dataconnect_posture", "dataconnect_endpoints", "dataconnect_freshness",
                 "nad_health"):
        monkeypatch.setattr(getattr(scheduler_module, name), "collect", lambda *a, **k: None)
    monkeypatch.setattr(
        scheduler_module.dataconnect_radius, "collect_reporting", lambda *a, **k: None)
    monkeypatch.setattr(
        scheduler_module.dataconnect_radius, "collect_active", lambda *a, **k: None)
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


def test_dataconnect_cooldown_lane_does_not_block_other_collection_planes():
    scheduler = PollScheduler(
        _cfg(collect_tacacs=False, dataconnect_query_timeout=1), object(), object())
    shutdown = threading.Event()
    started = threading.Event()
    release = threading.Event()
    scheduler._start_dataconnect_worker(shutdown)

    def slow_dataconnect():
        with collectors.observe("dataconnect_radius_active"):
            started.set()
            assert release.wait(1)

    scheduler._run_dataconnect("dataconnect_radius_active", 1800, slow_dataconnect)
    assert started.wait(1)

    rest_runs = []
    scheduler._run("deployment", 100.0, 300, lambda: rest_runs.append(True))
    assert rest_runs == [True]

    release.set()
    scheduler._dataconnect_queue.join()
    shutdown.set()
    scheduler._stop_dataconnect_worker()


def test_dataconnect_worker_serializes_domains_and_deduplicates_queued_runs():
    scheduler = PollScheduler(
        _cfg(collect_tacacs=False, dataconnect_query_timeout=1), object(), object())
    shutdown = threading.Event()
    first_started = threading.Event()
    release_first = threading.Event()
    second_started = threading.Event()
    order = []
    scheduler._start_dataconnect_worker(shutdown)

    def first():
        with collectors.observe("dataconnect_radius_active"):
            order.append("first")
            first_started.set()
            assert release_first.wait(1)

    def second():
        with collectors.observe("dataconnect_performance"):
            order.append("second")
            second_started.set()

    scheduler._run_dataconnect("dataconnect_radius_active", 1800, first)
    scheduler._run_dataconnect("dataconnect_radius_active", 1800, first)
    scheduler._run_dataconnect("dataconnect_performance", 3600, second)
    assert first_started.wait(1)
    assert not second_started.is_set()
    assert metrics.ise_dataconnect_worker_busy._value.get() == 1
    assert metrics.ise_dataconnect_queue_depth._value.get() == 1

    release_first.set()
    scheduler._dataconnect_queue.join()
    assert order == ["first", "second"]
    assert metrics.ise_dataconnect_worker_busy._value.get() == 0
    assert metrics.ise_dataconnect_queue_depth._value.get() == 0
    shutdown.set()
    scheduler._stop_dataconnect_worker()


def test_dataconnect_shutdown_discards_abandoned_queued_callbacks():
    scheduler = PollScheduler(
        _cfg(collect_tacacs=False, dataconnect_query_timeout=1), object(), object())
    shutdown = threading.Event()
    started = threading.Event()
    release = threading.Event()
    stale_runs = []
    scheduler._start_dataconnect_worker(shutdown)

    def current():
        with collectors.observe("dataconnect_radius_active"):
            started.set()
            assert release.wait(1)

    scheduler._run_dataconnect("dataconnect_radius_active", 1800, current)
    assert started.wait(1)
    scheduler._run_dataconnect(
        "dataconnect_performance", 3600, lambda: stale_runs.append(True))
    shutdown.set()
    release.set()
    scheduler._stop_dataconnect_worker()

    assert scheduler._dataconnect_queue.empty()
    assert scheduler._dataconnect_queue.unfinished_tasks == 0
    assert not scheduler._dataconnect_inflight
    assert stale_runs == []


def test_dataconnect_backlog_prioritizes_operational_domains():
    scheduler = PollScheduler(
        _cfg(collect_tacacs=False, dataconnect_query_timeout=1), object(), object())
    shutdown = threading.Event()
    first_started = threading.Event()
    release_first = threading.Event()
    order = []
    scheduler._start_dataconnect_worker(shutdown)

    def run(name, *, block=False):
        def callback():
            with collectors.observe(name):
                order.append(name)
                if block:
                    first_started.set()
                    assert release_first.wait(1)
        return callback

    # Hold the worker so the following two jobs are definitely both queued.
    scheduler._run_dataconnect(
        "dataconnect_endpoints", 86400,
        run("dataconnect_endpoints", block=True))
    assert first_started.wait(1)
    scheduler._run_dataconnect(
        "dataconnect_freshness", 43200, run("dataconnect_freshness"))
    scheduler._run_dataconnect(
        "dataconnect_performance", 3600, run("dataconnect_performance"))

    release_first.set()
    scheduler._dataconnect_queue.join()

    assert order == [
        "dataconnect_endpoints", "dataconnect_performance", "dataconnect_freshness"]
    shutdown.set()
    scheduler._stop_dataconnect_worker()


def test_paced_mnt_lane_does_not_block_rest_and_deduplicates_cycles():
    scheduler = PollScheduler(
        _cfg(collect_tacacs=False, request_timeout=1), object(), object(), mnt=object())
    shutdown = threading.Event()
    started = threading.Event()
    release = threading.Event()
    runs = []
    scheduler._start_mnt_worker(shutdown)

    def slow_mnt():
        with collectors.observe("mnt_active_posture"):
            runs.append(True)
            started.set()
            assert release.wait(1)

    scheduler._run_mnt("mnt_active_posture", 900, slow_mnt)
    scheduler._run_mnt("mnt_active_posture", 900, slow_mnt)
    assert started.wait(1)
    assert metrics.ise_mnt_worker_busy._value.get() == 1

    rest_runs = []
    scheduler._run("deployment", 100.0, 300, lambda: rest_runs.append(True))
    assert rest_runs == [True]

    release.set()
    scheduler._mnt_worker.join(1)
    assert runs == [True]
    assert metrics.ise_mnt_worker_busy._value.get() == 0
    shutdown.set()
    scheduler._stop_mnt_worker()


@pytest.mark.parametrize("configured", [3600, "invalid"])
def test_dataconnect_shutdown_wait_is_hard_bounded(configured):
    scheduler = PollScheduler(
        _cfg(collect_tacacs=False, dataconnect_query_timeout=configured),
        object(), object())

    class Worker:
        def __init__(self):
            self.timeout = None

        def join(self, timeout):
            self.timeout = timeout

        def is_alive(self):
            return True

    worker = Worker()
    scheduler._dataconnect_async = True
    scheduler._dataconnect_worker = worker
    scheduler._stop_dataconnect_worker()

    assert worker.timeout == 17


@pytest.mark.parametrize("configured", [3600, "invalid"])
def test_mnt_shutdown_wait_is_hard_bounded(configured):
    scheduler = PollScheduler(
        _cfg(collect_tacacs=False, request_timeout=configured),
        object(), object(), mnt=object())

    class Worker:
        def __init__(self):
            self.timeout = None

        def join(self, timeout):
            self.timeout = timeout

        def is_alive(self):
            return True

    worker = Worker()
    scheduler._mnt_async = True
    scheduler._mnt_worker = worker
    scheduler._stop_mnt_worker()

    assert worker.timeout == 32


def test_loop_exception_signals_workers_before_teardown(monkeypatch):
    scheduler = PollScheduler(
        _cfg(collect_tacacs=False, dataconnect_query_timeout=1, request_timeout=1),
        object(), object(), mnt=object(),
    )
    shutdown = threading.Event()
    monkeypatch.setattr(
        scheduler, "run_cycle",
        lambda: (_ for _ in ()).throw(RuntimeError("scheduler failed")),
    )

    with pytest.raises(RuntimeError, match="scheduler failed"):
        scheduler.loop(shutdown)

    assert shutdown.is_set()
    assert not scheduler.dataconnect_worker_alive


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


def test_transient_daily_dataconnect_failure_retries_after_slow_interval(monkeypatch):
    monkeypatch.setattr(scheduler_module.time, "time", lambda: 100.0)
    scheduler = PollScheduler(_cfg(slow_interval=3600), object(), object())

    def fail():
        with collectors.observe("dataconnect_radius"):
            raise RuntimeError("temporary database failure")

    scheduler._run("dataconnect_radius", 100.0, 86400, fail)

    assert scheduler.next_run["dataconnect_radius"] == 3700.0


def test_success_schedules_from_completion_and_publishes_freshness(monkeypatch, caplog):
    caplog.set_level("INFO", logger="ise_exporter.scheduler")
    monkeypatch.setattr(scheduler_module.time, "time", lambda: 400.0)
    scheduler = PollScheduler(_cfg(), object(), object())

    def succeed():
        with collectors.observe("dataconnect_radius"):
            pass

    scheduler._run("dataconnect_radius", 100.0, 60, succeed)

    assert scheduler.last_run["dataconnect_radius"] == 400.0
    assert scheduler.next_run["dataconnect_radius"] == 460.0
    assert scheduler.last_success["dataconnect_radius"] == 400.0
    assert metrics.ise_dataset_fresh.labels(
        dataset="dataconnect_radius", source="dataconnect")._value.get() == 1
    assert "Data Connect dataset dataconnect_radius collected successfully" in caplog.text


def test_completed_dataset_is_fresh_before_a_later_collector_returns(monkeypatch):
    now = [400.0]
    monkeypatch.setattr(scheduler_module.time, "time", lambda: now[0])
    scheduler = PollScheduler(_cfg(), object(), object())

    def succeed():
        with collectors.observe("dataconnect_radius"):
            pass

    scheduler._run("dataconnect_radius", 100.0, 60, succeed)

    # A later collector can be slow or stuck; the completed Data Connect domain
    # must already be visible as fresh instead of waiting for run_cycle() to end.
    assert metrics.ise_dataset_fresh.labels(
        dataset="dataconnect_radius", source="dataconnect")._value.get() == 1


def test_dataconnect_statement_pacing_is_not_applied_again_by_scheduler(monkeypatch):
    monkeypatch.setattr(scheduler_module.time, "time", lambda: 100.0)
    scheduler = PollScheduler(
        _cfg(dataconnect_max_duty_cycle_percent=0.5), object(), object())

    def succeed():
        with collectors.observe("dataconnect_radius"):
            pass

    scheduler._run("dataconnect_radius", 100.0, 300, succeed)

    assert scheduler.next_run["dataconnect_radius"] == 400.0
    assert metrics.ise_dataset_effective_interval_seconds.labels(
        dataset="dataconnect_radius", source="dataconnect")._value.get() == 300


def test_repeated_failures_use_slow_backoff(monkeypatch):
    monkeypatch.setattr(scheduler_module.time, "time", lambda: 200.0)
    scheduler = PollScheduler(_cfg(), object(), object())
    collectors._failures["dataconnect_radius"] = scheduler_module.MAX_CONSECUTIVE_FAILURES - 1

    def fail():
        with collectors.observe("dataconnect_radius"):
            raise RuntimeError("still unavailable")

    scheduler._run("dataconnect_radius", 100.0, 60, fail)

    assert scheduler.next_run["dataconnect_radius"] == 3800.0


def test_repeated_rest_failures_use_auth_guard_not_global_slow_tier(monkeypatch):
    monkeypatch.setattr(scheduler_module.time, "time", lambda: 200.0)
    scheduler = PollScheduler(_cfg(
        slow_interval=21600, auth_failure_backoff=900), object(), object())
    collectors._failures["deployment"] = scheduler_module.MAX_CONSECUTIVE_FAILURES - 1

    def fail():
        with collectors.observe("deployment"):
            raise RuntimeError("still unavailable")

    scheduler._run("deployment", 100.0, 300, fail)

    assert scheduler.next_run["deployment"] == 1100.0


def test_plan_initializes_enabled_disabled_cadence_and_freshness(monkeypatch):
    monkeypatch.setattr(scheduler_module.time, "time", lambda: 100.0)
    scheduler = PollScheduler(_cfg(collect_tacacs=False), object(), object())

    assert metrics.ise_dataset_enabled.labels(
        dataset="certificates", source="rest")._value.get() == 0
    assert metrics.ise_collector_enabled.labels(collector="certificates")._value.get() == 0
    assert metrics.ise_dataset_up.labels(dataset="certificates", source="rest")._value.get() == 0
    assert metrics.ise_dataset_interval_seconds.labels(
        dataset="dataconnect_radius", source="dataconnect")._value.get() == 86400
    assert metrics.ise_dataset_interval_seconds.labels(
        dataset="dataconnect_radius_active", source="dataconnect")._value.get() == 7200
    assert metrics.ise_dataset_enabled.labels(
        dataset="dataconnect_radius", source="dataconnect")._value.get() == 1
    assert {source for source, _interval, _enabled in scheduler.dataset_plan.values()} == {
        "rest", "dataconnect", "mnt"}

    scheduler.last_success["dataconnect_radius"] = 100.0
    scheduler._update_freshness(172899.0)
    assert metrics.ise_dataset_fresh.labels(
        dataset="dataconnect_radius", source="dataconnect")._value.get() == 1
    scheduler._update_freshness(172901.0)
    assert metrics.ise_dataset_fresh.labels(
        dataset="dataconnect_radius", source="dataconnect")._value.get() == 0


def test_fresh_dataconnect_snapshot_survives_restart_without_requery(
        monkeypatch, tmp_path):
    registry = CollectorRegistry()
    persisted = Gauge("restart_persisted", "test", ["key"], registry=registry)
    monkeypatch.setattr(
        scheduler_module, "_PERSISTED_DATACONNECT_METRICS",
        {"dataconnect_radius": (persisted,)},
    )
    clock = [400.0]
    monkeypatch.setattr(scheduler_module.time, "time", lambda: clock[0])
    cfg = _cfg(state_db_path=str(tmp_path / "state.sqlite3"))
    first = PollScheduler(cfg, object(), object())

    def succeed():
        with collectors.observe("dataconnect_radius"):
            persisted.labels(key="restored").set(42)

    first._run("dataconnect_radius", 100.0, 86400, succeed)
    persisted._metrics.clear()
    clock[0] = 401.0
    restarted = PollScheduler(cfg, object(), object())

    samples = {(sample.labels["key"], sample.value)
               for sample in persisted.collect()[0].samples}
    assert samples == {("restored", 42)}
    assert restarted.last_success["dataconnect_radius"] == 400.0
    assert restarted.next_run["dataconnect_radius"] == 86800.0
    assert metrics.ise_dataset_up.labels(
        dataset="dataconnect_radius", source="dataconnect")._value.get() == 1
    assert metrics.ise_dataset_fresh.labels(
        dataset="dataconnect_radius", source="dataconnect")._value.get() == 1

    queried = []
    restarted._run("dataconnect_radius", 401.0, 300, lambda: queried.append(True))
    assert queried == []


def test_restart_contract_keeps_radius_reporting_and_active_snapshots_disjoint():
    reporting = scheduler_module._PERSISTED_DATACONNECT_METRICS["dataconnect_radius"]
    active = scheduler_module._PERSISTED_DATACONNECT_METRICS[
        "dataconnect_radius_active"]

    assert set(reporting) == set(scheduler_module.dataconnect_radius._REPORTING_METRICS)
    assert set(active) == set(scheduler_module.dataconnect_radius._ACTIVE_METRICS)
    assert not set(reporting) & set(active)


def test_stale_dataconnect_snapshot_is_not_restored(monkeypatch, tmp_path):
    registry = CollectorRegistry()
    persisted = Gauge("stale_persisted", "test", registry=registry)
    monkeypatch.setattr(
        scheduler_module, "_PERSISTED_DATACONNECT_METRICS",
        {"dataconnect_radius": (persisted,)},
    )
    clock = [100.0]
    monkeypatch.setattr(scheduler_module.time, "time", lambda: clock[0])
    cfg = _cfg(state_db_path=str(tmp_path / "state.sqlite3"))
    first = PollScheduler(cfg, object(), object())

    def succeed():
        with collectors.observe("dataconnect_radius"):
            persisted.set(42)

    first._run("dataconnect_radius", 100.0, 86400, succeed)
    persisted.set(0)
    clock[0] = 172901.0
    restarted = PollScheduler(cfg, object(), object())

    assert persisted._value.get() == 0
    assert "dataconnect_radius" not in restarted.last_success
    queried = []
    restarted._run("dataconnect_radius", 701.0, 300, lambda: queried.append(True))
    assert queried == [True]


def test_unavailable_persistent_state_does_not_prevent_collection(monkeypatch, caplog):
    def unavailable(_self):
        raise PermissionError("state directory denied")

    monkeypatch.setattr(PollScheduler, "_state_store", unavailable)
    scheduler = PollScheduler(_cfg(), object(), object())

    assert scheduler.next_run == {}
    assert "could not open restart-persistent dataset state" in caplog.text
