import threading
import types

import pytest
from prometheus_client import CollectorRegistry, Gauge

from ise_exporter import collectors, metrics
from ise_exporter.dataconnect_schema import MANDATORY_COLUMNS_BY_VIEW, VIEW_CONTRACTS
import ise_exporter.scheduler as scheduler_module
from ise_exporter.scheduler import PollScheduler, _next_deadline


def test_collector_duration_uses_monotonic_time_during_wall_clock_correction(
        monkeypatch):
    monotonic = iter((10.0, 12.5))
    monkeypatch.setattr(collectors.time, "monotonic", lambda: next(monotonic))
    monkeypatch.setattr(collectors.time, "time", lambda: 5.0)

    with collectors.observe("clock_adjustment_test"):
        pass

    assert metrics.ise_last_successful_scrape.labels(
        collector="clock_adjustment_test")._value.get() == 5.0
    assert metrics.ise_collector_duration_seconds.labels(
        collector="clock_adjustment_test")._value.get() == 2.5


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
    collectors._failure_reasons.clear()
    collectors._failure_details.clear()


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


def test_devices_detail_pass_runs_off_the_calling_thread(monkeypatch):
    caller = threading.current_thread()
    started = threading.Event()
    release = threading.Event()
    executed_on = []

    def blocking_collect(client, cfg):
        executed_on.append(threading.current_thread())
        started.set()
        release.wait(2)
        return [{"id": "nad-1", "name": "sw-1"}]

    monkeypatch.setattr(scheduler_module.devices, "collect", blocking_collect)
    scheduler = PollScheduler(
        _cfg(startup_rate_limit_seconds=0), client=object(),
        dataconnect=object(), mnt=object())

    # Synchronous until the worker is activated.
    assert scheduler._devices_async is False
    scheduler._start_devices_worker(threading.Event())

    # A long detail pass must not block the caller (the REST lane).
    scheduler._run_devices(1_000_000_000.0)
    assert started.wait(2), "detail collect never started on a worker thread"
    assert executed_on and executed_on[-1] is not caller
    release.set()
    scheduler._stop_devices_worker()
    assert scheduler._nad_inventory == [{"id": "nad-1", "name": "sw-1"}]


def test_tacacs_config_runs_off_the_calling_thread_without_self_overlap(
        monkeypatch):
    caller = threading.current_thread()
    started = threading.Event()
    release = threading.Event()
    executed_on = []
    call_count = []

    def blocking_collect_config(client, cfg):
        call_count.append(1)
        executed_on.append(threading.current_thread())
        started.set()
        release.wait(2)

    monkeypatch.setattr(
        scheduler_module.tacacs, "collect_config", blocking_collect_config)
    scheduler = PollScheduler(
        _cfg(startup_rate_limit_seconds=0), client=object(),
        dataconnect=object(), mnt=object())

    # Synchronous until the worker is activated (deterministic for tests).
    assert scheduler._tacacs_config_async is False
    scheduler._start_tacacs_config_worker(threading.Event())

    # A long ERS enumeration must not block the caller (the main scheduler lane).
    scheduler._run_tacacs_config(1_000_000_000.0)
    assert started.wait(2), "tacacs_config collect never started on a worker thread"
    assert executed_on and executed_on[-1] is not caller

    # A second trigger while the first attempt is still in flight must be a
    # no-op dedupe rather than a concurrent second run.
    scheduler._run_tacacs_config(1_000_000_000.0)
    release.set()
    scheduler._stop_tacacs_config_worker()
    assert len(call_count) == 1


def test_stop_tacacs_config_worker_joins_within_bound(monkeypatch):
    release = threading.Event()

    def blocking_collect_config(client, cfg):
        release.wait(2)

    monkeypatch.setattr(
        scheduler_module.tacacs, "collect_config", blocking_collect_config)
    scheduler = PollScheduler(
        _cfg(startup_rate_limit_seconds=0, request_timeout=1), client=object(),
        dataconnect=object(), mnt=object())
    scheduler._start_tacacs_config_worker(threading.Event())
    scheduler._run_tacacs_config(1_000_000_000.0)

    release.set()
    scheduler._stop_tacacs_config_worker()
    assert scheduler._tacacs_config_worker.is_alive() is False


def test_tacacs_config_not_scheduled_when_collect_tacacs_is_false(monkeypatch):
    called = []
    # Stand in for every other dataset's collect() too: run_cycle() drives the
    # full plan, and unpatched collectors would fail against the bare stand-in
    # client/dataconnect/mnt objects below, polluting the process-global
    # metrics registry with unrelated failure samples for later tests.
    modules = (
        "deployment", "devices", "dataconnect_performance",
        "dataconnect_posture", "dataconnect_endpoints", "dataconnect_freshness",
        "nad_health", "mnt_active_posture",
    )
    for name in modules:
        monkeypatch.setattr(
            getattr(scheduler_module, name), "collect",
            lambda *args, **kwargs: None)
    monkeypatch.setattr(
        scheduler_module.dataconnect_radius, "collect_reporting",
        lambda *args, **kwargs: None)
    monkeypatch.setattr(
        scheduler_module.dataconnect_radius, "collect_active",
        lambda *args, **kwargs: None)
    monkeypatch.setattr(
        scheduler_module.tacacs, "collect_config",
        lambda *args, **kwargs: called.append(True))
    monkeypatch.setattr(
        scheduler_module.tacacs, "collect_activity",
        lambda *args, **kwargs: called.append(True))

    PollScheduler(
        _cfg(collect_tacacs=False), client=object(),
        dataconnect=object(), mnt=object()).run_cycle()

    assert called == []


def test_scheduler_publishes_cadence_aligned_scan_windows():
    PollScheduler(_cfg(), client=object(), dataconnect=object(), mnt=object())

    samples = {
        sample.labels["dataset"]: sample.value
        for sample in metrics.ise_dataconnect_scan_window_hours.collect()[0].samples
    }
    assert samples["dataconnect_radius"] == 1
    assert samples["dataconnect_performance"] == 6
    assert samples["dataconnect_posture"] == 6
    assert samples["dataconnect_endpoints"] == 6
    assert samples["dataconnect_nad_health"] == 6
    assert samples["tacacs_activity"] == 6


def test_scheduler_freshness_fallback_matches_half_hour_production_cadence():
    cfg = _cfg()

    scheduler = PollScheduler(cfg, object(), object())

    assert scheduler.dataset_plan["dataconnect_freshness"] == (
        "dataconnect", 1800, True)


def test_startup_journal_lists_dataset_source_cadence_and_time(caplog, monkeypatch):
    monkeypatch.setattr(scheduler_module.time, "time", lambda: 100.0)
    caplog.set_level("INFO", logger="ise_exporter.scheduler")

    PollScheduler(
        _cfg(startup_rate_limit_seconds=7, collect_tacacs=False),
        object(), object(), mnt=object())

    assert "startup schedule:" in caplog.text
    assert "startup_rate_limit_seconds=7" in caplog.text
    assert "scheduled dataset=deployment source=rest enabled=true" in caplog.text
    assert "interval_seconds=300" in caplog.text
    assert "due_at=1970-01-01T00:01:40Z" in caplog.text
    assert "scheduled dataset=tacacs_activity source=dataconnect enabled=false" in caplog.text


def test_expected_schema_discovery_deferral_is_informational(caplog):
    caplog.set_level("INFO", logger="ise_exporter.scheduler")
    scheduler = PollScheduler(
        _cfg(collect_tacacs=False), object(), object(), mnt=object())
    scheduler._dataconnect_schema_failures = {
        "dataconnect_performance": types.SimpleNamespace(
            reason="schema_validation_pending",
            detail="Data Connect schema discovery has not completed successfully",
        ),
    }
    caplog.clear()

    scheduler._log_startup_schedule()

    records = [
        record for record in caplog.records
        if "reason=schema_validation_pending" in record.getMessage()
    ]
    assert records
    assert all(record.levelname == "INFO" for record in records)


def test_schema_incompatible_dataset_is_visible_and_never_queried(caplog):
    failure = types.SimpleNamespace(
        reason="schema_missing_view_system_summary",
        detail="missing view SYSTEM_SUMMARY",
    )
    dataconnect = types.SimpleNamespace(dataset_schema_failures={
        "dataconnect_performance": failure,
    })
    caplog.set_level("WARNING", logger="ise_exporter.scheduler")
    scheduler = PollScheduler(_cfg(), object(), dataconnect, mnt=object())
    called = []

    scheduler._run_dataconnect(
        "dataconnect_performance", 1, lambda: called.append(True))

    assert called == []
    assert metrics.ise_dataset_up.labels(
        dataset="dataconnect_performance", source="dataconnect")._value.get() == 0
    assert metrics.ise_dataset_last_failure_info.labels(
        dataset="dataconnect_performance", source="dataconnect",
        reason="schema_missing_view_system_summary")._value.get() == 1
    detail_samples = [
        sample
        for sample in metrics.ise_dataset_last_failure_detail_info.collect()[0].samples
        if sample.labels.get("dataset") == "dataconnect_performance"
    ]
    assert len(detail_samples) == 1
    assert detail_samples[0].labels["detail"] == "missing view SYSTEM_SUMMARY"
    assert "blocked=true reason=schema_missing_view_system_summary" in caplog.text


def _schema_rows(include_tacacs=False):
    return [
        {
            "table_name": table,
            "column_name": column,
            "data_type": "VARCHAR2",
        }
        for table, contract in VIEW_CONTRACTS.items()
        if include_tacacs or contract.domain != "tacacs"
        for column in contract.required | MANDATORY_COLUMNS_BY_VIEW[table]
    ]


def test_schema_discovery_unblocks_compatible_datasets_and_restores_snapshots(
        monkeypatch):
    class DataConnect:
        schema_ready = False
        dataset_schema_failures = {}

        def query_catalog(self, _sql, _parameters=None):
            return _schema_rows()

        def set_schema(self, schema, failures):
            self.schema = schema
            self.dataset_schema_failures = failures
            self.schema_ready = True

    dataconnect = DataConnect()
    scheduler = PollScheduler(
        _cfg(collect_tacacs=False), object(), dataconnect, mnt=object())
    restored = []
    monkeypatch.setattr(
        scheduler, "_restore_dataconnect_state", lambda: restored.append(True))
    called = []

    scheduler._run_dataconnect(
        "dataconnect_performance", 1, lambda: called.append("premature"))
    scheduler._collect_dataconnect_schema()
    scheduler._run_dataconnect(
        "dataconnect_performance", 1, lambda: called.append("ready"))

    assert scheduler._dataconnect_schema_ready is True
    assert scheduler._dataconnect_schema_failures == {}
    assert dataconnect.schema_ready is True
    assert restored == [True]
    assert called == ["ready"]
    pending = [
        sample for sample in metrics.ise_dataset_last_failure_info.collect()[0].samples
        if sample.labels.get("dataset") == "dataconnect_performance"
        and sample.labels.get("reason") == "schema_validation_pending"
    ]
    assert pending == []
    pending_details = [
        sample
        for sample in metrics.ise_dataset_last_failure_detail_info.collect()[0].samples
        if sample.labels.get("dataset") == "dataconnect_performance"
        and sample.labels.get("reason") == "schema_validation_pending"
    ]
    assert pending_details == []


def test_cold_start_queues_operational_data_behind_schema_in_first_cycle():
    class DataConnect:
        schema_ready = False
        dataset_schema_failures = {}

    scheduler = PollScheduler(
        _cfg(collect_tacacs=False), object(), DataConnect(), mnt=object())
    scheduler._dataconnect_async = True
    queued = []
    scheduler._dataconnect_queue.put = lambda item: queued.append(item[2])

    scheduler._run_dataconnect(
        "dataconnect_schema", 86400, lambda: None)
    scheduler._run_dataconnect(
        "dataconnect_radius_active", 1800, lambda: None)
    scheduler._run_dataconnect(
        "dataconnect_performance", 3600, lambda: None)

    assert queued == [
        "dataconnect_schema",
        "dataconnect_radius_active",
        "dataconnect_performance",
    ]


def test_cold_start_dispatches_operational_lanes_before_inventory(monkeypatch):
    class DataConnect:
        schema_ready = False
        dataset_schema_failures = {}

    scheduler = PollScheduler(
        _cfg(collect_tacacs=False), object(), DataConnect(), mnt=object())
    dispatched = []
    monkeypatch.setattr(
        scheduler, "_run",
        lambda name, *_args, **_kwargs: dispatched.append(name))
    monkeypatch.setattr(
        scheduler, "_run_dataconnect",
        lambda name, *_args, **_kwargs: dispatched.append(name))
    monkeypatch.setattr(
        scheduler, "_run_mnt",
        lambda name, *_args, **_kwargs: dispatched.append(name))

    scheduler.run_cycle()

    assert dispatched[:5] == [
        "deployment",
        "dataconnect_schema",
        "dataconnect_radius_active",
        "dataconnect_performance",
        "mnt_active_posture",
    ]
    assert dispatched.index("devices") > dispatched.index("mnt_active_posture")


def test_schema_transport_failure_keeps_rest_reporting_lane_retryable(monkeypatch):
    class DataConnect:
        schema_ready = False
        dataset_schema_failures = {}

        def __init__(self):
            self.fail = True

        def query_catalog(self, _sql, _parameters=None):
            if self.fail:
                raise RuntimeError("database unavailable")
            return _schema_rows()

        def set_schema(self, schema, failures):
            self.schema_ready = True
            self.dataset_schema_failures = failures

    dataconnect = DataConnect()
    scheduler = PollScheduler(
        _cfg(collect_tacacs=False), object(), dataconnect, mnt=object())
    monkeypatch.setattr(scheduler, "_restore_dataconnect_state", lambda: None)

    scheduler._collect_dataconnect_schema()

    assert scheduler._dataconnect_schema_ready is False
    assert collectors.outcome("dataconnect_schema") is False
    assert metrics.ise_dataset_up.labels(
        dataset="deployment", source="rest")._value.get() == 0
    dataconnect.fail = False
    scheduler._collect_dataconnect_schema()
    assert scheduler._dataconnect_schema_ready is True
    assert collectors.outcome("dataconnect_schema") is True


def test_schema_discovery_retries_hourly_then_returns_to_daily_cadence():
    scheduler = PollScheduler(
        _cfg(collect_tacacs=False, slow_interval=21600), object(), object())

    collectors._failures["dataconnect_schema"] = 1
    assert scheduler._failure_retry(
        "dataconnect_schema", "dataconnect", 86400) == 3600
    collectors._failures["dataconnect_schema"] = 5
    assert scheduler._failure_retry(
        "dataconnect_schema", "dataconnect", 86400) == 86400


def test_startup_rate_limit_spaces_only_each_datasets_first_attempt(monkeypatch):
    clock = [100.0]
    sleeps = []
    monkeypatch.setattr(scheduler_module.time, "monotonic", lambda: clock[0])

    def sleep(delay):
        sleeps.append(delay)
        clock[0] += delay

    monkeypatch.setattr(scheduler_module.time, "sleep", sleep)
    scheduler = PollScheduler(
        _cfg(startup_rate_limit_seconds=7), object(), object(), mnt=object())

    assert scheduler._wait_for_startup_slot("deployment") is True
    assert scheduler._wait_for_startup_slot("devices") is True
    assert scheduler._wait_for_startup_slot("deployment") is True
    assert scheduler._wait_for_startup_slot("dataconnect_radius_active") is True

    assert sleeps == [7, 7]


def test_startup_rate_limit_wait_is_interruptible(monkeypatch):
    monkeypatch.setattr(scheduler_module.time, "monotonic", lambda: 100.0)
    scheduler = PollScheduler(
        _cfg(startup_rate_limit_seconds=7), object(), object(), mnt=object())
    assert scheduler._wait_for_startup_slot("deployment") is True

    waits = []

    class Shutdown:
        def wait(self, delay):
            waits.append(delay)
            return True

    scheduler._shutdown = Shutdown()
    assert scheduler._wait_for_startup_slot("devices") is False
    assert waits == [7]


def test_scheduler_respects_valid_explicit_cadences_but_preserves_auth_backoff():
    scheduler = PollScheduler(_cfg(
        scrape_interval=1,
        medium_interval=1,
        slow_interval=1,
        auth_failure_backoff=1,
        mnt_active_posture_interval=1,
        dataconnect_radius_interval=1,
        dataconnect_schema_interval=1,
        dataconnect_radius_active_interval=1,
        dataconnect_performance_interval=1,
        dataconnect_posture_interval=1,
        dataconnect_endpoints_interval=1,
        dataconnect_freshness_interval=1,
        dataconnect_nad_health_interval=1,
        dataconnect_tacacs_interval=1,
    ), object(), object(), mnt=object())

    assert scheduler.scrape_interval == 1
    assert scheduler.auth_failure_backoff == 300
    assert {name: interval for name, (_source, interval, _enabled)
            in scheduler.dataset_plan.items()} == {
        "deployment": 1,
        "devices": 1,
        "certificates": 1,
        "licensing": 1,
        "backup": 1,
        "patches": 1,
        "dataconnect_radius": 1,
        "dataconnect_schema": 1,
        "dataconnect_radius_active": 1,
        "dataconnect_performance": 1,
        "dataconnect_accounting_counters": 300,
        "dataconnect_posture_counters": 300,
        "dataconnect_authentication_counters": 300,
        "dataconnect_error_counters": 300,
        "dataconnect_posture": 1,
        "dataconnect_endpoints": 1,
        "dataconnect_freshness": 1,
        "endpoint_fleet": 900,
        "dataconnect_nad_health": 1,
        "mnt_active_posture": 1,
        "tacacs_config": 1,
        "tacacs_activity": 1,
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
        lambda client, cfg, ops_owners=None: seen.append(client),
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


def test_devices_worker_also_captures_the_ops_owner_mapping(monkeypatch):
    monkeypatch.setattr(
        scheduler_module.devices, "collect",
        lambda client, cfg: [{"id": "nad-1", "name": "switch-1"}])
    monkeypatch.setattr(
        scheduler_module.devices, "latest_ops_owner_by_nad",
        lambda: {"switch-1": "Campus"})
    scheduler = PollScheduler(
        _cfg(startup_rate_limit_seconds=0), client=object(),
        dataconnect=object(), mnt=object())

    assert scheduler._nad_ops_owners == {}
    scheduler._run_devices(1_000_000_000.0)

    assert scheduler._nad_ops_owners == {"switch-1": "Campus"}


def test_mnt_active_posture_reuses_the_scheduler_owned_ops_owner_mapping(monkeypatch):
    ops_owners = {"switch-1": "Campus"}
    seen = []
    modules = (
        "deployment", "devices", "dataconnect_performance",
        "dataconnect_posture", "dataconnect_endpoints", "dataconnect_freshness",
        "nad_health",
    )
    for name in modules:
        monkeypatch.setattr(
            getattr(scheduler_module, name), "collect", lambda *a, **k: None)
    monkeypatch.setattr(
        scheduler_module.dataconnect_radius, "collect_reporting", lambda *a, **k: None)
    monkeypatch.setattr(
        scheduler_module.dataconnect_radius, "collect_active", lambda *a, **k: None)
    monkeypatch.setattr(
        scheduler_module.mnt_active_posture, "collect",
        lambda client, cfg, mapping=None: seen.append(mapping),
    )
    scheduler = PollScheduler(
        _cfg(collect_tacacs=False), client=object(), dataconnect=object(), mnt=object())
    scheduler._nad_ops_owners = ops_owners

    scheduler.run_cycle()

    assert seen == [ops_owners]


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


def test_next_deadline_recovers_from_large_backward_clock_correction():
    assert _next_deadline(3600, 100, 60) == 160
    assert _next_deadline(401, 100, 60) == 160


def test_dataset_deadline_recovers_from_large_backward_clock_correction():
    scheduler = PollScheduler(_cfg(), object(), object())
    scheduler.next_run["deployment"] = 3600.0

    runs = []
    scheduler._run("deployment", 100.0, 300, lambda: runs.append(True))

    assert runs == [True]


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


def test_dataconnect_worker_serializes_domains_and_deduplicates_queued_runs(caplog):
    caplog.set_level("INFO", logger="ise_exporter.scheduler")
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
    assert "collection queued dataset=dataconnect_radius_active" in caplog.text
    assert "lane=serialized" in caplog.text
    assert "reason=scheduled_due" in caplog.text
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


def test_schema_revalidation_discards_already_queued_incompatible_dataset(caplog):
    class DataConnect:
        schema_ready = True
        dataset_schema_failures = {}

        def set_schema(self, _schema, failures):
            self.dataset_schema_failures = failures

    dataconnect = DataConnect()
    scheduler = PollScheduler(
        _cfg(collect_tacacs=False, dataconnect_query_timeout=1),
        object(), dataconnect,
    )
    scheduler._dataconnect_async = True
    scheduler._shutdown = threading.Event()
    ran = []
    failure = types.SimpleNamespace(
        reason="schema_missing_view_system_summary",
        detail="missing view SYSTEM_SUMMARY",
    )

    scheduler._run_dataconnect(
        "dataconnect_schema", 86400,
        lambda: scheduler._apply_dataconnect_schema(
            {}, {"dataconnect_performance": failure}),
    )
    scheduler._run_dataconnect(
        "dataconnect_performance", 21600, lambda: ran.append(True))

    scheduler._start_dataconnect_worker(scheduler._shutdown)
    scheduler._dataconnect_queue.join()

    assert ran == []
    assert "collection discarded dataset=dataconnect_performance" in caplog.text
    assert "reason=schema_missing_view_system_summary" in caplog.text
    assert "detail=missing view SYSTEM_SUMMARY" in caplog.text
    assert "query_started=false" in caplog.text
    assert "action=wait_for_compatible_schema" in caplog.text
    assert not scheduler._dataconnect_inflight
    scheduler._shutdown.set()
    scheduler._stop_dataconnect_worker()


def test_dataconnect_worker_survives_scheduler_bookkeeping_exception(
        monkeypatch, caplog):
    caplog.set_level("INFO", logger="ise_exporter.scheduler")
    scheduler = PollScheduler(
        _cfg(collect_tacacs=False, dataconnect_query_timeout=1), object(), object())
    shutdown = threading.Event()
    later_runs = []
    original_run = scheduler._run

    def fail_one_domain(name, now, tier, callback):
        if name == "dataconnect_radius_active":
            raise RuntimeError("bookkeeping failed")
        return original_run(name, now, tier, callback)

    monkeypatch.setattr(scheduler, "_run", fail_one_domain)
    scheduler._start_dataconnect_worker(shutdown)
    scheduler._run_dataconnect(
        "dataconnect_radius_active", 7200, lambda: None)
    scheduler._run_dataconnect(
        "dataconnect_performance", 21600, lambda: later_runs.append(True))
    scheduler._dataconnect_queue.join()

    assert later_runs == [True]
    assert scheduler.dataconnect_worker_alive
    assert collectors.failures("dataconnect_radius_active") == 1
    assert scheduler.next_run[
        "dataconnect_radius_active"] > scheduler_module.time.time()
    assert "Data Connect worker bookkeeping failed" in caplog.text
    assert "collection rescheduled dataset=dataconnect_radius_active" in caplog.text
    assert "retry_reason=worker_recovery" in caplog.text
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


def test_dataconnect_queue_ages_a_long_starved_item_ahead_of_a_fresh_one(
        monkeypatch):
    clock = [0.0]
    monkeypatch.setattr(scheduler_module.time, "time", lambda: clock[0])
    scheduler = PollScheduler(
        _cfg(collect_tacacs=False, dataconnect_query_timeout=1), object(), object())
    q = scheduler._dataconnect_queue

    # dataconnect_freshness (static priority 7) queued first and left waiting
    # long enough (> 7 aging levels * 900s) to age past dataconnect_radius_active
    # (static priority 0), which is enqueued fresh just before the dequeue.
    q.put((7, 0, "dataconnect_freshness", 86400, lambda: None))
    clock[0] = 6301.0
    q.put((0, 1, "dataconnect_radius_active", 1800, lambda: None))

    item = q.get()

    assert item[2] == "dataconnect_freshness"


def test_dataconnect_queue_follows_static_priority_when_freshly_queued(
        monkeypatch):
    clock = [100.0]
    monkeypatch.setattr(scheduler_module.time, "time", lambda: clock[0])
    scheduler = PollScheduler(
        _cfg(collect_tacacs=False, dataconnect_query_timeout=1), object(), object())
    q = scheduler._dataconnect_queue

    # Both items are queued at essentially the same time, so aging has not
    # accrued and the lower static priority (dataconnect_performance) wins.
    q.put((5, 0, "dataconnect_posture", 21600, lambda: None))
    q.put((1, 1, "dataconnect_performance", 300, lambda: None))

    first = q.get()
    second = q.get()

    assert first[2] == "dataconnect_performance"
    assert second[2] == "dataconnect_posture"


def test_shutdown_sentinel_wins_over_a_heavily_aged_pending_item(monkeypatch):
    clock = [0.0]
    monkeypatch.setattr(scheduler_module.time, "time", lambda: clock[0])
    scheduler = PollScheduler(
        _cfg(collect_tacacs=False, dataconnect_query_timeout=1), object(), object())
    q = scheduler._dataconnect_queue

    # A low-priority item aged far past every other dataset's static priority
    # would normally win the aging race, but shutdown must still take
    # precedence and stop the worker promptly.
    q.put((8, 0, "endpoint_fleet", 900, lambda: None))
    clock[0] = 100000.0
    q.put((-1, 1, None, None, None))

    item = q.get()

    assert item[2] is None


def test_dataconnect_shutdown_stops_worker_promptly_with_items_pending():
    scheduler = PollScheduler(
        _cfg(collect_tacacs=False, dataconnect_query_timeout=1), object(), object())
    shutdown = threading.Event()
    started = threading.Event()
    release = threading.Event()
    scheduler._start_dataconnect_worker(shutdown)

    def current():
        with collectors.observe("dataconnect_radius_active"):
            started.set()
            assert release.wait(1)

    scheduler._run_dataconnect("dataconnect_radius_active", 1800, current)
    assert started.wait(1)
    # Queue additional work behind the running item before shutting down, so
    # the worker must skip past pending work to honor the sentinel promptly.
    scheduler._run_dataconnect(
        "dataconnect_freshness", 86400, lambda: None)
    scheduler._run_dataconnect(
        "endpoint_fleet", 900, lambda: None)
    shutdown.set()
    release.set()

    scheduler._stop_dataconnect_worker()

    assert not scheduler.dataconnect_worker_alive
    assert not scheduler._dataconnect_async


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


def test_mnt_worker_bookkeeping_exception_is_accounted_and_recoverable(
        monkeypatch, caplog):
    caplog.set_level("INFO", logger="ise_exporter.scheduler")
    scheduler = PollScheduler(
        _cfg(collect_tacacs=False, request_timeout=1),
        object(), object(), mnt=object())
    shutdown = threading.Event()
    original_run = scheduler._run
    scheduler._start_mnt_worker(shutdown)
    monkeypatch.setattr(
        scheduler, "_run",
        lambda *args, **kwargs: (_ for _ in ()).throw(
            RuntimeError("bookkeeping failed")),
    )

    scheduler._run_mnt("mnt_active_posture", 900, lambda: None)
    scheduler._mnt_worker.join(1)

    assert not scheduler._mnt_inflight
    assert collectors.failures("mnt_active_posture") == 1
    assert scheduler.next_run[
        "mnt_active_posture"] > scheduler_module.time.time()
    assert "MnT worker bookkeeping failed" in caplog.text
    assert "collection rescheduled dataset=mnt_active_posture" in caplog.text
    assert "retry_reason=worker_recovery" in caplog.text

    later_runs = []
    monkeypatch.setattr(scheduler, "_run", original_run)
    scheduler.next_run["mnt_active_posture"] = 0
    scheduler._run_mnt(
        "mnt_active_posture", 900, lambda: later_runs.append(True))
    scheduler._mnt_worker.join(1)
    assert later_runs == [True]
    shutdown.set()
    scheduler._stop_mnt_worker()


def test_shutdown_rejects_new_dataconnect_and_mnt_work():
    scheduler = PollScheduler(
        _cfg(collect_tacacs=False, dataconnect_query_timeout=1, request_timeout=1),
        object(), object(), mnt=object(),
    )
    shutdown = threading.Event()
    runs = []
    scheduler._start_dataconnect_worker(shutdown)
    scheduler._start_mnt_worker(shutdown)
    shutdown.set()

    scheduler._run_dataconnect(
        "dataconnect_radius_active", 7200, lambda: runs.append("dataconnect"))
    scheduler._run_mnt(
        "mnt_active_posture", 900, lambda: runs.append("mnt"))

    assert runs == []
    assert scheduler._dataconnect_queue.empty()
    assert not scheduler._dataconnect_inflight
    assert not scheduler._mnt_inflight
    assert scheduler._mnt_worker is None
    scheduler._stop_dataconnect_worker()
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
    assert scheduler._dataconnect_async
    assert scheduler._dataconnect_stopping


def test_timed_out_dataconnect_stop_rejects_work_and_second_worker(monkeypatch):
    scheduler = PollScheduler(
        _cfg(collect_tacacs=False, dataconnect_query_timeout=1), object(), object())

    class Worker:
        def join(self, timeout):
            pass

        def is_alive(self):
            return True

    scheduler._dataconnect_async = True
    scheduler._dataconnect_worker = Worker()
    scheduler._stop_dataconnect_worker()
    runs = []
    scheduler._run_dataconnect(
        "dataconnect_radius_active", 7200, lambda: runs.append(True))
    monkeypatch.setattr(
        scheduler_module.threading, "Thread",
        lambda *args, **kwargs: (_ for _ in ()).throw(
            AssertionError("must not start a second worker")),
    )
    scheduler._start_dataconnect_worker(threading.Event())

    assert runs == []
    assert scheduler._dataconnect_stopping


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
    assert scheduler._mnt_async
    assert scheduler._mnt_stopping


def test_timed_out_mnt_stop_rejects_sync_work_and_second_worker(monkeypatch):
    scheduler = PollScheduler(
        _cfg(collect_tacacs=False, request_timeout=1),
        object(), object(), mnt=object())

    class Worker:
        def join(self, timeout):
            pass

        def is_alive(self):
            return True

    scheduler._mnt_async = True
    scheduler._mnt_worker = Worker()
    scheduler._stop_mnt_worker()
    runs = []
    scheduler._run_mnt(
        "mnt_active_posture", 900, lambda: runs.append(True))
    monkeypatch.setattr(
        scheduler_module.threading, "Thread",
        lambda *args, **kwargs: (_ for _ in ()).throw(
            AssertionError("must not start a second MnT worker")),
    )
    scheduler._start_mnt_worker(threading.Event())

    assert runs == []
    assert scheduler._mnt_stopping


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


def test_failed_dataconnect_attempt_never_retries_faster_than_five_minutes(
        monkeypatch, caplog):
    caplog.set_level("INFO", logger="ise_exporter.scheduler")
    now = [105.0]
    monkeypatch.setattr(scheduler_module.time, "time", lambda: now[0])
    scheduler = PollScheduler(_cfg(), object(), object())
    scheduler.last_success["dataconnect_radius"] = 95.0
    attempts = []

    def fail():
        attempts.append(True)
        with collectors.observe("dataconnect_radius"):
            raise RuntimeError("database unavailable")

    scheduler._run("dataconnect_radius", 100.0, 60, fail)

    assert len(attempts) == 1
    assert "dataconnect_radius" not in scheduler.last_run
    assert scheduler.last_attempt["dataconnect_radius"] == 105.0
    assert scheduler.next_run["dataconnect_radius"] == 405.0
    assert collectors.outcome("dataconnect_radius") is False
    assert metrics.ise_dataset_up.labels(
        dataset="dataconnect_radius", source="dataconnect")._value.get() == 0
    assert "collection started dataset=dataconnect_radius" in caplog.text
    assert "outcome=failure" in caplog.text
    assert "reason=database_failed" in caplog.text
    assert "detail=database unavailable" in caplog.text
    assert "exception_type=RuntimeError" in caplog.text
    assert "previous_success_age_seconds=10.000" in caplog.text
    assert "snapshot_state=retained" in caplog.text
    assert "retry_in_seconds=300" in caplog.text
    assert "retry_reason=database_protection" in caplog.text
    assert "action=retry_scheduled" in caplog.text
    failures = [
        record for record in caplog.records
        if "collection completed dataset=dataconnect_radius" in record.getMessage()
        and "outcome=failure" in record.getMessage()
    ]
    assert failures and all(record.levelname == "WARNING" for record in failures)

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
    assert "collection started dataset=dataconnect_radius" in caplog.text
    assert "collection completed dataset=dataconnect_radius" in caplog.text
    assert "outcome=success" in caplog.text
    assert "published=true" in caplog.text
    assert "reason=scheduled_collection" in caplog.text


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
        dataset="dataconnect_radius", source="dataconnect")._value.get() == 1800
    assert metrics.ise_dataset_interval_seconds.labels(
        dataset="dataconnect_radius_active", source="dataconnect")._value.get() == 1800
    assert metrics.ise_dataset_enabled.labels(
        dataset="dataconnect_radius", source="dataconnect")._value.get() == 1
    assert {source for source, _interval, _enabled in scheduler.dataset_plan.values()} == {
        "rest", "dataconnect", "mnt"}

    scheduler.last_success["dataconnect_radius"] = 100.0
    scheduler._update_freshness(3699.0)
    assert metrics.ise_dataset_fresh.labels(
        dataset="dataconnect_radius", source="dataconnect")._value.get() == 1
    scheduler._update_freshness(3701.0)
    assert metrics.ise_dataset_fresh.labels(
        dataset="dataconnect_radius", source="dataconnect")._value.get() == 0


def test_plan_caps_direct_active_radius_interval_at_stale_window():
    scheduler = PollScheduler(_cfg(
        dataconnect_radius_active_interval=7200), object(), object())

    assert scheduler.dataset_plan["dataconnect_radius_active"][1] == 3600


def test_future_success_after_large_backward_clock_correction_is_not_fresh():
    scheduler = PollScheduler(_cfg(), object(), object())
    scheduler.last_success["dataconnect_radius"] = 3600.0

    scheduler._update_dataset_freshness("dataconnect_radius", 100.0)

    assert metrics.ise_dataset_fresh.labels(
        dataset="dataconnect_radius", source="dataconnect")._value.get() == 0


def test_fresh_dataconnect_snapshot_survives_restart_without_requery(
        monkeypatch, tmp_path, caplog):
    registry = CollectorRegistry()
    persisted = Gauge("restart_persisted", "test", ["key"], registry=registry)
    monkeypatch.setattr(
        scheduler_module, "_PERSISTED_DATACONNECT_METRICS",
        {"dataconnect_radius": (persisted,)},
    )
    clock = [400.0]
    monkeypatch.setattr(scheduler_module.time, "time", lambda: clock[0])
    caplog.set_level("INFO", logger="ise_exporter.scheduler")
    cfg = _cfg(state_db_path=str(tmp_path / "state.sqlite3"))
    first = PollScheduler(cfg, object(), object())

    def succeed():
        with collectors.observe("dataconnect_radius"):
            persisted.labels(key="restored").set(42)

    first._run("dataconnect_radius", 100.0, 1800, succeed)
    persisted._metrics.clear()
    clock[0] = 401.0
    restarted = PollScheduler(cfg, object(), object())

    samples = {(sample.labels["key"], sample.value)
               for sample in persisted.collect()[0].samples}
    assert samples == {("restored", 42)}
    assert restarted.last_success["dataconnect_radius"] == 400.0
    assert restarted.next_run["dataconnect_radius"] == 2200.0
    assert metrics.ise_dataset_up.labels(
        dataset="dataconnect_radius", source="dataconnect")._value.get() == 1
    assert metrics.ise_dataset_fresh.labels(
        dataset="dataconnect_radius", source="dataconnect")._value.get() == 1
    assert "collection restored dataset=dataconnect_radius" in caplog.text
    assert "snapshot_age_seconds=1" in caplog.text
    assert "reason=restart_persistent_snapshot" in caplog.text

    queried = []
    restarted._run("dataconnect_radius", 401.0, 300, lambda: queried.append(True))
    assert queried == []


def test_empty_psn_snapshot_is_requeried_immediately_after_restart(
        monkeypatch, tmp_path, caplog):
    registry = CollectorRegistry()
    persisted = Gauge(
        "empty_psn_persisted", "test", ["node"], registry=registry)
    monkeypatch.setattr(
        scheduler_module, "_PERSISTED_DATACONNECT_METRICS",
        {"dataconnect_performance": (persisted,)},
    )
    monkeypatch.setattr(
        metrics.ise_dataconnect_psn_radius_requests_per_hour,
        "_name", persisted._name,
    )
    monkeypatch.setattr(scheduler_module.time, "time", lambda: 401.0)
    cfg = _cfg(state_db_path=str(tmp_path / "state.sqlite3"))
    store = scheduler_module.StateStore(cfg.state_db_path)
    store.replace_dataset_snapshot(
        "dataconnect_performance", 400.0,
        scheduler_module.serialize_metric_snapshot((persisted,)))
    store.close()
    caplog.set_level("INFO", logger="ise_exporter.scheduler")

    restarted = PollScheduler(cfg, object(), object())

    assert "dataconnect_performance" not in restarted.last_success
    assert "ignoring empty PSN performance snapshot" in caplog.text


def test_restart_contract_keeps_radius_reporting_and_active_snapshots_disjoint():
    reporting = scheduler_module._PERSISTED_DATACONNECT_METRICS["dataconnect_radius"]
    active = scheduler_module._PERSISTED_DATACONNECT_METRICS[
        "dataconnect_radius_active"]

    assert set(reporting) == set(scheduler_module.dataconnect_radius._REPORTING_METRICS)
    assert set(active) == set(scheduler_module.dataconnect_radius._ACTIVE_METRICS)
    assert not set(reporting) & set(active)


@pytest.mark.parametrize(("stored_domains", "include_tacacs", "expected"), (
    (("radius_auth", "tacacs"), True, True),
    (("radius_auth",), False, True),
    (("radius_auth", "tacacs"), False, False),
    (("radius_auth",), True, False),
))
def test_freshness_snapshot_view_set_tracks_tacacs_configuration(
        stored_domains, include_tacacs, expected):
    payload = {
        "metrics": {
            metrics.ise_dataconnect_view_has_recent_rows._name: {
                "labelnames": ["view", "domain"],
                "samples": [
                    {"labels": [f"view_{index}", domain], "value": 1}
                    for index, domain in enumerate(stored_domains)
                ],
            },
        },
    }

    assert scheduler_module._freshness_snapshot_matches_config(
        payload, include_tacacs) is expected


def test_tacacs_setting_change_skips_freshness_restore(monkeypatch, tmp_path, caplog):
    registry = CollectorRegistry()
    persisted = Gauge("freshness_config_persisted", "test", registry=registry)
    monkeypatch.setattr(
        scheduler_module, "_PERSISTED_DATACONNECT_METRICS",
        {"dataconnect_freshness": (persisted,)},
    )
    monkeypatch.setattr(
        scheduler_module, "_freshness_snapshot_matches_config",
        lambda _payload, _include_tacacs: False,
    )
    monkeypatch.setattr(scheduler_module.time, "time", lambda: 401.0)
    cfg = _cfg(
        state_db_path=str(tmp_path / "state.sqlite3"), collect_tacacs=False)
    store = scheduler_module.StateStore(cfg.state_db_path)
    store.replace_dataset_snapshot(
        "dataconnect_freshness", 400.0,
        scheduler_module.serialize_metric_snapshot((persisted,)))
    store.close()
    caplog.set_level("INFO", logger="ise_exporter.scheduler")

    restarted = PollScheduler(cfg, object(), object())

    assert "dataconnect_freshness" not in restarted.last_success
    assert "setting changed; collecting immediately" in caplog.text


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

    first._run("dataconnect_radius", 100.0, 1800, succeed)
    persisted.set(0)
    clock[0] = 3701.0
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


def test_collector_source_labels_agree_with_the_dataset_plan():
    # observe() derives its metric source label from collectors.source(), while
    # the scheduler keys the same ise_dataset_* series from dataset_plan. A
    # mismatch splits one dataset across two label pairs, so the correct pair
    # never reports success (found live with endpoint_fleet enabled).
    scheduler = PollScheduler(
        _cfg(), client=object(), dataconnect=object(), mnt=object())
    for name, (plan_source, _interval, _enabled) in scheduler.dataset_plan.items():
        assert collectors.source(name) == plan_source, name


def test_next_run_metric_seeds_now_for_enabled_and_zero_for_disabled(monkeypatch):
    monkeypatch.setattr(scheduler_module.time, "time", lambda: 500.0)
    PollScheduler(_cfg(collect_certificates=False), object(), object())

    # A dataset with no prior attempt and no restored snapshot is due
    # immediately, so its nominal next run is published as "now".
    assert metrics.ise_dataset_next_run_timestamp.labels(
        dataset="dataconnect_radius", source="dataconnect")._value.get() == 500.0
    # A disabled dataset is never scheduled and reports zero rather than a
    # misleadingly overdue timestamp.
    assert metrics.ise_dataset_next_run_timestamp.labels(
        dataset="certificates", source="rest")._value.get() == 0


def test_next_run_metric_tracks_next_run_after_success(monkeypatch):
    monkeypatch.setattr(scheduler_module.time, "time", lambda: 400.0)
    scheduler = PollScheduler(_cfg(), object(), object())

    def succeed():
        with collectors.observe("dataconnect_radius"):
            pass

    scheduler._run("dataconnect_radius", 100.0, 60, succeed)

    assert scheduler.next_run["dataconnect_radius"] == 460.0
    assert metrics.ise_dataset_next_run_timestamp.labels(
        dataset="dataconnect_radius", source="dataconnect")._value.get() == 460.0


def test_next_run_metric_tracks_retry_after_failure(monkeypatch):
    monkeypatch.setattr(scheduler_module.time, "time", lambda: 105.0)
    scheduler = PollScheduler(_cfg(), object(), object())
    scheduler.last_success["dataconnect_radius"] = 95.0

    def fail():
        with collectors.observe("dataconnect_radius"):
            raise RuntimeError("database unavailable")

    scheduler._run("dataconnect_radius", 100.0, 60, fail)

    assert scheduler.next_run["dataconnect_radius"] == 405.0
    assert metrics.ise_dataset_next_run_timestamp.labels(
        dataset="dataconnect_radius", source="dataconnect")._value.get() == 405.0


def test_next_run_metric_survives_restart_from_a_persisted_snapshot(
        monkeypatch, tmp_path):
    registry = CollectorRegistry()
    persisted = Gauge("next_run_persisted", "test", ["key"], registry=registry)
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
            persisted.labels(key="restored").set(1)

    first._run("dataconnect_radius", 100.0, 1800, succeed)
    clock[0] = 401.0
    restarted = PollScheduler(cfg, object(), object())

    assert restarted.next_run["dataconnect_radius"] == 2200.0
    assert metrics.ise_dataset_next_run_timestamp.labels(
        dataset="dataconnect_radius", source="dataconnect")._value.get() == 2200.0


def test_next_run_metric_advances_after_worker_bookkeeping_exception(monkeypatch):
    scheduler = PollScheduler(
        _cfg(collect_tacacs=False, dataconnect_query_timeout=1), object(), object())
    shutdown = threading.Event()
    original_run = scheduler._run

    def fail_one_domain(name, now, tier, callback):
        if name == "dataconnect_radius_active":
            raise RuntimeError("bookkeeping failed")
        return original_run(name, now, tier, callback)

    monkeypatch.setattr(scheduler, "_run", fail_one_domain)
    scheduler._start_dataconnect_worker(shutdown)
    scheduler._run_dataconnect("dataconnect_radius_active", 7200, lambda: None)
    scheduler._dataconnect_queue.join()

    assert metrics.ise_dataset_next_run_timestamp.labels(
        dataset="dataconnect_radius_active",
        source="dataconnect")._value.get() == scheduler.next_run[
            "dataconnect_radius_active"]
    assert metrics.ise_dataset_next_run_timestamp.labels(
        dataset="dataconnect_radius_active",
        source="dataconnect")._value.get() > scheduler_module.time.time()
    shutdown.set()
    scheduler._stop_dataconnect_worker()
