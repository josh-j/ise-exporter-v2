"""Immutable collection plan for the exporter runtime.

REST/OpenAPI owns platform and configuration state; Data Connect owns historical
monitoring/reporting datasets; MnT owns one bounded current-session posture
snapshot. There is no runtime source fallback and no collector reads another
collector's metrics to decide ownership.
"""
import itertools
import logging
import math
import queue
import threading
import time

from . import collectors, metrics
from .config import (
    DEFAULT_DATACONNECT_RADIUS_ACTIVE_INTERVAL,
    MAX_DATACONNECT_RADIUS_ACTIVE_INTERVAL,
)
from .state import StateStore
from .snapshots import (
    restore_metric_snapshot,
    serialize_metric_snapshot,
    snapshot_lock,
)
from .collectors import (
    backup,
    certificates,
    dataconnect_endpoints,
    dataconnect_freshness,
    dataconnect_performance,
    dataconnect_posture,
    dataconnect_radius,
    deployment,
    devices,
    endpoint_fleet,
    licensing,
    mnt_active_posture,
    nad_health,
    patches,
    tacacs,
)
from .collectors.dataconnect_common import event_window_hours, hourly_rollup_window_hours
from .dataconnect_schema import (
    DatasetSchemaFailure,
    inspect_dataconnect_schema,
)

logger = logging.getLogger(__name__)
MAX_CONSECUTIVE_FAILURES = 5
_DATACONNECT_SHUTDOWN_TIMEOUT = 17
_MNT_SHUTDOWN_TIMEOUT = 32
_WALL_CLOCK_SKEW_TOLERANCE = 300


def _minimum_interval(value, default, minimum):
    """Return a production-safe cadence for unchecked Config-like callers."""
    try:
        interval = int(value)
    except (TypeError, ValueError):
        interval = default
    return max(minimum, interval)


def _configured_interval(value, default):
    """Honor a valid positive operator cadence; Config already logs advisories."""
    try:
        interval = int(value)
    except (TypeError, ValueError):
        return default
    return interval if interval > 0 else default

# Lower values run first whenever more than one due domain is waiting. This does
# not add query concurrency or preempt an atomic collector; it prevents slow
# inventory/freshness work from keeping current operational health behind a cold-
# start backlog under a deliberately low Data Connect duty-cycle ceiling.
_DATACONNECT_PRIORITY = {
    "dataconnect_schema": -1,
    "dataconnect_radius_active": 0,
    "dataconnect_accounting_counters": 1,
    "dataconnect_posture_counters": 1,
    "dataconnect_authentication_counters": 1,
    "dataconnect_error_counters": 1,
    "dataconnect_performance": 1,
    "dataconnect_nad_health": 2,
    "dataconnect_radius": 3,
    "tacacs_activity": 4,
    "dataconnect_posture": 5,
    "dataconnect_endpoints": 6,
    "dataconnect_freshness": 7,
    "endpoint_fleet": 8,
}

# Static priority alone starves the low-priority datasets: the adaptive Data
# Connect cooldown (duration * (100/duty - 1), x999 at the default 0.1% duty)
# can make lane service time exceed the re-arrival period of the operational
# P0/P1 datasets, so a lower-priority item can find a higher-priority item
# waiting at *every* dequeue and never run. One priority level of aging per 15
# minutes of queue wait guarantees every queued dataset eventually crosses
# every static priority band ahead of it and runs, no matter how busy the lane is.
_DATACONNECT_PRIORITY_AGING_SECONDS = 900


class _AgingDataConnectQueue:
    """queue.Queue-compatible lane queue with wait-time priority aging.

    Selection at get() time uses effective_priority = static_priority -
    (now - queued_at) / _DATACONNECT_PRIORITY_AGING_SECONDS; the pending item
    with the lowest effective priority is returned. Ties break deterministically
    on (static_priority, queued_at, sequence) so behavior stays reproducible in
    tests. The shutdown sentinel (name is None) always wins immediately,
    regardless of aging, so shutdown is never delayed behind starved work.

    The public surface (put/get/get_nowait/task_done/join/empty/
    unfinished_tasks) intentionally mirrors queue.Queue/queue.PriorityQueue so
    the rest of the scheduler -- and existing tests -- can keep treating
    _dataconnect_queue as a drop-in queue.
    """

    def __init__(self):
        self._lock = threading.Lock()
        self._not_empty = threading.Condition(self._lock)
        self._items = []
        self.unfinished_tasks = 0

    def put(self, item):
        priority, sequence, name, tier, callback = item
        with self._not_empty:
            self._items.append(
                (priority, sequence, name, tier, callback, time.time()))
            self.unfinished_tasks += 1
            self._not_empty.notify_all()

    def get(self):
        with self._not_empty:
            while not self._items:
                self._not_empty.wait()
            return self._pop_best_locked()

    def get_nowait(self):
        with self._lock:
            if not self._items:
                raise queue.Empty
            return self._pop_best_locked()

    def _pop_best_locked(self):
        now = time.time()
        best_index = 0
        best_key = None
        for index, entry in enumerate(self._items):
            priority, sequence, name, _tier, _callback, queued_at = entry
            if name is None:
                # The shutdown sentinel takes precedence over any pending work,
                # aged or not, so shutdown is never delayed behind a backlog.
                best_index = index
                break
            effective_priority = (
                priority - (now - queued_at) / _DATACONNECT_PRIORITY_AGING_SECONDS)
            key = (effective_priority, priority, queued_at, sequence)
            if best_key is None or key < best_key:
                best_key = key
                best_index = index
        priority, sequence, name, tier, callback, _queued_at = (
            self._items.pop(best_index))
        return (priority, sequence, name, tier, callback)

    def task_done(self):
        with self._not_empty:
            self.unfinished_tasks = max(0, self.unfinished_tasks - 1)
            if self.unfinished_tasks == 0:
                self._not_empty.notify_all()

    def join(self):
        with self._not_empty:
            while self.unfinished_tasks > 0:
                self._not_empty.wait()

    def empty(self):
        with self._lock:
            return not self._items


_PERSISTED_DATACONNECT_METRICS = {
    "dataconnect_radius": dataconnect_radius._REPORTING_METRICS,
    "dataconnect_radius_active": dataconnect_radius._ACTIVE_METRICS,
    "dataconnect_performance": dataconnect_performance._METRICS,
    "dataconnect_posture": dataconnect_posture._METRICS,
    "dataconnect_endpoints": dataconnect_endpoints._METRICS,
    "dataconnect_freshness": dataconnect_freshness._METRICS,
    "dataconnect_nad_health": nad_health._METRICS,
    "tacacs_activity": tacacs._ACTIVITY_METRICS,
    "endpoint_fleet": endpoint_fleet._METRICS,
}


def _freshness_snapshot_matches_config(payload, include_tacacs):
    """Reject a fresh-but-wrong view set after a TACACS config change."""
    try:
        item = payload["metrics"][metrics.ise_dataconnect_view_has_recent_rows._name]
        domain_index = item["labelnames"].index("domain")
        domains = {
            sample["labels"][domain_index]
            for sample in item["samples"]
        }
    except (AttributeError, KeyError, TypeError, ValueError, IndexError):
        # The normal snapshot validator will report malformed/old payloads with
        # its more precise compatibility error.
        return True
    return ("tacacs" in domains) == bool(include_tacacs)


def _performance_snapshot_has_node_samples(payload):
    """Return false only for a valid PSN snapshot with no node rollups."""
    try:
        item = payload["metrics"][
            metrics.ise_dataconnect_psn_radius_requests_per_hour._name]
        samples = item["samples"]
    except (AttributeError, KeyError, TypeError):
        # Let the normal snapshot validator report malformed or old payloads.
        return True
    return not isinstance(samples, list) or bool(samples)


def _next_deadline(deadline, now, interval):
    """Advance to the first future cadence boundary, skipping missed ticks."""
    interval = max(1, interval)
    # Epoch time is required for persisted/reportable timestamps, but it can move
    # backwards after NTP or an administrator correction. A prior cadence boundary
    # that is now more than one interval plus ordinary skew into the future would
    # otherwise suspend the scheduler until wall time catches up.
    if deadline > now + _WALL_CLOCK_SKEW_TOLERANCE:
        return now + interval
    deadline += interval
    if deadline <= now:
        deadline += ((now - deadline) // interval + 1) * interval
    return deadline


class PollScheduler:
    def __init__(self, cfg, client, dataconnect=None, mnt=None):
        self.cfg = cfg
        self.scrape_interval = _configured_interval(
            getattr(cfg, "scrape_interval", 60), 60)
        self.medium_interval = _configured_interval(
            getattr(cfg, "medium_interval", 300), 300)
        self.slow_interval = _configured_interval(
            getattr(cfg, "slow_interval", 21600), 21600)
        self.auth_failure_backoff = _minimum_interval(
            getattr(cfg, "auth_failure_backoff", 900), 900, 300)
        try:
            startup_spacing = int(getattr(cfg, "startup_rate_limit_seconds", 0))
        except (TypeError, ValueError):
            startup_spacing = 5
        self.startup_rate_limit_seconds = max(0, startup_spacing)
        self._startup_lock = threading.Lock()
        self._startup_started = set()
        self._startup_next_at = 0.0
        self.client = client
        self.dataconnect = dataconnect
        self.mnt = mnt
        self.last_run = {}
        self.last_attempt = {}
        self.next_run = {}
        self._scheduled_delay = {}
        self.last_success = {}
        self._dataconnect_async = False
        self._dataconnect_queue = _AgingDataConnectQueue()
        self._dataconnect_sequence = itertools.count()
        self._dataconnect_inflight = set()
        self._dataconnect_queued_at = {}
        self._dataconnect_busy = False
        self._dataconnect_stopping = False
        self._dataconnect_lock = threading.RLock()
        self._dataconnect_worker = None
        self._mnt_async = False
        self._mnt_inflight = False
        self._mnt_stopping = False
        self._mnt_lock = threading.RLock()
        self._mnt_worker = None
        self._shutdown = None
        self._nad_inventory = None
        self._devices_async = False
        self._devices_inflight = False
        self._devices_lock = threading.RLock()
        self._devices_worker = None
        self._schema_managed = hasattr(dataconnect, "schema_ready")
        self._dataconnect_schema_ready = bool(getattr(
            dataconnect, "schema_ready", True))
        self._dataconnect_schema_failures = dict(getattr(
            dataconnect, "dataset_schema_failures", {}) or {})
        self.dataset_plan = self._dataset_plan()
        if self._schema_managed and not self._dataconnect_schema_ready:
            pending = DatasetSchemaFailure(
                reason="schema_validation_pending",
                detail="Data Connect schema discovery has not completed successfully",
            )
            self._dataconnect_schema_failures = {
                name: pending
                for name, (source, _interval, enabled) in self.dataset_plan.items()
                if source == "dataconnect" and name != "dataconnect_schema" and enabled
            }
        self._schema_metric_reasons = {}
        self._schema_metric_details = {}
        self._initialize_dataset_state()
        self._publish_worker_state(time.time())
        self._restore_dataconnect_state()
        self._log_startup_schedule()
        logger.info("collection plan: REST/OpenAPI=platform/config "
                    "DataConnect=historical-reporting MnT=bounded-active-posture")

    def _log_startup_schedule(self):
        """Journal every cadence and its true due time at process start."""
        now = time.time()
        logger.info(
            "startup schedule: dataset_count=%d startup_rate_limit_seconds=%s; "
            "cold-start attempts are globally spaced after becoming due",
            sum(enabled for _source, _interval, enabled in self.dataset_plan.values()),
            self.startup_rate_limit_seconds,
        )
        for name, (source, interval, enabled) in self.dataset_plan.items():
            if not enabled:
                logger.info(
                    "scheduled dataset=%s source=%s enabled=false interval_seconds=%s",
                    name, source, interval,
                )
                continue
            schema_failure = self._dataconnect_schema_failures.get(name)
            if schema_failure is not None:
                reason = getattr(schema_failure, "reason", "schema_incompatible")
                log = (logger.info if reason == "schema_validation_pending"
                       else logger.warning)
                log(
                    "scheduled dataset=%s source=%s enabled=true interval_seconds=%s "
                    "blocked=true reason=%s detail=%s",
                    name,
                    source,
                    interval,
                    reason,
                    getattr(schema_failure, "detail", "schema incompatible"),
                )
                continue
            restored_due = self.next_run.get(name)
            if restored_due is None:
                due_at = now
                reason = "cold_start"
            else:
                due_at = restored_due
                reason = "restored_snapshot"
            logger.info(
                "scheduled dataset=%s source=%s enabled=true interval_seconds=%s "
                "due_at=%s due_in_seconds=%.0f reason=%s",
                name,
                source,
                interval,
                time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime(due_at)),
                max(0.0, due_at - now),
                reason,
            )

    def _dataset_plan(self):
        cfg = self.cfg
        return {
            "deployment": ("rest", self.medium_interval, True),
            # NAD configuration and group membership are low-volatility. Keep the
            # complete ERS enumeration and bounded detail convergence off the
            # medium deployment-health cadence.
            "devices": ("rest", self.slow_interval, True),
            "certificates": ("rest", self.slow_interval, cfg.collect_certificates),
            "licensing": ("rest", self.slow_interval, cfg.collect_licensing),
            "backup": ("rest", self.slow_interval, cfg.collect_backup_status),
            "patches": ("rest", self.slow_interval, cfg.collect_patches),
            "dataconnect_radius": (
                "dataconnect", _configured_interval(
                    getattr(cfg, "dataconnect_radius_interval", 1800), 1800), True),
            "dataconnect_schema": (
                "dataconnect", _configured_interval(getattr(
                    cfg, "dataconnect_schema_interval", 86400), 86400),
                self._schema_managed),
            "dataconnect_radius_active": (
                "dataconnect", min(
                    MAX_DATACONNECT_RADIUS_ACTIVE_INTERVAL,
                    _configured_interval(getattr(
                        cfg, "dataconnect_radius_active_interval",
                        DEFAULT_DATACONNECT_RADIUS_ACTIVE_INTERVAL),
                        DEFAULT_DATACONNECT_RADIUS_ACTIVE_INTERVAL)), True),
            "dataconnect_performance": (
                "dataconnect", _configured_interval(getattr(
                    cfg, "dataconnect_performance_interval", 300), 300), True),
            "dataconnect_accounting_counters": (
                "dataconnect", _configured_interval(getattr(
                    cfg, "dataconnect_accounting_counters_interval", 300), 300),
                bool(getattr(cfg, "dataconnect_accounting_event_counters", False))),
            "dataconnect_posture_counters": (
                "dataconnect", _configured_interval(getattr(
                    cfg, "dataconnect_posture_counters_interval", 300), 300),
                bool(getattr(cfg, "dataconnect_posture_event_counters", False))),
            "dataconnect_authentication_counters": (
                "dataconnect", _configured_interval(getattr(
                    cfg, "dataconnect_authentication_counters_interval", 300), 300),
                bool(getattr(cfg, "dataconnect_authentication_event_counters", False))),
            "dataconnect_error_counters": (
                "dataconnect", _configured_interval(getattr(
                    cfg, "dataconnect_error_counters_interval", 300), 300),
                bool(getattr(cfg, "dataconnect_error_event_counters", False))),
            "dataconnect_posture": (
                "dataconnect", _configured_interval(getattr(
                    cfg, "dataconnect_posture_interval", 21600), 21600), True),
            "dataconnect_endpoints": (
                "dataconnect", _configured_interval(getattr(
                    cfg, "dataconnect_endpoints_interval", 21600), 21600), True),
            "dataconnect_freshness": (
                "dataconnect", _configured_interval(getattr(
                    cfg, "dataconnect_freshness_interval", 86400), 86400), True),
            "endpoint_fleet": (
                "dataconnect", _configured_interval(getattr(
                    cfg, "endpoint_fleet_interval", 900), 900),
                bool(getattr(cfg, "endpoint_fleet_enabled", False))),
            "dataconnect_nad_health": (
                "dataconnect", _configured_interval(getattr(
                    cfg, "dataconnect_nad_health_interval", 21600), 21600), True),
            "mnt_active_posture": (
                "mnt", _configured_interval(getattr(
                    cfg, "mnt_active_posture_interval", self.medium_interval), 300),
                getattr(cfg, "collect_mnt_active_posture", True)),
            "tacacs_config": ("rest", self.slow_interval, cfg.collect_tacacs),
            "tacacs_activity": (
                "dataconnect", _configured_interval(getattr(
                    cfg, "dataconnect_tacacs_interval", 21600), 21600),
                cfg.collect_tacacs),
        }

    def _initialize_dataset_state(self):
        for name, (source, interval, enabled) in self.dataset_plan.items():
            metrics.ise_dataset_enabled.labels(dataset=name, source=source).set(int(enabled))
            metrics.ise_dataset_interval_seconds.labels(
                dataset=name, source=source).set(interval)
            metrics.ise_dataset_effective_interval_seconds.labels(
                dataset=name, source=source).set(interval)
            metrics.ise_dataset_up.labels(dataset=name, source=source).set(0)
            metrics.ise_dataset_fresh.labels(dataset=name, source=source).set(0)
            metrics.ise_collector_enabled.labels(collector=name).set(int(enabled))
        for name, failure in self._dataconnect_schema_failures.items():
            if name not in self.dataset_plan or not self.dataset_plan[name][2]:
                continue
            reason = str(getattr(failure, "reason", "schema_incompatible"))
            metrics.ise_dataset_last_failure_info.labels(
                dataset=name, source="dataconnect", reason=reason).set(1)
            detail = collectors.failure_detail(reason, getattr(failure, "detail", None))
            metrics.ise_dataset_last_failure_detail_info.labels(
                dataset=name, source="dataconnect", reason=reason,
                detail=detail).set(1)
            self._schema_metric_reasons[name] = reason
            self._schema_metric_details[name] = detail
        # The scan window may intentionally be shorter than the protected run
        # cadence, so report the collector's configured sampling window rather
        # than implying that a full cadence interval is queried.
        scan_intervals = {
            "dataconnect_radius": getattr(
                self.cfg, "dataconnect_radius_interval", 1800),
            "dataconnect_performance": getattr(
                self.cfg, "dataconnect_performance_interval", 300),
            "dataconnect_posture": getattr(
                self.cfg, "dataconnect_posture_interval", 21600),
            "dataconnect_endpoints": getattr(
                self.cfg, "dataconnect_endpoints_interval", 21600),
            "dataconnect_nad_health": getattr(
                self.cfg, "dataconnect_nad_health_interval", 21600),
            "tacacs_activity": getattr(
                self.cfg, "dataconnect_tacacs_interval", 21600),
        }
        for dataset, interval in scan_intervals.items():
            window_hours = (hourly_rollup_window_hours(self.cfg, interval)
                            if dataset == "dataconnect_performance"
                            else event_window_hours(self.cfg, interval))
            metrics.ise_dataconnect_scan_window_hours.labels(dataset=dataset).set(
                window_hours)

    def _update_freshness(self, now):
        for name, (source, interval, enabled) in self.dataset_plan.items():
            self._update_dataset_freshness(name, now)

    def _update_dataset_freshness(self, name, now):
        """Publish freshness without waiting for the rest of a cycle to finish."""
        source, interval, enabled = self.dataset_plan[name]
        last_success = self.last_success.get(name)
        fresh = bool(enabled and last_success is not None
                     and last_success <= now + _WALL_CLOCK_SKEW_TOLERANCE
                     and now - last_success <= 2 * interval)
        metrics.ise_dataset_fresh.labels(dataset=name, source=source).set(int(fresh))

    def _state_store(self):
        return StateStore(getattr(self.cfg, "state_db_path", ":memory:"))

    def _restore_dataconnect_state(self):
        now = time.time()
        try:
            store = self._state_store()
        except Exception as error:
            logger.warning("could not open restart-persistent dataset state: %s", error)
            return
        try:
            for name, families in _PERSISTED_DATACONNECT_METRICS.items():
                source, interval, enabled = self.dataset_plan[name]
                if not enabled or name in self._dataconnect_schema_failures:
                    continue
                snapshot = store.dataset_snapshot(name)
                if snapshot is None:
                    continue
                updated_at, payload = snapshot
                if not math.isfinite(updated_at) or updated_at <= 0 or updated_at > now + 300:
                    logger.warning("ignoring invalid %s snapshot timestamp", name)
                    continue
                if now - updated_at > 2 * interval:
                    logger.info("ignoring stale %s snapshot; collecting immediately", name)
                    continue
                if (name == "dataconnect_freshness"
                        and not _freshness_snapshot_matches_config(
                            payload, getattr(self.cfg, "collect_tacacs", True))):
                    logger.info(
                        "ignoring Data Connect freshness snapshot after TACACS "
                        "collection setting changed; collecting immediately")
                    continue
                if (name == "dataconnect_performance"
                        and not _performance_snapshot_has_node_samples(payload)):
                    logger.info(
                        "ignoring empty PSN performance snapshot; collecting immediately")
                    continue
                try:
                    with snapshot_lock:
                        restore_metric_snapshot(families, payload)
                        metrics.ise_dataset_up.labels(
                            dataset=name, source=source).set(int(enabled))
                        metrics.ise_dataset_last_success_timestamp.labels(
                            dataset=name, source=source).set(updated_at)
                        metrics.ise_last_successful_scrape.labels(
                            collector=name).set(updated_at)
                        metrics.ise_dataset_fresh.labels(
                            dataset=name, source=source).set(1)
                except (TypeError, ValueError) as error:
                    logger.warning("ignoring incompatible %s snapshot: %s", name, error)
                    continue
                self.last_run[name] = updated_at
                self.last_success[name] = updated_at
                self.next_run[name] = updated_at + interval
                self._scheduled_delay[name] = interval
                self._update_dataset_freshness(name, now)
                logger.info(
                    "collection restored dataset=%s source=dataconnect "
                    "snapshot_age_seconds=%.0f published=true next_due_at=%s "
                    "next_in_seconds=%.0f reason=restart_persistent_snapshot",
                    name,
                    max(0, now - updated_at),
                    time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime(
                        self.next_run[name])),
                    max(0, self.next_run[name] - now),
                )
        except Exception as error:
            logger.warning("could not read restart-persistent dataset state: %s", error)
        finally:
            try:
                store.close()
            except Exception as error:
                logger.warning("could not close restart-persistent dataset state: %s", error)

    def _persist_dataconnect_state(self, name, completed):
        families = _PERSISTED_DATACONNECT_METRICS.get(name)
        if families is None:
            return
        try:
            payload = serialize_metric_snapshot(families)
            store = self._state_store()
            try:
                store.replace_dataset_snapshot(name, completed, payload)
            finally:
                store.close()
        except Exception as error:
            # Collection remains successful. Persistence is a load optimization;
            # a later restart safely falls back to querying the source again.
            logger.warning("could not persist %s snapshot: %s", name, error)

    def _due(self, name, now, tier):
        next_run = self.next_run.get(name, 0)
        scheduled_delay = self._scheduled_delay.get(name, tier)
        # Attempts schedule from completion using their effective success/retry
        # delay. If that deadline is now implausibly farther away than the delay
        # that created it, wall time moved backwards; collect once now and let
        # completion establish a corrected deadline.
        return (now >= next_run
                or next_run > now + max(1, scheduled_delay)
                + _WALL_CLOCK_SKEW_TOLERANCE)

    def _failure_retry(self, name, source, effective_interval):
        if collectors.failures(name) >= MAX_CONSECUTIVE_FAILURES:
            if source == "dataconnect":
                return max(self.slow_interval, effective_interval)
            # REST and MnT share the persistent authentication guard. Recover on
            # the dataset cadence after the account-safety backoff, not the global
            # six-hour slow tier.
            return max(effective_interval, self.auth_failure_backoff)
        if name == "dataconnect_schema":
            return max(300, min(effective_interval, 3600))
        if source == "dataconnect":
            # Failed reporting work can still consume substantial database time.
            return max(300, min(effective_interval, self.slow_interval))
        return min(effective_interval, self.scrape_interval)

    def _recover_worker_exception(self, name, tier, source, worker_name):
        """Keep an asynchronous lane alive after scheduler bookkeeping fails."""
        logger.exception("%s worker bookkeeping failed for %s", worker_name, name)
        completed = time.time()
        previous_success = self.last_success.get(name)
        success_age = (
            "never" if previous_success is None else
            f"{max(0.0, completed - previous_success):.3f}")
        try:
            collectors.record_failure(
                name,
                "worker_exception",
                f"{worker_name} worker bookkeeping failed",
                exception_type="SchedulerWorkerError",
            )
        except Exception:
            logger.exception(
                "could not publish %s worker failure for %s", worker_name, name)
        retry = self._failure_retry(name, source, tier)
        self.next_run[name] = completed + retry
        self._scheduled_delay[name] = retry
        logger.warning(
            "collection rescheduled dataset=%s source=%s outcome=failure "
            "published=false reason=worker_exception "
            "detail=%s exception_type=SchedulerWorkerError "
            "previous_success_age_seconds=%s snapshot_state=%s "
            "consecutive_failures=%d retry_at=%s retry_in_seconds=%s "
            "retry_reason=worker_recovery action=retry_scheduled",
            name,
            source,
            collectors.failure_detail(
                "worker_exception", f"{worker_name} worker bookkeeping failed"),
            success_age,
            "retained" if previous_success is not None else "none_available",
            collectors.failures(name),
            time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime(
                self.next_run[name])),
            retry,
        )
        try:
            self._update_dataset_freshness(name, completed)
        except Exception:
            logger.exception(
                "could not publish %s freshness after worker failure", name)

    def _run(self, name, now, tier, callback):
        if self._due(name, now, tier):
            if not self._wait_for_startup_slot(name):
                return
            source = self.dataset_plan[name][0]
            attempted_at = time.time()
            started = time.monotonic()
            previous_failures = collectors.failures(name)
            previous_success = self.last_success.get(name)
            success_age = ("never" if previous_success is None else
                           f"{max(0.0, attempted_at - previous_success):.3f}")
            logger.info(
                "collection started dataset=%s source=%s trigger=scheduled_due "
                "interval_seconds=%s previous_success_age_seconds=%s "
                "consecutive_failures=%d",
                name, source, tier, success_age, previous_failures,
            )
            collectors.begin_attempt(name)
            self.last_attempt[name] = attempted_at
            metrics.ise_dataset_last_attempt_timestamp.labels(
                dataset=name, source=source).set(attempted_at)
            try:
                callback()
            except Exception as error:
                logger.exception(
                    "collection callback escaped dataset=%s source=%s",
                    name,
                    source,
                )
                collectors.record_failure(
                    name,
                    "unhandled_exception",
                    str(error),
                    exception_type=type(error).__name__,
                )
            completed = time.time()
            duration = max(0.0, time.monotonic() - started)
            effective_interval = tier
            metrics.ise_dataset_effective_interval_seconds.labels(
                dataset=name, source=source).set(effective_interval)
            succeeded = collectors.outcome(name)
            # Test/extension callbacks that do not use observe() retain the historic
            # success behavior; production collectors always publish an outcome.
            if succeeded is not False:
                self.last_run[name] = completed
                self.last_success[name] = completed
                self.next_run[name] = completed + effective_interval
                self._scheduled_delay[name] = effective_interval
                if source == "dataconnect":
                    self._persist_dataconnect_state(name, completed)
                self._update_dataset_freshness(name, completed)
                outcome_reason = ("recovered" if previous_failures else
                                  "scheduled_collection")
                logger.info(
                    "collection completed dataset=%s source=%s outcome=success "
                    "duration_seconds=%.3f published=true next_due_at=%s "
                    "next_in_seconds=%s reason=%s",
                    name,
                    source,
                    duration,
                    time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime(
                        self.next_run[name])),
                    effective_interval,
                    outcome_reason,
                )
            else:
                retry = self._failure_retry(name, source, effective_interval)
                self.next_run[name] = completed + retry
                self._scheduled_delay[name] = retry
                self._update_dataset_freshness(name, completed)
                failure_context = collectors.last_failure_context(name)
                failure_reason = failure_context["reason"]
                failure_detail = failure_context["detail"]
                exception_type = failure_context["exception_type"]
                failures = collectors.failures(name)
                if failures >= MAX_CONSECUTIVE_FAILURES:
                    retry_reason = "consecutive_failure_slowdown"
                elif name == "dataconnect_schema":
                    retry_reason = "schema_discovery_retry"
                elif source == "dataconnect":
                    retry_reason = "database_protection"
                else:
                    retry_reason = "bounded_fast_retry"
                snapshot_state = (
                    "retained" if previous_success is not None else "none_available")
                logger.warning(
                    "collection completed dataset=%s source=%s outcome=failure "
                    "duration_seconds=%.3f published=false reason=%s detail=%s "
                    "exception_type=%s previous_success_age_seconds=%s "
                    "snapshot_state=%s consecutive_failures=%d retry_at=%s "
                    "retry_in_seconds=%s retry_reason=%s action=retry_scheduled",
                    name,
                    source,
                    duration,
                    failure_reason or "unknown_failure",
                    failure_detail or "No bounded failure detail was published",
                    exception_type or "not_available",
                    success_age,
                    snapshot_state,
                    failures,
                    time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime(
                        self.next_run[name])),
                    retry,
                    retry_reason,
                )

    def _wait_for_startup_slot(self, name):
        """Space each dataset's first attempt without changing later cadence.

        The reservation is shared by the REST, Data Connect, and MnT lanes, so
        parallel workers cannot create a restart-time request burst. Waiting is
        interruptible once the service loop has installed its shutdown event.
        """
        spacing = self.startup_rate_limit_seconds
        if spacing <= 0 or name in self._startup_started:
            return True
        with self._startup_lock:
            if name in self._startup_started:
                return True
            now = time.monotonic()
            starts_at = max(now, self._startup_next_at)
            self._startup_next_at = starts_at + spacing
            self._startup_started.add(name)
        delay = max(0.0, starts_at - time.monotonic())
        logger.info(
            "startup attempt dataset=%s reserved_not_before=%s wait_seconds=%.3f",
            name,
            time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime(time.time() + delay)),
            delay,
        )
        if delay <= 0:
            return True
        if self._shutdown is None:
            time.sleep(delay)
            return True
        return not self._shutdown.wait(delay)

    def _run_dataconnect(self, name, tier, callback):
        """Run synchronously in tests, or enqueue onto the single DB lane.

        Data Connect's adaptive duty-cycle cooldown can be much longer than the
        exporter loop interval on a large MnT. Keeping that wait off the primary
        scheduler lane prevents database protection from freezing REST and MnT
        collection, while the one-worker queue still guarantees that reporting
        statements never execute concurrently.
        """
        if self._dataconnect_dataset_enqueue_blocked(name):
            return
        if not self._dataconnect_async:
            self._run(name, time.time(), tier, callback)
            return
        with self._dataconnect_lock:
            now = time.time()
            if (self._dataconnect_stopping
                    or self._shutdown is not None and self._shutdown.is_set()
                    or name in self._dataconnect_inflight
                    or not self._due(name, now, tier)):
                return
            self._dataconnect_inflight.add(name)
            self._dataconnect_queued_at[name] = now
            self._dataconnect_queue.put((
                _DATACONNECT_PRIORITY.get(name, 100),
                next(self._dataconnect_sequence), name, tier, callback,
            ))
            self._publish_worker_state(now)
            logger.info(
                "collection queued dataset=%s source=dataconnect lane=serialized "
                "priority=%d queue_depth=%d reason=scheduled_due",
                name,
                _DATACONNECT_PRIORITY.get(name, 100),
                len(self._dataconnect_queued_at),
            )

    def _dataconnect_dataset_enqueue_blocked(self, name):
        """Allow cold-start work to queue behind in-flight schema discovery.

        Synchronous callers must still prove the schema before executing a
        reporting callback. In the production asynchronous lane, however, the
        schema job is the highest-priority serialized item. Queuing compatible-
        unknown work behind it avoids losing the whole first scheduler cycle
        while preserving the worker's authoritative post-discovery check.
        """
        if name == "dataconnect_schema":
            return False
        if self._dataconnect_schema_ready:
            return name in self._dataconnect_schema_failures
        with self._dataconnect_lock:
            return not (
                self._dataconnect_async
                and "dataconnect_schema" in self._dataconnect_inflight
            )

    def _dataconnect_dataset_blocked(self, name):
        return (name != "dataconnect_schema"
                and (not self._dataconnect_schema_ready
                     or name in self._dataconnect_schema_failures))

    def _apply_dataconnect_schema(self, schema, failures):
        """Atomically publish schema capability and unblock compatible domains."""
        failures = dict(failures or {})
        was_ready = self._dataconnect_schema_ready
        failure_logs = []
        with snapshot_lock:
            self.dataconnect.set_schema(schema, failures)
            for name, old_reason in tuple(self._schema_metric_reasons.items()):
                metrics.ise_dataset_last_failure_info.remove(
                    name, "dataconnect", old_reason)
                old_detail = self._schema_metric_details.get(name)
                if old_detail:
                    metrics.ise_dataset_last_failure_detail_info.remove(
                        name, "dataconnect", old_reason, old_detail)
            self._schema_metric_reasons.clear()
            self._schema_metric_details.clear()
            self._dataconnect_schema_failures = failures
            self._dataconnect_schema_ready = True
            for name, failure in failures.items():
                if name not in self.dataset_plan or not self.dataset_plan[name][2]:
                    continue
                reason = str(getattr(failure, "reason", "schema_incompatible"))
                metrics.ise_dataset_up.labels(
                    dataset=name, source="dataconnect").set(0)
                metrics.ise_dataset_fresh.labels(
                    dataset=name, source="dataconnect").set(0)
                metrics.ise_dataset_last_failure_info.labels(
                    dataset=name, source="dataconnect", reason=reason).set(1)
                detail = collectors.failure_detail(
                    reason, getattr(failure, "detail", None))
                metrics.ise_dataset_last_failure_detail_info.labels(
                    dataset=name, source="dataconnect", reason=reason,
                    detail=detail).set(1)
                self._schema_metric_reasons[name] = reason
                self._schema_metric_details[name] = detail
                failure_logs.append((
                    name, getattr(failure, "detail", "schema incompatible")))
        for name, detail in failure_logs:
            failure = failures[name]
            logger.warning(
                "collection blocked dataset=%s source=dataconnect "
                "reason=%s detail=%s query_started=false "
                "action=fix_schema_or_wait_for_revalidation",
                name,
                getattr(failure, "reason", "schema_incompatible"),
                collectors.failure_detail("schema_incompatible", detail),
            )
        return not was_ready

    def _collect_dataconnect_schema(self):
        restore_after_success = False
        with collectors.observe("dataconnect_schema"):
            schema, failures = inspect_dataconnect_schema(
                self.dataconnect,
                include_tacacs=getattr(self.cfg, "collect_tacacs", True),
            )
            restore_after_success = self._apply_dataconnect_schema(schema, failures)
            logger.info(
                "discovered %d Data Connect reporting views; incompatible_datasets=%d",
                len(schema), len(failures),
            )
        if (restore_after_success
                and collectors.outcome("dataconnect_schema") is True):
            # Startup snapshots are held back until the live schema proves each
            # dataset compatible. Restore them outside the schema collector's
            # transaction so a large set cannot become one oversized commit.
            self._restore_dataconnect_state()

    def _publish_worker_state(self, now=None):
        now = time.time() if now is None else now
        with self._dataconnect_lock:
            queued_at = tuple(self._dataconnect_queued_at.values())
            metrics.ise_dataconnect_worker_busy.set(int(self._dataconnect_busy))
            metrics.ise_dataconnect_queue_depth.set(len(queued_at))
            metrics.ise_dataconnect_oldest_queued_seconds.set(
                max(0.0, now - min(queued_at)) if queued_at else 0)
        with self._mnt_lock:
            metrics.ise_mnt_worker_busy.set(int(self._mnt_inflight))

    def _dataconnect_worker_loop(self):
        while True:
            item = self._dataconnect_queue.get()
            try:
                _priority, _sequence, name, tier, callback = item
                if name is None:
                    return
                with self._dataconnect_lock:
                    self._dataconnect_queued_at.pop(name, None)
                    if self._shutdown is not None and self._shutdown.is_set():
                        self._dataconnect_inflight.discard(name)
                        self._publish_worker_state()
                        return
                    # Schema revalidation has higher queue priority, but reporting
                    # callbacks can already be queued from the prior schema state.
                    # Recheck after dequeue so a newly incompatible dataset never
                    # executes one stale-contract statement.
                    if self._dataconnect_dataset_blocked(name):
                        failure = self._dataconnect_schema_failures.get(name)
                        logger.warning(
                            "collection discarded dataset=%s source=dataconnect "
                            "reason=%s detail=%s query_started=false "
                            "action=wait_for_compatible_schema",
                            name,
                            getattr(failure, "reason", "schema_incompatible"),
                            collectors.failure_detail(
                                "schema_incompatible",
                                getattr(failure, "detail", None)),
                        )
                        self._dataconnect_inflight.discard(name)
                        self._publish_worker_state()
                        continue
                    self._dataconnect_busy = True
                    self._publish_worker_state()
                try:
                    try:
                        self._run(name, time.time(), tier, callback)
                    except Exception:
                        # Collector callbacks are already contained by _run(). An
                        # exception here is scheduler/metrics infrastructure. Do
                        # not silently lose the sole serialized database worker
                        # and strand every later reporting domain in its queue.
                        self._recover_worker_exception(
                            name, tier, "dataconnect", "Data Connect")
                finally:
                    with self._dataconnect_lock:
                        self._dataconnect_busy = False
                        self._dataconnect_inflight.discard(name)
                        self._publish_worker_state()
            finally:
                self._dataconnect_queue.task_done()

    def _start_dataconnect_worker(self, shutdown):
        if self._dataconnect_async and self.dataconnect_worker_alive:
            return
        # A prior bounded stop may have timed out and then completed later. Only
        # after the old thread is confirmed dead may this scheduler own a new
        # serialized database lane.
        if self._dataconnect_stopping:
            self._discard_dataconnect_pending()
            self._dataconnect_async = False
            self._dataconnect_stopping = False
        self._shutdown = shutdown
        set_shutdown = getattr(self.dataconnect, "set_shutdown_event", None)
        if set_shutdown is not None:
            set_shutdown(shutdown)
        self._dataconnect_async = True
        self._dataconnect_worker = threading.Thread(
            target=self._dataconnect_worker_loop,
            name="ise-dataconnect-worker",
            daemon=True,
        )
        self._dataconnect_worker.start()

    def _stop_dataconnect_worker(self):
        if not self._dataconnect_async:
            return
        self._dataconnect_stopping = True
        self._dataconnect_queue.put((
            -1, next(self._dataconnect_sequence), None, None, None))
        if self._dataconnect_worker is not None:
            # The client hard-caps an individual query at 15 seconds. Keep the
            # scheduler boundary equally strict for unchecked Config-like callers.
            try:
                configured = int(getattr(self.cfg, "dataconnect_query_timeout", 15))
            except (TypeError, ValueError):
                configured = 15
            timeout = max(2, min(_DATACONNECT_SHUTDOWN_TIMEOUT, configured + 2))
            self._dataconnect_worker.join(timeout=timeout)
            if self._dataconnect_worker.is_alive():
                logger.warning("Data Connect worker did not stop within %ss", timeout)
            else:
                self._dataconnect_async = False
                self._dataconnect_stopping = False
                self._discard_dataconnect_pending()

    def _discard_dataconnect_pending(self):
        """Clear callbacks abandoned behind the priority shutdown sentinel."""
        while True:
            try:
                self._dataconnect_queue.get_nowait()
            except queue.Empty:
                break
            else:
                self._dataconnect_queue.task_done()
        with self._dataconnect_lock:
            self._dataconnect_busy = False
            self._dataconnect_inflight.clear()
            self._dataconnect_queued_at.clear()
            self._publish_worker_state()

    @property
    def dataconnect_worker_alive(self):
        worker = self._dataconnect_worker
        return worker is not None and worker.is_alive()

    @property
    def mnt_worker_alive(self):
        worker = self._mnt_worker
        return worker is not None and worker.is_alive()

    def _run_mnt(self, name, tier, callback):
        """Keep the paced detail-refresh cycle off the REST scheduler lane."""
        with self._mnt_lock:
            if self._mnt_stopping:
                return
            asynchronous = self._mnt_async
            if asynchronous:
                if (self._shutdown is not None and self._shutdown.is_set()
                        or self._mnt_inflight
                        or not self._due(name, time.time(), tier)):
                    return
                self._mnt_inflight = True
        if not asynchronous:
            self._run(name, time.time(), tier, callback)
            return
        self._publish_worker_state()

        def run():
            try:
                try:
                    self._run(name, time.time(), tier, callback)
                except Exception:
                    self._recover_worker_exception(name, tier, "mnt", "MnT")
            finally:
                with self._mnt_lock:
                    self._mnt_inflight = False
                self._publish_worker_state()

        self._mnt_worker = threading.Thread(
            target=run, name="ise-mnt-worker", daemon=True)
        self._mnt_worker.start()

    def _start_mnt_worker(self, shutdown):
        with self._mnt_lock:
            if self._mnt_stopping and self.mnt_worker_alive:
                return
            if self._mnt_stopping:
                self._mnt_stopping = False
                self._mnt_async = False
            if self._mnt_async:
                return
            self._shutdown = shutdown
            self._mnt_async = True
        set_shutdown = getattr(self.mnt, "set_shutdown_event", None)
        if set_shutdown is not None:
            set_shutdown(shutdown)

    def _stop_mnt_worker(self):
        with self._mnt_lock:
            if not self._mnt_async:
                return
            self._mnt_stopping = True
            worker = self._mnt_worker
        if worker is None:
            with self._mnt_lock:
                self._mnt_async = False
                self._mnt_stopping = False
            return
        if worker is not None:
            # MnT uses the REST transport's 30-second ceiling. Never let an
            # unchecked config turn service shutdown into an unbounded wait.
            try:
                configured = int(getattr(self.cfg, "request_timeout", 30))
            except (TypeError, ValueError):
                configured = 30
            timeout = max(2, min(_MNT_SHUTDOWN_TIMEOUT, configured + 2))
            worker.join(timeout=timeout)
            if worker.is_alive():
                logger.warning("MnT worker did not stop within %ss", timeout)
            else:
                with self._mnt_lock:
                    self._mnt_async = False
                    self._mnt_stopping = False

    def _run_devices(self, now):
        """Run the ERS device collector off the synchronous REST lane.

        The per-NAD detail refresh can be a long paced ERS walk on a large
        inventory. Running it on its own daemon thread keeps it from blocking
        certificates, licensing, backup, and patches behind it. It stays
        synchronous (deterministic) until loop() activates the worker.
        """
        name = "devices"
        tier = self.dataset_plan[name][1]

        def collect_devices():
            # A failed current REST attempt invalidates the join input; retaining
            # an older list would make NAD health look authoritative while ERS is down.
            self._nad_inventory = devices.collect(self.client, self.cfg)

        with self._devices_lock:
            asynchronous = self._devices_async
            if asynchronous:
                if (self._shutdown is not None and self._shutdown.is_set()
                        or self._devices_inflight
                        or not self._due(name, now, tier)):
                    return
                self._devices_inflight = True
        if not asynchronous:
            self._run(name, now, tier, collect_devices)
            return

        def run():
            try:
                self._run(name, time.time(), tier, collect_devices)
            except Exception:
                logger.exception("devices worker crashed")
            finally:
                with self._devices_lock:
                    self._devices_inflight = False

        self._devices_worker = threading.Thread(
            target=run, name="ise-devices-worker", daemon=True)
        self._devices_worker.start()

    def _start_devices_worker(self, shutdown):
        with self._devices_lock:
            self._shutdown = shutdown
            self._devices_async = True

    def _stop_devices_worker(self):
        with self._devices_lock:
            worker = self._devices_worker
            self._devices_async = False
        if worker is None:
            return
        try:
            configured = int(getattr(self.cfg, "request_timeout", 30))
        except (TypeError, ValueError):
            configured = 30
        worker.join(timeout=max(2, configured + 2))

    def run_cycle(self):
        cfg, now = self.cfg, time.time()

        # Establish basic exporter and schema health first. The schema worker is
        # asynchronous in production, so current operational datasets can queue
        # behind it while the slower REST inventory lane continues independently.
        self._run("deployment", now, self.dataset_plan["deployment"][1],
                  lambda: deployment.collect(self.client, cfg))

        if self._schema_managed:
            self._run_dataconnect(
                "dataconnect_schema", self.dataset_plan["dataconnect_schema"][1],
                self._collect_dataconnect_schema)

        self._run_dataconnect(
            "dataconnect_radius_active",
            self.dataset_plan["dataconnect_radius_active"][1],
            lambda: dataconnect_radius.collect_active(self.dataconnect, cfg))
        self._run_dataconnect(
            "dataconnect_performance",
            self.dataset_plan["dataconnect_performance"][1],
            lambda: dataconnect_performance.collect(self.dataconnect, cfg))

        # Opt-in incremental accounting-event counters. Operational cadence, but
        # dark unless enabled; it tails only new rows so Prometheus owns the windowing.
        if getattr(cfg, "dataconnect_accounting_event_counters", False):
            self._run_dataconnect(
                "dataconnect_accounting_counters",
                self.dataset_plan["dataconnect_accounting_counters"][1],
                lambda: dataconnect_radius.collect_accounting_counters(
                    self.dataconnect, cfg))

        # Opt-in incremental posture-assessment counters. Same id-tail engine as
        # the accounting counters: only new rows are read and Prometheus owns the
        # windowing. Dark unless enabled.
        if getattr(cfg, "dataconnect_posture_event_counters", False):
            self._run_dataconnect(
                "dataconnect_posture_counters",
                self.dataset_plan["dataconnect_posture_counters"][1],
                lambda: dataconnect_posture.collect_posture_counters(
                    self.dataconnect, cfg))

        # Opt-in incremental authentication pass/fail counters. Same id-tail engine
        # against RADIUS_AUTHENTICATIONS; dark unless enabled.
        if getattr(cfg, "dataconnect_authentication_event_counters", False):
            self._run_dataconnect(
                "dataconnect_authentication_counters",
                self.dataset_plan["dataconnect_authentication_counters"][1],
                lambda: dataconnect_radius.collect_authentication_counters(
                    self.dataconnect, cfg))

        # Opt-in incremental RADIUS error counters. Same id-tail engine against
        # RADIUS_ERRORS_VIEW; dark unless enabled.
        if getattr(cfg, "dataconnect_error_event_counters", False):
            self._run_dataconnect(
                "dataconnect_error_counters",
                self.dataset_plan["dataconnect_error_counters"][1],
                lambda: dataconnect_radius.collect_error_counters(
                    self.dataconnect, cfg))

        # MnT owns only a bounded current active-endpoint posture snapshot. Run
        # it before cold-start inventory so the overview becomes useful early.
        if getattr(cfg, "collect_mnt_active_posture", True):
            interval = self.dataset_plan["mnt_active_posture"][1]
            self._run_mnt(
                "mnt_active_posture", interval,
                lambda: mnt_active_posture.collect(self.mnt, cfg))

        # REST/OpenAPI control plane: always authoritative in every profile. The
        # ERS device collector runs on its own lane so a long per-NAD detail walk
        # never blocks the certificates/licensing/backup/patches collectors below.
        self._run_devices(now)
        if cfg.collect_certificates:
            self._run("certificates", now, self.dataset_plan["certificates"][1],
                      lambda: certificates.collect(self.client, cfg))
        if cfg.collect_licensing:
            self._run("licensing", now, self.dataset_plan["licensing"][1],
                      lambda: licensing.collect(self.client, cfg))
        if cfg.collect_backup_status:
            self._run("backup", now, self.dataset_plan["backup"][1],
                      lambda: backup.collect(self.client, cfg))
        if cfg.collect_patches:
            self._run("patches", now, self.dataset_plan["patches"][1],
                      lambda: patches.collect(self.client, cfg))

        # Exact historical reporting and current active-session reconstruction
        # have disjoint metric families and independent production-safe cadences.
        # Current operational datasets were queued above; the DB worker remains
        # strictly serialized and leaves the slower historical backlog behind them.
        self._run_dataconnect(
            "dataconnect_nad_health",
            self.dataset_plan["dataconnect_nad_health"][1],
            lambda: nad_health.collect(self._nad_inventory, self.dataconnect, cfg))
        self._run_dataconnect(
            "dataconnect_radius", self.dataset_plan["dataconnect_radius"][1],
            lambda: dataconnect_radius.collect_reporting(self.dataconnect, cfg))
        self._run_dataconnect(
            "dataconnect_posture", self.dataset_plan["dataconnect_posture"][1],
            lambda: dataconnect_posture.collect(self.dataconnect, cfg))
        self._run_dataconnect(
            "dataconnect_endpoints", self.dataset_plan["dataconnect_endpoints"][1],
            lambda: dataconnect_endpoints.collect(self.dataconnect, cfg))
        self._run_dataconnect(
            "dataconnect_freshness", self.dataset_plan["dataconnect_freshness"][1],
            lambda: dataconnect_freshness.collect(self.dataconnect, cfg))

        # Opt-in accumulated fleet posture runs last so its steady paging never
        # delays current operational datasets; it is dark unless enabled.
        if getattr(cfg, "endpoint_fleet_enabled", False):
            self._run_dataconnect(
                "endpoint_fleet", self.dataset_plan["endpoint_fleet"][1],
                lambda: endpoint_fleet.collect(self.dataconnect, cfg))

        # TACACS configuration is REST-owned; activity is Data Connect-owned in
        # standard mode. The collector exposes distinct metric families for each.
        if cfg.collect_tacacs:
            self._run("tacacs_config", now, self.dataset_plan["tacacs_config"][1],
                      lambda: tacacs.collect_config(self.client, cfg))
            self._run_dataconnect(
                "tacacs_activity", self.dataset_plan["tacacs_activity"][1],
                lambda: tacacs.collect_activity(self.dataconnect, cfg))
        self._publish_worker_state()
        self._update_freshness(time.time())

    def loop(self, shutdown):
        self._start_dataconnect_worker(shutdown)
        self._start_mnt_worker(shutdown)
        self._start_devices_worker(shutdown)
        try:
            nxt = time.time()
            while not shutdown.is_set():
                self.run_cycle()
                nxt = _next_deadline(nxt, time.time(), self.scrape_interval)
                while time.time() < nxt and not shutdown.is_set():
                    shutdown.wait(max(0, min(nxt - time.time(), 1)))
        finally:
            # Also signal cancellation when the loop exits because of an
            # unexpected scheduler exception. This interrupts database pacing
            # and prevents queued work from racing client teardown.
            shutdown.set()
            self._stop_dataconnect_worker()
            self._stop_mnt_worker()
            self._stop_devices_worker()
