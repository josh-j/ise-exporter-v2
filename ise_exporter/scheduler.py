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
    licensing,
    mnt_active_posture,
    nad_health,
    patches,
    tacacs,
)
from .collectors.dataconnect_common import event_window_hours

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
# not add query concurrency or preempt an atomic collector; it prevents daily
# inventory/freshness work from keeping current operational health behind a cold-
# start backlog under a deliberately low Data Connect duty-cycle ceiling.
_DATACONNECT_PRIORITY = {
    "dataconnect_radius_active": 0,
    "dataconnect_performance": 1,
    "dataconnect_nad_health": 2,
    "dataconnect_radius": 3,
    "tacacs_activity": 4,
    "dataconnect_posture": 5,
    "dataconnect_endpoints": 6,
    "dataconnect_freshness": 7,
}

_PERSISTED_DATACONNECT_METRICS = {
    "dataconnect_radius": dataconnect_radius._REPORTING_METRICS,
    "dataconnect_radius_active": dataconnect_radius._ACTIVE_METRICS,
    "dataconnect_performance": dataconnect_performance._METRICS,
    "dataconnect_posture": dataconnect_posture._METRICS,
    "dataconnect_endpoints": dataconnect_endpoints._METRICS,
    "dataconnect_freshness": dataconnect_freshness._METRICS,
    "dataconnect_nad_health": nad_health._METRICS,
    "tacacs_activity": tacacs._ACTIVITY_METRICS,
}


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
            getattr(cfg, "scrape_interval", 120), 120)
        self.medium_interval = _configured_interval(
            getattr(cfg, "medium_interval", 300), 300)
        self.slow_interval = _configured_interval(
            getattr(cfg, "slow_interval", 3600), 3600)
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
        self._dataconnect_queue = queue.PriorityQueue()
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
        self.dataset_plan = self._dataset_plan()
        self._initialize_dataset_state()
        self._publish_worker_state(time.time())
        self._restore_dataconnect_state()
        self._log_startup_schedule()
        logger.info("collection plan: REST/OpenAPI=platform/config "
                    "DataConnect=historical-reporting MnT=bounded-active-posture")

    def _log_startup_schedule(self):
        """Journal every enabled cadence and its earliest post-start attempt."""
        now = time.time()
        cold_slot = 0
        logger.info(
            "startup schedule: dataset_count=%d startup_rate_limit_seconds=%s",
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
            restored_due = self.next_run.get(name)
            if restored_due is None:
                not_before = now + cold_slot * self.startup_rate_limit_seconds
                cold_slot += 1
                reason = "cold_start"
            else:
                not_before = restored_due
                reason = "restored_snapshot"
            logger.info(
                "scheduled dataset=%s source=%s enabled=true interval_seconds=%s "
                "first_attempt_not_before=%s first_attempt_in_seconds=%.0f reason=%s",
                name,
                source,
                interval,
                time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime(not_before)),
                max(0.0, not_before - now),
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
                    getattr(cfg, "dataconnect_radius_interval", 86400), 86400), True),
            "dataconnect_radius_active": (
                "dataconnect", _configured_interval(getattr(
                    cfg, "dataconnect_radius_active_interval", 7200), 7200), True),
            "dataconnect_performance": (
                "dataconnect", _configured_interval(getattr(
                    cfg, "dataconnect_performance_interval", 21600), 21600), True),
            "dataconnect_posture": (
                "dataconnect", _configured_interval(getattr(
                    cfg, "dataconnect_posture_interval", 86400), 86400), True),
            "dataconnect_endpoints": (
                "dataconnect", _configured_interval(getattr(
                    cfg, "dataconnect_endpoints_interval", 86400), 86400), True),
            "dataconnect_freshness": (
                "dataconnect", _configured_interval(getattr(
                    cfg, "dataconnect_freshness_interval", 86400), 86400), True),
            "dataconnect_nad_health": (
                "dataconnect", _configured_interval(getattr(
                    cfg, "dataconnect_nad_health_interval", 86400), 86400), True),
            "mnt_active_posture": (
                "mnt", _configured_interval(getattr(
                    cfg, "mnt_active_posture_interval", self.medium_interval), 900),
                getattr(cfg, "collect_mnt_active_posture", True)),
            "tacacs_config": ("rest", self.slow_interval, cfg.collect_tacacs),
            "tacacs_activity": (
                "dataconnect", _configured_interval(getattr(
                    cfg, "dataconnect_tacacs_interval", 86400), 86400),
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
        # The scan window may intentionally be shorter than the protected run
        # cadence, so report the collector's configured sampling window rather
        # than implying that a full cadence interval is queried.
        scan_intervals = {
            "dataconnect_radius": getattr(
                self.cfg, "dataconnect_radius_interval", 86400),
            "dataconnect_performance": getattr(
                self.cfg, "dataconnect_performance_interval", 21600),
            "dataconnect_posture": getattr(
                self.cfg, "dataconnect_posture_interval", 86400),
            "dataconnect_endpoints": getattr(
                self.cfg, "dataconnect_endpoints_interval", 86400),
            "dataconnect_nad_health": getattr(
                self.cfg, "dataconnect_nad_health_interval", 86400),
            "tacacs_activity": getattr(
                self.cfg, "dataconnect_tacacs_interval", 86400),
        }
        for dataset, interval in scan_intervals.items():
            metrics.ise_dataconnect_scan_window_hours.labels(dataset=dataset).set(
                event_window_hours(self.cfg, interval))

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
                if not enabled:
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
                    "restored Data Connect dataset %s; next run in %.0fs",
                    name, max(0, self.next_run[name] - now),
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
        if source == "dataconnect":
            # Failed reporting work can still consume substantial database time.
            return max(300, min(effective_interval, self.slow_interval))
        return min(effective_interval, self.scrape_interval)

    def _recover_worker_exception(self, name, tier, source, worker_name):
        """Keep an asynchronous lane alive after scheduler bookkeeping fails."""
        logger.exception("%s worker bookkeeping failed for %s", worker_name, name)
        completed = time.time()
        try:
            collectors.record_failure(name, "worker_exception")
        except Exception:
            logger.exception(
                "could not publish %s worker failure for %s", worker_name, name)
        retry = self._failure_retry(name, source, tier)
        self.next_run[name] = completed + retry
        self._scheduled_delay[name] = retry
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
            collectors.begin_attempt(name)
            self.last_attempt[name] = now
            metrics.ise_dataset_last_attempt_timestamp.labels(
                dataset=name, source=source).set(now)
            try:
                callback()
            except Exception:
                logger.exception("%s callback escaped collector observation", name)
                collectors.record_failure(name, "unhandled_exception")
            completed = time.time()
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
                if source == "dataconnect":
                    logger.info(
                        "Data Connect dataset %s collected successfully; next run in %ss",
                        name, effective_interval,
                    )
            else:
                retry = self._failure_retry(name, source, effective_interval)
                self.next_run[name] = completed + retry
                self._scheduled_delay[name] = retry
                self._update_dataset_freshness(name, completed)

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

    def run_cycle(self):
        cfg, now = self.cfg, time.time()

        # REST/OpenAPI control plane: always authoritative in every profile.
        self._run("deployment", now, self.dataset_plan["deployment"][1],
                  lambda: deployment.collect(self.client, cfg))
        def collect_devices():
            # A failed current REST attempt invalidates the join input; retaining
            # an older list would make NAD health look authoritative while ERS is down.
            self._nad_inventory = devices.collect(self.client, cfg)

        self._run("devices", now, self.dataset_plan["devices"][1], collect_devices)
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
        # Queue the smallest/current operational datasets before slower historical
        # reports after a cold start. The DB worker remains strictly serialized.
        self._run_dataconnect(
            "dataconnect_radius_active",
            self.dataset_plan["dataconnect_radius_active"][1],
            lambda: dataconnect_radius.collect_active(self.dataconnect, cfg))
        self._run_dataconnect(
            "dataconnect_performance",
            self.dataset_plan["dataconnect_performance"][1],
            lambda: dataconnect_performance.collect(self.dataconnect, cfg))
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

        # MnT owns only a bounded current active-endpoint posture snapshot. It
        # never writes or substitutes for Data Connect historical metrics.
        if getattr(cfg, "collect_mnt_active_posture", True):
            interval = self.dataset_plan["mnt_active_posture"][1]
            self._run_mnt(
                "mnt_active_posture", interval,
                lambda: mnt_active_posture.collect(self.mnt, cfg))

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
