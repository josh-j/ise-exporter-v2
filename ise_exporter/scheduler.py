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
from .snapshots import restore_metric_snapshot, serialize_metric_snapshot
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
    deadline += interval
    if deadline <= now:
        deadline += ((now - deadline) // interval + 1) * interval
    return deadline


class PollScheduler:
    def __init__(self, cfg, client, dataconnect=None, mnt=None):
        self.cfg = cfg
        self.client = client
        self.dataconnect = dataconnect
        self.mnt = mnt
        self.last_run = {}
        self.last_attempt = {}
        self.next_run = {}
        self.last_success = {}
        self._dataconnect_async = False
        self._dataconnect_queue = queue.PriorityQueue()
        self._dataconnect_sequence = itertools.count()
        self._dataconnect_inflight = set()
        self._dataconnect_queued_at = {}
        self._dataconnect_busy = False
        self._dataconnect_lock = threading.RLock()
        self._dataconnect_worker = None
        self._mnt_async = False
        self._mnt_inflight = False
        self._mnt_lock = threading.RLock()
        self._mnt_worker = None
        self._shutdown = None
        self._nad_inventory = None
        self.dataset_plan = self._dataset_plan()
        self._initialize_dataset_state()
        self._publish_worker_state(time.time())
        self._restore_dataconnect_state()
        logger.info("collection plan: REST/OpenAPI=platform/config "
                    "DataConnect=historical-reporting MnT=bounded-active-posture")

    def _dataset_plan(self):
        cfg = self.cfg
        return {
            "deployment": ("rest", cfg.medium_interval, True),
            "devices": ("rest", cfg.medium_interval, True),
            "certificates": ("rest", cfg.slow_interval, cfg.collect_certificates),
            "licensing": ("rest", cfg.slow_interval, cfg.collect_licensing),
            "backup": ("rest", cfg.slow_interval, cfg.collect_backup_status),
            "patches": ("rest", cfg.slow_interval, cfg.collect_patches),
            "dataconnect_radius": (
                "dataconnect", getattr(cfg, "dataconnect_radius_interval", 86400), True),
            "dataconnect_radius_active": (
                "dataconnect", getattr(
                    cfg, "dataconnect_radius_active_interval", 1800), True),
            "dataconnect_performance": (
                "dataconnect", getattr(cfg, "dataconnect_performance_interval", 3600), True),
            "dataconnect_posture": (
                "dataconnect", getattr(cfg, "dataconnect_posture_interval", 21600), True),
            "dataconnect_endpoints": (
                "dataconnect", getattr(cfg, "dataconnect_endpoints_interval", 86400), True),
            "dataconnect_freshness": (
                "dataconnect", getattr(cfg, "dataconnect_freshness_interval", 86400), True),
            "dataconnect_nad_health": (
                "dataconnect", getattr(cfg, "dataconnect_nad_health_interval", 21600), True),
            "mnt_active_posture": (
                "mnt", getattr(cfg, "mnt_active_posture_interval", cfg.medium_interval),
                getattr(cfg, "collect_mnt_active_posture", True)),
            "tacacs_config": ("rest", cfg.slow_interval, cfg.collect_tacacs),
            "tacacs_activity": (
                "dataconnect", getattr(cfg, "dataconnect_tacacs_interval", 21600),
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
        scan_intervals = {
            "dataconnect_radius": getattr(
                self.cfg, "dataconnect_radius_interval", 86400),
            "dataconnect_performance": getattr(
                self.cfg, "dataconnect_performance_interval", 3600),
            "dataconnect_posture": getattr(
                self.cfg, "dataconnect_posture_interval", 21600),
            "dataconnect_endpoints": getattr(
                self.cfg, "dataconnect_endpoints_interval", 86400),
            "dataconnect_nad_health": getattr(
                self.cfg, "dataconnect_nad_health_interval", 21600),
            "tacacs_activity": getattr(
                self.cfg, "dataconnect_tacacs_interval", 21600),
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
                    restore_metric_snapshot(families, payload)
                except (TypeError, ValueError) as error:
                    logger.warning("ignoring incompatible %s snapshot: %s", name, error)
                    continue
                self.last_run[name] = updated_at
                self.last_success[name] = updated_at
                self.next_run[name] = updated_at + interval
                metrics.ise_dataset_up.labels(dataset=name, source=source).set(int(enabled))
                metrics.ise_dataset_last_success_timestamp.labels(
                    dataset=name, source=source).set(updated_at)
                metrics.ise_last_successful_scrape.labels(collector=name).set(updated_at)
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
        return now >= self.next_run.get(name, 0)

    def _run(self, name, now, tier, callback):
        if self._due(name, now, tier):
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
                if source == "dataconnect":
                    self._persist_dataconnect_state(name, completed)
                self._update_dataset_freshness(name, completed)
                if source == "dataconnect":
                    logger.info(
                        "Data Connect dataset %s collected successfully; next run in %ss",
                        name, effective_interval,
                    )
            else:
                if collectors.failures(name) >= MAX_CONSECUTIVE_FAILURES:
                    if source == "dataconnect":
                        retry = max(self.cfg.slow_interval, effective_interval)
                    else:
                        # REST and MnT already share the persistent authentication
                        # guard. Do not turn a five-failure streak on a fast health
                        # dataset into the global six-hour slow tier; recover on the
                        # dataset cadence once the account-safety backoff expires.
                        retry = max(
                            effective_interval,
                            getattr(self.cfg, "auth_failure_backoff", 900),
                        )
                elif source == "dataconnect":
                    # A failed reporting query can still consume substantial ISE
                    # database work. Never hammer it at the exporter loop cadence,
                    # but do not leave a daily dataset empty for 24 hours after one
                    # transient startup failure. The client-side adaptive duty-cycle
                    # gate remains authoritative when a slow query needs more rest.
                    retry = max(300, min(effective_interval, self.cfg.slow_interval))
                else:
                    retry = min(tier, getattr(self.cfg, "scrape_interval", tier))
                self.next_run[name] = completed + retry
                self._update_dataset_freshness(name, completed)

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
            if name in self._dataconnect_inflight or not self._due(name, now, tier):
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
                    self._run(name, time.time(), tier, callback)
                finally:
                    with self._dataconnect_lock:
                        self._dataconnect_busy = False
                        self._dataconnect_inflight.discard(name)
                        self._publish_worker_state()
            finally:
                self._dataconnect_queue.task_done()

    def _start_dataconnect_worker(self, shutdown):
        if self._dataconnect_async:
            return
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
        self._dataconnect_async = False
        self._dataconnect_queue.put((
            -1, next(self._dataconnect_sequence), None, None, None))
        if self._dataconnect_worker is not None:
            timeout = max(2, int(getattr(self.cfg, "dataconnect_query_timeout", 15)) + 2)
            self._dataconnect_worker.join(timeout=timeout)
            if self._dataconnect_worker.is_alive():
                logger.warning("Data Connect worker did not stop within %ss", timeout)
            else:
                with self._dataconnect_lock:
                    self._dataconnect_busy = False
                    self._dataconnect_inflight.clear()
                    self._dataconnect_queued_at.clear()
                    self._publish_worker_state()

    @property
    def dataconnect_worker_alive(self):
        worker = self._dataconnect_worker
        return worker is not None and worker.is_alive()

    def _run_mnt(self, name, tier, callback):
        """Keep the paced detail-refresh cycle off the REST scheduler lane."""
        if not self._mnt_async:
            self._run(name, time.time(), tier, callback)
            return
        with self._mnt_lock:
            if self._mnt_inflight or not self._due(name, time.time(), tier):
                return
            self._mnt_inflight = True
        self._publish_worker_state()

        def run():
            try:
                self._run(name, time.time(), tier, callback)
            finally:
                with self._mnt_lock:
                    self._mnt_inflight = False
                self._publish_worker_state()

        self._mnt_worker = threading.Thread(
            target=run, name="ise-mnt-worker", daemon=True)
        self._mnt_worker.start()

    def _start_mnt_worker(self, shutdown):
        self._mnt_async = True
        set_shutdown = getattr(self.mnt, "set_shutdown_event", None)
        if set_shutdown is not None:
            set_shutdown(shutdown)

    def _stop_mnt_worker(self):
        if not self._mnt_async:
            return
        self._mnt_async = False
        worker = self._mnt_worker
        if worker is not None:
            timeout = max(2, int(getattr(self.cfg, "request_timeout", 30)) + 2)
            worker.join(timeout=timeout)
            if worker.is_alive():
                logger.warning("MnT worker did not stop within %ss", timeout)

    def run_cycle(self):
        cfg, now = self.cfg, time.time()

        # REST/OpenAPI control plane: always authoritative in every profile.
        self._run("deployment", now, cfg.medium_interval,
                  lambda: deployment.collect(self.client, cfg))
        def collect_devices():
            # A failed current REST attempt invalidates the join input; retaining
            # an older list would make NAD health look authoritative while ERS is down.
            self._nad_inventory = devices.collect(self.client, cfg)

        self._run("devices", now, cfg.medium_interval, collect_devices)
        if cfg.collect_certificates:
            self._run("certificates", now, cfg.slow_interval,
                      lambda: certificates.collect(self.client, cfg))
        if cfg.collect_licensing:
            self._run("licensing", now, cfg.slow_interval,
                      lambda: licensing.collect(self.client, cfg))
        if cfg.collect_backup_status:
            self._run("backup", now, cfg.slow_interval,
                      lambda: backup.collect(self.client, cfg))
        if cfg.collect_patches:
            self._run("patches", now, cfg.slow_interval,
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
            interval = getattr(cfg, "mnt_active_posture_interval", cfg.medium_interval)
            self._run_mnt(
                "mnt_active_posture", interval,
                lambda: mnt_active_posture.collect(self.mnt, cfg))

        # TACACS configuration is REST-owned; activity is Data Connect-owned in
        # standard mode. The collector exposes distinct metric families for each.
        if cfg.collect_tacacs:
            self._run("tacacs_config", now, cfg.slow_interval,
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
                nxt = _next_deadline(nxt, time.time(), self.cfg.scrape_interval)
                while time.time() < nxt and not shutdown.is_set():
                    shutdown.wait(max(0, min(nxt - time.time(), 1)))
        finally:
            # Also signal cancellation when the loop exits because of an
            # unexpected scheduler exception. This interrupts database pacing
            # and prevents queued work from racing client teardown.
            shutdown.set()
            self._stop_dataconnect_worker()
            self._stop_mnt_worker()
