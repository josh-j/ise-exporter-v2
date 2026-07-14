"""Immutable collection plan for the exporter runtime.

REST/OpenAPI owns platform and configuration state; Data Connect owns historical
monitoring/reporting datasets; MnT owns one bounded current-session posture
snapshot. There is no runtime source fallback and no collector reads another
collector's metrics to decide ownership.
"""
import logging
import math
import time

from . import collectors, metrics
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

logger = logging.getLogger(__name__)
MAX_CONSECUTIVE_FAILURES = 5


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
        self.dataset_plan = self._dataset_plan()
        self._initialize_dataset_state()
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
                "dataconnect", getattr(cfg, "dataconnect_radius_interval", 300), True),
            "dataconnect_performance": (
                "dataconnect", getattr(cfg, "dataconnect_performance_interval", 300), True),
            "dataconnect_posture": (
                "dataconnect", getattr(cfg, "dataconnect_posture_interval", 900), True),
            "dataconnect_endpoints": (
                "dataconnect", getattr(cfg, "dataconnect_endpoints_interval", 21600), True),
            "dataconnect_freshness": (
                "dataconnect", getattr(cfg, "dataconnect_freshness_interval", 3600), True),
            "dataconnect_nad_health": (
                "dataconnect", getattr(cfg, "dataconnect_nad_health_interval", 900), True),
            "mnt_active_posture": (
                "mnt", getattr(cfg, "mnt_active_posture_interval", cfg.medium_interval),
                getattr(cfg, "collect_mnt_active_posture", True)),
            # Explicitly observable removal: no client, callback, or metric family
            # exists, but operators can distinguish intentional disablement from
            # a missing collector registration.
            "pxgrid_streaming": ("pxgrid", cfg.slow_interval, False),
            "tacacs_config": ("rest", cfg.slow_interval, cfg.collect_tacacs),
            "tacacs_activity": (
                "dataconnect", getattr(cfg, "dataconnect_tacacs_interval", 900),
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

    def _update_freshness(self, now):
        for name, (source, interval, enabled) in self.dataset_plan.items():
            last_success = self.last_success.get(name)
            fresh = bool(enabled and last_success is not None
                         and now - last_success <= 2 * interval)
            metrics.ise_dataset_fresh.labels(dataset=name, source=source).set(int(fresh))

    def _due(self, name, now, tier):
        return now >= self.next_run.get(name, 0)

    def _run(self, name, now, tier, callback):
        if self._due(name, now, tier):
            source = self.dataset_plan[name][0]
            started = time.monotonic()
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
            elapsed = max(0.0, time.monotonic() - started)
            effective_interval = tier
            if source == "dataconnect":
                duty_cycle = max(1, min(10, getattr(
                    self.cfg, "dataconnect_max_duty_cycle_percent", 5)))
                load_interval = math.ceil(elapsed * 100 / duty_cycle)
                effective_interval = max(tier, load_interval)
                metrics.ise_dataconnect_load_backoff_seconds.labels(dataset=name).set(
                    effective_interval - tier)
            metrics.ise_dataset_effective_interval_seconds.labels(
                dataset=name, source=source).set(effective_interval)
            succeeded = collectors.outcome(name)
            # Test/extension callbacks that do not use observe() retain the historic
            # success behavior; production collectors always publish an outcome.
            if succeeded is not False:
                self.last_run[name] = completed
                self.last_success[name] = completed
                self.next_run[name] = completed + effective_interval
            else:
                if collectors.failures(name) >= MAX_CONSECUTIVE_FAILURES:
                    retry = max(self.cfg.slow_interval, effective_interval)
                elif source == "dataconnect":
                    # A failed reporting query can still consume substantial ISE
                    # database work. Never hammer it at the exporter loop cadence.
                    retry = max(300, effective_interval)
                else:
                    retry = min(tier, getattr(self.cfg, "scrape_interval", tier))
                self.next_run[name] = completed + retry

    def run_cycle(self):
        cfg, now = self.cfg, time.time()

        # REST/OpenAPI control plane: always authoritative in every profile.
        self._run("deployment", now, cfg.medium_interval,
                  lambda: deployment.collect(self.client, cfg))
        self._run("devices", now, cfg.medium_interval,
                  lambda: devices.collect(self.client, cfg))
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

        # Data Connect reporting plane. Each domain owns disjoint metric families.
        self._run("dataconnect_radius", now, self.dataset_plan["dataconnect_radius"][1],
                  lambda: dataconnect_radius.collect(self.dataconnect, cfg))
        self._run("dataconnect_performance", now,
                  self.dataset_plan["dataconnect_performance"][1],
                  lambda: dataconnect_performance.collect(self.dataconnect, cfg))
        self._run("dataconnect_posture", now, self.dataset_plan["dataconnect_posture"][1],
                  lambda: dataconnect_posture.collect(self.dataconnect, cfg))
        self._run("dataconnect_endpoints", now,
                  self.dataset_plan["dataconnect_endpoints"][1],
                  lambda: dataconnect_endpoints.collect(self.dataconnect, cfg))
        self._run("dataconnect_freshness", now,
                  self.dataset_plan["dataconnect_freshness"][1],
                  lambda: dataconnect_freshness.collect(self.dataconnect, cfg))
        self._run("dataconnect_nad_health", now,
                  self.dataset_plan["dataconnect_nad_health"][1],
                  lambda: nad_health.collect(self.client, self.dataconnect, cfg))

        # MnT owns only a bounded current active-endpoint posture snapshot. It
        # never writes or substitutes for Data Connect historical metrics.
        if getattr(cfg, "collect_mnt_active_posture", True):
            interval = getattr(cfg, "mnt_active_posture_interval", cfg.medium_interval)
            self._run("mnt_active_posture", now, interval,
                      lambda: mnt_active_posture.collect(self.mnt, cfg))

        # TACACS configuration is REST-owned; activity is Data Connect-owned in
        # standard mode. The collector exposes distinct metric families for each.
        if cfg.collect_tacacs:
            self._run("tacacs_config", now, cfg.slow_interval,
                      lambda: tacacs.collect_config(self.client, cfg))
            self._run("tacacs_activity", now, self.dataset_plan["tacacs_activity"][1],
                      lambda: tacacs.collect_activity(self.dataconnect, cfg))
        self._update_freshness(time.time())

    def loop(self, shutdown):
        nxt = time.time()
        while not shutdown.is_set():
            self.run_cycle()
            nxt = _next_deadline(nxt, time.time(), self.cfg.scrape_interval)
            while time.time() < nxt and not shutdown.is_set():
                time.sleep(max(0, min(nxt - time.time(), 1)))
