"""Immutable collection plan for the exporter runtime.

REST/OpenAPI owns platform and configuration state; Data Connect owns
monitoring/reporting datasets. There is no runtime source fallback and no
collector reads another collector's metrics to decide ownership.
"""
import logging
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
    def __init__(self, cfg, client, dataconnect=None):
        self.cfg = cfg
        self.client = client
        self.dataconnect = dataconnect
        self.last_run = {}
        self.last_attempt = {}
        self.next_run = {}
        self.last_success = {}
        self.dataset_plan = self._dataset_plan()
        self._initialize_dataset_state()
        logger.info("collection plan: REST/OpenAPI=platform/config DataConnect=reporting")

    def _dataset_plan(self):
        cfg = self.cfg
        return {
            "deployment": ("rest", cfg.medium_interval, True),
            "devices": ("rest", cfg.medium_interval, True),
            "certificates": ("rest", cfg.slow_interval, cfg.collect_certificates),
            "licensing": ("rest", cfg.slow_interval, cfg.collect_licensing),
            "backup": ("rest", cfg.slow_interval, cfg.collect_backup_status),
            "patches": ("rest", cfg.slow_interval, cfg.collect_patches),
            "dataconnect_radius": ("dataconnect", cfg.fast_interval, True),
            "dataconnect_performance": ("dataconnect", cfg.fast_interval, True),
            "dataconnect_posture": ("dataconnect", cfg.medium_interval, True),
            "dataconnect_endpoints": ("dataconnect", cfg.slow_interval, True),
            "dataconnect_freshness": ("dataconnect", cfg.medium_interval, True),
            "dataconnect_nad_health": ("dataconnect", cfg.medium_interval, True),
            # Explicitly observable removal: no client, callback, or metric family
            # exists, but operators can distinguish intentional disablement from
            # a missing collector registration.
            "pxgrid_streaming": ("pxgrid", cfg.slow_interval, False),
            "tacacs_config": ("rest", cfg.slow_interval, cfg.collect_tacacs),
            "tacacs_activity": ("dataconnect", cfg.medium_interval, cfg.collect_tacacs),
        }

    def _initialize_dataset_state(self):
        for name, (source, interval, enabled) in self.dataset_plan.items():
            metrics.ise_dataset_enabled.labels(dataset=name, source=source).set(int(enabled))
            metrics.ise_dataset_interval_seconds.labels(
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
            succeeded = collectors.outcome(name)
            # Test/extension callbacks that do not use observe() retain the historic
            # success behavior; production collectors always publish an outcome.
            if succeeded is not False:
                self.last_run[name] = completed
                self.last_success[name] = completed
                self.next_run[name] = completed + tier
            else:
                if collectors.failures(name) >= MAX_CONSECUTIVE_FAILURES:
                    retry = self.cfg.slow_interval
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
        self._run("dataconnect_radius", now, cfg.fast_interval,
                  lambda: dataconnect_radius.collect(self.dataconnect, cfg))
        self._run("dataconnect_performance", now, cfg.fast_interval,
                  lambda: dataconnect_performance.collect(self.dataconnect, cfg))
        self._run("dataconnect_posture", now, cfg.medium_interval,
                  lambda: dataconnect_posture.collect(self.dataconnect, cfg))
        self._run("dataconnect_endpoints", now, cfg.slow_interval,
                  lambda: dataconnect_endpoints.collect(self.dataconnect, cfg))
        self._run("dataconnect_freshness", now, cfg.medium_interval,
                  lambda: dataconnect_freshness.collect(self.dataconnect, cfg))
        self._run("dataconnect_nad_health", now, cfg.medium_interval,
                  lambda: nad_health.collect(self.client, self.dataconnect, cfg))

        # TACACS configuration is REST-owned; activity is Data Connect-owned in
        # standard mode. The collector exposes distinct metric families for each.
        if cfg.collect_tacacs:
            self._run("tacacs_config", now, cfg.slow_interval,
                      lambda: tacacs.collect_config(self.client, cfg))
            self._run("tacacs_activity", now, cfg.medium_interval,
                      lambda: tacacs.collect_activity(self.dataconnect, cfg))
        self._update_freshness(time.time())

    def loop(self, shutdown):
        nxt = time.time()
        while not shutdown.is_set():
            self.run_cycle()
            nxt = _next_deadline(nxt, time.time(), self.cfg.scrape_interval)
            while time.time() < nxt and not shutdown.is_set():
                time.sleep(max(0, min(nxt - time.time(), 1)))
