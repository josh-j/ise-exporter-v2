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
    dataconnect_performance,
    dataconnect_posture,
    dataconnect_radius,
    deployment,
    devices,
    licensing,
    patches,
    tacacs,
)

logger = logging.getLogger(__name__)
MAX_CONSECUTIVE_FAILURES = 5


class PollScheduler:
    def __init__(self, cfg, client, dataconnect=None):
        self.cfg = cfg
        self.client = client
        self.dataconnect = dataconnect
        self.last_run = {}
        self.mappings = {"ops_owner": {}, "hostname": {}, "location": {}}
        logger.info("collection plan: REST/OpenAPI=platform/config DataConnect=reporting")

    def _due(self, name, now, tier):
        if name not in self.last_run:
            return True
        if collectors.failures(name) >= MAX_CONSECUTIVE_FAILURES:
            if (now - self.last_run[name]) < self.cfg.slow_interval:
                metrics.ise_collector_enabled.labels(collector=name).set(0)
                return False
        metrics.ise_collector_enabled.labels(collector=name).set(1)
        return (now - self.last_run[name]) >= tier

    def _run(self, name, now, tier, callback):
        if self._due(name, now, tier):
            callback()
            self.last_run[name] = now

    def run_cycle(self):
        cfg, now = self.cfg, time.time()

        # REST/OpenAPI control plane: always authoritative in every profile.
        self._run("deployment", now, cfg.medium_interval,
                  lambda: deployment.collect(self.client, cfg, self.mappings))
        self._run("devices", now, cfg.medium_interval,
                  lambda: devices.collect(self.client, cfg, self.mappings))
        if cfg.collect_certificates:
            self._run("certificates", now, cfg.slow_interval,
                      lambda: certificates.collect(self.client, cfg, self.mappings))
        if cfg.collect_licensing:
            self._run("licensing", now, cfg.slow_interval,
                      lambda: licensing.collect(self.client, cfg, self.mappings))
        if cfg.collect_backup_status:
            self._run("backup", now, cfg.slow_interval,
                      lambda: backup.collect(self.client, cfg, self.mappings))
        if cfg.collect_patches:
            self._run("patches", now, cfg.slow_interval,
                      lambda: patches.collect(self.client, cfg, self.mappings))

        # Data Connect reporting plane. Each domain owns disjoint metric families.
        self._run("dataconnect_radius", now, cfg.fast_interval,
                  lambda: dataconnect_radius.collect(self.dataconnect, cfg))
        self._run("dataconnect_performance", now, cfg.fast_interval,
                  lambda: dataconnect_performance.collect(self.dataconnect, cfg))
        self._run("dataconnect_posture", now, cfg.medium_interval,
                  lambda: dataconnect_posture.collect(self.dataconnect, cfg))
        self._run("dataconnect_endpoints", now, cfg.slow_interval,
                  lambda: dataconnect_endpoints.collect(self.dataconnect, cfg))

        # TACACS configuration is REST-owned; activity is Data Connect-owned in
        # standard mode. The collector exposes distinct metric families for each.
        if cfg.collect_tacacs:
            self._run("tacacs_config", now, cfg.slow_interval,
                      lambda: tacacs.collect_config(self.client, cfg))
            self._run("tacacs_activity", now, cfg.medium_interval,
                      lambda: tacacs.collect_activity(self.dataconnect, cfg))

    def loop(self, shutdown):
        nxt = time.time()
        while not shutdown.is_set():
            self.run_cycle()
            nxt += self.cfg.scrape_interval
            while time.time() < nxt and not shutdown.is_set():
                time.sleep(max(0, min(nxt - time.time(), 1)))
