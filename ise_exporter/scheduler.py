"""Polling engine: interval tiers, failure gating, and the cycle dispatch.
Owns last_run_times + failure_tracker (moved off the module globals). Drives the
poll-mode collectors. When cfg.collect_pxgrid_stream is true, sessions+authz are
skipped here because streaming.py feeds those gauges instead."""
import time
import logging

from . import metrics
from . import collectors
from .collectors import (sessions, authz, devices, endpoints, deployment,
                         certificates, licensing, backup, patches, models)

logger = logging.getLogger(__name__)
MAX_CONSECUTIVE_FAILURES = 5


class PollScheduler:
    def __init__(self, cfg, client, pxgrid=None):
        self.cfg = cfg
        self.client = client
        self.pxgrid = pxgrid
        self.last_run = {}
        self.mappings = {"ops_owner": {}, "hostname": {}, "location": {}}
        self._streaming_state = None   # tracks stream up/down to log the fallback flip once

        # log the poll-vs-stream split ONCE, at the point that actually decides it —
        # both flags are immutable for the process lifetime, so this can't go stale.
        streaming = cfg.collect_pxgrid_stream and pxgrid is not None
        if cfg.collect_pxgrid_stream and pxgrid is None:
            logger.warning("scheduler: COLLECT_PXGRID_STREAM=true but no usable pxGrid client — "
                           "falling back to polling for sessions/pxgrid_endpoints "
                           "(see the 'pxGrid disabled' warning above for why)")
        elif streaming:
            logger.info("scheduler: pxgrid streaming=ON — projector owns session/endpoint gauges; "
                       "sessions collector runs PSN-only, pxgrid_endpoints deferred to the stream")
        else:
            logger.info("scheduler: pxgrid streaming=OFF — polling all session/endpoint collectors")

    def _due(self, name, now, fast, medium, slow):
        if name not in self.last_run:
            return True
        # gated after too many failures, but half-open: allow one retry per slow tier
        # so a transient outage doesn't disable a collector until process restart
        if collectors.failures(name) >= MAX_CONSECUTIVE_FAILURES:
            if (now - self.last_run[name]) < self.cfg.slow_interval:
                metrics.ise_collector_enabled.labels(collector=name).set(0)
                return False
        metrics.ise_collector_enabled.labels(collector=name).set(1)
        tier = (self.cfg.fast_interval if name in fast else
                self.cfg.medium_interval if name in medium else
                self.cfg.slow_interval if name in slow else 0)
        return (now - self.last_run[name]) >= tier

    def run_cycle(self):
        cfg, now = self.cfg, time.time()
        fast = {"sessions", "endpoints"}
        medium = {"devices", "deployment", "authz"}
        slow = {"certificates", "licensing", "backup", "patches", "pxgrid_endpoints"}
        # "streaming" is now the LIVE state, not just config: true only while the pxGrid
        # stream is actually connected. When it drops, this flips to false and the full
        # session/authz/endpoint poll runs as a fallback until the stream recovers.
        streaming = collectors.stream_active(cfg) and self.pxgrid is not None
        if streaming != self._streaming_state:
            if self._streaming_state is not None:
                logger.info("scheduler: pxGrid stream %s — session/authz/endpoint collectors now %s",
                            "UP" if streaming else "DOWN",
                            "deferred to the stream" if streaming else "full MnT/REST polling (fallback)")
            self._streaming_state = streaming

        if self._due("deployment", now, fast, medium, slow):
            deployment.collect(self.client, cfg, self.mappings)
            self.last_run["deployment"] = now
        if self._due("devices", now, fast, medium, slow):
            devices.collect(self.client, cfg, self.mappings)
            self.last_run["devices"] = now
        # sessions runs in BOTH modes: in stream mode it self-limits to the per-PSN
        # gauge (ise_radius_sessions_by_psn), which the pxGrid session topic can't feed.
        if self._due("sessions", now, fast, medium, slow):
            sessions.collect(self.client, cfg, self.mappings)
            self.last_run["sessions"] = now
        if self._due("endpoints", now, fast, medium, slow):
            endpoints.collect(self.client, cfg, self.mappings)
            self.last_run["endpoints"] = now
        # authz runs in BOTH modes: in stream mode it emits only the failure-reason /
        # matched-rule / policy-set signals the session topic can't carry (it self-limits)
        if cfg.collect_authz and self._due("authz", now, fast, medium, slow):
            authz.collect(self.client, cfg, self.mappings)
            self.last_run["authz"] = now
        if cfg.collect_certificates and self._due("certificates", now, fast, medium, slow):
            certificates.collect(self.client, cfg, self.mappings)
            self.last_run["certificates"] = now
        if cfg.collect_licensing and self._due("licensing", now, fast, medium, slow):
            licensing.collect(self.client, cfg, self.mappings)
            self.last_run["licensing"] = now
        if cfg.collect_backup_status and self._due("backup", now, fast, medium, slow):
            backup.collect(self.client, cfg, self.mappings)
            self.last_run["backup"] = now
        if cfg.collect_patches and self._due("patches", now, fast, medium, slow):
            patches.collect(self.client, cfg, self.mappings)
            self.last_run["patches"] = now
        # bulk model collector only when NOT streaming (stream projects models itself)
        if cfg.collect_pxgrid_endpoints and not streaming and self.pxgrid \
                and self._due("pxgrid_endpoints", now, fast, medium, slow):
            models.collect(self.pxgrid, cfg)
            self.last_run["pxgrid_endpoints"] = now

    def loop(self, shutdown):
        nxt = time.time()
        while not shutdown.is_set():
            self.run_cycle()
            nxt += self.cfg.scrape_interval
            while time.time() < nxt and not shutdown.is_set():
                time.sleep(min(nxt - time.time(), 1))
