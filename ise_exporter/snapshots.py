"""Atomic publication boundary between collectors and Prometheus scrapes.

The Prometheus client exposes each labelled metric as a mutable child map.  Domain
collectors replace many related maps at once, while the HTTP server may collect them
from another thread.  This module provides one lock shared by both operations and a
rollback-capable replacement helper so a scrape observes either the old domain
snapshot or the new one.
"""
from __future__ import annotations

from threading import RLock

from prometheus_client import REGISTRY


snapshot_lock = RLock()


class LockedCollectorRegistry:
    """Registry facade that holds ``snapshot_lock`` for one complete scrape."""

    def __init__(self, registry=REGISTRY):
        self.registry = registry

    def collect(self):
        with snapshot_lock:
            yield from self.registry.collect()

    def restricted_registry(self, names):
        restricted = getattr(self.registry, "restricted_registry", None)
        if restricted is None:
            return self
        return LockedCollectorRegistry(restricted(names))


def replace_metric_snapshot(metric_families, writers):
    """Clear and rebuild labelled metric families atomically, with rollback.

    Writers are prepared after all network I/O and normalization.  The previous
    labelled-child maps remain available for rollback until every writer succeeds.
    """
    families = tuple(dict.fromkeys(metric_families))
    with snapshot_lock:
        backups = {}
        for metric in families:
            if hasattr(metric, "_metrics"):
                backups[metric] = ("labelled", dict(metric._metrics))
            elif hasattr(metric, "_value"):
                backups[metric] = ("scalar", metric._value.get())
            else:
                raise TypeError(f"unsupported metric family {metric!r}")
        try:
            for metric in families:
                kind, _previous = backups[metric]
                if kind == "labelled":
                    metric._metrics.clear()
                else:
                    metric.set(0)
            for writer in writers:
                writer()
        except Exception:
            for metric, (kind, previous) in backups.items():
                if kind == "labelled":
                    metric._metrics.clear()
                    metric._metrics.update(previous)
                else:
                    metric.set(previous)
            raise
