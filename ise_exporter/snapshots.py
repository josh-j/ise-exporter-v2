"""Atomic publication boundary between collectors and Prometheus scrapes.

The Prometheus client exposes each labelled metric as a mutable child map.  Domain
collectors replace many related maps at once, while the HTTP server may collect them
from another thread.  This module provides one lock shared by both operations and a
rollback-capable replacement helper so a scrape observes either the old domain
snapshot or the new one.
"""
from __future__ import annotations

import math
from contextlib import contextmanager
from threading import RLock, local

from prometheus_client import REGISTRY

from .util import MAX_METRIC_LABEL_BYTES


snapshot_lock = RLock()
_snapshot_staging = local()
MAX_METRIC_SNAPSHOT_SAMPLES = 20_000
MAX_PERSISTED_SNAPSHOT_SAMPLES = 20_000


def _validate_finite_metric_values(metric_families):
    """Reject poisoned numeric samples before they cross a snapshot boundary."""
    for metric in metric_families:
        children = getattr(metric, "_metrics", {}).values() \
            if hasattr(metric, "_metrics") else (metric,)
        for child in children:
            value = getattr(child, "_value", None)
            if isinstance(value, dict):  # Info payloads contain strings, not samples.
                continue
            if hasattr(value, "get"):
                value = value.get()
            try:
                finite = math.isfinite(float(value))
            except (TypeError, ValueError, OverflowError) as error:
                raise ValueError(
                    f"metric snapshot value is invalid for {metric._name}") from error
            if not finite:
                raise ValueError(
                    f"metric snapshot value is invalid for {metric._name}")


def _validate_metric_sample_count(metric_families):
    """Prevent any collector from publishing row-like Grafana state."""
    total = 0
    for metric in metric_families:
        total += len(metric._metrics) if hasattr(metric, "_metrics") else 1
        if total > MAX_METRIC_SNAPSHOT_SAMPLES:
            raise ValueError(
                f"metric snapshot exceeds the hard {MAX_METRIC_SNAPSHOT_SAMPLES}-sample limit")


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


def _replace_metric_snapshots(replacements, extra_families=(), extra_writers=()):
    """Apply one or more replacements and metadata writers under one lock."""
    replacements = tuple(
        (tuple(dict.fromkeys(families)), tuple(writers))
        for families, writers in replacements
    )
    replacement_families = tuple(dict.fromkeys(
        metric for families, _writers in replacements for metric in families))
    families = tuple(dict.fromkeys((*replacement_families, *extra_families)))
    with snapshot_lock:
        backups = {}
        for metric in families:
            if hasattr(metric, "_metrics"):
                backups[metric] = ("labelled", dict(metric._metrics))
            elif hasattr(metric, "info") and isinstance(
                    getattr(metric, "_value", None), dict):
                backups[metric] = ("info", dict(metric._value))
            elif hasattr(metric, "_value"):
                backups[metric] = ("scalar", metric._value.get())
            else:
                raise TypeError(f"unsupported metric family {metric!r}")
        try:
            for replacement, writers in replacements:
                for metric in replacement:
                    kind, _previous = backups[metric]
                    if kind == "labelled":
                        metric._metrics.clear()
                    elif kind == "info":
                        metric.info({})
                    else:
                        metric.set(0)
                for writer in writers:
                    writer()
            for writer in extra_writers:
                writer()
            _validate_metric_sample_count(replacement_families)
            _validate_finite_metric_values(families)
        except Exception:
            for metric, (kind, previous) in backups.items():
                if kind == "labelled":
                    metric._metrics.clear()
                    metric._metrics.update(previous)
                elif kind == "info":
                    metric.info(previous)
                else:
                    metric.set(previous)
            raise


@contextmanager
def stage_metric_snapshots():
    """Defer replacements until collector success metadata can join the commit."""
    if getattr(_snapshot_staging, "replacements", None) is not None:
        raise RuntimeError("nested metric snapshot transaction is not supported")
    replacements = []
    _snapshot_staging.replacements = replacements
    try:
        yield replacements
    finally:
        _snapshot_staging.replacements = None


def commit_metric_snapshots(replacements, extra_families=(), extra_writers=()):
    """Commit staged domain data and its validity metadata atomically."""
    _replace_metric_snapshots(replacements, extra_families, extra_writers)


def replace_metric_snapshot(metric_families, writers):
    """Clear and rebuild labelled metric families atomically, with rollback.

    Inside a collector observation the replacement is staged so the outer
    success metadata joins the same scrape boundary. Outside an observation it
    remains an immediate atomic replacement for restores and standalone users.
    """
    families = tuple(dict.fromkeys(metric_families))
    writers = tuple(writers)
    staged = getattr(_snapshot_staging, "replacements", None)
    if staged is not None:
        staged.append((families, writers))
        return
    _replace_metric_snapshots(((families, writers),))


def serialize_metric_snapshot(metric_families):
    """Return a JSON-safe copy of gauge families at one scrape boundary."""
    families = tuple(dict.fromkeys(metric_families))
    payload = {"version": 1, "metrics": {}}
    total_samples = 0
    with snapshot_lock:
        _validate_finite_metric_values(families)
        for metric in families:
            name = getattr(metric, "_name", "")
            if not name or name in payload["metrics"]:
                raise TypeError(f"unsupported or duplicate metric family {metric!r}")
            if hasattr(metric, "_metrics"):
                samples = []
                for labels, child in metric._metrics.items():
                    if any(len(label.encode("utf-8")) > MAX_METRIC_LABEL_BYTES
                           for label in labels):
                        raise ValueError(
                            f"metric snapshot label is too large for {name}")
                    samples.append({
                        "labels": list(labels), "value": child._value.get()})
                total_samples += len(samples)
                if total_samples > MAX_PERSISTED_SNAPSHOT_SAMPLES:
                    raise ValueError("metric snapshot exceeds the persisted sample limit")
                payload["metrics"][name] = {
                    "labelnames": list(metric._labelnames), "samples": samples,
                }
            elif hasattr(metric, "_value"):
                total_samples += 1
                if total_samples > MAX_PERSISTED_SNAPSHOT_SAMPLES:
                    raise ValueError("metric snapshot exceeds the persisted sample limit")
                payload["metrics"][name] = {
                    "labelnames": [],
                    "samples": [{"labels": [], "value": metric._value.get()}],
                }
            else:
                raise TypeError(f"unsupported metric family {metric!r}")
    return payload


def restore_metric_snapshot(metric_families, payload):
    """Atomically restore a complete, versioned gauge snapshot."""
    families = tuple(dict.fromkeys(metric_families))
    if not isinstance(payload, dict) or payload.get("version") != 1:
        raise ValueError("unsupported metric snapshot version")
    stored = payload.get("metrics")
    if not isinstance(stored, dict):
        raise ValueError("metric snapshot has no metric map")

    prepared = []
    total_samples = 0
    expected_names = {getattr(metric, "_name", "") for metric in families}
    if set(stored) != expected_names:
        raise ValueError("metric snapshot families do not match this exporter revision")
    for metric in families:
        item = stored[metric._name]
        labelnames = list(getattr(metric, "_labelnames", ()))
        if not isinstance(item, dict) or item.get("labelnames") != labelnames:
            raise ValueError(f"metric snapshot labels changed for {metric._name}")
        samples = item.get("samples")
        if not isinstance(samples, list):
            raise ValueError(f"metric snapshot samples are invalid for {metric._name}")
        total_samples += len(samples)
        if total_samples > MAX_PERSISTED_SNAPSHOT_SAMPLES:
            raise ValueError("metric snapshot exceeds the persisted sample limit")
        values = []
        for sample in samples:
            if not isinstance(sample, dict) or not isinstance(sample.get("labels"), list):
                raise ValueError(f"metric snapshot sample is invalid for {metric._name}")
            labels = sample["labels"]
            if len(labels) != len(labelnames):
                raise ValueError(f"metric snapshot label count changed for {metric._name}")
            if any(not isinstance(label, str) for label in labels):
                raise ValueError(f"metric snapshot label is invalid for {metric._name}")
            if any(len(label.encode("utf-8")) > MAX_METRIC_LABEL_BYTES
                   for label in labels):
                raise ValueError(f"metric snapshot label is too large for {metric._name}")
            try:
                value = float(sample["value"])
            except (KeyError, TypeError, ValueError) as error:
                raise ValueError(
                    f"metric snapshot value is invalid for {metric._name}") from error
            if not math.isfinite(value):
                raise ValueError(f"metric snapshot value is invalid for {metric._name}")
            values.append((labels, value))
        if not labelnames and len(values) != 1:
            raise ValueError(f"scalar metric snapshot is invalid for {metric._name}")
        prepared.append((metric, values))

    writers = []
    for metric, values in prepared:
        if getattr(metric, "_labelnames", ()):
            writers.extend(
                lambda metric=metric, labels=labels, value=value:
                    metric.labels(*labels).set(value)
                for labels, value in values
            )
        else:
            writers.append(lambda metric=metric, value=values[0][1]: metric.set(value))
    replace_metric_snapshot(families, writers)
