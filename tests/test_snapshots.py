import threading

import pytest
from prometheus_client import CollectorRegistry, Gauge

from ise_exporter.snapshots import (
    LockedCollectorRegistry,
    replace_metric_snapshot,
    snapshot_lock,
)


def _samples(metric):
    return {(sample.labels["key"], sample.value)
            for sample in metric.collect()[0].samples if sample.name == "snapshot_value"}


def test_snapshot_replacement_rolls_back_every_family_on_writer_failure():
    registry = CollectorRegistry()
    first = Gauge("snapshot_value", "test", ["key"], registry=registry)
    second = Gauge("snapshot_other", "test", ["key"], registry=registry)
    first.labels(key="old").set(1)
    second.labels(key="old").set(2)

    def fail():
        raise RuntimeError("writer failed")

    with pytest.raises(RuntimeError, match="writer failed"):
        replace_metric_snapshot((first, second), (
            lambda: first.labels(key="new").set(3), fail,
        ))

    assert _samples(first) == {("old", 1)}
    other = {(sample.labels["key"], sample.value)
             for sample in second.collect()[0].samples if sample.name == "snapshot_other"}
    assert other == {("old", 2)}


def test_snapshot_replacement_includes_scalar_gauges_and_rolls_them_back():
    registry = CollectorRegistry()
    labelled = Gauge("snapshot_labelled", "test", ["key"], registry=registry)
    scalar = Gauge("snapshot_scalar", "test", registry=registry)
    labelled.labels(key="old").set(1)
    scalar.set(7)

    with pytest.raises(RuntimeError):
        replace_metric_snapshot((labelled, scalar), (
            lambda: scalar.set(9),
            lambda: (_ for _ in ()).throw(RuntimeError("stop")),
        ))

    assert scalar._value.get() == 7
    labelled_samples = {(sample.labels["key"], sample.value)
                        for sample in labelled.collect()[0].samples}
    assert labelled_samples == {("old", 1)}


def test_locked_registry_waits_for_snapshot_publication_boundary():
    registry = CollectorRegistry()
    Gauge("locked_registry_value", "test", registry=registry).set(1)
    locked = LockedCollectorRegistry(registry)
    started = threading.Event()
    completed = threading.Event()

    def collect():
        started.set()
        list(locked.collect())
        completed.set()

    with snapshot_lock:
        thread = threading.Thread(target=collect)
        thread.start()
        assert started.wait(1)
        assert not completed.wait(0.05)
    thread.join(1)
    assert completed.is_set()
