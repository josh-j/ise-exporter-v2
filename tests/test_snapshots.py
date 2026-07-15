import threading

import pytest
from prometheus_client import CollectorRegistry, Gauge, Info

from ise_exporter import collectors, metrics
import ise_exporter.snapshots as snapshots_module
from ise_exporter.snapshots import (
    LockedCollectorRegistry,
    commit_metric_snapshots,
    replace_metric_snapshot,
    restore_metric_snapshot,
    serialize_metric_snapshot,
    snapshot_lock,
    stage_metric_snapshots,
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


def test_snapshot_replacement_includes_info_and_rolls_it_back():
    registry = CollectorRegistry()
    version = Info("snapshot_version", "test", registry=registry)
    level = Gauge("snapshot_level", "test", registry=registry)
    version.info({"version": "old"})
    level.set(10)

    with pytest.raises(RuntimeError):
        replace_metric_snapshot((version, level), (
            lambda: version.info({"version": "new"}),
            lambda: level.set(11),
            lambda: (_ for _ in ()).throw(RuntimeError("stop")),
        ))

    assert version._value == {"version": "old"}
    assert level._value.get() == 10


@pytest.mark.parametrize("invalid", (float("nan"), float("inf"), float("-inf")))
def test_snapshot_replacement_rejects_nonfinite_samples_and_rolls_back(invalid):
    registry = CollectorRegistry()
    labelled = Gauge("snapshot_finite_labelled", "test", ["key"], registry=registry)
    scalar = Gauge("snapshot_finite_scalar", "test", registry=registry)
    labelled.labels(key="old").set(1)
    scalar.set(2)

    with pytest.raises(ValueError, match="value is invalid"):
        replace_metric_snapshot((labelled, scalar), (
            lambda: labelled.labels(key="new").set(invalid),
            lambda: scalar.set(3),
        ))

    assert {(sample.labels["key"], sample.value)
            for sample in labelled.collect()[0].samples} == {("old", 1)}
    assert scalar._value.get() == 2


def test_snapshot_replacement_rejects_excessive_series_and_rolls_back(monkeypatch):
    registry = CollectorRegistry()
    metric = Gauge("snapshot_bounded", "test", ["key"], registry=registry)
    metric.labels(key="old").set(7)
    monkeypatch.setattr(snapshots_module, "MAX_METRIC_SNAPSHOT_SAMPLES", 2)

    with pytest.raises(ValueError, match="hard 2-sample limit"):
        replace_metric_snapshot((metric,), tuple(
            lambda key=key: metric.labels(key=key).set(1)
            for key in ("one", "two", "three")))

    assert {(sample.labels["key"], sample.value)
            for sample in metric.collect()[0].samples} == {("old", 7)}


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


def test_observed_snapshot_is_staged_until_success_metadata_commits():
    registry = CollectorRegistry()
    domain = Gauge("staged_domain_value", "test", ["key"], registry=registry)
    domain.labels(key="old").set(1)
    name = "staged_success_test"

    with collectors.observe(name):
        replace_metric_snapshot(
            (domain,), (lambda: domain.labels(key="new").set(2),))
        assert {(sample.labels["key"], sample.value)
                for sample in domain.collect()[0].samples} == {("old", 1)}

    assert {(sample.labels["key"], sample.value)
            for sample in domain.collect()[0].samples} == {("new", 2)}
    assert metrics.ise_dataset_up.labels(
        dataset=name, source="rest")._value.get() == 1
    assert metrics.ise_dataset_fresh.labels(
        dataset=name, source="rest")._value.get() == 1


def test_failed_observation_discards_staged_snapshot():
    registry = CollectorRegistry()
    domain = Gauge("discarded_domain_value", "test", ["key"], registry=registry)
    domain.labels(key="old").set(1)
    name = "staged_failure_test"

    with collectors.observe(name):
        replace_metric_snapshot(
            (domain,), (lambda: domain.labels(key="new").set(2),))
        raise collectors.CollectorFailed("incomplete snapshot")

    assert {(sample.labels["key"], sample.value)
            for sample in domain.collect()[0].samples} == {("old", 1)}
    assert metrics.ise_dataset_up.labels(
        dataset=name, source="rest")._value.get() == 0


def test_staged_metadata_failure_rolls_back_domain_and_metadata():
    registry = CollectorRegistry()
    domain = Gauge("transaction_domain", "test", registry=registry)
    health = Gauge("transaction_health", "test", registry=registry)
    domain.set(1)
    health.set(0)

    with stage_metric_snapshots() as replacements:
        replace_metric_snapshot((domain,), (lambda: domain.set(2),))

        def fail_metadata():
            health.set(1)
            raise RuntimeError("metadata failed")

        with pytest.raises(RuntimeError, match="metadata failed"):
            commit_metric_snapshots(
                replacements, (health,), (fail_metadata,))

    assert domain._value.get() == 1
    assert health._value.get() == 0


def test_metric_snapshot_round_trip_restores_labelled_and_scalar_gauges():
    registry = CollectorRegistry()
    labelled = Gauge("persisted_labelled", "test", ["key"], registry=registry)
    scalar = Gauge("persisted_scalar", "test", registry=registry)
    labelled.labels(key="first").set(3)
    labelled.labels(key="second").set(4)
    scalar.set(9)
    payload = serialize_metric_snapshot((labelled, scalar))

    labelled._metrics.clear()
    labelled.labels(key="wrong").set(99)
    scalar.set(0)
    restore_metric_snapshot((labelled, scalar), payload)

    assert {(sample.labels["key"], sample.value) for sample in labelled.collect()[0].samples} == {
        ("first", 3), ("second", 4)}
    assert scalar._value.get() == 9


def test_metric_snapshot_rejects_schema_drift_without_mutating_metrics():
    registry = CollectorRegistry()
    metric = Gauge("persisted_schema", "test", ["key"], registry=registry)
    metric.labels(key="current").set(7)
    payload = serialize_metric_snapshot((metric,))
    payload["metrics"]["persisted_schema"]["labelnames"] = ["changed"]

    with pytest.raises(ValueError, match="labels changed"):
        restore_metric_snapshot((metric,), payload)

    assert {(sample.labels["key"], sample.value) for sample in metric.collect()[0].samples} == {
        ("current", 7)}


@pytest.mark.parametrize("invalid", [float("nan"), float("inf"), "not-a-number"])
def test_metric_snapshot_rejects_invalid_values(invalid):
    registry = CollectorRegistry()
    metric = Gauge("persisted_invalid", "test", registry=registry)
    payload = serialize_metric_snapshot((metric,))
    payload["metrics"]["persisted_invalid"]["samples"][0]["value"] = invalid

    with pytest.raises(ValueError, match="value is invalid"):
        restore_metric_snapshot((metric,), payload)


def test_metric_snapshot_rejects_excessive_persisted_series(monkeypatch):
    registry = CollectorRegistry()
    metric = Gauge("persisted_excessive", "test", ["key"], registry=registry)
    metric.labels(key="current").set(7)
    payload = serialize_metric_snapshot((metric,))
    payload["metrics"]["persisted_excessive"]["samples"] = [
        {"labels": [f"key-{index}"], "value": index} for index in range(3)]
    monkeypatch.setattr(snapshots_module, "MAX_PERSISTED_SNAPSHOT_SAMPLES", 2)

    with pytest.raises(ValueError, match="sample limit"):
        restore_metric_snapshot((metric,), payload)

    assert {(sample.labels["key"], sample.value) for sample in metric.collect()[0].samples} == {
        ("current", 7)}


def test_metric_snapshot_refuses_to_serialize_excessive_series(monkeypatch):
    registry = CollectorRegistry()
    metric = Gauge("serialize_excessive", "test", ["key"], registry=registry)
    metric.labels(key="first").set(1)
    metric.labels(key="second").set(2)
    monkeypatch.setattr(snapshots_module, "MAX_PERSISTED_SNAPSHOT_SAMPLES", 1)

    with pytest.raises(ValueError, match="sample limit"):
        serialize_metric_snapshot((metric,))


def test_metric_snapshot_refuses_to_serialize_nonfinite_live_value():
    registry = CollectorRegistry()
    metric = Gauge("serialize_nonfinite", "test", registry=registry)
    metric.set(float("nan"))

    with pytest.raises(ValueError, match="value is invalid"):
        serialize_metric_snapshot((metric,))


def test_metric_snapshot_rejects_oversized_persisted_labels():
    registry = CollectorRegistry()
    metric = Gauge("persisted_large_label", "test", ["key"], registry=registry)
    payload = serialize_metric_snapshot((metric,))
    payload["metrics"]["persisted_large_label"]["samples"] = [{
        "labels": ["x" * 257], "value": 1}]

    with pytest.raises(ValueError, match="label is too large"):
        restore_metric_snapshot((metric,), payload)


def test_metric_snapshot_refuses_to_serialize_oversized_labels():
    registry = CollectorRegistry()
    metric = Gauge("serialize_large_label", "test", ["key"], registry=registry)
    metric.labels(key="x" * 257).set(1)

    with pytest.raises(ValueError, match="label is too large"):
        serialize_metric_snapshot((metric,))
