import io

import pytest

from ise_exporter import exporter_data


class _Response(io.BytesIO):
    def __enter__(self):
        return self

    def __exit__(self, *_args):
        self.close()


class _Opener:
    def __init__(self, payload):
        self.payload = payload

    def open(self, request, timeout):
        return _Response(self.payload)


def test_loads_bounded_loopback_prometheus_snapshot(monkeypatch):
    payload = b"""# HELP ise_up ISE availability
# TYPE ise_up gauge
ise_up 1
ise_dataset_up{dataset="nodes",source="rest"} 1
"""
    monkeypatch.setattr(
        exporter_data, "build_opener", lambda *_handlers: _Opener(payload))

    snapshot = exporter_data.load_exporter_snapshot()

    assert snapshot.url == "http://127.0.0.1:9618/metrics"
    assert [(sample.metric, sample.value) for sample in snapshot.samples] == [
        ("ise_up", 1.0), ("ise_dataset_up", 1.0)]
    assert snapshot.samples[1].labels == {"dataset": "nodes", "source": "rest"}


@pytest.mark.parametrize("url", (
    "https://127.0.0.1:9618/metrics",
    "http://ise.example:9618/metrics",
    "http://192.0.2.10:9618/metrics",
    "http://127.0.0.1:9618/other",
    "http://user:pass@127.0.0.1:9618/metrics",
))
def test_rejects_non_loopback_or_ambiguous_metrics_urls(url):
    with pytest.raises(exporter_data.ExporterDataError):
        exporter_data.load_exporter_snapshot(url)


def test_rejects_oversized_snapshot(monkeypatch):
    monkeypatch.setattr(
        exporter_data, "MAX_EXPORTER_SNAPSHOT_BYTES", 8)
    monkeypatch.setattr(
        exporter_data, "build_opener",
        lambda *_handlers: _Opener(b"ise_up 1\n"))

    with pytest.raises(exporter_data.ExporterDataError, match="exceeded"):
        exporter_data.load_exporter_snapshot()
