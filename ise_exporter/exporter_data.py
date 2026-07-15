"""Bounded, read-only access to the local exporter's Prometheus snapshot.

The operator CLI uses this before issuing additional ISE requests.  Only a
loopback metrics endpoint is accepted: exporter credentials and arbitrary HTTP
targets must never become reachable through an operator convenience command.
"""
from __future__ import annotations

from dataclasses import dataclass
import ipaddress
import os
import time
from urllib.parse import urlsplit
from urllib.request import ProxyHandler, Request, build_opener

from prometheus_client.parser import text_string_to_metric_families


DEFAULT_EXPORTER_METRICS_URL = "http://127.0.0.1:9618/metrics"
MAX_EXPORTER_SNAPSHOT_BYTES = 16 * 1024 * 1024
MAX_EXPORTER_SAMPLES = 100_000
EXPORTER_SNAPSHOT_TIMEOUT_SECONDS = 2.0


class ExporterDataError(RuntimeError):
    """The local exporter snapshot was unavailable or unsafe to consume."""


@dataclass(frozen=True)
class ExporterSample:
    metric: str
    labels: dict[str, str]
    value: float


@dataclass(frozen=True)
class ExporterSnapshot:
    url: str
    fetched_at: float
    samples: tuple[ExporterSample, ...]

    def named(self, *names: str) -> tuple[ExporterSample, ...]:
        wanted = frozenset(names)
        return tuple(sample for sample in self.samples if sample.metric in wanted)


def _metrics_url(value: str | None = None) -> str:
    raw = str(value or os.getenv(
        "ISE_EXPORTER_METRICS_URL", DEFAULT_EXPORTER_METRICS_URL)).strip()
    parsed = urlsplit(raw)
    if (parsed.scheme != "http" or parsed.username or parsed.password
            or parsed.query or parsed.fragment or parsed.path != "/metrics"):
        raise ExporterDataError(
            "ISE_EXPORTER_METRICS_URL must be a plain loopback http://HOST:PORT/metrics URL")
    try:
        address = ipaddress.ip_address(parsed.hostname or "")
    except ValueError as error:
        raise ExporterDataError(
            "ISE_EXPORTER_METRICS_URL must use a numeric loopback address") from error
    if not address.is_loopback:
        raise ExporterDataError("ISE_EXPORTER_METRICS_URL must remain on loopback")
    try:
        port = parsed.port
    except ValueError as error:
        raise ExporterDataError("ISE_EXPORTER_METRICS_URL has an invalid port") from error
    if port is None:
        raise ExporterDataError("ISE_EXPORTER_METRICS_URL must include an explicit port")
    return raw


def load_exporter_snapshot(url: str | None = None) -> ExporterSnapshot:
    target = _metrics_url(url)
    request = Request(target, headers={"Accept": "text/plain"}, method="GET")
    try:
        # Never let HTTP_PROXY turn a loopback-only data source into an external request.
        opener = build_opener(ProxyHandler({}))
        with opener.open(request, timeout=EXPORTER_SNAPSHOT_TIMEOUT_SECONDS) as response:
            payload = response.read(MAX_EXPORTER_SNAPSHOT_BYTES + 1)
    except Exception as error:
        raise ExporterDataError(f"local exporter metrics are unavailable: {error}") from error
    if len(payload) > MAX_EXPORTER_SNAPSHOT_BYTES:
        raise ExporterDataError(
            f"local exporter metrics exceeded {MAX_EXPORTER_SNAPSHOT_BYTES} bytes")
    try:
        text = payload.decode("utf-8")
        samples = []
        for family in text_string_to_metric_families(text):
            for sample in family.samples:
                samples.append(ExporterSample(
                    metric=str(sample.name),
                    labels={str(key): str(value) for key, value in sample.labels.items()},
                    value=float(sample.value),
                ))
                if len(samples) > MAX_EXPORTER_SAMPLES:
                    raise ExporterDataError(
                        f"local exporter metrics exceeded {MAX_EXPORTER_SAMPLES} samples")
    except ExporterDataError:
        raise
    except Exception as error:
        raise ExporterDataError(f"local exporter metrics could not be parsed: {error}") from error
    return ExporterSnapshot(target, time.time(), tuple(samples))
