"""Scheduler gating: when streaming is requested but pxGrid creds are missing
(pxgrid=None), the scheduler must fall back to POLLING sessions/models rather than
skip them — otherwise those metrics are silently never collected."""
import logging
import types

import ise_exporter.scheduler as S
from ise_exporter import metrics
from ise_exporter.scheduler import PollScheduler


def _cfg(**over):
    base = dict(collect_pxgrid_stream=True, collect_authz=True, collect_certificates=False,
                collect_licensing=False, collect_backup_status=False, collect_patches=False,
                collect_pxgrid_endpoints=False, fast_interval=60, medium_interval=300,
                slow_interval=3600)
    base.update(over)
    return types.SimpleNamespace(**base)


def test_streaming_falls_back_to_poll_without_pxgrid(monkeypatch):
    ran = []
    for name in ("deployment", "devices", "sessions", "endpoints", "authz"):
        monkeypatch.setattr(getattr(S, name), "collect",
                            (lambda n: (lambda *a, **k: ran.append(n)))(name))

    PollScheduler(_cfg(), client=None, pxgrid=None).run_cycle()
    assert "sessions" in ran   # poll path active because the streamer can't run


def test_stream_up_defers_endpoints_but_still_runs_sessions_authz(monkeypatch):
    metrics.ise_pxgrid_connected.set(1)   # stream UP
    ran = []
    for name in ("deployment", "devices", "sessions", "endpoints", "authz", "models"):
        monkeypatch.setattr(getattr(S, name), "collect",
                            (lambda n: (lambda *a, **k: ran.append(n)))(name))

    PollScheduler(_cfg(collect_pxgrid_endpoints=True), client=None, pxgrid=object()).run_cycle()
    # sessions runs PSN-only + authz runs reduced (self-limit internally), but the
    # pxgrid_endpoints (models) poll is deferred to the stream
    assert "sessions" in ran
    assert "authz" in ran
    assert "models" not in ran


def test_stream_down_falls_back_to_full_poll(monkeypatch):
    metrics.ise_pxgrid_connected.set(0)   # configured for streaming, but stream is DOWN
    ran = []
    for name in ("deployment", "devices", "sessions", "endpoints", "authz", "models"):
        monkeypatch.setattr(getattr(S, name), "collect",
                            (lambda n: (lambda *a, **k: ran.append(n)))(name))

    PollScheduler(_cfg(collect_pxgrid_endpoints=True), client=None, pxgrid=object()).run_cycle()
    # stream down -> full fallback: sessions/authz poll AND endpoints are polled via getEndpoints
    assert "sessions" in ran
    assert "authz" in ran
    assert "models" in ran


def test_logs_poll_fallback_reason_when_stream_requested_but_pxgrid_missing(caplog):
    with caplog.at_level(logging.WARNING):
        PollScheduler(_cfg(collect_pxgrid_stream=True), client=None, pxgrid=None)
    assert any("falling back to polling" in r.message for r in caplog.records)


def test_logs_streaming_mode_once_at_init(caplog):
    with caplog.at_level(logging.INFO):
        PollScheduler(_cfg(collect_pxgrid_stream=True), client=None, pxgrid=object())
    assert any("pxgrid streaming=ON" in r.message for r in caplog.records)


def test_logs_polling_mode_once_at_init(caplog):
    with caplog.at_level(logging.INFO):
        PollScheduler(_cfg(collect_pxgrid_stream=False), client=None, pxgrid=None)
    assert any("pxgrid streaming=OFF" in r.message for r in caplog.records)
