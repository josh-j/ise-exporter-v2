"""Scheduler gating: when streaming is requested but pxGrid creds are missing
(pxgrid=None), the scheduler must fall back to POLLING sessions/models rather than
skip them — otherwise those metrics are silently never collected."""
import logging
import types

import ise_exporter.scheduler as S
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


def test_streaming_skips_poll_when_pxgrid_present(monkeypatch):
    ran = []
    for name in ("deployment", "devices", "sessions", "endpoints", "authz"):
        monkeypatch.setattr(getattr(S, name), "collect",
                            (lambda n: (lambda *a, **k: ran.append(n)))(name))

    PollScheduler(_cfg(), client=None, pxgrid=object()).run_cycle()
    assert "sessions" not in ran   # streamer owns sessions
    assert "authz" in ran          # authz still runs (reduced) in stream mode


def test_logs_poll_fallback_reason_when_stream_requested_but_pxgrid_missing(caplog):
    with caplog.at_level(logging.WARNING):
        PollScheduler(_cfg(collect_pxgrid_stream=True), client=None, pxgrid=None)
    assert any("falling back to polling" in r.message for r in caplog.records)


def test_logs_streaming_mode_once_at_init(caplog):
    with caplog.at_level(logging.INFO):
        PollScheduler(_cfg(collect_pxgrid_stream=True), client=None, pxgrid=object())
    assert any("pxgrid streaming=True" in r.message for r in caplog.records)


def test_logs_polling_mode_once_at_init(caplog):
    with caplog.at_level(logging.INFO):
        PollScheduler(_cfg(collect_pxgrid_stream=False), client=None, pxgrid=None)
    assert any("pxgrid streaming=False" in r.message for r in caplog.records)
