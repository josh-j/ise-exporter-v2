import types

import ise_exporter.__main__ as app


def _cfg(**overrides):
    base = dict(
        log_level="INFO",
        pxgrid_host="px.example",
        pxgrid_port=8910,
        pxgrid_node_name="ise-exporter",
        pxgrid_client_cert="/cert.pem",
        pxgrid_client_key="/key.pem",
        pxgrid_ca_bundle="/ca.pem",
        pxgrid_query_timeout=5,
        collect_pxgrid_stream=False,
    )
    base.update(overrides)
    ns = types.SimpleNamespace(**base)
    ns.summary = lambda: "test-config"
    return ns


def _fake_pxgrid_control(calls):
    class FakePxGridControl:
        def __init__(self, cfg):
            self.cfg = cfg

        def account_activate(self):
            calls.append(("account_activate",))

        def session_topic(self):
            calls.append(("session_topic",))
            return "https://ise/session", "/topic/com.cisco.ise.session.all"

        def endpoint_topic(self):
            calls.append(("endpoint_topic",))
            return "https://ise/endpoint", "/topic/com.cisco.ise.endpoint"

        def resolve_pubsub(self):
            calls.append(("resolve_pubsub",))
            return "pubsub-node", ["wss://ise/pubsub"], "secret"

        def rest_query(self, service, endpoint, body=None, timeout=120):
            calls.append(("rest_query", service, endpoint, body or {}))
            return {"sessions": [{"auditSessionId": "A1"}]}

        def get_endpoints(self, **kwargs):
            calls.append(("get_endpoints", kwargs))
            return [{"macAddress": "00:00:00:00:00:01"}]

    return FakePxGridControl


def test_pxgrid_check_exercises_control_topics_and_rest_probes(monkeypatch):
    calls = []

    monkeypatch.setattr(app, "PxGridControl", _fake_pxgrid_control(calls))

    assert app.pxgrid_check(_cfg()) == 0
    assert calls[0] == ("account_activate",)
    assert ("session_topic",) in calls
    assert ("endpoint_topic",) in calls
    assert ("resolve_pubsub",) in calls
    assert any(call[:3] == ("rest_query", app.SESSION_SERVICE, "getSessions") for call in calls)
    assert any(call[0] == "get_endpoints" and call[1]["max_pages"] == 1 for call in calls)


def test_pxgrid_check_can_validate_stream_connect(monkeypatch):
    calls = []

    class FakeStreamer:
        def __init__(self, control, mappings, shutdown):
            calls.append(("streamer_init", mappings))

        def _connect_ws(self):
            calls.append(("connect_ws",))

        def _close_ws(self):
            calls.append(("close_ws",))

    monkeypatch.setattr(app, "PxGridControl", _fake_pxgrid_control(calls))
    monkeypatch.setattr(app, "PxGridStreamer", FakeStreamer)

    assert app.pxgrid_check(_cfg(), check_stream=True) == 0
    assert ("connect_ws",) in calls
    assert ("close_ws",) in calls


def test_pxgrid_check_closes_stream_after_connect_failure(monkeypatch):
    calls = []

    class FailingStreamer:
        def __init__(self, control, mappings, shutdown):
            calls.append(("streamer_init", mappings))

        def _connect_ws(self):
            calls.append(("connect_ws",))
            raise RuntimeError("stomp failed")

        def _close_ws(self):
            calls.append(("close_ws",))

    monkeypatch.setattr(app, "PxGridControl", _fake_pxgrid_control(calls))
    monkeypatch.setattr(app, "PxGridStreamer", FailingStreamer)

    assert app.pxgrid_check(_cfg(), check_stream=True) == 1
    assert ("connect_ws",) in calls
    assert ("close_ws",) in calls


def test_pxgrid_check_stream_runs_when_streaming_is_configured(monkeypatch):
    calls = []

    monkeypatch.setattr(app, "pxgrid_check",
                        lambda cfg, check_stream=False: calls.append(check_stream) or 0)
    monkeypatch.setattr(app.Config, "from_env", classmethod(lambda cls: _cfg(collect_pxgrid_stream=True)))
    monkeypatch.setattr(app, "load_dotenv", lambda: None)

    assert app.main(["--pxgrid-check"]) == 0
    assert calls == [True]


def test_pxgrid_check_reports_missing_pxgrid_config():
    assert app.pxgrid_check(_cfg(pxgrid_host="")) == 1
