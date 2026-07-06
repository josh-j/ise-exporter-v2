"""Bootstrap-race test: a DISCONNECT that arrives during the snapshot window must
win over a stale ACTIVE snapshot after the buffer is drained. The disconnect is
fired from inside the fake getSessions (while syncing=True) so it lands in the
buffer; after _bootstrap drains, the disconnected session must be gone."""
import logging
import ssl
import threading
import time
import types

import pytest

import ise_exporter.streaming as streaming
from ise_exporter.streaming import PxGridStreamer, _classify_stream_error


def _cfg():
    return types.SimpleNamespace(
        pxgrid_query_timeout=5, project_interval=30, resync_interval=3600,
        watchdog_timeout=90, reconnect_max_backoff=60, profiler_hierarchy_ttl=3600,
        pxgrid_client_cert="", pxgrid_client_key="", pxgrid_ca_bundle="",
    )


class FakeControl:
    """rest_query(getSessions) fires a mid-sync DISCONNECT for A2 before returning
    a snapshot that still shows A2 AUTHENTICATED."""
    def __init__(self):
        self.cfg = _cfg()
        self.host = "px"
        self.node_name = "exporter"
        self.streamer = None

    def rest_query(self, service, endpoint, body=None, timeout=120):
        if endpoint == "getSessions":
            # event arrives DURING the snapshot fetch, while syncing=True -> buffered
            self.streamer.on_event({"topic": "session",
                                    "session": {"auditSessionId": "A2", "state": "DISCONNECTED"}})
            return {"sessions": [
                {"auditSessionId": "A1", "state": "AUTHENTICATED"},
                {"auditSessionId": "A2", "state": "AUTHENTICATED"},
            ]}
        if endpoint == "getEndpoints":
            return {"endpoints": []}
        return {}

    def get_endpoints(self, **kwargs):
        return []


def test_drain_over_snapshot():
    ctl = FakeControl()
    mappings = {"hostname": {}, "location": {}, "ops_owner": {}}
    streamer = PxGridStreamer(ctl, mappings, threading.Event())
    ctl.streamer = streamer

    streamer._bootstrap("test")

    # A1 survives; A2's mid-sync DISCONNECT drained over the stale ACTIVE snapshot
    assert "A1" in streamer.sessions
    assert "A2" not in streamer.sessions
    assert not streamer.syncing
    assert streamer.buffer == []


def test_bootstrap_sends_heartbeats_during_slow_snapshot(monkeypatch):
    """A large deployment's getSessions/getEndpoints can outlast the STOMP
    heart-beat interval negotiated in CONNECT — if nothing keeps the socket
    active during that blocking window, ISE's broker sees a silent client and
    kills the connection right as the (perfectly good) snapshot lands."""
    monkeypatch.setattr(streaming, "_HEARTBEAT_SECS", 0.02)

    class SlowControl(FakeControl):
        def rest_query(self, service, endpoint, body=None, timeout=120):
            if endpoint == "getSessions":
                time.sleep(0.08)
                return {"sessions": []}
            return {}

        def get_endpoints(self, **kwargs):
            return []

    class FakeWs:
        def __init__(self):
            self.sent = []
            self.pings = 0

        def send_binary(self, payload):
            self.sent.append(payload)

        def ping(self, payload=b""):
            self.pings += 1

    ctl = SlowControl()
    streamer = PxGridStreamer(ctl, {"hostname": {}, "location": {}, "ops_owner": {}},
                              threading.Event())
    ctl.streamer = streamer
    streamer.ws = FakeWs()

    streamer._bootstrap("test")

    # keepalive during a slow snapshot is a WebSocket ping, not a STOMP newline
    assert streamer.ws.pings >= 1


def test_bootstrap_warns_when_sessions_present_but_endpoints_empty(caplog):
    class Control:
        def __init__(self):
            self.cfg = _cfg()
            self.host = "px"
            self.node_name = "exporter"

        def rest_query(self, service, endpoint, body=None, timeout=120):
            if endpoint == "getSessions":
                return {"sessions": [{"auditSessionId": "A1", "state": "STARTED"}]}
            return {}

        def get_endpoints(self, **kwargs):
            return []

    streamer = PxGridStreamer(Control(), {"hostname": {}, "location": {}, "ops_owner": {}},
                              threading.Event())

    with caplog.at_level(logging.WARNING):
        streamer._bootstrap("test")

    assert any("0 endpoints" in r.message for r in caplog.records)


def _streamer():
    ctl = FakeControl()
    s = PxGridStreamer(ctl, {"hostname": {}, "location": {}, "ops_owner": {}},
                       threading.Event())
    ctl.streamer = s
    return s


def test_normalize_events_batch_keeps_all():
    # a batched frame must yield every element, not just [0]
    events = PxGridStreamer._normalize_events(
        {"sessions": [{"auditSessionId": "S1"}, {"auditSessionId": "S2"}]})
    assert [e["session"]["auditSessionId"] for e in events] == ["S1", "S2"]


def test_normalize_events_accepts_nested_endpoint_batch_shape():
    events = PxGridStreamer._normalize_events(
        {"endpoints": {"endpoint": [{"macAddress": "00:00:00:00:00:01"},
                                    {"macAddress": "00:00:00:00:00:02"}]}})
    assert [e["endpoint"]["macAddress"] for e in events] == [
        "00:00:00:00:00:01",
        "00:00:00:00:00:02",
    ]


def test_normalize_events_empty_array_is_safe():
    # empty array used to IndexError on [0]; now yields no events
    assert PxGridStreamer._normalize_events({"sessions": []}) == []
    assert PxGridStreamer._normalize_events({"endpoints": []}) == []


def test_project_emits_posture_and_mdm_and_leaves_psn_untouched():
    from ise_exporter import metrics
    from ise_exporter.util import clear_metric

    ctl = FakeControl()
    mappings = {"hostname": {"10.0.0.1": "sw1"}, "location": {"10.0.0.1": "SiteA"},
                "ops_owner": {"10.0.0.1": "TeamA"}}
    s = PxGridStreamer(ctl, mappings, threading.Event())
    s.sessions = {
        "A": {"auditSessionId": "A", "state": "STARTED", "nasIpAddress": "10.0.0.1",
              "callingStationId": "00:00:00:00:00:01", "postureStatus": "Compliant"},
        "B": {"auditSessionId": "B", "state": "STARTED", "nasIpAddress": "10.0.0.1",
              "callingStationId": "00:00:00:00:00:02", "postureStatus": "NonCompliant",
              "mdmRegistered": "true", "mdmCompliant": "false", "mdmJailBroken": "true"},
        "C": {"auditSessionId": "C", "state": "STARTED", "nasIpAddress": "10.0.0.1",
              "callingStationId": "00:00:00:00:00:03"},   # no posture -> NotApplicable
    }
    s.endpoints = {}
    # PSN is poll-owned; the projector must not create series on it
    clear_metric(metrics.ise_radius_sessions_by_psn)

    s.project()

    posture = {sm.labels["status"]: sm.value
               for sm in metrics.ise_session_posture_status.collect()[0].samples}
    assert posture == {"Compliant": 1.0, "NonCompliant": 1.0, "NotApplicable": 1.0}

    # MDM projected only for the MDM-managed session (B), keyed by ops_owner
    mdm = {(sm.labels["dimension"], sm.labels["value"], sm.labels["ops_owner"]): sm.value
           for sm in metrics.ise_session_mdm_status.collect()[0].samples}
    assert mdm[("registered", "true", "TeamA")] == 1.0
    assert mdm[("compliant", "false", "TeamA")] == 1.0
    assert mdm[("jailbroken", "true", "TeamA")] == 1.0
    assert len(mdm) == 5   # 5 dims, session B only

    # projector left PSN empty (owned by the sessions poll collector)
    assert metrics.ise_radius_sessions_by_psn.collect()[0].samples == []


def test_batched_sessions_all_applied():
    s = _streamer()
    for ev in PxGridStreamer._normalize_events(
            {"sessions": [{"auditSessionId": "S1", "state": "STARTED"},
                          {"auditSessionId": "S2", "state": "STARTED"}]}):
        s.on_event(ev)
    assert {"S1", "S2"} <= set(s.sessions)


def test_stomp_frames_are_sent_as_websocket_binary():
    class FakeWs:
        def __init__(self):
            self.sent = []

        def send_binary(self, payload):
            self.sent.append(payload)

    s = _streamer()
    s.ws = FakeWs()
    s._send("CONNECT\n\n\x00")

    assert s.ws.sent == [b"CONNECT\n\n\x00"]


def test_connect_ws_tries_next_pubsub_url_and_subscribes_binary(monkeypatch):
    import websocket

    attempts = []
    sslopts = []

    class FakeWs:
        def __init__(self):
            self.sent = []

        def recv(self):
            return b"CONNECTED\nversion:1.2\n\n\x00"

        def send_binary(self, payload):
            self.sent.append(payload)

    def create_connection(url, **kwargs):
        attempts.append(url)
        sslopts.append(kwargs["sslopt"])
        if url == "wss://bad":
            raise OSError("down")
        return FakeWs()

    class Control(FakeControl):
        def resolve_pubsub(self):
            return "ise-node", ["wss://bad", "wss://good"], "secret"

        def session_topic(self):
            return "https://ise/session", "/topic/com.cisco.ise.session"

        def endpoint_topic(self):
            return "https://ise/endpoint", "/topic/com.cisco.ise.endpoint"

    monkeypatch.setattr(websocket, "create_connection", create_connection)

    ctl = Control()
    s = PxGridStreamer(ctl, {"hostname": {}, "location": {}, "ops_owner": {}},
                       threading.Event())
    ctl.streamer = s
    s._connect_ws()

    assert attempts == ["wss://bad", "wss://good"]
    assert sslopts[1]["cert_reqs"] == 0
    assert sslopts[1]["check_hostname"] is False
    assert all(isinstance(frame, bytes) for frame in s.ws.sent)
    assert s.ws.sent[0].startswith(b"CONNECT\n")
    # keepalive is WS ping/pong, so no STOMP heart-beat is negotiated
    assert b"heart-beat:0,0" in s.ws.sent[0]
    assert b"destination:/topic/com.cisco.ise.session" in s.ws.sent[1]
    assert b"destination:/topic/com.cisco.ise.endpoint" in s.ws.sent[2]


def test_connect_ws_fails_without_session_topic(monkeypatch):
    import websocket

    class FakeWs:
        def __init__(self):
            self.sent = []

        def recv(self):
            return b"CONNECTED\nversion:1.2\n\n\x00"

        def send_binary(self, payload):
            self.sent.append(payload)

    class Control(FakeControl):
        def resolve_pubsub(self):
            return "ise-node", ["wss://good"], "secret"

        def session_topic(self):
            raise RuntimeError("no session topic")

        def endpoint_topic(self):
            return "https://ise/endpoint", "/topic/com.cisco.ise.endpoint"

    monkeypatch.setattr(websocket, "create_connection", lambda *a, **k: FakeWs())

    ctl = Control()
    s = PxGridStreamer(ctl, {"hostname": {}, "location": {}, "ops_owner": {}},
                       threading.Event())

    with pytest.raises(RuntimeError, match="session topic"):
        s._connect_ws()


def test_sequence_gap_or_reset_requests_resync():
    s = _streamer()

    assert s._sequence_gap("session", {"sequence": 10}) is False
    assert s._sequence_gap("session", {"sequence": 11}) is False
    assert s._sequence_gap("session", {"sequence": 13}) is True

    assert s._sequence_gap("endpoint", {"sequence": 0}) is True
    assert s._sequence_gap("endpoint", {"sequence": 1}) is False


def test_recv_loop_sends_ws_ping_and_pong_refreshes_liveness(monkeypatch):
    import websocket
    monkeypatch.setattr(streaming, "_HEARTBEAT_SECS", 0.0)   # ping every iteration

    class FakeWs:
        def __init__(self):
            self.pings = 0
            self.calls = 0

        def settimeout(self, timeout):
            pass

        def recv_data(self, control_frame=False):
            self.calls += 1
            if self.calls == 1:
                return (websocket.ABNF.OPCODE_PONG, b"")   # ISE's pong to our ping
            raise RuntimeError("done")

        def ping(self, payload=b""):
            self.pings += 1

    s = _streamer()
    s.ws = FakeWs()
    s.last_recv = 0.0

    s._recv_loop()

    assert s.ws.pings >= 1        # kept alive with a WS ping, not a STOMP "\n"
    assert s.last_recv > 0.0      # a PONG counts as liveness (keeps the watchdog happy)


def test_payload_topic_detects_endpoint_payloads():
    assert PxGridStreamer._payload_topic({"endpoint": {}}) == "endpoint"
    assert PxGridStreamer._payload_topic({"endpoints": []}) == "endpoint"
    assert PxGridStreamer._payload_topic({"sessions": []}) == "session"


def test_recv_loop_resyncs_on_sequence_gap_without_applying_gap_payload():
    class Control:
        def __init__(self):
            self.cfg = _cfg()
            self.host = "px"
            self.node_name = "exporter"
            self.snapshots = 0

        def rest_query(self, service, endpoint, body=None, timeout=120):
            if endpoint == "getSessions":
                self.snapshots += 1
                return {"sessions": [{"auditSessionId": "SNAP", "state": "STARTED"}]}
            return {}

        def get_endpoints(self, **kwargs):
            return []

    class FakeWs:
        def __init__(self):
            self.frames = [
                b'MESSAGE\n\n{"sequence":1,"sessions":[{"auditSessionId":"S1","state":"STARTED"}]}\x00',
                b'MESSAGE\n\n{"sequence":3,"sessions":[{"auditSessionId":"S2","state":"STARTED"}]}\x00',
            ]
            self.timeout = None

        def settimeout(self, timeout):
            self.timeout = timeout

        def recv_data(self, control_frame=False):
            if self.frames:
                return (0x2, self.frames.pop(0))   # OPCODE_BINARY data frame
            raise RuntimeError("done")

        def send_binary(self, payload):
            pass

        def ping(self, payload=b""):
            pass

    ctl = Control()
    streamer = PxGridStreamer(ctl, {"hostname": {}, "location": {}, "ops_owner": {}},
                              threading.Event())
    streamer.ws = FakeWs()

    streamer._recv_loop()

    assert ctl.snapshots == 1
    assert set(streamer.sessions) == {"SNAP"}


@pytest.mark.parametrize("error,expected_fragment", [
    (RuntimeError("pxGrid account is PENDING approval in ISE; retry after approval"),
     "not approved/enabled in ISE"),
    (RuntimeError("pxGrid account is DISABLED in ISE; enable it before retrying"),
     "not approved/enabled in ISE"),
    (ssl.SSLError("certificate verify failed"), "TLS/certificate error"),
    (PermissionError(13, "Permission denied"), "permission denied"),
    (RuntimeError("pxGrid pubsub returned no wsUrl"), "pubsub service not published"),
    (RuntimeError("pxGrid ServiceLookup(com.cisco.ise.pubsub): no registered node"),
     "pubsub service not published"),
    (OSError("[Errno -2] Name or service not known"), "DNS resolution failed"),
    (ConnectionRefusedError("Connection refused"), "connection refused"),
    (TimeoutError("connection timed out"), "timed out"),
    (ValueError("something unrelated"), "ValueError: something unrelated"),
])
def test_classify_stream_error(error, expected_fragment):
    assert expected_fragment in _classify_stream_error(error)
