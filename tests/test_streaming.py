"""Bootstrap-race test: a DISCONNECT that arrives during the snapshot window must
win over a stale ACTIVE snapshot after the buffer is drained. The disconnect is
fired from inside the fake getSessions (while syncing=True) so it lands in the
buffer; after _bootstrap drains, the disconnected session must be gone."""
import ssl
import threading
import types

import pytest

from ise_exporter.streaming import PxGridStreamer, _classify_stream_error


def _cfg():
    return types.SimpleNamespace(
        pxgrid_query_timeout=5, project_interval=30, resync_interval=3600,
        watchdog_timeout=90, reconnect_max_backoff=60,
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


def test_normalize_events_empty_array_is_safe():
    # empty array used to IndexError on [0]; now yields no events
    assert PxGridStreamer._normalize_events({"sessions": []}) == []
    assert PxGridStreamer._normalize_events({"endpoints": []}) == []


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
    assert b"destination:/topic/com.cisco.ise.session" in s.ws.sent[1]
    assert b"destination:/topic/com.cisco.ise.endpoint" in s.ws.sent[2]


def test_sequence_gap_or_reset_requests_resync():
    s = _streamer()

    assert s._sequence_gap("session", {"sequence": 10}) is False
    assert s._sequence_gap("session", {"sequence": 11}) is False
    assert s._sequence_gap("session", {"sequence": 13}) is True

    assert s._sequence_gap("endpoint", {"sequence": 0}) is True
    assert s._sequence_gap("endpoint", {"sequence": 1}) is False


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

        def recv(self):
            if self.frames:
                return self.frames.pop(0)
            raise RuntimeError("done")

        def send_binary(self, payload):
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
