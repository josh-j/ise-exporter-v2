"""Bootstrap-race test: a DISCONNECT that arrives during the snapshot window must
win over a stale ACTIVE snapshot after the buffer is drained. The disconnect is
fired from inside the fake getSessions (while syncing=True) so it lands in the
buffer; after _bootstrap drains, the disconnected session must be gone."""
import threading
import types

from ise_exporter.streaming import PxGridStreamer


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
