"""pxGrid streaming engine. Event-sourced: topic events mutate two state dicts
(sessions, endpoints) in O(1); a projector thread recomputes every gauge from
current state on a timer. That's what makes the move pay off at scale — the
per-MAC fan-out disappears because the streamed session object already carries
its authz context, and metric cost is bounded by state size, not event rate.

Lifecycle (connect -> subscribe+buffer -> snapshot -> drain[newer wins] -> live):
events arriving during the snapshot window are buffered and replayed AFTER the
snapshot lands, so a DISCONNECT that races a stale ACTIVE snapshot correctly wins.
Four threads: supervisor (connect/bootstrap/reconnect-with-backoff), receive loop,
projector, maintenance (watchdog + hourly forced resync).

Feeds: sessions + authz(passed) + endpoint models. Does NOT feed failed-auth /
policy-set / matched-rule — those have no home on the session topic, so the poll
collectors keep owning them.

NOTE: _connect_ws/_recv_loop/_send below are the minimal hand-rolled STOMP/WSS
transport. The state machine (bootstrap/drain/project) is transport-agnostic — to
use the proven in-house WSS client, swap those three methods and keep the rest."""
import json
import logging
import threading
import time
from collections import defaultdict

from . import metrics
from .util import clear_metric, normalize_mac, first_nonempty
from .clients.pxgrid import SESSION_SERVICE, ENDPOINT_SERVICE
from .collectors.devices import nad_labels
from .collectors import models

logger = logging.getLogger(__name__)

_GONE_STATES = {"DISCONNECTED", "TERMINATED", "STOPPED", "DISCONNECT"}


def _session_key(s):
    return (s.get("auditSessionId") or s.get("audit_session_id")
            or s.get("callingStationId") or s.get("calling_station_id") or s.get("id") or "")


def _endpoint_key(e):
    return normalize_mac(first_nonempty(e, "macAddress", "MACAddress", "mac")) or e.get("id", "")


def _session_state(s):
    return (s.get("state") or s.get("status") or "").upper()


class PxGridStreamer:
    def __init__(self, control, mappings, shutdown):
        self.ctl = control
        self.cfg = control.cfg
        self.nad = mappings          # shared dict, kept fresh by collectors/devices.py
        self.shutdown = shutdown

        self.sessions = {}           # key -> session attr dict
        self.endpoints = {}          # key -> endpoint attr dict
        self.lock = threading.RLock()
        self.buffer = []             # events captured during bootstrap
        self.syncing = False
        self.connected = False
        self.last_event = 0.0
        self.ws = None
        self._stop = threading.Event()   # per-connection stop signal

    # ---- event ingestion -------------------------------------------------
    def on_event(self, event):
        """Topic-event entrypoint. Buffers during bootstrap, applies live otherwise."""
        with self.lock:
            self.last_event = time.time()
            topic = event.get("topic", "session")
            metrics.ise_pxgrid_events_total.labels(
                topic=topic, phase="buffered" if self.syncing else "live").inc()
            if self.syncing:
                self.buffer.append(event)
            else:
                self._apply(event)

    def _apply(self, event):
        topic = event.get("topic", "session")
        if topic == "session" and "session" in event:
            self._apply_session(event["session"])
        elif topic == "endpoint" and "endpoint" in event:
            self._apply_endpoint(event["endpoint"])

    def _apply_session(self, s):
        key = _session_key(s)
        if not key:
            return
        if _session_state(s) in _GONE_STATES:
            self.sessions.pop(key, None)
        else:
            self.sessions[key] = s

    def _apply_endpoint(self, e):
        key = _endpoint_key(e)
        if not key:
            return
        if (e.get("state") or "").upper() in ("DELETED", "DISCONNECTED"):
            self.endpoints.pop(key, None)
        else:
            self.endpoints[key] = e

    # ---- bootstrap: snapshot then drain (newer wins) ---------------------
    def _bootstrap(self, reason):
        with self.lock:
            self.syncing = True
            self.buffer.clear()      # events can only arrive after the in-bootstrap subscribe

        # snapshots run WITHOUT the lock held, so racing events land in the buffer
        snap_sessions = self._snapshot_sessions()
        snap_endpoints = self._snapshot_endpoints()

        with self.lock:
            self.sessions = {_session_key(s): s for s in snap_sessions
                             if _session_key(s) and _session_state(s) not in _GONE_STATES}
            self.endpoints = {_endpoint_key(e): e for e in snap_endpoints if _endpoint_key(e)}
            # drain: buffered events are newer than the snapshot, so they override it
            for event in self.buffer:
                self._apply(event)
            self.buffer.clear()
            self.syncing = False
        metrics.ise_pxgrid_resync_total.labels(reason=reason).inc()
        logger.info("pxGrid bootstrap(%s): %d sessions, %d endpoints",
                    reason, len(self.sessions), len(self.endpoints))

    def _snapshot(self, service, method, key):
        try:
            data = self.ctl.rest_query(service, method, {}, timeout=self.cfg.pxgrid_query_timeout)
        except Exception as e:
            logger.warning("%s snapshot failed: %s", method, e)
            return []
        return (data or {}).get(key, []) if isinstance(data, dict) else (data or [])

    def _snapshot_sessions(self):
        return self._snapshot(SESSION_SERVICE, "getSessions", "sessions")

    def _snapshot_endpoints(self):
        return self._snapshot(ENDPOINT_SERVICE, "getEndpoints", "endpoints")

    # ---- projection: state -> gauges -------------------------------------
    def project(self):
        with self.lock:
            sessions = list(self.sessions.values())
            endpoints = list(self.endpoints.values())

        metrics.ise_active_sessions.set(len(sessions))
        metrics.ise_pxgrid_state_size.labels(topic="session").set(len(sessions))
        metrics.ise_pxgrid_state_size.labels(topic="endpoint").set(len(endpoints))

        by_nad = defaultdict(int)
        by_owner = defaultdict(int)
        by_psn = defaultdict(int)
        status_ep = defaultdict(set)
        method_ep = defaultdict(set)
        profile_ep = defaultdict(set)

        for s in sessions:
            nad_name = first_nonempty(s, "nasName", "networkDeviceName", "network_device_name")
            nas_ip = first_nonempty(s, "nasIpAddress", "nas_ip_address")
            host, loc, owner = nad_labels(self.nad, nas_ip, name_hint=nad_name or None)
            psn = first_nonempty(s, "pxGridNode", "server", "psnNodeName") or "stream"
            mac = normalize_mac(first_nonempty(s, "macAddress", "callingStationId", "calling_station_id"))

            by_nad[(host, loc)] += 1
            by_owner[owner] += 1
            by_psn[psn] += 1

            status_ep[(host, loc, owner, "passed")].add(mac)
            method = first_nonempty(s, "authenticationMethod", "authProtocol")
            if method:
                method_ep[(method, host, loc, owner)].add(mac)
            profiles = s.get("selectedAuthzProfiles") or s.get("ANCpolicy") or []
            if isinstance(profiles, str):
                profiles = [profiles]
            for prof in profiles:
                profile_ep[(prof, host, loc, owner)].add(mac)

        for m in (metrics.ise_radius_sessions_by_nad, metrics.ise_radius_sessions_by_ops_owner,
                  metrics.ise_radius_sessions_by_psn, metrics.ise_session_status_endpoints,
                  metrics.ise_session_auth_methods, metrics.ise_authz_unique_endpoints_by_profile):
            clear_metric(m)
        for (host, loc), n in by_nad.items():
            metrics.ise_radius_sessions_by_nad.labels(nas_hostname=host, location=loc).set(n)
        for owner, n in by_owner.items():
            metrics.ise_radius_sessions_by_ops_owner.labels(ops_owner=owner).set(n)
        for psn, n in by_psn.items():
            metrics.ise_radius_sessions_by_psn.labels(psn=psn).set(n)
        for (host, loc, owner, status), macs in status_ep.items():
            metrics.ise_session_status_endpoints.labels(
                nad_hostname=host, location=loc, ops_owner=owner, status=status).set(len(macs))
        for (method, host, loc, owner), macs in method_ep.items():
            metrics.ise_session_auth_methods.labels(
                method=method, nad_hostname=host, location=loc, ops_owner=owner).set(len(macs))
        for (prof, host, loc, owner), macs in profile_ep.items():
            metrics.ise_authz_unique_endpoints_by_profile.labels(
                authz_profile=prof, nad_hostname=host, location=loc, ops_owner=owner).set(len(macs))

        # always emit (it clears first) so model series don't go stale when state empties
        models.emit_endpoint_metrics(endpoints)
        metrics.ise_pxgrid_last_event_timestamp.set(self.last_event)

    # ---- transport (minimal STOMP/WSS — swappable) -----------------------
    def _connect_ws(self):
        import websocket  # lazy: only needed when streaming is enabled
        peer, ws_url, secret = self.ctl.resolve_pubsub()
        if not ws_url:
            raise RuntimeError("pxGrid pubsub returned no wsUrl")
        header = [f"Authorization: Basic {self._basic(secret)}"]
        self.ws = websocket.create_connection(
            ws_url, header=header,
            sslopt={"certfile": self.cfg.pxgrid_client_cert,
                    "keyfile": self.cfg.pxgrid_client_key,
                    "ca_certs": self.cfg.pxgrid_ca_bundle or None},
            timeout=self.cfg.watchdog_timeout)
        self._send(f"CONNECT\naccept-version:1.2\nhost:{self.ctl.host}\n\n\x00")
        for topic in self._topics():
            self._send(f"SUBSCRIBE\nid:{topic}\ndestination:{topic}\n\n\x00")

    def _basic(self, secret):
        import base64
        raw = f"{self.ctl.node_name}:{secret}".encode()
        return base64.b64encode(raw).decode()

    def _topics(self):
        topics = []
        for name, resolve in (("session", self.ctl.session_topic),
                              ("endpoint", self.ctl.endpoint_topic)):
            try:
                _, topic = resolve()
                if topic:
                    topics.append(topic)
            except Exception as e:
                logger.warning("%s topic resolve failed: %s", name, e)
        return topics

    def _send(self, frame):
        if self.ws:
            self.ws.send(frame)

    def _close_ws(self):
        if self.ws:
            try:
                self.ws.close()
            except Exception:
                pass
            self.ws = None

    def _recv_loop(self):
        while not self._stop.is_set() and not self.shutdown.is_set():
            try:
                raw = self.ws.recv()
            except Exception as e:
                logger.info("recv loop ended: %s", e)
                break
            if not raw:
                continue
            body = self._stomp_body(raw)
            if not body:
                continue
            try:
                payload = json.loads(body)
            except ValueError:
                continue
            self.on_event(self._normalize(payload))
        self._stop.set()

    @staticmethod
    def _stomp_body(frame):
        """Extract the JSON body from a STOMP MESSAGE frame (header\\n\\nbody\\x00)."""
        if isinstance(frame, bytes):
            frame = frame.decode("utf-8", "replace")
        if "\n\n" not in frame:
            return ""
        return frame.split("\n\n", 1)[1].rstrip("\x00").strip()

    @staticmethod
    def _normalize(payload):
        """Map a topic payload to our internal event shape."""
        if "sessions" in payload:
            return {"topic": "session", "session": payload["sessions"][0]}
        if "session" in payload:
            return {"topic": "session", "session": payload["session"]}
        if "endpoints" in payload:
            return {"topic": "endpoint", "endpoint": payload["endpoints"][0]}
        if "endpoint" in payload:
            return {"topic": "endpoint", "endpoint": payload["endpoint"]}
        return {"topic": "session", "session": payload}

    # ---- worker threads --------------------------------------------------
    def _projector_loop(self, stop):
        while not stop.is_set() and not self.shutdown.is_set():
            try:
                self.project()
            except Exception as e:
                logger.warning("projection error: %s", e)
            stop.wait(self.cfg.project_interval)

    def _maintenance_loop(self, stop):
        last_resync = time.time()
        while not stop.is_set() and not self.shutdown.is_set():
            stop.wait(min(self.cfg.watchdog_timeout, 30))
            now = time.time()
            if self.connected and self.last_event and (now - self.last_event) > self.cfg.watchdog_timeout:
                logger.warning("pxGrid watchdog: no events for %ds, forcing reconnect",
                               int(now - self.last_event))
                stop.set()
                break
            if (now - last_resync) >= self.cfg.resync_interval:
                self._bootstrap("scheduled")
                last_resync = now

    # ---- supervisor ------------------------------------------------------
    def run(self):
        backoff = 1
        while not self.shutdown.is_set():
            stop = self._stop = threading.Event()
            try:
                self._connect_ws()
                self._bootstrap("connect")
                self.connected = True
                self.last_event = time.time()
                metrics.ise_pxgrid_connected.set(1)
                backoff = 1

                projector = threading.Thread(target=self._projector_loop, args=(stop,),
                                             name="pxgrid-project", daemon=True)
                maintenance = threading.Thread(target=self._maintenance_loop, args=(stop,),
                                               name="pxgrid-maint", daemon=True)
                projector.start()
                maintenance.start()
                self._recv_loop()    # blocks until disconnect / watchdog / shutdown
                projector.join(timeout=5)
                maintenance.join(timeout=5)
            except Exception as e:
                logger.warning("pxGrid stream error: %s", e)
            finally:
                self.connected = False
                metrics.ise_pxgrid_connected.set(0)
                self._close_ws()
                stop.set()

            if self.shutdown.is_set():
                break
            self.shutdown.wait(backoff)
            backoff = min(backoff * 2, self.cfg.reconnect_max_backoff)
        logger.info("pxGrid streamer stopped")
