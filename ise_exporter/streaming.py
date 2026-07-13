"""pxGrid streaming engine. Event-sourced: topic events mutate two state dicts
(sessions, endpoints) in O(1); a projector thread recomputes every gauge from
current state on a timer. That's what makes the move pay off at scale — the
per-MAC fan-out disappears because the streamed session object already carries
its authz context, and metric cost is bounded by state size, not event rate.

Lifecycle (connect -> subscribe+buffer -> snapshot -> drain[newer wins] -> live):
events arriving during the snapshot window are buffered and replayed AFTER the
snapshot lands, so a DISCONNECT that races a stale ACTIVE snapshot correctly wins.
Four persistent threads: supervisor (connect/bootstrap/reconnect-with-backoff),
receive loop, projector, maintenance (watchdog + hourly forced resync). A fifth,
transient heartbeat-keeper thread runs only for the duration of each bootstrap
(see _bootstrap/_heartbeat_keeper) so a slow snapshot doesn't starve the STOMP
heart-beat we promised in CONNECT.

Feeds: sessions + authz(passed) + endpoint models. Does NOT feed failed-auth /
policy-set / matched-rule — those have no home on the session topic, so the poll
collectors keep owning them.

NOTE: _connect_ws/_recv_loop/_send below are the minimal hand-rolled STOMP/WSS
transport. The state machine (bootstrap/drain/project) is transport-agnostic — to
use the proven in-house WSS client, swap those three methods and keep the rest."""
import json
import logging
import ssl
import threading
import time
from collections import defaultdict

from . import metrics
from .util import (clear_metric, clear_metric_where, normalize_mac, first_nonempty,
                   normalize_posture, normalize_bool_label)
from .clients.pxgrid import SESSION_SERVICE, _as_list
from .collectors.devices import nad_labels
from .collectors import models

logger = logging.getLogger(__name__)

_GONE_STATES = {"DISCONNECTED", "TERMINATED", "STOPPED", "DISCONNECT"}

# MDM device-trust dimensions carried on the pxGrid session object. label -> the
# source attribute; each is coerced to true|false|unknown for ise_session_mdm_status.
_MDM_DIMS = (
    ("registered", "mdmRegistered"),
    ("compliant", "mdmCompliant"),
    ("disk_encrypted", "mdmDiskEncrypted"),
    ("jailbroken", "mdmJailBroken"),
    ("pin_locked", "mdmPinLocked"),
)

# Keepalive cadence. pxGrid pubsub keeps the link alive with WebSocket ping/pong
# (Cisco documents a "60 seconds ping timeout"), NOT STOMP heart-beats: ISE's STOMP
# decoder parses a bare-newline heart-beat as a frame with an empty command and closes
# the socket with `Unknown command:` (code 1011). So we negotiate heart-beat:0,0 in
# CONNECT and send a WS ping on this timer instead — a failed ping is our liveness probe
# (an idle-but-alive link just gets ponged), and ISE's pong refreshes last_recv.
_HEARTBEAT_SECS = 10

# cadence for the periodic "still healthy" heartbeat log — deliberately coarser than
# watchdog_timeout so a healthy stream doesn't spam journalctl every 30s.
_STATUS_LOG_INTERVAL = 300


def _classify_stream_error(e):
    """Best-effort plain-language reason for journalctl — a raw exception repr from a
    chained websocket/ssl/requests failure ('Connection aborted', bare OSError, etc.)
    rarely explains itself to whoever is reading the log at 2am."""
    msg = str(e)
    low = msg.lower()
    if "pending" in low or "disabled" in low:
        return f"pxGrid account not approved/enabled in ISE — {msg}"
    if isinstance(e, ssl.SSLError) or "ssl" in type(e).__name__.lower() or "certificate" in low:
        return f"TLS/certificate error — check PXGRID_CA_BUNDLE and client cert validity: {msg}"
    if isinstance(e, PermissionError) or "permission denied" in low:
        return f"permission denied opening a cert/key file, or blocked by a local firewall/egress policy: {msg}"
    if "no wsurl" in low or "pubsub service not available" in low or "no registered node" in low:
        return f"pxGrid pubsub service not published on any ISE node — {msg}"
    if "name or service not known" in low or "nodename nor servname" in low or "getaddrinfo" in low:
        return f"DNS resolution failed for PXGRID_HOST — {msg}"
    if "connection refused" in low:
        return f"connection refused — is pxGrid listening on this host:port? {msg}"
    if "timed out" in low:
        return f"connection/handshake timed out — network path or firewall issue: {msg}"
    return f"{type(e).__name__}: {msg}"


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
        # endpoint attributes come from the getEndpoints REST poll unless the live topic
        # is explicitly enabled (getattr-defaulted so minimal test cfgs still work).
        self.subscribe_endpoint_topic = getattr(self.cfg, "pxgrid_subscribe_endpoint_topic", False)
        self.endpoint_refresh_interval = getattr(self.cfg, "pxgrid_endpoint_refresh_interval", 900)

        self.sessions = {}           # key -> session attr dict
        self.endpoints = {}          # key -> endpoint attr dict
        self.lock = threading.RLock()
        self.ws_lock = threading.Lock()  # serializes writes to self.ws across threads
        self.bootstrap_lock = threading.Lock()  # serializes concurrent resyncs (see _bootstrap)
        self.buffer = []             # events captured during bootstrap
        self.syncing = False
        self.connected = False
        self.last_event = 0.0     # last topic EVENT (session/endpoint change)
        self.last_recv = 0.0      # last FRAME of any kind, incl. server heartbeats
        self.last_sequence = {}   # topic -> last pxGrid sequence number seen
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
    def _heartbeat_keeper(self, stop):
        """getSessions/getEndpoints are plain REST calls (their own HTTPS
        connection, not the WSS pubsub socket) but they block whichever thread
        calls _bootstrap — including _recv_loop's, for gap/scheduled resyncs —
        for as long as they take. A large deployment (tens of thousands of
        sessions) can make that longer than ISE's pubsub ping timeout, so keep the
        WS ping going from a side thread for the duration; otherwise ISE sees a
        silent client mid-bootstrap and closes the socket right as the (perfectly
        good) snapshot lands."""
        while not stop.wait(_HEARTBEAT_SECS):
            try:
                self._ping()
            except Exception:
                return

    def _bootstrap(self, reason):
        # Serialize resyncs: a gap-resync (recv thread, _recv_loop) and a scheduled-resync
        # (maintenance thread, _maintenance_loop) must not run concurrently — one would
        # clear the buffer / rebuild state the other is mid-snapshot on, losing buffered
        # events and clobbering state. Neither caller holds self.lock here and the order is
        # always bootstrap_lock -> lock, so there's no deadlock.
        with self.bootstrap_lock:
            self._bootstrap_locked(reason)

    def _bootstrap_locked(self, reason):
        with self.lock:
            self.syncing = True
            self.buffer.clear()      # events can only arrive after the in-bootstrap subscribe

        # snapshots run WITHOUT the lock held, so racing events land in the buffer.
        # Keep the STOMP heart-beat alive for their (possibly long) duration.
        hb_stop = threading.Event()
        hb_thread = threading.Thread(target=self._heartbeat_keeper, args=(hb_stop,), daemon=True)
        hb_thread.start()
        try:
            snap_sessions = self._snapshot_sessions()
            snap_endpoints = self._snapshot_endpoints()
        finally:
            hb_stop.set()
            hb_thread.join(timeout=2)

        with self.lock:
            # None == snapshot failed: keep last-known state rather than wiping populated
            # gauges to zero on a transient error during a scheduled/gap resync. [] is a
            # genuine empty result and does replace state.
            if snap_sessions is not None:
                self.sessions = {_session_key(s): s for s in snap_sessions
                                 if _session_key(s) and _session_state(s) not in _GONE_STATES}
            if snap_endpoints is not None:
                self.endpoints = {_endpoint_key(e): e for e in snap_endpoints if _endpoint_key(e)}
            # drain: buffered events are newer than the snapshot, so they override it
            for event in self.buffer:
                self._apply(event)
            self.buffer.clear()
            self.syncing = False
        metrics.ise_pxgrid_resync_total.labels(reason=reason).inc()
        logger.info("pxGrid bootstrap(%s): %d sessions, %d endpoints",
                    reason, len(self.sessions), len(self.endpoints))
        if snap_sessions and snap_endpoints is not None and not snap_endpoints:
            logger.info("pxGrid bootstrap: got %d sessions but 0 endpoints. This is expected "
                        "on ISE 3.3; endpoint inventory/profiler metrics come from ERS, "
                        "and pxGrid endpoint snapshots remain optional enrichment.",
                        len(snap_sessions))

    def _snapshot(self, service, method, key):
        """Returns the snapshot list, [] for a genuinely-empty result, or None when the
        query failed — the None lets _bootstrap preserve last-known state instead of
        wiping it on a transient error (see _bootstrap)."""
        try:
            data = self.ctl.rest_query(service, method, {}, timeout=self.cfg.pxgrid_query_timeout)
        except Exception as e:
            logger.warning("%s snapshot failed: %s", method, e)
            return None
        return (data or {}).get(key, []) if isinstance(data, dict) else (data or [])

    def _snapshot_sessions(self):
        return self._snapshot(SESSION_SERVICE, "getSessions", "sessions")

    def _snapshot_endpoints(self):
        if not models.pxgrid_endpoint_poll_due(self.cfg):
            metrics.ise_endpoints_pxgrid_total.set(0)
            logger.info("getEndpoints snapshot skipped: empty endpoint feed backoff active; "
                        "using ERS endpoint baseline")
            return []
        try:
            endpoints = self.ctl.get_endpoints(timeout=self.cfg.pxgrid_query_timeout)
        except Exception as e:
            logger.warning("getEndpoints snapshot failed: %s", e)
            return None
        models.record_pxgrid_endpoint_result(len(endpoints), self.cfg)
        if not endpoints:
            metrics.ise_endpoints_pxgrid_total.set(0)
        return endpoints

    def _refresh_endpoints(self):
        """Refresh just the endpoint snapshot via getEndpoints — endpoint attributes
        (models/profiles/posture) come from this REST poll, not the endpoint topic.
        Keeps last-known state on an empty/failed read rather than wiping to zero."""
        snap = self._snapshot_endpoints()
        if snap is None:
            return
        with self.lock:
            self.endpoints = {_endpoint_key(e): e for e in snap if _endpoint_key(e)}
        logger.info("pxGrid endpoint refresh: %d endpoints", len(self.endpoints))

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
        status_ep = defaultdict(set)
        method_ep = defaultdict(set)
        profile_ep = defaultdict(set)
        posture_ep = defaultdict(set)   # (status, loc, owner) -> {mac}
        mdm_ep = defaultdict(set)       # (dimension, value, owner) -> {mac}
        mac_owner = {}                  # MAC -> ops_owner, to label endpoint posture

        # NB: no by-PSN breakdown here. The pxGrid session directory object carries no
        # owning-PSN field (nasIpAddress etc. yes, psnNodeName/server no), so it cannot
        # be derived from the stream. ise_radius_sessions_by_psn is owned exclusively by
        # the sessions poll collector (MnT ActiveList `server`), which now runs alongside
        # the stream in a PSN-only mode — so the projector must NOT clear or set it here,
        # or the two would fight. Site-level grouping comes from the `location` label on
        # ise_radius_sessions_by_nad (and ise_session_posture_status below).
        for s in sessions:
            nad_name = first_nonempty(s, "nasName", "networkDeviceName", "network_device_name")
            nas_ip = first_nonempty(s, "nasIpAddress", "nas_ip_address")
            host, loc, owner = nad_labels(self.nad, nas_ip, name_hint=nad_name or None)
            mac = normalize_mac(first_nonempty(s, "macAddress", "callingStationId", "calling_station_id"))

            by_nad[(host, loc)] += 1
            by_owner[owner] += 1
            if mac:
                mac_owner[mac] = owner

            status_ep[(host, loc, owner, "passed")].add(mac)
            method = first_nonempty(s, "authenticationMethod", "authProtocol")
            if method:
                method_ep[(method, host, loc, owner)].add(mac)
            profiles = s.get("selectedAuthzProfiles") or s.get("ANCpolicy") or []
            if isinstance(profiles, str):
                profiles = [profiles]
            for prof in profiles:
                profile_ep[(prof, host, loc, owner)].add(mac)

            posture_ep[(normalize_posture(first_nonempty(s, "postureStatus", "posture_status")),
                        loc, owner)].add(mac)
            # only project MDM for MDM-managed sessions — otherwise every non-enrolled
            # endpoint floods the metric as dimension=*/value=unknown.
            if first_nonempty(s, "mdmRegistered", "mdmCompliant", "mdmDeviceManager", "mdmManufacturer"):
                for dim, attr in _MDM_DIMS:
                    mdm_ep[(dim, normalize_bool_label(s.get(attr)), owner)].add(mac)

        for m in (metrics.ise_radius_sessions_by_nad, metrics.ise_radius_sessions_by_ops_owner,
                  metrics.ise_session_auth_methods, metrics.ise_authz_unique_endpoints_by_profile,
                  metrics.ise_session_posture_status, metrics.ise_session_mdm_status):
            clear_metric(m)
        # only clear our own status="passed" slice — authz owns status="failed" on this
        # same metric (failed auths aren't sessions), so a full clear would wipe it.
        clear_metric_where(metrics.ise_session_status_endpoints, status="passed")
        for (host, loc), n in by_nad.items():
            metrics.ise_radius_sessions_by_nad.labels(nas_hostname=host, location=loc).set(n)
        for owner, n in by_owner.items():
            metrics.ise_radius_sessions_by_ops_owner.labels(ops_owner=owner).set(n)
        # ise_radius_sessions_by_psn is poll-owned even in stream mode (see above)
        for (host, loc, owner, status), macs in status_ep.items():
            metrics.ise_session_status_endpoints.labels(
                nad_hostname=host, location=loc, ops_owner=owner, status=status).set(len(macs))
        for (method, host, loc, owner), macs in method_ep.items():
            metrics.ise_session_auth_methods.labels(
                method=method, nad_hostname=host, location=loc, ops_owner=owner).set(len(macs))
        for (prof, host, loc, owner), macs in profile_ep.items():
            metrics.ise_authz_unique_endpoints_by_profile.labels(
                authz_profile=prof, nad_hostname=host, location=loc, ops_owner=owner).set(len(macs))
        for (status, loc, owner), macs in posture_ep.items():
            metrics.ise_session_posture_status.labels(
                status=status, location=loc, ops_owner=owner).set(len(macs))
        for (dim, val, owner), macs in mdm_ep.items():
            metrics.ise_session_mdm_status.labels(dimension=dim, value=val, ops_owner=owner).set(len(macs))

        # always emit (it clears first) so model series don't go stale when state empties.
        # pxgrid is passed so the profiler category/parent hierarchy stays joined in
        # stream mode too — the refresh itself is TTL-gated, safe to call every tick.
        # mac_owner labels endpoint-sourced posture (PostureReport) by the ops owner of
        # the endpoint's live session.
        models.emit_endpoint_metrics(endpoints, pxgrid=self.ctl,
                                     hierarchy_ttl=self.cfg.profiler_hierarchy_ttl,
                                     mac_owner=mac_owner)
        metrics.ise_pxgrid_last_event_timestamp.set(self.last_event)

    # ---- transport (minimal STOMP/WSS — swappable) -----------------------
    def _connect_ws(self):
        import websocket  # lazy: only needed when streaming is enabled
        peer, ws_urls, secret = self.ctl.resolve_pubsub()
        if not ws_urls:
            raise RuntimeError("pxGrid pubsub returned no wsUrl")
        if isinstance(ws_urls, str):
            ws_urls = [ws_urls]
        logger.info("pxGrid pubsub: peer=%s ws_urls=%s", peer, ws_urls)
        header = [f"Authorization: Basic {self._basic(secret)}"]
        sslopt = {"certfile": self.cfg.pxgrid_client_cert,
                  "keyfile": self.cfg.pxgrid_client_key,
                  "cert_reqs": ssl.CERT_REQUIRED if self.cfg.pxgrid_ca_bundle else ssl.CERT_NONE}
        if self.cfg.pxgrid_ca_bundle:
            sslopt["ca_certs"] = self.cfg.pxgrid_ca_bundle
        else:
            sslopt["check_hostname"] = False
        last_error = None
        for ws_url in ws_urls:
            try:
                self.ws = websocket.create_connection(
                    ws_url, header=header,
                    sslopt=sslopt,
                    timeout=self.cfg.watchdog_timeout)
                break
            except Exception as e:
                last_error = e
                logger.warning("pxGrid pubsub connect failed for %s: %s", ws_url, e)
        if not self.ws:
            raise RuntimeError(f"pxGrid pubsub connect failed for all wsUrl values: {last_error}")
        # heart-beat:0,0 — no STOMP heart-beats; keepalive is WebSocket ping/pong (ISE
        # rejects a bare-newline STOMP heart-beat with "Unknown command:" and closes).
        self._send(f"CONNECT\naccept-version:1.2\n"
                   f"heart-beat:0,0\n"
                   f"host:{self.ctl.host}\n\n\x00")
        self._await_connected()
        topics = self._topics()
        session_topic = topics.get("session")
        if not session_topic:
            raise RuntimeError("pxGrid session topic not available; stream mode cannot run")
        if not self.subscribe_endpoint_topic:
            logger.info("pxGrid endpoint topic subscription disabled "
                        "(PXGRID_SUBSCRIBE_ENDPOINT_TOPIC=false) — endpoint attributes "
                        "(models/profiles/posture) come from the getEndpoints REST poll, "
                        "refreshed every %ds", self.endpoint_refresh_interval)
        elif not topics.get("endpoint"):
            logger.warning("pxGrid endpoint topic requested but not advertised by ISE — "
                           "falling back to getEndpoints snapshots. ISE only publishes this "
                           "topic when Administration > System > Profiling has BOTH 'Profiler "
                           "Forwarder Persistence Queue' and 'Custom Attribute for Profiling "
                           "Enforcement' enabled.")
        # log each destination exactly as sent — a rejected/typoed topic is otherwise
        # invisible (STOMP SUBSCRIBE isn't acked; ISE just drops the connection). id and
        # destination are always the same value, straight from ServiceLookup.
        for name, topic in topics.items():
            logger.info("pxGrid SUBSCRIBE %s topic -> %s", name, topic)
            self._send(f"SUBSCRIBE\nid:{topic}\ndestination:{topic}\n\n\x00")
        logger.info("pxGrid WSS connected, subscribed to %d topic(s): %s",
                    len(topics), list(topics.values()))

    def _basic(self, secret):
        import base64
        raw = f"{self.ctl.node_name}:{secret}".encode()
        return base64.b64encode(raw).decode()

    def _topics(self):
        topics = {}
        resolvers = [("session", self.ctl.session_topic)]
        # endpoint attributes come from the getEndpoints REST poll by default; only
        # resolve/subscribe the live endpoint topic when explicitly opted in.
        if self.subscribe_endpoint_topic:
            resolvers.append(("endpoint", self.ctl.endpoint_topic))
        for name, resolve in resolvers:
            try:
                _, topic = resolve()
                if topic:
                    topics[name] = topic
            except Exception as e:
                logger.warning("%s topic resolve failed: %s", name, e)
        return topics

    def _send(self, frame):
        # locked: _bootstrap's heartbeat keeper (a side thread) and _recv_loop's own
        # heartbeat can both be sending around a scheduled/gap-triggered resync —
        # the underlying socket write isn't safe to call concurrently from two threads.
        with self.ws_lock:
            if self.ws:
                payload = frame.encode("utf-8") if isinstance(frame, str) else frame
                if hasattr(self.ws, "send_binary"):
                    self.ws.send_binary(payload)
                else:
                    self.ws.send(payload, opcode=0x2)

    def _ping(self):
        """Send a WebSocket PING (transport keepalive + liveness probe). Serialized
        with _send via ws_lock — the socket write isn't safe from two threads."""
        with self.ws_lock:
            if self.ws:
                self.ws.ping()

    def _await_connected(self):
        """Wait for the STOMP CONNECTED frame before subscribing."""
        deadline = time.time() + self.cfg.watchdog_timeout
        while time.time() < deadline and not self.shutdown.is_set():
            raw = self.ws.recv()
            self.last_recv = time.time()
            if isinstance(raw, bytes):
                raw = raw.decode("utf-8", "replace")
            command = raw.split("\n", 1)[0].strip()
            if command == "CONNECTED":
                return
            if command == "ERROR":
                body = self._stomp_body(raw) or raw
                raise RuntimeError(f"pxGrid STOMP CONNECT failed: {body[:300]}")
            if not command:
                continue
            logger.debug("pxGrid ignoring pre-CONNECTED STOMP frame: %s", command)
        raise RuntimeError("pxGrid STOMP CONNECT timed out")

    def _close_ws(self):
        if self.ws:
            try:
                self.ws.close()
            except Exception:
                pass
            self.ws = None

    def _recv_loop(self):
        import websocket  # for the timeout exception type + ABNF control opcodes
        # short recv timeout so the loop wakes to send pings / check stop flags
        # regardless of event traffic — decoupled from watchdog_timeout on purpose.
        self.ws.settimeout(_HEARTBEAT_SECS)
        last_hb = time.time()
        while not self._stop.is_set() and not self.shutdown.is_set():
            opcode, raw = None, None
            try:
                # control_frame=True surfaces PING/PONG so ISE's pong to our ping (and
                # any server ping) refreshes last_recv — an idle link otherwise reads
                # as dead. websocket-client still auto-pongs incoming pings for us.
                opcode, raw = self.ws.recv_data(control_frame=True)
            except websocket.WebSocketTimeoutException:
                pass                  # idle tick — NOT a dead connection
            except Exception as e:
                logger.info("pxGrid recv loop ended: %s", e)
                break

            now = time.time()
            # the WS ping doubles as a liveness probe: a dead socket makes the send
            # raise and we reconnect; an idle-but-alive one just gets ponged.
            if now - last_hb >= _HEARTBEAT_SECS:
                try:
                    self._ping()
                except Exception as e:
                    logger.info("pxGrid ping send failed, reconnecting: %s", e)
                    break
                last_hb = now

            if opcode == websocket.ABNF.OPCODE_CLOSE:
                logger.info("pxGrid recv loop: server sent CLOSE frame")
                break
            if opcode in (websocket.ABNF.OPCODE_PING, websocket.ABNF.OPCODE_PONG):
                self.last_recv = now  # transport keepalive proves the link is live
                continue
            if not raw:
                continue
            self.last_recv = now      # any data frame proves liveness
            body = self._stomp_body(raw)
            if not body:
                continue              # non-body frame
            try:
                payload = json.loads(body)
            except ValueError:
                continue
            topic = self._payload_topic(payload)
            if self._sequence_gap(topic, payload):
                logger.warning("pxGrid %s sequence gap/reset detected; refreshing snapshot", topic)
                self._bootstrap(f"{topic}-sequence-gap")
                continue
            # one malformed/empty frame must not tear down the stream: iterate the
            # whole batch and guard each apply so a bad event is dropped, not fatal.
            for event in self._normalize_events(payload):
                try:
                    self.on_event(event)
                except Exception as e:
                    logger.warning("pxGrid event apply failed (dropped): %s", e)
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
    def _payload_topic(payload):
        if "endpoints" in payload or "endpoint" in payload:
            return "endpoint"
        return "session"

    def _sequence_gap(self, topic, payload):
        if "sequence" not in payload:
            return False
        try:
            seq = int(payload["sequence"])
        except (TypeError, ValueError):
            logger.warning("pxGrid %s payload has invalid sequence: %r", topic, payload["sequence"])
            return False

        prev = self.last_sequence.get(topic)
        self.last_sequence[topic] = seq
        if seq == 0:
            return True
        return prev is not None and seq != prev + 1

    @staticmethod
    def _normalize_events(payload):
        """Map a topic payload to a LIST of internal event shapes. Handles batched
        arrays (all elements, not just [0]) and empty arrays (returns [])."""
        if "sessions" in payload:
            return [{"topic": "session", "session": s}
                    for s in _as_list(payload["sessions"], "session")]
        if "session" in payload:
            return [{"topic": "session", "session": s}
                    for s in _as_list(payload["session"], "session")]
        if "endpoints" in payload:
            return [{"topic": "endpoint", "endpoint": e}
                    for e in _as_list(payload["endpoints"], "endpoint")]
        if "endpoint" in payload:
            return [{"topic": "endpoint", "endpoint": e}
                    for e in _as_list(payload["endpoint"], "endpoint")]
        return [{"topic": "session", "session": payload}]

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
        last_ep_refresh = time.time()
        last_status_log = 0.0
        while not stop.is_set() and not self.shutdown.is_set():
            stop.wait(min(self.cfg.watchdog_timeout, 30))
            now = time.time()
            # positive confirmation on a slow, fixed cadence — otherwise "working" is
            # only ever inferred from the absence of errors, which is indistinguishable
            # from "nobody's looked at the logs in a while."
            if self.connected and (now - last_status_log) >= _STATUS_LOG_INTERVAL:
                with self.lock:
                    n_sessions, n_endpoints = len(self.sessions), len(self.endpoints)
                age = int(now - self.last_recv) if self.last_recv else -1
                logger.info("pxGrid stream healthy: sessions=%d endpoints=%d last_frame=%ds_ago",
                            n_sessions, n_endpoints, age)
                last_status_log = now
            # liveness is "any frame received", not "a topic event" — with STOMP
            # heart-beats a quiet-but-healthy link keeps last_recv fresh, so idle
            # periods no longer force a reconnect (only a genuinely silent link does).
            if self.connected and self.last_recv and (now - self.last_recv) > self.cfg.watchdog_timeout:
                logger.warning("pxGrid watchdog: no frames for %ds (timeout=%ds) — forcing reconnect; "
                               "session/endpoint metrics will go stale until it reconnects",
                               int(now - self.last_recv), self.cfg.watchdog_timeout)
                stop.set()
                break
            if (now - last_resync) >= self.cfg.resync_interval:
                self._bootstrap("scheduled")
                last_resync = now
                last_ep_refresh = now   # bootstrap already re-snapshotted endpoints
            # refresh endpoint attributes (models/posture) from getEndpoints between full
            # resyncs — this is the source when the endpoint topic isn't subscribed.
            elif (self.connected and not self.subscribe_endpoint_topic
                    and (now - last_ep_refresh) >= self.endpoint_refresh_interval):
                self._refresh_endpoints()
                last_ep_refresh = now

    # ---- supervisor ------------------------------------------------------
    def run(self):
        backoff = 1
        down_since = None   # None while connected; set to the time a failure/disconnect began
        logger.info("pxGrid streamer starting: host=%s node_name=%s",
                    self.ctl.host, self.ctl.node_name)
        while not self.shutdown.is_set():
            stop = self._stop = threading.Event()
            try:
                logger.info("pxGrid connecting to %s ...", self.ctl.host)
                self._connect_ws()
                self._bootstrap("connect")
                self.connected = True
                self.last_event = self.last_recv = time.time()
                metrics.ise_pxgrid_connected.set(1)
                if down_since is None:
                    logger.info("pxGrid STREAM UP: host=%s node_name=%s", self.ctl.host, self.ctl.node_name)
                else:
                    logger.info("pxGrid STREAM UP: recovered after %ds down", int(time.time() - down_since))
                    down_since = None
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
                if down_since is None and not self.shutdown.is_set():
                    down_since = time.time()
                    logger.warning("pxGrid STREAM DOWN: connection closed, reconnecting")
            except Exception as e:
                if down_since is None:
                    down_since = time.time()
                logger.warning("pxGrid STREAM DOWN: %s", _classify_stream_error(e))
            finally:
                self.connected = False
                metrics.ise_pxgrid_connected.set(0)
                self._close_ws()
                stop.set()

            if self.shutdown.is_set():
                break
            logger.info("pxGrid reconnecting in %ds (down for %ds so far)",
                        backoff, int(time.time() - down_since) if down_since else 0)
            self.shutdown.wait(backoff)
            backoff = min(backoff * 2, self.cfg.reconnect_max_backoff)
        logger.info("pxGrid streamer stopped")
