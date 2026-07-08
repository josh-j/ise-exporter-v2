"""pxGrid 2.0 control plane: ServiceLookup / AccessSecret / generic rest_query,
plus pubsub + topic resolution for the streaming engine. Used by BOTH the bulk
model collector (collectors/models.py -> getEndpoints) and the streamer
(streaming.py -> getSessions snapshot + WSS topics).

Pure transport — imports nothing from metrics."""
import logging
import os
import requests
from requests.auth import HTTPBasicAuth

logger = logging.getLogger(__name__)

SESSION_SERVICE = "com.cisco.ise.session"
ENDPOINT_SERVICE = "com.cisco.ise.endpoint"
PUBSUB_SERVICE = "com.cisco.ise.pubsub"
PROFILER_SERVICE = "com.cisco.ise.config.profiler"
ENDPOINT_BULK_START = "1970-01-01T00:00:00.000Z"
ENDPOINT_PAGE_SIZE = 1000


def _as_list(value, singular_key=None):
    """Normalize Cisco's small response-shape differences into a list."""
    if value is None:
        return []
    if isinstance(value, list):
        return value
    if isinstance(value, dict) and singular_key:
        nested = value.get(singular_key) or value.get(singular_key.capitalize())
        if nested is not None:
            return _as_list(nested)
    return [value]


def _rest_base(props):
    """Endpoint/ANC docs spell it restBaseUrl; session docs restBaseURL — read both."""
    return props.get("restBaseUrl") or props.get("restBaseURL")


def _check_path(path, label):
    """Surface a bad cert/key/CA path at startup instead of as a wrapped
    'Connection aborted' / 'invalid path' error the first time it's used."""
    if not path:
        return
    if not os.path.isfile(path):
        logger.error("pxGrid %s not found: %s — pxGrid calls will fail until this exists", label, path)
    elif not os.access(path, os.R_OK):
        logger.error("pxGrid %s not readable (permission denied) by this process: %s", label, path)


class PxGridControl:
    def __init__(self, cfg):
        self.cfg = cfg
        self.host = cfg.pxgrid_host
        self.node_name = cfg.pxgrid_node_name
        self.control_base = f"https://{cfg.pxgrid_host}:{cfg.pxgrid_port}/pxgrid/control"
        self.session = requests.Session()
        self.session.cert = (cfg.pxgrid_client_cert, cfg.pxgrid_client_key)
        self.session.verify = cfg.pxgrid_ca_bundle or False
        # don't let an ambient REQUESTS_CA_BUNDLE/CURL_CA_BUNDLE override our verify
        # choice (it silently forces verification when we intend verify=False).
        self.session.trust_env = False
        self.session.auth = HTTPBasicAuth(cfg.pxgrid_node_name, "")
        self.session.headers.update({"Content-Type": "application/json",
                                     "Accept": "application/json"})
        # cache of resolved (peer_node, rest_base, secret) keyed by service name
        self._svc = {}
        self._activated = False
        logger.info("pxGrid control: host=%s port=%s node_name=%s cert=%s key=%s",
                    self.host, cfg.pxgrid_port, self.node_name,
                    cfg.pxgrid_client_cert, cfg.pxgrid_client_key)
        _check_path(cfg.pxgrid_client_cert, "client cert")
        _check_path(cfg.pxgrid_client_key, "client key")
        _check_path(cfg.pxgrid_ca_bundle, "CA bundle")
        if cfg.pxgrid_ca_bundle:
            logger.info("pxGrid TLS verify ON (ca=%s)", cfg.pxgrid_ca_bundle)
        else:
            # the control channel carries the per-service access secrets — unverified
            # TLS exposes them to MITM. Set PXGRID_CA_BUNDLE in production.
            logger.warning("pxGrid TLS verify OFF — no PXGRID_CA_BUNDLE set; "
                           "server certificate is NOT validated (set it in production)")

    def _control_post(self, op, body):
        url = f"{self.control_base}/{op}"
        logger.debug("pxGrid control POST %s body=%s", url, body or {})
        try:
            r = self.session.post(url, json=body or {}, timeout=30)
            r.raise_for_status()
        except requests.exceptions.HTTPError as e:
            code = e.response.status_code if e.response is not None else 0
            body_txt = e.response.text[:300] if e.response is not None else ""
            logger.warning("pxGrid %s -> HTTP %s: %s", op, code, body_txt)
            raise
        except requests.exceptions.RequestException as e:
            # connection refused / TLS handshake / timeout — the common "nothing in ISE" causes
            logger.warning("pxGrid %s -> transport error: %s", op, e)
            raise
        return r.json()

    def account_activate(self):
        """Activate this pxGrid account before service access.

        Certificate-authenticated consumers send Basic auth as "nodeName:" and may
        need an ISE admin approval before the controller returns ENABLED.
        """
        if self._activated:
            return {"accountState": "ENABLED"}
        data = self._control_post("AccountActivate", {"description": "ise-exporter"})
        state = (data.get("accountState") or "").upper()
        version = data.get("version", "unknown")
        logger.info("pxGrid AccountActivate: state=%s version=%s", state or "UNKNOWN", version)
        if state == "ENABLED":
            self._activated = True
            return data
        if state == "PENDING":
            raise RuntimeError("pxGrid account is PENDING approval in ISE; retry after approval")
        if state == "DISABLED":
            raise RuntimeError("pxGrid account is DISABLED in ISE; enable it before retrying")
        raise RuntimeError(f"pxGrid AccountActivate returned unexpected state: {state or data!r}")

    def _ensure_active(self):
        if not self._activated:
            self.account_activate()

    def service_lookup_all(self, service_name):
        """Return all registered service node properties for a service."""
        self._ensure_active()
        data = self._control_post("ServiceLookup", {"name": service_name})
        services = data.get("services", [])
        if not services:
            logger.warning("pxGrid ServiceLookup(%s): no registered node "
                           "(account not approved, or service unavailable)", service_name)
            return []
        logger.info("pxGrid ServiceLookup(%s): nodes=%s", service_name,
                    ", ".join(s.get("nodeName", "?") for s in services))
        return services

    def service_lookup(self, service_name):
        """Return the first registered service node's properties dict, or None."""
        services = self.service_lookup_all(service_name)
        if not services:
            return None
        logger.info("pxGrid ServiceLookup(%s): node=%s", service_name,
                    services[0].get("nodeName"))
        return services[0]

    def access_secret(self, peer_node_name):
        self._ensure_active()
        data = self._control_post("AccessSecret", {"peerNodeName": peer_node_name})
        secret = data.get("secret", "")
        logger.debug("pxGrid AccessSecret(%s): %s", peer_node_name,
                     "obtained" if secret else "EMPTY")
        return secret

    def _resolved_services(self, service_name, *, use_cache=True, skip_peers=()):
        """Resolve all REST provider candidates for a query service."""
        skip_peers = set(skip_peers)
        if use_cache and service_name in self._svc and self._svc[service_name][0] not in skip_peers:
            return [self._svc[service_name]]

        services = self.service_lookup_all(service_name)
        if not services:
            raise RuntimeError(f"pxGrid ServiceLookup returned no node for {service_name}")
        resolved = []
        for svc in services:
            peer = svc.get("nodeName")
            if not peer or peer in skip_peers:
                continue
            rest_base = _rest_base(svc.get("properties", {}))
            if not rest_base:
                logger.warning("pxGrid service %s node %s has no restBaseUrl", service_name, peer)
                continue
            secret = self.access_secret(peer)
            resolved.append((peer, rest_base, secret))
            logger.info("pxGrid resolved %s: peer=%s rest_base=%s",
                        service_name, peer, rest_base)
        if not resolved:
            raise RuntimeError(f"pxGrid service {service_name} has no usable REST node")
        self._svc[service_name] = resolved[0]
        return resolved

    def rest_query(self, service_name, endpoint, body=None, timeout=120):
        """POST {restBaseUrl}/{endpoint} with the per-service access secret as the
        Basic-auth password. Re-resolves once on 401/403/404 (secret rotation)."""
        failed_peers = set()
        last_error = None
        for attempt in (1, 2):
            candidates = self._resolved_services(
                service_name, use_cache=(attempt == 1 and not failed_peers),
                skip_peers=failed_peers)
            retry_secret = False
            for peer, rest_base, secret in candidates:
                url = f"{rest_base.rstrip('/')}/{endpoint.lstrip('/')}"
                logger.debug("pxGrid query %s (attempt %d)", url, attempt)
                try:
                    r = self.session.post(url, json=body or {},
                                          auth=HTTPBasicAuth(self.node_name, secret),
                                          timeout=timeout)
                    r.raise_for_status()
                    self._svc[service_name] = (peer, rest_base, secret)
                    logger.debug("pxGrid query %s -> HTTP %s", url, r.status_code)
                    return r.json()
                except requests.exceptions.HTTPError as e:
                    last_error = e
                    code = e.response.status_code if e.response is not None else 0
                    if code in (401, 403, 404) and attempt == 1:
                        logger.info("pxGrid %s -> %s, re-resolving service", endpoint, code)
                        self._svc.pop(service_name, None)
                        retry_secret = True
                        break
                    if code >= 500:
                        failed_peers.add(peer)
                        self._svc.pop(service_name, None)
                        logger.info("pxGrid %s peer %s -> HTTP %s, trying next provider",
                                    endpoint, peer, code)
                        continue
                    raise
                except requests.exceptions.RequestException as e:
                    last_error = e
                    failed_peers.add(peer)
                    self._svc.pop(service_name, None)
                    continue
            if retry_secret:
                continue
            if failed_peers and attempt == 1:
                continue
            if last_error:
                raise last_error
        if last_error:
            raise last_error
        return None

    def get_endpoints(self, *, start_timestamp=ENDPOINT_BULK_START,
                      page_size=ENDPOINT_PAGE_SIZE, max_pages=None, timeout=120):
        """Fetch all pxGrid endpoints using the documented mandatory timestamp filter
        and startIndex/count paging.

        Cisco documents startCreateTimestamp OR startUpdateTimestamp as mandatory
        (either one). We try BOTH together first (matches Cisco's bulk example), then
        fall back to each single filter: some ISE builds AND the two and return nothing
        when an endpoint has a blank create- or update-timestamp, so the combined query
        can come back empty on a deployment whose endpoints are perfectly real. If ALL
        filter variants return zero, that's an ISE-side context-publishing problem (the
        service resolved but ISE published no endpoints), not a query error — surfaced
        loudly so it isn't mistaken for "no endpoints exist".
        """
        filters = (
            {"startCreateTimestamp": start_timestamp, "startUpdateTimestamp": start_timestamp},
            {"startCreateTimestamp": start_timestamp},
            {"startUpdateTimestamp": start_timestamp},
        )
        for i, timestamp_filter in enumerate(filters):
            endpoints = self._get_endpoints_paged(timestamp_filter, page_size, max_pages, timeout)
            if endpoints:
                if i:
                    logger.info("pxGrid getEndpoints: %d endpoints via fallback filter %s "
                                "(combined create+update filter returned none)",
                                len(endpoints), list(timestamp_filter))
                return endpoints
        logger.warning(
            "pxGrid getEndpoints returned 0 endpoints for every timestamp filter (queried "
            "from epoch, so this is NOT a filter-window issue). The endpoint service "
            "resolved and the query is authorized — ISE simply has nothing in its pxGrid "
            "endpoint directory to return. This is common and expected on many deployments: "
            "the pxGrid endpoint feed only carries endpoints ISE has published live context "
            "for (driven by active RADIUS sessions/network activity), and is often empty even "
            "when the endpoint DB is not. Verified against ISE 3.3 that it stays empty on a "
            "node with no active sessions even with Profiler Forwarder Persistence Queue + "
            "Custom Attribute for Profiling Enforcement enabled and an endpoint statically "
            "profiled — so it is not a simple settings toggle. Sessions still stream fine. "
            "The endpoint profile/model breakdown falls back to the ERS endpoint collector "
            "(COLLECT_ERS_ENDPOINT_FALLBACK); pxGrid-native endpoint attributes "
            "(MFC model/OS, Secure Client posture) stay empty until ISE actually publishes "
            "endpoint context — check the pxGrid client group grants EndpointService "
            "(com.cisco.ise.endpoint) and that endpoints have live pxGrid-published context.")
        return []

    def _get_endpoints_paged(self, timestamp_filter, page_size, max_pages, timeout):
        endpoints = []
        start_index = 0
        pages = 0
        while True:
            body = {**timestamp_filter, "startIndex": start_index,
                    "count": page_size, "order": "ASC"}
            data = self.rest_query(ENDPOINT_SERVICE, "getEndpoints", body, timeout=timeout)
            if isinstance(data, dict):
                page = _as_list(data.get("endpoints") or data.get("endpoint"), "endpoint")
            else:
                page = _as_list(data)
            endpoints.extend(page)
            pages += 1
            if len(page) < page_size or (max_pages is not None and pages >= max_pages):
                return endpoints
            start_index += len(page)

    def get_profiler_profiles(self, timeout=120):
        """Catalog of profiling policies (id/name/hierarchy) via the profiler
        config service — metadata about the POLICY TREE, not endpoint counts.
        fullName is a colon-joined ancestry path (e.g. 'Apple-Device:Apple-iPhone');
        collectors/models.py cross-references this by name against getEndpoints'
        endPointPolicy to attach category/parent to per-profile endpoint counts."""
        data = self.rest_query(PROFILER_SERVICE, "getProfiles", {}, timeout=timeout)
        return (data or {}).get("profiles", [])

    def resolve_pubsub(self):
        """Return (peer_node, ws_url, secret) for the pubsub (WSS) service."""
        svc = self.service_lookup(PUBSUB_SERVICE)
        if not svc:
            raise RuntimeError("pxGrid pubsub service not available")
        peer = svc["nodeName"]
        props = svc.get("properties", {})
        ws_url = props.get("wsUrl") or props.get("wsPubsubService")
        secret = self.access_secret(peer)
        return peer, ws_url, secret

    def session_topic(self):
        """Return (rest_base, topic) for the session directory. Defaults to the base
        `sessionTopic` (universally available + authorized for any session-service
        client); prefers `sessionTopicAll` only when PXGRID_SESSION_TOPIC_ALL=true,
        since .all is 3.3p2/3.4+ and needs the client's group authorized for it."""
        svc = self.service_lookup(SESSION_SERVICE)
        if not svc:
            raise RuntimeError("pxGrid session service not available")
        props = svc.get("properties", {})
        base, all_topic = props.get("sessionTopic"), props.get("sessionTopicAll")
        if getattr(self.cfg, "pxgrid_session_topic_all", False):
            return _rest_base(props), all_topic or base
        return _rest_base(props), base or all_topic

    def endpoint_topic(self):
        """Return (rest_base, topic) for the endpoint service."""
        svc = self.service_lookup(ENDPOINT_SERVICE)
        if not svc:
            raise RuntimeError("pxGrid endpoint service not available")
        props = svc.get("properties", {})
        return _rest_base(props), props.get("endpointTopic") or props.get("topic")
