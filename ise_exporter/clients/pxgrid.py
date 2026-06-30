"""pxGrid 2.0 control plane: ServiceLookup / AccessSecret / generic rest_query,
plus pubsub + topic resolution for the streaming engine. Used by BOTH the bulk
model collector (collectors/models.py -> getEndpoints) and the streamer
(streaming.py -> getSessions snapshot + WSS topics).

Pure transport — imports nothing from metrics."""
import logging
import requests
from requests.auth import HTTPBasicAuth

logger = logging.getLogger(__name__)

SESSION_SERVICE = "com.cisco.ise.session"
ENDPOINT_SERVICE = "com.cisco.ise.endpoint"
PUBSUB_SERVICE = "com.cisco.ise.pubsub"


def _rest_base(props):
    """Endpoint/ANC docs spell it restBaseUrl; session docs restBaseURL — read both."""
    return props.get("restBaseUrl") or props.get("restBaseURL")


class PxGridControl:
    def __init__(self, cfg):
        self.cfg = cfg
        self.host = cfg.pxgrid_host
        self.node_name = cfg.pxgrid_node_name
        self.control_base = f"https://{cfg.pxgrid_host}:{cfg.pxgrid_port}/pxgrid/control"
        self.session = requests.Session()
        self.session.cert = (cfg.pxgrid_client_cert, cfg.pxgrid_client_key)
        self.session.verify = cfg.pxgrid_ca_bundle or False
        self.session.auth = HTTPBasicAuth(cfg.pxgrid_node_name, "")
        self.session.headers.update({"Content-Type": "application/json",
                                     "Accept": "application/json"})
        # cache of resolved (peer_node, rest_base, secret) keyed by service name
        self._svc = {}

    def _control_post(self, op, body):
        url = f"{self.control_base}/{op}"
        r = self.session.post(url, json=body or {}, timeout=30)
        r.raise_for_status()
        return r.json()

    def service_lookup(self, service_name):
        """Return the first registered service node's properties dict, or None."""
        data = self._control_post("ServiceLookup", {"name": service_name})
        services = data.get("services", [])
        return services[0] if services else None

    def access_secret(self, peer_node_name):
        data = self._control_post("AccessSecret", {"peerNodeName": peer_node_name})
        return data.get("secret", "")

    def _resolve(self, service_name):
        """Resolve and cache (peer_node, rest_base, secret) for a query service."""
        if service_name in self._svc:
            return self._svc[service_name]
        svc = self.service_lookup(service_name)
        if not svc:
            raise RuntimeError(f"pxGrid ServiceLookup returned no node for {service_name}")
        peer = svc["nodeName"]
        rest_base = _rest_base(svc.get("properties", {}))
        if not rest_base:
            raise RuntimeError(f"pxGrid service {service_name} has no restBaseUrl")
        secret = self.access_secret(peer)
        self._svc[service_name] = (peer, rest_base, secret)
        return self._svc[service_name]

    def rest_query(self, service_name, endpoint, body=None, timeout=120):
        """POST {restBaseUrl}/{endpoint} with the per-service access secret as the
        Basic-auth password. Re-resolves once on 401/403/404 (secret rotation)."""
        for attempt in (1, 2):
            peer, rest_base, secret = self._resolve(service_name)
            url = f"{rest_base.rstrip('/')}/{endpoint.lstrip('/')}"
            try:
                r = self.session.post(url, json=body or {},
                                      auth=HTTPBasicAuth(self.node_name, secret),
                                      timeout=timeout)
                r.raise_for_status()
                return r.json()
            except requests.exceptions.HTTPError as e:
                code = e.response.status_code if e.response is not None else 0
                if code in (401, 403, 404) and attempt == 1:
                    logger.info("pxGrid %s -> %s, re-resolving service", endpoint, code)
                    self._svc.pop(service_name, None)
                    continue
                raise
        return None

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
        """Return (rest_base, topic) for the session directory."""
        svc = self.service_lookup(SESSION_SERVICE)
        if not svc:
            raise RuntimeError("pxGrid session service not available")
        props = svc.get("properties", {})
        return _rest_base(props), props.get("sessionTopic")

    def endpoint_topic(self):
        """Return (rest_base, topic) for the endpoint service."""
        svc = self.service_lookup(ENDPOINT_SERVICE)
        if not svc:
            raise RuntimeError("pxGrid endpoint service not available")
        props = svc.get("properties", {})
        return _rest_base(props), props.get("endpointTopic") or props.get("topic")
