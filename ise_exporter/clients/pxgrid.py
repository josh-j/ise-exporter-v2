"""Bounded, read-only pxGrid 2.0 control and REST client for the operator CLI."""
from __future__ import annotations

from dataclasses import dataclass
from urllib.parse import urlsplit

import requests
from requests.auth import HTTPBasicAuth


MAX_RESPONSE_BYTES = 64 * 1024 * 1024


@dataclass(frozen=True)
class PxGridOperation:
    service: str
    endpoint: str
    result_keys: tuple[str, ...]


OPERATIONS = {
    "sessions": PxGridOperation("com.cisco.ise.session", "getSessions", ("sessions", "session")),
    "session-by-ip": PxGridOperation("com.cisco.ise.session", "getSessionByIpAddress", ("session", "sessions")),
    "session-by-mac": PxGridOperation("com.cisco.ise.session", "getSessionByMacAddress", ("session", "sessions")),
    "user-groups": PxGridOperation("com.cisco.ise.session", "getUserGroups", ("userGroups", "groups")),
    "user-group-by-username": PxGridOperation("com.cisco.ise.session", "getUserGroupByUserName", ("userGroup", "userGroups")),
    "system-health": PxGridOperation("com.cisco.ise.system", "getHealths", ("healths", "health")),
    "system-performance": PxGridOperation("com.cisco.ise.system", "getPerformances", ("performances", "performance")),
    "trustsec-security-groups": PxGridOperation("com.cisco.ise.config.trustsec", "getSecurityGroups", ("securityGroups", "securityGroup")),
    "trustsec-acls": PxGridOperation("com.cisco.ise.config.trustsec", "getSecurityGroupAcls", ("securityGroupAcls", "securityGroupAcl")),
    "trustsec-virtual-networks": PxGridOperation("com.cisco.ise.config.trustsec", "getVirtualNetwork", ("virtualNetworks", "virtualNetwork")),
    "trustsec-egress-policies": PxGridOperation("com.cisco.ise.config.trustsec", "getEgressPolicies", ("egressPolicies", "egressPolicy")),
    "trustsec-egress-matrices": PxGridOperation("com.cisco.ise.config.trustsec", "getEgressMatrices", ("egressMatrices", "egressMatrix")),
    "endpoints": PxGridOperation("com.cisco.ise.endpoint", "getEndpoints", ("endpoints", "endpoint")),
    "sxp-bindings": PxGridOperation("com.cisco.ise.sxp", "getBindings", ("bindings", "binding")),
    "radius-failures": PxGridOperation("com.cisco.ise.radius", "getFailures", ("failures", "failure")),
    "radius-failure-by-id": PxGridOperation("com.cisco.ise.radius", "getFailureById", ("failure", "failures")),
    "mdm-endpoints": PxGridOperation("com.cisco.ise.mdm", "getEndpoints", ("endpoints", "endpoint")),
    "mdm-endpoint-by-mac": PxGridOperation("com.cisco.ise.mdm", "getEndpointByMacAddress", ("endpoint", "endpoints")),
    "mdm-endpoints-by-type": PxGridOperation("com.cisco.ise.mdm", "getEndpointsByType", ("endpoints", "endpoint")),
    "mdm-endpoints-by-os": PxGridOperation("com.cisco.ise.mdm", "getEndpointsByOsType", ("endpoints", "endpoint")),
    "profiler-profiles": PxGridOperation("com.cisco.ise.config.profiler", "getProfiles", ("profiles", "profile")),
    "anc-policies": PxGridOperation("com.cisco.ise.config.anc", "getPolicies", ("policies", "policy")),
    "anc-policy-by-name": PxGridOperation("com.cisco.ise.config.anc", "getPolicyByName", ("policy", "policies")),
    "anc-endpoints": PxGridOperation("com.cisco.ise.config.anc", "getEndpoints", ("endpoints", "endpoint")),
    "anc-endpoint-by-mac": PxGridOperation("com.cisco.ise.config.anc", "getEndpointByMacAddress", ("endpoint", "endpoints")),
    "anc-endpoint-policies": PxGridOperation("com.cisco.ise.config.anc", "getEndpointPolicies", ("endpointPolicies", "policies")),
}

KNOWN_SERVICES = tuple(sorted({op.service for op in OPERATIONS.values()} | {"com.cisco.ise.pubsub"}))


class PxGridControl:
    def __init__(self, cfg):
        if not cfg.pxgrid_ready:
            raise RuntimeError(
                "pxGrid is not configured; set [pxgrid] host, node_name, and either "
                "ISE_PXGRID_PASSWORD or client_cert/client_key")
        self.cfg = cfg
        self.control_base = f"https://{cfg.pxgrid_host}:{cfg.pxgrid_port}/pxgrid/control"
        self.session = requests.Session()
        self.session.trust_env = False
        self.session.verify = cfg.pxgrid_ca_bundle if cfg.pxgrid_ca_bundle else cfg.pxgrid_ssl_verify
        if cfg.pxgrid_client_cert:
            self.session.cert = (cfg.pxgrid_client_cert, cfg.pxgrid_client_key)
        self.session.auth = HTTPBasicAuth(cfg.pxgrid_node_name, cfg.pxgrid_password)
        self.session.headers.update({"Accept": "application/json", "Content-Type": "application/json"})
        self._services = {}
        self._active = False

    def close(self):
        self.session.close()

    def _post(self, url, body, *, auth=None):
        response = self.session.post(
            url, json=body or {}, auth=auth, timeout=self.cfg.pxgrid_request_timeout)
        response.raise_for_status()
        if int(response.headers.get("Content-Length", 0) or 0) > MAX_RESPONSE_BYTES:
            raise RuntimeError("pxGrid response exceeded the 64 MiB safety ceiling")
        if len(response.content) > MAX_RESPONSE_BYTES:
            raise RuntimeError("pxGrid response exceeded the 64 MiB safety ceiling")
        return response.json()

    def control(self, operation, body=None):
        return self._post(f"{self.control_base}/{operation}", body or {})

    def activate(self):
        data = self.control("AccountActivate", {"description": "ise-cli PowerShell operator"})
        state = str(data.get("accountState", "")).upper()
        if state == "ENABLED":
            self._active = True
        elif state == "PENDING":
            raise RuntimeError("pxGrid account is PENDING approval in ISE")
        elif state == "DISABLED":
            raise RuntimeError("pxGrid account is DISABLED in ISE")
        else:
            raise RuntimeError(f"pxGrid returned an unexpected account state: {state or data!r}")
        return data

    def lookup(self, service_name):
        if not self._active:
            self.activate()
        data = self.control("ServiceLookup", {"name": service_name})
        services = data.get("services") or []
        return services if isinstance(services, list) else [services]

    def services(self, service_name=None):
        names = (service_name,) if service_name else KNOWN_SERVICES
        rows = []
        for name in names:
            for service in self.lookup(name):
                # ISE 3.3 can advertise both restBaseURL and restBaseUrl in the
                # same properties object.  They are distinct JSON keys but
                # collide in PowerShell's case-insensitive object model.  Keep
                # the last advertised spelling/value so ConvertFrom-Json can
                # turn service discovery into native PowerShell objects.
                normalized = dict(service)
                properties = normalized.get("properties")
                if isinstance(properties, dict):
                    unique = {}
                    spellings = {}
                    for key, value in properties.items():
                        folded = key.casefold()
                        previous = spellings.get(folded)
                        if previous is not None:
                            unique.pop(previous, None)
                        unique[key] = value
                        spellings[folded] = key
                    normalized["properties"] = unique
                rows.append({"serviceName": name, **normalized})
        return rows

    def topics(self, service_name=None):
        rows = []
        for service in self.services(service_name):
            properties = service.get("properties") or {}
            for name, value in properties.items():
                if "topic" in name.casefold() and value:
                    rows.append({
                        "serviceName": service["serviceName"],
                        "nodeName": service.get("nodeName"),
                        "property": name,
                        "topic": value,
                    })
        return rows

    def _provider(self, service_name):
        cached = self._services.get(service_name)
        if cached:
            return cached
        services = self.lookup(service_name)
        if not services:
            raise RuntimeError(f"pxGrid service is unavailable: {service_name}")
        service = services[0]
        peer = service.get("nodeName")
        props = service.get("properties") or {}
        rest_base = props.get("restBaseUrl") or props.get("restBaseURL")
        parsed = urlsplit(rest_base or "")
        if parsed.scheme != "https" or not parsed.hostname:
            raise RuntimeError(f"pxGrid service returned an unsafe REST URL: {rest_base!r}")
        secret = self.control("AccessSecret", {"peerNodeName": peer}).get("secret", "")
        self._services[service_name] = (rest_base.rstrip("/"), secret)
        return self._services[service_name]

    def query(self, operation_name, body=None):
        operation = OPERATIONS[operation_name]
        rest_base, secret = self._provider(operation.service)
        data = self._post(
            f"{rest_base}/{operation.endpoint}", body or {},
            auth=HTTPBasicAuth(self.cfg.pxgrid_node_name, secret))
        if not isinstance(data, dict):
            return data if isinstance(data, list) else [data]
        for key in operation.result_keys:
            if key in data:
                value = data[key]
                return value if isinstance(value, list) else [value]
        return [data]
