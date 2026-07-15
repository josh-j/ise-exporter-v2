"""Runtime compatibility contract for the supported Cisco ISE release.

The exporter intentionally targets the API behavior of the lab deployment:
Cisco ISE 3.3.0.430 Patch 11.  Validation uses only supported, read-only PAN
OpenAPI calls and does not require appliance shell or root access.
"""

from collections.abc import Mapping
from dataclasses import dataclass


SUPPORTED_ISE_VERSION = "3.3.0.430"
SUPPORTED_PATCH_LEVEL = 11
MAX_CERTIFICATES_PER_STORE = 1000
MAX_CERTIFICATE_ROWS = 5000
MAX_DEPLOYMENT_NODES = 100
DEPLOYMENT_NODE_STATES = (
    "Connected", "Disconnected", "InProgress", "NotApplicable", "NotInSync",
    "NotUpgraded", "RegistrationFailed", "ReplicationStopped",
)
DEPLOYMENT_NODE_ROLES = frozenset({
    "PrimaryAdmin", "PrimaryDedicatedMonitoring", "PrimaryMonitoring",
    "SecondaryAdmin", "SecondaryDedicatedMonitoring", "SecondaryMonitoring",
    "Standalone",
})
DEPLOYMENT_NODE_SERVICES = frozenset({
    "DeviceAdmin", "PassiveIdentity", "Profiler", "SXP", "Session", "TC-NAC",
    "pxGrid", "pxGridCloud",
})


class ISECompatibilityError(RuntimeError):
    """The connected ISE deployment does not satisfy the supported contract."""


def valid_hostname(value):
    """Accept DNS-safe ISE node names suitable for metric labels and URL paths."""
    if not isinstance(value, str) or not value or len(value) > 253:
        return False
    labels = value.split(".")
    allowed = frozenset(
        "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789-")
    return all(
        1 <= len(label) <= 63
        and label[0] != "-" and label[-1] != "-"
        and not (set(label) - allowed)
        for label in labels)


@dataclass(frozen=True)
class ISECompatibility:
    """Facts confirmed by :func:`validate_ise_compatibility`."""

    ise_version: str
    patch_level: int
    installed_patches: tuple[int, ...]
    deployment_nodes: tuple[str, ...]


def _installed_patches(payload):
    patch_versions = payload.get("patchVersion")
    if not isinstance(patch_versions, list):
        raise ISECompatibilityError(
            "ISE compatibility check failed: GET /api/v1/patch returned no "
            "patchVersion list")

    patches = []
    for index, patch in enumerate(patch_versions):
        if not isinstance(patch, Mapping) or "patchNumber" not in patch:
            raise ISECompatibilityError(
                "ISE compatibility check failed: GET /api/v1/patch returned "
                f"an invalid patchVersion entry at index {index}")
        try:
            number = int(patch["patchNumber"])
        except (TypeError, ValueError) as exc:
            raise ISECompatibilityError(
                "ISE compatibility check failed: GET /api/v1/patch returned "
                f"invalid patchNumber {patch['patchNumber']!r}") from exc
        if number < 1:
            raise ISECompatibilityError(
                "ISE compatibility check failed: GET /api/v1/patch returned "
                f"invalid patchNumber {number}")
        patches.append(number)
    return tuple(sorted(set(patches)))


def _deployment_nodes(payload):
    if not isinstance(payload, list) or not payload:
        raise ISECompatibilityError(
            "ISE compatibility check failed: GET /api/v1/deployment/node "
            "returned no deployment nodes")
    if len(payload) > MAX_DEPLOYMENT_NODES:
        raise ISECompatibilityError(
            "ISE compatibility check failed: GET /api/v1/deployment/node "
            f"exceeded the {MAX_DEPLOYMENT_NODES}-node safety ceiling")

    hostnames = []
    required = ("hostname", "nodeStatus", "roles", "services")
    for index, node in enumerate(payload):
        if not isinstance(node, Mapping):
            raise ISECompatibilityError(
                "ISE compatibility check failed: GET /api/v1/deployment/node "
                f"returned an invalid node at index {index}")
        missing = tuple(field for field in required if field not in node)
        if missing:
            raise ISECompatibilityError(
                "ISE compatibility check failed: GET /api/v1/deployment/node "
                f"node {index} is missing fields: {', '.join(missing)}")
        hostname = node["hostname"]
        if not valid_hostname(hostname):
            raise ISECompatibilityError(
                "ISE compatibility check failed: GET /api/v1/deployment/node "
                f"node {index} has an invalid hostname")
        roles = node["roles"]
        services = node["services"]
        if (node["nodeStatus"] not in DEPLOYMENT_NODE_STATES
                or not isinstance(roles, list) or not isinstance(services, list)
                or any(not isinstance(value, str) for value in roles + services)
                or any(role not in DEPLOYMENT_NODE_ROLES for role in roles)
                or any(service not in DEPLOYMENT_NODE_SERVICES for service in services)
                or len(roles) != len(set(roles))
                or len(services) != len(set(services))):
            raise ISECompatibilityError(
                "ISE compatibility check failed: GET /api/v1/deployment/node "
                f"node {hostname!r} has invalid status, roles, or services")
        hostnames.append(hostname)
    if len({hostname.casefold() for hostname in hostnames}) != len(hostnames):
        raise ISECompatibilityError(
            "ISE compatibility check failed: GET /api/v1/deployment/node "
            "returned duplicate hostnames")
    return tuple(hostnames)


def validate_ise_compatibility(client) -> ISECompatibility:
    """Validate a live ISE client against the sole supported release contract.

    ``client`` must provide ``get_pan_api(path, api_name=...)`` with the same
    semantics as :class:`ise_exporter.clients.rest.ISERestClient`.
    """
    patch_payload = client.get_pan_api("/patch", api_name="compatibility_patch")
    if not isinstance(patch_payload, Mapping):
        raise ISECompatibilityError(
            "ISE compatibility check failed: GET /api/v1/patch returned no response")

    version = patch_payload.get("iseVersion")
    if version != SUPPORTED_ISE_VERSION:
        raise ISECompatibilityError(
            f"unsupported Cisco ISE version {version!r}; this exporter requires "
            f"exactly {SUPPORTED_ISE_VERSION} Patch {SUPPORTED_PATCH_LEVEL}")

    installed_patches = _installed_patches(patch_payload)
    patch_level = max(installed_patches, default=0)
    if patch_level != SUPPORTED_PATCH_LEVEL:
        raise ISECompatibilityError(
            f"unsupported Cisco ISE patch level {patch_level}; this exporter "
            f"requires exactly {SUPPORTED_ISE_VERSION} Patch {SUPPORTED_PATCH_LEVEL}")

    nodes_payload = client.get_pan_api(
        "/deployment/node", api_name="compatibility_deployment")
    deployment_nodes = _deployment_nodes(nodes_payload)
    return ISECompatibility(
        ise_version=version,
        patch_level=patch_level,
        installed_patches=installed_patches,
        deployment_nodes=deployment_nodes,
    )
