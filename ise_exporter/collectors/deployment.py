"""deployment collector (port of collect_deployment_metrics). PAN OpenAPI node
status -> per-node Enum, role counts, PAN-HA state. Also owns ise_up (1 when PAN
answers with node status) and the one-shot ise_info, since deployment polls in
both poll and stream modes whereas sessions may not."""
import logging
from collections import defaultdict

from .. import metrics
from ..compatibility import (
    DEPLOYMENT_NODE_ROLES,
    DEPLOYMENT_NODE_SERVICES,
    DEPLOYMENT_NODE_STATES,
)
from ..snapshots import replace_metric_snapshot
from ..util import metric_label
from . import observe, CollectorFailed
from .nodes import get_nodes

logger = logging.getLogger(__name__)

_info_set = False
_METRICS = (metrics.ise_deployment_status, metrics.ise_node_count,
            metrics.ise_pan_ha_enabled, metrics.ise_node_service_enabled)


def collect(client, cfg):
    global _info_set
    with observe("deployment"):
        nodes = get_nodes(client, cfg, force=True)   # authoritative; also refreshes the shared cache
        if not nodes:
            metrics.ise_up.set(0)
            raise CollectorFailed("no deployment node status")
        role_counts = defaultdict(int)
        rows = []
        hostnames = set()
        for node in nodes:
            if not isinstance(node, dict):
                metrics.ise_up.set(0)
                raise CollectorFailed("deployment node response contained a non-object")
            hostname = node.get("hostname")
            status = node.get("nodeStatus")
            roles = node.get("roles")
            services = node.get("services")
            if (not isinstance(hostname, str) or not hostname.strip()
                    or len(hostname) > 253 or hostname in hostnames):
                metrics.ise_up.set(0)
                raise CollectorFailed("deployment node response contained an invalid hostname")
            if status not in DEPLOYMENT_NODE_STATES:
                metrics.ise_up.set(0)
                raise CollectorFailed(
                    f"deployment node {hostname!r} contained invalid status {status!r}")
            if (not isinstance(roles, list) or not isinstance(services, list)
                    or any(not isinstance(value, str) or not value.strip()
                           for value in roles + services)
                    or any(role not in DEPLOYMENT_NODE_ROLES for role in roles)
                    or any(service not in DEPLOYMENT_NODE_SERVICES for service in services)
                    or len(roles) != len(set(roles))
                    or len(services) != len(set(services))):
                metrics.ise_up.set(0)
                raise CollectorFailed(
                    f"deployment node {hostname!r} contained invalid roles or services")
            hostnames.add(hostname)
            hostname = metric_label(hostname)
            roles_str = metric_label(",".join(roles) if roles else "PSN")
            services_str = metric_label(",".join(services) if services else "none")
            service_labels = tuple(metric_label(service) for service in services)
            if roles:
                for role in roles:
                    role_counts[metric_label(role)] += 1
            else:
                role_counts["PSN"] += 1
            rows.append((hostname, roles_str, services_str, service_labels, status))

        pan_ha = client.get_pan_api("/deployment/pan-ha", api_name="pan_ha")
        if (not isinstance(pan_ha, dict)
                or not isinstance(pan_ha.get("isEnabled"), bool)):
            metrics.ise_up.set(0)
            raise CollectorFailed("PAN HA status request failed or returned invalid data")

        def publish():
            for hostname, roles_str, services_str, service_labels, normalized in rows:
                metrics.ise_deployment_status.labels(
                    node=hostname, roles=roles_str, services=services_str).state(normalized)
                for service in service_labels:
                    metrics.ise_node_service_enabled.labels(
                        node=hostname, service=service).set(1)
            for role, count in role_counts.items():
                metrics.ise_node_count.labels(role=role).set(count)
            metrics.ise_pan_ha_enabled.set(1 if pan_ha["isEnabled"] else 0)

        replace_metric_snapshot(_METRICS, (publish,))
        metrics.ise_up.set(1)
        if not _info_set:
            metrics.ise_info.info({"hostname": client.host})
            _info_set = True
        logger.info("Deployment: %d nodes", len(nodes))
