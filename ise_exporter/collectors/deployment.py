"""deployment collector (port of collect_deployment_metrics). PAN OpenAPI node
status -> per-node Enum, role counts, PAN-HA state. Also owns ise_up (1 when PAN
answers with node status) and the one-shot ise_info, since deployment polls in
both poll and stream modes whereas sessions may not."""
import logging
from collections import defaultdict

from .. import metrics
from ..util import clear_metric
from . import observe, CollectorFailed
from .nodes import get_nodes

logger = logging.getLogger(__name__)

_STATES = ("Connected", "Disconnected", "Registering", "Syncing")
_info_set = False


def collect(client, cfg, mappings):
    global _info_set
    with observe("deployment"):
        nodes = get_nodes(client, cfg, force=True)   # authoritative; also refreshes the shared cache
        if not nodes:
            metrics.ise_up.set(0)
            raise CollectorFailed("no deployment node status")
        metrics.ise_up.set(1)
        if not _info_set:
            metrics.ise_info.info({"hostname": client.host})
            _info_set = True

        role_counts = defaultdict(int)
        for node in nodes:
            hostname = node.get("hostname", "unknown")
            status = node.get("nodeStatus", "Unknown")
            roles = node.get("roles", [])
            services = node.get("services", [])
            roles_str = ",".join(roles) if roles else "PSN"
            services_str = ",".join(services) if services else "none"
            if roles:
                for role in roles:
                    role_counts[role] += 1
            else:
                role_counts["PSN"] += 1
            normalized = status if status in _STATES else "Unknown"
            try:
                metrics.ise_deployment_status.labels(
                    node=hostname, roles=roles_str, services=services_str).state(normalized)
            except Exception:
                pass

        clear_metric(metrics.ise_node_count)
        for role, n in role_counts.items():
            metrics.ise_node_count.labels(role=role).set(n)
        logger.info("Deployment: %d nodes", len(nodes))

        pan_ha = client.get_pan_api("/deployment/pan-ha", api_name="pan_ha")
        if pan_ha:
            metrics.ise_pan_ha_enabled.set(1 if pan_ha.get("isEnabled", False) else 0)
