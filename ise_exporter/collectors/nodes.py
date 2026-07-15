"""Shared, briefly-cached PAN deployment node list. Both the deployment collector
(authoritative — force-refreshes each run) and the certificates collector (which
only needs hostnames to walk cert stores) call /deployment/node; without this they
would each fetch it every cycle. Cached for one medium tier so the certificates
slow-tier run reuses the list the deployment medium-tier run just fetched."""
import time

from ..compatibility import MAX_DEPLOYMENT_NODES, valid_hostname

_cache = {"nodes": None, "ts": 0.0}


def validated_node_rows(value):
    """Validate the bounded identity portion shared by node-list consumers."""
    hostnames = [node.get("hostname") for node in value] \
        if isinstance(value, list) and all(isinstance(node, dict) for node in value) \
        else []
    if (not isinstance(value, list) or len(value) > MAX_DEPLOYMENT_NODES
            or len(hostnames) != len(value)
            or any(not valid_hostname(hostname) for hostname in hostnames)
            or len({hostname.casefold() for hostname in hostnames}) != len(hostnames)):
        return None
    return value


def get_nodes(client, cfg, force=False):
    now = time.time()
    if not force and _cache["nodes"] is not None and (now - _cache["ts"]) < cfg.medium_interval:
        return _cache["nodes"]
    nodes = validated_node_rows(
        client.get_pan_api("/deployment/node", api_name="pan_nodes"))
    if nodes is None:
        _cache.update(nodes=None, ts=0.0)
        return None
    if nodes:
        _cache["nodes"] = nodes
        _cache["ts"] = now
    else:
        _cache.update(nodes=None, ts=0.0)
    return nodes
