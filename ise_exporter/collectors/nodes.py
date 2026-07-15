"""Shared, briefly-cached PAN deployment node list. Both the deployment collector
(authoritative — force-refreshes each run) and the certificates collector (which
only needs hostnames to walk cert stores) call /deployment/node; without this they
would each fetch it every cycle. Cached for one medium tier so the certificates
slow-tier run reuses the list the deployment medium-tier run just fetched."""
import time

_cache = {"nodes": None, "ts": 0.0}
MAX_DEPLOYMENT_NODES = 100


def _valid_hostname(value):
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


def get_nodes(client, cfg, force=False):
    now = time.time()
    if not force and _cache["nodes"] is not None and (now - _cache["ts"]) < cfg.medium_interval:
        return _cache["nodes"]
    nodes = client.get_pan_api("/deployment/node", api_name="pan_nodes")
    hostnames = [node.get("hostname") for node in nodes] \
        if isinstance(nodes, list) and all(isinstance(node, dict) for node in nodes) \
        else []
    if (not isinstance(nodes, list) or len(nodes) > MAX_DEPLOYMENT_NODES
            or len(hostnames) != len(nodes)
            or any(not _valid_hostname(hostname) for hostname in hostnames)
            or len({hostname.casefold() for hostname in hostnames}) != len(hostnames)):
        _cache.update(nodes=None, ts=0.0)
        return None
    if nodes:
        _cache["nodes"] = nodes
        _cache["ts"] = now
    else:
        _cache.update(nodes=None, ts=0.0)
    return nodes
