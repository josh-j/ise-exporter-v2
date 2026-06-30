"""Shared, briefly-cached PAN deployment node list. Both the deployment collector
(authoritative — force-refreshes each run) and the certificates collector (which
only needs hostnames to walk cert stores) call /deployment/node; without this they
would each fetch it every cycle. Cached for one medium tier so the certificates
slow-tier run reuses the list the deployment medium-tier run just fetched."""
import time

_cache = {"nodes": None, "ts": 0.0}


def get_nodes(client, cfg, force=False):
    now = time.time()
    if not force and _cache["nodes"] is not None and (now - _cache["ts"]) < cfg.medium_interval:
        return _cache["nodes"]
    nodes = client.get_pan_api("/deployment/node", api_name="pan_nodes")
    if nodes:
        _cache["nodes"] = nodes
        _cache["ts"] = now
    return nodes
