"""devices collector (port of collect_device_metrics). Enumerates ERS network
devices, derives device-type / location / ops-owner from the Network Device Group
hierarchy, and refreshes the shared `mappings` dict (keyed by NAD IP) that
sessions / authz / streaming join against for their labels."""
import logging
from collections import defaultdict
from ipaddress import ip_address, ip_network

from .. import metrics
from ..util import clear_metric
from . import observe, CollectorFailed

logger = logging.getLogger(__name__)

_cache = None


def _device_cache(cfg):
    global _cache
    if _cache is None:
        from ..caches import DeviceCache
        _cache = DeviceCache(cfg.device_cache_ttl)
    return _cache


def _classify(det):
    """(name, ip, device_type, location, ops_owner) from an ERS NetworkDevice body.
    Groups look like 'Location#All Locations#Germany#Ramstein AB' — drop the
    category and the 'All X' root (parts[2:]) for location; leaf for the rest."""
    ip_list = det.get("NetworkDeviceIPList", [])
    if ip_list:
        ip = ip_list[0].get("ipaddress", ip_list[0].get("ipAddress", "unknown"))
    else:
        ip = "unknown"
    name = det.get("name", "unknown")

    # location default is capital "Unknown" to match normalize_location() / nad_labels(),
    # so a NAD with no Location group shares a series with location-less sessions rather
    # than splitting into a separate lowercase "unknown". (ops_owner/device_type stay
    # lowercase — consistent with their own label sources.)
    location, ops_owner, device_type = "Unknown", "unknown", "unknown"
    for g in det.get("NetworkDeviceGroupList", []):
        parts = g.split("#")
        if parts[0] == "Location" and len(parts) > 2:
            location = "#".join(parts[2:])
        elif parts[0] == "Ops Owner" and len(parts) > 2:
            ops_owner = parts[-1]
        elif parts[0] == "Device Type" and len(parts) > 2:
            device_type = parts[-1]
    return name, ip, device_type, location, ops_owner


def _nad_networks(det, name, location, ops_owner):
    networks = []
    for entry in det.get("NetworkDeviceIPList", []):
        raw_ip = entry.get("ipaddress", entry.get("ipAddress"))
        if not raw_ip:
            continue
        mask = entry.get("mask", 32)
        try:
            network = ip_network(f"{raw_ip}/{mask}", strict=False)
        except (TypeError, ValueError):
            logger.warning("Devices: ignoring invalid NAD IP entry %r/%r for %s",
                           raw_ip, mask, name)
            continue
        networks.append((network, name, location, ops_owner))
    return networks


def collect(client, cfg, mappings):
    with observe("devices"):
        devices = client.get_ers("/config/networkdevice", {"size": 100},
                                 get_all=True, api_name="ers_devices")
        if not devices:
            raise CollectorFailed("no network devices returned")
        metrics.ise_network_devices_total.set(len(devices))

        if not cfg.collect_device_details:
            return

        cache = _device_cache(cfg)
        ops_map, host_map, loc_map, network_map = {}, {}, {}, []
        loc_counts = defaultdict(int)
        ops_counts = defaultdict(int)
        type_counts = defaultdict(int)

        for d in devices:
            dev_id = d.get("id")
            if not dev_id:
                continue
            det = cache.get(dev_id)
            if det is None:
                raw = client.get_ers(f"/config/networkdevice/{dev_id}", api_name="ers_device_detail")
                det = raw.get("NetworkDevice") if raw else None
                if not det:
                    continue
                cache.set(dev_id, det)

            name, ip, device_type, location, ops_owner = _classify(det)
            ops_map[ip] = ops_owner
            host_map[ip] = name
            loc_map[ip] = location
            network_map.extend(_nad_networks(det, name, location, ops_owner))
            loc_counts[location] += 1
            ops_counts[ops_owner] += 1
            type_counts[device_type] += 1

        # replace shared mappings wholesale (drops devices removed since last cycle).
        # Rebind each key atomically rather than clear()+update(), so the streamer
        # thread reading mappings["hostname"] never observes a half-empty dict.
        mappings["ops_owner"] = ops_map
        mappings["hostname"] = host_map
        mappings["location"] = loc_map
        mappings["networks"] = network_map

        clear_metric(metrics.ise_network_devices_by_location)
        clear_metric(metrics.ise_network_devices_by_ops_owner)
        clear_metric(metrics.ise_network_devices_by_type)
        for k, v in loc_counts.items():
            metrics.ise_network_devices_by_location.labels(location=k).set(v)
        for k, v in ops_counts.items():
            metrics.ise_network_devices_by_ops_owner.labels(ops_owner=k).set(v)
        for k, v in type_counts.items():
            metrics.ise_network_devices_by_type.labels(device_type=k).set(v)
        logger.info("Devices: %d total, %d locations", len(devices), len(loc_counts))


def nad_labels(mappings, nas_ip, name_hint=None, loc_hint=None):
    """(hostname, location, ops_owner) for a NAD IP, honoring per-session hints
    when the session payload carries its own device name / location."""
    hostname = name_hint or mappings["hostname"].get(nas_ip)
    location = loc_hint or mappings["location"].get(nas_ip)
    ops_owner = mappings["ops_owner"].get(nas_ip)

    if ops_owner is None:
        try:
            addr = ip_address(nas_ip)
        except (TypeError, ValueError):
            addr = None
        if addr is not None:
            for network, net_name, net_location, net_owner in mappings.get("networks", []):
                if addr in network:
                    hostname = hostname or net_name
                    location = location or net_location
                    ops_owner = net_owner
                    break

    hostname = hostname or nas_ip or "unknown"
    location = location or "Unknown"
    ops_owner = ops_owner or "unknown"
    return hostname, location, ops_owner
