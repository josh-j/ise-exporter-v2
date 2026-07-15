"""Collect bounded-cardinality network-device inventory from ERS."""
import logging
from collections import defaultdict

from .. import metrics
from ..snapshots import replace_metric_snapshot
from . import observe, CollectorFailed

logger = logging.getLogger(__name__)

_cache = None
_METRICS = (
    metrics.ise_network_devices_total,
    metrics.ise_network_devices_by_location,
    metrics.ise_network_devices_by_ops_owner,
    metrics.ise_network_devices_by_type,
)


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
    if not isinstance(det, dict):
        raise CollectorFailed("network device detail was not an object")
    ip_list = det.get("NetworkDeviceIPList", [])
    groups = det.get("NetworkDeviceGroupList", [])
    if (not isinstance(ip_list, list)
            or any(not isinstance(row, dict) for row in ip_list)
            or not isinstance(groups, list)
            or any(not isinstance(group, str) for group in groups)):
        raise CollectorFailed("network device detail contained invalid list fields")
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
    for g in groups:
        parts = g.split("#")
        if parts[0] == "Location" and len(parts) > 2:
            location = "#".join(parts[2:])
        elif parts[0] == "Ops Owner" and len(parts) > 2:
            ops_owner = parts[-1]
        elif parts[0] == "Device Type" and len(parts) > 2:
            device_type = parts[-1]
    return name, ip, device_type, location, ops_owner


def collect(client, cfg):
    inventory = None
    with observe("devices"):
        devices = client.get_ers("/config/networkdevice", {"size": 100},
                                 get_all=True, api_name="ers_devices")
        if devices is None:
            raise CollectorFailed("network device inventory request failed")
        if not isinstance(devices, list):
            raise CollectorFailed("network device inventory response was not a list")
        device_ids = [str(row.get("id") or "").strip()
                      for row in devices if isinstance(row, dict)]
        if (len(device_ids) != len(devices) or any(not device_id for device_id in device_ids)
                or len(set(device_ids)) != len(device_ids)
                or any(not str(row.get("name") or "").strip() for row in devices)):
            raise CollectorFailed("network device inventory contained invalid identities")

        if not cfg.collect_device_details:
            replace_metric_snapshot(
                _METRICS, (lambda: metrics.ise_network_devices_total.set(len(devices)),))
            return devices

        cache = _device_cache(cfg)
        cache.retain(
            row.get("id") for row in devices
            if isinstance(row, dict) and row.get("id"))
        loc_counts = defaultdict(int)
        ops_counts = defaultdict(int)
        type_counts = defaultdict(int)

        for d in devices:
            dev_id = d.get("id")
            if not dev_id:
                continue
            det = cache.get(dev_id)
            if det is None:
                raw = client.get_ers(
                    f"/config/networkdevice/{dev_id}", api_name="ers_device_detail")
                det = raw.get("NetworkDevice") if raw else None
                if not det:
                    raise CollectorFailed(
                        f"network device detail request failed for {dev_id}")
                cache.set(dev_id, det)

            _name, _ip, device_type, location, ops_owner = _classify(det)
            loc_counts[location] += 1
            ops_counts[ops_owner] += 1
            type_counts[device_type] += 1

        def publish():
            metrics.ise_network_devices_total.set(len(devices))
            for key, value in loc_counts.items():
                metrics.ise_network_devices_by_location.labels(location=key).set(value)
            for key, value in ops_counts.items():
                metrics.ise_network_devices_by_ops_owner.labels(ops_owner=key).set(value)
            for key, value in type_counts.items():
                metrics.ise_network_devices_by_type.labels(device_type=key).set(value)

        replace_metric_snapshot(_METRICS, (publish,))
        inventory = devices
        logger.info("Devices: %d total, %d locations", len(devices), len(loc_counts))

    return inventory
