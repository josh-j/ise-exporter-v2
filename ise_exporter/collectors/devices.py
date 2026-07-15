"""Collect bounded-cardinality network-device inventory from ERS."""
import logging
from collections import defaultdict
import time

from .. import metrics
from ..snapshots import replace_metric_snapshot
from ..state import StateStore
from ..util import metric_label
from . import observe, CollectorFailed

logger = logging.getLogger(__name__)

_METRICS = (
    metrics.ise_network_devices_total,
    metrics.ise_network_devices_by_location,
    metrics.ise_network_devices_by_ops_owner,
    metrics.ise_network_devices_by_type,
    metrics.ise_network_device_detail_coverage,
    metrics.ise_network_device_detail_cache_entries,
    metrics.ise_network_device_detail_refresh_requests,
    metrics.ise_network_device_detail_refresh_failures,
    metrics.ise_network_device_detail_refresh_deferred,
)


def _sanitized_detail(det):
    """Validate detail and retain only non-secret group classification data."""
    _name, _ip, device_type, location, ops_owner = _classify(det)
    # Reconstruct only the three normalized classifications needed by metrics.
    # This gives the persisted row a small constant bound even if ISE returns a
    # very large group list, and excludes authenticationSettings by construction.
    return {"NetworkDeviceGroupList": [
        f"Location#All Locations#{location}",
        f"Ops Owner#All Ops Owners#{ops_owner}",
        f"Device Type#All Device Types#{device_type}",
    ]}


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
    return (
        metric_label(name), metric_label(ip), metric_label(device_type),
        metric_label(location, "Unknown"), metric_label(ops_owner),
    )


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
                or any(len(device_id.encode("utf-8")) > 256 for device_id in device_ids)
                or any(not str(row.get("name") or "").strip() for row in devices)):
            raise CollectorFailed("network device inventory contained invalid identities")

        if not cfg.collect_device_details:
            replace_metric_snapshot(
                _METRICS, (lambda: metrics.ise_network_devices_total.set(len(devices)),))
            return devices

        now = time.time()
        ttl = getattr(cfg, "device_cache_ttl", 2592000)
        max_requests = getattr(cfg, "device_detail_max_requests", 25)
        request_interval = getattr(
            cfg, "device_detail_request_interval_ms", 250) / 1000.0
        store = StateStore(getattr(cfg, "state_db_path", ":memory:"))
        try:
            cached = store.network_device_entries(device_ids)

            # Some ERS versions may include full group data in the list result.
            # Accept it without a detail request, but persist only the group list.
            for row in devices:
                if "NetworkDeviceGroupList" not in row:
                    continue
                try:
                    detail = _sanitized_detail(row)
                except CollectorFailed:
                    continue
                store.put_network_device(row["id"], detail, now=now)
                cached[row["id"]] = {"detail": detail, "updated_at": now}

            stale_before = now - ttl
            refresh_ids = sorted(
                (device_id for device_id in device_ids
                 if device_id not in cached
                 or cached[device_id]["updated_at"] < stale_before),
                key=lambda device_id: (
                    device_id in cached,
                    cached.get(device_id, {}).get("updated_at", -1),
                    device_id,
                ),
            )
            attempted = 0
            failures = 0
            failure_streak = 0
            for dev_id in refresh_ids[:max_requests]:
                if attempted:
                    time.sleep(request_interval)
                attempted += 1
                raw = client.get_ers(
                    f"/config/networkdevice/{dev_id}", api_name="ers_device_detail")
                det = raw.get("NetworkDevice") if isinstance(raw, dict) else None
                try:
                    detail = _sanitized_detail(det)
                except CollectorFailed:
                    failures += 1
                    failure_streak += 1
                    if failure_streak >= 3:
                        break
                    continue
                store.put_network_device(dev_id, detail, now=now)
                cached[dev_id] = {"detail": detail, "updated_at": now}
                failure_streak = 0

            store.finish_network_device_cycle(device_ids, now=now)
            cache_entries = store.network_device_count()
        finally:
            store.close()

        loc_counts = defaultdict(int)
        ops_counts = defaultdict(int)
        type_counts = defaultdict(int)

        for dev_id in device_ids:
            entry = cached.get(dev_id)
            if entry is None:
                continue
            _name, _ip, device_type, location, ops_owner = _classify(entry["detail"])
            loc_counts[location] += 1
            ops_counts[ops_owner] += 1
            type_counts[device_type] += 1

        covered = sum(device_id in cached for device_id in device_ids)
        deferred = sum(
            device_id not in cached or cached[device_id]["updated_at"] < stale_before
            for device_id in device_ids)

        def publish():
            metrics.ise_network_devices_total.set(len(devices))
            metrics.ise_network_device_detail_coverage.set(
                covered / len(device_ids) if device_ids else 1)
            metrics.ise_network_device_detail_cache_entries.set(cache_entries)
            metrics.ise_network_device_detail_refresh_requests.set(attempted)
            metrics.ise_network_device_detail_refresh_failures.set(failures)
            metrics.ise_network_device_detail_refresh_deferred.set(deferred)
            for key, value in loc_counts.items():
                metrics.ise_network_devices_by_location.labels(location=key).set(value)
            for key, value in ops_counts.items():
                metrics.ise_network_devices_by_ops_owner.labels(ops_owner=key).set(value)
            for key, value in type_counts.items():
                metrics.ise_network_devices_by_type.labels(device_type=key).set(value)

        replace_metric_snapshot(_METRICS, (publish,))
        inventory = devices
        logger.info(
            "Devices: %d total, %d detail cached, %d refresh requests, %d deferred",
            len(devices), covered, attempted, deferred)

    return inventory
