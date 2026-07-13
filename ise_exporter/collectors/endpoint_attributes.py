"""Slow ERS endpoint-object sweep.

Walks the ERS endpoint objects (``/ers/config/endpoint/{id}``) a bounded page per
slow cycle from a TTL cache and emits low-cardinality aggregates: profile policy
(via profileId), identity group (via groupId), static assignment flags, and custom
attributes.

ISE 3.3 exposes MFC OS/manufacturer plus deployment-specific custom attributes on
the ERS endpoint object. When posture integrations copy ``PostureReport`` and agent
version into those custom attributes, this collector provides the stable fallback
for the Secure Client dashboard without requiring pxGrid getEndpoints.
"""
import logging
import json
import os
import time
from collections import defaultdict
from concurrent.futures import ThreadPoolExecutor

from .. import metrics
from ..util import (clear_metric, first_nonempty, normalize_agent_version,
                    normalize_bool_label, normalize_mac, parse_posture_report,
                    POSTURE_REPORT_KEYS, SECURECLIENT_VERSION_KEYS)
from . import CollectorFailed, observe, pxgrid_endpoints_present

logger = logging.getLogger(__name__)

_records = {}             # endpoint id -> {"seen": epoch, "detail": {}}
_group_cache = {}         # endpoint group id -> group name
_profile_cache = {}       # profiler profile id -> policy/profile name
_next_page = 1
_cache_loaded = False
_posture_attributes_present = False


def posture_attributes_present():
    """Whether cached ERS endpoints currently own posture-policy/agent metrics."""
    return _posture_attributes_present


def collect(client, cfg):
    with observe("ers_endpoint_attributes"):
        _load_cache_once(cfg.ers_endpoint_attribute_cache_file)
        _expire_cache(cfg.ers_endpoint_attribute_cache_ttl)
        inventory_total = client.get_ers_total("/config/endpoint",
                                               api_name="ers_endpoint_attr_total")
        refreshed, errors = _refresh_page(client, cfg)
        _emit_metrics(client, cfg, refreshed, errors, inventory_total)
        _save_cache(cfg.ers_endpoint_attribute_cache_file)


def _load_cache_once(path):
    global _cache_loaded, _next_page
    if _cache_loaded or not path:
        return
    _cache_loaded = True
    try:
        with open(path, encoding="utf-8") as fh:
            data = json.load(fh)
    except FileNotFoundError:
        return
    except Exception as e:
        logger.warning("ERS endpoint attributes: failed to load cache %s: %s", path, e)
        return
    if not isinstance(data, dict):
        return
    records = data.get("records")
    if isinstance(records, dict):
        _records.clear()
        for endpoint_id, rec in records.items():
            if isinstance(rec, dict) and isinstance(rec.get("detail"), dict):
                _records[str(endpoint_id)] = {
                    "seen": float(rec.get("seen") or 0),
                    "detail": rec["detail"],
                }
    groups = data.get("groups")
    if isinstance(groups, dict):
        _group_cache.clear()
        _group_cache.update({str(k): str(v) for k, v in groups.items()})
    profiles = data.get("profiles")
    if isinstance(profiles, dict):
        _profile_cache.clear()
        _profile_cache.update({str(k): str(v) for k, v in profiles.items()})
    try:
        _next_page = max(1, int(data.get("next_page") or 1))
    except (TypeError, ValueError):
        _next_page = 1
    logger.info("ERS endpoint attributes: loaded cache %s records=%d next_page=%d",
                path, len(_records), _next_page)


def _save_cache(path):
    if not path:
        return
    data = {
        "version": 1,
        "saved_at": time.time(),
        "next_page": _next_page,
        "records": _records,
        "groups": _group_cache,
        "profiles": _profile_cache,
    }
    try:
        directory = os.path.dirname(path)
        if directory:
            os.makedirs(directory, exist_ok=True)
        tmp = f"{path}.tmp"
        fd = os.open(tmp, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
        with os.fdopen(fd, "w", encoding="utf-8") as fh:
            json.dump(data, fh, sort_keys=True, separators=(",", ":"))
        os.replace(tmp, path)
    except Exception as e:
        logger.warning("ERS endpoint attributes: failed to save cache %s: %s", path, e)


def _expire_cache(ttl):
    if ttl <= 0:
        return
    cutoff = time.time() - ttl
    for endpoint_id in [eid for eid, rec in _records.items() if rec.get("seen", 0) < cutoff]:
        _records.pop(endpoint_id, None)


# ISE ERS caps a single /config/endpoint list request at size=100; the configured
# page size is a per-cycle refresh *budget*, gathered across as many 100-row ERS
# pages as needed and walked across cycles via _next_page.
_ERS_MAX_LIST_SIZE = 100


def _refresh_page(client, cfg):
    global _next_page
    budget = max(1, cfg.ers_endpoint_attribute_page_size)
    ers_size = min(budget, _ERS_MAX_LIST_SIZE)
    start_page = _next_page
    endpoints = []
    while len(endpoints) < budget:
        batch = client.get_ers("/config/endpoint", {"size": ers_size, "page": _next_page},
                               api_name="ers_endpoint_attr_list") or []
        endpoints.extend(batch)
        if len(batch) >= ers_size:
            _next_page += 1          # full page — keep gathering toward the budget
        else:
            _next_page = 1           # short/empty page — end of inventory, wrap
            break

    if not endpoints:
        if start_page == 1:
            raise CollectorFailed("no endpoint list returned for ERS attribute scan")
        return 0, {"list": 0, "detail": 0}

    endpoint_ids = [ep["id"] for ep in endpoints if isinstance(ep, dict) and ep.get("id")]
    stale_ids = [eid for eid in endpoint_ids if _is_stale(eid, cfg.ers_endpoint_attribute_cache_ttl)]
    errors = {"list": 0, "detail": 0}
    if not stale_ids:
        return 0, errors

    def fetch(endpoint_id):
        detail = client.get_ers(f"/config/endpoint/{endpoint_id}", api_name="ers_endpoint_attr_detail")
        return endpoint_id, detail, (None if detail is not None else "detail")

    refreshed = 0
    with ThreadPoolExecutor(max_workers=max(1, cfg.max_workers)) as pool:
        for endpoint_id, detail, error in pool.map(fetch, stale_ids):
            if error:
                errors[error] += 1
                continue
            _records[endpoint_id] = {"seen": time.time(), "detail": _endpoint_detail(detail)}
            refreshed += 1
    return refreshed, errors


def _is_stale(endpoint_id, ttl):
    rec = _records.get(endpoint_id)
    return not rec or ttl <= 0 or (time.time() - rec.get("seen", 0)) >= ttl


def _endpoint_detail(raw):
    if not isinstance(raw, dict):
        return {}
    ep = raw.get("ERSEndPoint", raw)
    return ep if isinstance(ep, dict) else {}


def _emit_metrics(client, cfg, refreshed, errors, inventory_total=None):
    global _posture_attributes_present
    pxgrid_has_endpoints = pxgrid_endpoints_present()
    _posture_attributes_present = any(
        first_nonempty(_custom_attrs(rec["detail"]),
                       *(POSTURE_REPORT_KEYS + SECURECLIENT_VERSION_KEYS))
        for rec in _records.values())
    metric_list = [
        metrics.ise_endpoint_attribute_fetch_errors,
        metrics.ise_endpoint_attribute_coverage,
        metrics.ise_endpoints_by_profiled_policy,
        metrics.ise_endpoints_by_identity_group,
        metrics.ise_endpoint_static_assignment,
        metrics.ise_endpoint_custom_attribute_value,
    ]
    if not pxgrid_has_endpoints:
        metric_list.extend((
            metrics.ise_endpoints_by_policy,
            metrics.ise_endpoints_by_profile_all,
            metrics.ise_endpoints_by_hardware_model,
            metrics.ise_endpoints_by_manufacturer,
            metrics.ise_endpoints_by_endpoint_type,
            metrics.ise_endpoints_by_os,
            metrics.ise_endpoint_mfc_coverage,
        ))
        if _posture_attributes_present:
            metric_list.extend((metrics.ise_posture_policy_result,
                                metrics.ise_endpoints_by_secureclient_version))
    for metric in metric_list:
        clear_metric(metric)

    total = int(inventory_total) if inventory_total is not None else len(_records)
    cached = len(_records)
    metrics.ise_endpoints_total.set(total)
    metrics.ise_endpoint_attribute_cache_entries.set(cached)
    metrics.ise_endpoint_attribute_scan_last_count.set(refreshed)
    for stage, count in errors.items():
        metrics.ise_endpoint_attribute_fetch_errors.labels(stage=stage).set(count)
    if not cached:
        return

    by_policy = defaultdict(int)
    by_group = defaultdict(int)
    by_static = defaultdict(int)
    by_custom = defaultdict(int)
    coverage = defaultdict(int, {"posture_report": 0, "secureclient_version": 0})
    profile_ids = {}          # leaf policy label -> profileId, for the ERS hierarchy fallback
    by_manufacturer = defaultdict(int)
    by_model = defaultdict(int)
    by_os = defaultdict(int)
    by_scversion = defaultdict(set)
    posture_policies = defaultdict(set)
    mfc_cov = defaultdict(int)

    custom_keys = set(cfg.ers_endpoint_custom_attribute_keys)
    for rec in _records.values():
        ep = rec["detail"]

        policy = _resolve_profile(client, ep.get("profileId"))
        _count(by_policy, policy, cfg)
        _cover(coverage, "policy", policy)
        policy_label = _label(policy, cfg) or "unknown"
        if ep.get("profileId") and policy_label != "unknown":
            profile_ids.setdefault(policy_label, ep["profileId"])

        group = _resolve_group(client, ep.get("groupId"))
        _count(by_group, group, cfg)
        _cover(coverage, "identity_group", group)

        for key in ("staticProfileAssignment", "staticGroupAssignment"):
            by_static[(key, normalize_bool_label(ep.get(key)))] += 1

        # ISE MFC classification (manufacturer/model/OS), learned by the profiler and
        # exposed on the ERS endpoint object — no pxGrid getEndpoints required.
        mfg = _mfc(ep, "mfcHardwareManufacturer")
        _count(by_manufacturer, mfg, cfg)
        _cover(mfc_cov, "manufacturer", mfg)
        model = _mfc(ep, "mfcHardwareModel")
        _count(by_model, model, cfg)
        _cover(mfc_cov, "model", model)
        os_ = _mfc(ep, "mfcOperatingSystem")
        _count(by_os, os_, cfg)
        _cover(mfc_cov, "os", os_)

        custom = _custom_attrs(ep)
        endpoint_key = normalize_mac(ep.get("mac") or ep.get("name")) or str(ep.get("id") or "")
        report = first_nonempty(custom, *POSTURE_REPORT_KEYS)
        if report and endpoint_key:
            coverage["posture_report"] += 1
            for policy_name, result in parse_posture_report(report):
                posture_policies[(policy_name, result, "unknown")].add(endpoint_key)
        version = normalize_agent_version(first_nonempty(custom, *SECURECLIENT_VERSION_KEYS))
        if version and endpoint_key:
            coverage["secureclient_version"] += 1
            by_scversion[version].add(endpoint_key)
        for key in custom_keys:
            value = custom.get(key)
            if value:
                by_custom[(key, _label(value, cfg))] += 1
                coverage[f"custom_{key}"] += 1

    _emit_labeled(metrics.ise_endpoints_by_profiled_policy, by_policy, "policy")
    _emit_labeled(metrics.ise_endpoints_by_identity_group, by_group, "group")
    for (assignment, value), count in by_static.items():
        metrics.ise_endpoint_static_assignment.labels(assignment=assignment, value=value).set(count)
    for (key, value), count in by_custom.items():
        metrics.ise_endpoint_custom_attribute_value.labels(key=key, value=value).set(count)
    for attr, count in coverage.items():
        metrics.ise_endpoint_attribute_coverage.labels(attribute=attr).set(count / cached)

    if not pxgrid_has_endpoints:
        # No pxGrid catalog on this run — fill the category/parent hierarchy from ERS
        # so ise_endpoints_by_profile_all carries real categories instead of "unknown".
        from .models import resolve_hierarchy_from_ers
        resolve_hierarchy_from_ers(client, profile_ids)
        _emit_baseline_endpoint_metrics(by_policy, total)
        # MFC manufacturer/model/OS from the ERS mfcAttributes (real for profiled
        # endpoints, "unknown" otherwise); pxGrid getEndpoints can still overwrite these.
        _emit_labeled(metrics.ise_endpoints_by_manufacturer, by_manufacturer, "manufacturer")
        _emit_labeled(metrics.ise_endpoints_by_hardware_model, by_model, "model")
        _emit_labeled(metrics.ise_endpoints_by_os, by_os, "os")
        for attr in ("manufacturer", "model", "os", "endpoint_type"):
            metrics.ise_endpoint_mfc_coverage.labels(attribute=attr).set(mfc_cov.get(attr, 0) / cached)
        if not _emit_device_type_summary(client):
            metrics.ise_endpoints_by_endpoint_type.labels(endpoint_type="unknown").set(total)
        if _posture_attributes_present:
            for version, endpoint_keys in by_scversion.items():
                metrics.ise_endpoints_by_secureclient_version.labels(
                    version=version).set(len(endpoint_keys))
            for (policy_name, result, owner), endpoint_keys in posture_policies.items():
                metrics.ise_posture_policy_result.labels(
                    policy=policy_name, result=result, ops_owner=owner
                ).set(len(endpoint_keys))
    logger.info("ERS endpoint attributes: cache=%d refreshed=%d next_page=%d",
                total, refreshed, _next_page)


def _emit_device_type_summary(client):
    """Populate ise_endpoints_by_endpoint_type from the OpenAPI
    /api/v1/endpoint/deviceType/summary — a server-aggregated per-type count that
    works on ISE 3.3 without pxGrid (the per-endpoint MFC type is pxGrid-only, but
    this rollup is not). Returns True if at least one row was emitted."""
    rows = client.get_pan_api("/endpoint/deviceType/summary",
                              api_name="endpoint_device_type_summary", unwrap=False)
    if not isinstance(rows, list):
        return False
    emitted = False
    for row in rows:
        if not isinstance(row, dict):
            continue
        try:
            count = int(row.get("total") or 0)
        except (TypeError, ValueError):
            continue
        metrics.ise_endpoints_by_endpoint_type.labels(
            endpoint_type=str(row.get("deviceType") or "unknown")).set(count)
        emitted = True
    return emitted


def _emit_baseline_endpoint_metrics(by_policy, total):
    """ERS is the baseline endpoint inventory source, especially on ISE 3.3 where
    pxGrid getEndpoints commonly returns zero. Emit the shared endpoint-profile
    gauges here too; pxGrid getEndpoints can still overwrite them as enrichment
    when it is actually delivering endpoints."""
    if not total:
        return
    from .models import _hierarchy

    for policy, count in by_policy.items():
        metrics.ise_endpoints_by_policy.labels(policy=policy).set(count)
        category, parent = _hierarchy.get(policy, ("unknown", ""))
        metrics.ise_endpoints_by_profile_all.labels(
            category=category, parent=parent, profile=policy).set(count)


def _label(value, cfg):
    text = str(value or "").strip()
    if not text:
        return ""
    text = " ".join(text.split())
    max_len = max(8, cfg.ers_endpoint_attribute_value_max_len)
    return text if len(text) <= max_len else text[:max_len - 3] + "..."


def _count(counter, value, cfg):
    counter[_label(value, cfg) or "unknown"] += 1


def _cover(coverage, attr, value):
    if value:
        coverage[attr] += 1


def _emit_labeled(metric, rows, label):
    for value, count in rows.items():
        metric.labels(**{label: value}).set(count)


def _mfc(ep, key):
    """Read an ISE MFC attribute (mfcHardwareManufacturer / mfcHardwareModel /
    mfcOperatingSystem / mfcDeviceType) off the ERS endpoint object's mfcAttributes.
    ISE returns each value as a list split on commas, so rejoin -> 'Cisco Systems, Inc.'."""
    vals = (ep.get("mfcAttributes") or {}).get(key)
    if isinstance(vals, list):
        return ",".join(str(v) for v in vals).strip()
    return str(vals or "").strip()


def _custom_attrs(ep):
    custom = ep.get("customAttributes") or {}
    if not isinstance(custom, dict):
        return {}
    nested = custom.get("customAttributes")
    if isinstance(nested, dict):
        return nested
    return custom


def _resolve_group(client, group_id):
    if not group_id:
        return ""
    if group_id not in _group_cache:
        data = client.get_ers(f"/config/endpointgroup/{group_id}",
                              api_name="ers_endpoint_attr_group")
        group = (data or {}).get("EndPointGroup", {}) if isinstance(data, dict) else {}
        _group_cache[group_id] = group.get("name") or group_id
    return _group_cache[group_id]


def _resolve_profile(client, profile_id):
    if not profile_id:
        return ""
    if profile_id not in _profile_cache:
        data = client.get_ers(f"/config/profilerprofile/{profile_id}",
                              api_name="ers_endpoint_attr_profile")
        profile = (data or {}).get("ProfilerProfile", {}) if isinstance(data, dict) else {}
        _profile_cache[profile_id] = profile.get("name") or profile_id
    return _profile_cache[profile_id]
