"""Device-model collector: one bulk pxGrid getEndpoints, aggregated in-process by
MFC attributes (hardware model / manufacturer / endpoint type / OS / policy). No
per-endpoint fan-out. Manufacturer falls back model->oui->unknown so OUI lifts
coverage where MFC manufacturer is blank; unclassified buckets to 'unknown' so
gaps stay visible. Also emits MFC coverage fractions per attribute.

Also joins the ISE-wide profiler POLICY CATALOG (pxGrid getProfiles — the
category/parent hierarchy shown in Policy > Profiling, not endpoint counts)
onto the by-policy counts above, so ise_endpoints_by_profile_all carries
category/parent labels alongside the flat policy name. The catalog changes
rarely, so it's cached at module scope and refreshed at most every
profiler_hierarchy_ttl seconds regardless of how often emit_endpoint_metrics
runs (every 30s in stream mode) — a failed refresh doesn't retry every call
either, it just leaves 'unknown' category/parent until the next TTL window."""
import logging
import time
from collections import defaultdict

from .. import metrics
from ..util import (clear_metric, first_nonempty, normalize_mac,
                    parse_posture_report, normalize_agent_version)
logger = logging.getLogger(__name__)

# pxGrid emits camelCase; Context Visibility / ERS show PascalCase. Read both.
_MODEL_KEYS = ("mfcInfoHardwareModel", "MFCInfoHardwareModel")
_MFG_KEYS = ("mfcInfoHardwareManufacturer", "MFCInfoHardwareManufacturer")
_TYPE_KEYS = ("mfcInfoEndpointType", "MFCInfoEndpointType", "mfcInfoDeviceType")
_OS_KEYS = ("mfcInfoOperatingSystem", "MFCInfoOperatingSystem")
_POLICY_KEYS = ("endPointPolicy", "EndPointPolicy", "MFCInfoEndpointPolicy")
_OUI_KEYS = ("oui", "OUI")
# Secure Client / posture agent version — attribute name varies (and may be absent
# entirely) across ISE versions; read every plausible spelling. Best-effort: only
# endpoints with a real value produce a series, so an all-blank deployment leaves
# ise_endpoints_by_secureclient_version empty rather than one giant 'unknown' bucket.
_SECURECLIENT_VERSION_KEYS = ("secureClientVersion", "SecureClientVersion",
                              "anyConnectVersion", "AnyConnectVersion",
                              "postureAgentVersion", "PostureAgentVersion",
                              "AnyConnectAgentVersion")
# Per-policy posture pass/fail lives in the endpoint's PostureReport attribute
# (Context Visibility), collected here via getEndpoints — NOT the endpoint topic and
# NOT MnT session detail.
_POSTURE_REPORT_KEYS = ("PostureReport", "postureReport")
_MAC_KEYS = ("macAddress", "MACAddress", "mac")


def _ep_attr(ep, *keys):
    """Read an endpoint attribute by any of `keys`, checking the top level first and
    then the nested attribute maps ISE sometimes wraps custom attributes in — so this
    works whether getEndpoints returns attributes flat or under customAttributes/etc."""
    v = first_nonempty(ep, *keys)
    if v:
        return v
    for container in ("customAttributes", "attributes", "otherAttributes"):
        sub = ep.get(container)
        if isinstance(sub, dict):
            v = first_nonempty(sub, *keys)
            if v:
                return v
    return ""

# leaf policy name -> (category, parent); empty until the first successful fetch
_hierarchy = {}
_hierarchy_fetched_at = 0.0   # last SUCCESSFUL refresh — drives the age gauge
_hierarchy_checked_at = 0.0   # last attempt (success or failure) — TTL-gates retries


def collect(pxgrid, cfg):
    try:
        endpoints = pxgrid.get_endpoints(timeout=cfg.pxgrid_query_timeout)
    except Exception as e:
        logger.warning("pxGrid getEndpoints failed: %s", e)
        return
    if not endpoints:
        return
    emit_endpoint_metrics(endpoints, pxgrid=pxgrid, hierarchy_ttl=cfg.profiler_hierarchy_ttl)


def _parse_profile_hierarchy(profiles):
    """getProfiles returns the policy catalog as a flat list with a colon-joined
    ancestry path, e.g. name='Apple-iPhone', fullName='Apple-Device:Apple-iDevice:
    Apple-iPhone'. category is the hierarchy root; parent the immediate ancestor;
    both are absent (empty) for a top-level policy that has no parent."""
    table = {}
    for p in profiles:
        name = first_nonempty(p, "name", "Name")
        full = first_nonempty(p, "fullName", "fqname", "FullName", "FQName") or name
        if not name:
            continue
        parts = [seg for seg in full.split(":") if seg]
        category = parts[0] if parts else name
        parent = parts[-2] if len(parts) > 1 else ""
        table[name] = (category, parent)
    return table


def _refresh_hierarchy(pxgrid, ttl):
    global _hierarchy, _hierarchy_fetched_at, _hierarchy_checked_at
    if (time.time() - _hierarchy_checked_at) < ttl:
        return
    _hierarchy_checked_at = time.time()
    try:
        profiles = pxgrid.get_profiler_profiles()
    except Exception as e:
        logger.warning("pxGrid getProfiles (profiler hierarchy) failed: %s", e)
        return
    if not profiles:
        return
    _hierarchy = _parse_profile_hierarchy(profiles)
    _hierarchy_fetched_at = time.time()
    metrics.ise_profiler_policies_total.set(len(_hierarchy))
    logger.info("profiler hierarchy refreshed: %d policies", len(_hierarchy))


def emit_endpoint_metrics(endpoints, pxgrid=None, hierarchy_ttl=3600, mac_owner=None):
    """Aggregate a list of pxGrid endpoint attribute maps onto the model + posture
    gauges. Shared by the poll collector (collect) and the stream projector. Pass
    pxgrid to also join the profiler category/parent hierarchy (TTL-gated — safe to
    call every projection tick); omit it to skip that join entirely (e.g. tests that
    don't care about the hierarchy). mac_owner is an optional {MAC: ops_owner} map
    (the stream projector builds it from live sessions) used to label posture by ops
    owner; endpoints with no matching session fall back to ops_owner='unknown'."""
    if pxgrid is not None:
        _refresh_hierarchy(pxgrid, hierarchy_ttl)
    if _hierarchy_fetched_at:
        metrics.ise_profiler_hierarchy_age_seconds.set(time.time() - _hierarchy_fetched_at)
    mac_owner = mac_owner or {}

    by_model = defaultdict(int)
    by_mfg = defaultdict(int)
    by_type = defaultdict(int)
    by_os = defaultdict(int)
    by_policy = defaultdict(int)
    by_scversion = defaultdict(int)
    posture_policies = defaultdict(set)   # (policy, result, ops_owner) -> {mac}
    coverage = {"model": 0, "manufacturer": 0, "endpoint_type": 0, "os": 0}
    total = 0

    for ep in endpoints:
        total += 1
        model = first_nonempty(ep, *_MODEL_KEYS)
        mfg = first_nonempty(ep, *_MFG_KEYS)
        oui = first_nonempty(ep, *_OUI_KEYS)
        etype = first_nonempty(ep, *_TYPE_KEYS)
        os_ = first_nonempty(ep, *_OS_KEYS)
        policy = first_nonempty(ep, *_POLICY_KEYS)
        scversion = normalize_agent_version(_ep_attr(ep, *_SECURECLIENT_VERSION_KEYS))
        if scversion:
            by_scversion[scversion] += 1

        # per-policy posture pass/fail from the endpoint's PostureReport attribute
        mac = normalize_mac(first_nonempty(ep, *_MAC_KEYS))
        report = _ep_attr(ep, *_POSTURE_REPORT_KEYS)
        if report and mac:
            owner = mac_owner.get(mac, "unknown")
            for pol, res in parse_posture_report(report):
                posture_policies[(pol, res, owner)].add(mac)

        if model:
            coverage["model"] += 1
        # manufacturer: MFC field, then OUI fallback
        mfg_final = mfg or oui
        if mfg_final:
            coverage["manufacturer"] += 1
        if etype:
            coverage["endpoint_type"] += 1
        if os_:
            coverage["os"] += 1

        by_model[model or "unknown"] += 1
        by_mfg[mfg_final or "unknown"] += 1
        by_type[etype or "unknown"] += 1
        by_os[os_ or "unknown"] += 1
        by_policy[policy or "unknown"] += 1

    for metric in (metrics.ise_endpoints_by_hardware_model, metrics.ise_endpoints_by_manufacturer,
                   metrics.ise_endpoints_by_endpoint_type, metrics.ise_endpoints_by_os,
                   metrics.ise_endpoints_by_policy, metrics.ise_endpoint_mfc_coverage,
                   metrics.ise_endpoints_by_profile_all,
                   metrics.ise_endpoints_by_secureclient_version,
                   metrics.ise_posture_policy_result):
        clear_metric(metric)

    for model, n in by_model.items():
        metrics.ise_endpoints_by_hardware_model.labels(model=model).set(n)
    for mfg, n in by_mfg.items():
        metrics.ise_endpoints_by_manufacturer.labels(manufacturer=mfg).set(n)
    for etype, n in by_type.items():
        metrics.ise_endpoints_by_endpoint_type.labels(endpoint_type=etype).set(n)
    for os_, n in by_os.items():
        metrics.ise_endpoints_by_os.labels(os=os_).set(n)
    for policy, n in by_policy.items():
        metrics.ise_endpoints_by_policy.labels(policy=policy).set(n)
        category, parent = _hierarchy.get(policy, ("unknown", ""))
        metrics.ise_endpoints_by_profile_all.labels(
            category=category, parent=parent, profile=policy).set(n)

    for ver, n in by_scversion.items():
        metrics.ise_endpoints_by_secureclient_version.labels(version=ver).set(n)
    for (pol, res, owner), macs in posture_policies.items():
        metrics.ise_posture_policy_result.labels(
            policy=pol, result=res, ops_owner=owner).set(len(macs))

    metrics.ise_endpoints_pxgrid_total.set(total)
    for attr, hit in coverage.items():
        metrics.ise_endpoint_mfc_coverage.labels(attribute=attr).set(hit / total if total else 0.0)
    logger.debug("models: %d endpoints, model coverage %.0f%%",
                 total, 100 * coverage["model"] / total if total else 0)
