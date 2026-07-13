"""authz collector (port of collect_authz_metrics) — the per-MAC Session/MACAddress
fan-out. Cached because the policy decision is stable for a session's lifetime, so
steady-state cost is just new MACs. Cold-cache cost is bounded by
max_detail_fetches_per_cycle so this collector never blocks the others; the cache
warms over a few hours and metrics converge as it fills.

Emits *unique-endpoint* (distinct-MAC) counts per (nad, location, ops_owner) for
status / failure-reason / auth-method / authz-profile / matched-rule / policy-set.
The matched-rule and policy-set come from other_attr_string and are the ground-truth
open-mode vs closed-mode signal."""
import logging
import math
from collections import defaultdict
from concurrent.futures import ThreadPoolExecutor

from .. import metrics
from ..util import (clear_metric, clear_metric_where, normalize_mac,
                    normalize_location, parse_other_attr_string, normalize_posture,
                    parse_posture_report, normalize_agent_version, first_nonempty,
                    parse_step_latencies, SECURECLIENT_VERSION_KEYS, POSTURE_REPORT_KEYS)
from . import observe, CollectorFailed, stream_active
from .devices import nad_labels

logger = logging.getLogger(__name__)
_UNSET = object()

# SECURECLIENT_VERSION_KEYS / POSTURE_REPORT_KEYS (shared with models.py, defined in util)
# are pulled from a session's other_attr_string and emitted onto ise_posture_policy_result /
# ise_endpoints_by_secureclient_version ONLY when pxGrid getEndpoints isn't delivering
# endpoints (models.py owns them otherwise) — see the fallback block in collect().

# Gauges this collector owns in POLL mode (all of them) vs STREAMING mode. In
# streaming mode the pxGrid projector owns sessions / passed-status / auth-methods /
# profiles; authz keeps the MnT fan-out only for the signals the session topic can't
# carry — failure reasons, matched authz rule, and policy set — so those three are
# the only gauges it clears/emits, avoiding a double-clear war with the projector.
_STREAM_OWNED = (
    metrics.ise_session_failure_reasons,
    metrics.ise_session_failure_auth_methods,
    metrics.ise_session_authz_rule_endpoints,
    metrics.ise_session_policy_set_endpoints,
)
_UNIQUE_ENDPOINT_METRICS = (
    metrics.ise_session_status_endpoints, metrics.ise_session_auth_methods,
    metrics.ise_authz_unique_endpoints_by_profile, metrics.ise_session_posture_status,
) + _STREAM_OWNED

_cache = None
_observed_recent_auth_ids = {}
_MAX_OBSERVED_RECENT_AUTHS = 10000


def _posture_source_owners():
    """Return independent ownership for (PostureReport, agent version).

    A populated endpoint feed is not sufficient: ISE commonly returns endpoints
    without either posture field while exposing both in MnT other_attr_string.
    """
    from . import endpoint_attributes, models
    report = (models.posture_report_present()
              or endpoint_attributes.posture_report_present())
    version = (models.secureclient_version_present()
               or endpoint_attributes.secureclient_version_present())
    return report, version


def _detail_cache(cfg):
    global _cache
    if _cache is None:
        from ..caches import SessionDetailCache
        _cache = SessionDetailCache(cfg.session_detail_cache_ttl)
    return _cache


def _fetch_detail(client, cache, mac):
    """Fetch + cache one MAC's detail, recording the fetch result. Returns detail."""
    res = client.get_mnt_xml(f"/Session/MACAddress/{mac}", api_name="mnt_mac_session")
    if res is None or not res.get("sessions"):
        metrics.ise_session_detail_fetches_total.labels(result="fetch_failed").inc()
        return None
    detail = res["sessions"][0]
    cache.set(mac, detail)
    metrics.ise_session_detail_fetches_total.labels(result="fetched").inc()
    return detail


def _fetch_recent_auth_status(client, mac):
    """Fetch recent Live Log auth status for a MAC. Session/MACAddress is tied to
    live accounting sessions and can miss Access-Reject records; AuthStatus carries
    the recent reject details that failure triage panels need."""
    return client.get_mnt_xml(f"/AuthStatus/MACAddress/{mac}/600/20/All",
                              api_name="mnt_auth_status")


def _recent_auth_status_macs(client, cfg, active_macs):
    limit = min(getattr(cfg, "recent_auth_status_max", 25),
                getattr(cfg, "max_detail_fetches_per_cycle", 2000))
    macs = list(active_macs)
    seen = set(macs)
    if len(macs) >= limit:
        return macs[:limit]
    if not hasattr(client, "get_ers"):
        return macs
    endpoints = client.get_ers("/config/endpoint", {"size": 100}, get_all=True,
                               api_name="ers_endpoint_recent_auth_status") or []
    for ep in endpoints:
        mac = normalize_mac(ep.get("name", ""))
        if mac and mac not in seen:
            macs.append(mac)
            seen.add(mac)
        if len(macs) >= limit:
            break
    return macs


def _emit_unique(metric, accumulator, first_label):
    """Emit distinct-MAC counts for a `{(first, nad, loc, owner): {mac}}` accumulator
    onto a gauge whose first label is `first_label` and rest are the NAD label set."""
    for (first, nad, loc, owner), macs in accumulator.items():
        metric.labels(**{first_label: first, "nad_hostname": nad,
                         "location": loc, "ops_owner": owner}).set(len(macs))


def _milliseconds(value):
    try:
        milliseconds = float(value)
    except (TypeError, ValueError):
        return None
    return milliseconds / 1000.0 if milliseconds >= 0 and math.isfinite(milliseconds) else None


def _observe_latency(detail, other, nad, loc, owner):
    """Observe one freshly fetched authentication's total, client, and step timing."""
    status = ("passed" if detail.get("passed", "").lower() == "true"
              else "failed" if detail.get("failed", "").lower() == "true"
              else "unknown")
    psn = (detail.get("acs_server") or "unknown").strip() or "unknown"
    total = _milliseconds(other.get("TotalAuthenLatency"))
    if total is not None:
        metrics.ise_radius_auth_latency_seconds.labels(
            nad_hostname=nad, location=loc, ops_owner=owner, status=status
        ).observe(total)
        metrics.ise_radius_auth_latency_by_psn_seconds.labels(
            psn=psn, status=status).observe(total)
    client = _milliseconds(other.get("ClientLatency"))
    if client is not None:
        metrics.ise_radius_client_latency_seconds.labels(
            psn=psn, status=status).observe(client)
    for step_code, latency in parse_step_latencies(
            detail.get("execution_steps"), other.get("StepLatency")):
        metrics.ise_radius_step_latency_seconds.labels(
            psn=psn, step_code=step_code, status=status).observe(latency)


def _observe_recent_latency_once(detail, other, nad, loc, owner):
    """Observe Live Log latency once per auth transaction despite repeated polling."""
    auth_id = str(detail.get("auth_id") or detail.get("cpmsession_id") or "").strip()
    if not auth_id or auth_id in _observed_recent_auth_ids:
        return
    _observe_latency(detail, other, nad, loc, owner)
    _observed_recent_auth_ids[auth_id] = None
    while len(_observed_recent_auth_ids) > _MAX_OBSERVED_RECENT_AUTHS:
        _observed_recent_auth_ids.pop(next(iter(_observed_recent_auth_ids)))


def collect(client, cfg, mappings, active_list=_UNSET):
    with observe("authz"):
        result = active_list
        if result is _UNSET:
            result = client.get_mnt_xml("/Session/ActiveList", api_name="mnt_sessions")
        if result is None:
            raise CollectorFailed("no ActiveList response")
        cache = _detail_cache(cfg)
        # only defer to the projector while the stream is actually UP; when it's down we
        # emit the full status/method/profile set from the poll fan-out (fallback).
        streaming = stream_active(cfg)
        owned = _STREAM_OWNED if streaming else _UNIQUE_ENDPOINT_METRICS

        active_macs = set()
        for s in result.get("sessions", []):
            mac = normalize_mac(s.get("calling_station_id", ""))
            if mac:
                active_macs.add(mac)
        recent_status_macs = _recent_auth_status_macs(client, cfg, active_macs)

        if not active_macs and not recent_status_macs:
            cache.cleanup(active_macs)   # no active sessions -> drop all cached detail
            for m in owned:
                clear_metric(m)
            # status="failed" isn't in _STREAM_OWNED, so in stream mode the loop above didn't
            # clear it — do it explicitly (mirrors the main path) or a stale failed-endpoint
            # series lingers after ActiveList drops to empty. Poll mode's full clear covered it.
            if streaming:
                clear_metric_where(metrics.ise_session_status_endpoints, status="failed")
            # no sessions -> no other_attr_string posture either; clear the fallback gauges
            # unless getEndpoints owns them.
            report_owned, version_owned = _posture_source_owners()
            if not report_owned:
                clear_metric(metrics.ise_posture_policy_result)
            if not version_owned:
                clear_metric(metrics.ise_endpoints_by_secureclient_version)
            metrics.ise_session_detail_cache_size.set(cache.size())
            metrics.ise_session_warmup_progress.set(1.0)
            return

        dropped = cache.cleanup(active_macs)

        # single pass over active MACs: keep the cached detail, queue the misses
        details = {}
        uncached = []
        for mac in active_macs:
            d = cache.get(mac)
            if d is None:
                uncached.append(mac)
            else:
                details[mac] = d
        to_fetch = uncached[:cfg.max_detail_fetches_per_cycle]
        if details:
            metrics.ise_session_detail_fetches_total.labels(result="cache_hit").inc(len(details))
        logger.info("Authz: %d unique MACs, %d uncached, fetching %d (skip %d), %d stale dropped",
                    len(active_macs), len(uncached), len(to_fetch),
                    len(uncached) - len(to_fetch), dropped)

        newly_fetched = set()   # observe latency once per fresh fetch, not per scrape cycle
        if to_fetch:
            with ThreadPoolExecutor(max_workers=max(1, cfg.max_workers)) as pool:
                for mac, detail in zip(to_fetch, pool.map(
                        lambda m: _fetch_detail(client, cache, m), to_fetch)):
                    if detail is not None:
                        details[mac] = detail
                        newly_fetched.add(mac)

        passed = defaultdict(set)
        failed = defaultdict(set)
        reasons = defaultdict(set)
        methods = defaultdict(set)
        failed_methods = defaultdict(set)
        profiles = defaultdict(set)
        rules = defaultdict(set)
        policy_sets = defaultdict(set)
        posture = defaultdict(set)          # (status, loc, owner) -> {mac}
        posture_policies = defaultdict(set)  # (policy, result, owner) -> {mac} (PostureReport)
        scversion = defaultdict(set)         # secure-client version -> {mac}

        for mac, detail in details.items():
            # accounting (Stop) records carry no auth verdict — skip them
            if "passed" not in detail and "failed" not in detail:
                continue

            nas_ip = detail.get("nas_ip_address", "")
            name_hint = detail.get("network_device_name")
            loc_hint = normalize_location(detail["location"]) if detail.get("location") else None
            nad, loc, owner = nad_labels(mappings, nas_ip, name_hint=name_hint, loc_hint=loc_hint)
            key = (nad, loc, owner)

            if detail.get("passed", "").lower() == "true":
                passed[key].add(mac)
            if detail.get("failed", "").lower() == "true":
                failed[key].add(mac)
                reason = detail.get("failure_reason", "")
                code = reason.split(" ", 1)[0] if reason else "unknown"
                if code and code != "unknown":
                    reasons[(code,) + key].add(mac)

            method = detail.get("authentication_method", "")
            if method:
                methods[(method,) + key].add(mac)
                if detail.get("failed", "").lower() == "true":
                    failed_methods[(method,) + key].add(mac)

            for p in detail.get("selected_azn_profiles", "").split(","):
                p = p.strip()
                if p:
                    profiles[(p,) + key].add(mac)

            other = parse_other_attr_string(detail.get("other_attr_string", ""))
            if other.get("AuthorizationPolicyMatchedRule"):
                rules[(other["AuthorizationPolicyMatchedRule"],) + key].add(mac)
            if other.get("ISEPolicySetName"):
                policy_sets[(other["ISEPolicySetName"],) + key].add(mac)

            # RADIUS auth transaction latency (TotalAuthenLatency, ms). Observe only on a fresh
            # fetch so each authentication is sampled once — a Histogram is cumulative, so
            # re-observing a cache hit every scrape would inflate _count/_sum. status mirrors
            # ise_session_status_endpoints so latency panels can split passed vs failed.
            if mac in newly_fetched:
                _observe_latency(detail, other, nad, loc, owner)

            # posture field names vary by ISE version. The explicit other-attribute
            # PostureStatus is
            # authoritative: ISE 3.3 can leave the top-level/assessment status at
            # NotApplicable even when the agent reports Compliant.
            pstatus = normalize_posture(
                other.get("PostureStatus") or detail.get("posture_status")
                or other.get("PostureAssessmentStatus"))
            posture[(pstatus, loc, owner)].add(mac)

            # per-policy PostureReport + Secure Client version live in other_attr_string;
            # accumulate now, emit below only as the getEndpoints fallback (see block).
            report = first_nonempty(other, *POSTURE_REPORT_KEYS)
            if report:
                for pol, res in parse_posture_report(report):
                    posture_policies[(pol, res, owner)].add(mac)
            scver = normalize_agent_version(first_nonempty(other, *SECURECLIENT_VERSION_KEYS))
            if scver:
                scversion[scver].add(mac)

        for mac in recent_status_macs:
            status = _fetch_recent_auth_status(client, mac)
            for detail in (status or {}).get("sessions", []):
                if detail.get("failed", "").lower() != "true":
                    continue
                nas_ip = detail.get("nas_ip_address", "")
                name_hint = detail.get("network_device_name")
                loc_hint = (normalize_location(detail["location"])
                            if detail.get("location") else None)
                nad, loc, owner = nad_labels(
                    mappings, nas_ip, name_hint=name_hint, loc_hint=loc_hint)
                key = (nad, loc, owner)
                failed[key].add(mac)
                reason = detail.get("failure_reason", "")
                code = reason.split(" ", 1)[0] if reason else "unknown"
                if code and code != "unknown":
                    reasons[(code,) + key].add(mac)
                method = detail.get("authentication_method", "")
                if method:
                    methods[(method,) + key].add(mac)
                    failed_methods[(method,) + key].add(mac)
                _observe_recent_latency_once(
                    detail, parse_other_attr_string(detail.get("other_attr_string", "")),
                    nad, loc, owner)

        for m in owned:
            clear_metric(m)

        # always emitted — the session topic can't carry these
        _emit_unique(metrics.ise_session_failure_reasons, reasons, "reason_code")
        _emit_unique(metrics.ise_session_failure_auth_methods, failed_methods, "method")
        _emit_unique(metrics.ise_session_authz_rule_endpoints, rules, "authz_rule")
        _emit_unique(metrics.ise_session_policy_set_endpoints, policy_sets, "policy_set")

        # status="failed" is emitted in BOTH modes: failed auths aren't active sessions,
        # so the stream projector (which owns status="passed") can't produce them —
        # authz is the only source of the failed-endpoint count that failure-rate panels
        # need. In stream mode clear ONLY the failed series so we don't wipe the
        # projector's passed series (poll mode's full clear of `owned` already did it).
        if streaming:
            clear_metric_where(metrics.ise_session_status_endpoints, status="failed")
        for (nad, loc, owner), macs in failed.items():
            metrics.ise_session_status_endpoints.labels(
                nad_hostname=nad, location=loc, ops_owner=owner, status="failed").set(len(macs))

        # streamer-owned in stream mode, so only emit these from the poll fan-out
        if not streaming:
            for (nad, loc, owner), macs in passed.items():
                metrics.ise_session_status_endpoints.labels(
                    nad_hostname=nad, location=loc, ops_owner=owner, status="passed").set(len(macs))
            _emit_unique(metrics.ise_session_auth_methods, methods, "method")
            _emit_unique(metrics.ise_authz_unique_endpoints_by_profile, profiles, "authz_profile")
            for (status, loc, owner), macs in posture.items():
                metrics.ise_session_posture_status.labels(
                    status=status, location=loc, ops_owner=owner).set(len(macs))

        # Per-policy posture + Secure Client version fallback from the real MnT
        # other_attr_string fields. Ownership is checked independently for each metric:
        # getEndpoints often has endpoint rows but lacks one or both posture attributes.
        report_owned, version_owned = _posture_source_owners()
        if not report_owned:
            clear_metric(metrics.ise_posture_policy_result)
            for (pol, res, owner), macs in posture_policies.items():
                metrics.ise_posture_policy_result.labels(
                    policy=pol, result=res, ops_owner=owner).set(len(macs))
        if not version_owned:
            clear_metric(metrics.ise_endpoints_by_secureclient_version)
            for ver, macs in scversion.items():
                metrics.ise_endpoints_by_secureclient_version.labels(version=ver).set(len(macs))

        metrics.ise_session_detail_cache_size.set(cache.size())
        cached_count = len(details)
        warmup = cached_count / len(active_macs) if active_macs else 1.0
        metrics.ise_session_warmup_progress.set(warmup)
        logger.info("Authz: warmup=%.1f%% (%d/%d cached)", 100 * warmup, cached_count, len(active_macs))
