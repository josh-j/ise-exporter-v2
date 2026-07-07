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
from collections import defaultdict
from concurrent.futures import ThreadPoolExecutor

from .. import metrics
from ..util import (clear_metric, clear_metric_where, normalize_mac,
                    normalize_location, parse_other_attr_string, normalize_posture)
from . import observe, CollectorFailed
from .devices import nad_labels

logger = logging.getLogger(__name__)

# Gauges this collector owns in POLL mode (all of them) vs STREAMING mode. In
# streaming mode the pxGrid projector owns sessions / passed-status / auth-methods /
# profiles; authz keeps the MnT fan-out only for the signals the session topic can't
# carry — failure reasons, matched authz rule, and policy set — so those three are
# the only gauges it clears/emits, avoiding a double-clear war with the projector.
_STREAM_OWNED = (
    metrics.ise_session_failure_reasons,
    metrics.ise_session_authz_rule_endpoints,
    metrics.ise_session_policy_set_endpoints,
)
_UNIQUE_ENDPOINT_METRICS = (
    metrics.ise_session_status_endpoints, metrics.ise_session_auth_methods,
    metrics.ise_authz_unique_endpoints_by_profile, metrics.ise_session_posture_status,
) + _STREAM_OWNED

_cache = None


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


def _emit_unique(metric, accumulator, first_label):
    """Emit distinct-MAC counts for a `{(first, nad, loc, owner): {mac}}` accumulator
    onto a gauge whose first label is `first_label` and rest are the NAD label set."""
    for (first, nad, loc, owner), macs in accumulator.items():
        metric.labels(**{first_label: first, "nad_hostname": nad,
                         "location": loc, "ops_owner": owner}).set(len(macs))


def collect(client, cfg, mappings):
    with observe("authz"):
        result = client.get_mnt_xml("/Session/ActiveList", api_name="mnt_sessions")
        if result is None:
            raise CollectorFailed("no ActiveList response")
        cache = _detail_cache(cfg)
        # in streaming mode the projector owns sessions/status/methods/profiles
        streaming = cfg.collect_pxgrid_stream
        owned = _STREAM_OWNED if streaming else _UNIQUE_ENDPOINT_METRICS

        active_macs = set()
        for s in result.get("sessions", []):
            mac = normalize_mac(s.get("calling_station_id", ""))
            if mac:
                active_macs.add(mac)

        if not active_macs:
            for m in owned:
                clear_metric(m)
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

        if to_fetch:
            with ThreadPoolExecutor(max_workers=cfg.max_workers) as pool:
                for mac, detail in zip(to_fetch, pool.map(
                        lambda m: _fetch_detail(client, cache, m), to_fetch)):
                    if detail is not None:
                        details[mac] = detail

        passed = defaultdict(set)
        failed = defaultdict(set)
        reasons = defaultdict(set)
        methods = defaultdict(set)
        profiles = defaultdict(set)
        rules = defaultdict(set)
        policy_sets = defaultdict(set)
        posture = defaultdict(set)          # (status, loc, owner) -> {mac}

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

            for p in detail.get("selected_azn_profiles", "").split(","):
                p = p.strip()
                if p:
                    profiles[(p,) + key].add(mac)

            other = parse_other_attr_string(detail.get("other_attr_string", ""))
            if other.get("AuthorizationPolicyMatchedRule"):
                rules[(other["AuthorizationPolicyMatchedRule"],) + key].add(mac)
            if other.get("ISEPolicySetName"):
                policy_sets[(other["ISEPolicySetName"],) + key].add(mac)

            # posture: top-level MnT tag first, then the other-attr string (field name
            # varies by ISE version) — normalize_posture handles empty -> NotApplicable.
            pstatus = normalize_posture(
                detail.get("posture_status")
                or other.get("PostureStatus") or other.get("PostureAssessmentStatus"))
            posture[(pstatus, loc, owner)].add(mac)

        for m in owned:
            clear_metric(m)

        # always emitted — the session topic can't carry these
        _emit_unique(metrics.ise_session_failure_reasons, reasons, "reason_code")
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

        metrics.ise_session_detail_cache_size.set(cache.size())
        cached_count = len(details)
        warmup = cached_count / len(active_macs) if active_macs else 1.0
        metrics.ise_session_warmup_progress.set(warmup)
        logger.info("Authz: warmup=%.1f%% (%d/%d cached)", 100 * warmup, cached_count, len(active_macs))
