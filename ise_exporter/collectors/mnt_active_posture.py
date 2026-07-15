"""Bounded current Secure Client/posture snapshot from MnT active sessions.

This collector is deliberately separate from Data Connect posture reporting:
MnT owns only a bounded view of *currently active* endpoint details, while Data
Connect owns historical posture assessments. No fallback or shared metric family
connects the two sources.
"""
from __future__ import annotations

from collections import Counter, defaultdict
from concurrent.futures import ThreadPoolExecutor, as_completed
import hashlib
import json
import math
import re
from threading import Lock
import time

from .. import metrics
from ..snapshots import replace_metric_snapshot
from ..state import StateStore
from ..util import (
    MAX_ISE_STEP_CODE,
    SECURECLIENT_VERSION_KEYS,
    first_nonempty,
    is_mac,
    metric_label,
    normalize_agent_version,
    normalize_bool_label,
    normalize_mac,
    normalize_posture,
    parse_other_attr_string,
    parse_posture_report,
    parse_step_latencies,
)
from . import CollectorFailed, observe


MAX_STEP_CODES = 256
MAX_ACTIVE_COUNT = 1_000_000_000
MAX_STATUS_GROUPS = 256
MAX_AGENT_GROUPS = 256
MAX_POLICY_GROUPS = 1024


_FIELDS = (
    "other_attr_string",
    "posture_status",
    "posture_applicable",
    "posture_assessment_status",
    "posture_report",
    "posture_agent_version",
    "step_latency",
    "total_authentication_latency",
)

_METRICS = (
    metrics.ise_mnt_active_sessions_total,
    metrics.ise_mnt_active_posture_candidate_endpoints_total,
    metrics.ise_mnt_active_posture_detail_requests,
    metrics.ise_mnt_active_posture_detail_endpoints,
    metrics.ise_mnt_active_posture_detail_coverage_ratio,
    metrics.ise_mnt_active_posture_detail_truncated,
    metrics.ise_mnt_active_posture_cache_entries,
    metrics.ise_mnt_active_posture_cache_hits,
    metrics.ise_mnt_active_posture_cache_misses,
    metrics.ise_mnt_active_posture_refresh_deferred,
    metrics.ise_mnt_active_posture_cache_oldest_age_seconds,
    metrics.ise_mnt_active_posture_field_coverage_ratio,
    metrics.ise_mnt_active_posture_endpoints,
    metrics.ise_mnt_active_posture_applicable_endpoints,
    metrics.ise_mnt_active_posture_assessment_endpoints,
    metrics.ise_mnt_active_secure_client_endpoints,
    metrics.ise_mnt_active_posture_policy_results,
    metrics.ise_mnt_active_step_latency_seconds,
    metrics.ise_mnt_active_step_latency_samples,
    metrics.ise_mnt_active_total_authentication_latency_seconds,
    metrics.ise_mnt_active_total_authentication_latency_samples,
)


def _value(detail, attrs, *keys):
    """Read MnT snake_case detail first, then OTHER_ATTR_STRING spellings."""
    value = first_nonempty(detail, *keys)
    return value or first_nonempty(attrs, *keys)


def _active_mac(row):
    raw = first_nonempty(
        row, "calling_station_id", "callingStationId", "mac_address", "macAddress", "mac")
    # Reject malformed response blobs before normalize_mac() builds a compact
    # copy and the validation path normalizes it a second time.
    if len(raw) > 64:
        return ""
    return normalize_mac(raw) if is_mac(raw) else ""


def _active_count(payload):
    """Extract MnT's small ActiveCount response without trusting wrapper totals."""
    if not isinstance(payload, dict):
        return None
    sessions = payload.get("sessions")
    if not isinstance(sessions, list) or not sessions or not isinstance(sessions[0], dict):
        return None
    raw = first_nonempty(sessions[0], "count", "active_count", "activeCount")
    try:
        value = int(raw)
    except (TypeError, ValueError):
        return None
    return value if 0 <= value <= MAX_ACTIVE_COUNT else None


def _milliseconds(value):
    """Return a safe seconds value for ISE's millisecond latency attributes."""
    text = str(value or "").strip()
    if text.lower().endswith("ms"):
        text = text[:-2].strip()
    try:
        milliseconds = float(text)
    except (TypeError, ValueError):
        return None
    # One day is far beyond a useful authentication sample and prevents a
    # malformed attribute from dominating dashboard ranges.
    if not math.isfinite(milliseconds) or milliseconds < 0 or milliseconds > 86_400_000:
        return None
    return milliseconds / 1000.0


def _step_samples(execution_steps, step_latency):
    """Parse mapped step codes, or bounded numeric positions when ISE omits them."""
    if execution_steps:
        return [(step, seconds) for step, seconds in parse_step_latencies(
            execution_steps, step_latency) if seconds <= 86_400]
    samples = []
    for item in str(step_latency or "").split(";"):
        position, separator, raw_ms = item.partition("=")
        if not separator:
            continue
        try:
            number = int(position.strip())
        except ValueError:
            continue
        seconds = _milliseconds(raw_ms)
        # Step positions are labels, so impose a tight numeric domain rather
        # than accepting arbitrary OTHER_ATTR_STRING text as cardinality.
        if 1 <= number <= MAX_ISE_STEP_CODE and seconds is not None:
            samples.append((str(number), seconds))
    return samples


def _agent_os(agent):
    """Derive one bounded OS family from the normalized posture-agent version."""
    match = re.match(r"^(Windows|macOS|Mac OS X|Linux|Android|iOS)\b", agent or "", re.I)
    if not match:
        return "Unknown"
    value = match.group(1).lower()
    return {"windows": "Windows", "macos": "macOS", "mac os x": "macOS",
            "linux": "Linux", "android": "Android", "ios": "iOS"}[value]


class _RequestPacer:
    def __init__(self, interval_seconds, shutdown=None):
        self.interval = max(0.0, float(interval_seconds))
        self.next_at = 0.0
        self.lock = Lock()
        self.shutdown = shutdown

    def wait(self):
        with self.lock:
            remaining = self.next_at - time.monotonic()
            if remaining > 0:
                if self.shutdown is not None:
                    if self.shutdown.wait(remaining):
                        raise RuntimeError("MnT detail pacing cancelled during exporter shutdown")
                else:
                    time.sleep(remaining)
            self.next_at = time.monotonic() + self.interval


def _detail(client, mac, pacer=None):
    if pacer is not None:
        pacer.wait()
    payload = client.get_mnt_xml(
        f"/Session/MACAddress/{mac}", api_name="mnt_active_posture_detail")
    if not isinstance(payload, dict):
        return None
    sessions = payload.get("sessions")
    if not isinstance(sessions, list) or not sessions or not isinstance(sessions[0], dict):
        return None
    return sessions[0]


def _bounded_text(value, limit):
    text = str(value or "").strip()
    if not text:
        return ""
    encoded = text.encode("utf-8")
    if len(encoded) <= limit:
        return text
    return encoded[:limit].decode("utf-8", "ignore")


def _compact_detail(detail):
    """Retain only bounded inputs needed to rebuild current posture metrics.

    MnT session detail includes identity and authorization fields unrelated to
    this collector. Persisting the whole response would turn a load-reduction
    cache into an unnecessary second copy of current session data.
    """
    raw_other = _bounded_text(
        first_nonempty(detail, "other_attr_string", "otherAttrString"), 131_072)
    attrs = parse_other_attr_string(raw_other)
    fields = {
        "posture_status": _value(detail, attrs, "posture_status", "PostureStatus"),
        "posture_assessment_status": _value(
            detail, attrs, "posture_assessment_status", "PostureAssessmentStatus"),
        "posture_applicable": _value(
            detail, attrs, "posture_applicable", "PostureApplicable"),
        "posture_report": _value(detail, attrs, "posture_report", "PostureReport"),
        "posture_agent_version": first_nonempty(attrs, *SECURECLIENT_VERSION_KEYS)
            or _value(detail, attrs, "posture_agent_version", "PostureAgentVersion"),
        "server": _value(detail, attrs, "server", "acs_server", "ise_node", "Server"),
        "execution_steps": _value(
            detail, attrs, "execution_steps", "ExecutionSteps", "Steps"),
        "step_latency": _value(detail, attrs, "step_latency", "StepLatency"),
        "total_authen_latency": _value(
            detail, attrs, "total_authen_latency", "TotalAuthenLatency",
            "total_authentication_latency", "TotalAuthenticationLatency"),
    }
    limits = {
        "posture_report": 65_536,
        "execution_steps": 16_384,
        "step_latency": 16_384,
        "posture_agent_version": 512,
        "server": 128,
    }
    compact = {
        key: text for key, value in fields.items()
        if (text := _bounded_text(value, limits.get(key, 1024)))
    }
    if raw_other:
        compact["other_attr_string_present"] = True
    return compact


def _bounded_details(client, macs, workers, request_interval=0):
    if not macs:
        return {}
    results = {}
    pacer = _RequestPacer(request_interval, getattr(client, "shutdown_event", None))
    with ThreadPoolExecutor(max_workers=max(1, min(workers, len(macs)))) as executor:
        futures = {executor.submit(_detail, client, mac, pacer): mac for mac in macs}
        for future in as_completed(futures):
            try:
                detail = future.result()
            except Exception:
                detail = None
            if detail is not None:
                results[futures[future]] = detail
    return results


def _session_signature(row):
    """Stable active-session identity without persisting it as a metric label."""
    keys = (
        "audit_session_id", "auditSessionId", "session_id", "sessionId",
        "acct_session_id", "acctSessionId", "acs_server", "acsServer",
        "authentication_method", "authenticationMethod", "authen_time", "authenTime",
    )
    material = {
        key: _bounded_text(value, 1024)
        for key in keys
        if (value := row.get(key)) not in (None, "")
        and isinstance(value, (str, int, float, bool))
    }
    if not material:
        # Do not hash the whole ActiveList row: elapsed-time fields can change
        # every poll and would defeat the request budget. If this appliance omits
        # session IDs, the normal oldest-first rotation refreshes the endpoint.
        material = {"mac": _active_mac(row)}
    encoded = json.dumps(material, sort_keys=True, separators=(",", ":"), default=str)
    return hashlib.sha256(encoded.encode()).hexdigest()


def _aggregate(details):
    statuses = Counter()
    applicable = Counter()
    assessments = Counter()
    agents = Counter()
    policies = Counter()
    coverage = Counter()
    steps = defaultdict(list)
    total_latency = []

    def increment_bounded(counter, key, limit, overflow):
        if key in counter or len(counter) < limit - 1:
            counter[key] += 1
        else:
            counter[overflow] += 1

    for detail in details:
        raw_other = first_nonempty(detail, "other_attr_string", "otherAttrString")
        attrs = parse_other_attr_string(raw_other)
        if raw_other or detail.get("other_attr_string_present"):
            coverage["other_attr_string"] += 1

        posture_status = _value(detail, attrs, "posture_status", "PostureStatus")
        assessment = _value(
            detail, attrs, "posture_assessment_status", "PostureAssessmentStatus")
        posture_status = posture_status or assessment
        posture_applicable = _value(
            detail, attrs, "posture_applicable", "PostureApplicable")
        report = _value(detail, attrs, "posture_report", "PostureReport")
        agent = normalize_agent_version(first_nonempty(attrs, *SECURECLIENT_VERSION_KEYS))
        if not agent:
            agent = normalize_agent_version(_value(
                detail, attrs, "posture_agent_version", "PostureAgentVersion"))
        os_name = _agent_os(agent)
        psn = _value(detail, attrs, "server", "acs_server", "ise_node", "Server")
        psn = metric_label(psn, "Unknown", 128)

        if posture_status:
            coverage["posture_status"] += 1
        if posture_applicable:
            coverage["posture_applicable"] += 1
        if assessment:
            coverage["posture_assessment_status"] += 1
        if report:
            coverage["posture_report"] += 1
        if agent:
            coverage["posture_agent_version"] += 1

        status = metric_label(
            normalize_posture(posture_status) if posture_status else "Unknown",
            "Unknown", 128)
        increment_bounded(
            statuses, (status, os_name, psn), MAX_STATUS_GROUPS,
            ("Other", "Unknown", "Unknown"))
        applicable[normalize_bool_label(posture_applicable)] += 1
        assessment_status = metric_label(
            normalize_posture(assessment) if assessment else "Unknown", "Unknown", 128)
        increment_bounded(
            assessments, assessment_status, MAX_STATUS_GROUPS, "Other")
        increment_bounded(
            agents, metric_label(agent, "Unknown", 128), MAX_AGENT_GROUPS, "Other")
        for policy, result in set(parse_posture_report(report)):
            increment_bounded(
                policies, (metric_label(policy, "Unknown", 128), result),
                MAX_POLICY_GROUPS, ("Other", result))

        execution_steps = _value(
            detail, attrs, "execution_steps", "ExecutionSteps", "Steps")
        step_latency = _value(detail, attrs, "step_latency", "StepLatency")
        parsed_steps = _step_samples(execution_steps, step_latency)
        if parsed_steps:
            coverage["step_latency"] += 1
        for step, seconds in parsed_steps:
            steps[step].append(seconds)

        auth_latency = _milliseconds(_value(
            detail, attrs, "total_authen_latency", "TotalAuthenLatency",
            "total_authentication_latency", "TotalAuthenticationLatency"))
        if auth_latency is not None:
            coverage["total_authentication_latency"] += 1
            total_latency.append(auth_latency)

    # A malformed endpoint population must not manufacture an unbounded label
    # domain. Prefer the most-observed legitimate ISE step codes and use numeric
    # ordering as a deterministic tie-breaker.
    steps = dict(sorted(
        steps.items(), key=lambda item: (-len(item[1]), int(item[0])))[:MAX_STEP_CODES])
    return statuses, applicable, assessments, agents, policies, coverage, steps, total_latency


def collect(client, cfg):
    """Publish one atomic, bounded snapshot of current MnT endpoint detail."""
    with observe("mnt_active_posture"):
        count_payload = client.get_mnt_xml(
            "/Session/ActiveCount", api_name="mnt_active_posture_count")
        preflight_count = _active_count(count_payload)
        if preflight_count is None:
            raise CollectorFailed("MnT ActiveCount returned no usable session count")
        list_ceiling = max(1, min(250000, int(getattr(
            cfg, "mnt_active_posture_max_active_list_sessions", 10000))))
        metrics.ise_mnt_session_list_preflight_count.set(preflight_count)
        metrics.ise_mnt_session_list_ceiling.set(list_ceiling)
        metrics.ise_mnt_session_list_skipped.set(int(preflight_count > list_ceiling))
        if preflight_count > list_ceiling:
            raise CollectorFailed(
                f"MnT ActiveList refused: ActiveCount {preflight_count} exceeds "
                f"production ceiling {list_ceiling}")

        active = ({"total": 0, "sessions": []} if preflight_count == 0 else
                  client.get_mnt_xml(
                      "/Session/ActiveList", api_name="mnt_active_posture_list"))
        if not isinstance(active, dict) or not isinstance(active.get("sessions"), list):
            raise CollectorFailed("MnT ActiveList returned no usable session list")

        rows = active["sessions"]
        try:
            active_total = int(active.get("total"))
        except (TypeError, ValueError):
            raise CollectorFailed("MnT ActiveList returned an invalid session count") from None
        if active_total < 0 or active_total != len(rows):
            raise CollectorFailed(
                f"MnT ActiveList count mismatch: declared {active_total}, "
                f"parsed {len(rows)}")
        if active_total > list_ceiling or len(rows) > list_ceiling:
            raise CollectorFailed(
                f"MnT ActiveList refused after preflight: {len(rows)} parsed sessions "
                f"exceed production ceiling {list_ceiling}")
        # Preserve ActiveList order while avoiding duplicate detail requests for
        # endpoints with more than one active session.
        active_rows = {}
        for row in rows:
            if isinstance(row, dict) and (mac := _active_mac(row)):
                active_rows.setdefault(mac, row)
        candidates = list(active_rows)
        limit = max(0, min(1000, int(getattr(
            cfg, "mnt_active_posture_max_sessions", 1000))))
        selected = candidates[:limit]
        workers = max(1, min(4, int(getattr(
            cfg, "mnt_active_posture_workers", 2))))
        request_budget = max(1, min(250, int(getattr(
            cfg, "mnt_active_posture_max_requests_per_cycle", len(selected) or 1))))
        refresh_ttl = max(1, int(getattr(
            cfg, "mnt_active_posture_refresh_ttl", 3600)))
        interval = max(1, int(getattr(cfg, "mnt_active_posture_interval", 900)))
        request_interval = max(0, int(getattr(
            cfg, "mnt_active_posture_request_interval_ms", 500))) / 1000.0
        now = time.time()

        store = StateStore(getattr(cfg, "state_db_path", ":memory:"))
        try:
            cached = store.posture_entries(selected)
            signatures = {mac: _session_signature(active_rows[mac]) for mac in selected}
            mandatory = [mac for mac in selected if mac not in cached
                         or cached[mac]["signature"] != signatures[mac]]
            unchanged = [mac for mac in selected if mac in cached
                         and cached[mac]["signature"] == signatures[mac]]
            oldest = sorted(unchanged, key=lambda mac: cached[mac]["updated_at"])
            expired = [mac for mac in oldest
                       if now - cached[mac]["updated_at"] >= refresh_ttl]
            rotation_target = math.ceil(len(selected) * interval / refresh_ttl)
            refresh = list(dict.fromkeys(mandatory + expired + oldest[:rotation_target]))
            planned = refresh[:request_budget]
            deferred = max(0, len(refresh) - len(planned))
            fetched = _bounded_details(
                client, planned, workers, request_interval=request_interval)
            for mac, detail in fetched.items():
                store.put_posture(
                    mac, signatures[mac], _compact_detail(detail), now=now)
            store.finish_posture_cycle(selected, now=now)
            current = store.posture_entries(selected)
        finally:
            store.close()

        # Never publish a detail from an older session.  An unchanged cached
        # response remains usable if its best-effort refresh failed.
        usable = {
            mac: entry for mac, entry in current.items()
            if entry["signature"] == signatures[mac]
        }
        if selected and not usable:
            raise CollectorFailed("no current or cached MnT session details available")
        details = [usable[mac]["detail"] for mac in selected if mac in usable]
        cache_hits = sum(1 for mac in selected if mac in cached
                         and cached[mac]["signature"] == signatures[mac]
                         and mac not in fetched)
        cache_misses = sum(1 for mac in selected if mac not in cached)
        oldest_age = max(
            (max(0.0, now - entry["updated_at"]) for entry in usable.values()),
            default=0.0)

        aggregates = _aggregate(details)
        (statuses, applicable, assessments, agents, policies, coverage,
         steps, total_latency) = aggregates
        writers = [
            lambda: metrics.ise_mnt_active_sessions_total.set(active_total),
            lambda: metrics.ise_mnt_active_posture_candidate_endpoints_total.set(
                len(candidates)),
            lambda: metrics.ise_mnt_active_posture_detail_requests.set(len(planned)),
            lambda: metrics.ise_mnt_active_posture_detail_endpoints.set(len(details)),
            lambda: metrics.ise_mnt_active_posture_detail_coverage_ratio.set(
                len(details) / len(selected) if selected else 1),
            lambda: metrics.ise_mnt_active_posture_detail_truncated.set(
                int(len(selected) < len(candidates))),
            lambda: metrics.ise_mnt_active_posture_cache_entries.set(len(usable)),
            lambda: metrics.ise_mnt_active_posture_cache_hits.set(cache_hits),
            lambda: metrics.ise_mnt_active_posture_cache_misses.set(cache_misses),
            lambda: metrics.ise_mnt_active_posture_refresh_deferred.set(deferred),
            lambda: metrics.ise_mnt_active_posture_cache_oldest_age_seconds.set(oldest_age),
        ]
        writers.extend(
            lambda field=field: metrics.ise_mnt_active_posture_field_coverage_ratio.labels(
                field=field).set(coverage[field] / len(details) if details else 0)
            for field in _FIELDS
        )
        writers.extend(
            lambda status=status, os_name=os_name, psn=psn, count=count:
                metrics.ise_mnt_active_posture_endpoints.labels(
                    status=status, os=os_name, psn=psn).set(count)
            for (status, os_name, psn), count in statuses.items()
        )
        writers.extend(
            lambda value=value, count=count:
                metrics.ise_mnt_active_posture_applicable_endpoints.labels(
                    applicable=value).set(count)
            for value, count in applicable.items()
        )
        writers.extend(
            lambda status=status, count=count:
                metrics.ise_mnt_active_posture_assessment_endpoints.labels(
                    status=status).set(count)
            for status, count in assessments.items()
        )
        writers.extend(
            lambda agent=agent, count=count:
                metrics.ise_mnt_active_secure_client_endpoints.labels(
                    agent_version=agent).set(count)
            for agent, count in agents.items()
        )
        writers.extend(
            lambda policy=policy, result=result, count=count:
                metrics.ise_mnt_active_posture_policy_results.labels(
                    policy=policy, result=result).set(count)
            for (policy, result), count in policies.items()
        )
        for step, samples in steps.items():
            stats = {"sum": sum(samples), "avg": sum(samples) / len(samples), "max": max(samples)}
            writers.extend(
                lambda step=step, stat=stat, value=value:
                    metrics.ise_mnt_active_step_latency_seconds.labels(
                        step=step, stat=stat).set(value)
                for stat, value in stats.items()
            )
            writers.append(
                lambda step=step, count=len(samples):
                    metrics.ise_mnt_active_step_latency_samples.labels(step=step).set(count))
        if total_latency:
            latency_stats = {
                "sum": sum(total_latency),
                "avg": sum(total_latency) / len(total_latency),
                "max": max(total_latency),
            }
            writers.extend(
                lambda stat=stat, value=value:
                    metrics.ise_mnt_active_total_authentication_latency_seconds.labels(
                        stat=stat).set(value)
                for stat, value in latency_stats.items()
            )
        writers.append(
            lambda: metrics.ise_mnt_active_total_authentication_latency_samples.set(
                len(total_latency)))
        replace_metric_snapshot(_METRICS, writers)
