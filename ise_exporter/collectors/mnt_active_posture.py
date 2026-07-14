"""Bounded current Secure Client/posture snapshot from MnT active sessions.

This collector is deliberately separate from Data Connect posture reporting:
MnT owns only a bounded view of *currently active* endpoint details, while Data
Connect owns historical posture assessments. No fallback or shared metric family
connects the two sources.
"""
from __future__ import annotations

from collections import Counter, defaultdict
from concurrent.futures import ThreadPoolExecutor, as_completed
import math
import re

from .. import metrics
from ..snapshots import replace_metric_snapshot
from ..util import (
    SECURECLIENT_VERSION_KEYS,
    first_nonempty,
    is_mac,
    normalize_agent_version,
    normalize_bool_label,
    normalize_mac,
    normalize_posture,
    parse_other_attr_string,
    parse_posture_report,
    parse_step_latencies,
)
from . import CollectorFailed, observe


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
    return normalize_mac(raw) if is_mac(raw) else ""


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
        if 1 <= number <= 10_000 and seconds is not None:
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


def _detail(client, mac):
    payload = client.get_mnt_xml(
        f"/Session/MACAddress/{mac}", api_name="mnt_active_posture_detail")
    if not isinstance(payload, dict):
        return None
    sessions = payload.get("sessions")
    if not isinstance(sessions, list) or not sessions or not isinstance(sessions[0], dict):
        return None
    return sessions[0]


def _bounded_details(client, macs, workers):
    if not macs:
        return []
    results = []
    with ThreadPoolExecutor(max_workers=max(1, min(workers, len(macs)))) as executor:
        futures = {executor.submit(_detail, client, mac): mac for mac in macs}
        for future in as_completed(futures):
            try:
                detail = future.result()
            except Exception:
                detail = None
            if detail is not None:
                results.append(detail)
    return results


def _aggregate(details):
    statuses = Counter()
    applicable = Counter()
    assessments = Counter()
    agents = Counter()
    policies = Counter()
    coverage = Counter()
    steps = defaultdict(list)
    total_latency = []

    for detail in details:
        raw_other = first_nonempty(detail, "other_attr_string", "otherAttrString")
        attrs = parse_other_attr_string(raw_other)
        if raw_other:
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
        psn = (psn or "Unknown")[:128]

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

        status = normalize_posture(posture_status) if posture_status else "Unknown"
        statuses[(status, os_name, psn)] += 1
        applicable[normalize_bool_label(posture_applicable)] += 1
        assessments[normalize_posture(assessment) if assessment else "Unknown"] += 1
        agents[(agent or "Unknown")[:128]] += 1
        for policy, result in set(parse_posture_report(report)):
            policies[(policy[:128], result)] += 1

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

    return statuses, applicable, assessments, agents, policies, coverage, steps, total_latency


def collect(client, cfg):
    """Publish one atomic, bounded snapshot of current MnT endpoint detail."""
    with observe("mnt_active_posture"):
        active = client.get_mnt_xml(
            "/Session/ActiveList", api_name="mnt_active_posture_list")
        if not isinstance(active, dict) or not isinstance(active.get("sessions"), list):
            raise CollectorFailed("MnT ActiveList returned no usable session list")

        rows = active["sessions"]
        try:
            active_total = max(0, int(active.get("total", len(rows))))
        except (TypeError, ValueError):
            active_total = len(rows)
        # Preserve ActiveList order while avoiding duplicate detail requests for
        # endpoints with more than one active session.
        candidates = list(dict.fromkeys(mac for row in rows if (mac := _active_mac(row))))
        limit = max(0, int(getattr(cfg, "mnt_active_posture_max_sessions", 1000)))
        selected = candidates[:limit]
        workers = max(1, int(getattr(cfg, "mnt_active_posture_workers", 8)))
        details = _bounded_details(client, selected, workers)
        if selected and not details:
            raise CollectorFailed("all selected MnT session-detail lookups failed")

        aggregates = _aggregate(details)
        (statuses, applicable, assessments, agents, policies, coverage,
         steps, total_latency) = aggregates
        writers = [
            lambda: metrics.ise_mnt_active_sessions_total.set(active_total),
            lambda: metrics.ise_mnt_active_posture_candidate_endpoints_total.set(
                len(candidates)),
            lambda: metrics.ise_mnt_active_posture_detail_requests.set(len(selected)),
            lambda: metrics.ise_mnt_active_posture_detail_endpoints.set(len(details)),
            lambda: metrics.ise_mnt_active_posture_detail_coverage_ratio.set(
                len(details) / len(selected) if selected else 1),
            lambda: metrics.ise_mnt_active_posture_detail_truncated.set(
                int(len(selected) < len(candidates))),
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
