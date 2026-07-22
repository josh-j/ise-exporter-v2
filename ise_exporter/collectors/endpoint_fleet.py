"""Accumulated fleet-wide endpoint posture from Cisco ISE Data Connect.

The bounded posture reporting collector only sees a short window, and the MnT
active-session plane only samples a capped number of live sessions. This opt-in
collector keeps each endpoint's latest posture assessment in a restart-persistent
cache, so fleet aggregates accumulate toward the whole posture-applicable
population over a day or two instead of resetting to one window.

It reads only what feeds the metrics (status, OS, agent version, matched policy,
assessing node, assessment time). MAC addresses stay inside the private cache and
never become Prometheus labels. Source is Data Connect only.
"""
import json
import logging
import time

from .. import metrics
from ..state import StateStore
from . import observe
from .dataconnect_common import (
    epoch,
    event_window_hours,
    integer,
    label,
    query_set,
    recent_event_predicate,
    replace_snapshot,
    schema_expression,
    schema_has,
    schema_projection,
)


logger = logging.getLogger(__name__)

_METRICS = (
    metrics.ise_endpoint_fleet_assessed_total,
    metrics.ise_endpoint_fleet_eligible_total,
    metrics.ise_endpoint_fleet_coverage_ratio,
    metrics.ise_endpoint_fleet_compliance_ratio,
    metrics.ise_endpoint_fleet_posture,
    metrics.ise_endpoint_fleet_by_os,
    metrics.ise_endpoint_fleet_by_agent_version,
    metrics.ise_endpoint_fleet_by_policy,
    metrics.ise_endpoint_fleet_by_psn,
    metrics.ise_endpoint_fleet_cache_entries,
    metrics.ise_endpoint_fleet_oldest_assessment_age_seconds,
    metrics.ise_endpoint_fleet_stale,
    metrics.ise_endpoint_fleet_scan_truncated,
)

_DEFAULT_ROW_CAP = 6000
_MIN_ROW_CAP = 100
_MAX_ROW_CAP = 200000
_STALE_DAYS = (30, 90)

# The posture-applicable population moves on inventory timescales (endpoints
# are onboarded/decommissioned over days), not the 900s poll cadence. Refresh
# the SELECT COUNT(*) FROM endpoints_data denominator at most this often and
# publish the cached value between refreshes, so the full-table scan does not
# burn scarce Data Connect duty budget every cycle on large deployments.
_ELIGIBLE_REFRESH_SECONDS = 21600
_ELIGIBLE_STATE_KEY = "endpoint_fleet_eligible"


def _eligible_supported(schema):
    return (schema_has(schema, "ENDPOINTS_DATA", "mac_address")
            and schema_has(schema, "ENDPOINTS_DATA", "posture_applicable"))


def _eligible_query():
    return "SELECT COUNT(*) AS eligible FROM endpoints_data WHERE NVL(posture_applicable, 0) = 1"


def _cached_eligible(cfg, now):
    """Read the persisted eligible count and staleness before any Data Connect
    call. The state store is opened and closed here, before the (potentially
    long, paced) query session below -- never held open across it, matching
    the per-row commit rationale in collectors/devices.py: a transaction left
    open across a network wait would block the other collectors that share
    this SQLite database until they hit the busy timeout.
    """
    store = StateStore(cfg.state_db_path)
    try:
        raw = store.get_value(_ELIGIBLE_STATE_KEY)
    finally:
        store.close()
    if not raw:
        return None, True
    try:
        data = json.loads(raw)
        eligible = int(data["eligible"])
        fetched_at = float(data["fetched_at"])
    except (TypeError, ValueError, KeyError, json.JSONDecodeError):
        return None, True
    if eligible < 0:
        return None, True
    # A fetched_at in the future means the wall clock was set back after the
    # value was stored; treat it as stale rather than trusting a cache entry
    # that could otherwise appear fresh for up to _ELIGIBLE_REFRESH_SECONDS
    # past the clock correction.
    due = (now - fetched_at) >= _ELIGIBLE_REFRESH_SECONDS or fetched_at > now
    return eligible, due


def _row_cap(cfg):
    """Clamp the configurable per-scan assessment row cap to safe bounds."""
    try:
        cap = int(getattr(cfg, "endpoint_fleet_max_rows", _DEFAULT_ROW_CAP))
    except (TypeError, ValueError):
        cap = _DEFAULT_ROW_CAP
    return max(_MIN_ROW_CAP, min(_MAX_ROW_CAP, cap))


def _normalized_mac(column):
    """Oracle expression for format-insensitive MAC identity matching."""
    return (f"UPPER(REPLACE(REPLACE(REPLACE(TRIM({column}), ':', ''), "
            "'-', ''), '.', ''))")


def _is_compliant(status):
    text = status.lower()
    return ("noncompliant" not in text and "non-compliant" not in text
            and "non_compliant" not in text
            and ("compliant" in text or "passed" in text))


def _is_failed(status):
    text = status.lower()
    return ("noncompliant" in text or "non-compliant" in text
            or "non_compliant" in text or "failed" in text)


def _queries(window_hours, row_cap, schema=None):
    view = "POSTURE_ASSESSMENT_BY_ENDPOINT"
    endpoint_mac = schema_expression(schema, view, "endpoint_mac_address")
    mac_norm = _normalized_mac(endpoint_mac)
    recent = recent_event_predicate("timestamp", window_hours)
    projections = [
        schema_projection(schema, view, column, fallback)
        for column, fallback in (
            ("posture_status", "'NotApplicable'"),
            ("endpoint_operating_system", "'Unknown'"),
            ("posture_agent_version", "'Unknown'"),
            ("posture_policy_matched", "'none'"),
            ("ise_node", "'unknown'"),
        )
    ]
    assessments = f"""
        SELECT mac, posture_status, endpoint_operating_system,
               posture_agent_version, posture_policy_matched, ise_node, assessed
        FROM (
            SELECT {mac_norm} AS mac, {", ".join(projections)},
                   timestamp AS assessed,
                   ROW_NUMBER() OVER (
                       PARTITION BY {mac_norm} ORDER BY timestamp DESC, id DESC
                   ) AS row_num
            FROM posture_assessment_by_endpoint
            WHERE {recent} AND TRIM({endpoint_mac}) IS NOT NULL
        ) WHERE row_num = 1
        ORDER BY assessed DESC
        FETCH FIRST {row_cap} ROWS ONLY
    """
    return {"assessments": assessments}


def collect(dataconnect, cfg):
    """Accumulate latest per-endpoint posture and publish fleet aggregates."""
    with observe("endpoint_fleet"):
        schema = getattr(dataconnect, "schema", None)
        interval = int(getattr(cfg, "endpoint_fleet_interval", 900))
        retention = int(getattr(cfg, "endpoint_fleet_retention_seconds", 7776000))
        # Cover comfortably more than one poll gap so a cycle never leaves a hole
        # between the previous scan and this one; the cache carries older state.
        window_hours = event_window_hours(cfg, interval + 3600)
        row_cap = _row_cap(cfg)
        have_assessments = schema_has(
            schema, "POSTURE_ASSESSMENT_BY_ENDPOINT", "endpoint_mac_address")

        now = time.time()
        cached_eligible, eligible_due = _cached_eligible(cfg, now)
        include_eligible = eligible_due and _eligible_supported(schema)

        statements = {}
        if have_assessments:
            statements.update(_queries(window_hours, row_cap, schema))
        if include_eligible:
            statements["eligible"] = _eligible_query()

        assessments = []
        eligible_rows = None
        if statements:
            combined = query_set(dataconnect, statements)
            assessments = combined.get("assessments", [])
            eligible_rows = combined.get("eligible")

        # A scan that returns the full cap dropped the oldest re-postures of this
        # window (e.g. a patch-push mass re-posture). Newly-assessed endpoints are
        # picked up on later cycles, but if the fleet re-postures faster than the
        # cap every cycle, the same oldest endpoints can stay starved and coverage
        # stays understated until max_rows is raised above the re-posture volume.
        # Flag it so that is visible rather than silent.
        truncated = len(assessments) >= row_cap
        if truncated:
            logger.warning(
                "collector detail dataset=endpoint_fleet source=dataconnect "
                "component=posture_accumulator outcome=scan_truncated rows=%d "
                "row_cap=%d action=raise_endpoint_fleet_max_rows",
                len(assessments), row_cap)
        fresh_eligible = None
        if eligible_rows and eligible_rows[0].get("eligible") is not None:
            fresh_eligible = integer(eligible_rows[0].get("eligible"))
        eligible = fresh_eligible if fresh_eligible is not None else cached_eligible

        store = StateStore(cfg.state_db_path)
        try:
            for row in assessments:
                mac = row.get("mac")
                if not mac:
                    continue
                store.put_endpoint_posture(
                    mac=mac,
                    status=label(row.get("posture_status"), "NotApplicable"),
                    os_name=label(row.get("endpoint_operating_system"), "Unknown"),
                    agent_version=label(row.get("posture_agent_version"), "Unknown"),
                    policy=label(row.get("posture_policy_matched"), "none"),
                    psn=label(row.get("ise_node"), "unknown"),
                    assessed_at=epoch(row.get("assessed")),
                    now=now)
            if fresh_eligible is not None:
                store.set_value(
                    _ELIGIBLE_STATE_KEY,
                    json.dumps({"eligible": fresh_eligible, "fetched_at": now}),
                    commit=False)
            store.commit()
            store.prune_endpoint_posture(now - retention)
            aggregate = store.endpoint_posture_aggregate(
                now=now, stale_days=_STALE_DAYS)
            entries = store.endpoint_posture_count()
        finally:
            store.close()

        dimensions = aggregate["dimensions"]
        total = aggregate["total"]
        statuses = dimensions.get("status", {})
        compliant = sum(count for status, count in statuses.items()
                        if _is_compliant(status))
        failed = sum(count for status, count in statuses.items()
                     if _is_failed(status))

        writers = [
            lambda total=total: metrics.ise_endpoint_fleet_assessed_total.set(total),
            lambda entries=entries: metrics.ise_endpoint_fleet_cache_entries.set(entries),
            lambda truncated=truncated:
                metrics.ise_endpoint_fleet_scan_truncated.set(int(truncated)),
            lambda compliant=compliant, failed=failed:
                metrics.ise_endpoint_fleet_compliance_ratio.set(
                    compliant / (compliant + failed) if compliant + failed else 0),
        ]
        metric_by_dimension = {
            "status": (metrics.ise_endpoint_fleet_posture, "status"),
            "os": (metrics.ise_endpoint_fleet_by_os, "os"),
            "agent_version": (
                metrics.ise_endpoint_fleet_by_agent_version, "agent_version"),
            "policy": (metrics.ise_endpoint_fleet_by_policy, "policy"),
            "psn": (metrics.ise_endpoint_fleet_by_psn, "psn"),
        }
        for dimension, (metric, label_name) in metric_by_dimension.items():
            for value, count in dimensions.get(dimension, {}).items():
                writers.append(
                    lambda metric=metric, label_name=label_name, value=value,
                    count=count: metric.labels(**{label_name: value}).set(count))

        if eligible is not None:
            writers.extend((
                lambda eligible=eligible:
                    metrics.ise_endpoint_fleet_eligible_total.set(eligible),
                lambda total=total, eligible=eligible:
                    metrics.ise_endpoint_fleet_coverage_ratio.set(
                        total / eligible if eligible else 0),
            ))

        oldest = aggregate.get("oldest_assessed_at")
        if oldest is not None:
            writers.append(
                lambda oldest=oldest:
                    metrics.ise_endpoint_fleet_oldest_assessment_age_seconds.set(
                        max(0.0, now - oldest)))
        for days, count in aggregate.get("stale", {}).items():
            writers.append(
                lambda days=days, count=count: metrics.ise_endpoint_fleet_stale.labels(
                    age_days=str(days)).set(count))

        replace_snapshot(_METRICS, writers)
