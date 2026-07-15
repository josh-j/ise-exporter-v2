"""Posture and Secure Client reporting from Cisco ISE Data Connect."""
from .. import metrics
from . import observe
from .dataconnect_common import (
    event_window_hours,
    group_limit,
    integer,
    label,
    recent_event_predicate,
    replace_snapshot,
)


_METRICS = (
    metrics.ise_dataconnect_posture_endpoint_assessments,
    metrics.ise_dataconnect_posture_assessed_endpoints_total,
    metrics.ise_dataconnect_posture_eligible_endpoints_total,
    metrics.ise_dataconnect_posture_eligible_recently_assessed_total,
    metrics.ise_dataconnect_posture_eligible_without_recent_assessment_total,
    metrics.ise_dataconnect_posture_eligible_recent_assessment_ratio,
    metrics.ise_dataconnect_posture_compliant_endpoints_total,
    metrics.ise_dataconnect_posture_failed_endpoints_total,
    metrics.ise_dataconnect_posture_compliance_ratio,
    metrics.ise_dataconnect_posture_condition_assessments,
    metrics.ise_dataconnect_posture_failures,
    metrics.ise_dataconnect_posture_topk_groups_returned,
    metrics.ise_dataconnect_posture_topk_groups_total,
    metrics.ise_dataconnect_posture_topk_truncated,
)


_STATUS_KEY = """LOWER(REPLACE(REPLACE(REPLACE(
    TRIM(posture_status), '-', ''), '_', ''), ' ', ''))"""


def _normalized_mac(column):
    """Oracle expression for format-insensitive MAC identity matching."""
    return (f"UPPER(REPLACE(REPLACE(REPLACE(TRIM({column}), ':', ''), "
            "'-', ''), '.', ''))")


def _latest_posture_cte(window_hours=6):
    posture_mac = _normalized_mac("endpoint_mac_address")
    posture_recent = recent_event_predicate("timestamp", window_hours)
    return f"""
        WITH ranked_posture AS (
            SELECT endpoint_mac_address, posture_status,
                   endpoint_operating_system, posture_agent_version,
                   posture_policy_matched, ise_node, message_code,
                   ROW_NUMBER() OVER (
                       PARTITION BY CASE
                           WHEN TRIM(endpoint_mac_address) IS NOT NULL
                               THEN 'mac:' || {posture_mac}
                           WHEN TRIM(session_id) IS NOT NULL
                               THEN 'session:' || TRIM(session_id)
                           ELSE 'row:' || TO_CHAR(id)
                       END
                       ORDER BY timestamp DESC, id DESC
                   ) AS row_num
            FROM posture_assessment_by_endpoint p
            WHERE {posture_recent}
        ), latest_posture AS (
            SELECT /*+ MATERIALIZE */ endpoint_mac_address, posture_status,
                   endpoint_operating_system, posture_agent_version,
                   posture_policy_matched, ise_node, message_code
            FROM ranked_posture WHERE row_num = 1
        )
    """


def _queries(limit, window_hours=6):
    latest = _latest_posture_cte(window_hours)
    condition_recent = recent_event_predicate("logged_at", window_hours)
    posture_mac = _normalized_mac("p.endpoint_mac_address")
    inventory_mac = _normalized_mac("e.mac_address")
    return {
        "snapshot": latest + f"""
            , eligible_coverage AS (
                SELECT COUNT(*) AS eligible_endpoints,
                       SUM(CASE WHEN p.endpoint_mac_address IS NOT NULL THEN 1 ELSE 0 END)
                           AS recently_assessed,
                       SUM(CASE WHEN p.endpoint_mac_address IS NULL THEN 1 ELSE 0 END)
                           AS without_recent_assessment
                FROM endpoints_data e
                LEFT JOIN latest_posture p ON {posture_mac} = {inventory_mac}
                WHERE NVL(e.posture_applicable, 0) = 1
            ), grouped_posture AS (
                SELECT CASE WHEN GROUPING(message_code) = 1
                            THEN 'endpoints' ELSE 'failures' END AS breakdown,
                       {_STATUS_KEY} AS status_key, posture_status,
                       endpoint_operating_system, posture_agent_version,
                       posture_policy_matched, ise_node, message_code,
                       COUNT(*) AS endpoints
                FROM latest_posture
                GROUP BY GROUPING SETS (
                    ({_STATUS_KEY}, posture_status, endpoint_operating_system,
                     posture_agent_version, posture_policy_matched, ise_node),
                    ({_STATUS_KEY}, posture_status, posture_policy_matched,
                     ise_node, message_code)
                )
            ), filtered_posture AS (
                SELECT * FROM grouped_posture
                WHERE breakdown = 'endpoints'
                   OR status_key IN ('noncompliant', 'failed', 'error')
            ), ranked_posture_groups AS (
                SELECT filtered_posture.*,
                       SUM(CASE WHEN breakdown = 'endpoints'
                                THEN endpoints ELSE 0 END) OVER () AS total_endpoints,
                       SUM(CASE WHEN breakdown = 'endpoints'
                                     AND status_key IN ('compliant', 'passed')
                                THEN endpoints ELSE 0 END) OVER () AS compliant_endpoints,
                       SUM(CASE WHEN breakdown = 'endpoints'
                                     AND status_key IN (
                                         'noncompliant', 'failed', 'error')
                                THEN endpoints ELSE 0 END) OVER () AS failed_endpoints,
                       COUNT(*) OVER (PARTITION BY breakdown) AS total_groups,
                       ROW_NUMBER() OVER (
                           PARTITION BY breakdown ORDER BY endpoints DESC
                       ) AS group_rank
                FROM filtered_posture
            )
            SELECT breakdown, status_key, posture_status,
                   endpoint_operating_system, posture_agent_version,
                   posture_policy_matched, ise_node, message_code, endpoints,
                   total_endpoints, compliant_endpoints, failed_endpoints,
                   total_groups, NULL AS eligible_endpoints,
                   NULL AS recently_assessed, NULL AS without_recent_assessment
            FROM ranked_posture_groups
            WHERE group_rank <= {limit}
            UNION ALL
            SELECT 'coverage' AS breakdown, NULL, NULL, NULL, NULL, NULL, NULL,
                   NULL, NULL, NULL, NULL, NULL, NULL, eligible_endpoints,
                   recently_assessed, without_recent_assessment
            FROM eligible_coverage
        """,
        "conditions": f"""
            SELECT grouped_conditions.*, COUNT(*) OVER () AS total_groups
            FROM (
                SELECT policy, policy_status, condition_name, condition_status,
                       enforcement_name, COUNT(DISTINCT endpoint_id) AS endpoints
                FROM posture_assessment_by_condition
                WHERE {condition_recent}
                GROUP BY policy, policy_status, condition_name, condition_status,
                         enforcement_name
            ) grouped_conditions
            ORDER BY endpoints DESC FETCH FIRST {limit} ROWS ONLY
        """,
    }


def collect(dataconnect, cfg):
    """Atomically replace posture snapshots without exporting endpoint identity."""
    with observe("dataconnect_posture"):
        rows = {name: dataconnect.query(sql)
                for name, sql in _queries(
                    group_limit(cfg), event_window_hours(
                        cfg, getattr(cfg, "dataconnect_posture_interval", 21600))).items()}
        snapshot = rows["snapshot"]
        snapshot_groups = {
            breakdown: [row for row in snapshot if row.get("breakdown") == breakdown]
            for breakdown in ("endpoints", "failures")
        }
        summaries = {
            **{name: (values[0] if values else {})
               for name, values in snapshot_groups.items()},
            "conditions": rows["conditions"][0] if rows["conditions"] else {},
        }
        endpoints = [{
            "status": label(row.get("posture_status"), "NotApplicable"),
            "os": label(row.get("endpoint_operating_system"), "Unknown"),
            "agent": label(row.get("posture_agent_version"), "Unknown"),
            "policy": label(row.get("posture_policy_matched"), "none"),
            "psn": label(row.get("ise_node")),
            "count": integer(row.get("endpoints")),
        } for row in snapshot_groups["endpoints"]]
        conditions = [{
            "policy": label(row.get("policy"), "none"),
            "policy_status": label(row.get("policy_status")),
            "condition": label(row.get("condition_name"), "none"),
            "condition_status": label(row.get("condition_status")),
            "enforcement": label(row.get("enforcement_name"), "none"),
            "count": integer(row.get("endpoints")),
        } for row in rows["conditions"]]
        failures = [{
            "code": label(row.get("message_code")),
            "status": label(row.get("posture_status")),
            "policy": label(row.get("posture_policy_matched"), "none"),
            "psn": label(row.get("ise_node")),
            "count": integer(row.get("endpoints")),
        } for row in snapshot_groups["failures"]]

        writers = [
            lambda row=row: metrics.ise_dataconnect_posture_endpoint_assessments.labels(
                status=row["status"], os=row["os"], agent_version=row["agent"],
                policy=row["policy"], psn=row["psn"]).set(row["count"])
            for row in endpoints
        ]
        writers.extend(
            lambda row=row: metrics.ise_dataconnect_posture_condition_assessments.labels(
                policy=row["policy"], policy_status=row["policy_status"],
                condition=row["condition"], condition_status=row["condition_status"],
                enforcement=row["enforcement"]).set(row["count"])
            for row in conditions
        )
        writers.extend(
            lambda row=row: metrics.ise_dataconnect_posture_failures.labels(
                message_code=row["code"], status=row["status"],
                policy=row["policy"], psn=row["psn"]).set(row["count"])
            for row in failures
        )
        total = integer(summaries["endpoints"].get("total_endpoints"))
        compliant = integer(summaries["endpoints"].get("compliant_endpoints"))
        failed = integer(summaries["endpoints"].get("failed_endpoints"))
        coverage = next((row for row in snapshot
                         if row.get("breakdown") == "coverage"), {})
        eligible = integer(coverage.get("eligible_endpoints"))
        eligible_assessed = integer(coverage.get("recently_assessed"))
        eligible_unassessed = integer(coverage.get("without_recent_assessment"))
        writers.extend((
            lambda: metrics.ise_dataconnect_posture_assessed_endpoints_total.set(total),
            lambda: metrics.ise_dataconnect_posture_eligible_endpoints_total.set(eligible),
            lambda: metrics.ise_dataconnect_posture_eligible_recently_assessed_total.set(
                eligible_assessed),
            lambda: metrics.ise_dataconnect_posture_eligible_without_recent_assessment_total.set(
                eligible_unassessed),
            lambda: metrics.ise_dataconnect_posture_eligible_recent_assessment_ratio.set(
                eligible_assessed / eligible if eligible else 0),
            lambda: metrics.ise_dataconnect_posture_compliant_endpoints_total.set(compliant),
            lambda: metrics.ise_dataconnect_posture_failed_endpoints_total.set(failed),
            lambda: metrics.ise_dataconnect_posture_compliance_ratio.set(
                compliant / (compliant + failed) if compliant + failed else 0),
        ))
        breakdowns = {
            "endpoints": (len(endpoints), summaries["endpoints"]),
            "conditions": (len(conditions), summaries["conditions"]),
            "failures": (len(failures), summaries["failures"]),
        }
        for breakdown, (returned, summary) in breakdowns.items():
            group_total = integer(summary.get("total_groups"))
            writers.extend((
                lambda breakdown=breakdown, returned=returned:
                    metrics.ise_dataconnect_posture_topk_groups_returned.labels(
                        breakdown=breakdown).set(returned),
                lambda breakdown=breakdown, group_total=group_total:
                    metrics.ise_dataconnect_posture_topk_groups_total.labels(
                        breakdown=breakdown).set(group_total),
                lambda breakdown=breakdown, returned=returned, group_total=group_total:
                    metrics.ise_dataconnect_posture_topk_truncated.labels(
                        breakdown=breakdown).set(1 if returned < group_total else 0),
            ))
        replace_snapshot(_METRICS, writers)
