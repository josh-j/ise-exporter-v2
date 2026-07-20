"""Posture and Secure Client reporting from Cisco ISE Data Connect."""
from .. import metrics
from . import observe
from .dataconnect_common import (
    event_window_hours,
    group_limit,
    integer,
    label,
    query_set,
    recent_event_predicate,
    replace_snapshot,
    schema_expression,
    schema_has,
    schema_projection,
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
    metrics.ise_dataconnect_posture_enforcement_assessments,
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


def _latest_posture_cte(window_hours=6, schema=None):
    view = "POSTURE_ASSESSMENT_BY_ENDPOINT"
    endpoint_mac = schema_expression(schema, view, "endpoint_mac_address")
    session_id = schema_expression(schema, view, "session_id")
    posture_mac = _normalized_mac(endpoint_mac)
    posture_recent = recent_event_predicate("timestamp", window_hours)
    identity = []
    if schema_has(schema, view, "endpoint_mac_address"):
        identity.append(
            f"WHEN TRIM({endpoint_mac}) IS NOT NULL THEN 'mac:' || {posture_mac}")
    if schema_has(schema, view, "session_id"):
        identity.append(
            f"WHEN TRIM({session_id}) IS NOT NULL THEN 'session:' || TRIM({session_id})")
    identity_expression = (
        "CASE " + " ".join(identity) + " ELSE 'row:' || TO_CHAR(id) END"
        if identity else "'row:' || TO_CHAR(id)"
    )
    projections = [
        schema_projection(schema, view, column, fallback)
        for column, fallback in (
            ("endpoint_mac_address", "NULL"), ("posture_status", "'NotApplicable'"),
            ("endpoint_operating_system", "'Unknown'"),
            ("posture_agent_version", "'Unknown'"),
            ("posture_policy_matched", "'none'"), ("ise_node", "'unknown'"),
            ("message_code", "'unknown'"),
        )
    ]
    return f"""
        WITH ranked_posture AS (
            SELECT {", ".join(projections)},
                   ROW_NUMBER() OVER (
                       PARTITION BY {identity_expression}
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


def _queries(limit, window_hours=6, schema=None):
    latest = _latest_posture_cte(window_hours, schema)
    condition_recent = recent_event_predicate("logged_at", window_hours)
    posture_mac = _normalized_mac("p.endpoint_mac_address")
    inventory_mac = _normalized_mac("e.mac_address")
    if (schema_has(schema, "POSTURE_ASSESSMENT_BY_ENDPOINT", "endpoint_mac_address")
            and schema_has(schema, "ENDPOINTS_DATA", "mac_address")
            and schema_has(schema, "ENDPOINTS_DATA", "posture_applicable")):
        coverage_cte = f"""
            SELECT COUNT(*) AS eligible_endpoints,
                   SUM(CASE WHEN p.endpoint_mac_address IS NOT NULL THEN 1 ELSE 0 END)
                       AS recently_assessed,
                   SUM(CASE WHEN p.endpoint_mac_address IS NULL THEN 1 ELSE 0 END)
                       AS without_recent_assessment
            FROM endpoints_data e
            LEFT JOIN latest_posture p ON {posture_mac} = {inventory_mac}
            WHERE NVL(e.posture_applicable, 0) = 1
        """
    else:
        coverage_cte = """
            SELECT NULL AS eligible_endpoints, NULL AS recently_assessed,
                   NULL AS without_recent_assessment FROM dual
        """
    condition_view = "POSTURE_ASSESSMENT_BY_CONDITION"
    condition_dimensions = {
        column: schema_expression(schema, condition_view, column, fallback)
        for column, fallback in (
            ("policy", "'none'"), ("policy_status", "'unknown'"),
            ("condition_name", "'none'"), ("condition_status", "'unknown'"),
            ("enforcement_name", "'none'"),
            ("enforcement_type", "'unknown'"),
            ("enforcement_status", "'unknown'"),
            ("posture_status", "'unknown'"), ("ise_node", "'unknown'"),
        )
    }
    return {
        "snapshot": latest + f"""
            , eligible_coverage AS (
                {coverage_cte}
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
            WITH condition_source AS (
                SELECT endpoint_id, {condition_dimensions["policy"]} AS policy,
                       {condition_dimensions["policy_status"]} AS policy_status,
                       {condition_dimensions["condition_name"]} AS condition_name,
                       {condition_dimensions["condition_status"]} AS condition_status,
                       {condition_dimensions["enforcement_name"]} AS enforcement_name,
                       {condition_dimensions["enforcement_type"]} AS enforcement_type,
                       {condition_dimensions["enforcement_status"]} AS enforcement_status,
                       {condition_dimensions["posture_status"]} AS posture_status,
                       {condition_dimensions["ise_node"]} AS ise_node
                FROM posture_assessment_by_condition
                WHERE {condition_recent}
            ), grouped_conditions AS (
                SELECT CASE WHEN GROUPING(condition_name) = 0
                            THEN 'conditions' ELSE 'enforcement' END AS breakdown,
                       policy, policy_status, condition_name, condition_status,
                       enforcement_name, enforcement_type, enforcement_status,
                       posture_status, ise_node,
                       COUNT(DISTINCT endpoint_id) AS endpoints
                FROM condition_source
                GROUP BY GROUPING SETS (
                    (policy, policy_status, condition_name, condition_status,
                     enforcement_name),
                    (enforcement_name, enforcement_type, enforcement_status,
                     posture_status, ise_node)
                )
            ), ranked_conditions AS (
                SELECT grouped_conditions.*,
                       COUNT(*) OVER (PARTITION BY breakdown) AS total_groups,
                       ROW_NUMBER() OVER (
                           PARTITION BY breakdown ORDER BY endpoints DESC
                       ) AS group_rank
                FROM grouped_conditions
            )
            SELECT * FROM ranked_conditions WHERE group_rank <= {limit}
        """,
    }


def collect(dataconnect, cfg):
    """Atomically replace posture snapshots without exporting endpoint identity."""
    with observe("dataconnect_posture"):
        rows = query_set(
            dataconnect,
            _queries(
                group_limit(cfg), event_window_hours(
                    cfg, getattr(cfg, "dataconnect_posture_interval", 21600)),
                getattr(dataconnect, "schema", None)),
        )
        snapshot = rows["snapshot"]
        snapshot_groups = {
            breakdown: [row for row in snapshot if row.get("breakdown") == breakdown]
            for breakdown in ("endpoints", "failures")
        }
        summaries = {
            **{name: (values[0] if values else {})
               for name, values in snapshot_groups.items()},
            **{
                name: next((row for row in rows["conditions"]
                            if row.get("breakdown") == name), {})
                for name in ("conditions", "enforcement")
            },
        }
        if not summaries["conditions"]:
            summaries["conditions"] = next(
                (row for row in rows["conditions"] if row.get("breakdown") is None), {})
        endpoints = [{
            "status": label(row.get("posture_status"), "NotApplicable"),
            "os": label(row.get("endpoint_operating_system"), "Unknown"),
            "agent": label(row.get("posture_agent_version"), "Unknown"),
            "policy": label(row.get("posture_policy_matched"), "none"),
            "psn": label(row.get("ise_node")),
            "count": integer(row.get("endpoints")),
        } for row in snapshot_groups["endpoints"]]
        condition_rows = [row for row in rows["conditions"]
                          if row.get("breakdown") in (None, "conditions")]
        enforcement_rows = [row for row in rows["conditions"]
                            if row.get("breakdown") == "enforcement"]
        conditions = [{
            "policy": label(row.get("policy"), "none"),
            "policy_status": label(row.get("policy_status")),
            "condition": label(row.get("condition_name"), "none"),
            "condition_status": label(row.get("condition_status")),
            "enforcement": label(row.get("enforcement_name"), "none"),
            "count": integer(row.get("endpoints")),
        } for row in condition_rows]
        enforcement = [{
            "enforcement": label(row.get("enforcement_name"), "none"),
            "type": label(row.get("enforcement_type")),
            "status": label(row.get("enforcement_status")),
            "posture_status": label(row.get("posture_status")),
            "psn": label(row.get("ise_node")),
            "count": integer(row.get("endpoints")),
        } for row in enforcement_rows]
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
            lambda row=row: metrics.ise_dataconnect_posture_enforcement_assessments.labels(
                enforcement=row["enforcement"], enforcement_type=row["type"],
                enforcement_status=row["status"], posture_status=row["posture_status"],
                psn=row["psn"]).set(row["count"])
            for row in enforcement
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
        eligible_available = coverage.get("eligible_endpoints") is not None
        eligible = integer(coverage.get("eligible_endpoints"))
        eligible_assessed = integer(coverage.get("recently_assessed"))
        eligible_unassessed = integer(coverage.get("without_recent_assessment"))
        writers.extend((
            lambda: metrics.ise_dataconnect_posture_assessed_endpoints_total.set(total),
            lambda: metrics.ise_dataconnect_posture_compliant_endpoints_total.set(compliant),
            lambda: metrics.ise_dataconnect_posture_failed_endpoints_total.set(failed),
            lambda: metrics.ise_dataconnect_posture_compliance_ratio.set(
                compliant / (compliant + failed) if compliant + failed else 0),
        ))
        if eligible_available:
            writers.extend((
                lambda: metrics.ise_dataconnect_posture_eligible_endpoints_total.labels(
                    source_view="endpoints_data").set(eligible),
                lambda: metrics.ise_dataconnect_posture_eligible_recently_assessed_total.labels(
                    source_view="endpoints_data").set(
                    eligible_assessed),
                lambda: metrics.ise_dataconnect_posture_eligible_without_recent_assessment_total.labels(
                    source_view="endpoints_data").set(
                    eligible_unassessed),
                lambda: metrics.ise_dataconnect_posture_eligible_recent_assessment_ratio.labels(
                    source_view="endpoints_data").set(
                    eligible_assessed / eligible if eligible else 0),
            ))
        breakdowns = {
            "endpoints": (len(endpoints), summaries["endpoints"]),
            "conditions": (len(conditions), summaries["conditions"]),
            "enforcement": (len(enforcement), summaries["enforcement"]),
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
