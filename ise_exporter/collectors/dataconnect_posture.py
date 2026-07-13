"""Posture and Secure Client reporting from Cisco ISE Data Connect."""
from .. import metrics
from . import observe
from .dataconnect_common import group_limit, integer, label, replace_snapshot


_METRICS = (
    metrics.ise_dataconnect_posture_endpoint_assessments,
    metrics.ise_dataconnect_posture_condition_assessments,
    metrics.ise_dataconnect_posture_failures,
)


def _queries(limit):
    return {
        "endpoints": f"""
            SELECT posture_status, endpoint_operating_system, posture_agent_version,
                   posture_policy_matched, ise_node,
                   COUNT(DISTINCT endpoint_mac_address) AS endpoints
            FROM posture_assessment_by_endpoint
            WHERE timestamp >= SYSTIMESTAMP - INTERVAL '2' DAY
            GROUP BY posture_status, endpoint_operating_system, posture_agent_version,
                     posture_policy_matched, ise_node
            ORDER BY endpoints DESC FETCH FIRST {limit} ROWS ONLY
        """,
        "conditions": f"""
            SELECT policy, policy_status, condition_name, condition_status,
                   enforcement_name, COUNT(DISTINCT endpoint_id) AS endpoints
            FROM posture_assessment_by_condition
            WHERE logged_at >= SYSTIMESTAMP - INTERVAL '2' DAY
            GROUP BY policy, policy_status, condition_name, condition_status,
                     enforcement_name
            ORDER BY endpoints DESC FETCH FIRST {limit} ROWS ONLY
        """,
        "failures": f"""
            SELECT message_code, posture_status, posture_policy_matched, ise_node,
                   COUNT(DISTINCT endpoint_mac_address) AS endpoints
            FROM posture_assessment_by_endpoint
            WHERE timestamp >= SYSTIMESTAMP - INTERVAL '2' DAY
              AND (LOWER(NVL(posture_status, 'unknown')) NOT IN
                   ('compliant', 'passed', 'notapplicable') OR failure_reason IS NOT NULL)
            GROUP BY message_code, posture_status, posture_policy_matched, ise_node
            ORDER BY endpoints DESC FETCH FIRST {limit} ROWS ONLY
        """,
    }


def collect(dataconnect, cfg):
    """Atomically replace posture snapshots without exporting endpoint identity."""
    with observe("dataconnect_posture"):
        rows = {name: dataconnect.query(sql)
                for name, sql in _queries(group_limit(cfg)).items()}
        endpoints = [{
            "status": label(row.get("posture_status"), "NotApplicable"),
            "os": label(row.get("endpoint_operating_system"), "Unknown"),
            "agent": label(row.get("posture_agent_version"), "Unknown"),
            "policy": label(row.get("posture_policy_matched"), "none"),
            "psn": label(row.get("ise_node")),
            "count": integer(row.get("endpoints")),
        } for row in rows["endpoints"]]
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
        } for row in rows["failures"]]

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
        replace_snapshot(_METRICS, writers)
