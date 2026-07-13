"""RADIUS reporting-plane collection from Cisco ISE Data Connect.

All event queries are explicitly bounded to the last two days and aggregate in
Oracle before returning data.  Usernames, MAC addresses, session IDs, free-form
failure text, and other unbounded values never become Prometheus labels.
"""
from .. import metrics
from . import observe
from .dataconnect_common import group_limit, integer, label, number, replace_snapshot


_METRICS = (
    metrics.ise_dataconnect_radius_authentication_events,
    metrics.ise_dataconnect_radius_response_time_seconds,
    metrics.ise_dataconnect_radius_accounting_events,
    metrics.ise_dataconnect_radius_accounting_session_seconds,
    metrics.ise_dataconnect_radius_active_sessions,
    metrics.ise_dataconnect_radius_errors,
)


def _queries(limit):
    return {
        "authentication": f"""
            SELECT CASE WHEN NVL(failed, 0) > 0 THEN 'failed' ELSE 'passed' END AS status,
                   authentication_method, authentication_protocol, device_name,
                   policy_set_name, ise_node, COUNT(*) AS events,
                   AVG(NVL(response_time, 0)) AS avg_response_ms,
                   MAX(NVL(response_time, 0)) AS max_response_ms
            FROM radius_authentications
            WHERE timestamp >= SYSTIMESTAMP - INTERVAL '2' DAY
            GROUP BY CASE WHEN NVL(failed, 0) > 0 THEN 'failed' ELSE 'passed' END,
                     authentication_method, authentication_protocol, device_name,
                     policy_set_name, ise_node
            ORDER BY events DESC FETCH FIRST {limit} ROWS ONLY
        """,
        "accounting": f"""
            SELECT acct_status_type, device_name, authorization_policy, ise_node,
                   COUNT(*) AS events
            FROM radius_accounting
            WHERE timestamp >= SYSTIMESTAMP - INTERVAL '2' DAY
            GROUP BY acct_status_type, device_name, authorization_policy, ise_node
            ORDER BY events DESC FETCH FIRST {limit} ROWS ONLY
        """,
        "accounting_sessions": f"""
            SELECT device_name, ise_node,
                   AVG(NVL(acct_session_time, 0)) AS avg_session_seconds,
                   MAX(NVL(acct_session_time, 0)) AS max_session_seconds
            FROM radius_accounting
            WHERE timestamp >= SYSTIMESTAMP - INTERVAL '2' DAY
              AND NVL(acct_session_time, 0) > 0
            GROUP BY device_name, ise_node
            ORDER BY max_session_seconds DESC FETCH FIRST {limit} ROWS ONLY
        """,
        "active_sessions": f"""
            SELECT device_name, ise_node, COUNT(*) AS sessions
            FROM (
                SELECT acct_session_id,
                       MAX(device_name) KEEP (DENSE_RANK LAST ORDER BY timestamp) AS device_name,
                       MAX(ise_node) KEEP (DENSE_RANK LAST ORDER BY timestamp) AS ise_node,
                       MAX(acct_status_type) KEEP (DENSE_RANK LAST ORDER BY timestamp) AS last_status
                FROM radius_accounting
                WHERE timestamp >= SYSTIMESTAMP - INTERVAL '2' DAY
                  AND acct_session_id IS NOT NULL
                GROUP BY acct_session_id
            )
            WHERE LOWER(NVL(last_status, 'stop')) NOT LIKE '%stop%'
            GROUP BY device_name, ise_node
            ORDER BY sessions DESC FETCH FIRST {limit} ROWS ONLY
        """,
        "errors": f"""
            SELECT TO_CHAR(message_code) AS message_code, network_device_name,
                   authentication_method, ise_node, COUNT(*) AS events
            FROM radius_errors_view
            WHERE timestamp >= SYSTIMESTAMP - INTERVAL '2' DAY
            GROUP BY TO_CHAR(message_code), network_device_name,
                     authentication_method, ise_node
            ORDER BY events DESC FETCH FIRST {limit} ROWS ONLY
        """,
    }


def collect(dataconnect, cfg):
    """Atomically replace the bounded RADIUS reporting snapshot."""
    with observe("dataconnect_radius"):
        rows = {name: dataconnect.query(sql)
                for name, sql in _queries(group_limit(cfg)).items()}
        auth = [{
            "status": label(row.get("status")),
            "method": label(row.get("authentication_method"), "none"),
            "protocol": label(row.get("authentication_protocol"), "none"),
            "nad": label(row.get("device_name")),
            "policy": label(row.get("policy_set_name"), "none"),
            "psn": label(row.get("ise_node")),
            "events": integer(row.get("events")),
            "avg": number(row.get("avg_response_ms")) / 1000.0,
            "max": number(row.get("max_response_ms")) / 1000.0,
        } for row in rows["authentication"]]
        accounting = [{
            "event_type": label(row.get("acct_status_type"), "unknown"),
            "nad": label(row.get("device_name")),
            "policy": label(row.get("authorization_policy"), "none"),
            "psn": label(row.get("ise_node")),
            "events": integer(row.get("events")),
        } for row in rows["accounting"]]
        accounting_sessions = [{
            "nad": label(row.get("device_name")),
            "psn": label(row.get("ise_node")),
            "avg": number(row.get("avg_session_seconds")),
            "max": number(row.get("max_session_seconds")),
        } for row in rows["accounting_sessions"]]
        active_sessions = [{
            "nad": label(row.get("device_name")),
            "psn": label(row.get("ise_node")),
            "sessions": integer(row.get("sessions")),
        } for row in rows["active_sessions"]]
        errors = [{
            "code": label(row.get("message_code")),
            "nad": label(row.get("network_device_name")),
            "method": label(row.get("authentication_method"), "none"),
            "psn": label(row.get("ise_node")),
            "events": integer(row.get("events")),
        } for row in rows["errors"]]

        writers = []
        for row in auth:
            writers.append(lambda row=row: metrics.ise_dataconnect_radius_authentication_events.labels(
                status=row["status"], authentication_method=row["method"],
                authentication_protocol=row["protocol"], nad=row["nad"],
                policy_set=row["policy"], psn=row["psn"]).set(row["events"]))
            for stat in ("avg", "max"):
                writers.append(lambda row=row, stat=stat:
                    metrics.ise_dataconnect_radius_response_time_seconds.labels(
                        stat=stat, status=row["status"], nad=row["nad"], psn=row["psn"]
                    ).set(row[stat]))
        for row in accounting:
            writers.append(lambda row=row: metrics.ise_dataconnect_radius_accounting_events.labels(
                event_type=row["event_type"], nad=row["nad"],
                authorization_policy=row["policy"], psn=row["psn"]).set(row["events"]))
        for row in accounting_sessions:
            for stat in ("avg", "max"):
                writers.append(lambda row=row, stat=stat:
                    metrics.ise_dataconnect_radius_accounting_session_seconds.labels(
                        stat=stat, nad=row["nad"], psn=row["psn"]).set(row[stat]))
        for row in active_sessions:
            writers.append(lambda row=row: metrics.ise_dataconnect_radius_active_sessions.labels(
                nad=row["nad"], psn=row["psn"]).set(row["sessions"]))
        for row in errors:
            writers.append(lambda row=row: metrics.ise_dataconnect_radius_errors.labels(
                message_code=row["code"], nad=row["nad"],
                authentication_method=row["method"], psn=row["psn"]).set(row["events"]))
        replace_snapshot(_METRICS, writers)
