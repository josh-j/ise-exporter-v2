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
    metrics.ise_dataconnect_radius_authentication_events_total,
    metrics.ise_dataconnect_radius_distinct_endpoints_total,
    metrics.ise_dataconnect_radius_distinct_users_total,
    metrics.ise_dataconnect_radius_failure_events,
    metrics.ise_dataconnect_radius_response_time_seconds,
    metrics.ise_dataconnect_radius_response_time_samples,
    metrics.ise_dataconnect_radius_accounting_events,
    metrics.ise_dataconnect_radius_accounting_events_total,
    metrics.ise_dataconnect_radius_accounting_session_seconds,
    metrics.ise_dataconnect_radius_active_sessions,
    metrics.ise_dataconnect_radius_active_sessions_total,
    metrics.ise_dataconnect_radius_active_session_stale_cutoff_seconds,
    metrics.ise_dataconnect_radius_errors,
    metrics.ise_dataconnect_radius_errors_total,
    metrics.ise_dataconnect_radius_topk_groups_returned,
    metrics.ise_dataconnect_radius_topk_groups_total,
    metrics.ise_dataconnect_radius_topk_truncated,
)

_FAILURE_CLASS_SQL = """CASE
    WHEN TRIM(failure_reason) IS NULL THEN 'unspecified'
    WHEN LOWER(failure_reason) LIKE '%password%'
      OR LOWER(failure_reason) LIKE '%credential%' THEN 'credentials'
    WHEN LOWER(failure_reason) LIKE '%certificate%'
      OR LOWER(failure_reason) LIKE '%tls%' THEN 'certificate_or_tls'
    WHEN LOWER(failure_reason) LIKE '%identity%'
      OR LOWER(failure_reason) LIKE '%user not found%' THEN 'identity'
    WHEN LOWER(failure_reason) LIKE '%timeout%'
      OR LOWER(failure_reason) LIKE '%no response%' THEN 'timeout'
    WHEN LOWER(failure_reason) LIKE '%policy%'
      OR LOWER(failure_reason) LIKE '%reject%'
      OR LOWER(failure_reason) LIKE '%denied%' THEN 'policy_denied'
    ELSE 'other' END"""


def _active_cte(stale_minutes):
    return f"""
        WITH keyed_accounting AS (
            SELECT CASE
                       WHEN TRIM(audit_session_id) IS NOT NULL
                           THEN 'audit:' || TRIM(audit_session_id)
                       WHEN TRIM(session_id) IS NOT NULL
                           THEN 'session:' || TRIM(session_id)
                       ELSE 'acct:' ||
                            NVL(TRIM(device_name), NVL(TRIM(nas_ip_address), 'unknown')) ||
                            ':' || TRIM(acct_session_id)
                   END AS session_key,
                   id, timestamp AS event_time, device_name, ise_node, acct_status_type
            FROM radius_accounting
            WHERE timestamp >= SYSTIMESTAMP - INTERVAL '2' DAY
              AND (TRIM(audit_session_id) IS NOT NULL
                   OR TRIM(session_id) IS NOT NULL
                   OR TRIM(acct_session_id) IS NOT NULL)
        ), latest_accounting AS (
            SELECT keyed_accounting.*,
                   ROW_NUMBER() OVER (
                       PARTITION BY session_key ORDER BY event_time DESC, id DESC
                   ) AS row_num
            FROM keyed_accounting
        ), active_accounting AS (
            SELECT device_name, ise_node
            FROM latest_accounting
            WHERE row_num = 1
              AND LOWER(NVL(acct_status_type, 'stop')) NOT LIKE '%stop%'
              AND event_time >= SYSTIMESTAMP -
                  NUMTODSINTERVAL({stale_minutes}, 'MINUTE')
        )
    """


def _queries(limit, stale_minutes=60):
    active_cte = _active_cte(stale_minutes)
    return {
        "authentication": f"""
            SELECT grouped_auth.*,
                   SUM(events) OVER () AS total_events,
                   COUNT(*) OVER () AS total_groups
            FROM (
                SELECT CASE WHEN NVL(failed, 0) > 0 THEN 'failed' ELSE 'passed' END
                           AS status,
                       authentication_method, authentication_protocol, device_name,
                       policy_set_name, ise_node, COUNT(*) AS events
                FROM radius_authentications
                WHERE timestamp >= SYSTIMESTAMP - INTERVAL '2' DAY
                GROUP BY CASE WHEN NVL(failed, 0) > 0 THEN 'failed' ELSE 'passed' END,
                         authentication_method, authentication_protocol, device_name,
                         policy_set_name, ise_node
            ) grouped_auth
            ORDER BY events DESC FETCH FIRST {limit} ROWS ONLY
        """,
        "identity_summary": """
            SELECT COUNT(DISTINCT calling_station_id) AS distinct_endpoints,
                   COUNT(DISTINCT username) AS distinct_users
            FROM radius_authentications
            WHERE timestamp >= SYSTIMESTAMP - INTERVAL '2' DAY
        """,
        "failure_context": f"""
            SELECT grouped_failure.*,
                   SUM(events) OVER () AS total_events,
                   COUNT(*) OVER () AS total_groups
            FROM (
                SELECT {_FAILURE_CLASS_SQL} AS failure_class,
                       policy_set_name, location, COUNT(*) AS events
                FROM radius_authentications
                WHERE timestamp >= SYSTIMESTAMP - INTERVAL '2' DAY
                  AND NVL(failed, 0) > 0
                GROUP BY {_FAILURE_CLASS_SQL}, policy_set_name, location
            ) grouped_failure
            ORDER BY events DESC FETCH FIRST {limit} ROWS ONLY
        """,
        "latency": f"""
            SELECT grouped_latency.*, COUNT(*) OVER () AS total_groups
            FROM (
                SELECT CASE WHEN NVL(failed, 0) > 0 THEN 'failed' ELSE 'passed' END
                           AS status,
                       device_name, ise_node, COUNT(response_time) AS samples,
                       AVG(response_time) AS avg_response_ms,
                       MAX(response_time) AS max_response_ms
                FROM radius_authentications
                WHERE timestamp >= SYSTIMESTAMP - INTERVAL '2' DAY
                  AND response_time IS NOT NULL
                GROUP BY CASE WHEN NVL(failed, 0) > 0 THEN 'failed' ELSE 'passed' END,
                         device_name, ise_node
            ) grouped_latency
            ORDER BY samples DESC FETCH FIRST {limit} ROWS ONLY
        """,
        "accounting": f"""
            SELECT grouped_accounting.*,
                   SUM(events) OVER () AS total_events,
                   COUNT(*) OVER () AS total_groups
            FROM (
                SELECT acct_status_type, device_name, authorization_policy, ise_node,
                       COUNT(*) AS events
                FROM radius_accounting
                WHERE timestamp >= SYSTIMESTAMP - INTERVAL '2' DAY
                GROUP BY acct_status_type, device_name, authorization_policy, ise_node
            ) grouped_accounting
            ORDER BY events DESC FETCH FIRST {limit} ROWS ONLY
        """,
        "accounting_sessions": f"""
            SELECT grouped_sessions.*, COUNT(*) OVER () AS total_groups
            FROM (
                SELECT device_name, ise_node,
                       AVG(acct_session_time) AS avg_session_seconds,
                       MAX(acct_session_time) AS max_session_seconds
                FROM radius_accounting
                WHERE timestamp >= SYSTIMESTAMP - INTERVAL '2' DAY
                  AND acct_session_time IS NOT NULL AND acct_session_time > 0
                GROUP BY device_name, ise_node
            ) grouped_sessions
            ORDER BY max_session_seconds DESC FETCH FIRST {limit} ROWS ONLY
        """,
        "active_sessions": active_cte + f"""
            SELECT grouped_active.*,
                   SUM(sessions) OVER () AS total_sessions,
                   COUNT(*) OVER () AS total_groups
            FROM (
                SELECT device_name, ise_node, COUNT(*) AS sessions
                FROM active_accounting
                GROUP BY device_name, ise_node
            ) grouped_active
            ORDER BY sessions DESC FETCH FIRST {limit} ROWS ONLY
        """,
        "errors": f"""
            SELECT grouped_errors.*,
                   SUM(events) OVER () AS total_events,
                   COUNT(*) OVER () AS total_groups
            FROM (
                SELECT TO_CHAR(message_code) AS message_code, network_device_name,
                       authentication_method, ise_node, COUNT(*) AS events
                FROM radius_errors_view
                WHERE timestamp >= SYSTIMESTAMP - INTERVAL '2' DAY
                GROUP BY TO_CHAR(message_code), network_device_name,
                         authentication_method, ise_node
            ) grouped_errors
            ORDER BY events DESC FETCH FIRST {limit} ROWS ONLY
        """,
    }


def collect(dataconnect, cfg):
    """Atomically replace the bounded RADIUS reporting snapshot."""
    with observe("dataconnect_radius"):
        limit = group_limit(cfg)
        stale_minutes = max(5, min(1440, int(getattr(
            cfg, "dataconnect_active_session_stale_minutes", 60))))
        rows = {name: dataconnect.query(sql)
                for name, sql in _queries(limit, stale_minutes).items()}
        summaries = {name: (values[0] if values else {}) for name, values in rows.items()}
        auth = [{
            "status": label(row.get("status")),
            "method": label(row.get("authentication_method"), "none"),
            "protocol": label(row.get("authentication_protocol"), "none"),
            "nad": label(row.get("device_name")),
            "policy": label(row.get("policy_set_name"), "none"),
            "psn": label(row.get("ise_node")),
            "events": integer(row.get("events")),
        } for row in rows["authentication"]]
        latency = [{
            "status": label(row.get("status")),
            "nad": label(row.get("device_name")),
            "psn": label(row.get("ise_node")),
            "samples": integer(row.get("samples")),
            "avg": number(row.get("avg_response_ms")) / 1000.0,
            "max": number(row.get("max_response_ms")) / 1000.0,
        } for row in rows["latency"]
            if row.get("avg_response_ms") is not None and row.get("max_response_ms") is not None]
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
        failure_context = [{
            "failure_class": label(row.get("failure_class"), "unspecified"),
            "policy": label(row.get("policy_set_name"), "none"),
            "location": label(row.get("location"), "Unknown"),
            "events": integer(row.get("events")),
        } for row in rows["failure_context"]]

        writers = []
        for row in auth:
            writers.append(lambda row=row: metrics.ise_dataconnect_radius_authentication_events.labels(
                status=row["status"], authentication_method=row["method"],
                authentication_protocol=row["protocol"], nad=row["nad"],
                policy_set=row["policy"], psn=row["psn"]).set(row["events"]))
        for row in latency:
            for stat in ("avg", "max"):
                writers.append(lambda row=row, stat=stat:
                    metrics.ise_dataconnect_radius_response_time_seconds.labels(
                        stat=stat, status=row["status"], nad=row["nad"], psn=row["psn"]
                    ).set(row[stat]))
            writers.append(lambda row=row:
                metrics.ise_dataconnect_radius_response_time_samples.labels(
                    status=row["status"], nad=row["nad"], psn=row["psn"]
                ).set(row["samples"]))
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
        for row in failure_context:
            writers.append(lambda row=row: metrics.ise_dataconnect_radius_failure_events.labels(
                failure_class=row["failure_class"], policy_set=row["policy"],
                location=row["location"]).set(row["events"]))

        identity_summary = summaries["identity_summary"]
        writers.extend((
            lambda: metrics.ise_dataconnect_radius_authentication_events_total.set(
                integer(summaries["authentication"].get("total_events"))),
            lambda: metrics.ise_dataconnect_radius_distinct_endpoints_total.set(
                integer(identity_summary.get("distinct_endpoints"))),
            lambda: metrics.ise_dataconnect_radius_distinct_users_total.set(
                integer(identity_summary.get("distinct_users"))),
            lambda: metrics.ise_dataconnect_radius_accounting_events_total.set(
                integer(summaries["accounting"].get("total_events"))),
            lambda: metrics.ise_dataconnect_radius_active_sessions_total.set(
                integer(summaries["active_sessions"].get("total_sessions"))),
            lambda: metrics.ise_dataconnect_radius_active_session_stale_cutoff_seconds.set(
                stale_minutes * 60),
            lambda: metrics.ise_dataconnect_radius_errors_total.set(
                integer(summaries["errors"].get("total_events"))),
        ))
        breakdowns = {
            "authentication": (len(auth), summaries["authentication"]),
            "latency": (len(latency), summaries["latency"]),
            "accounting": (len(accounting), summaries["accounting"]),
            "accounting_sessions": (len(accounting_sessions), summaries["accounting_sessions"]),
            "active_sessions": (len(active_sessions), summaries["active_sessions"]),
            "errors": (len(errors), summaries["errors"]),
            "failure_context": (len(failure_context), summaries["failure_context"]),
        }
        for breakdown, (returned, summary) in breakdowns.items():
            total = integer(summary.get("total_groups"))
            writers.extend((
                lambda breakdown=breakdown, returned=returned:
                    metrics.ise_dataconnect_radius_topk_groups_returned.labels(
                        breakdown=breakdown).set(returned),
                lambda breakdown=breakdown, total=total:
                    metrics.ise_dataconnect_radius_topk_groups_total.labels(
                        breakdown=breakdown).set(total),
                lambda breakdown=breakdown, returned=returned, total=total:
                    metrics.ise_dataconnect_radius_topk_truncated.labels(
                        breakdown=breakdown).set(1 if returned < total else 0),
            ))
        replace_snapshot(_METRICS, writers)
