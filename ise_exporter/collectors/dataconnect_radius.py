"""Exact RADIUS reporting and bounded current-session collection from Data Connect.

Historical event queries are explicitly bounded to a short configured window and run on
a slow reporting cadence. A separate query reconstructs only current likely-active
sessions on a shorter cadence. Usernames, MAC addresses, session IDs, free-form
failure text, and other unbounded values never become Prometheus labels.
"""
from .. import metrics
from . import observe
from .dataconnect_common import (
    event_window_hours,
    group_limit,
    integer,
    label,
    number,
    query_set,
    recent_event_predicate,
    replace_snapshot,
)


_REPORTING_METRICS = (
    metrics.ise_dataconnect_radius_authentication_events,
    metrics.ise_dataconnect_radius_authentication_events_total,
    metrics.ise_dataconnect_radius_distinct_endpoints_total,
    metrics.ise_dataconnect_radius_distinct_users_total,
    metrics.ise_dataconnect_radius_failure_events,
    metrics.ise_dataconnect_radius_failure_events_total,
    metrics.ise_dataconnect_radius_response_time_seconds,
    metrics.ise_dataconnect_radius_response_time_samples,
    metrics.ise_dataconnect_radius_accounting_events,
    metrics.ise_dataconnect_radius_accounting_events_total,
    metrics.ise_dataconnect_radius_accounting_event_type_total,
    metrics.ise_dataconnect_radius_accounting_session_seconds,
    metrics.ise_dataconnect_radius_errors,
    metrics.ise_dataconnect_radius_errors_total,
    metrics.ise_dataconnect_radius_topk_groups_returned,
    metrics.ise_dataconnect_radius_topk_groups_total,
    metrics.ise_dataconnect_radius_topk_groups_total_exact,
    metrics.ise_dataconnect_radius_topk_truncated,
)

_ACTIVE_METRICS = (
    metrics.ise_dataconnect_radius_active_sessions,
    metrics.ise_dataconnect_radius_active_sessions_total,
    metrics.ise_dataconnect_radius_active_session_stale_cutoff_seconds,
    metrics.ise_dataconnect_radius_active_groups_returned,
    metrics.ise_dataconnect_radius_active_groups_total,
    metrics.ise_dataconnect_radius_active_groups_truncated,
)

_METRICS = _REPORTING_METRICS + _ACTIVE_METRICS

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
            WHERE timestamp >= SYSTIMESTAMP -
                  NUMTODSINTERVAL({stale_minutes}, 'MINUTE')
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
              AND LOWER(TRIM(acct_status_type)) IN (
                  'start', 'interim', 'interim-update', 'interim update', 'update'
              )
        )
    """


def _queries(limit, stale_minutes=60, window_hours=6):
    active_cte = _active_cte(stale_minutes)
    auth_recent = recent_event_predicate("timestamp", window_hours)
    auth_summary_recent = recent_event_predicate("timestamp", window_hours)
    accounting_recent = recent_event_predicate("timestamp", window_hours)
    errors_recent = recent_event_predicate("timestamp", window_hours)
    return {
        "authentication": f"""
            WITH grouped_auth AS (
                SELECT CASE WHEN GROUPING(authentication_method) = 0
                            THEN 'authentication' ELSE 'latency' END AS breakdown,
                       CASE WHEN NVL(failed, 0) > 0 THEN 'failed' ELSE 'passed' END
                           AS status,
                       authentication_method, authentication_protocol, device_name,
                       authorization_policy, ise_node, COUNT(*) AS events,
                       COUNT(response_time) AS samples,
                       AVG(response_time) AS avg_response_ms,
                       MAX(response_time) AS max_response_ms
                FROM radius_authentications
                WHERE {auth_recent}
                GROUP BY GROUPING SETS (
                    (CASE WHEN NVL(failed, 0) > 0 THEN 'failed' ELSE 'passed' END,
                     authentication_method, authentication_protocol, device_name,
                     authorization_policy, ise_node),
                    (CASE WHEN NVL(failed, 0) > 0 THEN 'failed' ELSE 'passed' END,
                     device_name, ise_node)
                )
            ), ranked_auth AS (
                SELECT grouped_auth.*,
                       COUNT(*) OVER (PARTITION BY breakdown) AS total_groups,
                       ROW_NUMBER() OVER (
                           PARTITION BY breakdown
                           ORDER BY CASE WHEN breakdown = 'authentication'
                                         THEN events ELSE samples END DESC
                       ) AS group_rank
                FROM grouped_auth
                WHERE breakdown = 'authentication' OR samples > 0
            )
            SELECT * FROM ranked_auth WHERE group_rank <= {limit}
        """,
        "volume_summary": f"""
            WITH grouped_failure AS (
                SELECT CASE WHEN GROUPING(authorization_profiles) = 1
                            THEN 'volume_summary' ELSE 'failure_context' END AS breakdown,
                       {_FAILURE_CLASS_SQL} AS failure_class,
                       authorization_profiles, location,
                       SUM(NVL(passed_count, 0) + NVL(failed_count, 0)) AS total_events,
                       SUM(NVL(failed_count, 0)) AS failure_events,
                       COUNT(DISTINCT calling_station_id) AS distinct_endpoints,
                       COUNT(DISTINCT username) AS distinct_users,
                       SUM(NVL(failed_count, 0)) AS events
                FROM radius_authentication_summary
                WHERE {auth_summary_recent}
                GROUP BY GROUPING SETS (
                    (),
                    ({_FAILURE_CLASS_SQL}, authorization_profiles, location)
                )
            ), ranked_failure AS (
                SELECT grouped_failure.*,
                       COUNT(*) OVER (PARTITION BY breakdown) AS total_groups,
                       ROW_NUMBER() OVER (
                           PARTITION BY breakdown ORDER BY events DESC
                       ) AS group_rank
                FROM grouped_failure
                WHERE breakdown = 'volume_summary' OR events > 0
            )
            SELECT * FROM ranked_failure
            WHERE breakdown = 'volume_summary' OR group_rank <= {limit}
        """,
        "accounting": f"""
            WITH grouped_accounting AS (
                SELECT CASE WHEN GROUPING(acct_status_type) = 0
                            THEN 'accounting' ELSE 'accounting_sessions' END AS breakdown,
                       acct_status_type, device_name, authorization_policy, ise_node,
                       COUNT(*) AS events,
                       COUNT(CASE WHEN acct_session_time > 0
                                  THEN acct_session_time END) AS samples,
                       AVG(CASE WHEN acct_session_time > 0
                                THEN acct_session_time END) AS avg_session_seconds,
                       MAX(CASE WHEN acct_session_time > 0
                                THEN acct_session_time END) AS max_session_seconds
                FROM radius_accounting
                WHERE {accounting_recent}
                GROUP BY GROUPING SETS (
                    (acct_status_type, device_name, authorization_policy, ise_node),
                    (device_name, ise_node)
                )
            ), ranked_accounting AS (
                SELECT grouped_accounting.*,
                       SUM(events) OVER (PARTITION BY breakdown) AS total_events,
                       SUM(CASE WHEN LOWER(NVL(acct_status_type, '')) LIKE '%start%'
                                THEN events ELSE 0 END)
                           OVER (PARTITION BY breakdown) AS start_events,
                       SUM(CASE WHEN LOWER(NVL(acct_status_type, '')) LIKE '%stop%'
                                THEN events ELSE 0 END)
                           OVER (PARTITION BY breakdown) AS stop_events,
                       COUNT(*) OVER (PARTITION BY breakdown) AS total_groups,
                       ROW_NUMBER() OVER (
                           PARTITION BY breakdown
                           ORDER BY CASE WHEN breakdown = 'accounting'
                                         THEN events ELSE samples END DESC
                       ) AS group_rank
                FROM grouped_accounting
                WHERE breakdown = 'accounting' OR samples > 0
            )
            SELECT * FROM ranked_accounting WHERE group_rank <= {limit}
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
                WHERE {errors_recent}
                GROUP BY TO_CHAR(message_code), network_device_name,
                         authentication_method, ise_node
            ) grouped_errors
            ORDER BY events DESC FETCH FIRST {limit} ROWS ONLY
        """,
    }


def _reporting_queries(limit, window_hours=6):
    return {name: sql for name, sql in _queries(limit, window_hours=window_hours).items()
            if name != "active_sessions"}


def collect_reporting(dataconnect, cfg):
    """Atomically replace a bounded recent RADIUS reporting snapshot."""
    with observe("dataconnect_radius"):
        limit = group_limit(cfg)
        combined = query_set(
            dataconnect,
            _reporting_queries(
                limit, event_window_hours(
                    cfg, getattr(cfg, "dataconnect_radius_interval", 86400))),
        )
        rows = {
            "authentication": [row for row in combined["authentication"]
                               if row.get("breakdown") == "authentication"],
            "latency": [row for row in combined["authentication"]
                        if row.get("breakdown") == "latency"],
            "volume_summary": [row for row in combined["volume_summary"]
                               if row.get("breakdown") == "volume_summary"],
            "failure_context": [row for row in combined["volume_summary"]
                                if row.get("breakdown") == "failure_context"],
            "accounting": [row for row in combined["accounting"]
                           if row.get("breakdown") == "accounting"],
            "accounting_sessions": [row for row in combined["accounting"]
                                    if row.get("breakdown") == "accounting_sessions"],
            "errors": combined["errors"],
        }
        summaries = {name: (values[0] if values else {}) for name, values in rows.items()}
        auth = [{
            "status": label(row.get("status")),
            "method": label(row.get("authentication_method"), "none"),
            "protocol": label(row.get("authentication_protocol"), "none"),
            "nad": label(row.get("device_name")),
            "policy": label(row.get("authorization_policy"), "none"),
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
        errors = [{
            "code": label(row.get("message_code")),
            "nad": label(row.get("network_device_name")),
            "method": label(row.get("authentication_method"), "none"),
            "psn": label(row.get("ise_node")),
            "events": integer(row.get("events")),
        } for row in rows["errors"]]
        failure_context = [{
            "failure_class": label(row.get("failure_class"), "unspecified"),
            "profile": label(row.get("authorization_profiles"), "none"),
            "location": label(row.get("location"), "Unknown"),
            "events": integer(row.get("events")),
        } for row in rows["failure_context"]]

        writers = []
        for row in auth:
            writers.append(lambda row=row: metrics.ise_dataconnect_radius_authentication_events.labels(
                status=row["status"], authentication_method=row["method"],
                authentication_protocol=row["protocol"], nad=row["nad"],
                authorization_policy=row["policy"], psn=row["psn"]).set(row["events"]))
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
        for row in errors:
            writers.append(lambda row=row: metrics.ise_dataconnect_radius_errors.labels(
                message_code=row["code"], nad=row["nad"],
                authentication_method=row["method"], psn=row["psn"]).set(row["events"]))
        for row in failure_context:
            writers.append(lambda row=row: metrics.ise_dataconnect_radius_failure_events.labels(
                failure_class=row["failure_class"], authorization_profile=row["profile"],
                location=row["location"]).set(row["events"]))

        volume_summary = summaries["volume_summary"]
        writers.extend((
            lambda: metrics.ise_dataconnect_radius_authentication_events_total.set(
                integer(volume_summary.get("total_events"))),
            lambda: metrics.ise_dataconnect_radius_distinct_endpoints_total.set(
                integer(volume_summary.get("distinct_endpoints"))),
            lambda: metrics.ise_dataconnect_radius_distinct_users_total.set(
                integer(volume_summary.get("distinct_users"))),
            lambda: metrics.ise_dataconnect_radius_failure_events_total.set(
                integer(volume_summary.get("failure_events"))),
            lambda: metrics.ise_dataconnect_radius_accounting_events_total.set(
                integer(summaries["accounting"].get("total_events"))),
            lambda: metrics.ise_dataconnect_radius_accounting_event_type_total.labels(
                event_type="start").set(
                    integer(summaries["accounting"].get("start_events"))),
            lambda: metrics.ise_dataconnect_radius_accounting_event_type_total.labels(
                event_type="stop").set(
                    integer(summaries["accounting"].get("stop_events"))),
            lambda: metrics.ise_dataconnect_radius_errors_total.set(
                integer(summaries["errors"].get("total_events"))),
        ))
        breakdowns = {
            "authentication": (len(auth), summaries["authentication"]),
            "latency": (len(latency), summaries["latency"]),
            "accounting": (len(accounting), summaries["accounting"]),
            "accounting_sessions": (len(accounting_sessions), summaries["accounting_sessions"]),
            "errors": (len(errors), summaries["errors"]),
            "failure_context": (len(failure_context), summaries["failure_context"]),
        }
        for breakdown, (returned, summary) in breakdowns.items():
            total = integer(summary.get("total_groups"))
            total_exact = integer(summary.get("total_groups_exact", 1))
            writers.extend((
                lambda breakdown=breakdown, returned=returned:
                    metrics.ise_dataconnect_radius_topk_groups_returned.labels(
                        breakdown=breakdown).set(returned),
                lambda breakdown=breakdown, total=total:
                    metrics.ise_dataconnect_radius_topk_groups_total.labels(
                        breakdown=breakdown).set(total),
                lambda breakdown=breakdown, total_exact=total_exact:
                    metrics.ise_dataconnect_radius_topk_groups_total_exact.labels(
                        breakdown=breakdown).set(total_exact),
                lambda breakdown=breakdown, returned=returned, total=total,
                total_exact=total_exact:
                    metrics.ise_dataconnect_radius_topk_truncated.labels(
                        breakdown=breakdown).set(
                            1 if not total_exact or returned < total else 0),
            ))
        replace_snapshot(_REPORTING_METRICS, writers)


def collect_active(dataconnect, cfg):
    """Atomically replace the current bounded active-session reconstruction."""
    with observe("dataconnect_radius_active"):
        limit = group_limit(cfg)
        # This query runs repeatedly and reads the large accounting event view.
        # A caller-created config object must not expand it into the former
        # day-long scan; 60 minutes is both the documented reconstruction window
        # and a hard execution-boundary ceiling.
        stale_minutes = max(5, min(60, int(getattr(
            cfg, "dataconnect_active_session_stale_minutes", 60))))
        values = dataconnect.query(_queries(limit, stale_minutes)["active_sessions"])
        summary = values[0] if values else {}
        active_sessions = [{
            "nad": label(row.get("device_name")),
            "psn": label(row.get("ise_node")),
            "sessions": integer(row.get("sessions")),
        } for row in values]
        total_groups = integer(summary.get("total_groups"))
        writers = [
            lambda row=row: metrics.ise_dataconnect_radius_active_sessions.labels(
                nad=row["nad"], psn=row["psn"]).set(row["sessions"])
            for row in active_sessions
        ]
        writers.extend((
            lambda: metrics.ise_dataconnect_radius_active_sessions_total.set(
                integer(summary.get("total_sessions"))),
            lambda: metrics.ise_dataconnect_radius_active_session_stale_cutoff_seconds.set(
                stale_minutes * 60),
            lambda: metrics.ise_dataconnect_radius_active_groups_returned.set(
                len(active_sessions)),
            lambda: metrics.ise_dataconnect_radius_active_groups_total.set(total_groups),
            lambda: metrics.ise_dataconnect_radius_active_groups_truncated.set(
                int(len(active_sessions) < total_groups)),
        ))
        replace_snapshot(_ACTIVE_METRICS, writers)
