"""Exact RADIUS reporting and bounded current-session collection from Data Connect.

Historical event queries are explicitly bounded to a short configured window and run on
a 30-minute reporting cadence. A separate query reconstructs only current likely-active
sessions on a shorter cadence. Usernames, MAC addresses, session IDs, free-form
failure text, and other unbounded values never become Prometheus labels.
"""
from .. import metrics
from ..dataconnect_schema import (
    RADIUS_AUTHENTICATION_DETAIL_COLUMNS,
    preferred_radius_authentication_view,
)
from . import dataconnect_tail, observe
from .dataconnect_common import (
    event_window_hours,
    group_limit,
    integer,
    label,
    number,
    query_set,
    recent_event_predicate,
    replace_snapshot,
    schema_expression,
    schema_has,
    schema_projection,
    signed_integer,
)


# Curated, extensible translation of the most common Cisco ISE RADIUS message
# codes to a short human-readable summary. The MESSAGE_CODE column is a bounded
# numeric code and the RADIUS errors view carries no accompanying description
# column, so translation is a static lookup. Codes not listed here render as the
# bare number (empty text); extend this map as new codes are triaged.
_RADIUS_MESSAGE_CODE_TEXT = {
    "5400": "Authentication failed",
    "5411": "Supplicant stopped responding to ISE",
    "5434": "Endpoint restarted a new EAP session",
    "5440": "Endpoint abandoned the EAP session and started a new one",
    "5449": "Endpoint failed the RADIUS authentication",
    "11007": "Could not locate Network Device or AAA Client",
    "11013": "RADIUS packet contains an invalid Message-Authenticator",
    "11036": "The Message-Authenticator RADIUS attribute is invalid",
    "11038": "RADIUS Accounting-Request contains an invalid Authenticator",
    "12508": "EAP-TLS handshake failed",
    "12509": "EAP-TLS handshake failed on an unsupported certificate",
    "12511": "EAP-TLS handshake failed on an unknown CA certificate",
    "12514": "EAP-TLS handshake failed on an untrusted client certificate",
    "15039": "Rejected per authorization policy",
    "22040": "Wrong password or invalid shared secret",
    "22056": "Subject not found in the applicable identity store(s)",
    "24408": "Wrong user password against Active Directory",
    "24491": "Active Directory contains multiple identical accounts",
}


def _radius_message_text(code):
    """Return a bounded human summary for a RADIUS message code, or empty."""
    if code is None:
        return ""
    return _RADIUS_MESSAGE_CODE_TEXT.get(str(code).strip(), "")


_REPORTING_METRICS = (
    metrics.ise_dataconnect_radius_authentication_events,
    metrics.ise_dataconnect_radius_authentication_events_total,
    metrics.ise_dataconnect_radius_distinct_endpoints_total,
    metrics.ise_dataconnect_radius_distinct_users_total,
    metrics.ise_dataconnect_radius_failure_events,
    metrics.ise_dataconnect_radius_failure_events_total,
    metrics.ise_dataconnect_radius_authentication_summary_events,
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
    metrics.ise_dataconnect_radius_active_session_delta,
    metrics.ise_dataconnect_radius_active_session_delta_window_seconds,
    metrics.ise_dataconnect_radius_active_session_stale_cutoff_seconds,
    metrics.ise_dataconnect_radius_active_groups_returned,
    metrics.ise_dataconnect_radius_active_groups_total,
    metrics.ise_dataconnect_radius_active_groups_truncated,
)

_METRICS = _REPORTING_METRICS + _ACTIVE_METRICS

_SUMMARY_DIMENSIONS = (
    "identity_store", "identity_group", "device_type", "security_group",
)

def _failure_class_sql(column="failure_reason"):
    return f"""CASE
    WHEN TRIM({column}) IS NULL THEN 'unspecified'
    WHEN LOWER({column}) LIKE '%password%'
      OR LOWER({column}) LIKE '%credential%' THEN 'credentials'
    WHEN LOWER({column}) LIKE '%certificate%'
      OR LOWER({column}) LIKE '%tls%' THEN 'certificate_or_tls'
    WHEN LOWER({column}) LIKE '%identity%'
      OR LOWER({column}) LIKE '%user not found%' THEN 'identity'
    WHEN LOWER({column}) LIKE '%timeout%'
      OR LOWER({column}) LIKE '%no response%' THEN 'timeout'
    WHEN LOWER({column}) LIKE '%policy%'
      OR LOWER({column}) LIKE '%reject%'
      OR LOWER({column}) LIKE '%denied%' THEN 'policy_denied'
    ELSE 'other' END"""


_FAILURE_CLASS_SQL = _failure_class_sql()


def _active_cte(stale_minutes, delta_minutes=5, schema=None):
    view = "RADIUS_ACCOUNTING"
    return f"""
        WITH recent_accounting AS (
            SELECT /*+ MATERIALIZE */
                   {schema_projection(schema, view, "audit_session_id")},
                   {schema_projection(schema, view, "session_id")},
                   acct_session_id, id, timestamp AS event_time,
                   {schema_projection(schema, view, "device_name", "'unknown'")},
                   {schema_projection(schema, view, "nas_ip_address", "'unknown'")},
                   {schema_projection(schema, view, "ise_node", "'unknown'")},
                   acct_status_type
            FROM radius_accounting
            WHERE timestamp >= CAST(
                      SYSTIMESTAMP - NUMTODSINTERVAL({stale_minutes}, 'MINUTE')
                      AS TIMESTAMP)
        ), keyed_accounting AS (
            SELECT CASE
                       WHEN TRIM(audit_session_id) IS NOT NULL
                           THEN 'audit:' || TRIM(audit_session_id)
                       WHEN TRIM(session_id) IS NOT NULL
                           THEN 'session:' || TRIM(session_id)
                       ELSE 'acct:' ||
                            NVL(TRIM(device_name), NVL(TRIM(nas_ip_address), 'unknown')) ||
                            ':' || TRIM(acct_session_id)
                   END AS session_key,
                   id, event_time, device_name, ise_node, acct_status_type
            FROM recent_accounting
            WHERE (TRIM(audit_session_id) IS NOT NULL
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
        ), grouped_active AS (
            SELECT device_name, ise_node, COUNT(*) AS sessions
            FROM active_accounting
            GROUP BY device_name, ise_node
        ), ranked_active AS (
            SELECT grouped_active.*,
                   SUM(sessions) OVER () AS total_sessions,
                   COUNT(*) OVER () AS total_groups,
                   ROW_NUMBER() OVER (ORDER BY sessions DESC) AS group_rank
            FROM grouped_active
        ), grouped_delta AS (
            SELECT ise_node,
                   SUM(CASE
                       WHEN LOWER(TRIM(acct_status_type)) LIKE '%start%' THEN 1
                       WHEN LOWER(TRIM(acct_status_type)) LIKE '%stop%' THEN -1
                       ELSE 0
                   END) AS session_delta
            FROM recent_accounting
            WHERE event_time >= CAST(
                      SYSTIMESTAMP - NUMTODSINTERVAL({delta_minutes}, 'MINUTE')
                      AS TIMESTAMP)
              AND (LOWER(TRIM(acct_status_type)) LIKE '%start%'
                   OR LOWER(TRIM(acct_status_type)) LIKE '%stop%')
            GROUP BY ise_node
        ), ranked_delta AS (
            SELECT grouped_delta.*,
                   ROW_NUMBER() OVER (
                       ORDER BY ABS(session_delta) DESC) AS group_rank
            FROM grouped_delta
        )
    """


def _queries(limit, stale_minutes=60, window_hours=6, delta_minutes=5,
             authentication_policy_column="authorization_policy",
             accounting_policy_expression="authorization_policy", schema=None,
             authentication_view="RADIUS_AUTHENTICATIONS"):
    authentication_policy_column = str(authentication_policy_column).lower()
    if authentication_policy_column not in {
            "authorization_policy", "policy_set_name", "'none'"}:
        raise ValueError("unsupported RADIUS authentication policy column")
    authentication_view = str(authentication_view).upper()
    if authentication_view not in {
            "RADIUS_AUTHENTICATIONS", "RADIUS_AUTHENTICATIONS_WEEK"}:
        raise ValueError("unsupported RADIUS authentication view")
    accounting_policy_expression = str(accounting_policy_expression).lower()
    if accounting_policy_expression not in {"authorization_policy", "'none'"}:
        raise ValueError("unsupported RADIUS accounting policy expression")
    active_cte = _active_cte(stale_minutes, delta_minutes, schema)
    auth_recent = recent_event_predicate("timestamp", window_hours)
    auth_summary_recent = recent_event_predicate("timestamp", window_hours)
    accounting_recent = recent_event_predicate("timestamp", window_hours)
    errors_recent = recent_event_predicate("timestamp", window_hours)
    auth_view = authentication_view
    auth = {
        column: schema_expression(schema, auth_view, column, fallback)
        for column, fallback in (
            ("authentication_method", "'none'"),
            ("authentication_protocol", "'none'"), ("device_name", "'unknown'"),
            ("ise_node", "'unknown'"), ("response_time", "NULL"),
        )
    }
    status = ("CASE WHEN NVL(failed, 0) > 0 THEN 'failed' ELSE 'passed' END"
              if schema_has(schema, auth_view, "failed") else "'unknown'")
    summary_view = "RADIUS_AUTHENTICATION_SUMMARY"
    failure_reason = schema_expression(schema, summary_view, "failure_reason")
    failure_class = _failure_class_sql(failure_reason)
    summary = {
        column: schema_expression(schema, summary_view, column, fallback)
        for column, fallback in (
            ("authorization_profiles", "'none'"), ("location", "'Unknown'"),
            ("calling_station_id", "NULL"), ("username", "NULL"),
            ("identity_store", "'unknown'"), ("identity_group", "'unknown'"),
            ("device_type", "'unknown'"), ("security_group", "'unknown'"),
        )
    }
    summary_dimensions = tuple(
        dimension for dimension in _SUMMARY_DIMENSIONS
        if schema_has(schema, summary_view, dimension)
    )
    dimension_breakdown = "\n".join(
        f"WHEN GROUPING({dimension}) = 0 THEN '{dimension}'"
        for dimension in summary_dimensions
    )
    dimension_value = "\n".join(
        f"WHEN GROUPING({dimension}) = 0 THEN {dimension}"
        for dimension in summary_dimensions
    )
    dimension_groupings = "".join(
        f", ({dimension})" for dimension in summary_dimensions
    )
    accounting_view = "RADIUS_ACCOUNTING"
    accounting = {
        column: schema_expression(schema, accounting_view, column, fallback)
        for column, fallback in (
            ("acct_status_type", "'unknown'"), ("device_name", "'unknown'"),
            ("ise_node", "'unknown'"), ("acct_session_time", "NULL"),
        )
    }
    error_view = "RADIUS_ERRORS_VIEW"
    errors = {
        column: schema_expression(schema, error_view, column, fallback)
        for column, fallback in (
            ("message_code", "'unknown'"), ("network_device_name", "'unknown'"),
            ("authentication_method", "'none'"), ("ise_node", "'unknown'"),
        )
    }
    return {
        "authentication": f"""
            WITH auth_source AS (
                SELECT {status} AS status,
                       {auth["authentication_method"]} AS authentication_method,
                       {auth["authentication_protocol"]} AS authentication_protocol,
                       {auth["device_name"]} AS device_name,
                       {authentication_policy_column} AS authorization_policy,
                       {auth["ise_node"]} AS ise_node,
                       {auth["response_time"]} AS response_time
                FROM {auth_view.lower()}
                WHERE {auth_recent}
            ), grouped_auth AS (
                SELECT CASE WHEN GROUPING(authentication_method) = 0
                            THEN 'authentication' ELSE 'latency' END AS breakdown,
                       status, authentication_method, authentication_protocol,
                       device_name, authorization_policy, ise_node,
                       COUNT(*) AS events,
                       COUNT(response_time) AS samples,
                       AVG(response_time) AS avg_response_ms,
                       MAX(response_time) AS max_response_ms
                FROM auth_source
                GROUP BY GROUPING SETS (
                    (status, authentication_method, authentication_protocol,
                     device_name, authorization_policy, ise_node),
                    (status, device_name, ise_node)
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
            WITH failure_source AS (
                SELECT {failure_class} AS failure_class,
                       {summary["authorization_profiles"]} AS authorization_profiles,
                       {summary["location"]} AS location,
                       passed_count, failed_count,
                       {summary["calling_station_id"]} AS calling_station_id,
                       {summary["username"]} AS username,
                       {summary["identity_store"]} AS identity_store,
                       {summary["identity_group"]} AS identity_group,
                       {summary["device_type"]} AS device_type,
                       {summary["security_group"]} AS security_group
                FROM radius_authentication_summary
                WHERE {auth_summary_recent}
            ), grouped_failure AS (
                SELECT CASE
                           WHEN GROUPING(failure_class) = 0 THEN 'failure_context'
                           {dimension_breakdown}
                           ELSE 'volume_summary'
                       END AS breakdown,
                       failure_class, authorization_profiles, location,
                       CASE
                           {dimension_value}
                           ELSE NULL
                       END AS dimension_value,
                       SUM(NVL(passed_count, 0) + NVL(failed_count, 0)) AS total_events,
                       SUM(NVL(passed_count, 0)) AS passed_events,
                       SUM(NVL(failed_count, 0)) AS failure_events,
                       COUNT(DISTINCT calling_station_id) AS distinct_endpoints,
                       COUNT(DISTINCT username) AS distinct_users,
                       SUM(NVL(failed_count, 0)) AS events
                FROM failure_source
                GROUP BY GROUPING SETS (
                    (),
                    (failure_class, authorization_profiles, location)
                    {dimension_groupings}
                )
            ), ranked_failure AS (
                SELECT grouped_failure.*,
                       COUNT(*) OVER (PARTITION BY breakdown) AS total_groups,
                       ROW_NUMBER() OVER (
                           PARTITION BY breakdown ORDER BY
                               CASE WHEN breakdown = 'failure_context'
                                    THEN events ELSE total_events END DESC
                       ) AS group_rank
                FROM grouped_failure
                WHERE breakdown = 'volume_summary'
                   OR (breakdown = 'failure_context' AND events > 0)
                   OR (breakdown <> 'failure_context' AND total_events > 0)
            )
            SELECT * FROM ranked_failure
            WHERE breakdown = 'volume_summary' OR group_rank <= {limit}
        """,
        "accounting": f"""
            WITH accounting_source AS (
                SELECT {accounting["acct_status_type"]} AS acct_status_type,
                       {accounting["device_name"]} AS device_name,
                       {accounting_policy_expression} AS authorization_policy,
                       {accounting["ise_node"]} AS ise_node,
                       {accounting["acct_session_time"]} AS acct_session_time
                FROM radius_accounting
                WHERE {accounting_recent}
            ), grouped_accounting AS (
                SELECT CASE WHEN GROUPING(acct_status_type) = 0
                            THEN 'accounting' ELSE 'accounting_sessions' END AS breakdown,
                       acct_status_type, device_name, authorization_policy, ise_node,
                       COUNT(*) AS events,
                       COUNT(CASE WHEN acct_session_time > 0
                                  THEN acct_session_time END) AS samples,
                       AVG(CASE WHEN acct_session_time > 0
                                THEN acct_session_time END)
                           AS avg_session_seconds,
                       MAX(CASE WHEN acct_session_time > 0
                                THEN acct_session_time END)
                           AS max_session_seconds
                FROM accounting_source
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
            SELECT 'active' AS breakdown, device_name, ise_node, sessions,
                   NULL AS session_delta, total_sessions, total_groups
            FROM ranked_active
            WHERE group_rank <= {limit}
            UNION ALL
            SELECT 'delta' AS breakdown, NULL AS device_name, ise_node,
                   NULL AS sessions, session_delta,
                   NULL AS total_sessions, NULL AS total_groups
            FROM ranked_delta
            WHERE group_rank <= {limit}
        """,
        "errors": f"""
            SELECT grouped_errors.*,
                   SUM(events) OVER () AS total_events,
                   COUNT(*) OVER () AS total_groups
            FROM (
                SELECT TO_CHAR({errors["message_code"]}) AS message_code,
                       {errors["network_device_name"]} AS network_device_name,
                       {errors["authentication_method"]} AS authentication_method,
                       {errors["ise_node"]} AS ise_node, COUNT(*) AS events
                FROM radius_errors_view
                WHERE {errors_recent}
                GROUP BY TO_CHAR({errors["message_code"]}),
                         {errors["network_device_name"]},
                         {errors["authentication_method"]}, {errors["ise_node"]}
            ) grouped_errors
            ORDER BY events DESC FETCH FIRST {limit} ROWS ONLY
        """,
    }


def _reporting_queries(limit, window_hours=6,
                       authentication_policy_column="authorization_policy",
                       accounting_policy_expression="authorization_policy", schema=None,
                       authentication_view="RADIUS_AUTHENTICATIONS"):
    return {name: sql for name, sql in _queries(
                limit, window_hours=window_hours,
                authentication_policy_column=authentication_policy_column,
                accounting_policy_expression=accounting_policy_expression,
                schema=schema, authentication_view=authentication_view).items()
            if name != "active_sessions"}


def _authentication_source(dataconnect):
    schema = getattr(dataconnect, "schema", None)
    view = preferred_radius_authentication_view(
        schema, preferred_columns=RADIUS_AUTHENTICATION_DETAIL_COLUMNS)
    if schema is None:
        # Direct collector integrations predating capability negotiation retain
        # the legacy query shape. Production always uses discovered schema.
        return view, "authorization_policy"
    columns = set(schema.get(view, {}))
    if "AUTHORIZATION_POLICY" in columns:
        return view, "authorization_policy"
    if "POLICY_SET_NAME" in columns:
        return view, "policy_set_name"
    return view, "'none'"


def _accounting_policy_expression(dataconnect):
    schema = getattr(dataconnect, "schema", {})
    columns = schema.get("RADIUS_ACCOUNTING", {}) \
        if isinstance(schema, dict) else {}
    if "AUTHORIZATION_POLICY" in columns:
        return "authorization_policy"
    if columns:
        return "'none'"
    # Direct collector integrations predating capability negotiation retain the
    # lab Patch 11 behavior. The production client always has discovered schema.
    return "authorization_policy"


def collect_reporting(dataconnect, cfg):
    """Atomically replace a bounded recent RADIUS reporting snapshot."""
    with observe("dataconnect_radius"):
        limit = group_limit(cfg)
        authentication_view, authentication_policy = _authentication_source(dataconnect)
        combined = query_set(
            dataconnect,
            _reporting_queries(
                limit, event_window_hours(
                    cfg, getattr(cfg, "dataconnect_radius_interval", 1800)),
                authentication_policy_column=authentication_policy,
                accounting_policy_expression=_accounting_policy_expression(dataconnect),
                schema=getattr(dataconnect, "schema", None),
                authentication_view=authentication_view),
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
            **{
                breakdown: [row for row in combined["volume_summary"]
                            if row.get("breakdown") == breakdown]
                for breakdown in _SUMMARY_DIMENSIONS
            },
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
            "text": _radius_message_text(row.get("message_code")),
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
        summary_dimensions = [
            {
                "dimension": dimension,
                "value": label(row.get("dimension_value")),
                "passed": integer(row.get("passed_events")),
                "failed": integer(row.get("failure_events")),
            }
            for dimension in _SUMMARY_DIMENSIONS
            for row in rows[dimension]
        ]

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
                message_code=row["code"], message_text=row["text"], nad=row["nad"],
                authentication_method=row["method"], psn=row["psn"]).set(row["events"]))
        for row in failure_context:
            writers.append(lambda row=row: metrics.ise_dataconnect_radius_failure_events.labels(
                failure_class=row["failure_class"], authorization_profile=row["profile"],
                location=row["location"]).set(row["events"]))
        for row in summary_dimensions:
            for status in ("passed", "failed"):
                writers.append(
                    lambda row=row, status=status:
                    metrics.ise_dataconnect_radius_authentication_summary_events.labels(
                        dimension=row["dimension"], value=row["value"], status=status,
                    ).set(row[status])
                )

        volume_summary = summaries["volume_summary"]
        writers.extend((
            lambda: metrics.ise_dataconnect_radius_authentication_events_total.set(
                integer(volume_summary.get("total_events"))),
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
        schema = getattr(dataconnect, "schema", None)
        if schema_has(
                schema, "RADIUS_AUTHENTICATION_SUMMARY", "calling_station_id"):
            writers.append(
                lambda: metrics.ise_dataconnect_radius_distinct_endpoints_total.labels(
                    source_view="radius_authentication_summary").set(
                    integer(volume_summary.get("distinct_endpoints"))))
        if schema_has(schema, "RADIUS_AUTHENTICATION_SUMMARY", "username"):
            writers.append(
                lambda: metrics.ise_dataconnect_radius_distinct_users_total.labels(
                    source_view="radius_authentication_summary").set(
                    integer(volume_summary.get("distinct_users"))))
        breakdowns = {
            "authentication": (len(auth), summaries["authentication"]),
            "latency": (len(latency), summaries["latency"]),
            "accounting": (len(accounting), summaries["accounting"]),
            "accounting_sessions": (len(accounting_sessions), summaries["accounting_sessions"]),
            "errors": (len(errors), summaries["errors"]),
            "failure_context": (len(failure_context), summaries["failure_context"]),
            **{
                breakdown: (len(rows[breakdown]), summaries[breakdown])
                for breakdown in _SUMMARY_DIMENSIONS
            },
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
    """Replace active sessions and the short-window delta from one bounded scan."""
    with observe("dataconnect_radius_active"):
        limit = group_limit(cfg)
        # This query runs repeatedly and reads the large accounting event view.
        # A caller-created config object must not expand it into the former
        # day-long scan; 60 minutes is both the documented reconstruction window
        # and a hard execution-boundary ceiling.
        stale_minutes = max(5, min(60, int(getattr(
            cfg, "dataconnect_active_session_stale_minutes", 60))))
        interval_seconds = max(60, int(getattr(
            cfg, "dataconnect_radius_active_interval", 300)))
        delta_minutes = max(1, min(stale_minutes, (interval_seconds + 59) // 60))
        values = dataconnect.query(_queries(
            limit, stale_minutes, delta_minutes=delta_minutes,
            schema=getattr(dataconnect, "schema", None)
        )["active_sessions"])
        active_values = [row for row in values
                         if row.get("breakdown", "active") == "active"]
        delta_values = [row for row in values if row.get("breakdown") == "delta"]
        summary = active_values[0] if active_values else {}
        active_sessions = [{
            "nad": label(row.get("device_name")),
            "psn": label(row.get("ise_node")),
            "sessions": integer(row.get("sessions")),
        } for row in active_values]
        session_deltas = [{
            "psn": label(row.get("ise_node")),
            "delta": signed_integer(row.get("session_delta")),
        } for row in delta_values]
        total_groups = integer(summary.get("total_groups"))
        writers = [
            lambda row=row: metrics.ise_dataconnect_radius_active_sessions.labels(
                nad=row["nad"], psn=row["psn"]).set(row["sessions"])
            for row in active_sessions
        ]
        writers.extend(
            lambda row=row: metrics.ise_dataconnect_radius_active_session_delta.labels(
                psn=row["psn"]).set(row["delta"])
            for row in session_deltas
        )
        writers.extend((
            lambda: metrics.ise_dataconnect_radius_active_sessions_total.set(
                integer(summary.get("total_sessions"))),
            lambda: metrics.ise_dataconnect_radius_active_session_stale_cutoff_seconds.set(
                stale_minutes * 60),
            lambda: metrics.ise_dataconnect_radius_active_session_delta_window_seconds.set(
                delta_minutes * 60),
            lambda: metrics.ise_dataconnect_radius_active_groups_returned.set(
                len(active_sessions)),
            lambda: metrics.ise_dataconnect_radius_active_groups_total.set(total_groups),
            lambda: metrics.ise_dataconnect_radius_active_groups_truncated.set(
                int(len(active_sessions) < total_groups)),
        ))
        replace_snapshot(_ACTIVE_METRICS, writers)


def collect_accounting_counters(dataconnect, cfg):
    """Tail new RADIUS accounting rows into monotonic counters (opt-in).

    Publishes cumulative ``event_type x psn`` counters so Prometheus computes the
    rate/increase over any window instead of the exporter re-summing a fixed
    server-side window each cycle. See ``dataconnect_tail`` for the shared tail
    engine and docs/incremental-tailing-plan.md for the semantics.
    """
    with observe("dataconnect_accounting_counters"):
        dataconnect_tail.tail_counters(
            dataconnect, cfg,
            dataset="dataconnect_accounting_counters",
            view="radius_accounting",
            label_columns=(
                ("event_type", "acct_status_type", "'unknown'"),
                ("psn", "ise_node", "'unknown'"),
            ),
            counter=metrics.ise_dataconnect_radius_accounting_tail_total)


def collect_authentication_counters(dataconnect, cfg):
    """Tail new RADIUS authentication rows into monotonic counters (opt-in, Slice 3).

    Publishes cumulative ``result x psn`` counters (passed/failed by PSN) so Prometheus
    computes the auth pass/fail rate over any window instead of the exporter re-summing
    a fixed server-side window each cycle. RADIUS_AUTHENTICATIONS carries the same global
    monotonic ``ID`` as RADIUS_ACCOUNTING; the numeric ``FAILED`` flag is mapped to a
    ``passed``/``failed`` string in SQL (so the label is stable and Oracle-type-safe).
    See ``dataconnect_tail`` and docs/incremental-tailing-plan.md.
    """
    with observe("dataconnect_authentication_counters"):
        dataconnect_tail.tail_counters(
            dataconnect, cfg,
            dataset="dataconnect_authentication_counters",
            view="radius_authentications",
            label_columns=(
                ("result", "failed", "'unknown'",
                 "CASE WHEN failed = 1 THEN 'failed'"
                 " WHEN failed = 0 THEN 'passed' ELSE 'unknown' END"),
                ("psn", "ise_node", "'unknown'"),
            ),
            counter=metrics.ise_dataconnect_radius_authentication_tail_total)
