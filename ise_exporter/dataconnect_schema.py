"""Authoritative Cisco ISE 3.3 Patch 11 Data Connect schema contract.

Collectors and operator tooling depend on the same reporting views.  Keeping the
required columns here lets startup fail before the metrics endpoint advertises a
partially compatible reporting plane.
"""
from __future__ import annotations

from dataclasses import dataclass


class DataConnectSchemaError(RuntimeError):
    """The connected Data Connect account lacks a required view or column."""


@dataclass(frozen=True)
class ViewContract:
    required: frozenset[str]
    optional: frozenset[str] = frozenset()
    time_column: str = ""
    domain: str = ""


def _view(required, *, optional=(), time_column="", domain=""):
    return ViewContract(frozenset(required), frozenset(optional), time_column, domain)


VIEW_CONTRACTS = {
    "RADIUS_AUTHENTICATIONS": _view({
        "TIMESTAMP", "FAILED", "AUTHENTICATION_METHOD", "AUTHENTICATION_PROTOCOL",
        "DEVICE_NAME", "POLICY_SET_NAME", "ISE_NODE", "RESPONSE_TIME",
        "CALLING_STATION_ID", "USERNAME", "FAILURE_REASON", "LOCATION",
        "AUTHORIZATION_POLICY",
    }, optional={"FRAMED_IP_ADDRESS"},
       time_column="TIMESTAMP", domain="radius_auth"),
    "RADIUS_AUTHENTICATION_SUMMARY": _view({
        "TIMESTAMP", "ISE_NODE", "USERNAME", "CALLING_STATION_ID", "DEVICE_NAME",
        "LOCATION", "ACCESS_SERVICE", "AUTHORIZATION_PROFILES", "FAILURE_REASON",
        "TOTAL_RESPONSE_TIME", "MAX_RESPONSE_TIME", "PASSED_COUNT", "FAILED_COUNT",
    }, time_column="TIMESTAMP", domain="radius_auth"),
    "RADIUS_ACCOUNTING": _view({
        "ID", "TIMESTAMP", "ACCT_SESSION_ID", "ACCT_STATUS_TYPE", "DEVICE_NAME", "ISE_NODE",
        "ACCT_SESSION_TIME", "AUTHORIZATION_POLICY", "NAS_IP_ADDRESS", "AUDIT_SESSION_ID",
        "SESSION_ID",
    }, optional={"CALLING_STATION_ID", "USERNAME", "LOCATION"},
       time_column="TIMESTAMP", domain="radius_accounting"),
    "RADIUS_ERRORS_VIEW": _view({
        "TIMESTAMP", "MESSAGE_CODE", "NETWORK_DEVICE_NAME", "AUTHENTICATION_METHOD",
        "ISE_NODE",
    }, optional={"CALLING_STATION_ID", "USERNAME", "FAILURE_REASON"},
       time_column="TIMESTAMP", domain="radius_errors"),
    "ENDPOINTS_DATA": _view({
        "ID", "ENDPOINT_ID", "MAC_ADDRESS", "ENDPOINT_IP", "HOSTNAME",
        "ENDPOINT_POLICY", "IDENTITY_GROUP_ID", "POSTURE_APPLICABLE",
        "CUSTOM_ATTRIBUTES", "PORTAL_USER", "MDM_GUID", "NATIVE_UDID", "UPDATE_TIME",
    }, optional={"PROFILE_SERVER", "CREATE_TIME"}, domain="endpoints"),
    "PROFILED_ENDPOINTS_SUMMARY": _view({
        "TIMESTAMP", "ENDPOINT_ID", "ENDPOINT_PROFILE", "SOURCE", "ENDPOINT_ACTION_NAME",
        "IDENTITY_GROUP",
    }, time_column="TIMESTAMP", domain="endpoints"),
    "POSTURE_ASSESSMENT_BY_ENDPOINT": _view({
        "ID", "TIMESTAMP", "SESSION_ID", "ENDPOINT_MAC_ADDRESS", "POSTURE_STATUS",
        "ENDPOINT_OPERATING_SYSTEM", "POSTURE_AGENT_VERSION", "POSTURE_POLICY_MATCHED",
        "ISE_NODE", "MESSAGE_CODE",
    }, optional={"FAILURE_REASON", "POLICY_STATUS"},
       time_column="TIMESTAMP", domain="posture"),
    "POSTURE_ASSESSMENT_BY_CONDITION": _view({
        "LOGGED_AT", "ENDPOINT_ID", "POLICY", "POLICY_STATUS", "CONDITION_NAME",
        "CONDITION_STATUS", "ENFORCEMENT_NAME",
    }, optional={"FAILURE_REASON", "MESSAGE_CODE"},
       time_column="LOGGED_AT", domain="posture"),
    "KEY_PERFORMANCE_METRICS": _view({
        "LOGGED_TIME", "ISE_NODE", "RADIUS_REQUESTS_HR", "LOGGED_TO_MNT_HR", "NOISE_HR",
        "SUPPRESSION_HR", "AVG_LOAD", "MAX_LOAD", "AVG_LATENCY_PER_REQ", "AVG_TPS",
    }, time_column="LOGGED_TIME", domain="performance"),
    "SYSTEM_SUMMARY": _view({
        "TIMESTAMP", "ISE_NODE", "CPU_UTILIZATION", "MEMORY_UTILIZATION", "DISKSPACE_ROOT",
        "DISKSPACE_BOOT", "DISKSPACE_OPT", "DISKSPACE_STOREDCONFIG", "DISKSPACE_TMP",
        "DISKSPACE_RUNTIME",
    }, time_column="TIMESTAMP", domain="performance"),
    "AAA_DIAGNOSTICS_VIEW": _view({
        "TIMESTAMP", "ISE_NODE", "MESSAGE_SEVERITY", "CATEGORY", "MESSAGE_CODE",
    }, time_column="TIMESTAMP", domain="performance"),
    "SYSTEM_DIAGNOSTICS_VIEW": _view({
        "TIMESTAMP", "ISE_NODE", "MESSAGE_SEVERITY", "CATEGORY", "MESSAGE_CODE",
    }, time_column="TIMESTAMP", domain="performance"),
    "TACACS_AUTHENTICATION_LAST_TWO_DAYS": _view({
        "USERNAME", "STATUS", "DEVICE_NAME", "AUTHENTICATION_POLICY", "IDENTITY_STORE",
        "FAILURE_REASON", "EPOCH_TIME",
    }, time_column="EPOCH_TIME", domain="tacacs"),
    "TACACS_AUTHORIZATION_LAST_TWO_DAYS": _view({
        "USERNAME", "STATUS", "DEVICE_NAME", "AUTHORIZATION_POLICY", "SHELL_PROFILE",
        "MATCHED_COMMAND_SET", "COMMAND_FROM_DEVICE", "EPOCH_TIME",
    }, time_column="EPOCH_TIME", domain="tacacs"),
    "TACACS_ACCOUNTING_LAST_TWO_DAYS": _view({
        "USERNAME", "STATUS", "DEVICE_NAME", "COMMAND", "COMMAND_ARGS", "EPOCH_TIME",
    }, time_column="EPOCH_TIME", domain="tacacs"),
}


def metadata_rows(dataconnect, table_names=None, *, query=None):
    names = tuple(table_names or VIEW_CONTRACTS)
    unknown = set(names) - set(VIEW_CONTRACTS)
    if unknown:
        raise ValueError(f"unknown Data Connect contract views: {', '.join(sorted(unknown))}")
    literals = ", ".join(f"'{name}'" for name in names)
    execute = query or dataconnect.query
    return execute(f"""
        SELECT table_name, column_id, column_name, data_type, data_length, nullable
        FROM user_tab_columns
        WHERE table_name IN ({literals})
        ORDER BY table_name, column_id
    """)


def schema_by_table(rows):
    schema = {}
    for row in rows:
        table = str(row.get("table_name") or "").upper()
        column = str(row.get("column_name") or "").upper()
        if table and column:
            schema.setdefault(table, {})[column] = str(row.get("data_type") or "").upper()
    return schema


def table_columns(dataconnect, table):
    name = str(table or "").strip().upper()
    rows = dataconnect.query("""
        SELECT column_name, data_type
        FROM user_tab_columns
        WHERE table_name = :table_name
        ORDER BY column_id
    """, {"table_name": name})
    return {str(row.get("column_name") or "").upper():
            str(row.get("data_type") or "").upper()
            for row in rows if row.get("column_name")}


def validate_dataconnect_schema(dataconnect, *, include_tacacs=True):
    contracts = {name: contract for name, contract in VIEW_CONTRACTS.items()
                 if include_tacacs or contract.domain != "tacacs"}
    schema = schema_by_table(metadata_rows(dataconnect, contracts))
    failures = []
    for table, contract in contracts.items():
        columns = set(schema.get(table, {}))
        if not columns:
            failures.append(f"missing view {table}")
            continue
        missing = sorted(contract.required - columns)
        if missing:
            failures.append(f"{table} missing columns: {', '.join(missing)}")
    if failures:
        raise DataConnectSchemaError(
            "ISE 3.3 Patch 11 Data Connect schema is incompatible: " + "; ".join(failures))
    return schema
