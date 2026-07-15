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


@dataclass(frozen=True)
class DatasetSchemaFailure:
    """One bounded metric reason plus full journal detail for a blocked dataset."""

    reason: str
    detail: str


def _view(required, *, optional=(), time_column="", domain=""):
    return ViewContract(frozenset(required), frozenset(optional), time_column, domain)


VIEW_CONTRACTS = {
    "RADIUS_AUTHENTICATIONS": _view({
        "TIMESTAMP", "FAILED", "AUTHENTICATION_METHOD", "AUTHENTICATION_PROTOCOL",
        "DEVICE_NAME", "ISE_NODE", "RESPONSE_TIME",
    }, optional={"AUTHORIZATION_POLICY", "CALLING_STATION_ID", "FAILURE_REASON",
                 "FRAMED_IP_ADDRESS", "LOCATION", "POLICY_SET_NAME", "USERNAME"},
       time_column="TIMESTAMP", domain="radius_auth"),
    "RADIUS_AUTHENTICATION_SUMMARY": _view({
        "TIMESTAMP", "USERNAME", "CALLING_STATION_ID", "DEVICE_NAME", "LOCATION",
        "AUTHORIZATION_PROFILES", "FAILURE_REASON", "PASSED_COUNT", "FAILED_COUNT",
    }, optional={"ACCESS_SERVICE", "ISE_NODE", "MAX_RESPONSE_TIME", "TOTAL_RESPONSE_TIME"},
       time_column="TIMESTAMP", domain="radius_auth"),
    "RADIUS_ACCOUNTING": _view({
        "ID", "TIMESTAMP", "ACCT_SESSION_ID", "ACCT_STATUS_TYPE", "DEVICE_NAME", "ISE_NODE",
        "ACCT_SESSION_TIME", "NAS_IP_ADDRESS", "AUDIT_SESSION_ID",
        "SESSION_ID",
    }, optional={"AUTHORIZATION_POLICY", "CALLING_STATION_ID", "USERNAME", "LOCATION"},
       time_column="TIMESTAMP", domain="radius_accounting"),
    "RADIUS_ERRORS_VIEW": _view({
        "TIMESTAMP", "MESSAGE_CODE", "NETWORK_DEVICE_NAME", "AUTHENTICATION_METHOD",
        "ISE_NODE",
    }, optional={"CALLING_STATION_ID", "USERNAME", "FAILURE_REASON"},
       time_column="TIMESTAMP", domain="radius_errors"),
    "ENDPOINTS_DATA": _view({
        "MAC_ADDRESS", "ENDPOINT_IP", "HOSTNAME", "ENDPOINT_POLICY",
        "IDENTITY_GROUP_ID", "POSTURE_APPLICABLE",
        "CUSTOM_ATTRIBUTES", "PORTAL_USER", "MDM_GUID", "NATIVE_UDID", "UPDATE_TIME",
    }, optional={"CREATE_TIME", "ENDPOINT_ID", "ID", "PROFILE_SERVER"},
       domain="endpoints"),
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
        "MATCHED_COMMAND_SET", "EPOCH_TIME",
    }, optional={"COMMAND_FROM_DEVICE"}, time_column="EPOCH_TIME", domain="tacacs"),
    "TACACS_ACCOUNTING_LAST_TWO_DAYS": _view({
        "USERNAME", "STATUS", "DEVICE_NAME", "COMMAND", "EPOCH_TIME",
    }, optional={"COMMAND_ARGS"}, time_column="EPOCH_TIME", domain="tacacs"),
}


DATASET_VIEW_DEPENDENCIES = {
    "dataconnect_radius": frozenset({
        "RADIUS_AUTHENTICATIONS", "RADIUS_AUTHENTICATION_SUMMARY",
        "RADIUS_ACCOUNTING", "RADIUS_ERRORS_VIEW",
    }),
    "dataconnect_radius_active": frozenset({"RADIUS_ACCOUNTING"}),
    "dataconnect_performance": frozenset({
        "KEY_PERFORMANCE_METRICS", "SYSTEM_SUMMARY",
        "AAA_DIAGNOSTICS_VIEW", "SYSTEM_DIAGNOSTICS_VIEW",
    }),
    "dataconnect_posture": frozenset({
        "POSTURE_ASSESSMENT_BY_ENDPOINT", "POSTURE_ASSESSMENT_BY_CONDITION",
        "ENDPOINTS_DATA",
    }),
    "dataconnect_endpoints": frozenset({
        "ENDPOINTS_DATA", "PROFILED_ENDPOINTS_SUMMARY",
    }),
    "dataconnect_nad_health": frozenset({"RADIUS_AUTHENTICATION_SUMMARY"}),
    "tacacs_activity": frozenset({
        "TACACS_AUTHENTICATION_LAST_TWO_DAYS",
        "TACACS_AUTHORIZATION_LAST_TWO_DAYS",
        "TACACS_ACCOUNTING_LAST_TWO_DAYS",
    }),
}


def metadata_rows(dataconnect, table_names=None, *, query=None):
    names = tuple(table_names or VIEW_CONTRACTS)
    unknown = set(names) - set(VIEW_CONTRACTS)
    if unknown:
        raise ValueError(f"unknown Data Connect contract views: {', '.join(sorted(unknown))}")
    literals = ", ".join(f"'{name}'" for name in names)
    execute = query or getattr(dataconnect, "query_catalog", dataconnect.query)
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
    execute = getattr(dataconnect, "query_catalog", dataconnect.query)
    rows = execute("""
        SELECT column_name, data_type
        FROM user_tab_columns
        WHERE table_name = :table_name
        ORDER BY column_id
    """, {"table_name": name})
    return {str(row.get("column_name") or "").upper():
            str(row.get("data_type") or "").upper()
            for row in rows if row.get("column_name")}


def _contracts(include_tacacs):
    return {name: contract for name, contract in VIEW_CONTRACTS.items()
            if include_tacacs or contract.domain != "tacacs"}


def _view_failures(schema, contracts):
    failures = {}
    for table, contract in contracts.items():
        columns = set(schema.get(table, {}))
        if not columns:
            failures[table] = f"missing view {table}"
            continue
        missing = sorted(contract.required - columns)
        if missing:
            failures[table] = f"{table} missing columns: {', '.join(missing)}"
    return failures


def inspect_dataconnect_schema(dataconnect, *, include_tacacs=True):
    """Discover capabilities and contain incompatibility to dependent datasets."""
    contracts = _contracts(include_tacacs)
    schema = schema_by_table(metadata_rows(dataconnect, contracts))
    view_failures = _view_failures(schema, contracts)
    dependencies = dict(DATASET_VIEW_DEPENDENCIES)
    dependencies["dataconnect_freshness"] = frozenset(
        name for name, contract in contracts.items() if contract.time_column)
    if not include_tacacs:
        dependencies.pop("tacacs_activity", None)

    dataset_failures = {}
    for dataset, views in dependencies.items():
        failed = [view_failures[view] for view in sorted(views)
                  if view in view_failures]
        if not failed:
            continue
        first_view = next(view for view in sorted(views) if view in view_failures)
        issue = view_failures[first_view]
        if issue.startswith("missing view "):
            reason = f"schema_missing_view_{first_view.lower()}"
        else:
            first_column = issue.split(":", 1)[1].split(",", 1)[0].strip().lower()
            reason = f"schema_{first_view.lower()}_missing_{first_column}"
        dataset_failures[dataset] = DatasetSchemaFailure(
            reason=reason[:96], detail="; ".join(failed))
    return schema, dataset_failures


def validate_dataconnect_schema(dataconnect, *, include_tacacs=True):
    contracts = _contracts(include_tacacs)
    schema = schema_by_table(metadata_rows(dataconnect, contracts))
    failures = _view_failures(schema, contracts)
    if failures:
        raise DataConnectSchemaError(
            "ISE 3.3 Patch 11 Data Connect schema is incompatible: "
            + "; ".join(failures.values()))
    return schema
