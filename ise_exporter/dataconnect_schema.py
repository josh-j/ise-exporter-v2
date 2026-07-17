"""Cisco ISE Data Connect schema discovery and capability negotiation.

Collectors share one discovered view map. Dataset-specific core columns remain
fail-closed, while absent optional dimensions and values are omitted or replaced
with bounded stable labels by the owning collector.
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
    freshness_expected: bool = False
    freshness_probe: bool = True


@dataclass(frozen=True)
class DatasetSchemaFailure:
    """One bounded metric reason plus full journal detail for a blocked dataset."""

    reason: str
    detail: str


def _view(required, *, optional=(), time_column="", domain="",
          freshness_expected=False, freshness_probe=True):
    return ViewContract(
        frozenset(required), frozenset(optional), time_column, domain,
        freshness_expected, freshness_probe)


VIEW_CONTRACTS = {
    "RADIUS_AUTHENTICATIONS": _view({
        "TIMESTAMP",
    }, optional={"FAILED", "AUTHENTICATION_METHOD", "AUTHENTICATION_PROTOCOL",
                 "DEVICE_NAME", "ISE_NODE", "RESPONSE_TIME", "AUTHORIZATION_POLICY",
                 "POLICY_SET_NAME", "TIMESTAMP_TIMEZONE"},
       time_column="TIMESTAMP", domain="radius_auth"),
    # Performance-oriented seven-day view. It is an optional replacement for the
    # raw authentication scan when the documented AUTHORIZATION_POLICY dimension
    # is available, not an additional mandatory dataset dependency or freshness
    # probe.
    "RADIUS_AUTHENTICATIONS_WEEK": _view({
        "TIMESTAMP",
    }, optional={"FAILED", "AUTHENTICATION_METHOD", "AUTHENTICATION_PROTOCOL",
                 "DEVICE_NAME", "ISE_NODE", "RESPONSE_TIME", "AUTHORIZATION_POLICY",
                 "TIMESTAMP_TIMEZONE"},
       time_column="TIMESTAMP", domain="radius_auth", freshness_probe=False),
    "RADIUS_AUTHENTICATION_SUMMARY": _view({
        "TIMESTAMP", "PASSED_COUNT", "FAILED_COUNT",
    }, optional={"USERNAME", "CALLING_STATION_ID", "DEVICE_NAME", "LOCATION",
                 "AUTHORIZATION_PROFILES", "FAILURE_REASON",
                 "IDENTITY_STORE", "IDENTITY_GROUP", "DEVICE_TYPE", "SECURITY_GROUP"},
       time_column="TIMESTAMP", domain="radius_auth"),
    "RADIUS_ACCOUNTING": _view({
        "ID", "TIMESTAMP", "ACCT_SESSION_ID", "ACCT_STATUS_TYPE",
    }, optional={"DEVICE_NAME", "ISE_NODE", "ACCT_SESSION_TIME", "NAS_IP_ADDRESS",
                 "AUDIT_SESSION_ID", "SESSION_ID", "AUTHORIZATION_POLICY",
                 "TIMESTAMP_TIMEZONE"},
       time_column="TIMESTAMP", domain="radius_accounting"),
    "RADIUS_ERRORS_VIEW": _view({
        "TIMESTAMP",
    }, optional={"MESSAGE_CODE", "NETWORK_DEVICE_NAME", "AUTHENTICATION_METHOD",
                 "ISE_NODE", "TIMESTAMP_TIMEZONE"},
       time_column="TIMESTAMP", domain="radius_errors"),
    "ENDPOINTS_DATA": _view({
        "MAC_ADDRESS",
    }, optional={"ENDPOINT_IP", "HOSTNAME", "ENDPOINT_POLICY", "IDENTITY_GROUP_ID",
                 "POSTURE_APPLICABLE", "CUSTOM_ATTRIBUTES", "PORTAL_USER", "MDM_GUID",
                 "NATIVE_UDID", "UPDATE_TIME", "CREATE_TIME", "ENDPOINT_ID", "ID",
                 "PROFILE_SERVER"},
       domain="endpoints"),
    "PROFILED_ENDPOINTS_SUMMARY": _view({
        "TIMESTAMP", "ENDPOINT_ID",
    }, optional={"ENDPOINT_PROFILE", "SOURCE", "ENDPOINT_ACTION_NAME", "IDENTITY_GROUP"},
       time_column="TIMESTAMP", domain="endpoints"),
    "POSTURE_ASSESSMENT_BY_ENDPOINT": _view({
        "ID", "TIMESTAMP",
    }, optional={"SESSION_ID", "ENDPOINT_MAC_ADDRESS", "POSTURE_STATUS",
                 "ENDPOINT_OPERATING_SYSTEM", "POSTURE_AGENT_VERSION",
                 "POSTURE_POLICY_MATCHED", "ISE_NODE", "MESSAGE_CODE",
                 "TIMESTAMP_TIMEZONE"},
       time_column="TIMESTAMP", domain="posture"),
    "POSTURE_ASSESSMENT_BY_CONDITION": _view({
        "LOGGED_AT", "ENDPOINT_ID",
    }, optional={"POLICY", "POLICY_STATUS", "CONDITION_NAME", "CONDITION_STATUS",
                 "ENFORCEMENT_NAME", "ENFORCEMENT_TYPE", "ENFORCEMENT_STATUS",
                 "POSTURE_STATUS", "ISE_NODE"},
       time_column="LOGGED_AT", domain="posture"),
    "KEY_PERFORMANCE_METRICS": _view({
        "LOGGED_TIME", "ISE_NODE",
    }, optional={
        "RADIUS_REQUESTS_HR", "LOGGED_TO_MNT_HR", "NOISE_HR", "SUPPRESSION_HR",
        "AVG_LOAD", "MAX_LOAD", "AVG_LATENCY_PER_REQ", "AVG_TPS",
    }, time_column="LOGGED_TIME", domain="performance", freshness_expected=True),
    "SYSTEM_SUMMARY": _view({
        "TIMESTAMP", "ISE_NODE",
    }, optional={
        "CPU_UTILIZATION", "MEMORY_UTILIZATION", "DISKSPACE_ROOT",
        "DISKSPACE_BOOT", "DISKSPACE_OPT", "DISKSPACE_STOREDCONFIG", "DISKSPACE_TMP",
        "DISKSPACE_RUNTIME",
    }, time_column="TIMESTAMP", domain="performance", freshness_expected=True),
    "AAA_DIAGNOSTICS_VIEW": _view({
        "TIMESTAMP", "ISE_NODE",
    }, optional={"MESSAGE_SEVERITY", "CATEGORY", "MESSAGE_CODE", "TIMESTAMP_TIMEZONE"},
       time_column="TIMESTAMP", domain="performance"),
    "SYSTEM_DIAGNOSTICS_VIEW": _view({
        "TIMESTAMP", "ISE_NODE",
    }, optional={"MESSAGE_SEVERITY", "CATEGORY", "MESSAGE_CODE", "TIMESTAMP_TIMEZONE"},
       time_column="TIMESTAMP", domain="performance"),
    "TACACS_AUTHENTICATION_LAST_TWO_DAYS": _view({
        "EPOCH_TIME",
    }, optional={"USERNAME", "STATUS", "DEVICE_NAME", "AUTHENTICATION_POLICY",
                 "IDENTITY_STORE", "FAILURE_REASON"},
       time_column="EPOCH_TIME", domain="tacacs"),
    "TACACS_AUTHORIZATION_LAST_TWO_DAYS": _view({
        "EPOCH_TIME",
    }, optional={"USERNAME", "STATUS", "DEVICE_NAME", "AUTHORIZATION_POLICY",
                 "SHELL_PROFILE", "MATCHED_COMMAND_SET", "COMMAND_FROM_DEVICE"},
       time_column="EPOCH_TIME", domain="tacacs"),
    "TACACS_ACCOUNTING_LAST_TWO_DAYS": _view({
        "EPOCH_TIME",
    }, optional={"USERNAME", "STATUS", "DEVICE_NAME", "COMMAND", "COMMAND_ARGS"},
       time_column="EPOCH_TIME", domain="tacacs"),
}


DATASET_VIEW_DEPENDENCIES = {
    "dataconnect_radius": frozenset({
        "RADIUS_AUTHENTICATIONS", "RADIUS_AUTHENTICATIONS_WEEK",
        "RADIUS_AUTHENTICATION_SUMMARY",
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


DATASET_VIEW_ALTERNATIVES = {
    "dataconnect_radius": (
        frozenset({"RADIUS_AUTHENTICATIONS", "RADIUS_AUTHENTICATIONS_WEEK"}),
    ),
}


# Optional views enrich a dataset when present but must not block its core
# collector. They remain listed in DATASET_VIEW_DEPENDENCIES so SQL/view
# ownership stays explicit and schema telemetry can still expose them.
DATASET_OPTIONAL_VIEWS = {
    "dataconnect_posture": frozenset({"ENDPOINTS_DATA"}),
}


# Required columns are dataset-specific. A reporting view can feed multiple
# collectors with different needs, so one missing optional dimension must not
# disable every consumer of that view.
DATASET_REQUIRED_COLUMNS = {
    "dataconnect_radius": {
        "RADIUS_AUTHENTICATIONS": {"TIMESTAMP"},
        "RADIUS_AUTHENTICATIONS_WEEK": {"TIMESTAMP", "AUTHORIZATION_POLICY"},
        "RADIUS_AUTHENTICATION_SUMMARY": {"TIMESTAMP", "PASSED_COUNT", "FAILED_COUNT"},
        "RADIUS_ACCOUNTING": {"TIMESTAMP"},
        "RADIUS_ERRORS_VIEW": {"TIMESTAMP"},
    },
    "dataconnect_radius_active": {
        "RADIUS_ACCOUNTING": {
            "ID", "TIMESTAMP", "ACCT_SESSION_ID", "ACCT_STATUS_TYPE",
        },
    },
    "dataconnect_performance": {
        "KEY_PERFORMANCE_METRICS": {"LOGGED_TIME", "ISE_NODE"},
        "SYSTEM_SUMMARY": {"TIMESTAMP", "ISE_NODE"},
        "AAA_DIAGNOSTICS_VIEW": {"TIMESTAMP", "ISE_NODE"},
        "SYSTEM_DIAGNOSTICS_VIEW": {"TIMESTAMP", "ISE_NODE"},
    },
    "dataconnect_posture": {
        "POSTURE_ASSESSMENT_BY_ENDPOINT": {"ID", "TIMESTAMP"},
        "POSTURE_ASSESSMENT_BY_CONDITION": {"LOGGED_AT", "ENDPOINT_ID"},
        "ENDPOINTS_DATA": set(),
    },
    "dataconnect_endpoints": {
        "ENDPOINTS_DATA": set(),
        "PROFILED_ENDPOINTS_SUMMARY": {"TIMESTAMP", "ENDPOINT_ID"},
    },
    "dataconnect_nad_health": {
        "RADIUS_AUTHENTICATION_SUMMARY": {
            "TIMESTAMP", "PASSED_COUNT", "FAILED_COUNT", "DEVICE_NAME",
        },
    },
    "tacacs_activity": {
        "TACACS_AUTHENTICATION_LAST_TWO_DAYS": {"EPOCH_TIME"},
        "TACACS_AUTHORIZATION_LAST_TWO_DAYS": {"EPOCH_TIME"},
        "TACACS_ACCOUNTING_LAST_TWO_DAYS": {"EPOCH_TIME"},
    },
}


def mandatory_columns_by_view():
    """Return the union of columns required by any scheduled dataset."""
    required = {view: set() for view in VIEW_CONTRACTS}
    for dataset_requirements in DATASET_REQUIRED_COLUMNS.values():
        for view, columns in dataset_requirements.items():
            required[view].update(columns)
    return required


MANDATORY_COLUMNS_BY_VIEW = mandatory_columns_by_view()


RADIUS_AUTHENTICATION_DETAIL_COLUMNS = frozenset({
    "FAILED", "AUTHENTICATION_METHOD", "AUTHENTICATION_PROTOCOL",
    "DEVICE_NAME", "ISE_NODE", "RESPONSE_TIME",
})


def preferred_radius_authentication_view(
        schema, *, required_columns=(), preferred_columns=()):
    """Choose the compatible auth view without losing useful base-view columns."""
    base_name = "RADIUS_AUTHENTICATIONS"
    week_name = "RADIUS_AUTHENTICATIONS_WEEK"
    if schema is None:
        return base_name
    if not isinstance(schema, dict):
        raise TypeError("Data Connect schema must be a table mapping")

    required = {str(column).upper() for column in required_columns} | {"TIMESTAMP"}
    preferred = {str(column).upper() for column in preferred_columns}
    base = set(schema.get(base_name, {}))
    week = set(schema.get(week_name, {}))
    base_usable = bool(base) and required <= base
    week_usable = bool(week) and required <= week and "AUTHORIZATION_POLICY" in week
    if base_usable and not week_usable:
        return base_name
    if week_usable and not base_usable:
        return week_name
    if not base_usable and not week_usable:
        # Preserve the primary view in diagnostics; the caller will report the
        # exact missing column or unavailable-view failure.
        return base_name if base else week_name if week else base_name

    base_coverage = len(base & preferred)
    week_coverage = len(week & preferred)
    base_has_policy = bool(base & {"AUTHORIZATION_POLICY", "POLICY_SET_NAME"})
    if week_coverage >= base_coverage and not base_has_policy:
        return week_name
    return base_name


def metadata_rows(dataconnect, table_names=None, *, query=None):
    names = tuple(table_names or VIEW_CONTRACTS)
    unknown = set(names) - set(VIEW_CONTRACTS)
    if unknown:
        raise ValueError(f"unknown Data Connect contract views: {', '.join(sorted(unknown))}")
    literals = ", ".join(f"'{name}'" for name in names)
    execute = query or getattr(dataconnect, "query_catalog", None)
    if execute is None:
        execute = dataconnect.query
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


def optional_schema_gaps(schema):
    """Return known optional columns absent from otherwise available views."""
    return {
        table: tuple(sorted(
            (contract.required | contract.optional)
            - MANDATORY_COLUMNS_BY_VIEW[table]
            - set(schema.get(table, {}))))
        for table, contract in VIEW_CONTRACTS.items()
        if table in schema and (
            (contract.required | contract.optional)
            - MANDATORY_COLUMNS_BY_VIEW[table]
            - set(schema.get(table, {})))
    }


def table_columns(dataconnect, table, *, query=None):
    name = str(table or "").strip().upper()
    execute = query or getattr(dataconnect, "query_catalog", None)
    if execute is None:
        execute = dataconnect.query
    rows = execute("""
        SELECT column_name, data_type
        FROM user_tab_columns
        WHERE table_name = :table_name
        ORDER BY column_id
    """, {"table_name": name})
    if rows is None:
        return None
    return {str(row.get("column_name") or "").upper():
            str(row.get("data_type") or "").upper()
            for row in rows if row.get("column_name")}


def _contracts(include_tacacs):
    return {name: contract for name, contract in VIEW_CONTRACTS.items()
            if include_tacacs or contract.domain != "tacacs"}


def inspect_dataconnect_schema(dataconnect, *, include_tacacs=True):
    """Discover capabilities and contain incompatibility to dependent datasets."""
    contracts = _contracts(include_tacacs)
    schema = schema_by_table(metadata_rows(dataconnect, contracts))
    dependencies = dict(DATASET_VIEW_DEPENDENCIES)
    if not include_tacacs:
        dependencies.pop("tacacs_activity", None)

    dataset_failures = {}
    for dataset, views in dependencies.items():
        requirements = DATASET_REQUIRED_COLUMNS.get(dataset, {})
        failed = []
        alternatives = DATASET_VIEW_ALTERNATIVES.get(dataset, ())
        alternative_views = set().union(*alternatives) if alternatives else set()
        optional_views = DATASET_OPTIONAL_VIEWS.get(dataset, frozenset())
        for view in sorted(views):
            if view in alternative_views or view in optional_views:
                continue
            columns = set(schema.get(view, {}))
            if not columns:
                failed.append(f"missing view {view}")
                continue
            missing = sorted(set(requirements.get(view, ())) - columns)
            if missing:
                failed.append(f"{view} missing columns: {', '.join(missing)}")
        for choices in alternatives:
            compatible = False
            details = []
            for view in sorted(choices):
                columns = set(schema.get(view, {}))
                if not columns:
                    details.append(f"{view} missing")
                    continue
                missing = sorted(set(requirements.get(view, ())) - columns)
                if missing:
                    details.append(f"{view} missing columns: {', '.join(missing)}")
                    continue
                compatible = True
                break
            if not compatible:
                failed.append(
                    "missing compatible view " + " or ".join(sorted(choices))
                    + f" ({'; '.join(details)})")
        if not failed:
            continue
        issue = failed[0]
        first_view = issue.removeprefix("missing view ").split(" missing columns:", 1)[0]
        if issue.startswith("missing compatible view "):
            reason = f"schema_{dataset}_missing_compatible_view"
        elif issue.startswith("missing view "):
            reason = f"schema_missing_view_{first_view.lower()}"
        else:
            first_column = issue.split(":", 1)[1].split(",", 1)[0].strip().lower()
            reason = f"schema_{first_view.lower()}_missing_{first_column}"
        dataset_failures[dataset] = DatasetSchemaFailure(
            reason=reason[:96], detail="; ".join(failed))
    usable_freshness_views = [
        view for view, contract in contracts.items()
        if contract.time_column and contract.freshness_probe
        and (contract.time_column in schema.get(view, {})
             or (contract.time_column != "EPOCH_TIME"
                 and "TIMESTAMP_TIMEZONE" in schema.get(view, {})))
    ]
    if not usable_freshness_views:
        dataset_failures["dataconnect_freshness"] = DatasetSchemaFailure(
            reason="schema_missing_all_freshness_views",
            detail="no available reporting view exposes a supported freshness timestamp",
        )
    return schema, dataset_failures


def validate_dataconnect_schema(dataconnect, *, include_tacacs=True):
    """Validate the same dataset capabilities used by the scheduled runtime."""
    schema, failures = inspect_dataconnect_schema(
        dataconnect, include_tacacs=include_tacacs)
    if failures:
        raise DataConnectSchemaError(
            "Data Connect schema cannot support required collector datasets: "
            + "; ".join(
                f"{dataset}: {failure.detail}"
                for dataset, failure in sorted(failures.items())))
    return schema
