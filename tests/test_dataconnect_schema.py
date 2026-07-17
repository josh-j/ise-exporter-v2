import pytest

from ise_exporter.collectors import (
    dataconnect_endpoints,
    dataconnect_performance,
    dataconnect_posture,
    dataconnect_radius,
    tacacs,
)
from ise_exporter.dataconnect_schema import (
    DATASET_REQUIRED_COLUMNS,
    DATASET_OPTIONAL_VIEWS,
    DATASET_VIEW_ALTERNATIVES,
    DATASET_VIEW_DEPENDENCIES,
    DataConnectSchemaError,
    MANDATORY_COLUMNS_BY_VIEW,
    VIEW_CONTRACTS,
    inspect_dataconnect_schema,
    optional_schema_gaps,
    schema_by_table,
    table_columns,
    validate_dataconnect_schema,
)


class DataConnect:
    def __init__(self, rows):
        self.rows = rows
        self.calls = []

    def query(self, sql, parameters=None):
        self.calls.append((sql, parameters))
        return self.rows


class CatalogDataConnect(DataConnect):
    def query(self, sql, parameters=None):
        raise AssertionError("schema lookup used reporting-query duty accounting")

    def query_catalog(self, sql, parameters=None):
        self.calls.append((sql, parameters))
        return self.rows


def _contract_rows(include_tacacs=True):
    rows = []
    for table, contract in VIEW_CONTRACTS.items():
        if not include_tacacs and contract.domain == "tacacs":
            continue
        for position, column in enumerate(
                sorted(contract.required | MANDATORY_COLUMNS_BY_VIEW[table]), 1):
            rows.append({
                "table_name": table,
                "column_id": position,
                "column_name": column,
                "data_type": "VARCHAR2",
            })
    return rows


def test_schema_by_table_normalizes_catalog_names():
    assert schema_by_table([{
        "table_name": "radius_accounting",
        "column_name": "acct_session_id",
        "data_type": "varchar2",
    }]) == {"RADIUS_ACCOUNTING": {"ACCT_SESSION_ID": "VARCHAR2"}}


def test_optional_schema_gaps_are_visible_without_becoming_dataset_failures():
    schema = schema_by_table(_contract_rows())

    gaps = optional_schema_gaps(schema)

    assert "AVG_TPS" in gaps["KEY_PERFORMANCE_METRICS"]
    assert "HOSTNAME" in gaps["ENDPOINTS_DATA"]


def test_all_query_builders_degrade_optional_columns_from_one_discovered_schema():
    rows = _contract_rows()
    schema, failures = inspect_dataconnect_schema(DataConnect(rows))

    assert not failures
    performance = dataconnect_performance._queries(10, schema=schema)
    endpoints = dataconnect_endpoints._queries(10, schema=schema)
    posture = dataconnect_posture._queries(10, schema=schema)
    radius = dataconnect_radius._queries(
        10, authentication_policy_column="'none'",
        accounting_policy_expression="'none'", schema=schema)
    tacacs_queries = tacacs._activity_queries(10, 0, schema=schema)

    assert "avg_tps" not in performance["kpi"].lower()
    assert "NULL AS hostname" in endpoints["inventory"]
    assert "NULL AS endpoint_mac_address" in posture["snapshot"]
    assert "'none' AS authentication_method" in radius["authentication"]
    assert "'unknown' AS status" in tacacs_queries["authentication"]


def test_validate_schema_accepts_complete_patch_11_contract():
    client = DataConnect(_contract_rows())
    schema = validate_dataconnect_schema(client)
    assert set(schema) == set(VIEW_CONTRACTS)
    assert "user_tab_columns" in client.calls[0][0].lower()


def test_validate_schema_prefers_bounded_catalog_query_path():
    client = CatalogDataConnect(_contract_rows())

    validate_dataconnect_schema(client)

    assert len(client.calls) == 1


def test_contract_requires_columns_used_unconditionally_by_latest_session_queries():
    assert {"ID", "TIMESTAMP", "ACCT_SESSION_ID", "ACCT_STATUS_TYPE"} <= \
        VIEW_CONTRACTS["RADIUS_ACCOUNTING"].required
    assert {"AUDIT_SESSION_ID", "SESSION_ID", "NAS_IP_ADDRESS"} <= \
        VIEW_CONTRACTS["RADIUS_ACCOUNTING"].optional
    assert {"ID", "TIMESTAMP"} <= \
        VIEW_CONTRACTS["POSTURE_ASSESSMENT_BY_ENDPOINT"].required
    assert {"SESSION_ID", "MESSAGE_CODE"} <= \
        VIEW_CONTRACTS["POSTURE_ASSESSMENT_BY_ENDPOINT"].optional


def test_contract_negotiates_optional_radius_authorization_policy():
    assert "AUTHORIZATION_POLICY" in VIEW_CONTRACTS["RADIUS_AUTHENTICATIONS"].optional
    assert "POLICY_SET_NAME" in VIEW_CONTRACTS["RADIUS_AUTHENTICATIONS"].optional
    assert "AUTHORIZATION_POLICY" in \
        VIEW_CONTRACTS["RADIUS_AUTHENTICATIONS_WEEK"].optional
    assert "AUTHORIZATION_POLICY" in VIEW_CONTRACTS["RADIUS_ACCOUNTING"].optional
    assert "AUTHORIZATION_POLICY" not in VIEW_CONTRACTS["RADIUS_ACCOUNTING"].required
    assert {"TIMESTAMP", "PASSED_COUNT", "FAILED_COUNT"} <= \
        VIEW_CONTRACTS["RADIUS_AUTHENTICATION_SUMMARY"].required
    assert {"USERNAME", "CALLING_STATION_ID"} <= \
        VIEW_CONTRACTS["RADIUS_AUTHENTICATION_SUMMARY"].optional
    assert "DEVICE_NAME" in VIEW_CONTRACTS["RADIUS_AUTHENTICATION_SUMMARY"].optional
    assert VIEW_CONTRACTS["RADIUS_AUTHENTICATION_SUMMARY"].time_column == "TIMESTAMP"


def test_contract_telemetry_tracks_only_collector_consumed_optional_columns():
    optional = {
        "RADIUS_AUTHENTICATIONS": {"TIMESTAMP_TIMEZONE"},
        "RADIUS_AUTHENTICATION_SUMMARY": {
            "IDENTITY_STORE", "IDENTITY_GROUP", "DEVICE_TYPE", "SECURITY_GROUP",
        },
        "ENDPOINTS_DATA": {"ENDPOINT_ID", "ID"},
        "TACACS_AUTHORIZATION_LAST_TWO_DAYS": {"COMMAND_FROM_DEVICE"},
        "TACACS_ACCOUNTING_LAST_TWO_DAYS": {"COMMAND_ARGS"},
        "KEY_PERFORMANCE_METRICS": {
            "RADIUS_REQUESTS_HR", "LOGGED_TO_MNT_HR", "NOISE_HR", "SUPPRESSION_HR",
            "AVG_LOAD", "MAX_LOAD", "AVG_LATENCY_PER_REQ", "AVG_TPS",
        },
        "SYSTEM_SUMMARY": {
            "CPU_UTILIZATION", "MEMORY_UTILIZATION", "DISKSPACE_ROOT",
            "DISKSPACE_BOOT", "DISKSPACE_OPT", "DISKSPACE_STOREDCONFIG",
            "DISKSPACE_TMP", "DISKSPACE_RUNTIME",
        },
        "AAA_DIAGNOSTICS_VIEW": {"MESSAGE_SEVERITY", "CATEGORY", "MESSAGE_CODE"},
        "SYSTEM_DIAGNOSTICS_VIEW": {"MESSAGE_SEVERITY", "CATEGORY", "MESSAGE_CODE"},
    }
    for view, columns in optional.items():
        assert columns <= VIEW_CONTRACTS[view].optional
        assert columns.isdisjoint(VIEW_CONTRACTS[view].required)


def test_contract_requires_columns_used_unconditionally_by_endpoint_queries():
    assert "MAC_ADDRESS" in VIEW_CONTRACTS["ENDPOINTS_DATA"].required
    assert {
        "ENDPOINT_IP", "HOSTNAME", "ENDPOINT_POLICY", "IDENTITY_GROUP_ID",
        "POSTURE_APPLICABLE", "CUSTOM_ATTRIBUTES", "PORTAL_USER", "MDM_GUID",
        "NATIVE_UDID", "UPDATE_TIME",
    } <= VIEW_CONTRACTS["ENDPOINTS_DATA"].optional


def test_tacacs_contracts_expose_epoch_freshness_boundaries():
    for name, contract in VIEW_CONTRACTS.items():
        if contract.domain == "tacacs":
            assert contract.time_column == "EPOCH_TIME", name


def test_validate_schema_reports_missing_views_and_columns():
    rows = _contract_rows()
    rows = [row for row in rows
            if row["table_name"] != "SYSTEM_SUMMARY"
            and not (row["table_name"] == "RADIUS_ACCOUNTING"
                     and row["column_name"] == "ACCT_SESSION_ID")]
    with pytest.raises(DataConnectSchemaError) as error:
        validate_dataconnect_schema(DataConnect(rows))
    assert "missing view SYSTEM_SUMMARY" in str(error.value)
    assert "RADIUS_ACCOUNTING missing columns: ACCT_SESSION_ID" in str(error.value)


def test_validate_schema_accepts_column_not_mandatory_for_any_dataset():
    rows = [row for row in _contract_rows()
            if not (row["table_name"] == "ENDPOINTS_DATA"
                    and row["column_name"] == "MAC_ADDRESS")]
    rows.append({
        "table_name": "ENDPOINTS_DATA",
        "column_id": 1,
        "column_name": "HOSTNAME",
        "data_type": "VARCHAR2",
    })

    schema = validate_dataconnect_schema(DataConnect(rows))

    assert "MAC_ADDRESS" not in schema["ENDPOINTS_DATA"]


def test_schema_inspection_contains_failures_to_dependent_datasets():
    rows = _contract_rows()
    rows = [row for row in rows
            if row["table_name"] != "SYSTEM_SUMMARY"
            and not (row["table_name"] == "RADIUS_ACCOUNTING"
                     and row["column_name"] == "ACCT_SESSION_ID")]

    schema, failures = inspect_dataconnect_schema(DataConnect(rows))

    assert "SYSTEM_SUMMARY" not in schema
    assert failures["dataconnect_performance"].reason == \
        "schema_missing_view_system_summary"
    assert "missing view SYSTEM_SUMMARY" in \
        failures["dataconnect_performance"].detail
    assert "dataconnect_radius" not in failures
    assert failures["dataconnect_radius_active"].reason == \
        "schema_radius_accounting_missing_acct_session_id"
    assert "dataconnect_posture" not in failures
    assert "dataconnect_endpoints" not in failures
    assert "dataconnect_freshness" not in failures


def test_radius_schema_accepts_week_view_when_base_view_is_unavailable():
    rows = [row for row in _contract_rows()
            if row["table_name"] != "RADIUS_AUTHENTICATIONS"]
    rows.append({
        "table_name": "RADIUS_AUTHENTICATIONS_WEEK",
        "column_id": 2,
        "column_name": "AUTHORIZATION_POLICY",
        "data_type": "VARCHAR2",
    })

    schema, failures = inspect_dataconnect_schema(DataConnect(rows))

    assert "RADIUS_AUTHENTICATIONS" not in schema
    assert "dataconnect_radius" not in failures


def test_radius_schema_fails_when_neither_authentication_view_is_compatible():
    rows = [row for row in _contract_rows()
            if row["table_name"] not in {
                "RADIUS_AUTHENTICATIONS", "RADIUS_AUTHENTICATIONS_WEEK"}]

    _schema, failures = inspect_dataconnect_schema(DataConnect(rows))

    failure = failures["dataconnect_radius"]
    assert failure.reason == "schema_dataconnect_radius_missing_compatible_view"
    assert "RADIUS_AUTHENTICATIONS or RADIUS_AUTHENTICATIONS_WEEK" in failure.detail


def test_missing_optional_endpoint_inventory_does_not_block_posture():
    rows = [row for row in _contract_rows()
            if row["table_name"] != "ENDPOINTS_DATA"]

    _schema, failures = inspect_dataconnect_schema(DataConnect(rows))

    assert "dataconnect_posture" not in failures
    assert failures["dataconnect_endpoints"].reason == \
        "schema_missing_view_endpoints_data"


def test_freshness_schema_fails_only_when_no_probe_view_is_usable():
    _schema, failures = inspect_dataconnect_schema(DataConnect([]))

    assert failures["dataconnect_freshness"].reason == \
        "schema_missing_all_freshness_views"


def test_timezone_only_reporting_view_is_usable_for_freshness():
    rows = [{
        "table_name": "RADIUS_ERRORS_VIEW",
        "column_name": "TIMESTAMP_TIMEZONE",
        "data_type": "TIMESTAMP WITH TIME ZONE",
    }]

    _schema, failures = inspect_dataconnect_schema(DataConnect(rows))

    assert "dataconnect_freshness" not in failures


def test_every_scheduled_dataconnect_dataset_has_explicit_view_dependencies():
    expected = {
        "dataconnect_radius", "dataconnect_radius_active",
        "dataconnect_performance", "dataconnect_posture",
        "dataconnect_endpoints", "dataconnect_nad_health", "tacacs_activity",
    }
    assert set(DATASET_VIEW_DEPENDENCIES) == expected
    assert set(DATASET_REQUIRED_COLUMNS) == expected
    assert set(DATASET_VIEW_ALTERNATIVES) == {"dataconnect_radius"}
    assert DATASET_OPTIONAL_VIEWS == {
        "dataconnect_posture": frozenset({"ENDPOINTS_DATA"}),
    }
    for dataset, views in DATASET_VIEW_DEPENDENCIES.items():
        assert set(DATASET_REQUIRED_COLUMNS[dataset]) == set(views), dataset


def test_dataset_dependencies_cover_every_reporting_view_named_by_collector_sql():
    query_sets = {
        "dataconnect_radius": dataconnect_radius._reporting_queries(10),
        "dataconnect_radius_active": {
            "active": dataconnect_radius._queries(10)["active_sessions"],
        },
        "dataconnect_performance": dataconnect_performance._queries(10),
        "dataconnect_posture": dataconnect_posture._queries(10),
        "dataconnect_endpoints": dataconnect_endpoints._queries(10),
        "tacacs_activity": tacacs._activity_queries(10, 0),
    }
    for dataset, statements in query_sets.items():
        sql = "\n".join(statements.values()).lower()
        referenced = {
            view for view in VIEW_CONTRACTS if view.lower() in sql
        }
        assert referenced <= DATASET_VIEW_DEPENDENCIES[dataset], dataset


def test_validate_schema_can_exclude_tacacs_contracts():
    schema = validate_dataconnect_schema(
        DataConnect(_contract_rows(include_tacacs=False)), include_tacacs=False)
    assert all(not name.startswith("TACACS_") for name in schema)


def test_table_columns_uses_bound_catalog_lookup():
    client = DataConnect([{"column_name": "user_name", "data_type": "varchar2"}])
    assert table_columns(client, "radius_authentications") == {"USER_NAME": "VARCHAR2"}
    assert client.calls[0][1] == {"table_name": "RADIUS_AUTHENTICATIONS"}
