import pytest

from ise_exporter.dataconnect_schema import (
    DataConnectSchemaError,
    VIEW_CONTRACTS,
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
        for position, column in enumerate(sorted(contract.required), 1):
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
    assert {"ID", "AUDIT_SESSION_ID", "SESSION_ID", "NAS_IP_ADDRESS"} <= \
        VIEW_CONTRACTS["RADIUS_ACCOUNTING"].required
    assert {"ID", "SESSION_ID", "MESSAGE_CODE"} <= \
        VIEW_CONTRACTS["POSTURE_ASSESSMENT_BY_ENDPOINT"].required


def test_contract_requires_patch11_radius_summary_and_authorization_policy():
    assert "AUTHORIZATION_POLICY" in VIEW_CONTRACTS["RADIUS_AUTHENTICATIONS"].required
    assert {
        "TIMESTAMP", "USERNAME", "CALLING_STATION_ID", "PASSED_COUNT", "FAILED_COUNT",
    } <= VIEW_CONTRACTS["RADIUS_AUTHENTICATION_SUMMARY"].required
    assert VIEW_CONTRACTS["RADIUS_AUTHENTICATION_SUMMARY"].time_column == "TIMESTAMP"


def test_contract_requires_columns_used_unconditionally_by_endpoint_queries():
    assert {
        "ENDPOINT_ID", "ENDPOINT_IP", "HOSTNAME", "ENDPOINT_POLICY", "IDENTITY_GROUP_ID",
        "POSTURE_APPLICABLE", "CUSTOM_ATTRIBUTES", "PORTAL_USER", "MDM_GUID",
        "NATIVE_UDID", "UPDATE_TIME",
    } <= VIEW_CONTRACTS["ENDPOINTS_DATA"].required


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


def test_validate_schema_can_exclude_tacacs_contracts():
    schema = validate_dataconnect_schema(
        DataConnect(_contract_rows(include_tacacs=False)), include_tacacs=False)
    assert all(not name.startswith("TACACS_") for name in schema)


def test_table_columns_uses_bound_catalog_lookup():
    client = DataConnect([{"column_name": "user_name", "data_type": "varchar2"}])
    assert table_columns(client, "radius_authentications") == {"USER_NAME": "VARCHAR2"}
    assert client.calls[0][1] == {"table_name": "RADIUS_AUTHENTICATIONS"}
