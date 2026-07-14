import json
import io
import types
from datetime import datetime, timezone

import pytest

from ise_exporter import cli


class FakeClient:
    def __init__(self):
        self.cfg = types.SimpleNamespace(
            ise_host="pan.example.mil", ise_mnt_host="mnt.example.mil")
        self.calls = []

    def health_check(self):
        return {"pan": True, "mnt": False}

    def get_ers(self, path, params=None, get_all=False, api_name="x"):
        self.calls.append(("ers", path, params, get_all, api_name))
        if path == "/config/endpoint/id-1":
            return {"ERSEndPoint": {"id": "id-1", "mac": "AA:BB:CC:DD:EE:FF",
                                     "profileId": "windows"}}
        if path == "/config/endpoint" and params and str(params.get("filter", "")).startswith("mac.EQ"):
            return [{"id": "id-1", "name": "AA:BB:CC:DD:EE:FF"}]
        if path == "/config/endpoint":
            page, size = params["page"], params["size"]
            start = (page - 1) * size
            return [{"id": f"id-{i}", "name": f"endpoint-{i}"}
                    for i in range(start, min(start + size, 205))]
        if path == "/config/networkdevice":
            return [{"id": "nad-1", "name": "switch-1"}]
        if path == "/config/profilerprofile":
            return [{"id": "prof-1", "name": "Windows10-Workstation"}]
        if path == "/config/internaluser":
            return [{"id": "user-1", "name": "readonly"}]
        return {"path": path, "params": params}

    def get_pan_api(self, path, api_name="x", unwrap=True, params=None):
        self.calls.append(("openapi", path, unwrap, api_name, params))
        if path == "/endpoint":
            value = str((params or {}).get("filter", "")).rsplit(".", 1)[-1]
            if value in ("192.0.2.25", "client-25.example.test"):
                return [{"id": "id-1", "mac": "AA:BB:CC:DD:EE:FF",
                         "ipAddress": "192.0.2.25", "assetName": "client-25.example.test"}]
            return []
        return [{"name": "pan-1", "roles": ["PrimaryAdmin"]}]

    def get_mnt_xml(self, path, api_name="x"):
        self.calls.append(("mnt", path, api_name))
        if path == "/Session/ActiveList":
            return {"total": 2, "sessions": [
                {"calling_station_id": "AA:00", "server": "psn-1"},
                {"calling_station_id": "BB:00", "server": "psn-2"},
            ]}
        if path == "/Session/IPAddress/192.0.2.25":
            return {"total": 1, "sessions": [{
                "calling_station_id": "aa-bb-cc-dd-ee-ff",
                "framed_ip_address": "192.0.2.25", "server": "psn-1"}]}
        if path.startswith("/AuthStatus/"):
            return {"total": 1, "sessions": [{"passed": "false", "failure_reason": "22056"}]}
        if path.startswith("/Session/MACAddress/"):
            return {"total": 1, "sessions": [{
                "posture_status": "NotApplicable",
                "other_attr_string": (
                    "PostureAgentVersion=Posture Agent for Windows 5.1.18.314:!:"
                    "PostureAssessmentStatus=NotApplicable:!:PostureStatus=Compliant:!:"
                    "PostureReport=C2CP-WIN-FIREWALL\\;Passed\\;(details)"),
            }]}
        return {"total": 0, "sessions": []}


class FakeDataConnect:
    def __init__(self):
        self.calls = []
        self.closed = False

    def query(self, sql, parameters=None):
        self.calls.append((sql, parameters or {}))
        lowered = sql.lower()
        if "from endpoints_data" in lowered:
            return [{"id": "id-1", "endpoint_id": "epid:profile-1",
                     "mac_address": "AA:BB:CC:DD:EE:FF",
                     "endpoint_ip": "192.0.2.25", "hostname": "client-25.example.test"}]
        if "select distinct table_name" in lowered:
            return [{"value": "CUSTOM_REPORT_VIEW"}]
        if "from user_tab_columns" in lowered:
            return [{"column_name": name} for name in (
                "TIMESTAMP", "USERNAME", "CALLING_STATION_ID", "DEVICE_NAME",
                "ISE_NODE", "AUTHENTICATION_METHOD", "AUTHENTICATION_PROTOCOL",
                "POLICY_SET_NAME", "FAILED", "RESPONSE_TIME")]
        if "from radius_authentications" in lowered:
            return [{"username": "alice", "calling_station_id": "AA:BB:CC:DD:EE:FF",
                     "device_name": "nad-1", "failed": 0}]
        return []

    def close(self):
        self.closed = True


class CompletionDataConnect(FakeDataConnect):
    schemas = {
        "ENDPOINTS_DATA": (
            ("ID", "VARCHAR2"), ("MAC_ADDRESS", "VARCHAR2"),
            ("ENDPOINT_IP", "VARCHAR2"), ("HOSTNAME", "VARCHAR2"),
            ("ENDPOINT_POLICY", "VARCHAR2"), ("IDENTITY_GROUP_ID", "VARCHAR2"),
            ("UPDATE_TIME", "TIMESTAMP WITH TIME ZONE"),
        ),
        "RADIUS_AUTHENTICATIONS": (
            ("TIMESTAMP", "TIMESTAMP WITH TIME ZONE"),
            ("CALLING_STATION_ID", "VARCHAR2"), ("USERNAME", "VARCHAR2"),
            ("AUTHORIZATION_POLICY", "VARCHAR2"), ("POLICY_SET_NAME", "VARCHAR2"),
            ("LOCATION", "VARCHAR2"), ("DEVICE_NAME", "VARCHAR2"),
            ("ISE_NODE", "VARCHAR2"),
        ),
        "RADIUS_ACCOUNTING": (
            ("TIMESTAMP", "TIMESTAMP WITH TIME ZONE"),
            ("CALLING_STATION_ID", "VARCHAR2"), ("USERNAME", "VARCHAR2"),
            ("AUTHORIZATION_POLICY", "VARCHAR2"), ("DEVICE_NAME", "VARCHAR2"),
        ),
        "RADIUS_ERRORS_VIEW": (
            ("TIMESTAMP", "TIMESTAMP WITH TIME ZONE"),
            ("CALLING_STATION_ID", "VARCHAR2"), ("FAILURE_REASON", "VARCHAR2"),
            ("NETWORK_DEVICE_NAME", "VARCHAR2"),
        ),
        "POSTURE_ASSESSMENT_BY_ENDPOINT": (
            ("TIMESTAMP", "TIMESTAMP WITH TIME ZONE"),
            ("ENDPOINT_MAC_ADDRESS", "VARCHAR2"),
            ("POSTURE_STATUS", "VARCHAR2"), ("POSTURE_AGENT_VERSION", "VARCHAR2"),
        ),
    }

    def query(self, sql, parameters=None):
        self.calls.append((sql, parameters or {}))
        lowered = sql.lower()
        if "select distinct table_name" in lowered:
            return [{"value": "CUSTOM_REPORT_VIEW"}]
        if "from user_tab_columns" in lowered:
            table = (parameters or {}).get("table_name")
            return [{"column_name": column, "data_type": data_type}
                    for column, data_type in self.schemas.get(table, ())]
        if "from endpoints_data e" in lowered:
            return [{"id": "id-1", "mac_address": "AA:BB:CC:DD:EE:FF",
                     "endpoint_ip": "192.0.2.25", "hostname": "LAB-WIN-001",
                     "endpoint_policy": "Windows Workstations"}]
        if "select mac_address, endpoint_ip, hostname" in lowered:
            return [
                {"mac_address": "AA:BB:CC:DD:EE:FF", "endpoint_ip": "192.0.2.25",
                 "hostname": "client-25.example.test"},
                {"mac_address": "00:11:22:33:44:55", "endpoint_ip": "192.0.2.26",
                 "hostname": "client with space"},
            ]
        if "select distinct endpoint_policy" in lowered:
            return [{"value": "Windows Workstations"}, {"value": "Windows Servers"}]
        if "select distinct ise_node" in lowered:
            return [{"value": "laba-ise-001"}, {"value": "laba-ise-002"}]
        if "select distinct username" in lowered:
            return [{"value": "alice"}, {"value": "alex admin"}]
        if "select distinct device_name" in lowered:
            return [{"value": "access-switch-01"}, {"value": "access switch 02"}]
        return super().query(sql, parameters)


def test_schema_is_network_and_credential_free(capsys):
    assert cli.main(["schema", "secure-client", "--output", "json"]) == 0
    schema = json.loads(capsys.readouterr().out)
    assert schema["host_env"] == "ISE_MNT_HOST"
    assert schema["method"] == "GET"


def test_endpoints_are_bounded_and_paginated(capsys):
    client = FakeClient()

    assert cli.main(["endpoints", "--limit", "125", "-o", "json"], client=client) == 0

    rows = json.loads(capsys.readouterr().out)
    assert len(rows) == 125
    calls = [call for call in client.calls if call[0] == "ers"]
    assert [call[2]["page"] for call in calls] == [1, 2]
    assert [call[2]["size"] for call in calls] == [100, 25]


@pytest.mark.parametrize(("pattern", "expected"), (
    ("LAB-*", "name.STARTSW.LAB-"),
    ("*-WIN", "name.ENDSW.-WIN"),
    ("*LAPTOP*", "name.CONTAINS.LAPTOP"),
    ("LAB-001", "name.EQ.LAB-001"),
))
def test_endpoints_wildcards_are_server_side_ers_filters(pattern, expected, capsys):
    client = FakeClient()

    assert cli.main(["endpoints", pattern, "--limit", "5", "-o", "json"],
                    client=client) == 0

    assert client.calls[0][2]["filter"] == expected


def test_endpoints_rejects_complex_wildcard_without_enumerating():
    client = FakeClient()

    with pytest.raises(SystemExit):
        cli.main(["endpoints", "LAB-*-WIN"], client=client)

    assert client.calls == []


def test_secure_client_uses_mnt_session_path_and_exporter_parsers(capsys):
    client = FakeClient()

    assert cli.main([
        "secure-client", "AA:BB:CC:DD:EE:FF", "--include-all", "-o", "json"
    ], client=client) == 0

    result = json.loads(capsys.readouterr().out)
    assert client.calls == [(
        "mnt", "/Session/MACAddress/AA:BB:CC:DD:EE:FF", "cli_secure_client")]
    assert result["posture_status"] == "Compliant"  # explicit other-attribute verdict wins
    assert result["agent_version"] == "Windows 5.1.18.314"
    assert result["policies"] == [{"policy": "C2CP-WIN-FIREWALL", "result": "Passed"}]
    assert result["other_attributes"]["PostureStatus"] == "Compliant"


def test_endpoint_can_join_ers_detail_and_mnt_session(capsys):
    client = FakeClient()

    assert cli.main([
        "endpoint", "AA:BB:CC:DD:EE:FF", "--include-session", "-o", "json"
    ], client=client) == 0

    result = json.loads(capsys.readouterr().out)
    assert result["id"] == "id-1"
    assert result["mnt_sessions"][0]["posture_status"] == "NotApplicable"
    assert [call[0] for call in client.calls] == ["ers", "ers", "mnt"]


def test_generic_get_is_read_only_and_routes_by_family(capsys):
    client = FakeClient()

    assert cli.main([
        "get", "mnt", "/Session/ActiveList", "-o", "json"
    ], client=client) == 0

    assert json.loads(capsys.readouterr().out)["total"] == 2
    assert client.calls == [("mnt", "/Session/ActiveList", "cli_get_mnt")]


def test_generic_get_rejects_full_urls_and_parent_traversal():
    for path in ("https://other.example/api", "/Session/../config"):
        with pytest.raises(SystemExit):
            cli.main(["get", "mnt", path], client=FakeClient())


def test_csv_and_select_produce_pipeline_friendly_output(capsys):
    client = FakeClient()

    assert cli.main([
        "sessions", "--select", "calling_station_id,server", "-o", "csv"
    ], client=client) == 0

    assert capsys.readouterr().out.splitlines() == [
        "calling_station_id,server", "AA:00,psn-1", "BB:00,psn-2"]


def test_pretty_output_uses_property_list_for_single_nested_object():
    output = io.StringIO()

    cli.render({
        "mac": "AA:BB:CC:DD:EE:FF",
        "agent_version": "Windows 5.1.18.314",
        "policies": [{"policy": "C2CP-WIN-FIREWALL", "result": "Passed"}],
    }, stream=output)

    rendered = output.getvalue()
    assert "mac" in rendered
    assert "AA:BB:CC:DD:EE:FF" in rendered
    assert "agent_version" in rendered
    assert "Windows 5.1.18.314" in rendered
    assert "C2CP-WIN-FIREWALL" in rendered


def test_pretty_output_uses_table_for_multiple_objects():
    output = io.StringIO()

    cli.render([{"name": "pan-1", "role": "PAN"},
                {"name": "psn-1", "role": "PSN"}], stream=output)

    rendered = output.getvalue()
    assert "name" in rendered and "role" in rendered
    assert "pan-1" in rendered and "psn-1" in rendered


def test_json_output_serializes_dataconnect_datetime_values():
    output = io.StringIO()

    cli.render({"timestamp": datetime(2026, 7, 13, tzinfo=timezone.utc)},
               output="json", stream=output)

    assert json.loads(output.getvalue())["timestamp"] == "2026-07-13 00:00:00+00:00"


def test_empty_table_output_is_explicit():
    output = io.StringIO()

    cli.render([], stream=output)

    assert "No results." in output.getvalue()


@pytest.mark.parametrize("value", (
    "aa-bb-cc-dd-ee-ff", "aabb.ccdd.eeff", "aabbccddeeff",
    "AA BB CC DD EE FF", "AA:BB:CC:DD:EE:FF",
))
def test_endpoint_accepts_common_mac_formats(value, capsys):
    client = FakeClient()

    assert cli.main(["endpoint", value, "-o", "json"], client=client) == 0

    assert json.loads(capsys.readouterr().out)["id"] == "id-1"
    lookup = client.calls[0]
    assert lookup[2]["filter"] == "mac.EQ.AA:BB:CC:DD:EE:FF"


def test_ip_resolution_prefers_dataconnect_and_enriches_from_ers(capsys):
    client = FakeClient()
    dataconnect = FakeDataConnect()

    assert cli.main([
        "resolve", "192.0.2.25", "-o", "json"
    ], client=client, dataconnect=dataconnect) == 0

    result = json.loads(capsys.readouterr().out)
    assert result["kind"] == "ip"
    assert result["source"] == "dataconnect+ers"
    assert result["mac"] == "AA:BB:CC:DD:EE:FF"
    assert result["endpoint"]["id"] == "id-1"
    assert any("from endpoints_data" in sql.lower() for sql, _ in dataconnect.calls)
    assert not any(call[0] == "openapi" for call in client.calls)


def test_hostname_is_resolved_for_secure_client_via_dataconnect(capsys):
    client = FakeClient()
    dataconnect = FakeDataConnect()

    assert cli.main([
        "secure-client", "client-25.example.test", "-o", "json"
    ], client=client, dataconnect=dataconnect) == 0

    assert json.loads(capsys.readouterr().out)["mac"] == "AA:BB:CC:DD:EE:FF"
    assert client.calls[-1] == (
        "mnt", "/Session/MACAddress/AA:BB:CC:DD:EE:FF", "cli_secure_client")


def test_session_by_ip_uses_direct_mnt_ip_route(capsys):
    client = FakeClient()

    assert cli.main(["session", "192.0.2.25", "-o", "json"], client=client) == 0

    assert json.loads(capsys.readouterr().out)[0]["server"] == "psn-1"
    assert client.calls == [("mnt", "/Session/IPAddress/192.0.2.25", "cli_session_lookup")]


def test_dataconnect_report_is_bounded_and_filters_normalized_mac(capsys):
    client = FakeClient()
    dataconnect = FakeDataConnect()

    assert cli.main([
        "radius-auth", "--identifier", "aabb.ccdd.eeff", "--limit", "5", "-o", "json"
    ], client=client, dataconnect=dataconnect) == 0

    assert json.loads(capsys.readouterr().out)[0]["username"] == "alice"
    report_sql, parameters = dataconnect.calls[-1]
    assert "FETCH FIRST 5 ROWS ONLY" in report_sql
    assert "CALLING_STATION_ID = :endpoint_identifier" in report_sql
    assert parameters["endpoint_identifier"] == "AA:BB:CC:DD:EE:FF"


def test_dataconnect_schema_is_metadata_only_and_table_is_bound(capsys):
    dataconnect = FakeDataConnect()

    assert cli.main([
        "dataconnect-schema", "ENDPOINTS_DATA", "-o", "json"
    ], client=FakeClient(), dataconnect=dataconnect) == 0

    assert json.loads(capsys.readouterr().out)
    sql, parameters = dataconnect.calls[-1]
    assert "FROM user_tab_columns" in sql
    assert parameters == {"table_name": "ENDPOINTS_DATA"}
    assert "FROM endpoints_data" not in sql


def test_no_subcommand_enters_repl_and_question_mark_shows_commands():
    stdin = io.StringIO("?\nschema secure-client -o json\nquit\n")
    stdout = io.StringIO()

    assert cli.main([], stdin=stdin, stdout=stdout) == 0

    rendered = stdout.getvalue()
    assert "Cisco ISE read-only shell" in rendered
    assert "radius-auth" in rendered
    assert "secure-client" in rendered
    assert '"api": "MnT XML"' in rendered


def test_repl_recovers_from_parse_error_and_runs_next_command():
    stdin = io.StringIO("not-a-command\nschema health -o json\nexit\n")
    stdout = io.StringIO()

    assert cli.main([], stdin=stdin, stdout=stdout) == 0

    rendered = stdout.getvalue()
    assert "invalid choice" in rendered
    assert '"api": "ERS + MnT + optional Data Connect"' in rendered


def test_repl_completion_uses_parser_options_and_enum_choices():
    shell = cli.ISEShell(client=FakeClient(), dataconnect=CompletionDataConnect(),
                         stdin=io.StringIO(), stdout=io.StringIO())

    options = shell.completion_candidates("radius-auth --")
    assert {"--identifier", "--username", "--nad", "--status", "--limit",
            "--output", "--select"}.issubset(set(options))
    assert shell.completion_candidates(
        "tacacs-activity --event-type a") == [
            "accounting", "authentication", "authorization"]
    assert shell.completion_candidates("radius-auth --output js") == [
        "json", "jsonl"]
    assert shell.completion_candidates("posture --status N") == [
        "NonCompliant", "NotApplicable"]


def test_repl_completion_tracks_positionals_even_after_option_values():
    shell = cli.ISEShell(client=FakeClient(), dataconnect=CompletionDataConnect(),
                         stdin=io.StringIO(), stdout=io.StringIO())

    assert shell.completion_candidates(
        "endpoint --output json cli") == [
            "'client with space'", "client-25.example.test"]
    assert shell.completion_candidates("get openapi /lic") == [
        "/license/system/tier-state "]
    assert shell.completion_candidates("schema sec") == ["secure-client "]


def test_repl_completion_offers_bounded_quoted_live_values_and_caches_them():
    dataconnect = CompletionDataConnect()
    shell = cli.ISEShell(client=FakeClient(), dataconnect=dataconnect,
                         stdin=io.StringIO(), stdout=io.StringIO())

    assert shell.completion_candidates("endpoint client") == [
        "'client with space'", "client-25.example.test"]
    first_call_count = len(dataconnect.calls)
    assert shell.completion_candidates("endpoint client") == [
        "'client with space'", "client-25.example.test"]
    assert len(dataconnect.calls) == first_call_count
    assert shell.completion_candidates("endpoint-report --profile Win") == [
        "'Windows Workstations'", "'Windows Servers'"]
    assert shell.completion_candidates("certificates --node laba-") == [
        "laba-ise-001", "laba-ise-002"]
    endpoint_sql, parameters = dataconnect.calls[0]
    assert "FETCH FIRST 25 ROWS ONLY" in endpoint_sql
    assert parameters == {"prefix": "CLIENT%"}


def test_repl_completion_offers_schema_tables_and_comma_select_fields():
    shell = cli.ISEShell(client=FakeClient(), dataconnect=CompletionDataConnect(),
                         stdin=io.StringIO(), stdout=io.StringIO())

    tables = shell.completion_candidates("dataconnect-schema C")
    assert tables == ["CUSTOM_REPORT_VIEW "]
    assert shell.completion_candidates(
        "radius-auth --select timestamp,user") == ["timestamp,username"]


def test_endpoint_context_search_joins_schema_discovered_sources(capsys):
    dataconnect = CompletionDataConnect()

    assert cli.main([
        "endpoints", "name=LAB-*", "authorization-policy=Permit*",
        "location=Berlin-*", "endpoint-policy=Windows*", "--limit", "25", "-o", "json",
    ], client=FakeClient(), dataconnect=dataconnect) == 0

    result = json.loads(capsys.readouterr().out)
    assert result[0]["hostname"] == "LAB-WIN-001"
    assert result[0]["matched_filters"] == [
        "name=LAB-*", "authorization-policy=Permit*", "location=Berlin-*",
        "endpoint-policy=Windows*"]
    assert set(result[0]["matched_context"]) == {
        "name", "authorization-policy", "location", "endpoint-policy"}
    sql, parameters = next(
        (sql, parameters) for sql, parameters in dataconnect.calls
        if "FROM ENDPOINTS_DATA e" in sql)
    assert "RADIUS_AUTHENTICATIONS" in sql
    assert "AUTHORIZATION_POLICY" in sql
    assert "LOCATION" in sql
    assert "ENDPOINT_POLICY" in sql
    assert "MIN(match_value) AS match_value" in sql
    assert "MATCHED_CONTEXT_0" in sql
    assert "FETCH FIRST 25 ROWS ONLY" in sql
    assert set(parameters.values()) == {"LAB-%", "PERMIT%", "BERLIN-%", "WINDOWS%"}


def test_repeated_endpoint_field_values_are_or_and_distinct_fields_are_and(capsys):
    dataconnect = CompletionDataConnect()

    assert cli.main([
        "endpoints", "location=Berlin*", "location=London*", "posture-status=Compliant",
        "-o", "json",
    ], client=FakeClient(), dataconnect=dataconnect) == 0

    sql = next(sql for sql, _parameters in dataconnect.calls
               if "FROM ENDPOINTS_DATA e" in sql)
    assert "RADIUS_AUTHENTICATIONS" in sql
    assert "POSTURE_ASSESSMENT_BY_ENDPOINT" in sql
    assert " UNION " in sql
    assert "JOIN matched_0" in sql and "JOIN matched_1" in sql
    assert "EXISTS" not in sql and "REPLACE(" not in sql
    assert "FETCH FIRST 5000 ROWS ONLY" in sql


def test_endpoint_fields_catalog_includes_every_searchable_qualified_column(capsys):
    dataconnect = CompletionDataConnect()

    assert cli.main(["endpoint-fields", "*policy*", "-o", "json"],
                    dataconnect=dataconnect) == 0

    fields = {row["field"] for row in json.loads(capsys.readouterr().out)}
    assert {"authorization-policy", "endpoint-policy", "policy-set",
            "auth.authorization-policy", "endpoint.endpoint-policy"}.issubset(fields)


def test_endpoint_search_completion_offers_fields_and_live_context_values():
    shell = cli.ISEShell(client=FakeClient(), dataconnect=CompletionDataConnect(),
                         stdin=io.StringIO(), stdout=io.StringIO())

    assert "authorization-policy=" in shell.completion_candidates("endpoints auth")
    assert shell.completion_candidates("endpoints endpoint-policy=Win") == [
        "'endpoint-policy=Windows Servers'", "'endpoint-policy=Windows Workstations'"]
