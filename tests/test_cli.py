import json
import io
import types
from datetime import datetime, timezone

import pytest

from ise_exporter import cli
from ise_exporter.exporter_data import ExporterSample, ExporterSnapshot


def test_cli_version_reports_revision_and_exact_ise_target(monkeypatch, capsys):
    monkeypatch.setenv("ISE_EXPORTER_BUILD_REVISION", "abc1234")

    with pytest.raises(SystemExit) as exited:
        cli.main(["--version"])

    assert exited.value.code == 0
    assert capsys.readouterr().out == (
        "ise-cli 2.0.0 (revision abc1234; Cisco ISE 3.3.0.430 Patch 11)\n")


def test_machine_completion_protocol_returns_json_without_entering_repl(monkeypatch, capsys):
    monkeypatch.setattr(
        cli.ISEShell, "_enable_history",
        lambda _self: pytest.fail("machine completion must not initialize history"))

    assert cli.main(["--complete", "radius-auth --st", "--cursor", "16"]) == 0

    assert json.loads(capsys.readouterr().out) == ["--status "]


def test_explicit_cli_config_uses_toml(monkeypatch, tmp_path):
    explicit = tmp_path / "production.toml"
    explicit.write_text(
        '[ise]\n'
        'host = "production-pan.example"\n'
        'user = "production-reader"\n'
        'password = "left=middle=right"\n')
    monkeypatch.delenv("ISE_PASS", raising=False)

    cfg = cli._load_config(explicit)

    assert cfg.ise_host == "production-pan.example"
    assert cfg.ise_user == "production-reader"
    assert cfg.ise_pass == "left=middle=right"


class FakeClient:
    def __init__(self):
        self.cfg = types.SimpleNamespace(
            ise_host="pan.example.com", ise_mnt_host="mnt.example.com")
        self.calls = []

    def health_check(self):
        return {"pan": True, "mnt": False}

    def check_api(self, family):
        self.calls.append(("check", family))
        return {
            "service": family, "healthy": True, "status": "ok",
            "reachable": True, "authenticated": True,
        }

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

    def get_pan_api_all(self, path, api_name="x", params=None, **kwargs):
        self.calls.append(("openapi_all", path, api_name, params, kwargs))
        return []

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
            if (parameters or {}).get("table_name") == "ENDPOINTS_DATA":
                return [{"column_name": name, "data_type": "VARCHAR2"}
                        for name in (
                            "ID", "ENDPOINT_ID", "MAC_ADDRESS", "ENDPOINT_IP",
                            "HOSTNAME", "ENDPOINT_POLICY", "IDENTITY_GROUP_ID",
                            "UPDATE_TIME")]
            return [{"column_name": name,
                     "data_type": "TIMESTAMP" if name == "TIMESTAMP" else "VARCHAR2"}
                    for name in (
                "TIMESTAMP", "USERNAME", "CALLING_STATION_ID", "DEVICE_NAME",
                "ISE_NODE", "AUTHENTICATION_METHOD", "AUTHENTICATION_PROTOCOL",
                "POLICY_SET_NAME", "FAILED", "RESPONSE_TIME")]
        if "from radius_authentications" in lowered:
            return [{"username": "alice", "calling_station_id": "AA:BB:CC:DD:EE:FF",
                     "device_name": "nad-1", "failed": 0}]
        return []

    def close(self):
        self.closed = True


def _exporter_snapshot():
    return ExporterSnapshot(
        "http://127.0.0.1:9618/metrics", 2000.0, (
            ExporterSample("ise_up", {}, 1),
            ExporterSample("ise_network_devices_total", {}, 17),
            ExporterSample("ise_dataset_up", {"dataset": "dataconnect_radius", "source": "dataconnect"}, 1),
            ExporterSample("ise_dataset_fresh", {"dataset": "dataconnect_radius", "source": "dataconnect"}, 1),
            ExporterSample("ise_dataset_last_success_timestamp", {"dataset": "dataconnect_radius", "source": "dataconnect"}, 1970),
            ExporterSample("ise_consecutive_failures", {"collector": "dataconnect_radius"}, 0),
            ExporterSample("ise_dataconnect_psn_load_percent", {"node": "ise01", "stat": "avg"}, 42),
            ExporterSample("ise_nad_authentication_events", {"nad": "switch01", "status": "passed"}, 81),
            ExporterSample("ise_node_service_enabled", {"node": "ise01", "service": "pxGrid"}, 1),
        ))


def test_overview_and_collector_status_reuse_exporter_snapshot(capsys):
    snapshot = _exporter_snapshot()
    assert cli.main(["overview", "-o", "json"], exporter_snapshot=snapshot) == 0
    overview = json.loads(capsys.readouterr().out)
    assert {row["name"]: row["value"] for row in overview if row["section"] == "overview"} == {
        "ise_available": 1.0, "network_devices": 17.0}

    assert cli.main([
        "collector-status", "*radius*", "-o", "json"
    ], exporter_snapshot=snapshot) == 0
    status = json.loads(capsys.readouterr().out)
    assert status == [{
        "age_seconds": 30.0, "consecutive_failures": 0,
        "data_source": "exporter_cache", "dataset": "dataconnect_radius",
        "failure_detail": "", "failure_reason": "", "fresh": True,
        "last_success_timestamp": 1970.0, "source": "dataconnect", "up": True,
    }]


def test_psn_and_nad_summaries_use_cached_metrics_without_live_calls(capsys):
    snapshot = _exporter_snapshot()
    assert cli.main(["psn-summary", "ise01", "-o", "json"],
                    exporter_snapshot=snapshot) == 0
    assert json.loads(capsys.readouterr().out)[0]["metric"] == \
        "ise_dataconnect_psn_load_percent"
    assert cli.main(["nad-summary", "switch01", "-o", "json"],
                    exporter_snapshot=snapshot) == 0
    assert json.loads(capsys.readouterr().out)[0]["value"] == 81.0


def test_endpoint_and_auth_workflows_are_bounded_and_source_labeled(capsys):
    client = FakeClient()
    assert cli.main([
        "endpoint-summary", "AA:BB:CC:DD:EE:FF", "-o", "json"
    ], client=client) == 0
    rows = json.loads(capsys.readouterr().out)
    assert [row["section"] for row in rows] == ["resolution", "session"]
    assert rows[0]["source"] == "live_ers"

    assert cli.main([
        "troubleshoot-auth", "AA:BB:CC:DD:EE:FF", "--limit", "5", "-o", "json"
    ], client=client) == 0
    rows = json.loads(capsys.readouterr().out)
    assert rows[-1]["section"] == "authentication"
    assert rows[-1]["source"] == "live_mnt"


def test_endpoint_and_auth_workflows_keep_partial_results_when_mnt_fails(capsys):
    class UnavailableMntClient(FakeClient):
        def get_mnt_xml(self, path, api_name="x"):
            self.calls.append(("mnt", path, api_name))
            return None

    client = UnavailableMntClient()
    assert cli.main([
        "endpoint-summary", "AA:BB:CC:DD:EE:FF", "-o", "json"
    ], client=client) == 0
    rows = json.loads(capsys.readouterr().out)
    assert [row["section"] for row in rows] == ["resolution", "session"]
    assert rows[1] == {
        "detail": (
            "MnT returned no response for "
            "/Session/MACAddress/AA:BB:CC:DD:EE:FF"),
        "section": "session",
        "source": "live_mnt",
        "status": "unavailable",
    }

    assert cli.main([
        "troubleshoot-auth", "AA:BB:CC:DD:EE:FF", "--limit", "5",
        "-o", "json"
    ], client=client) == 0
    rows = json.loads(capsys.readouterr().out)
    assert [row["section"] for row in rows] == [
        "resolution", "session", "authentication"]
    assert rows[-1]["status"] == "unavailable"
    assert rows[-1]["source"] == "live_mnt"


def test_endpoint_and_auth_workflows_report_empty_mnt_sections(capsys):
    class EmptyMntClient(FakeClient):
        def get_mnt_xml(self, path, api_name="x"):
            self.calls.append(("mnt", path, api_name))
            return {"total": 0, "sessions": []}

    client = EmptyMntClient()
    assert cli.main([
        "endpoint-summary", "AA:BB:CC:DD:EE:FF", "-o", "json"
    ], client=client) == 0
    rows = json.loads(capsys.readouterr().out)
    assert rows[-1] == {
        "detail": "no active MnT session found",
        "section": "session",
        "source": "live_mnt",
        "status": "no_results",
    }

    assert cli.main([
        "troubleshoot-auth", "AA:BB:CC:DD:EE:FF", "--limit", "5",
        "-o", "json"
    ], client=client) == 0
    rows = json.loads(capsys.readouterr().out)
    assert rows[-1] == {
        "detail": "no MnT authentication records found in the requested window",
        "section": "authentication",
        "source": "live_mnt",
        "status": "no_results",
    }


def test_pxgrid_status_is_explicit_about_removed_collector(capsys):
    assert cli.main(["pxgrid-status", "-o", "json"],
                    exporter_snapshot=_exporter_snapshot()) == 0
    rows = json.loads(capsys.readouterr().out)
    row = rows[0]
    assert row["status"] == "not_collected"
    assert row["source"] == "architecture"
    assert rows[1]["metric"] == "ise_node_service_enabled"
    assert rows[1]["service"] == "pxGrid"


def test_nad_summary_falls_back_to_one_live_ers_query_when_cache_is_empty(capsys):
    empty = ExporterSnapshot("http://127.0.0.1:9618/metrics", 2000, ())
    client = FakeClient()
    assert cli.main(["nad-summary", "switch-1", "-o", "json"],
                    client=client, exporter_snapshot=empty) == 0
    rows = json.loads(capsys.readouterr().out)
    assert rows == [{
        "id": "nad-1", "name": "switch-1", "section": "inventory",
        "source": "live_ers"}]
    assert sum(call[0:2] == ("ers", "/config/networkdevice")
               for call in client.calls) == 1


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
            ("POSTURE_REPORT", "CLOB"),
        ),
    }

    def query(self, sql, parameters=None):
        self.calls.append((sql, parameters or {}))
        lowered = sql.lower()
        if "select distinct table_name" in lowered:
            return [{"value": "CUSTOM_REPORT_VIEW"}]
        if "from user_tab_columns" in lowered:
            table = (parameters or {}).get("table_name")
            if table is None and "table_name in" in lowered:
                return [
                    {"table_name": table_name, "column_name": column,
                     "data_type": data_type}
                    for table_name, columns in self.schemas.items()
                    for column, data_type in columns
                ]
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


def test_health_schema_describes_authenticated_probe_paths_and_output(capsys):
    assert cli.main(["schema", "health", "--output", "json"]) == 0
    schema = json.loads(capsys.readouterr().out)
    assert schema["paths"] == [
        "/ers/config/networkdevice?size=1&page=1",
        "/admin/API/mnt/Session/ActiveCount",
    ]
    assert schema["fields"] == [
        "service", "host", "reachable", "authenticated", "http_status",
        "probe_status"]


def test_health_reports_reachability_and_authentication(capsys):
    assert cli.main(["health", "-o", "json"], client=FakeClient()) == 0
    rows = json.loads(capsys.readouterr().out)
    assert rows == [
        {"authenticated": True, "host": "pan.example.com", "http_status": 0,
         "probe_status": "completed",
         "reachable": True, "service": "PAN/ERS"},
        {"authenticated": False, "host": "mnt.example.com", "http_status": 0,
         "probe_status": "completed",
         "reachable": False, "service": "MnT"},
    ]


@pytest.mark.parametrize(("command", "family"), (
    ("ers-check", "ers"),
    ("openapi-check", "openapi"),
    ("mnt-check", "mnt"),
))
def test_focused_api_checks_return_powershell_friendly_objects(
        command, family, capsys):
    client = FakeClient()

    assert cli.main([command, "-o", "json"], client=client) == 0

    assert json.loads(capsys.readouterr().out) == [{
        "authenticated": True, "healthy": True, "reachable": True,
        "service": family, "status": "ok",
    }]
    assert client.calls == [("check", family)]


def test_health_works_with_only_dataconnect_configuration(capsys):
    cfg = types.SimpleNamespace(
        ise_host="", ise_mnt_host="", ise_user="", ise_pass="",
        dataconnect_host="mnt.example.com", dataconnect_ready=True)
    class HealthyDataConnect(FakeDataConnect):
        def query(self, sql, parameters=None):
            if "user_views" in sql:
                return [{"available": 1}]
            return super().query(sql, parameters)

    dataconnect = HealthyDataConnect()
    assert cli.main(["health", "-o", "json"], cfg=cfg, dataconnect=dataconnect) == 0
    assert json.loads(capsys.readouterr().out) == [{
        "authenticated": True, "host": "mnt.example.com", "http_status": 0,
        "probe_status": "completed",
        "reachable": True, "service": "Data Connect"}]


def test_health_defers_dataconnect_probe_instead_of_waiting_for_pacing(capsys):
    cfg = types.SimpleNamespace(
        ise_host="", ise_mnt_host="", ise_user="", ise_pass="",
        dataconnect_host="mnt.example.com", dataconnect_ready=True)

    class PacedDataConnect(FakeDataConnect):
        def query(self, sql, parameters=None):
            raise AssertionError("health must not use the blocking query path")

        def query_if_ready(self, sql, parameters=None):
            self.calls.append((sql, parameters or {}))
            return None

    dataconnect = PacedDataConnect()
    assert cli.main(["health", "-o", "json"], cfg=cfg, dataconnect=dataconnect) == 0
    assert json.loads(capsys.readouterr().out) == [{
        "authenticated": None, "host": "mnt.example.com", "http_status": 0,
        "probe_status": "deferred", "reachable": None,
        "service": "Data Connect"}]
    assert len(dataconnect.calls) == 1


def test_sessions_rejects_nonpositive_limit_before_network_access(capsys):
    client = FakeClient()
    assert cli.main(["sessions", "--allow-expensive", "--limit", "0"], client=client) == 2
    assert client.calls == []
    error = capsys.readouterr().err
    assert error == "ise-cli: error: --limit must be at least 1\n"
    assert "usage:" not in error


def test_programmatic_config_cannot_raise_safe_cli_row_limit():
    args = types.SimpleNamespace(limit=5001, allow_expensive=False)
    cfg = types.SimpleNamespace(
        cli_max_rows=999999, cli_production_safe=True,
        cli_allow_expensive=False)

    with pytest.raises(cli.CLIError, match="production-safe maximum 5000"):
        cli._guard_row_limit(args, cfg)


def test_auth_status_default_stays_in_production_safe_envelope(capsys):
    client = FakeClient()

    assert cli.main([
        "auth-status", "AA:BB:CC:DD:EE:FF", "-o", "json"
    ], client=client) == 0

    assert client.calls == [(
        "mnt", "/AuthStatus/MACAddress/AA:BB:CC:DD:EE:FF/600/20/All",
        "cli_auth_status")]


@pytest.mark.parametrize("option,value", (("--seconds", "3601"), ("--limit", "101")))
def test_auth_status_large_query_requires_explicit_acknowledgement(option, value):
    client = FakeClient()

    assert cli.main([
        "auth-status", "AA:BB:CC:DD:EE:FF", option, value
    ], client=client) == 2

    assert client.calls == []


def test_auth_status_acknowledgement_cannot_bypass_hard_ceiling():
    client = FakeClient()

    assert cli.main([
        "auth-status", "AA:BB:CC:DD:EE:FF", "--seconds", "86401",
        "--allow-expensive",
    ], client=client) == 2

    assert client.calls == []


def test_auth_status_allows_bounded_expensive_troubleshooting(capsys):
    client = FakeClient()

    assert cli.main([
        "auth-status", "AA:BB:CC:DD:EE:FF", "--seconds", "7200",
        "--limit", "200", "--allow-expensive", "-o", "json",
    ], client=client) == 0

    assert client.calls == [(
        "mnt", "/AuthStatus/MACAddress/AA:BB:CC:DD:EE:FF/7200/200/All",
        "cli_auth_status")]


def test_certificates_uses_bounded_complete_openapi_pagination(capsys):
    class Client(FakeClient):
        def get_pan_api(self, path, api_name="x", unwrap=True, params=None):
            self.calls.append(("openapi", path, unwrap, api_name, params))
            return [{"hostname": "pan-1"}]

        def get_pan_api_all(self, path, api_name="x", params=None, **kwargs):
            self.calls.append(("openapi_all", path, api_name, params, kwargs))
            return [{"friendlyName": "certificate"}]

    client = Client()

    assert cli.main(["certificates", "-o", "json"], client=client) == 0

    rows = json.loads(capsys.readouterr().out)
    assert {(row["store"], row["hostname"]) for row in rows} == {
        ("system", "pan-1"), ("trusted", "trust_store")}
    paginated = [call for call in client.calls if call[0] == "openapi_all"]
    assert len(paginated) == 2
    assert all(call[3] == {"size": 100} for call in paginated)
    assert all(call[4] == {"max_pages": 10, "max_rows": 1000}
               for call in paginated)


def test_certificates_rejects_unsafe_node_before_request(capsys):
    client = FakeClient()

    assert cli.main([
        "certificates", "--node", "pan-1/../../patch",
    ], client=client) == 2

    assert client.calls == []
    assert "DNS-safe ISE hostname" in capsys.readouterr().err


def test_endpoints_are_bounded_and_paginated(capsys):
    client = FakeClient()

    assert cli.main(["endpoints", "--limit", "125", "-o", "json"], client=client) == 0

    rows = json.loads(capsys.readouterr().out)
    assert len(rows) == 125
    calls = [call for call in client.calls if call[0] == "ers"]
    assert [call[2]["page"] for call in calls] == [1, 2]
    assert [call[2]["size"] for call in calls] == [100, 25]


def test_all_ers_inventory_stops_at_production_page_ceiling(monkeypatch):
    monkeypatch.setattr(cli, "ERS_MAX_PAGES", 2)

    class EndlessClient(FakeClient):
        def get_ers(self, path, params=None, get_all=False, api_name="x"):
            self.calls.append(("ers", path, params, get_all, api_name))
            return [{"id": f"row-{index}"} for index in range(100)]

    client = EndlessClient()
    with pytest.raises(cli.CLIError, match="production safety ceiling of 200 rows"):
        cli._ers_rows(client, "/config/endpoint", all_rows=True)
    assert len(client.calls) == 2


@pytest.mark.parametrize("pattern", ("LAB-*", "*-WIN", "*LAPTOP*", "LAB-001"))
def test_endpoint_name_search_requires_dataconnect_on_ise_33(pattern):
    client = FakeClient()
    expensive = ["--allow-expensive"] if pattern.startswith("*") else []

    assert cli.main(["endpoints", pattern, *expensive, "--limit", "5"],
                    client=client) == 2

    assert client.calls == []


def test_endpoints_rejects_complex_wildcard_without_enumerating():
    client = FakeClient()

    assert cli.main(["endpoints", "LAB-*-WIN"], client=client) == 2

    assert client.calls == []


def test_leading_wildcard_requires_explicit_production_acknowledgement():
    client = FakeClient()

    assert cli.main(["endpoints", "*LAPTOP*"], client=client) == 2

    assert client.calls == []


def test_endpoint_search_rejects_excessive_query_complexity_before_network_access():
    with pytest.raises(cli.CLIError, match="at most 8 criteria"):
        cli._parse_endpoint_criteria([f"field-{index}=value" for index in range(9)])

    with pytest.raises(cli.CLIError, match="may not exceed 256 characters"):
        cli._parse_endpoint_criteria(["name=" + "x" * 257])


def test_complete_inventory_requires_explicit_production_acknowledgement():
    client = FakeClient()

    assert cli.main(["endpoints", "--all"], client=client) == 2

    assert client.calls == []


def test_dataconnect_attribute_search_rejects_misleading_all(capsys):
    dataconnect = CompletionDataConnect()

    assert cli.main([
        "endpoints", "name=LAB-*", "--all", "--allow-expensive",
    ], client=FakeClient(), dataconnect=dataconnect) == 2

    assert "cannot truthfully enumerate" in capsys.readouterr().err
    assert dataconnect.calls == []


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
        "get", "mnt", "/Session/ActiveList", "--allow-expensive", "-o", "json"
    ], client=client) == 0

    assert json.loads(capsys.readouterr().out)["total"] == 2
    assert client.calls == [("mnt", "/Session/ActiveList", "cli_get_mnt")]


def test_generic_get_rejects_full_urls_and_parent_traversal():
    for path in ("https://other.example/api", "/Session/../config"):
        assert cli.main(["get", "mnt", path], client=FakeClient()) == 2


def test_generic_mnt_auth_status_requires_explicit_acknowledgement(capsys):
    path = "/AuthStatus/MACAddress/AA:BB:CC:DD:EE:FF/600/20/All"
    client = FakeClient()

    assert cli.main(["get", "mnt", path], client=client) == 2
    assert client.calls == []

    assert cli.main([
        "get", "mnt", path, "--allow-expensive", "-o", "json"
    ], client=client) == 0
    assert client.calls == [("mnt", path, "cli_get_mnt")]


def test_csv_and_select_produce_pipeline_friendly_output(capsys):
    client = FakeClient()

    assert cli.main([
        "sessions", "--allow-expensive", "--select", "calling_station_id,server",
        "-o", "csv"
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


def test_endpoint_detail_removes_api_plumbing_and_flattens_mfc_fields(capsys):
    class NestedEndpointClient(FakeClient):
        def get_ers(self, path, params=None, get_all=False, api_name="x"):
            if path == "/config/endpoint/id-1":
                return {"ERSEndPoint": {
                    "id": "id-1",
                    "mac": "AA:BB:CC:DD:EE:FF",
                    "identityStore": "",
                    "link": {"href": "https://ise.invalid/ers/config/endpoint/id-1",
                             "rel": "self"},
                    "customAttributes": {"customAttributes": {}},
                    "mfcAttributes": {
                        "mfcDeviceType": [],
                        "mfcHardwareManufacturer": ["Zabbly"],
                        "mfcHardwareModel": ["Model A", "Model B"],
                        "mfcOperatingSystem": [],
                    },
                }}
            return super().get_ers(path, params, get_all, api_name)

    assert cli.main([
        "endpoint", "AA:BB:CC:DD:EE:FF", "-o", "json"
    ], client=NestedEndpointClient()) == 0

    assert json.loads(capsys.readouterr().out) == {
        "hardwareManufacturer": "Zabbly",
        "hardwareModel": "Model A, Model B",
        "id": "id-1",
        "mac": "AA:BB:CC:DD:EE:FF",
    }


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


def test_endpoint_resolution_does_not_select_absent_optional_row_ids():
    dataconnect = FakeDataConnect()
    dataconnect.schema = {
        "ENDPOINTS_DATA": {
            "MAC_ADDRESS": "VARCHAR2", "ENDPOINT_IP": "VARCHAR2",
            "HOSTNAME": "VARCHAR2", "ENDPOINT_POLICY": "VARCHAR2",
            "IDENTITY_GROUP_ID": "VARCHAR2", "UPDATE_TIME": "TIMESTAMP",
        },
    }

    rows = cli._dataconnect_endpoint_candidates(
        dataconnect, "client-25.example.test", "hostname")

    assert rows[0]["mac_address"] == "AA:BB:CC:DD:EE:FF"
    sql = dataconnect.calls[0][0].upper()
    assert "SELECT MAC_ADDRESS, ENDPOINT_IP, HOSTNAME" in sql
    assert "SELECT ID," not in sql
    assert "ENDPOINT_ID" not in sql
    assert "LOWER(HOSTNAME)" not in sql
    assert "HOSTNAME IN" in sql
    parameters = dataconnect.calls[0][1]
    assert parameters["identifier_lower"] == "client-25.example.test"
    assert parameters["identifier_upper"] == "CLIENT-25.EXAMPLE.TEST"


def test_hostname_endpoint_without_dataconnect_id_is_enriched_by_mac(capsys):
    class SchemaLimitedDataConnect(FakeDataConnect):
        schema = {
            "ENDPOINTS_DATA": {
                "MAC_ADDRESS": "VARCHAR2", "ENDPOINT_IP": "VARCHAR2",
                "HOSTNAME": "VARCHAR2",
            },
        }

        def query(self, sql, parameters=None):
            self.calls.append((sql, parameters or {}))
            return [{
                "mac_address": "AA:BB:CC:DD:EE:FF",
                "endpoint_ip": "192.0.2.25",
                "hostname": "client-25.example.test",
            }]

    client = FakeClient()

    assert cli.main([
        "endpoint", "client-25.example.test", "-o", "json"
    ], client=client, dataconnect=SchemaLimitedDataConnect()) == 0

    result = json.loads(capsys.readouterr().out)
    assert result == {
        "id": "id-1",
        "mac": "AA:BB:CC:DD:EE:FF",
        "profileId": "windows",
    }
    assert any(
        call[1] == "/config/endpoint"
        and call[2]["filter"] == "mac.EQ.AA:BB:CC:DD:EE:FF"
        for call in client.calls
        if call[0] == "ers"
    )


def test_endpoint_resolution_does_not_order_by_absent_optional_timestamp():
    dataconnect = FakeDataConnect()
    dataconnect.schema = {
        "ENDPOINTS_DATA": {
            "MAC_ADDRESS": "VARCHAR2", "ENDPOINT_IP": "VARCHAR2",
            "HOSTNAME": "VARCHAR2",
        },
    }

    rows = cli._dataconnect_endpoint_candidates(
        dataconnect, "client-25.example.test", "hostname")

    assert rows[0]["mac_address"] == "AA:BB:CC:DD:EE:FF"
    sql = dataconnect.calls[0][0].upper()
    assert "UPDATE_TIME" not in sql
    assert "CREATE_TIME" not in sql
    assert "FETCH FIRST 10 ROWS ONLY" in sql
    assert "ORDER BY" not in sql


def test_endpoint_resolution_uses_interactive_point_lookup_path():
    class PointLookupDataConnect(FakeDataConnect):
        schema = {"ENDPOINTS_DATA": {
            "MAC_ADDRESS": "VARCHAR2", "HOSTNAME": "VARCHAR2",
        }}

        def query(self, _sql, _parameters=None):
            raise AssertionError("aggregate reporting path must not be used")

        def query_endpoint_lookup(self, sql, parameters=None):
            self.calls.append((sql, parameters or {}))
            return [{"mac_address": "AA:BB:CC:DD:EE:FF", "hostname": "client"}]

    dataconnect = PointLookupDataConnect()

    rows = cli._dataconnect_endpoint_candidates(dataconnect, "client", "hostname")

    assert rows[0]["mac_address"] == "AA:BB:CC:DD:EE:FF"
    assert "HOSTNAME IN" in dataconnect.calls[0][0]


def test_endpoint_resolution_reports_busy_exporter_gate():
    class BusyDataConnect(FakeDataConnect):
        schema = {"ENDPOINTS_DATA": {
            "MAC_ADDRESS": "VARCHAR2", "HOSTNAME": "VARCHAR2",
        }}

        def query_endpoint_lookup(self, _sql, parameters=None):
            return None

    with pytest.raises(cli.CLIError, match="busy with an exporter collection"):
        cli._dataconnect_endpoint_candidates(BusyDataConnect(), "client", "hostname")


def test_endpoint_resolution_uses_required_columns_without_catalog_round_trip():
    class UncachedVariant:
        schema = {}

        def __init__(self):
            self.calls = []

        def query(self, sql, parameters=None):
            self.calls.append(("report", sql, parameters))
            return [{"mac_address": "AA:BB:CC:DD:EE:FF", "hostname": "client"}]

    dataconnect = UncachedVariant()

    rows = cli._dataconnect_endpoint_candidates(dataconnect, "client", "hostname")

    assert rows[0]["mac_address"] == "AA:BB:CC:DD:EE:FF"
    assert [call[0] for call in dataconnect.calls] == ["report"]
    sql = dataconnect.calls[0][1].upper()
    assert "SELECT MAC_ADDRESS, ENDPOINT_IP, HOSTNAME" in sql
    assert "ID," not in sql
    assert "ORDER BY" not in sql


def test_endpoint_resolution_rejects_missing_search_capability_before_row_query():
    class MissingHostname:
        schema = {"ENDPOINTS_DATA": {"MAC_ADDRESS": "VARCHAR2"}}

        def query(self, _sql, _parameters=None):
            raise AssertionError("reporting query must not execute")

    with pytest.raises(cli.CLIError, match="column HOSTNAME is unavailable"):
        cli._dataconnect_endpoint_candidates(MissingHostname(), "client", "hostname")


def test_mac_required_commands_reject_ambiguous_hostname_resolution():
    class AmbiguousDataConnect(FakeDataConnect):
        def query(self, sql, parameters=None):
            if "from endpoints_data" in sql.lower():
                return [
                    {"id": "id-1", "mac_address": "AA:BB:CC:DD:EE:01",
                     "hostname": "duplicate"},
                    {"id": "id-2", "mac_address": "AA:BB:CC:DD:EE:02",
                     "hostname": "duplicate"},
                ]
            return super().query(sql, parameters)

    client = FakeClient()
    assert cli.main(["secure-client", "duplicate"], client=client,
                    dataconnect=AmbiguousDataConnect()) == 2
    assert not [call for call in client.calls if call[0] == "mnt"]


def test_endpoint_resolution_preserves_dataconnect_failure_context():
    class BrokenDataConnect(FakeDataConnect):
        def query(self, sql, parameters=None):
            raise RuntimeError("shared pacing gate unavailable")

    with pytest.raises(cli.CLIError, match="shared pacing gate unavailable"):
        cli._resolve_endpoint(
            FakeClient(), "client.example", dataconnect=BrokenDataConnect())


def test_endpoint_fields_preserves_required_schema_failure_context():
    class BrokenSchemaDataConnect(FakeDataConnect):
        def query(self, sql, parameters=None):
            raise RuntimeError("ORA-01017 invalid credentials")

    with pytest.raises(cli.CLIError, match="ORA-01017 invalid credentials"):
        cli._endpoint_fields(BrokenSchemaDataConnect())


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
    assert "NUMTODSINTERVAL(6, 'HOUR')" in report_sql
    assert "CALLING_STATION_ID = :endpoint_identifier" in report_sql
    assert parameters["endpoint_identifier"] == "AA:BB:CC:DD:EE:FF"


def test_dataconnect_query_validates_identifiers_and_binds_operator_filters(capsys):
    dataconnect = FakeDataConnect()

    assert cli.main([
        "dataconnect-query", "RADIUS_AUTHENTICATIONS",
        "--column", "TIMESTAMP", "--column", "USERNAME",
        "--where", "DEVICE_NAME=nad-1", "--like", "USERNAME=ali*",
        "--order-by", "TIMESTAMP", "--descending", "--limit", "5", "-o", "json",
    ], client=FakeClient(), dataconnect=dataconnect) == 0

    assert json.loads(capsys.readouterr().out)[0]["username"] == "alice"
    sql, parameters = dataconnect.calls[-1]
    assert "SELECT q.TIMESTAMP, q.USERNAME FROM RADIUS_AUTHENTICATIONS q" in sql
    assert "q.DEVICE_NAME = :exact_0" in sql
    assert "UPPER(q.USERNAME) LIKE :pattern_0 ESCAPE '\\'" in sql
    assert "NUMTODSINTERVAL(6, 'HOUR')" in sql
    assert "ORDER BY q.TIMESTAMP DESC FETCH FIRST 5 ROWS ONLY" in sql
    assert parameters["exact_0"] == "nad-1"
    assert parameters["pattern_0"] == "ALI%"
    assert "nad-1" not in sql and "ali" not in sql.lower()


def test_dataconnect_query_rejects_unvalidated_table_and_column(capsys):
    dataconnect = FakeDataConnect()

    assert cli.main([
        "dataconnect-query", "RADIUS_AUTHENTICATIONS;DROP_TABLE",
        "-o", "json",
    ], client=FakeClient(), dataconnect=dataconnect) == 2
    assert "only letters, numbers, and underscores" in capsys.readouterr().err

    assert cli.main([
        "dataconnect-query", "RADIUS_AUTHENTICATIONS", "--column", "PASSWORD",
        "-o", "json",
    ], client=FakeClient(), dataconnect=dataconnect) == 2
    assert "unknown RADIUS_AUTHENTICATIONS column 'PASSWORD'" in capsys.readouterr().err


def test_dataconnect_query_requires_acknowledgement_for_wider_event_window(capsys):
    dataconnect = FakeDataConnect()

    assert cli.main([
        "dataconnect-query", "RADIUS_AUTHENTICATIONS", "--hours", "48", "-o", "json",
    ], client=FakeClient(), dataconnect=dataconnect) == 2
    assert "production-safe maximum 6 hours" in capsys.readouterr().err

    assert cli.main([
        "dataconnect-query", "RADIUS_AUTHENTICATIONS", "--hours", "48",
        "--allow-expensive", "-o", "json",
    ], client=FakeClient(), dataconnect=dataconnect) == 0
    capsys.readouterr()
    assert "NUMTODSINTERVAL(48, 'HOUR')" in dataconnect.calls[-1][0]


def test_dataconnect_query_does_not_wait_for_busy_reporting_gate(capsys):
    class BusyReporting(FakeDataConnect):
        def query_interactive(self, sql, parameters=None):
            self.calls.append((sql, parameters or {}))
            return None

    dataconnect = BusyReporting()

    assert cli.main([
        "dataconnect-query", "RADIUS_AUTHENTICATIONS",
        "--column", "TIMESTAMP", "--limit", "5", "-o", "json",
    ], client=FakeClient(), dataconnect=dataconnect) == 2
    assert "reporting gate is busy or cooling down" in capsys.readouterr().err
    assert len(dataconnect.calls) == 2


def test_dataconnect_catalog_walks_all_accessible_objects_with_bound_pattern(capsys):
    dataconnect = FakeDataConnect()

    assert cli.main([
        "dataconnect-catalog", "*TACACS*", "-o", "json",
    ], client=FakeClient(), dataconnect=dataconnect) == 0

    capsys.readouterr()
    sql, parameters = dataconnect.calls[-1]
    assert "FROM user_tab_columns" in sql
    assert "GROUP BY table_name" in sql
    assert "LIKE :pattern" in sql
    assert parameters == {"pattern": "%TACACS%"}


def test_interactive_dataconnect_metadata_returns_busy_instead_of_waiting(capsys):
    class BusyCatalog(FakeDataConnect):
        def query_catalog_if_ready(self, sql, parameters=None):
            self.calls.append((sql, parameters or {}))
            return None

    for arguments in (
        ["dataconnect-schema", "UPSPOLICY", "-o", "json"],
        ["dataconnect-catalog", "UPS*", "-o", "json"],
        ["dataconnect-query", "UPSPOLICY", "--limit", "5", "-o", "json"],
    ):
        dataconnect = BusyCatalog()
        assert cli.main(
            arguments, client=FakeClient(), dataconnect=dataconnect) == 2
        assert "catalog is busy with another query" in capsys.readouterr().err
        assert len(dataconnect.calls) == 1


def test_dataconnect_health_reports_oracle_session_without_credentials(capsys):
    class DiagnosticDataConnect(FakeDataConnect):
        def query(self, sql, parameters=None):
            self.calls.append((sql, parameters or {}))
            return [{
                "current_schema": "DATACONNECT", "service_name": "cpm10",
                "instance_name": "cpm10", "accessible_views": 17,
                "accessible_columns": 240,
            }]

    dataconnect = DiagnosticDataConnect()
    assert cli.main([
        "dataconnect-health", "-o", "json",
    ], client=FakeClient(), dataconnect=dataconnect) == 0

    result = json.loads(capsys.readouterr().out)
    assert result["reachable"] is True and result["authenticated"] is True
    assert result["current_schema"] == "DATACONNECT"
    assert "configured_host" in result and "latency_ms" in result
    assert "query_timeout_seconds" in result
    assert "password" not in result


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


def test_named_dataconnect_schema_uses_catalog_only_client_without_eager_fallback():
    class CatalogOnly:
        def __init__(self):
            self.calls = []

        def query_catalog(self, sql, parameters=None):
            self.calls.append((sql, parameters))
            return [{"table_name": "ENDPOINTS_DATA", "column_name": "MAC_ADDRESS"}]

    dataconnect = CatalogOnly()

    assert cli._dataconnect_schema(dataconnect, "ENDPOINTS_DATA") == [{
        "table_name": "ENDPOINTS_DATA", "column_name": "MAC_ADDRESS",
    }]
    assert dataconnect.calls[0][1] == {"table_name": "ENDPOINTS_DATA"}


def test_dataconnect_schema_defaults_to_supported_contract_views(capsys):
    dataconnect = FakeDataConnect()

    assert cli.main([
        "dataconnect-schema", "-o", "json"
    ], client=FakeClient(), dataconnect=dataconnect) == 0

    assert json.loads(capsys.readouterr().out)
    sql, parameters = dataconnect.calls[-1]
    assert "FROM user_tab_columns" in sql
    assert "WHERE table_name IN" in sql
    assert "'ENDPOINTS_DATA'" in sql
    assert "'RADIUS_AUTHENTICATIONS'" in sql
    assert parameters == {}


def test_no_subcommand_enters_repl_and_question_mark_shows_commands():
    stdin = io.StringIO("?\nschema secure-client -o json\nquit\n")
    stdout = io.StringIO()

    assert cli.main([], stdin=stdin, stdout=stdout) == 0

    rendered = stdout.getvalue()
    assert "Cisco ISE read-only shell" in rendered
    assert "radius-auth" in rendered
    assert "secure-client" in rendered
    assert '"api": "MnT XML"' in rendered


def test_shell_close_releases_dataconnect_and_rest_clients():
    closed = []

    class Resource:
        def __init__(self, name):
            self.name = name

        def close(self):
            closed.append(self.name)

    shell = cli.ISEShell(
        client=Resource("rest"), dataconnect=Resource("dataconnect"),
        stdin=io.StringIO(), stdout=io.StringIO())

    shell.close()

    assert closed == ["dataconnect", "rest"]


def test_shell_close_warns_and_still_closes_every_client():
    closed = []
    stdout = io.StringIO()

    class Resource:
        def __init__(self, name, fail=False):
            self.name = name
            self.fail = fail

        def close(self):
            closed.append(self.name)
            if self.fail:
                raise RuntimeError("simulated close failure")

    shell = cli.ISEShell(
        client=Resource("rest"),
        dataconnect=Resource("dataconnect", fail=True),
        stdin=io.StringIO(), stdout=stdout)

    shell.close()

    assert closed == ["dataconnect", "rest"]
    assert "warning: failed to close Data Connect client" in stdout.getvalue()


def test_noninteractive_cleanup_does_not_mask_success(capsys):
    closed = []

    class Resource:
        cfg = None

        def __init__(self, name, fail=False):
            self.name = name
            self.fail = fail

        def close(self):
            closed.append(self.name)
            if self.fail:
                raise RuntimeError("simulated close failure")

    assert cli.main(
        ["schema", "health", "-o", "json"],
        client=Resource("rest"),
        dataconnect=Resource("dataconnect", fail=True),
    ) == 0

    captured = capsys.readouterr()
    assert json.loads(captured.out)["api"]
    assert "warning: failed to close Data Connect client" in captured.err
    assert closed == ["dataconnect", "rest"]


def test_cli_history_refuses_symlinks_and_enforces_private_mode(tmp_path):
    history = tmp_path / "history"
    target = tmp_path / "target"
    target.write_text("must-not-overwrite")
    history.symlink_to(target)

    with pytest.raises(OSError, match="user-owned regular file"):
        cli.ISEShell._validate_history_file(history)

    history.unlink()

    class Readline:
        def write_history_file(self, path):
            path.write_text("endpoint AA:BB:CC:DD:EE:FF")
            path.chmod(0o666)

    cli.ISEShell._write_history(Readline(), history)

    assert history.read_text() == "endpoint AA:BB:CC:DD:EE:FF"
    assert history.stat().st_mode & 0o777 == 0o600


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
    assert shell.completion_candidates("endpoint client-2") == [
        "client-25.example.test "]
    assert shell.completion_candidates("endpoint client") == [
        "'client with space'", "client-25.example.test"]
    assert len(dataconnect.calls) == first_call_count
    assert shell.completion_candidates("endpoint-report --profile Win") == [
        "'Windows Workstations'", "'Windows Servers'"]
    assert shell.completion_candidates("certificates --node pan") == ["pan-1"]
    endpoint_sql, parameters = dataconnect.calls[0]
    assert "FETCH FIRST 25 ROWS ONLY" in endpoint_sql
    assert parameters == {"prefix": "CL%"}


def test_repl_completion_offers_schema_tables_and_comma_select_fields():
    shell = cli.ISEShell(client=FakeClient(), dataconnect=CompletionDataConnect(),
                         stdin=io.StringIO(), stdout=io.StringIO())

    tables = shell.completion_candidates("dataconnect-schema C")
    assert tables == ["CUSTOM_REPORT_VIEW "]
    assert shell.completion_candidates(
        "radius-auth --select timestamp,user") == ["timestamp,username"]


def test_live_completion_refines_a_truncated_cached_prefix():
    class SaturatedDataConnect(CompletionDataConnect):
        def query(self, sql, parameters=None):
            self.calls.append((sql, parameters or {}))
            prefix = (parameters or {}).get("prefix")
            if prefix == "WI%":
                return [{"value": f"Win-{index:02d}"} for index in range(25)]
            if prefix == "WINDOWS%":
                return [{"value": "Windows Workstations"}]
            return super().query(sql, parameters)

    dataconnect = SaturatedDataConnect()
    shell = cli.ISEShell(client=FakeClient(), dataconnect=dataconnect,
                         stdin=io.StringIO(), stdout=io.StringIO())

    assert shell._dc_values(
        "ENDPOINTS_DATA", "ENDPOINT_POLICY", "Windows") == (
            "Windows Workstations",)
    assert [parameters["prefix"] for _sql, parameters in dataconnect.calls] == [
        "WI%", "WINDOWS%"]


def test_production_completion_never_scans_event_views():
    dataconnect = CompletionDataConnect()
    client = FakeClient()
    shell = cli.ISEShell(client=client, dataconnect=dataconnect,
                         stdin=io.StringIO(), stdout=io.StringIO())

    assert shell.completion_candidates("radius-auth --username al") == []
    assert shell.completion_candidates("endpoints authorization-policy=Pe") == []
    assert shell.completion_candidates("tacacs-activity --device sw") == ["switch-1"]
    assert shell.completion_candidates("tacacs-activity --username re") == ["readonly"]
    assert not any(
        "RADIUS_AUTHENTICATIONS" in sql or "TACACS_" in sql
        for sql, _parameters in dataconnect.calls)


def test_live_completion_returns_immediately_when_shared_pacing_is_busy():
    class BusyDataConnect:
        def __init__(self):
            self.calls = []

        def query_if_ready(self, sql, parameters=None):
            self.calls.append((sql, parameters or {}))
            return None

        def query(self, *_args, **_kwargs):
            raise AssertionError("completion used the blocking query path")

        def close(self):
            pass

    dataconnect = BusyDataConnect()
    shell = cli.ISEShell(client=FakeClient(), dataconnect=dataconnect,
                         stdin=io.StringIO(), stdout=io.StringIO())

    assert shell.completion_candidates("endpoint cli") == []
    assert "authorization-policy=" in shell.completion_candidates("endpoints auth")
    assert dataconnect.calls


def test_expensive_completion_opt_in_restores_live_event_values():
    dataconnect = CompletionDataConnect()
    cfg = types.SimpleNamespace(cli_production_safe=True, cli_allow_expensive=True)
    shell = cli.ISEShell(client=FakeClient(), cfg=cfg, dataconnect=dataconnect,
                         stdin=io.StringIO(), stdout=io.StringIO())

    assert shell.completion_candidates("radius-auth --username al") == [
        "alice", "'alex admin'"]
    assert any("RADIUS_AUTHENTICATIONS" in sql for sql, _parameters in dataconnect.calls)


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
    assert "ASCIISTR(e.HOSTNAME) AS HOSTNAME" in sql
    assert "ASCIISTR(s0_0_0.HOSTNAME) AS match_value" in sql
    assert "UPPER(REPLACE(REPLACE(REPLACE(TRIM(s0_0_0.MAC_ADDRESS)" in sql
    assert "e.MAC_ADDRESS IN (m0.match_mac" in sql
    assert "REPLACE(e.MAC_ADDRESS" not in sql
    assert "LOWER(SUBSTR(m0.match_mac, 1, 2)" in sql
    assert "FETCH FIRST 25 ROWS ONLY" in sql
    assert "NUMTODSINTERVAL(6, 'HOUR')" in sql
    assert set(parameters.values()) == {"LAB-%", "PERMIT%", "BERLIN-%", "WINDOWS%"}
    schema_queries = [sql for sql, _parameters in dataconnect.calls
                      if "FROM user_tab_columns" in sql]
    assert len(schema_queries) == 1
    assert all(spec["table"] in schema_queries[0]
               for spec in cli.ENDPOINT_CONTEXT_SOURCES.values())


def test_endpoint_context_search_uses_safe_clob_match_expression(capsys):
    dataconnect = CompletionDataConnect()

    assert cli.main([
        "endpoints", "posture-report=C2CP*", "--limit", "5", "-o", "json",
    ], client=FakeClient(), dataconnect=dataconnect) == 0

    sql, _parameters = next(
        (sql, parameters) for sql, parameters in dataconnect.calls
        if "FROM ENDPOINTS_DATA e" in sql)
    assert "UPPER(ASCIISTR(DBMS_LOB.SUBSTR(" in sql
    assert ".POSTURE_REPORT, 4000, 1))) LIKE" in sql


def test_cli_dataconnect_reports_honor_lower_production_scan_ceiling(capsys):
    client = FakeClient()
    client.cfg.dataconnect_event_window_hours = 4
    dataconnect = FakeDataConnect()

    assert cli.main(["radius-auth", "--limit", "5", "-o", "json"],
                    client=client, dataconnect=dataconnect) == 0

    report_sql, _parameters = dataconnect.calls[-1]
    assert "NUMTODSINTERVAL(4, 'HOUR')" in report_sql
    assert "INTERVAL '2' DAY" not in report_sql


def test_cli_tacacs_report_bounds_numeric_epoch_view(monkeypatch, capsys):
    class TacacsDataConnect(FakeDataConnect):
        def query(self, sql, parameters=None):
            self.calls.append((sql, parameters or {}))
            if "FROM user_tab_columns" in sql:
                return [
                    {"column_name": "EPOCH_TIME", "data_type": "NUMBER"},
                    {"column_name": "USERNAME", "data_type": "VARCHAR2"},
                ]
            return [{"epoch_time": 99999, "username": "netadmin"}]

    client = FakeClient()
    client.cfg.dataconnect_event_window_hours = 4
    dataconnect = TacacsDataConnect()
    monkeypatch.setattr(cli.time, "time", lambda: 100000)

    assert cli.main([
        "tacacs-activity", "--event-type", "authentication", "--limit", "5",
        "-o", "json",
    ], client=client, dataconnect=dataconnect) == 0

    report_sql, parameters = dataconnect.calls[-1]
    assert "EPOCH_TIME >= :minimum_epoch" in report_sql
    assert parameters == {"minimum_epoch": 85600}


def test_repeated_endpoint_field_values_are_or_and_distinct_fields_are_and(capsys):
    dataconnect = CompletionDataConnect()

    assert cli.main([
        "endpoints", "location=Berlin*", "location=London*", "posture-status=Compliant",
        "--allow-expensive", "-o", "json",
    ], client=FakeClient(), dataconnect=dataconnect) == 0

    sql = next(sql for sql, _parameters in dataconnect.calls
               if "FROM ENDPOINTS_DATA e" in sql)
    assert "RADIUS_AUTHENTICATIONS" in sql
    assert "POSTURE_ASSESSMENT_BY_ENDPOINT" in sql
    assert " UNION " in sql
    assert "JOIN matched_0" in sql and "JOIN matched_1" in sql
    assert "EXISTS" not in sql
    assert "REPLACE(e.MAC_ADDRESS" not in sql
    assert "e.MAC_ADDRESS IN (m0.match_mac" in sql
    assert "FETCH FIRST 100 ROWS ONLY" in sql


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


def test_endpoint_projection_safely_converts_legacy_text_and_time_types():
    assert cli._safe_select_expression("e", "CUSTOM_ATTRIBUTES", "VARCHAR2") == \
        "ASCIISTR(e.CUSTOM_ATTRIBUTES) AS CUSTOM_ATTRIBUTES"
    assert cli._safe_select_expression("e", "PROBE_DATA", "CLOB") == \
        "ASCIISTR(DBMS_LOB.SUBSTR(e.PROBE_DATA, 4000, 1)) AS PROBE_DATA"
    assert cli._safe_select_expression(
        "e", "UPDATE_TIME", "TIMESTAMP(6) WITH TIME ZONE") == (
            "TO_CHAR(e.UPDATE_TIME, 'YYYY-MM-DD\"T\"HH24:MI:SS.FF TZH:TZM') AS UPDATE_TIME")


def test_endpoint_match_safely_converts_legacy_clob_values():
    assert cli._safe_match_expression("p", "POSTURE_REPORT", "CLOB") == \
        "ASCIISTR(DBMS_LOB.SUBSTR(p.POSTURE_REPORT, 4000, 1))"


def test_endpoint_attribute_payloads_are_operator_readable_without_data_loss():
    probe = ("i\x11\x06chaddr\x11\x11AA:BB:CC:DD:EE:FF"
             "\x11\x09Ops Owner\x11\x11Campus Operations")
    assert cli._decode_endpoint_attribute_payload(probe) == {
        "chaddr": "AA:BB:CC:DD:EE:FF",
        "Ops Owner": "Campus Operations",
    }
    assert cli._decode_endpoint_attribute_payload(
        '{"Ops Owner":"Campus Operations"}') == {
            "Ops Owner": "Campus Operations"}
    malformed = "i\x11\x20too-short"
    assert cli._decode_endpoint_attribute_payload(malformed) == malformed
