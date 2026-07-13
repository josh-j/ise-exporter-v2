import json
import types

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

    def get_pan_api(self, path, api_name="x", unwrap=True):
        self.calls.append(("openapi", path, unwrap, api_name))
        return [{"name": "pan-1", "roles": ["PrimaryAdmin"]}]

    def get_mnt_xml(self, path, api_name="x"):
        self.calls.append(("mnt", path, api_name))
        if path == "/Session/ActiveList":
            return {"total": 2, "sessions": [
                {"calling_station_id": "AA:00", "server": "psn-1"},
                {"calling_station_id": "BB:00", "server": "psn-2"},
            ]}
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
