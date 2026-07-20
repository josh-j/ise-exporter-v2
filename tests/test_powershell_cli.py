import json
import os
import shutil
import subprocess
from pathlib import Path

import pytest


ROOT = Path(__file__).parents[1]
MODULE = ROOT / "powershell" / "Ise.Cli" / "Ise.Cli.psd1"
LAUNCHER = ROOT / "powershell" / "ise-cli"
PROFILE = ROOT / "powershell" / "Ise.Cli.Profile.ps1"


def test_powershell_cli_is_a_pwsh_module_over_private_bounded_backend():
    manifest = MODULE.read_text()
    implementation = MODULE.with_suffix(".psm1").read_text()

    assert "PowerShellVersion = '7.2'" in manifest
    for command in (
        "Get-IseOverview", "Get-IseCollectorStatus", "Get-IseEndpointSummary",
        "Debug-IseAuthentication", "Debug-IsePsn", "Get-IseNadSummary",
        "Get-IsePxGridStatus", "Test-IsePxGrid", "Test-IseErs",
        "Test-IseOpenApi", "Test-IseMnt", "Get-IsePxGridSession",
        "Get-IsePxGridEndpoint", "Get-IsePxGridRadiusFailure",
        "Find-IseEndpoint", "Get-IseEndpoint", "Get-IseSecureClient",
        "Get-IseRadiusAuthentication", "Watch-IseRadiusAuthentication",
        "Get-IseTacacsActivity",
        "Get-IseDataConnectTable", "Get-IseDataConnectColumn",
        "Get-IseDataConnectRow", "Search-IseDataConnect", "Get-IseAlert",
        "Get-IseSystemDiagnostic", "Get-IseAaaDiagnostic", "Test-IseDataConnect",
        "Get-IseSchema", "Invoke-IseReadOnlyRequest",
    ):
        assert f"'{command}'" in manifest
        assert f"function {command}" in implementation
    assert "ise-cli-backend" in implementation
    assert "'/opt/ise-exporter/.venv/bin/ise-cli-backend'" in implementation
    assert "ConvertFrom-Json" in implementation
    assert "System.Diagnostics.ProcessStartInfo" in implementation
    assert "Register-ArgumentCompleter" in implementation
    assert "Invoke-WebRequest" not in implementation
    assert "Invoke-RestMethod" not in implementation
    assert "OracleConnection" not in implementation
    assert all(
        ".Add(" not in line or "[void]" in line
        for line in implementation.splitlines()
    ), "PowerShell List.Add return values must never leak into the object pipeline"
    assert "Write-Output -NoEnumerate $arguments" in implementation


def test_powershell_cli_launcher_is_shell_safe():
    subprocess.run(["bash", "-n", str(LAUNCHER)], check=True)
    assert "exec pwsh -NoLogo -NoProfile -NoExit" in LAUNCHER.read_text()
    assert 'export PSModulePath="${SCRIPT_DIR}' in LAUNCHER.read_text()
    assert 'Ise.Cli.Profile.ps1' in LAUNCHER.read_text()
    assert 'INSTALLED_BACKEND="/opt/ise-exporter/.venv/bin/ise-cli-backend"' \
        in LAUNCHER.read_text()


def test_powershell_cli_profile_has_operator_focused_ux():
    profile = PROFILE.read_text()
    assert "Import-Module Ise.Cli" in profile
    assert "Show-IseCliHelp" in profile
    assert "Get-IseOverview" in profile
    assert "Debug-IseAuthentication" in profile
    assert "Get-IseCollectorStatus" in profile
    assert "Find-Endpoint" in profile
    assert "MenuComplete" in profile
    assert "HistorySearchBackward" in profile
    assert "function global:prompt" in profile


@pytest.mark.skipif(shutil.which("pwsh") is None, reason="PowerShell 7 is not installed")
def test_powershell_module_imports_and_exports_native_commands():
    script = f"""
        $ErrorActionPreference = 'Stop'
        Import-Module '{MODULE}' -Force
        $commands = @(Get-Command -Module Ise.Cli | Select-Object -ExpandProperty Name)
        if ($commands.Count -lt 46) {{ throw "only $($commands.Count) commands exported" }}
        foreach ($required in @('Find-IseEndpoint','Find-Endpoint','Get-IseEndpoint','Get-IseCliVersion','Get-IseOverview','Debug-IseAuthentication','Debug-IsePsn','Get-IseNadSummary','Get-IsePxGridStatus','Test-IsePxGrid','Test-IseErs','Test-IseOpenApi','Test-IseMnt','Get-IsePxGridSession','Get-IsePxGridEndpoint','Get-IseDataConnectColumn','Get-IseDataConnectRow','Get-IseRadiusAuthentication','Watch-IseRadiusAuthentication')) {{
            if ($required -notin $commands) {{ throw "missing $required" }}
        }}
    """
    subprocess.run(
        ["pwsh", "-NoLogo", "-NoProfile", "-Command", script], check=True)


@pytest.mark.skipif(shutil.which("pwsh") is None, reason="PowerShell 7 is not installed")
def test_powershell_cli_profile_loads_alias_help_and_prompt():
    module_root = MODULE.parents[1]
    script = f"""
        $ErrorActionPreference = 'Stop'
        $env:PSModulePath = '{module_root}:' + $env:PSModulePath
        . '{PROFILE}'
        if (-not $global:ISE_CLI_PROFILE_ACTIVE) {{ throw 'profile marker missing' }}
        if ((Get-Alias Find-Endpoint).Definition -ne 'Find-IseEndpoint') {{ throw 'alias missing' }}
        if ((Get-Alias ise-help).Definition -ne 'Show-IseCliHelp') {{ throw 'help alias missing' }}
        if ((prompt) -notlike 'ISE PS *> ') {{ throw 'ISE prompt missing' }}
    """
    subprocess.run(
        ["pwsh", "-NoLogo", "-NoProfile", "-Command", script], check=True)


@pytest.mark.skipif(shutil.which("pwsh") is None, reason="PowerShell 7 is not installed")
def test_powershell_cmdlet_returns_only_backend_objects(tmp_path):
    backend = tmp_path / "ise-cli-backend"
    backend.write_text(
        "#!/bin/sh\n"
        "case \" $* \" in\n"
        "  *\" --version \"*) printf '%s\\n' 'ise-cli test' ;;\n"
        "  *\" --complete \"*) printf '%s\\n' '[\"--status \"]' ;;\n"
        "  *) printf '%s\\n' '[{\"name\":\"LAB-01\",\"mac\":\"AA:BB\"}]' ;;\n"
        "esac\n")
    backend.chmod(0o755)
    script = f"""
        $ErrorActionPreference = 'Stop'
        $env:ISE_CLI_BACKEND = '{backend}'
        Import-Module '{MODULE}' -Force
        $items = @(Find-IseEndpoint 'LAB-*' -Limit 25)
        if ($items.Count -ne 1) {{ throw "expected one object, got $($items.Count)" }}
        if ($items[0].name -ne 'LAB-01') {{ throw 'backend JSON was not converted' }}
        if ($items[0] -is [int]) {{ throw 'list mutation index leaked into pipeline' }}
    """
    subprocess.run(
        ["pwsh", "-NoLogo", "-NoProfile", "-Command", script], check=True)


@pytest.mark.skipif(shutil.which("pwsh") is None, reason="PowerShell 7 is not installed")
def test_powershell_radius_log_get_and_watch_have_friendly_ux(tmp_path):
    calls = tmp_path / "calls"
    backend = tmp_path / "ise-cli-backend"
    backend.write_text(
        "#!/bin/sh\n"
        f"printf '%s\\n' \"$*\" >> {calls}\n"
        "printf '%s\\n' "
        "'[{\"timestamp\":\"2026-07-17T12:00:00Z\",\"username\":\"svc-radius\","
        "\"calling_station_id\":\"AA:BB:CC:DD:EE:FF\",\"device_name\":\"laba-sw-001\","
        "\"ise_node\":\"laba-ise-001\",\"policy_set_name\":\"Wired\","
        "\"authorization_policy\":\"DenyAccess\",\"authentication_method\":\"Certificate\","
        "\"authentication_protocol\":\"EAP-TLS\",\"failed\":1,\"response_time\":42}]'\n")
    backend.chmod(0o755)
    script = f"""
        $ErrorActionPreference = 'Stop'
        $env:ISE_CLI_BACKEND = '{backend}'
        Import-Module '{MODULE}' -Force
        $rows = @(Get-IseRadiusAuthentication -PsnLike 'laba-ise-*' -Failed `
            -PolicySetLike 'host\\*-*-*' -AuthorizationPolicyLike 'Deny*' `
            -Method Certificate -Protocol EAP-TLS `
            -Hours 1 -Limit 200)
        if ($rows.Count -ne 1) {{ throw "expected one row, got $($rows.Count)" }}
        if ($rows[0].PSObject.TypeNames[0] -ne 'Ise.Cli.RadiusAuthentication') {{
            throw 'friendly RADIUS type missing'
        }}
        if ($rows[0].Time -isnot [datetime] -or $rows[0].Result -ne 'Failed') {{
            throw 'friendly time/result fields missing'
        }}
        if ($rows[0].Psn -ne 'laba-ise-001' -or $rows[0].PolicySet -ne 'Wired') {{
            throw 'friendly PSN/policy fields missing'
        }}
        if ($rows[0].Method -ne 'Certificate' -or $rows[0].Protocol -ne 'EAP-TLS') {{
            throw 'friendly authentication method/protocol fields missing'
        }}
        $display = (Get-TypeData Ise.Cli.RadiusAuthentication).DefaultDisplayPropertySet.ReferencedProperties
        if ('Time' -notin $display -or 'Result' -notin $display -or
            'Endpoint' -notin $display -or 'Psn' -notin $display -or
            'Method' -notin $display -or 'Protocol' -notin $display -or
            'Username' -in $display) {{
            throw 'compact default display missing'
        }}
        $watched = @(Watch-IseRadiusAuthentication -NadLike 'laba-sw-*' -Failed `
            -PolicySetLike 'host*-*-*' -Protocol EAP-TLS -Hours 1 -Once)
        if ($watched.Count -ne 1 -or $watched[0].Username -ne 'svc-radius') {{
            throw 'watch did not emit the new authentication'
        }}
    """
    subprocess.run(
        ["pwsh", "-NoLogo", "-NoProfile", "-Command", script], check=True)

    logged = calls.read_text().splitlines()
    assert len(logged) == 2
    assert all("radius-auth" in call and "--policy-set-like" in call
               and "--hours 1" in call
               for call in logged)
    assert "--psn-like laba-ise-*" in logged[0]
    assert "--authorization-policy-like Deny*" in logged[0]
    assert "--policy-set-like host\\*-*-*" in logged[0]
    assert "--nad-like laba-sw-*" in logged[1]
    assert "--authentication-method Certificate" in logged[0]
    assert all("--authentication-protocol EAP-TLS" in call for call in logged)
    assert "--status failed" in logged[0]


@pytest.mark.skipif(shutil.which("pwsh") is None, reason="PowerShell 7 is not installed")
def test_powershell_empty_arguments_help_and_empty_results_have_good_ux(tmp_path):
    calls = tmp_path / "calls"
    backend = tmp_path / "ise-cli-backend"
    backend.write_text(
        "#!/bin/sh\n"
        f"printf '%s\\n' \"$*\" >> {calls}\n"
        "case \" $* \" in\n"
        "  *\" dataconnect-schema --help \"*) printf '%s\\n' 'SCHEMA HELP' ;;\n"
        "  *\" dataconnect-schema ENDPOINTS_DATA --output json \"*) printf '%s\\n' "
        "'[{\"table_name\":\"ENDPOINTS_DATA\",\"column_id\":1,\"column_name\":\"MAC_ADDRESS\",\"data_type\":\"VARCHAR2\",\"nullable\":\"N\",\"data_length\":64},"
        "{\"table_name\":\"ENDPOINTS_DATA\",\"column_id\":2,\"column_name\":\"HOSTNAME\",\"data_type\":\"VARCHAR2\",\"nullable\":\"Y\",\"data_length\":255}]' ;;\n"
        "  *\" dataconnect-schema --output json \"*) printf '%s\\n' "
        "'[{\"table_name\":\"ENDPOINTS_DATA\",\"column_id\":1,\"column_name\":\"MAC_ADDRESS\",\"data_type\":\"VARCHAR2\",\"nullable\":\"N\"},"
        "{\"table_name\":\"ENDPOINTS_DATA\",\"column_id\":2,\"column_name\":\"HOSTNAME\",\"data_type\":\"VARCHAR2\",\"nullable\":\"Y\"},"
        "{\"table_name\":\"RADIUS_AUTHENTICATIONS\",\"column_id\":1,\"column_name\":\"TIMESTAMP\",\"data_type\":\"TIMESTAMP\",\"nullable\":\"N\"}]' ;;\n"
        "  *\" radius-errors \"*) printf '%s\\n' '[]' ;;\n"
        "  *\" dataconnect-query \"*) printf '%s\\n' '[{\"username\":\"alice\"}]' ;;\n"
        "  *) printf '%s\\n' '[]' ;;\n"
        "esac\n")
    backend.chmod(0o755)
    script = f"""
        $ErrorActionPreference = 'Stop'
        $env:ISE_CLI_BACKEND = '{backend}'
        Import-Module '{MODULE}' -Force
        $summary = @(Get-IseDataConnectSchema)
        if ($summary.Count -ne 2) {{ throw "expected two table summaries, got $($summary.Count)" }}
        $endpointSummary = $summary | Where-Object table_name -eq 'ENDPOINTS_DATA'
        if ($endpointSummary.columns -ne 2 -or $endpointSummary.data_types -ne 'VARCHAR2') {{
            throw 'schema summary did not aggregate columns'
        }}
        $schema = @(Get-IseDataConnectSchema ENDPOINTS_DATA)
        if ($schema.Count -ne 2 -or $schema[0].PSObject.TypeNames[0] -ne 'Ise.Cli.DataConnectColumn') {{
            throw 'table detail did not return typed column objects'
        }}
        if ($schema[0].data_length -ne 64) {{ throw 'non-display properties were lost' }}
        $tableObject = [pscustomobject]@{{ table_name='ENDPOINTS_DATA' }}
        $pipelineSchema = @($tableObject | Get-IseDataConnectColumn)
        if ($pipelineSchema.Count -ne 2) {{ throw 'column pipeline did not use table_name' }}
        $allColumns = @(Get-IseDataConnectSchema -AllColumns)
        if ($allColumns.Count -ne 3) {{ throw 'AllColumns did not preserve the full schema' }}
        if ($allColumns[0].PSObject.TypeNames[0] -ne 'Ise.Cli.DataConnectColumn') {{
            throw 'AllColumns did not return typed column objects'
        }}
        $help = Get-IseDataConnectSchema --help
        if ($help.Trim() -ne 'SCHEMA HELP') {{ throw "unexpected help: $help" }}
        $query = @(Search-IseDataConnect RADIUS_AUTHENTICATIONS `
            -Column TIMESTAMP,USERNAME -Where @{{ DEVICE_NAME='nad-1' }} `
            -Like @{{ USERNAME='ali*' }} -OrderBy TIMESTAMP -Descending -Limit 25)
        if ($query[0].username -ne 'alice') {{ throw 'Data Connect query object missing' }}
        $pipelineQuery = @([pscustomobject]@{{ table_name='RADIUS_AUTHENTICATIONS' }} |
            Get-IseDataConnectRow -Column TIMESTAMP,USERNAME -Limit 25)
        if ($pipelineQuery[0].PSObject.TypeNames[0] -ne 'Ise.Cli.DataConnectRow.RADIUS_AUTHENTICATIONS') {{
            throw 'row pipeline did not return a table-specific typed object'
        }}
        Get-IseRadiusError
    """
    result = subprocess.run(
        ["pwsh", "-NoLogo", "-NoProfile", "-Command", script],
        check=True, text=True, capture_output=True)

    assert "No results." in result.stdout
    assert calls.read_text().splitlines() == [
        "dataconnect-schema --output json",
        "dataconnect-schema ENDPOINTS_DATA --output json",
        "dataconnect-schema ENDPOINTS_DATA --output json",
        "dataconnect-schema --output json",
        "dataconnect-schema --help",
        "dataconnect-query RADIUS_AUTHENTICATIONS --limit 25 --column TIMESTAMP --column USERNAME --where DEVICE_NAME=nad-1 --like USERNAME=ali* --order-by TIMESTAMP --descending --output json",
        "dataconnect-query RADIUS_AUTHENTICATIONS --limit 25 --column TIMESTAMP --column USERNAME --output json",
        "radius-errors --limit 100 --output json",
    ]


@pytest.mark.skipif(shutil.which("pwsh") is None, reason="PowerShell 7 is not installed")
def test_powershell_backend_resolution_tolerates_duplicate_path_entries(tmp_path):
    backend = tmp_path / "ise-cli-backend"
    backend.write_text("#!/bin/sh\nprintf '%s\\n' 'ise-cli duplicate-path-test'\n")
    backend.chmod(0o755)
    env = os.environ | {
        "PATH": os.pathsep.join((str(tmp_path), str(tmp_path), os.environ["PATH"])),
    }
    script = f"""
        $ErrorActionPreference = 'Stop'
        Import-Module '{MODULE}' -Force
        if ((Get-IseCliVersion) -ne 'ise-cli duplicate-path-test') {{
            throw 'duplicate PATH entries produced an invalid backend path'
        }}
    """
    subprocess.run(
        ["pwsh", "-NoLogo", "-NoProfile", "-Command", script], env=env, check=True)


@pytest.mark.skipif(shutil.which("pwsh") is None, reason="PowerShell 7 is not installed")
def test_compatibility_launcher_preserves_config_file_and_subcommand_help(tmp_path):
    calls = tmp_path / "calls"
    backend = tmp_path / "ise-cli-backend"
    backend.write_text(
        "#!/bin/sh\n"
        f"printf '%s\\n' \"$*\" >> {calls}\n"
        "case \" $* \" in\n"
        "  *\" --help \"*) printf '%s\\n' 'ENDPOINT HELP' ;;\n"
        "  *) printf '%s\\n' '[{\"name\":\"LAB-01\"}]' ;;\n"
        "esac\n")
    backend.chmod(0o755)
    env = os.environ | {"ISE_CLI_BACKEND": str(backend)}

    help_result = subprocess.run(
        [str(LAUNCHER), "--config", "/tmp/ise.toml", "endpoints", "--help"],
        env=env, check=True, text=True, capture_output=True)
    json_result = subprocess.run(
        [str(LAUNCHER), "--config=/tmp/ise.toml", "endpoints", "--output", "json"],
        env=env, check=True, text=True, capture_output=True)
    short_json_result = subprocess.run(
        [str(LAUNCHER), "endpoints", "-o", "json"],
        env=env, check=True, text=True, capture_output=True)

    assert help_result.stdout == "ENDPOINT HELP\n"
    assert json.loads(json_result.stdout) == {"name": "LAB-01"}
    assert json.loads(short_json_result.stdout) == {"name": "LAB-01"}
    assert calls.read_text().splitlines() == [
        "--config /tmp/ise.toml endpoints --help",
        "--config /tmp/ise.toml endpoints --output json",
        "endpoints --output json",
    ]
