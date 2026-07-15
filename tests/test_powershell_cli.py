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
        "Get-IsePxGridStatus",
        "Find-IseEndpoint", "Get-IseEndpoint", "Get-IseSecureClient",
        "Get-IseRadiusAuthentication", "Get-IseTacacsActivity",
        "Get-IseSchema", "Invoke-IseReadOnlyRequest",
    ):
        assert f"'{command}'" in manifest
        assert f"function {command}" in implementation
    assert "ise-cli-backend" in implementation
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
        if ($commands.Count -lt 44) {{ throw "only $($commands.Count) commands exported" }}
        foreach ($required in @('Find-IseEndpoint','Find-Endpoint','Get-IseEndpoint','Get-IseCliVersion','Get-IseOverview','Debug-IseAuthentication','Debug-IsePsn','Get-IseNadSummary','Get-IsePxGridStatus')) {{
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
def test_powershell_empty_arguments_help_and_empty_results_have_good_ux(tmp_path):
    calls = tmp_path / "calls"
    backend = tmp_path / "ise-cli-backend"
    backend.write_text(
        "#!/bin/sh\n"
        f"printf '%s\\n' \"$*\" >> {calls}\n"
        "case \" $* \" in\n"
        "  *\" dataconnect-schema --help \"*) printf '%s\\n' 'SCHEMA HELP' ;;\n"
        "  *\" dataconnect-schema --output json \"*) printf '%s\\n' '[{\"table_name\":\"ENDPOINTS_DATA\"}]' ;;\n"
        "  *\" radius-errors \"*) printf '%s\\n' '[]' ;;\n"
        "  *) printf '%s\\n' '[]' ;;\n"
        "esac\n")
    backend.chmod(0o755)
    script = f"""
        $ErrorActionPreference = 'Stop'
        $env:ISE_CLI_BACKEND = '{backend}'
        Import-Module '{MODULE}' -Force
        $schema = @(Get-IseDataConnectSchema)
        if ($schema.Count -ne 1 -or $schema[0].table_name -ne 'ENDPOINTS_DATA') {{
            throw 'schema without a table did not return backend objects'
        }}
        $help = Get-IseDataConnectSchema --help
        if ($help.Trim() -ne 'SCHEMA HELP') {{ throw "unexpected help: $help" }}
        Get-IseRadiusError
    """
    result = subprocess.run(
        ["pwsh", "-NoLogo", "-NoProfile", "-Command", script],
        check=True, text=True, capture_output=True)

    assert "No results." in result.stdout
    assert calls.read_text().splitlines() == [
        "dataconnect-schema --output json",
        "dataconnect-schema --help",
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

    assert help_result.stdout == "ENDPOINT HELP\n"
    assert json.loads(json_result.stdout) == {"name": "LAB-01"}
    assert calls.read_text().splitlines() == [
        "--config /tmp/ise.toml endpoints --help",
        "--config /tmp/ise.toml endpoints --output json",
    ]
