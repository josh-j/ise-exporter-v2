import os
import shutil
import subprocess
from pathlib import Path

import pytest


ROOT = Path(__file__).parents[1]
LAUNCHER = ROOT / "powershell" / "ise-cli"
PROFILE = ROOT / "powershell" / "Ise.Cli.Profile.ps1"
MODULE = ROOT / "powershell" / "Ise.Cli" / "Ise.Cli.psm1"
MANIFEST = ROOT / "powershell" / "Ise.Cli" / "Ise.Cli.psd1"
INSTALLER = ROOT / "deploy" / "install.sh"


def test_profile_has_isolated_history_completion_prompt_and_banner():
    profile = PROFILE.read_text()

    for expected in (
        "XDG_STATE_HOME",
        "HistorySavePath",
        "PredictionSource History",
        "MenuComplete",
        "ReverseSearchHistory",
        "Show-IseCliBanner",
        "Read-only | cached-first | bounded defaults",
        "function global:prompt",
    ):
        assert expected in profile


def test_new_operator_workflows_have_context_completion():
    module = MODULE.read_text()

    for command in (
        "Get-IseEndpointSummary",
        "Debug-IseAuthentication",
        "Debug-IsePsn",
        "Get-IseNadSummary",
    ):
        assert command in module
    assert "'Get-IseEndpointSummary' { 'endpoint-summary' }" in module
    assert "'Debug-IseAuthentication' { 'troubleshoot-auth' }" in module


def test_launcher_falls_back_to_bounded_backend_without_pwsh(tmp_path):
    backend = tmp_path / "ise-cli-backend"
    backend.write_text("#!/bin/sh\nprintf '%s\\n' \"$*\"\n")
    backend.chmod(0o755)
    env = os.environ | {
        "ISE_CLI_BACKEND": str(backend),
        "ISE_CLI_FORCE_BACKEND": "1",
    }

    result = subprocess.run(
        [str(LAUNCHER), "endpoints", "--limit", "25"],
        env=env, check=True, text=True, capture_output=True)

    assert result.stdout == "endpoints --limit 25\n"


def test_launcher_remains_shell_safe():
    subprocess.run(
        ["bash", "-n", str(LAUNCHER)],
        check=True,
        env=os.environ,
    )


def test_installed_launcher_resolves_usr_local_style_symlink(tmp_path):
    installed = tmp_path / "opt" / "ise-exporter" / "powershell"
    shutil.copytree(ROOT / "powershell", installed)
    bin_dir = tmp_path / "usr" / "local" / "bin"
    bin_dir.mkdir(parents=True)
    launcher_link = bin_dir / "ise-cli"
    launcher_link.symlink_to(installed / "ise-cli")
    fake_bin = tmp_path / "fake-bin"
    fake_bin.mkdir()
    fake_pwsh = fake_bin / "pwsh"
    fake_pwsh.write_text(
        "#!/bin/sh\n"
        "printf '%s\\n' \"$*\"\n"
        "printf '%s\\n' \"$PSModulePath\"\n")
    fake_pwsh.chmod(0o755)

    result = subprocess.run(
        [str(launcher_link)], check=True, text=True, capture_output=True,
        env=os.environ | {"PATH": f"{fake_bin}:{os.environ['PATH']}"})

    lines = result.stdout.splitlines()
    assert lines[0] == f"-NoLogo -NoProfile -NoExit -File {installed / 'Ise.Cli.Profile.ps1'}"
    assert lines[1].split(":", 1)[0] == str(installed)


def test_installer_deploys_and_verifies_the_global_cli():
    installer = INSTALLER.read_text()

    assert "CLI_LINK=/usr/local/bin/ise-cli" in installer
    assert 'ln -sfn "$PWSH_CLI_DIR/ise-cli" "$CLI_LINK"' in installer
    assert "PowerShell profile/module self-check failed" in installer
    assert 'ISE_CLI_BACKEND="$VENV/bin/ise-cli-backend"' in installer
    assert '"$CLI_LINK" --version' in installer
    assert "installed ise-cli launcher/backend self-check failed" in installer


@pytest.mark.skipif(shutil.which("pwsh") is None, reason="PowerShell 7 is not installed")
def test_powershell_bulk_wrappers_send_bounded_defaults(tmp_path):
    calls = tmp_path / "calls"
    backend = tmp_path / "ise-cli-backend"
    backend.write_text(
        "#!/bin/sh\n"
        f"printf '%s\\n' \"$*\" >> '{calls}'\n"
        "printf '%s\\n' '[]'\n")
    backend.chmod(0o755)
    script = f"""
        $ErrorActionPreference = 'Stop'
        $env:ISE_CLI_BACKEND = '{backend}'
        Import-Module '{MANIFEST}' -Force
        Get-IseNode | Out-Null
        Get-IseRepository | Out-Null
        Get-IseCertificate -TrustedOnly | Out-Null
    """

    subprocess.run(
        ["pwsh", "-NoLogo", "-NoProfile", "-Command", script], check=True)

    assert calls.read_text().splitlines() == [
        "nodes --limit 50 --output json",
        "repositories --limit 100 --output json",
        "certificates --limit 100 --trusted-only --output json",
    ]
