import json
import subprocess
from pathlib import Path


def test_secure_client_curl_uses_exporter_mnt_path_and_parser():
    script = Path(__file__).parents[1] / "tools/curl_secure_client_attributes.sh"
    text = script.read_text()

    assert 'https://${ISE_MNT_HOST}/admin/API/mnt/Session/MACAddress/${mac}' in text
    assert "parse_other_attr_string" in text
    assert "parse_posture_report" in text
    subprocess.run(["bash", "-n", str(script)], check=True)


def test_curl_probes_return_schema_without_credentials_or_network():
    tools = Path(__file__).parents[1] / "tools"
    expected = {
        "curl_ers_endpoint_detail.sh": ("ERS", "ISE_HOST"),
        "curl_mnt_endpoint_attributes.sh": ("MnT XML", "ISE_MNT_HOST"),
        "curl_secure_client_attributes.sh": ("MnT XML", "ISE_MNT_HOST"),
    }
    for name, (api, host_env) in expected.items():
        result = subprocess.run(
            [str(tools / name), "--schema-only"],
            check=True, capture_output=True, text=True, env={},
        )
        schema = json.loads(result.stdout)
        assert schema["api"] == api
        assert schema["host_env"] == host_env


def test_install_script_exposes_cli_to_all_users_without_exposing_config():
    script = (Path(__file__).parents[1] / "deploy/install.sh").read_text()

    assert "CLI_LINK=/usr/local/bin/ise-cli" in script
    assert 'ln -sfn "$VENV/bin/ise-cli" "$CLI_LINK"' in script
    assert 'chmod -R go-w "$VENV"' in script
    assert 'chmod -R a+rX "$VENV"' in script
    assert 'chmod 640 "$ENV_FILE"' in script
    assert 'chmod 750 "$CERTS_DIR"' in script
