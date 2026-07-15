from dataclasses import fields
from pathlib import Path

import pytest

from ise_exporter.config import Config, ConfigError


def _write(tmp_path, text):
    path = tmp_path / "config.toml"
    path.write_text(text)
    return path


def test_example_is_complete_and_parseable(monkeypatch):
    path = Path(__file__).parents[1] / "ise-exporter.toml.example"
    monkeypatch.setenv("ISE_PASS", "rest-secret")
    monkeypatch.setenv("ISE_DATACONNECT_PASSWORD", "database-secret")
    monkeypatch.setenv("ISE_PXGRID_PASSWORD", "pxgrid-secret")

    config = Config.load(path)

    assert config.config_file == str(path)
    assert config.ise_host == "pan1.example.com"
    assert config.ise_mnt_host == "mnt1.example.com"
    assert config.ise_pass == "rest-secret"
    assert config.dataconnect_password == "database-secret"
    assert config.pxgrid_password == "pxgrid-secret"
    assert config.pxgrid_ready
    assert config.dataconnect_performance_interval == 900
    assert config.dataconnect_max_duty_cycle_percent == 0.1
    assert config.mnt_active_posture_interval == 900


def test_example_explains_units_safety_and_operational_tradeoffs():
    path = Path(__file__).parents[1] / "ise-exporter.toml.example"
    example = path.read_text()

    for explanation in (
        "Durations are in seconds",
        "dashboards useful soon after a restart",
        "preventing account lockout",
        "Increasing this raises load on the MnT node",
        "one tenth of one percent, not ten percent",
        "PSN CPU, memory, latency, diagnostics, and throughput",
        "Require explicit --allow-expensive",
    ):
        assert explanation in example


def test_toml_groups_map_to_every_runtime_field():
    excluded = {"config_file", "ise_pass", "dataconnect_password"}
    configured = set(Config.__dataclass_fields__) - excluded
    mapped = set(__import__("ise_exporter.config", fromlist=["_TOML_FIELDS"])
                 ._TOML_FIELDS.values())

    assert configured <= mapped


def test_secret_environment_is_the_only_override(monkeypatch, tmp_path):
    path = _write(tmp_path, """
[ise]
host = "toml-pan"
password = "toml-rest-secret"
[dataconnect]
password = "toml-database-secret"
""")
    monkeypatch.setenv("ISE_HOST", "ignored-environment-pan")
    monkeypatch.setenv("ISE_PASS", "environment-rest-secret")
    monkeypatch.setenv("ISE_DATACONNECT_PASSWORD", "environment-database-secret")
    monkeypatch.setenv("ISE_PXGRID_PASSWORD", "environment-pxgrid-secret")

    config = Config.load(path)

    assert config.ise_host == "toml-pan"
    assert config.ise_pass == "environment-rest-secret"
    assert config.dataconnect_password == "environment-database-secret"
    assert config.pxgrid_password == "environment-pxgrid-secret"


def test_config_path_environment_selects_file(monkeypatch, tmp_path):
    path = _write(tmp_path, "[ise]\nhost = 'selected-pan'\n")
    monkeypatch.setenv("ISE_EXPORTER_CONFIG", str(path))

    config = Config.from_env()

    assert config.config_file == str(path)
    assert config.ise_host == "selected-pan"


def test_missing_explicit_file_fails(monkeypatch, tmp_path):
    monkeypatch.setenv("ISE_EXPORTER_CONFIG", str(tmp_path / "missing.toml"))

    with pytest.raises(ConfigError, match="does not exist"):
        Config.load()


def test_unknown_key_fails_instead_of_silently_defaulting(tmp_path):
    path = _write(tmp_path, "[dataconnect]\nquery_timout_seconds = 15\n")

    with pytest.raises(ConfigError, match="dataconnect.query_timout_seconds"):
        Config.load(path)


@pytest.mark.parametrize(("text", "message"), (
    ("[exporter]\nport = '9618'\n", "exporter.port must be int"),
    ("[collectors]\ntacacs = 'yes'\n", "collectors.tacacs must be bool"),
    ("[dataconnect]\nmax_duty_cycle_percent = 0\n", "must be greater than 0"),
    ("[dataconnect]\nquery_timeout_seconds = 30\n", "must be between 5 and 15"),
    ("[exporter]\nscrape_interval_seconds = 0\n", "must be at least 1"),
))
def test_invalid_values_fail_with_the_toml_key(tmp_path, text, message):
    with pytest.raises(ConfigError, match=message):
        Config.load(_write(tmp_path, text))


def test_mnt_tls_inherits_rest_tls_when_omitted(tmp_path):
    path = _write(tmp_path, """
[ise.rest_tls]
verify = false
ca_bundle = "/ca/rest.pem"
""")

    config = Config.load(path)

    assert config.rest_ssl_verify is False
    assert config.mnt_ssl_verify is False
    assert config.mnt_ca_bundle == "/ca/rest.pem"


def test_summary_excludes_passwords(monkeypatch, tmp_path):
    path = _write(tmp_path, "[ise]\nhost = 'pan1.example.com'\n")
    monkeypatch.setenv("ISE_PASS", "super-secret")
    monkeypatch.setenv("ISE_DATACONNECT_PASSWORD", "database-secret")

    summary = Config.load(path).summary()

    assert "super-secret" not in summary
    assert "database-secret" not in summary
    assert "pan1.example.com" in summary


def test_defaults_still_support_direct_test_construction():
    config = Config()

    assert len(fields(config)) > 60
    assert config.state_db_path == "/var/lib/ise-exporter/state.sqlite3"
    assert config.dataconnect_ready is False
