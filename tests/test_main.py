import os
import types

import pytest

import ise_exporter.__main__ as app
import ise_exporter
from ise_exporter import metrics


def _cfg(**overrides):
    values = dict(
        log_level="INFO",
        ise_host="pan.example",
        dataconnect_host="mnt.example",
        dataconnect_user="dataconnect",
        dataconnect_password="secret",
        dataconnect_ready=True,
        exporter_port=9618,
    )
    values.update(overrides)
    cfg = types.SimpleNamespace(**values)
    cfg.summary = lambda: "test-config"
    return cfg


def test_exporter_version_reports_revision_and_exact_ise_target(monkeypatch, capsys):
    monkeypatch.setenv("ISE_EXPORTER_BUILD_REVISION", "abc1234")

    with pytest.raises(SystemExit) as exited:
        app.main(["--version"])

    assert exited.value.code == 0
    assert capsys.readouterr().out == (
        "ise-exporter 2.0.0 (revision abc1234; Cisco ISE 3.3.0.430 Patch 11)\n")


def test_build_revision_falls_back_to_bounded_installer_marker(
        monkeypatch, tmp_path):
    marker = tmp_path / "REVISION"
    marker.write_text("deadbeef1234\n")
    monkeypatch.delenv("ISE_EXPORTER_BUILD_REVISION", raising=False)
    monkeypatch.setattr(ise_exporter, "BUILD_REVISION_FILE", str(marker))

    assert ise_exporter.build_revision() == "deadbeef1234"

    marker.write_text("x" * 65)
    assert ise_exporter.build_revision() == "unknown"


def test_main_publishes_bounded_build_identity(monkeypatch):
    monkeypatch.setenv("ISE_EXPORTER_BUILD_REVISION", "not a valid label value!")
    monkeypatch.setattr(app, "Config", types.SimpleNamespace(from_env=lambda: _cfg(
        ise_host="", dataconnect_ready=False)))

    assert app.main([]) == 1

    samples = metrics.ise_exporter_build_info.collect()[0].samples
    assert any(sample.labels == {
        "version": "2.0.0", "revision": "unknown",
        "target_ise_release": "3.3.0.430 Patch 11",
    } for sample in samples)


def test_dataconnect_check_validates_contract_and_closes(monkeypatch):
    calls = []

    class Client:
        def __init__(self, cfg):
            calls.append("init")

        def close(self):
            calls.append("close")

    monkeypatch.setattr(app, "DataConnectClient", Client)
    monkeypatch.setattr(
        app, "validate_dataconnect_schema",
        lambda client, include_tacacs: calls.append((client, include_tacacs)) or {"A": {}},
    )
    assert app.dataconnect_check(_cfg()) == 0
    assert calls[0] == "init"
    assert calls[1][1] is True
    assert calls[-1] == "close"


def test_dataconnect_check_requires_credentials():
    assert app.dataconnect_check(_cfg(dataconnect_ready=False)) == 1


def test_dataconnect_schema_prints_catalog_metadata_and_closes(monkeypatch, capsys):
    calls = []

    class Client:
        def __init__(self, cfg):
            calls.append("init")

        def query(self, sql):
            calls.append(sql)
            return [{"table_name": "RADIUS_ACCOUNTING", "column_name": "ACCT_SESSION_ID"}]

        def close(self):
            calls.append("close")

    monkeypatch.setattr(app, "DataConnectClient", Client)
    assert app.dataconnect_schema(_cfg()) == 0
    assert '"table_name": "RADIUS_ACCOUNTING"' in capsys.readouterr().out
    assert "user_tab_columns" in calls[1]
    assert calls[-1] == "close"


def test_load_env_reads_deployment_env_file(monkeypatch, tmp_path):
    env_file = tmp_path / "ise-exporter.env"
    env_file.write_text("ISE_DATACONNECT_HOST=deployed-host.example\n")
    monkeypatch.setattr(app, "DEPLOY_ENV_FILE", str(env_file))
    monkeypatch.delenv("ISE_DATACONNECT_HOST", raising=False)
    try:
        app._load_env()
        assert os.environ.get("ISE_DATACONNECT_HOST") == "deployed-host.example"
    finally:
        os.environ.pop("ISE_DATACONNECT_HOST", None)


def test_load_env_preserves_literal_value_after_first_equals(monkeypatch, tmp_path):
    env_file = tmp_path / "ise-exporter.env"
    env_file.write_text(
        "ISE_PASS=left=middle=right\n"
        "ISE_DATACONNECT_PASSWORD='secret # 1=name=value'\n"
    )
    monkeypatch.chdir(tmp_path)
    monkeypatch.setattr(app, "DEPLOY_ENV_FILE", str(env_file))
    for key in ("ISE_PASS", "ISE_DATACONNECT_PASSWORD"):
        monkeypatch.delenv(key, raising=False)

    app._load_env()

    assert os.environ["ISE_PASS"] == "left=middle=right"
    assert os.environ["ISE_DATACONNECT_PASSWORD"] == "secret # 1=name=value"
