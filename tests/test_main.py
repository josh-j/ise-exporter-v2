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
        state_db_path=":memory:",
        rest_auth_guard_file="",
        dataconnect_auth_guard_file="",
        dataconnect_shared_pacing_file="",
    )
    values.update(overrides)
    cfg = types.SimpleNamespace(**values)
    cfg.summary = lambda: "test-config"
    return cfg


@pytest.fixture(autouse=True)
def _runtime_lock(monkeypatch):
    monkeypatch.setattr(app, "acquire_runtime_lock", lambda _path: 123)
    monkeypatch.setattr(app, "release_runtime_lock", lambda _descriptor: None)


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


@pytest.mark.parametrize(("override", "message"), (
    ({"ise_host": "https://pan.example"}, "ISE_HOST must be a bare"),
    ({"dataconnect_host": "reader@mnt.example"},
     "ISE_DATACONNECT_HOST must be a bare"),
    ({"ise_mnt_host": "mnt.example/admin", "collect_mnt_active_posture": True},
     "ISE_MNT_HOST must be a bare"),
))
def test_main_rejects_ambiguous_authenticated_targets(
        monkeypatch, caplog, override, message):
    values = {
        "ise_mnt_host": "mnt.example", "collect_mnt_active_posture": True,
        "collect_tacacs": True, **override,
    }
    cfg = _cfg(**values)
    monkeypatch.setattr(app, "Config", types.SimpleNamespace(from_env=lambda: cfg))

    assert app.main([]) == 1
    assert message in caplog.text


def test_reset_state_switch_is_one_shot_and_clears_every_state_plane(
        monkeypatch, caplog):
    cfg = _cfg(
        state_db_path="/state.sqlite3",
        rest_auth_guard_file="/rest.guard",
        dataconnect_auth_guard_file="/dataconnect.guard",
        dataconnect_shared_pacing_file="/dataconnect.pacing",
    )
    seen = []
    monkeypatch.setattr(app, "Config", types.SimpleNamespace(from_env=lambda: cfg))
    monkeypatch.setattr(
        app, "reset_exporter_state",
        lambda state, guards: seen.append((state, guards)) or (
            state, *guards),
    )
    monkeypatch.setattr(
        app, "ISEControlPlaneClient",
        lambda *_args, **_kwargs: (_ for _ in ()).throw(
            AssertionError("reset must exit before creating API clients")),
    )

    assert app.main(["--reset-state"]) == 0
    assert seen == [(
        "/state.sqlite3",
        ("/rest.guard", "/dataconnect.guard", "/dataconnect.pacing"),
    )]
    assert "reset removed /dataconnect.pacing" in caplog.text


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


def test_compatibility_failure_closes_control_plane_client(monkeypatch):
    closed = []

    class Client:
        def __init__(self, cfg, auth_guard=None):
            pass

        def close(self):
            closed.append("control")

    monkeypatch.setattr(app, "Config", types.SimpleNamespace(from_env=lambda: _cfg(
        ise_mnt_host="", collect_mnt_active_posture=False)))
    monkeypatch.setattr(app, "ISEControlPlaneClient", Client)
    monkeypatch.setattr(
        app, "validate_ise_compatibility",
        lambda _client: (_ for _ in ()).throw(app.ISECompatibilityError("unsupported")),
    )

    assert app.main([]) == 1
    assert closed == ["control"]


def test_schema_discovery_is_scheduler_owned_after_metrics_start(monkeypatch):
    closed = []
    events = []

    class Control:
        def __init__(self, cfg, auth_guard=None):
            pass

        def close(self):
            closed.append("control")

    class DataConnect:
        def __init__(self, cfg):
            self.schema_ready = False
            self.dataset_schema_failures = {}

        def query(self, *_args, **_kwargs):
            raise AssertionError("main must not query Data Connect before metrics start")

        def close(self):
            closed.append("dataconnect")
            raise RuntimeError("database close failed")

    class Scheduler:
        dataconnect_worker_alive = False
        mnt_worker_alive = False

        def __init__(self, cfg, client, dataconnect, mnt):
            assert client.propagate_failures is True
            events.append(("scheduler", dataconnect.schema_ready))

        def loop(self, shutdown):
            events.append(("loop", shutdown.is_set()))

    compatibility = types.SimpleNamespace(
        ise_version="3.3.0.430", patch_level=11, deployment_nodes=("ise-1",))
    monkeypatch.setattr(app, "Config", types.SimpleNamespace(from_env=lambda: _cfg(
        ise_mnt_host="", collect_mnt_active_posture=False, collect_tacacs=True)))
    monkeypatch.setattr(app, "ISEControlPlaneClient", Control)
    monkeypatch.setattr(app, "DataConnectClient", DataConnect)
    monkeypatch.setattr(app, "validate_ise_compatibility", lambda _client: compatibility)
    monkeypatch.setattr(
        app, "start_http_server",
        lambda *_args, **_kwargs: events.append(("metrics", True)))
    monkeypatch.setattr(app, "PollScheduler", Scheduler)

    assert app.main([]) == 0
    assert events == [
        ("metrics", True), ("scheduler", False), ("loop", False),
    ]
    assert closed == ["dataconnect", "control"]


def test_stop_metrics_server_closes_listener_and_joins_thread():
    calls = []

    class Server:
        def shutdown(self):
            calls.append("shutdown")

        def server_close(self):
            calls.append("server_close")

    class Thread:
        def join(self, timeout):
            calls.append(("join", timeout))

        def is_alive(self):
            return False

    app._stop_metrics_server((Server(), Thread()))

    assert calls == ["shutdown", "server_close", ("join", 2)]


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


def test_deployment_env_wins_over_local_dotenv_but_not_process_env(
        monkeypatch, tmp_path):
    env_file = tmp_path / "deployed.env"
    env_file.write_text("ISE_HOST=deployed-pan.example\n")
    (tmp_path / ".env").write_text("ISE_HOST=local-dev-pan.example\n")
    monkeypatch.chdir(tmp_path)
    monkeypatch.setattr(app, "DEPLOY_ENV_FILE", str(env_file))
    monkeypatch.delenv("ISE_HOST", raising=False)

    app._load_env()

    assert os.environ["ISE_HOST"] == "deployed-pan.example"

    monkeypatch.setenv("ISE_HOST", "systemd-pan.example")
    app._load_env()
    assert os.environ["ISE_HOST"] == "systemd-pan.example"


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
