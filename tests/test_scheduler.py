import types

import ise_exporter.scheduler as scheduler_module
from ise_exporter.scheduler import PollScheduler


def _cfg(**overrides):
    values = dict(
        collect_certificates=False,
        collect_licensing=False,
        collect_backup_status=False,
        collect_patches=False,
        collect_tacacs=True,
        fast_interval=60,
        medium_interval=300,
        slow_interval=3600,
    )
    values.update(overrides)
    return types.SimpleNamespace(**values)


def test_collection_plan_has_one_writer_per_reporting_domain(monkeypatch):
    ran = []
    modules = (
        "deployment", "devices", "dataconnect_radius", "dataconnect_performance",
        "dataconnect_posture", "dataconnect_endpoints",
    )
    for name in modules:
        monkeypatch.setattr(
            getattr(scheduler_module, name), "collect",
            lambda *args, _name=name, **kwargs: ran.append(_name),
        )
    monkeypatch.setattr(
        scheduler_module.tacacs, "collect_config",
        lambda *args, **kwargs: ran.append("tacacs_config"),
    )
    monkeypatch.setattr(
        scheduler_module.tacacs, "collect_activity",
        lambda *args, **kwargs: ran.append("tacacs_activity"),
    )

    PollScheduler(_cfg(), client=object(), dataconnect=object()).run_cycle()

    assert set(ran) == {*modules, "tacacs_config", "tacacs_activity"}
    assert len(ran) == len(set(ran))


def test_scheduler_never_calls_mnt(monkeypatch):
    class Client:
        def get_mnt_xml(self, *args, **kwargs):
            raise AssertionError("MnT must not participate in exporter collection")

    for name in (
        "deployment", "devices", "dataconnect_radius", "dataconnect_performance",
        "dataconnect_posture", "dataconnect_endpoints",
    ):
        monkeypatch.setattr(getattr(scheduler_module, name), "collect", lambda *a, **k: None)

    PollScheduler(_cfg(collect_tacacs=False), Client(), object()).run_cycle()


def test_disabled_control_plane_collectors_do_not_run(monkeypatch):
    for name in ("deployment", "devices", "dataconnect_radius", "dataconnect_performance",
                 "dataconnect_posture", "dataconnect_endpoints"):
        monkeypatch.setattr(getattr(scheduler_module, name), "collect", lambda *a, **k: None)
    for name in ("certificates", "licensing", "backup", "patches"):
        monkeypatch.setattr(
            getattr(scheduler_module, name), "collect",
            lambda *a, _name=name, **k: (_ for _ in ()).throw(
                AssertionError(f"{_name} should be disabled")),
        )

    PollScheduler(_cfg(collect_tacacs=False), object(), object()).run_cycle()
