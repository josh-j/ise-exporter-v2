import json
from pathlib import Path


DASHBOARDS = Path(__file__).parents[1] / "dashboards"


def _panels(panels):
    for panel in panels:
        yield panel
        yield from _panels(panel.get("panels", []))


def test_visible_table_footers_include_legacy_reducer():
    """Grafana 13's table migration reads reducer[0] when a footer is shown."""
    missing = []
    for path in sorted(DASHBOARDS.glob("*.json")):
        dashboard = json.loads(path.read_text())
        for panel in _panels(dashboard.get("panels", [])):
            footer = panel.get("options", {}).get("footer", {})
            if panel.get("type") == "table" and footer.get("show"):
                if not footer.get("reducer"):
                    missing.append(f"{path.name}: panel {panel.get('id')}")

    assert not missing, "visible table footer missing reducer: " + ", ".join(missing)


def test_failure_work_queue_uses_dataconnect_error_dimensions():
    dashboard = json.loads((DASHBOARDS / "ise-failure-triage.json").read_text())
    panel = next(panel for panel in _panels(dashboard["panels"]) if panel.get("id") == 10)
    work_queue = next(target for target in panel["targets"] if target["refId"] == "A")

    assert "ise_dataconnect_radius_errors" in work_queue["expr"]
    assert work_queue["format"] == "table"
    assert work_queue["instant"] is True


def test_dashboards_do_not_reference_removed_collection_planes():
    forbidden = ("ise_pxgrid_", "ise_session_", "ise_endpoint_attribute_", "ise_endpoints_pxgrid_")
    violations = []
    for path in sorted(DASHBOARDS.glob("*.json")):
        text = path.read_text().lower()
        for metric in forbidden:
            if metric in text:
                violations.append(f"{path.name}: {metric}")

    assert not violations, "removed collection-plane metric references: " + ", ".join(violations)


def test_pxgrid_dashboard_is_removed():
    assert not (DASHBOARDS / "ise-pxgrid-health.json").exists()


def test_removed_runtime_cannot_return_through_config_or_imports():
    root = DASHBOARDS.parent
    config_text = (root / "ise_exporter/config.py").read_text().upper()
    main_text = (root / "ise_exporter/__main__.py").read_text().lower()
    assert "PXGRID" not in config_text
    assert "pxgrid" not in main_text
    assert not (root / "ise_exporter/clients/pxgrid.py").exists()


def test_every_prometheus_target_uses_imported_datasource():
    missing = []
    for path in sorted(DASHBOARDS.glob("*.json")):
        dashboard = json.loads(path.read_text())
        inputs = {item.get("name") for item in dashboard.get("__inputs", [])}
        if "DS_PROMETHEUS" not in inputs:
            missing.append(f"{path.name}: dashboard input")
        for panel in _panels(dashboard.get("panels", [])):
            for target in panel.get("targets", []):
                datasource = target.get("datasource", {})
                if datasource.get("uid") != "${DS_PROMETHEUS}":
                    missing.append(f"{path.name}: panel {panel.get('id')}")

    assert not missing, "Prometheus datasource not wired: " + ", ".join(missing)


def test_sessions_dashboard_exposes_accounting_derived_active_sessions():
    text = (DASHBOARDS / "ise-sessions-auth.json").read_text()
    assert "ise_dataconnect_radius_active_sessions" in text
