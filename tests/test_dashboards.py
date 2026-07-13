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


def test_failure_work_queue_context_is_limited_to_failing_nads():
    dashboard = json.loads((DASHBOARDS / "ise-failure-triage.json").read_text())
    panel = next(panel for panel in _panels(dashboard["panels"]) if panel.get("id") == 14)
    passed_context = next(target for target in panel["targets"] if target["refId"] == "B")

    assert 'status="passed"' in passed_context["expr"]
    assert 'status="failed"' in passed_context["expr"]
    assert "and on (nad_hostname, location, ops_owner)" in passed_context["expr"]
