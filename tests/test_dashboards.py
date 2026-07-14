import ast
import json
from pathlib import Path
import re


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


def test_failure_work_queue_uses_failed_authentication_dimensions():
    dashboard = json.loads((DASHBOARDS / "ise-failure-triage.json").read_text())
    panel = next(panel for panel in _panels(dashboard["panels"]) if panel.get("id") == 10)
    work_queue = next(target for target in panel["targets"] if target["refId"] == "A")

    assert "ise_dataconnect_radius_authentication_events" in work_queue["expr"]
    assert "status=~" in work_queue["expr"]
    assert "ise_dataconnect_radius_errors" not in work_queue["expr"]
    assert work_queue["format"] == "table"
    assert work_queue["instant"] is True


def test_failure_nad_panels_use_all_failed_authentications_not_sparse_error_view():
    dashboard = json.loads((DASHBOARDS / "ise-failure-triage.json").read_text())
    panels = {panel["id"]: panel for panel in _panels(dashboard["panels"])}

    for panel_id in (6, 7):
        expression = panels[panel_id]["targets"][0]["expr"]
        assert "ise_dataconnect_radius_authentication_events" in expression
        assert "status=~" in expression
        assert "ise_dataconnect_radius_errors" not in expression


def test_radius_headline_stats_use_exact_totals_not_topk_breakdowns():
    expected = {
        "ise-auth-troubleshooting.json": {
            1: ("ise_dataconnect_radius_authentication_events_total",
                "ise_dataconnect_radius_failure_events_total"),
            2: ("ise_dataconnect_radius_failure_events_total",),
        },
        "ise-failure-triage.json": {
            1: ("ise_dataconnect_radius_failure_events_total",),
            2: ("ise_dataconnect_radius_authentication_events_total",
                "ise_dataconnect_radius_failure_events_total"),
        },
        "ise-sessions-auth.json": {
            2: ("ise_dataconnect_radius_authentication_events_total",),
            3: ("ise_dataconnect_radius_active_sessions_total",),
        },
    }

    for name, panel_contracts in expected.items():
        dashboard = json.loads((DASHBOARDS / name).read_text())
        panels = {panel["id"]: panel for panel in _panels(dashboard["panels"])}
        for panel_id, exact_metrics in panel_contracts.items():
            expression = panels[panel_id]["targets"][0]["expr"]
            for metric in exact_metrics:
                assert metric in expression
            assert "sum(ise_dataconnect_radius_authentication_events" not in expression
            if "ise_dataconnect_radius_active_sessions_total" in exact_metrics:
                assert "sum(ise_dataconnect_radius_active_sessions)" not in expression

    for name in ("ise-auth-troubleshooting.json", "ise-failure-triage.json"):
        text = (DASHBOARDS / name).read_text()
        assert "ise_dataconnect_radius_failure_events_total" in text


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


def test_every_dashboard_defines_prometheus_variable_for_file_provisioning():
    """File provisioning does not resolve __inputs like the import UI does."""
    missing = []
    for path in sorted(DASHBOARDS.glob("*.json")):
        dashboard = json.loads(path.read_text())
        variables = {
            item.get("name"): item
            for item in dashboard.get("templating", {}).get("list", [])
        }
        datasource = variables.get("DS_PROMETHEUS", {})
        if datasource.get("type") != "datasource" or datasource.get("query") != "prometheus":
            missing.append(path.name)

    assert not missing, "Prometheus template variable missing: " + ", ".join(missing)


def test_sessions_dashboard_exposes_accounting_derived_active_sessions():
    text = (DASHBOARDS / "ise-sessions-auth.json").read_text()
    assert "ise_dataconnect_radius_active_sessions" in text


def test_domain_dashboards_expose_authoritative_dataset_availability():
    expected = {
        "ise-auth-troubleshooting.json": {("dataconnect_radius", "dataconnect")},
        "ise-sessions-auth.json": {("dataconnect_radius", "dataconnect")},
        "ise-failure-triage.json": {("dataconnect_radius", "dataconnect")},
        "ise-endpoint-profiles.json": {("dataconnect_endpoints", "dataconnect")},
        "ise-endpoints-devices.json": {("dataconnect_endpoints", "dataconnect")},
        "ise-secureclient.json": {
            ("mnt_active_posture", "mnt"),
            ("dataconnect_posture", "dataconnect"),
        },
        "ise-psn-troubleshooting.json": {("dataconnect_performance", "dataconnect")},
        "ise-tacacs.json": {
            ("tacacs_config", "rest"),
            ("tacacs_activity", "dataconnect"),
        },
    }
    for name, datasets in expected.items():
        dashboard = json.loads((DASHBOARDS / name).read_text())
        expressions = {
            target["expr"]
            for panel in _panels(dashboard["panels"])
            for target in panel.get("targets", [])
        }
        for dataset, source in datasets:
            selector = f'ise_dataset_up{{dataset="{dataset}",source="{source}"}}'
            assert any(selector in expression for expression in expressions), (
                f"{name} has no visible availability query for {dataset}/{source}")


def test_domain_queries_do_not_mask_outages_as_unconditional_zero():
    violations = []
    for path in sorted(DASHBOARDS.glob("*.json")):
        if path.name == "ise-overview.json":
            continue
        dashboard = json.loads(path.read_text())
        for panel in _panels(dashboard.get("panels", [])):
            for target in panel.get("targets", []):
                expression = target.get("expr", "")
                if "or vector(0)" in expression:
                    violations.append(f"{path.name}: panel {panel.get('id')} uses bare vector(0)")
                if "or on() (0 *" in expression and not (
                        "ise_dataset_up" in expression and "== 1" in expression):
                    violations.append(
                        f"{path.name}: panel {panel.get('id')} zero fallback is not up-gated")
                if (path.name != "ise-data-quality.json"
                        and "or on() (0 *" in expression
                        and "and on()" not in expression.split(" or on() (0 *", 1)[0]):
                    violations.append(
                        f"{path.name}: panel {panel.get('id')} stale value is not up-gated")

    assert not violations, "outage-masking dashboard queries: " + ", ".join(violations)


def test_secureclient_dashboard_separates_active_mnt_from_historical_dataconnect():
    dashboard = json.loads((DASHBOARDS / "ise-secureclient.json").read_text())
    panels = {panel["title"]: panel for panel in _panels(dashboard["panels"])}

    active_contracts = {
        "Active Posture Status (MnT)": "ise_mnt_active_posture_endpoints",
        "Active Secure Client / Posture Agent Versions (MnT)":
            "ise_mnt_active_secure_client_endpoints",
        "Active Endpoints by OS (MnT)": "sum by (os) (ise_mnt_active_posture_endpoints)",
        "Active Endpoints by PSN (MnT)": "sum by (psn, status)",
        "Active Posture Policies: Passed vs Failed (MnT)":
            "ise_mnt_active_posture_policy_results",
        "Failed Active Posture Policies (MnT)": "ise_mnt_active_posture_policy_results",
    }
    for title, expected_metric in active_contracts.items():
        expressions = " ".join(target["expr"] for target in panels[title]["targets"])
        assert expected_metric in expressions
        assert "ise_dataconnect_" not in expressions

    historical = (
        "Historical Policy/Condition Results (Data Connect)",
        "Historical Failed Conditions (Data Connect)",
        "Historical Posture Failure Work Queue (Data Connect)",
        "Historical Assessments by Agent Version (Data Connect)",
        "Historical Assessments by OS (Data Connect)",
        "Historical Assessments by PSN (Data Connect)",
    )
    for title in historical:
        expressions = " ".join(target["expr"] for target in panels[title]["targets"])
        assert "ise_dataconnect_posture_" in expressions
        assert "ise_mnt_active_" not in expressions


def test_secureclient_dashboard_exposes_mnt_sample_quality():
    dashboard = json.loads((DASHBOARDS / "ise-secureclient.json").read_text())
    text = " ".join(
        target["expr"]
        for panel in _panels(dashboard["panels"])
        for target in panel.get("targets", [])
    )
    for metric in (
        "ise_dataset_up{dataset=\"mnt_active_posture\",source=\"mnt\"}",
        "ise_dataset_last_success_timestamp{dataset=\"mnt_active_posture\",source=\"mnt\"}",
        "ise_mnt_active_posture_detail_coverage_ratio",
        "ise_mnt_active_posture_detail_truncated",
        "ise_mnt_active_posture_field_coverage_ratio",
    ):
        assert metric in text


def _exported_metric_names():
    metrics_path = DASHBOARDS.parent / "ise_exporter/metrics.py"
    tree = ast.parse(metrics_path.read_text())
    names = set()
    for node in ast.walk(tree):
        if not isinstance(node, ast.Assign) or not isinstance(node.value, ast.Call):
            continue
        call = node.value
        if not isinstance(call.func, ast.Name) or not call.args:
            continue
        kind = call.func.id
        if kind not in {"Gauge", "Counter", "Histogram", "Info", "Enum"}:
            continue
        if not isinstance(call.args[0], ast.Constant):
            continue
        base = call.args[0].value
        if kind == "Info":
            names.add(f"{base}_info")
        else:
            names.add(base)
        if kind == "Histogram":
            names.update(f"{base}_{suffix}" for suffix in ("bucket", "count", "sum", "created"))
        if kind == "Counter":
            counter_base = base.removesuffix("_total")
            names.update((f"{counter_base}_total", f"{counter_base}_created"))
    return names


def test_every_dashboard_metric_exists_in_the_registry_contract():
    exported = _exported_metric_names()
    missing = []
    for path in sorted(DASHBOARDS.glob("*.json")):
        dashboard = json.loads(path.read_text())
        for panel in _panels(dashboard.get("panels", [])):
            for target in panel.get("targets", []):
                referenced = set(re.findall(r"\bise_[a-zA-Z0-9_]+\b", target.get("expr", "")))
                for metric in sorted(referenced - exported):
                    missing.append(f"{path.name}: panel {panel.get('id')}: {metric}")

    assert not missing, "dashboard references unknown metrics: " + ", ".join(missing)


def test_data_quality_dashboard_exposes_collection_and_source_freshness():
    text = (DASHBOARDS / "ise-data-quality.json").read_text()
    for metric in (
        "ise_dataset_enabled",
        "ise_dataset_up",
        "ise_dataset_fresh",
        "ise_dataset_last_attempt_timestamp",
        "ise_dataset_last_success_timestamp",
        "ise_dataconnect_view_rows",
        "ise_dataconnect_view_newest_event_timestamp",
        "ise_dataconnect_view_oldest_event_timestamp",
        "ise_mnt_active_posture_detail_coverage_ratio",
        "ise_mnt_active_posture_detail_truncated",
        "ise_mnt_active_posture_field_coverage_ratio",
        "ise_mnt_active_posture_cache_entries",
        "ise_mnt_active_posture_refresh_deferred",
        "ise_mnt_active_posture_cache_oldest_age_seconds",
        "ise_dataconnect_incremental_mode",
        "ise_dataconnect_reconciliation_age_seconds",
    ):
        assert metric in text


def test_data_quality_dashboard_does_not_render_empty_views_as_epoch_old():
    dashboard = json.loads((DASHBOARDS / "ise-data-quality.json").read_text())
    panel = next(panel for panel in _panels(dashboard["panels"]) if panel.get("id") == 6)
    expressions = {target["refId"]: target["expr"] for target in panel["targets"]}

    assert "ise_dataconnect_view_newest_event_timestamp > 0" in expressions[
        "Newest event age"]
    assert "ise_dataconnect_view_rows > 0" in expressions["Window span"]


def test_data_quality_summary_stats_are_gated_by_authoritative_datasets():
    dashboard = json.loads((DASHBOARDS / "ise-data-quality.json").read_text())
    panels = {panel["id"]: panel for panel in _panels(dashboard["panels"])}

    assert "0 * (count(ise_dataset_up) > 0)" in panels[1]["targets"][0]["expr"]
    assert "0 * (count(ise_dataset_up) > 0)" in panels[2]["targets"][0]["expr"]
    assert 'dataset="dataconnect_freshness"' in panels[3]["targets"][0]["expr"]
    truncation = panels[4]["targets"][0]["expr"]
    for dataset in (
            "dataconnect_radius", "dataconnect_posture", "dataconnect_endpoints",
            "dataconnect_performance"):
        assert dataset in truncation
    assert truncation.count("max(ise_dataset_up") == 4


def test_psn_diagnostic_headline_uses_exact_total_not_topk_breakdown():
    dashboard = json.loads((DASHBOARDS / "ise-psn-troubleshooting.json").read_text())
    panel = next(panel for panel in _panels(dashboard["panels"]) if panel.get("id") == 4)
    expression = panel["targets"][0]["expr"]

    assert "ise_dataconnect_diagnostic_events_total" in expression
    assert "sum(ise_dataconnect_diagnostic_events)" not in expression


def test_disconnected_node_stat_is_zero_when_all_nodes_are_healthy():
    text = (DASHBOARDS / "ise-data-quality.json").read_text()

    assert ('sum(ise_deployment_status{ise_deployment_status=\\"Disconnected\\"})'
            in text)
    assert "sum(ise_deployment_status == bool 2)" not in text
    assert "sum(ise_deployment_status == 2)" not in text


def test_overview_freshness_uses_each_datasets_published_effective_interval():
    dashboard = json.loads((DASHBOARDS / "ise-overview.json").read_text())
    panel = next(panel for panel in _panels(dashboard["panels"]) if panel.get("id") == 29)
    expression = panel["targets"][0]["expr"]

    assert "ise_dataset_last_success_timestamp" in expression
    assert "on(dataset,source) ise_dataset_effective_interval_seconds" in expression
    assert "/ 60" not in expression
    assert "/ 300" not in expression
    assert "/ 3600" not in expression
