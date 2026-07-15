import ast
import json
from pathlib import Path
import re

from ise_exporter.config import Config


DASHBOARDS = Path(__file__).parents[1] / "dashboards"


def _panels(panels):
    for panel in panels:
        yield panel
        yield from _panels(panel.get("panels", []))


def _dashboard(name):
    return json.loads((DASHBOARDS / name).read_text())


def _panel(dashboard, title):
    return next(
        panel for panel in _panels(dashboard["panels"])
        if panel.get("title") == title)


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
    dashboard = _dashboard("ise-access-troubleshooting.json")
    panel = _panel(dashboard, "RADIUS Failure Work Queue")
    work_queue = next(target for target in panel["targets"] if target["refId"] == "A")

    assert "ise_dataconnect_radius_authentication_events" in work_queue["expr"]
    assert "status=~" in work_queue["expr"]
    assert "ise_dataconnect_radius_errors" not in work_queue["expr"]
    assert work_queue["format"] == "table"
    assert work_queue["instant"] is True


def test_failure_nad_panels_use_all_failed_authentications_not_sparse_error_view():
    dashboard = _dashboard("ise-access-troubleshooting.json")

    for title in ("Failing NADs", "Auth Methods at Failing NADs"):
        expression = _panel(dashboard, title)["targets"][0]["expr"]
        assert "ise_dataconnect_radius_authentication_events" in expression
        assert "status=~" in expression
        assert "ise_dataconnect_radius_errors" not in expression


def test_failure_context_panels_expose_summary_reason_profile_and_location():
    dashboard = _dashboard("ise-access-troubleshooting.json")

    for title, label in (("Failure Classes", "failure_class"),
                         ("Failed Authorization Profiles", "authorization_profile"),
                         ("Failure Locations", "location")):
        expression = _panel(dashboard, title)["targets"][0]["expr"]
        assert "ise_dataconnect_radius_failure_events" in expression
        assert label in expression
        assert 'ise_dataset_up{dataset="dataconnect_radius"' in expression


def test_radius_headline_stats_use_exact_totals_not_topk_breakdowns():
    expected = {
        "Pass Rate": ("ise_dataconnect_radius_authentication_events_total",
                      "ise_dataconnect_radius_failure_events_total"),
        "Failed Auth": (
            "ise_dataconnect_radius_failure_events_total",),
        "Active Sessions": ("ise_dataconnect_radius_active_sessions_total",),
        "Acct Starts": ("ise_dataconnect_radius_accounting_event_type_total",),
    }

    dashboard = _dashboard("ise-access-troubleshooting.json")
    for title, exact_metrics in expected.items():
        expression = _panel(dashboard, title)["targets"][0]["expr"]
        for metric in exact_metrics:
            assert metric in expression
        assert "sum(ise_dataconnect_radius_authentication_events" not in expression
        if "ise_dataconnect_radius_active_sessions_total" in exact_metrics:
            assert "sum(ise_dataconnect_radius_active_sessions)" not in expression
        if "ise_dataconnect_radius_accounting_event_type_total" in exact_metrics:
            assert "sum(ise_dataconnect_radius_accounting_events" not in expression


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


def test_dashboard_set_is_consolidated_around_operator_workflows():
    assert {path.name for path in DASHBOARDS.glob("*.json")} == {
        "ise-access-troubleshooting.json",
        "ise-endpoints-devices.json",
        "ise-exporter-health.json",
        "ise-overview.json",
        "ise-psn-troubleshooting.json",
        "ise-secureclient.json",
        "ise-tacacs.json",
    }


def test_distribution_panels_use_readable_horizontal_bars():
    violations = []
    for path in sorted(DASHBOARDS.glob("*.json")):
        dashboard = json.loads(path.read_text())
        for panel in _panels(dashboard.get("panels", [])):
            if panel.get("type") == "piechart":
                violations.append(f"{path.name}: panel {panel.get('id')} uses a pie chart")
                continue
            if panel.get("type") != "bargauge":
                continue
            options = panel.get("options", {})
            thresholds = panel.get("fieldConfig", {}).get(
                "defaults", {}).get("thresholds", {}).get("steps", [])
            if options.get("orientation") != "horizontal":
                violations.append(
                    f"{path.name}: panel {panel.get('id')} is not horizontal")
            if not thresholds:
                violations.append(
                    f"{path.name}: panel {panel.get('id')} uses implicit colors")

    assert not violations, "poor distribution visualizations: " + ", ".join(violations)


def test_dense_endpoint_profile_distribution_is_bounded_for_readable_labels():
    dashboard = _dashboard("ise-endpoints-devices.json")
    panel = _panel(dashboard, "Endpoints by Profile")

    assert panel["type"] == "bargauge"
    assert "topk(10," in panel["targets"][0]["expr"]


def test_safety_limits_render_all_values_without_a_table_frame_picker():
    dashboard = _dashboard("ise-exporter-health.json")
    panel = _panel(dashboard, "Data Connect Enforced Safety Limits")

    assert panel["type"] == "stat"
    assert panel["options"]["orientation"] == "horizontal"
    assert {target["refId"] for target in panel["targets"]} == {"A", "B", "C", "D"}


def test_exporter_health_owns_exporter_data_quality_and_freshness():
    health = (DASHBOARDS / "ise-exporter-health.json").read_text()
    overview = (DASHBOARDS / "ise-overview.json").read_text()

    for metric in (
        "ise_dataset_last_attempt_timestamp",
        "ise_dataset_last_success_timestamp",
        "ise_dataconnect_view_newest_recent_event_timestamp",
        "ise_dataconnect_queue_depth",
        "ise_dataconnect_query_last_duration_seconds",
        "ise_exporter_build_info",
    ):
        assert metric in health
        assert metric not in overview


def test_pxgrid_cannot_return_to_exporter_runtime():
    root = DASHBOARDS.parent
    main_text = (root / "ise_exporter/__main__.py").read_text().lower()
    assert "pxgrid" not in main_text
    cli_text = (root / "ise_exporter/cli.py").read_text().lower()
    assert "clients.pxgrid" in cli_text
    assert (root / "ise_exporter/clients/pxgrid.py").exists()


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


def test_access_dashboard_exposes_accounting_derived_active_sessions():
    text = (DASHBOARDS / "ise-access-troubleshooting.json").read_text()
    assert "ise_dataconnect_radius_active_sessions" in text


def test_domain_dashboards_expose_authoritative_dataset_availability():
    expected = {
        "ise-access-troubleshooting.json": {
            ("dataconnect_radius", "dataconnect"),
            ("dataconnect_radius_active", "dataconnect"),
        },
        "ise-endpoints-devices.json": {
            ("dataconnect_endpoints", "dataconnect"), ("devices", "rest"),
        },
        "ise-secureclient.json": {
            ("mnt_active_posture", "mnt"),
            ("dataconnect_posture", "dataconnect"),
        },
        "ise-psn-troubleshooting.json": {
            ("dataconnect_performance", "dataconnect"), ("deployment", "rest"),
        },
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


def test_tacacs_unused_account_panels_require_activity_and_bound_retention():
    dashboard = json.loads((DASHBOARDS / "ise-tacacs.json").read_text())
    panels = {panel["id"]: panel for panel in _panels(dashboard["panels"])}
    for panel_id in (3, 7):
        expression = panels[panel_id]["targets"][0]["expr"]
        assert "ise_tacacs_account_last_seen_timestamp" in expression
        assert "ise_tacacs_unused_account_review_seconds" in expression
        assert 'dataset="tacacs_config",source="rest"' in expression
        assert 'dataset="tacacs_activity",source="dataconnect"' in expression
    assert "three" in panels[7]["description"].lower()
    assert "raw mnt history" in panels[3]["description"].lower()


def test_tacacs_dashboard_exposes_internal_user_detail_completeness():
    dashboard = json.loads((DASHBOARDS / "ise-tacacs.json").read_text())
    panels = {panel["id"]: panel for panel in _panels(dashboard["panels"])}
    assert "ise_tacacs_internal_user_detail_coverage" in panels[13]["targets"][0]["expr"]
    assert "ise_tacacs_internal_user_detail_refresh_deferred" in \
        panels[14]["targets"][0]["expr"]
    assert "ise_tacacs_internal_user_detail_refresh_failures" in \
        panels[15]["targets"][0]["expr"]
    assert "ise_tacacs_policy_rule_coverage" in panels[16]["targets"][0]["expr"]
    assert "ise_tacacs_policy_rule_refresh_deferred" in \
        panels[17]["targets"][0]["expr"]
    assert "ise_tacacs_policy_rule_refresh_failures" in \
        panels[18]["targets"][0]["expr"]


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
                if (path.name != "ise-exporter-health.json"
                        and "or on() (0 *" in expression
                        and "and on()" not in expression.split(" or on() (0 *", 1)[0]):
                    violations.append(
                        f"{path.name}: panel {panel.get('id')} stale value is not up-gated")

    assert not violations, "outage-masking dashboard queries: " + ", ".join(violations)


def test_every_domain_data_query_is_gated_by_its_authoritative_dataset():
    contracts = (
        (r"ise_dataconnect_radius_active_", "dataconnect_radius_active", "dataconnect"),
        (r"ise_dataconnect_radius_(?!active_)", "dataconnect_radius", "dataconnect"),
        (r"ise_dataconnect_(?:endpoint|profile)",
         "dataconnect_endpoints", "dataconnect"),
        (r"ise_dataconnect_posture_", "dataconnect_posture", "dataconnect"),
        (r"ise_dataconnect_(?:psn|node|diagnostic)",
         "dataconnect_performance", "dataconnect"),
        (r"ise_dataconnect_view_", "dataconnect_freshness", "dataconnect"),
        (r"ise_mnt_active_", "mnt_active_posture", "mnt"),
        (r"ise_tacacs_(?:internal_user|policy)", "tacacs_config", "rest"),
        (r"ise_tacacs_(?:account|events|dataconnect)",
         "tacacs_activity", "dataconnect"),
        (r"ise_network_devices(?:_|_total)", "devices", "rest"),
        (r"ise_(?:deployment_status|node_count|pan_ha_enabled)", "deployment", "rest"),
        (r"ise_certificate", "certificates", "rest"),
        (r"ise_license_", "licensing", "rest"),
        (r"ise_backup_", "backup", "rest"),
        (r"ise_(?:patch_|version_info)", "patches", "rest"),
    )
    violations = []
    for path in sorted(DASHBOARDS.glob("*.json")):
        dashboard = json.loads(path.read_text())
        for panel in _panels(dashboard.get("panels", [])):
            for target in panel.get("targets", []):
                expression = target.get("expr", "")
                for pattern, dataset, source in contracts:
                    if not re.search(pattern, expression):
                        continue
                    selector = f'dataset="{dataset}",source="{source}"'
                    if selector not in expression or "ise_dataset_up" not in expression:
                        violations.append(
                            f"{path.name}: panel {panel.get('id')} lacks {dataset} gate")

    assert not violations, "ungated authoritative data: " + ", ".join(violations)


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


def _exported_metric_labels():
    metrics_path = DASHBOARDS.parent / "ise_exporter/metrics.py"
    tree = ast.parse(metrics_path.read_text())
    result = {}
    for node in ast.walk(tree):
        if not isinstance(node, ast.Assign) or not isinstance(node.value, ast.Call):
            continue
        call = node.value
        if not isinstance(call.func, ast.Name) or len(call.args) < 2:
            continue
        kind = call.func.id
        if kind not in {"Gauge", "Counter", "Histogram", "Info", "Enum"}:
            continue
        if not isinstance(call.args[0], ast.Constant):
            continue
        labels_node = call.args[2] if len(call.args) > 2 else None
        if labels_node is None:
            labels_node = next((keyword.value for keyword in call.keywords
                                if keyword.arg in {"labelnames", "labels"}), None)
        labels = set()
        if isinstance(labels_node, (ast.List, ast.Tuple)):
            labels = {item.value for item in labels_node.elts
                      if isinstance(item, ast.Constant) and isinstance(item.value, str)}
        base = call.args[0].value
        if kind == "Enum":
            labels.add(base)
        metric_names = {f"{base}_info"} if kind == "Info" else {base}
        if kind == "Histogram":
            metric_names.update(f"{base}_{suffix}"
                                for suffix in ("bucket", "count", "sum", "created"))
            result[f"{base}_bucket"] = labels | {"le"}
        if kind == "Counter":
            counter_base = base.removesuffix("_total")
            metric_names.update((f"{counter_base}_total", f"{counter_base}_created"))
        for name in metric_names:
            result.setdefault(name, set()).update(labels)
    return result


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


def test_dashboard_legends_reference_real_metric_labels():
    labels_by_metric = _exported_metric_labels()
    invalid = []
    for path in sorted(DASHBOARDS.glob("*.json")):
        dashboard = json.loads(path.read_text())
        for panel in _panels(dashboard.get("panels", [])):
            for target in panel.get("targets", []):
                legend_labels = set(re.findall(
                    r"\{\{\s*([a-zA-Z_][a-zA-Z0-9_]*)\s*\}\}",
                    target.get("legendFormat", "")))
                if not legend_labels:
                    continue
                referenced = set(re.findall(
                    r"\bise_[a-zA-Z0-9_]+\b", target.get("expr", "")))
                available = set().union(
                    *(labels_by_metric.get(metric, set()) for metric in referenced))
                for label in sorted(legend_labels - available):
                    invalid.append(
                        f"{path.name}: panel {panel.get('id')}: {label}")

    assert not invalid, "dashboard legends reference unknown labels: " + ", ".join(invalid)


def test_dashboard_selectors_reference_real_metric_labels():
    labels_by_metric = _exported_metric_labels()
    invalid = []
    for path in sorted(DASHBOARDS.glob("*.json")):
        dashboard = json.loads(path.read_text())
        for panel in _panels(dashboard.get("panels", [])):
            for target in panel.get("targets", []):
                expression = target.get("expr", "")
                for metric, selector in re.findall(
                        r"\b(ise_[a-zA-Z0-9_]+)\s*\{([^{}]*)\}", expression):
                    used = set(re.findall(
                        r"\b([a-zA-Z_][a-zA-Z0-9_]*)\s*(?:=~|!~|!=|=)", selector))
                    for label in sorted(used - labels_by_metric.get(metric, set())):
                        invalid.append(
                            f"{path.name}: panel {panel.get('id')}: {metric}.{label}")

    assert not invalid, "dashboard selectors reference unknown labels: " + ", ".join(invalid)


def test_dashboard_grouping_references_real_metric_labels():
    labels_by_metric = _exported_metric_labels()
    invalid = []
    for path in sorted(DASHBOARDS.glob("*.json")):
        dashboard = json.loads(path.read_text())
        for panel in _panels(dashboard.get("panels", [])):
            for target in panel.get("targets", []):
                expression = target.get("expr", "")
                referenced = set(re.findall(
                    r"\bise_[a-zA-Z0-9_]+\b", expression))
                available = set().union(
                    *(labels_by_metric.get(metric, set()) for metric in referenced))
                for raw in re.findall(
                        r"\b(?:by|without)\s*\(([^()]*)\)", expression):
                    grouped = {label.strip() for label in raw.split(",") if label.strip()}
                    for label in sorted(grouped - available):
                        invalid.append(
                            f"{path.name}: panel {panel.get('id')}: {label}")

    assert not invalid, "dashboard grouping references unknown labels: " + ", ".join(invalid)


def test_exporter_health_exposes_collection_and_source_freshness():
    text = (DASHBOARDS / "ise-exporter-health.json").read_text()
    for metric in (
        "ise_dataset_enabled",
        "ise_exporter_build_info",
        "ise_dataset_up",
        "ise_dataset_fresh",
        "ise_dataset_last_attempt_timestamp",
        "ise_dataset_last_success_timestamp",
        "ise_dataconnect_view_has_recent_rows",
        "ise_dataconnect_view_newest_recent_event_timestamp",
        "ise_nad_inventory_selected",
        "ise_nad_inventory_total",
        "ise_nad_inventory_truncated",
        "ise_nad_activity_groups_returned",
        "ise_nad_activity_groups_total",
        "ise_nad_activity_groups_truncated",
        "ise_mnt_active_posture_detail_coverage_ratio",
        "ise_mnt_active_posture_detail_truncated",
        "ise_dataconnect_radius_active_groups_truncated",
        "ise_tacacs_topk_truncated",
        "ise_tacacs_internal_user_inventory_truncated",
        "ise_dataconnect_worker_busy",
        "ise_dataconnect_queue_depth",
        "ise_dataconnect_query_last_duration_seconds",
        "ise_dataconnect_oldest_queued_seconds",
        "ise_dataconnect_max_duty_cycle_percent",
        "ise_dataconnect_query_timeout_seconds",
        "ise_dataconnect_result_row_ceiling",
        "ise_dataconnect_result_byte_ceiling",
        "ise_mnt_worker_busy",
        "ise_mnt_session_list_preflight_count",
        "ise_mnt_session_list_ceiling",
        "ise_mnt_session_list_skipped",
    ):
        assert metric in text


def test_dataset_validity_gates_require_both_availability_and_freshness():
    missing = []
    gate = re.compile(r"max\(ise_dataset_up\{([^{}]+)\}\) == 1")
    for path in sorted(DASHBOARDS.glob("*.json")):
        dashboard = json.loads(path.read_text())
        for panel in _panels(dashboard.get("panels", [])):
            for target in panel.get("targets", []):
                expression = target.get("expr", "")
                for selector in gate.findall(expression):
                    expected = (
                        f"max(ise_dataset_fresh{{{selector}}}) == 1")
                    if expected not in expression:
                        missing.append(
                            f"{path.name}: panel {panel.get('id')}: {selector}")

    assert not missing, "dataset gates omit freshness: " + ", ".join(missing)


def test_access_dashboard_gates_active_count_on_active_dataset():
    dashboard = _dashboard("ise-access-troubleshooting.json")
    panel = _panel(dashboard, "Active Sessions")
    expression = panel["targets"][0]["expr"]

    assert 'dataset="dataconnect_radius_active"' in expression
    assert 'dataset="dataconnect_radius",' not in expression


def test_exporter_health_does_not_render_empty_views_as_epoch_old():
    dashboard = _dashboard("ise-exporter-health.json")
    panel = _panel(dashboard, "Data Connect Source-Event Freshness")
    expressions = {target["refId"]: target["expr"] for target in panel["targets"]}

    assert "ise_dataconnect_view_newest_recent_event_timestamp > 0" in expressions[
        "Newest recent event age"]
    assert "ise_dataconnect_view_has_recent_rows" in expressions["Has recent rows"]
    assert "Window span" not in expressions


def test_exporter_health_summary_stats_are_gated_by_authoritative_datasets():
    dashboard = _dashboard("ise-exporter-health.json")

    unavailable = _panel(dashboard, "Unavailable")["targets"][0]["expr"]
    stale = _panel(dashboard, "Stale Datasets")["targets"][0]["expr"]
    views = _panel(dashboard, "Empty Recent Views")["targets"][0]["expr"]
    for expression in (unavailable, stale):
        assert "0 * (count(ise_dataset_up" in expression
        assert 'dataset=~"$dataset",source=~"$source"' in expression
    assert 'dataset="dataconnect_freshness"' in views
    assert "or on() (0 *" in views
    assert "== 1" in views
    truncation = _panel(dashboard, "Truncation")["targets"][0]["expr"]
    for dataset in (
            "dataconnect_radius", "dataconnect_radius_active",
            "dataconnect_posture", "dataconnect_endpoints",
            "dataconnect_performance"):
        assert dataset in truncation
    for dataset in ("tacacs_activity", "tacacs_config"):
        assert dataset in truncation
    # Every term gates both its preserved value and its valid-zero fallback.
    assert truncation.count("max(ise_dataset_up") == 14
    assert truncation.count("max(ise_dataset_fresh") == 14
    assert truncation.count(" and on() ((max(ise_dataset_up") == 7


def test_exporter_health_lists_each_unavailable_dataset_and_latest_reason():
    dashboard = _dashboard("ise-exporter-health.json")
    panel = _panel(dashboard, "Unavailable Dataset Details")
    expression = panel["targets"][0]["expr"]

    assert panel["title"] == "Unavailable Dataset Details"
    assert panel["type"] == "table"
    assert "ise_dataset_last_failure_info" in expression
    assert "ise_dataset_last_failure_detail_info" in expression
    assert 'ise_dataset_enabled{dataset=~"$dataset",source=~"$source"} == 1' in expression
    assert 'ise_dataset_up{dataset=~"$dataset",source=~"$source"} == 0' in expression
    assert 'ise_dataset_fresh{dataset=~"$dataset",source=~"$source"} == 0' in expression
    assert '"not_attempted"' in expression
    assert '"stale"' in expression
    assert '"Last successful collection is older than two configured intervals"' in expression
    assert '"NONE"' in expression
    assert '"All enabled datasets are available and fresh"' in expression
    assert "absent(count(" in expression
    assert panel["targets"][0]["format"] == "table"
    assert panel["targets"][0]["instant"] is True
    assert len(panel["targets"]) == 1
    organize = panel["transformations"][0]
    assert organize["id"] == "organize"
    assert organize["options"]["indexByName"] == {
        "dataset": 0, "source": 1, "reason": 2, "detail": 3,
    }
    assert organize["options"]["renameByName"]["reason"] == "Failure category"
    assert organize["options"]["renameByName"]["detail"] == "Why unavailable"

    age_panel = _panel(dashboard, "Dataset Collection Attempt and Success Age")
    ages = {target["refId"]: target["expr"] for target in age_panel["targets"]}
    assert "ise_dataset_last_attempt_timestamp" in ages["Attempt age"]
    assert "ise_dataset_last_success_timestamp" in ages["Success age"]


def test_access_dashboard_collection_age_thresholds_match_domain_cadences():
    dashboard = _dashboard("ise-access-troubleshooting.json")
    panel = _panel(dashboard, "Collection Age")

    defaults = panel["fieldConfig"]["defaults"]["thresholds"]["steps"]
    assert [step["value"] for step in defaults] == [None, 129600, 172800]
    active = panel["fieldConfig"]["overrides"][0]
    assert active["matcher"] == {"id": "byFrameRefID", "options": "Active sessions"}
    steps = active["properties"][0]["value"]["steps"]
    assert [step["value"] for step in steps] == [None, 2700, 3600]


def test_dashboard_age_thresholds_match_production_collection_cadences():
    config = Config.load(DASHBOARDS.parent / "ise-exporter.toml.example")
    slow_interval = config.slow_interval
    expected = {
        ("ise-access-troubleshooting.json", "Collection Age"):
            (129600, 172800),
        ("ise-endpoints-devices.json", "Dataset Collection Age"):
            (129600, 172800),
        ("ise-psn-troubleshooting.json", "Dataset Collection Age"): (1350, 1800),
        ("ise-secureclient.json", "Active Snapshot Age (MnT)"): (1350, 1800),
        ("ise-secureclient.json", "Historical Snapshot Age (Data Connect)"):
            (32400, 43200),
        ("ise-tacacs.json", "Configuration Collection Age"): (
            slow_interval * 3 // 2, slow_interval * 2),
        ("ise-tacacs.json", "Activity Collection Age"): (32400, 43200),
    }
    for (filename, title), thresholds in expected.items():
        dashboard = _dashboard(filename)
        panel = _panel(dashboard, title)
        steps = panel["fieldConfig"]["defaults"]["thresholds"]["steps"]
        assert tuple(step["value"] for step in steps[1:]) == thresholds


def test_psn_troubleshooting_refresh_matches_prometheus_scrape_cadence():
    dashboard = _dashboard("ise-psn-troubleshooting.json")

    assert dashboard["refresh"] == "1m"


def test_exporter_health_domain_panels_do_not_publish_stale_values_during_outages():
    dashboard = _dashboard("ise-exporter-health.json")
    ownership = {
        "Posture Coverage": "dataconnect_posture",
        "Unknown Endpoint Profiles": "dataconnect_endpoints",
        "Endpoints Stale 90d": "dataconnect_endpoints",
        "MnT Detail Coverage": "mnt_active_posture",
        "MnT Detail Truncated": "mnt_active_posture",
    }

    for title, datasets in ownership.items():
        if isinstance(datasets, str):
            datasets = (datasets,)
        targets = _panel(dashboard, title)["targets"]
        expected = datasets if len(datasets) > 1 else datasets * len(targets)
        assert len(targets) == len(expected)
        for target, dataset in zip(targets, expected, strict=True):
            expression = target["expr"]
            assert f'dataset="{dataset}"' in expression, (title, expression)
            assert "ise_dataset_up" in expression, (title, expression)
            assert "== 1" in expression, (title, expression)


def test_nad_health_panels_require_fresh_inventory_and_activity_sources():
    dashboard = _dashboard("ise-exporter-health.json")

    for title in ("NAD Inventory Export Coverage", "NAD Activity Group Coverage"):
        for target in _panel(dashboard, title)["targets"]:
            expression = target["expr"]
            for dataset, source in (
                    ("dataconnect_nad_health", "dataconnect"),
                    ("devices", "rest")):
                selector = f'dataset="{dataset}",source="{source}"'
                assert f"ise_dataset_up{{{selector}}}" in expression
                assert f"ise_dataset_fresh{{{selector}}}" in expression


def test_unknown_endpoint_profile_stat_uses_exact_inventory_total():
    dashboard = _dashboard("ise-exporter-health.json")
    panel = _panel(dashboard, "Unknown Endpoint Profiles")
    expression = panel["targets"][0]["expr"]

    assert "ise_dataconnect_endpoints_unknown_profile_total" in expression
    assert "ise_dataconnect_endpoints_by_profile" not in expression


def test_endpoint_dashboard_exposes_dataconnect_field_coverage():
    dashboard = json.loads((DASHBOARDS / "ise-endpoints-devices.json").read_text())
    panel = next(panel for panel in _panels(dashboard["panels"]) if panel.get("id") == 12)
    expression = panel["targets"][0]["expr"]

    assert "ise_dataconnect_endpoint_field_coverage_ratio" in expression
    assert 'dataset="dataconnect_endpoints"' in expression
    assert "ise_dataset_up" in expression
    assert panel["fieldConfig"]["defaults"]["unit"] == "percentunit"


def test_endpoint_dashboard_exposes_bounded_nad_detail_completeness():
    dashboard = json.loads((DASHBOARDS / "ise-endpoints-devices.json").read_text())
    panels = {panel["id"]: panel for panel in _panels(dashboard["panels"])}

    assert "ise_network_device_detail_coverage" in panels[13]["targets"][0]["expr"]
    assert panels[13]["fieldConfig"]["defaults"]["unit"] == "percentunit"
    assert "ise_network_device_detail_refresh_deferred" in \
        panels[14]["targets"][0]["expr"]
    assert "ise_network_device_detail_refresh_failures" in \
        panels[15]["targets"][0]["expr"]
    for panel_id in (13, 14, 15):
        expression = panels[panel_id]["targets"][0]["expr"]
        assert 'ise_dataset_up{dataset="devices",source="rest"}' in expression
        assert "== 1" in expression


def test_endpoint_dashboard_hides_stale_rest_device_snapshots():
    dashboard = json.loads((DASHBOARDS / "ise-endpoints-devices.json").read_text())
    panels = {panel["id"]: panel for panel in _panels(dashboard["panels"])}

    for panel_id in (2, 9, 10, 11):
        expression = panels[panel_id]["targets"][0]["expr"]
        assert 'ise_dataset_up{dataset="devices",source="rest"}' in expression
        assert "== 1" in expression


def test_psn_diagnostic_headline_respects_node_filter():
    dashboard = json.loads((DASHBOARDS / "ise-psn-troubleshooting.json").read_text())
    panel = next(panel for panel in _panels(dashboard["panels"]) if panel.get("id") == 4)
    expression = panel["targets"][0]["expr"]

    assert 'sum(ise_dataconnect_diagnostic_events{node=~"$psn"})' in expression
    assert "ise_dataconnect_diagnostic_events_total" not in expression


def test_psn_dashboard_hides_stale_deployment_snapshot():
    dashboard = json.loads((DASHBOARDS / "ise-psn-troubleshooting.json").read_text())
    panel = next(panel for panel in _panels(dashboard["panels"]) if panel.get("id") == 14)
    expression = panel["targets"][0]["expr"]

    assert 'ise_dataset_up{dataset="deployment",source="rest"}' in expression
    assert "== 1" in expression


def test_exporter_health_query_duration_survives_sparse_production_cadence():
    dashboard = _dashboard("ise-exporter-health.json")
    panel = _panel(dashboard, "Latest Data Connect Query Duration")
    target = panel["targets"][0]

    assert panel["type"] == "bargauge"
    assert panel["title"] == "Latest Data Connect Query Duration"
    assert target["expr"] == "ise_dataconnect_query_last_duration_seconds"
    assert target["instant"] is True
    assert "histogram_quantile" not in target["expr"]


def test_exporter_health_exposes_attempt_and_success_age_per_dataset():
    dashboard = _dashboard("ise-exporter-health.json")
    panel = _panel(dashboard, "Dataset Collection Attempt and Success Age")
    expressions = {target["refId"]: target["expr"] for target in panel["targets"]}

    assert "ise_dataset_last_attempt_timestamp" in expressions["Attempt age"]
    assert "ise_dataset_last_success_timestamp" in expressions["Success age"]
    assert all('ise_dataset_enabled{dataset=~"$dataset",source=~"$source"} == 1'
               in expr for expr in expressions.values())


def test_overview_operational_panels_hide_stale_rest_snapshots():
    dashboard = _dashboard("ise-overview.json")
    ownership = {
        "ISE Up": "deployment",
        "PAN HA Enabled": "deployment",
        "Certificates Expired": "certificates",
        "Certs Expiring Soon": "certificates",
        "Backup Age": "backup",
        "Patch Level": "patches",
        "Nodes by Role": "deployment",
        "Deployment Status": "deployment",
        "ISE Info": "deployment",
        "ISE Version": "patches",
        "Certificate Expiry (days, soonest first)": "certificates",
        "License Consumption": "licensing",
        "License Compliance": "licensing",
        "License Tiers Enabled": "licensing",
        "Patch Installed": "patches",
        "Backup Configured": "backup",
        "Time Since Last Backup Success": "backup",
    }

    for title, dataset in ownership.items():
        expression = _panel(dashboard, title)["targets"][0]["expr"]
        assert f'dataset="{dataset}",source="rest"' in expression, (
            title, expression)
        assert "ise_dataset_up" in expression, (title, expression)

    # ISE Up must show DOWN rather than a stale UP or a blank panel.
    assert "ise_up * on() max(ise_dataset_up" in \
        _panel(dashboard, "ISE Up")["targets"][0]["expr"]
    # A healthy certificate snapshot with no expiring certs is a real zero.
    expiring = _panel(dashboard, "Certs Expiring Soon")["targets"][0]["expr"]
    assert "or on() (0 *" in expiring
    assert "== 1" in expiring


def _variables(dashboard):
    return {item["name"]: item for item in dashboard["templating"]["list"]}


def test_troubleshooting_variables_match_exported_metric_dimensions():
    psn = _dashboard("ise-psn-troubleshooting.json")
    access = _dashboard("ise-access-troubleshooting.json")
    health = _dashboard("ise-exporter-health.json")

    assert set(_variables(psn)) == {"DS_PROMETHEUS", "psn"}
    assert set(_variables(access)) == {
        "DS_PROMETHEUS", "psn", "nad", "status", "authorization_policy"}
    assert set(_variables(health)) == {"DS_PROMETHEUS", "dataset", "source"}

    for dashboard in (psn, access, health):
        for item in list(_variables(dashboard).values())[1:]:
            assert item["multi"] is True
            assert item["includeAll"] is True
            assert item["allValue"] == ".*"


def test_dashboard_navigation_preserves_time_and_variables():
    for path in sorted(DASHBOARDS.glob("*.json")):
        dashboard = json.loads(path.read_text())
        destinations = {link["title"] for link in dashboard["links"]}
        assert destinations == {"Overview", "Access", "PSN", "Exporter Health"}
        assert all(link["keepTime"] and link["includeVars"]
                   for link in dashboard["links"])


def test_psn_and_access_queries_apply_supported_filters():
    psn = _dashboard("ise-psn-troubleshooting.json")
    for item in _panels(psn["panels"]):
        for target in item.get("targets", []):
            expr = target.get("expr", "")
            if any(metric in expr for metric in (
                    "ise_dataconnect_psn_", "ise_dataconnect_node_",
                    "ise_dataconnect_diagnostic_events", "ise_deployment_status")):
                assert 'node=~"$psn"' in expr, (item["title"], expr)

    access = _dashboard("ise-access-troubleshooting.json")
    expressions = "\n".join(
        target.get("expr", "")
        for item in _panels(access["panels"])
        for target in item.get("targets", []))
    assert 'psn=~"$psn"' in expressions
    assert 'nad=~"$nad"' in expressions
    assert 'status=~"$status"' in expressions
    assert 'authorization_policy=~"$authorization_policy"' in expressions


def test_dataset_failures_route_to_responsible_dashboard():
    health = _dashboard("ise-exporter-health.json")
    panel = _panel(health, "Unavailable Dataset Details")
    expression = panel["targets"][0]["expr"]
    link = panel["fieldConfig"]["defaults"]["links"][0]

    for uid in (
            "ise-access-troubleshooting", "ise-psn-troubleshooting",
            "ise-secureclient", "ise-tacacs", "ise-endpoints-devices"):
        assert uid in expression
    assert "${__field.labels.dashboard_uid}" in link["url"]
    assert "${__url_time_range}" in link["url"]


def test_username_and_certificate_rows_have_contextual_drilldowns():
    tacacs = _dashboard("ise-tacacs.json")
    username = _variables(tacacs)["username"]
    assert username["query"]["query"] == \
        "label_values(ise_tacacs_internal_user_info, username)"

    username_panels = [
        item for item in _panels(tacacs["panels"])
        if any('username=~"$username"' in target.get("expr", "")
               for target in item.get("targets", []))]
    assert username_panels
    for item in username_panels:
        links = item["fieldConfig"]["defaults"]["links"]
        assert any("${__field.labels.username}" in link["url"]
                   for link in links)

    overview = _dashboard("ise-overview.json")
    certificates = _panel(overview, "Certificate Expiry (days, soonest first)")
    urls = [link["url"] for link in certificates["fieldConfig"]["defaults"]["links"]]
    assert any("${__field.labels.hostname}" in url for url in urls)
    assert any("var-dataset=certificates" in url for url in urls)


def test_alert_rules_cover_requested_failures_and_link_real_panels():
    alerting_dir = (DASHBOARDS.parent /
                    "deploy/test-monitoring/grafana/provisioning/alerting")
    text = (alerting_dir / "alerting.yml").read_text()
    required_metrics = (
        "ise_up", "ise_dataset_up", "ise_dataset_fresh",
        "ise_dataconnect_oldest_queued_seconds",
        "ise_mnt_active_posture_detail_truncated",
        "authentication_backoff",
        "ise_dataconnect_node_cpu_utilization_percent",
        "ise_dataconnect_node_memory_utilization_percent",
    )
    assert all(metric in text for metric in required_metrics)
    contact_points = (alerting_dir / "contact-points.yml").read_text()
    policies = (alerting_dir / "policies.yml").read_text()
    assert "type: prometheus-alertmanager" in contact_points
    assert "url: http://127.0.0.1:9093" in contact_points
    assert "receiver: Local Alertmanager" in policies

    dashboard_uids = {
        json.loads(path.read_text())["uid"]: json.loads(path.read_text())
        for path in DASHBOARDS.glob("*.json")}
    linked = re.findall(
        r"__dashboardUid__: ([^\n]+)\n\s+__panelId__: \"(\d+)\"", text)
    assert len(linked) == 8
    for uid, panel_id in linked:
        assert uid in dashboard_uids
        assert any(str(item.get("id")) == panel_id
                   for item in _panels(dashboard_uids[uid]["panels"]))
