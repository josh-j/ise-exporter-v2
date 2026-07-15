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


def test_failure_context_panels_expose_summary_reason_profile_and_location():
    dashboard = json.loads((DASHBOARDS / "ise-failure-triage.json").read_text())
    panels = {panel["id"]: panel for panel in _panels(dashboard["panels"])}

    for panel_id, label in ((11, "failure_class"), (12, "authorization_profile"),
                            (13, "location")):
        expression = panels[panel_id]["targets"][0]["expr"]
        assert "ise_dataconnect_radius_failure_events" in expression
        assert label in expression
        assert 'ise_dataset_up{dataset="dataconnect_radius"' in expression


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
            4: ("ise_dataconnect_radius_accounting_event_type_total",),
            12: ("ise_dataconnect_radius_accounting_event_type_total",),
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
            if "ise_dataconnect_radius_accounting_event_type_total" in exact_metrics:
                assert "sum(ise_dataconnect_radius_accounting_events" not in expression

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
        "ise-sessions-auth.json": {
            ("dataconnect_radius", "dataconnect"),
            ("dataconnect_radius_active", "dataconnect"),
        },
        "ise-failure-triage.json": {("dataconnect_radius", "dataconnect")},
        "ise-endpoint-profiles.json": {("dataconnect_endpoints", "dataconnect")},
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
                if (path.name != "ise-data-quality.json"
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


def test_data_quality_dashboard_exposes_collection_and_source_freshness():
    text = (DASHBOARDS / "ise-data-quality.json").read_text()
    for metric in (
        "ise_dataset_enabled",
        "ise_exporter_build_info",
        "ise_dataset_up",
        "ise_dataset_fresh",
        "ise_dataset_last_attempt_timestamp",
        "ise_dataset_last_success_timestamp",
        "ise_dataconnect_view_has_rows",
        "ise_dataconnect_view_newest_event_timestamp",
        "ise_mnt_active_posture_detail_coverage_ratio",
        "ise_mnt_active_posture_detail_truncated",
        "ise_mnt_active_posture_field_coverage_ratio",
        "ise_mnt_active_posture_cache_entries",
        "ise_mnt_active_posture_refresh_deferred",
        "ise_mnt_active_posture_cache_oldest_age_seconds",
        "ise_dataconnect_radius_active_groups_truncated",
        "ise_tacacs_topk_truncated",
        "ise_tacacs_internal_user_inventory_truncated",
        "ise_dataconnect_worker_busy",
        "ise_dataconnect_queue_depth",
        "ise_dataconnect_query_last_duration_seconds",
        "ise_dataconnect_oldest_queued_seconds",
        "ise_mnt_worker_busy",
        "ise_mnt_session_list_preflight_count",
        "ise_mnt_session_list_ceiling",
        "ise_mnt_session_list_skipped",
    ):
        assert metric in text


def test_sessions_dashboard_gates_active_count_on_active_dataset():
    dashboard = json.loads((DASHBOARDS / "ise-sessions-auth.json").read_text())
    panel = next(panel for panel in _panels(dashboard["panels"]) if panel.get("id") == 3)
    expression = panel["targets"][0]["expr"]

    assert 'dataset="dataconnect_radius_active"' in expression
    assert 'dataset="dataconnect_radius",' not in expression


def test_data_quality_dashboard_does_not_render_empty_views_as_epoch_old():
    dashboard = json.loads((DASHBOARDS / "ise-data-quality.json").read_text())
    panel = next(panel for panel in _panels(dashboard["panels"]) if panel.get("id") == 6)
    expressions = {target["refId"]: target["expr"] for target in panel["targets"]}

    assert "ise_dataconnect_view_newest_event_timestamp > 0" in expressions[
        "Newest event age"]
    assert "ise_dataconnect_view_has_rows" in expressions["Has rows"]
    assert "Window span" not in expressions


def test_data_quality_summary_stats_are_gated_by_authoritative_datasets():
    dashboard = json.loads((DASHBOARDS / "ise-data-quality.json").read_text())
    panels = {panel["id"]: panel for panel in _panels(dashboard["panels"])}

    assert "0 * (count(ise_dataset_up) > 0)" in panels[1]["targets"][0]["expr"]
    assert "0 * (count(ise_dataset_up) > 0)" in panels[2]["targets"][0]["expr"]
    assert 'dataset="dataconnect_freshness"' in panels[3]["targets"][0]["expr"]
    assert "or on() (0 *" in panels[3]["targets"][0]["expr"]
    assert "== 1" in panels[3]["targets"][0]["expr"]
    truncation = panels[4]["targets"][0]["expr"]
    for dataset in (
            "dataconnect_radius", "dataconnect_radius_active",
            "dataconnect_posture", "dataconnect_endpoints",
            "dataconnect_performance"):
        assert dataset in truncation
    for dataset in ("tacacs_activity", "tacacs_config"):
        assert dataset in truncation
    # Every term gates both its preserved value and its valid-zero fallback.
    assert truncation.count("max(ise_dataset_up") == 14
    assert truncation.count(" and on() (max(ise_dataset_up") == 7


def test_sessions_dashboard_collection_age_thresholds_match_domain_cadences():
    dashboard = json.loads((DASHBOARDS / "ise-sessions-auth.json").read_text())
    panel = next(panel for panel in _panels(dashboard["panels"]) if panel.get("id") == 91)

    defaults = panel["fieldConfig"]["defaults"]["thresholds"]["steps"]
    assert [step["value"] for step in defaults] == [None, 129600, 172800]
    active = panel["fieldConfig"]["overrides"][0]
    assert active["matcher"] == {"id": "byFrameRefID", "options": "Active sessions"}
    steps = active["properties"][0]["value"]["steps"]
    assert [step["value"] for step in steps] == [None, 2700, 3600]


def test_dashboard_age_thresholds_match_production_collection_cadences():
    sample = (DASHBOARDS.parent / ".env.example").read_text()
    slow_interval = int(re.search(
        r"^SLOW_INTERVAL=(\d+)$", sample, re.MULTILINE).group(1))
    expected = {
        ("ise-auth-troubleshooting.json", 91): (129600, 172800),
        ("ise-failure-triage.json", 91): (129600, 172800),
        ("ise-endpoint-profiles.json", 91): (129600, 172800),
        ("ise-endpoints-devices.json", 91): (129600, 172800),
        ("ise-psn-troubleshooting.json", 91): (5400, 7200),
        ("ise-secureclient.json", 91): (1350, 1800),
        ("ise-secureclient.json", 93): (32400, 43200),
        ("ise-tacacs.json", 92): (
            slow_interval * 3 // 2, slow_interval * 2),
        ("ise-tacacs.json", 93): (32400, 43200),
        ("ise-data-quality.json", 18): (1350, 1800),
    }
    for (filename, panel_id), thresholds in expected.items():
        dashboard = json.loads((DASHBOARDS / filename).read_text())
        panel = next(
            panel for panel in _panels(dashboard["panels"]) if panel.get("id") == panel_id)
        steps = panel["fieldConfig"]["defaults"]["thresholds"]["steps"]
        assert tuple(step["value"] for step in steps[1:]) == thresholds


def test_data_quality_domain_panels_do_not_publish_stale_values_during_outages():
    dashboard = json.loads((DASHBOARDS / "ise-data-quality.json").read_text())
    panels = {panel["id"]: panel for panel in _panels(dashboard["panels"])}
    ownership = {
        7: "dataconnect_posture",
        8: "dataconnect_endpoints",
        9: "dataconnect_endpoints",
        10: "dataconnect_radius",
        11: "dataconnect_nad_health",
        12: "dataconnect_nad_health",
        13: "certificates",
        14: "deployment",
        15: "dataconnect_nad_health",
        16: "certificates",
        19: "mnt_active_posture",
        20: "mnt_active_posture",
        21: "mnt_active_posture",
        30: "mnt_active_posture",
        31: "mnt_active_posture",
        32: "mnt_active_posture",
        33: ("dataconnect_radius", "dataconnect_radius_active"),
    }

    for panel_id, datasets in ownership.items():
        if isinstance(datasets, str):
            datasets = (datasets,)
        targets = panels[panel_id]["targets"]
        expected = datasets if len(datasets) > 1 else datasets * len(targets)
        assert len(targets) == len(expected)
        for target, dataset in zip(targets, expected, strict=True):
            expression = target["expr"]
            assert f'dataset="{dataset}"' in expression, (panel_id, expression)
            assert "ise_dataset_up" in expression, (panel_id, expression)
            assert "== 1" in expression, (panel_id, expression)


def test_unknown_endpoint_profile_stat_uses_exact_inventory_total():
    dashboard = json.loads((DASHBOARDS / "ise-data-quality.json").read_text())
    panel = next(panel for panel in _panels(dashboard["panels"]) if panel.get("id") == 8)
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


def test_psn_diagnostic_headline_uses_exact_total_not_topk_breakdown():
    dashboard = json.loads((DASHBOARDS / "ise-psn-troubleshooting.json").read_text())
    panel = next(panel for panel in _panels(dashboard["panels"]) if panel.get("id") == 4)
    expression = panel["targets"][0]["expr"]

    assert "ise_dataconnect_diagnostic_events_total" in expression
    assert "sum(ise_dataconnect_diagnostic_events)" not in expression


def test_psn_dashboard_hides_stale_deployment_snapshot():
    dashboard = json.loads((DASHBOARDS / "ise-psn-troubleshooting.json").read_text())
    panel = next(panel for panel in _panels(dashboard["panels"]) if panel.get("id") == 14)
    expression = panel["targets"][0]["expr"]

    assert 'ise_dataset_up{dataset="deployment",source="rest"}' in expression
    assert "== 1" in expression


def test_disconnected_node_stat_is_zero_when_all_nodes_are_healthy():
    text = (DASHBOARDS / "ise-data-quality.json").read_text()

    assert ('sum(ise_deployment_status{ise_deployment_status=\\"Disconnected\\"})'
            in text)
    assert "sum(ise_deployment_status == bool 2)" not in text
    assert "sum(ise_deployment_status == 2)" not in text


def test_data_quality_query_duration_survives_sparse_production_cadence():
    dashboard = json.loads((DASHBOARDS / "ise-data-quality.json").read_text())
    panel = next(panel for panel in _panels(dashboard["panels"]) if panel.get("id") == 24)
    target = panel["targets"][0]

    assert panel["type"] == "bargauge"
    assert panel["title"] == "Latest Data Connect Query Duration"
    assert target["expr"] == "ise_dataconnect_query_last_duration_seconds"
    assert target["instant"] is True
    assert "histogram_quantile" not in target["expr"]


def test_overview_freshness_uses_each_datasets_published_effective_interval():
    dashboard = json.loads((DASHBOARDS / "ise-overview.json").read_text())
    panel = next(panel for panel in _panels(dashboard["panels"]) if panel.get("id") == 29)
    expression = panel["targets"][0]["expr"]

    assert "ise_dataset_last_success_timestamp" in expression
    assert "on(dataset,source) ise_dataset_effective_interval_seconds" in expression
    assert "/ 60" not in expression
    assert "/ 300" not in expression
    assert "/ 3600" not in expression


def test_overview_operational_panels_hide_stale_rest_snapshots():
    dashboard = json.loads((DASHBOARDS / "ise-overview.json").read_text())
    panels = {panel["id"]: panel for panel in _panels(dashboard["panels"])}
    ownership = {
        2: "deployment", 3: "deployment", 4: "certificates",
        5: "certificates", 6: "backup", 7: "patches",
        8: "deployment", 9: "deployment", 10: "deployment",
        11: "patches", 19: "certificates", 20: "licensing",
        21: "licensing", 23: "licensing", 24: "patches",
        25: "backup", 26: "backup",
    }

    for panel_id, dataset in ownership.items():
        expression = panels[panel_id]["targets"][0]["expr"]
        assert f'dataset="{dataset}",source="rest"' in expression, (
            panel_id, expression)
        assert "ise_dataset_up" in expression, (panel_id, expression)

    # ISE Up must show DOWN rather than a stale UP or a blank panel.
    assert "ise_up * on() max(ise_dataset_up" in panels[2]["targets"][0]["expr"]
    # A healthy certificate snapshot with no expiring certs is a real zero.
    expiring = panels[5]["targets"][0]["expr"]
    assert "or on() (0 *" in expiring
    assert "== 1" in expiring
