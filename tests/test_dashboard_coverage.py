from ise_exporter.dashboard_coverage import render_coverage_metrics


UPSTREAM = """
# HELP ise_dataset_up Whether a dataset is available
# TYPE ise_dataset_up gauge
ise_dataset_up{dataset="dataconnect_radius",source="dataconnect"} 1
ise_dataset_up{dataset="endpoint_fleet",source="dataconnect"} 0
# HELP ise_dataset_fresh Whether a dataset is fresh
# TYPE ise_dataset_fresh gauge
ise_dataset_fresh{dataset="endpoint_fleet",source="dataconnect"} 0
# HELP ise_endpoint_fleet_coverage_ratio Existing disabled gauge
# TYPE ise_endpoint_fleet_coverage_ratio gauge
ise_endpoint_fleet_coverage_ratio 0
ise_up 1
"""


def test_coverage_overlay_preserves_real_metrics_and_replaces_disabled_fleet():
    rendered = render_coverage_metrics(UPSTREAM, now=1000)

    assert 'ise_dataset_up{dataset="dataconnect_radius",source="dataconnect"} 1' in rendered
    assert rendered.count(
        'ise_dataset_up{dataset="endpoint_fleet",source="dataconnect"}') == 1
    assert 'ise_dataset_up{dataset="endpoint_fleet",source="dataconnect"} 1' in rendered
    samples = [
        line for line in rendered.splitlines()
        if line.startswith("ise_endpoint_fleet_coverage_ratio ")
    ]
    assert len(samples) == 1
    assert "ise_endpoint_fleet_coverage_ratio 0.8" in rendered
    assert "ise_up 1" in rendered


def test_coverage_overlay_populates_every_absent_dashboard_domain():
    rendered = render_coverage_metrics(UPSTREAM, now=1000)

    for metric in (
        "ise_dataconnect_radius_accounting_session_seconds",
        "ise_dataconnect_radius_errors",
        "ise_dataconnect_profile_events",
        "ise_nad_authentication_events",
        "ise_dataconnect_schema_column_available",
        "ise_dataconnect_tail_cursor_id",
        "ise_dataconnect_tail_resets_total",
        "ise_dataconnect_diagnostic_events",
        "ise_mnt_active_posture_policy_results",
        "ise_dataconnect_posture_condition_assessments",
        "ise_endpoint_fleet_posture",
        "ise_tacacs_account_authentication_events",
        "ise_tacacs_account_authorization_events",
        "ise_tacacs_accounting_events",
    ):
        assert metric in rendered


def test_coverage_rate_counters_advance_with_wall_time():
    first = render_coverage_metrics(UPSTREAM, now=1000)
    second = render_coverage_metrics(UPSTREAM, now=1030)

    assert (
        'ise_dataconnect_radius_error_tail_total'
        '{message_code="54321",psn="laba-ise-003"} 1000'
    ) in first
    assert (
        'ise_dataconnect_radius_error_tail_total'
        '{message_code="54321",psn="laba-ise-003"} 1030'
    ) in second
    assert (
        'ise_dataconnect_posture_assessment_tail_total'
        '{status="Failed",psn="laba-ise-003"} 1030'
    ) in second
    assert (
        'ise_dataconnect_radius_accounting_tail_total'
        '{event_type="start",psn="laba-ise-003"} 2060'
    ) in second
    assert (
        'ise_dataconnect_radius_accounting_tail_total'
        '{event_type="stop",psn="laba-ise-003"} 1030'
    ) in second
    assert (
        'ise_dataconnect_radius_authentication_tail_total'
        '{result="passed",psn="laba-ise-003"} 3090'
    ) in second
    assert (
        'ise_dataconnect_radius_authentication_tail_total'
        '{result="failed",psn="laba-ise-003"} 1030'
    ) in second
