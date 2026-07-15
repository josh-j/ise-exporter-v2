import types

import pytest

from ise_exporter.collectors import (
    dataconnect_endpoints,
    dataconnect_freshness,
    dataconnect_performance,
    dataconnect_posture,
    dataconnect_radius,
    nad_health,
    tacacs,
)
from ise_exporter.collectors.dataconnect_common import event_window_hours, group_limit
from ise_exporter.config import Config
from ise_exporter.clients.dataconnect import MAX_BATCH_RESULT_ROWS, MAX_RESULT_ROWS


def test_large_mnt_default_profile_stays_below_two_due_statements_per_hour():
    cfg = Config()
    statements_per_run = {
        "radius": len(dataconnect_radius._reporting_queries(cfg.dataconnect_max_groups)),
        "radius_active": 1,
        "performance": len(dataconnect_performance._queries(cfg.dataconnect_max_groups)),
        "posture": len(dataconnect_posture._queries(cfg.dataconnect_max_groups)),
        "endpoints": len(dataconnect_endpoints._queries(cfg.dataconnect_max_groups)),
        "freshness": 1,
        "nad_health": 1,
        "tacacs": len(tacacs._activity_queries(
            cfg.dataconnect_max_groups, cutoff_epoch=1)),
    }
    intervals = {
        "radius": cfg.dataconnect_radius_interval,
        "radius_active": cfg.dataconnect_radius_active_interval,
        "performance": cfg.dataconnect_performance_interval,
        "posture": cfg.dataconnect_posture_interval,
        "endpoints": cfg.dataconnect_endpoints_interval,
        "freshness": cfg.dataconnect_freshness_interval,
        "nad_health": cfg.dataconnect_nad_health_interval,
        "tacacs": cfg.dataconnect_tacacs_interval,
    }

    statements_per_hour = sum(
        count * 3600 / intervals[name]
        for name, count in statements_per_run.items()
    )

    assert statements_per_run == {
        "radius": 4,
        "radius_active": 1,
        "performance": 4,
        "posture": 2,
        "endpoints": 2,
        "freshness": 1,
        "nad_health": 1,
        "tacacs": 3,
    }
    assert statements_per_hour == pytest.approx(1.7083333333333333)
    assert statements_per_hour < 2


def test_freshness_uses_one_statement_for_every_timestamped_view():
    query = dataconnect_freshness._query(Config(), now=2_000_000_000)

    assert query.startswith("/* ise_exporter:dataconnect_freshness */")
    assert query.count("UNION ALL") == len(
        dataconnect_freshness._timestamped_views()) - 1
    assert query.count("FETCH FIRST 1 ROWS ONLY") == len(
        dataconnect_freshness._timestamped_views())


def test_posture_reuses_one_bounded_latest_assessment_snapshot():
    queries = dataconnect_posture._queries(Config().dataconnect_max_groups)

    assert list(queries) == ["snapshot", "conditions"]
    assert queries["snapshot"].lower().count(
        "from posture_assessment_by_endpoint") == 1
    assert "/*+ MATERIALIZE */" in queries["snapshot"]


def test_endpoint_inventory_uses_one_current_table_scan():
    queries = dataconnect_endpoints._queries(Config().dataconnect_max_groups)

    assert list(queries) == ["inventory", "profiling"]
    assert queries["inventory"].lower().count("from endpoints_data") == 1
    assert "GROUPING SETS ((), (endpoint_policy), (identity_group_id))" in \
        queries["inventory"]


def test_radius_reporting_scans_each_large_historical_view_only_once():
    queries = dataconnect_radius._reporting_queries(Config().dataconnect_max_groups)
    raw = [name for name, sql in queries.items()
           if "FROM radius_authentications" in sql]
    summary = [name for name, sql in queries.items()
               if "FROM radius_authentication_summary" in sql]

    accounting = [name for name, sql in queries.items()
                  if "FROM radius_accounting" in sql]

    assert raw == ["authentication"]
    assert summary == ["volume_summary"]
    assert accounting == ["accounting"]


def test_alternate_config_cannot_export_more_than_production_group_ceiling():
    assert group_limit(types.SimpleNamespace(dataconnect_max_groups=999_999)) == 1000
    assert len(tacacs._activity_queries(1000, cutoff_epoch=1)) == 3


def test_nad_health_query_has_the_same_hard_group_ceiling():
    class DataConnect:
        def query(self, sql):
            assert "WHERE group_rank <= 1000" in sql
            return []

    nad_health.collect(
        [], DataConnect(),
        types.SimpleNamespace(
            dataconnect_max_groups=999_999,
            dataconnect_nad_health_interval=86400,
            dataconnect_event_window_hours=6,
        ))


def test_tacacs_query_builder_refuses_an_unbounded_event_scan():
    with pytest.raises(TypeError):
        tacacs._activity_queries(1000)

    with pytest.raises((TypeError, ValueError)):
        tacacs._activity_queries(1000, cutoff_epoch=None)


def test_malformed_config_like_scan_window_fails_safe():
    cfg = types.SimpleNamespace(dataconnect_event_window_hours="invalid")

    assert event_window_hours(cfg, "invalid") == 1


def test_tacacs_internal_last_seen_reuses_each_existing_view_scan():
    queries = tacacs._activity_queries(1000, cutoff_epoch=1, internal_user_count=1000)

    for event_type, sql in queries.items():
        assert sql.lower().count(f"from tacacs_{event_type}_last_two_days") == 1
        assert "WHERE epoch_time >= :minimum_epoch" in sql
        assert "GROUP BY GROUPING SETS" in sql
        assert "breakdown = 'detail' AND group_rank <= 1000" in sql
        assert sql.count(":internal_user_") == 1000


def test_maximum_group_profile_fits_hard_statement_and_batch_row_budgets():
    groups = group_limit(Config())
    # RADIUS: authentication + latency, summary + failure context,
    # accounting + session duration, and errors.
    radius_rows = (2 * groups) + (1 + groups) + (2 * groups) + groups
    # TACACS: top-K detail plus at most one last-seen row per bounded internal
    # account, repeated across authentication, authorization, and accounting.
    tacacs_rows = 3 * (groups + Config().tacacs_internal_user_max)

    assert 2 * groups <= MAX_RESULT_ROWS
    assert radius_rows == 6001
    assert tacacs_rows == 6000
    assert max(radius_rows, tacacs_rows) <= MAX_BATCH_RESULT_ROWS
