import types

import pytest

from ise_exporter.collectors import (
    dataconnect_endpoints,
    dataconnect_freshness,
    dataconnect_performance,
    dataconnect_posture,
    dataconnect_radius,
    tacacs,
)
from ise_exporter.collectors.dataconnect_common import group_limit
from ise_exporter.config import Config


def test_100k_default_profile_stays_below_10_scheduled_statements_per_hour():
    cfg = Config()
    statements_per_run = {
        "radius": len(dataconnect_radius._reporting_queries(cfg.dataconnect_max_groups)),
        "radius_active": 1,
        "performance": len(dataconnect_performance._queries(cfg.dataconnect_max_groups)),
        "posture": len(dataconnect_posture._queries(cfg.dataconnect_max_groups)),
        "endpoints": len(dataconnect_endpoints._queries(cfg.dataconnect_max_groups)),
        "freshness": len(dataconnect_freshness._timestamped_views()),
        "nad_health": 1,
        "tacacs": len(tacacs._activity_queries(cfg.dataconnect_max_groups)),
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
        "posture": 4,
        "endpoints": 3,
        "freshness": 14,
        "nad_health": 1,
        "tacacs": 3,
    }
    assert statements_per_hour == pytest.approx(8.208333333333334)
    assert statements_per_hour < 8.25


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
    assert len(tacacs._activity_queries(1000)) == 3
