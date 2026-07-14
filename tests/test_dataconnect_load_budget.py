import pytest

from ise_exporter.collectors import (
    dataconnect_endpoints,
    dataconnect_freshness,
    dataconnect_performance,
    dataconnect_posture,
    dataconnect_radius,
    tacacs,
)
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
        "radius": 7,
        "radius_active": 1,
        "performance": 4,
        "posture": 4,
        "endpoints": 4,
        "freshness": 13,
        "nad_health": 1,
        "tacacs": 3,
    }
    assert statements_per_hour == pytest.approx(8.875)
    assert statements_per_hour < 9
