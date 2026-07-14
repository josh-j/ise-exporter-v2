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


def test_100k_default_profile_stays_below_25_scheduled_statements_per_hour():
    cfg = Config()
    statements_per_run = {
        "radius": len(dataconnect_radius._queries(cfg.dataconnect_max_groups)),
        "performance": len(dataconnect_performance._queries(cfg.dataconnect_max_groups)),
        "posture": len(dataconnect_posture._queries(cfg.dataconnect_max_groups)),
        "endpoints": len(dataconnect_endpoints._queries(cfg.dataconnect_max_groups)),
        "freshness": len(dataconnect_freshness._timestamped_views()),
        "nad_health": 1,
        "tacacs": len(tacacs._activity_queries(cfg.dataconnect_max_groups)),
    }
    intervals = {
        "radius": cfg.dataconnect_radius_interval,
        "performance": cfg.dataconnect_performance_interval,
        "posture": cfg.dataconnect_posture_interval,
        "endpoints": cfg.dataconnect_endpoints_interval,
        "freshness": cfg.dataconnect_freshness_interval,
        "nad_health": cfg.dataconnect_nad_health_interval,
        "tacacs": cfg.dataconnect_tacacs_interval,
    }

    reconciliation_statements_per_hour = sum(
        count * 3600 / intervals[name]
        for name, count in statements_per_run.items()
    )
    # Database clock + six small rollup windows + current active sessions.
    steady_radius = len(dataconnect_radius._ROLLUP_DATASETS) + 2
    steady_statements_per_hour = (
        reconciliation_statements_per_hour
        - statements_per_run["radius"] * 3600 / intervals["radius"]
        + steady_radius * 3600 / intervals["radius"]
    )

    assert statements_per_run == {
        "radius": 8,
        "performance": 4,
        "posture": 4,
        "endpoints": 6,
        "freshness": 13,
        "nad_health": 1,
        "tacacs": 3,
    }
    assert reconciliation_statements_per_hour == pytest.approx(22.6666667)
    assert steady_statements_per_hour == pytest.approx(22.6666667)
