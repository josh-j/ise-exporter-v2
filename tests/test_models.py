"""Profiler hierarchy join: pxGrid getProfiles returns the ISE-wide policy
CATALOG (id/name/fullName ancestry), not endpoint counts — models.py caches it
(TTL-gated, since it rarely changes) and joins category/parent onto the
by-policy endpoint counts already computed from getEndpoints."""
import pytest

from ise_exporter import metrics
from ise_exporter.collectors import models


@pytest.fixture(autouse=True)
def _reset_hierarchy_cache():
    models._hierarchy = {}
    models._hierarchy_fetched_at = 0.0
    models._hierarchy_checked_at = 0.0
    yield
    models._hierarchy = {}
    models._hierarchy_fetched_at = 0.0
    models._hierarchy_checked_at = 0.0


def _rows(metric):
    return {(s.labels["category"], s.labels["parent"], s.labels["profile"]): s.value
            for s in metric.collect()[0].samples}


class _PxGrid:
    def __init__(self, profiles):
        self.profiles = profiles
        self.calls = 0

    def get_profiler_profiles(self):
        self.calls += 1
        return self.profiles


class _Failing:
    calls = 0

    def get_profiler_profiles(self):
        self.calls += 1
        raise RuntimeError("pxGrid down")


def test_parse_profile_hierarchy_root_and_nested():
    profiles = [
        {"id": "1", "name": "Apple-Device", "fullName": "Apple-Device"},
        {"id": "2", "name": "Apple-iPhone", "fullName": "Apple-Device:Apple-iPhone"},
        {"id": "3", "name": "Apple-iPhone-15", "fullName": "Apple-Device:Apple-iPhone:Apple-iPhone-15"},
    ]
    table = models._parse_profile_hierarchy(profiles)
    assert table["Apple-Device"] == ("Apple-Device", "")
    assert table["Apple-iPhone"] == ("Apple-Device", "Apple-Device")
    assert table["Apple-iPhone-15"] == ("Apple-Device", "Apple-iPhone")


def test_emit_endpoint_metrics_without_pxgrid_skips_hierarchy_join():
    endpoints = [{"endPointPolicy": "Cisco-IP-Phone-8841"}]
    models.emit_endpoint_metrics(endpoints)
    assert _rows(metrics.ise_endpoints_by_profile_all) == {
        ("unknown", "", "Cisco-IP-Phone-8841"): 1.0
    }


def test_emit_endpoint_metrics_joins_category_and_parent_when_pxgrid_given():
    pxgrid = _PxGrid([
        {"id": "1", "name": "Cisco-IP-Phone-8841",
         "fullName": "IP-Phone:Cisco-IP-Phone:Cisco-IP-Phone-8841"},
    ])
    endpoints = [
        {"endPointPolicy": "Cisco-IP-Phone-8841"},
        {"endPointPolicy": "Cisco-IP-Phone-8841"},
        {"endPointPolicy": "Some-Unmapped-Policy"},
    ]
    models.emit_endpoint_metrics(endpoints, pxgrid=pxgrid, hierarchy_ttl=3600)

    assert _rows(metrics.ise_endpoints_by_profile_all) == {
        ("IP-Phone", "Cisco-IP-Phone", "Cisco-IP-Phone-8841"): 2.0,
        ("unknown", "", "Some-Unmapped-Policy"): 1.0,
    }
    assert metrics.ise_profiler_policies_total._value.get() == 1


def test_refresh_hierarchy_is_ttl_gated():
    pxgrid = _PxGrid([{"id": "1", "name": "A", "fullName": "A"}])
    endpoints = [{"endPointPolicy": "A"}]

    models.emit_endpoint_metrics(endpoints, pxgrid=pxgrid, hierarchy_ttl=3600)
    models.emit_endpoint_metrics(endpoints, pxgrid=pxgrid, hierarchy_ttl=3600)

    assert pxgrid.calls == 1


def test_refresh_hierarchy_runs_every_call_when_ttl_is_zero():
    pxgrid = _PxGrid([{"id": "1", "name": "A", "fullName": "A"}])
    endpoints = [{"endPointPolicy": "A"}]

    models.emit_endpoint_metrics(endpoints, pxgrid=pxgrid, hierarchy_ttl=0)
    models.emit_endpoint_metrics(endpoints, pxgrid=pxgrid, hierarchy_ttl=0)

    assert pxgrid.calls == 2


def test_refresh_hierarchy_failure_does_not_crash_and_leaves_unknown():
    pxgrid = _Failing()
    endpoints = [{"endPointPolicy": "A"}]

    models.emit_endpoint_metrics(endpoints, pxgrid=pxgrid, hierarchy_ttl=3600)

    assert pxgrid.calls == 1
    assert _rows(metrics.ise_endpoints_by_profile_all) == {("unknown", "", "A"): 1.0}


def test_secureclient_version_only_counts_endpoints_that_expose_one():
    endpoints = [
        {"macAddress": "00:00:00:00:00:01", "secureClientVersion": "5.1.2.42"},
        {"macAddress": "00:00:00:00:00:02", "AnyConnectVersion": "4.10.07061"},
        {"macAddress": "00:00:00:00:00:03"},   # no agent version -> no series (not 'unknown')
    ]
    models.emit_endpoint_metrics(endpoints)
    versions = {s.labels["version"]: s.value
                for s in metrics.ise_endpoints_by_secureclient_version.collect()[0].samples}
    assert versions == {"5.1.2.42": 1.0, "4.10.07061": 1.0}


def test_hierarchy_age_gauge_set_after_successful_refresh():
    pxgrid = _PxGrid([{"id": "1", "name": "A", "fullName": "A"}])
    endpoints = [{"endPointPolicy": "A"}]

    models.emit_endpoint_metrics(endpoints, pxgrid=pxgrid, hierarchy_ttl=3600)

    assert metrics.ise_profiler_hierarchy_age_seconds._value.get() >= 0
