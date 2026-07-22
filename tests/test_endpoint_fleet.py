import time
import types

import pytest

from ise_exporter import metrics
from ise_exporter.collectors import endpoint_fleet
from ise_exporter.util import clear_metric


@pytest.fixture(autouse=True)
def _clear():
    for metric in endpoint_fleet._METRICS:
        clear_metric(metric)


def _rows(metric, *labels):
    return {tuple(sample.labels[name] for name in labels): sample.value
            for sample in metric.collect()[0].samples}


class DataConnect:
    """Fake Data Connect returning a settable assessment batch per cycle."""

    def __init__(self, eligible=4):
        self.schema = None
        self.assessments = []
        self.eligible = eligible
        self.sql = []

    def query(self, sql):
        self.sql.append(sql)
        lowered = sql.lower()
        if "posture_assessment_by_endpoint" in lowered:
            return list(self.assessments)
        return [{"eligible": self.eligible}]


def _cfg(tmp_path, **overrides):
    values = {
        "state_db_path": str(tmp_path / "state.sqlite3"),
        "endpoint_fleet_interval": 900,
        "endpoint_fleet_retention_seconds": 7776000,
        "dataconnect_event_window_hours": 6,
    }
    values.update(overrides)
    return types.SimpleNamespace(**values)


def _assessment(mac, status, os_name, agent, policy, psn, assessed):
    return {
        "mac": mac, "posture_status": status,
        "endpoint_operating_system": os_name, "posture_agent_version": agent,
        "posture_policy_matched": policy, "ise_node": psn, "assessed": assessed,
    }


def test_accumulates_latest_posture_across_cycles(tmp_path):
    client = DataConnect(eligible=4)
    cfg = _cfg(tmp_path)
    now = time.time()

    client.assessments = [
        _assessment("AA", "Compliant", "Windows", "5.1", "Corp", "psn-1", now),
        _assessment("BB", "NonCompliant", "macOS", "5.1", "Corp", "psn-2", now),
    ]
    endpoint_fleet.collect(client, cfg)

    assert metrics.ise_endpoint_fleet_assessed_total._value.get() == 2
    assert metrics.ise_endpoint_fleet_eligible_total._value.get() == 4
    assert metrics.ise_endpoint_fleet_coverage_ratio._value.get() == 0.5
    assert metrics.ise_endpoint_fleet_compliance_ratio._value.get() == 0.5
    assert _rows(metrics.ise_endpoint_fleet_posture, "status") == {
        ("Compliant",): 1, ("NonCompliant",): 1}
    assert _rows(metrics.ise_endpoint_fleet_by_os, "os") == {
        ("Windows",): 1, ("macOS",): 1}
    assert _rows(metrics.ise_endpoint_fleet_by_psn, "psn") == {
        ("psn-1",): 1, ("psn-2",): 1}

    # A later cycle sees only a new endpoint; the earlier two persist in the cache.
    client.assessments = [
        _assessment("CC", "Compliant", "Windows", "5.1", "Corp", "psn-1", now + 1),
    ]
    endpoint_fleet.collect(client, cfg)

    assert metrics.ise_endpoint_fleet_assessed_total._value.get() == 3
    assert metrics.ise_endpoint_fleet_coverage_ratio._value.get() == 0.75
    assert metrics.ise_endpoint_fleet_compliance_ratio._value.get() == pytest.approx(2 / 3)
    assert _rows(metrics.ise_endpoint_fleet_posture, "status") == {
        ("Compliant",): 2, ("NonCompliant",): 1}


def test_newer_assessment_replaces_older_for_same_endpoint(tmp_path):
    client = DataConnect(eligible=2)
    cfg = _cfg(tmp_path)
    now = time.time()

    client.assessments = [
        _assessment("AA", "Compliant", "Windows", "5.1", "Corp", "psn-1", now)]
    endpoint_fleet.collect(client, cfg)
    assert _rows(metrics.ise_endpoint_fleet_posture, "status") == {("Compliant",): 1}

    # Same endpoint re-postures NonCompliant later: latest wins, no double count.
    client.assessments = [
        _assessment("AA", "NonCompliant", "Windows", "5.1", "Corp", "psn-1", now + 5)]
    endpoint_fleet.collect(client, cfg)
    assert metrics.ise_endpoint_fleet_assessed_total._value.get() == 1
    assert _rows(metrics.ise_endpoint_fleet_posture, "status") == {("NonCompliant",): 1}

    # An out-of-order older assessment must not overwrite the newer state.
    client.assessments = [
        _assessment("AA", "Compliant", "Windows", "5.1", "Corp", "psn-1", now - 100)]
    endpoint_fleet.collect(client, cfg)
    assert _rows(metrics.ise_endpoint_fleet_posture, "status") == {("NonCompliant",): 1}


def test_scan_row_cap_is_configurable_and_flags_truncation(tmp_path, monkeypatch, caplog):
    # Shrink the lower bound so the test can exercise the cap with a few rows.
    monkeypatch.setattr(endpoint_fleet, "_MIN_ROW_CAP", 2)
    client = DataConnect(eligible=4)
    now = time.time()

    # A full-cap scan flags truncation and points operators at the knob.
    client.assessments = [
        _assessment("AA", "Compliant", "Windows", "5.1", "Corp", "psn-1", now),
        _assessment("BB", "Compliant", "Windows", "5.1", "Corp", "psn-1", now),
    ]
    with caplog.at_level("WARNING"):
        endpoint_fleet.collect(client, _cfg(tmp_path, endpoint_fleet_max_rows=2))
    assert metrics.ise_endpoint_fleet_scan_truncated._value.get() == 1
    assert "outcome=scan_truncated" in caplog.text
    assert "row_cap=2" in caplog.text

    # A scan below the cap clears the flag.
    client.assessments = [
        _assessment("CC", "Compliant", "Windows", "5.1", "Corp", "psn-1", now)]
    endpoint_fleet.collect(client, _cfg(tmp_path, endpoint_fleet_max_rows=5))
    assert metrics.ise_endpoint_fleet_scan_truncated._value.get() == 0


def test_scan_row_cap_appears_in_the_generated_sql(tmp_path):
    client = DataConnect(eligible=4)
    client.assessments = []
    endpoint_fleet.collect(client, _cfg(tmp_path, endpoint_fleet_max_rows=1234))

    assert any("FETCH FIRST 1234 ROWS ONLY" in sql for sql in client.sql)


def test_eligible_query_issued_on_first_cycle_then_cached_within_ttl(tmp_path):
    client = DataConnect(eligible=4)
    cfg = _cfg(tmp_path)
    now = time.time()

    client.assessments = [
        _assessment("AA", "Compliant", "Windows", "5.1", "Corp", "psn-1", now)]
    endpoint_fleet.collect(client, cfg)
    assert any("endpoints_data" in sql.lower() for sql in client.sql)
    assert metrics.ise_endpoint_fleet_eligible_total._value.get() == 4
    assert metrics.ise_endpoint_fleet_coverage_ratio._value.get() == 0.25

    # Second cycle within the TTL: no eligible statement issued, but the
    # published eligible/coverage values still come from the cached entry
    # even though the live source count changed underneath it.
    client.sql = []
    client.eligible = 999
    client.assessments = [
        _assessment("BB", "Compliant", "Windows", "5.1", "Corp", "psn-2", now + 1)]
    endpoint_fleet.collect(client, cfg)
    assert not any("endpoints_data" in sql.lower() for sql in client.sql)
    assert metrics.ise_endpoint_fleet_eligible_total._value.get() == 4
    assert metrics.ise_endpoint_fleet_coverage_ratio._value.get() == 0.5


def test_eligible_query_reissued_once_ttl_elapses(tmp_path, monkeypatch):
    client = DataConnect(eligible=4)
    cfg = _cfg(tmp_path)
    now = time.time()

    client.assessments = [
        _assessment("AA", "Compliant", "Windows", "5.1", "Corp", "psn-1", now)]
    endpoint_fleet.collect(client, cfg)

    monkeypatch.setattr(
        endpoint_fleet.time, "time",
        lambda: now + endpoint_fleet._ELIGIBLE_REFRESH_SECONDS + 1)
    client.sql = []
    client.eligible = 10
    client.assessments = []
    endpoint_fleet.collect(client, cfg)
    assert any("endpoints_data" in sql.lower() for sql in client.sql)
    assert metrics.ise_endpoint_fleet_eligible_total._value.get() == 10


def test_future_fetched_at_treated_as_stale(tmp_path):
    client = DataConnect(eligible=4)
    cfg = _cfg(tmp_path)
    now = time.time()

    client.assessments = []
    endpoint_fleet.collect(client, cfg)

    # Simulate a clock correction by writing a cache entry from "the future".
    from ise_exporter.state import StateStore
    import json
    store = StateStore(cfg.state_db_path)
    store.set_value(
        "endpoint_fleet_eligible",
        json.dumps({"eligible": 4, "fetched_at": now + 3600}))
    store.close()

    client.sql = []
    client.eligible = 7
    client.assessments = []
    endpoint_fleet.collect(client, cfg)
    assert any("endpoints_data" in sql.lower() for sql in client.sql)
    assert metrics.ise_endpoint_fleet_eligible_total._value.get() == 7


def test_no_dataconnect_call_when_assessments_unsupported_and_eligible_cached(tmp_path):
    client = DataConnect(eligible=4)
    # Schema without POSTURE_ASSESSMENT_BY_ENDPOINT.endpoint_mac_address: the
    # assessments query is never issued for this deployment.
    client.schema = {
        "POSTURE_ASSESSMENT_BY_ENDPOINT": set(),
        "ENDPOINTS_DATA": {"MAC_ADDRESS", "POSTURE_APPLICABLE"},
    }
    cfg = _cfg(tmp_path)
    client.assessments = []
    endpoint_fleet.collect(client, cfg)
    assert any("endpoints_data" in sql.lower() for sql in client.sql)
    assert metrics.ise_endpoint_fleet_eligible_total._value.get() == 4

    # Second cycle within the TTL: eligible is cached, assessments remain
    # unsupported -- no Data Connect statement issued at all this cycle.
    client.sql = []
    client.eligible = 999
    endpoint_fleet.collect(client, cfg)
    assert client.sql == []
    assert metrics.ise_endpoint_fleet_eligible_total._value.get() == 4


def test_prunes_assessments_beyond_retention(tmp_path):
    client = DataConnect(eligible=2)
    cfg = _cfg(tmp_path, endpoint_fleet_retention_seconds=3600)
    now = time.time()

    client.assessments = [
        _assessment("AA", "Compliant", "Windows", "5.1", "Corp", "psn-1", now - 7200),
        _assessment("BB", "Compliant", "Windows", "5.1", "Corp", "psn-1", now),
    ]
    endpoint_fleet.collect(client, cfg)

    # AA is older than the 1h retention and is dropped; BB remains.
    assert metrics.ise_endpoint_fleet_assessed_total._value.get() == 1
    assert metrics.ise_endpoint_fleet_cache_entries._value.get() == 1
