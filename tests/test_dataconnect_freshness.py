import re
from datetime import datetime, timezone
import types

import pytest

from ise_exporter import metrics
from ise_exporter.collectors import dataconnect_freshness
from ise_exporter.dataconnect_schema import VIEW_CONTRACTS
from ise_exporter.util import clear_metric


@pytest.fixture(autouse=True)
def _clear():
    for metric in dataconnect_freshness._METRICS:
        clear_metric(metric)


def _rows(metric):
    return {(sample.labels["view"], sample.labels["domain"]): sample.value
            for sample in metric.collect()[0].samples}


class DataConnect:
    """Fake with only ``query()`` -- exercises the query_set() fallback path."""

    def __init__(self):
        self.sql = []

    def query(self, sql):
        self.sql.append(sql)
        return [{
                "view_name": "radius_authentications",
                "domain": "radius_auth",
                "newest_event": datetime(2026, 7, 14, 4, 30, tzinfo=timezone.utc),
        }]


class QueryManyDataConnect:
    """Fake with ``query_many()`` -- exercises the shared-lease batch path."""

    def __init__(self):
        self.batches = []

    def query_many(self, statements, parameters=None):
        self.batches.append(dict(statements))
        results = {}
        for name, sql in statements.items():
            views_in_statement = re.findall(r"SELECT '([a-z_]+)' AS view_name", sql)
            results[name] = [{
                "view_name": view,
                "domain": "irrelevant",
                "newest_event": datetime(2026, 7, 14, 4, 30, tzinfo=timezone.utc),
            } for view in views_in_statement]
        return results


def test_collects_bounded_presence_and_newest_event_for_every_timestamped_view(
        monkeypatch):
    client = DataConnect()
    monkeypatch.setattr(dataconnect_freshness.time, "time", lambda: 2_000_000_000)
    dataconnect_freshness.collect(client, types.SimpleNamespace(
        dataconnect_event_window_hours=24,
        dataconnect_freshness_interval=86400,
    ))

    timestamped = {name.lower(): contract.domain
                   for name, contract in VIEW_CONTRACTS.items()
                   if contract.time_column and contract.freshness_probe}
    expected_chunks = len(dataconnect_freshness._chunk_views(
        dataconnect_freshness._timestamped_views()))
    assert len(client.sql) == expected_chunks
    sql = "\nUNION ALL\n".join(client.sql)
    assert sql.count("FETCH FIRST 1 ROWS ONLY") == len(timestamped)
    assert sql.count("DESC NULLS LAST") == len(timestamped)
    assert sql.count("EPOCH_TIME >= 1999978400") == 3
    assert "INTERVAL '2' DAY" not in sql
    assert sql.count("NUMTODSINTERVAL(6, 'HOUR')") == len(timestamped) - 3
    assert "COUNT(" not in sql and "MIN(" not in sql and "MAX(" not in sql

    rows = _rows(metrics.ise_dataconnect_view_has_recent_rows)
    assert set(rows) == {(view, domain) for view, domain in timestamped.items()}
    assert rows[("radius_authentications", "radius_auth")] == 1
    assert rows[("radius_accounting", "radius_accounting")] == 0
    expectations = _rows(metrics.ise_dataconnect_view_freshness_expected)
    assert expectations[("key_performance_metrics", "performance")] == 1
    assert expectations[("radius_accounting", "radius_accounting")] == 0
    assert _rows(metrics.ise_dataconnect_view_newest_recent_event_timestamp)[
        ("radius_authentications", "radius_auth")] == pytest.approx(1784003400)


def test_freshness_honors_lower_production_scan_ceiling(monkeypatch):
    client = DataConnect()
    monkeypatch.setattr(dataconnect_freshness.time, "time", lambda: 2_000_000_000)

    dataconnect_freshness.collect(client, types.SimpleNamespace(
        dataconnect_event_window_hours=4,
        dataconnect_freshness_interval=86400,
    ))

    expected_chunks = len(dataconnect_freshness._chunk_views(
        dataconnect_freshness._timestamped_views()))
    assert len(client.sql) == expected_chunks
    sql = "\nUNION ALL\n".join(client.sql)
    assert sql.count("EPOCH_TIME >= 1999985600") == 3
    assert sql.count("NUMTODSINTERVAL(4, 'HOUR')") == \
        len(dataconnect_freshness._timestamped_views()) - 3


def test_freshness_excludes_tacacs_views_when_collection_is_disabled(monkeypatch):
    client = DataConnect()
    monkeypatch.setattr(dataconnect_freshness.time, "time", lambda: 2_000_000_000)

    dataconnect_freshness.collect(client, types.SimpleNamespace(
        collect_tacacs=False,
        dataconnect_event_window_hours=4,
        dataconnect_freshness_interval=86400,
    ))

    sql = "\nUNION ALL\n".join(client.sql)
    assert "tacacs_" not in sql.lower()
    assert "EPOCH_TIME" not in sql
    expected = dataconnect_freshness._timestamped_views(include_tacacs=False)
    assert sql.count("FETCH FIRST 1 ROWS ONLY") == len(expected)
    assert all(domain != "tacacs" for _view, domain in _rows(
        metrics.ise_dataconnect_view_has_recent_rows))


@pytest.mark.parametrize(("value", "expected"), [
    (None, 0),
    (1784003400, 1784003400),
    (1784003400000, 1784003400),
    ("1784003400", 1784003400),
    ("2026-07-14T04:30:00.000000", 1784003400),
    (datetime(2026, 7, 14, 4, 30), 1784003400),
])
def test_timestamp_normalization(value, expected):
    assert dataconnect_freshness._timestamp(value) == pytest.approx(expected)


def test_freshness_prefers_timezone_column_and_skips_missing_views():
    schema = {
        "RADIUS_AUTHENTICATIONS": {
            "TIMESTAMP": "TIMESTAMP", "TIMESTAMP_TIMEZONE": "TIMESTAMP WITH TIME ZONE"},
    }
    sql = dataconnect_freshness._query(
        types.SimpleNamespace(dataconnect_freshness_interval=86400), schema=schema)

    assert "FROM RADIUS_AUTHENTICATIONS" in sql
    assert "TIMESTAMP_TIMEZONE >= SYSTIMESTAMP" in sql
    assert "TZH:TZM" in sql
    assert "RADIUS_ACCOUNTING" not in sql


def test_freshness_never_compares_tacacs_timezone_to_epoch_number():
    schema = {
        "TACACS_AUTHENTICATION_LAST_TWO_DAYS": {
            "EPOCH_TIME": "NUMBER",
            "TIMESTAMP_TIMEZONE": "TIMESTAMP WITH TIME ZONE",
        },
    }

    sql = dataconnect_freshness._query(
        types.SimpleNamespace(dataconnect_freshness_interval=86400),
        now=2_000_000_000,
        schema=schema,
    )

    assert "EPOCH_TIME >= 1999978400" in sql
    assert "TIMESTAMP_TIMEZONE >= 1999978400" not in sql


def test_freshness_accepts_timezone_only_view_and_rejects_empty_schema():
    schema = {
        "RADIUS_ERRORS_VIEW": {
            "TIMESTAMP_TIMEZONE": "TIMESTAMP WITH TIME ZONE",
        },
    }

    sql = dataconnect_freshness._query(
        types.SimpleNamespace(dataconnect_freshness_interval=86400), schema=schema)

    assert "FROM RADIUS_ERRORS_VIEW" in sql
    assert "TIMESTAMP_TIMEZONE >= SYSTIMESTAMP" in sql
    with pytest.raises(ValueError, match="freshness timestamp"):
        dataconnect_freshness._query(
            types.SimpleNamespace(dataconnect_freshness_interval=86400), schema={})


def test_freshness_statements_stay_within_the_branch_cap_and_batch_ceiling():
    statements = dataconnect_freshness._statements(
        types.SimpleNamespace(dataconnect_freshness_interval=86400))

    assert len(statements) <= dataconnect_freshness._MAX_PROBE_STATEMENTS
    for sql in statements.values():
        # Each branch begins with its own "SELECT '<view>' AS view_name" projection.
        branch_count = len(re.findall(r"SELECT '[a-z_]+' AS view_name", sql))
        assert branch_count <= dataconnect_freshness._MAX_PROBE_BRANCHES_PER_STATEMENT


def test_freshness_statements_all_carry_the_pacing_marker():
    statements = dataconnect_freshness._statements(
        types.SimpleNamespace(dataconnect_freshness_interval=86400))

    assert statements
    for sql in statements.values():
        assert sql.startswith("/* ise_exporter:dataconnect_freshness */")


def test_freshness_merges_chunked_results_into_one_complete_snapshot(monkeypatch):
    client = QueryManyDataConnect()
    monkeypatch.setattr(dataconnect_freshness.time, "time", lambda: 2_000_000_000)

    dataconnect_freshness.collect(client, types.SimpleNamespace(
        dataconnect_event_window_hours=24,
        dataconnect_freshness_interval=86400,
    ))

    # query_many() is called exactly once, batching every chunk under one lease.
    assert len(client.batches) == 1
    statements = client.batches[0]
    assert 1 < len(statements) <= dataconnect_freshness._MAX_PROBE_STATEMENTS

    timestamped = {name.lower() for name, contract in VIEW_CONTRACTS.items()
                   if contract.time_column and contract.freshness_probe}
    rows = _rows(metrics.ise_dataconnect_view_has_recent_rows)
    assert {view for view, _domain in rows} == timestamped
    assert all(value == 1 for value in rows.values())
