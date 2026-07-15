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
    def __init__(self):
        self.sql = []

    def query(self, sql):
        self.sql.append(sql)
        if "RADIUS_AUTHENTICATIONS" in sql:
            return [{
                "newest_event": datetime(2026, 7, 14, 4, 30, tzinfo=timezone.utc),
            }]
        return []


def test_collects_bounded_presence_and_newest_event_for_every_timestamped_view(
        monkeypatch):
    client = DataConnect()
    monkeypatch.setattr(dataconnect_freshness.time, "time", lambda: 2_000_000_000)
    dataconnect_freshness.collect(client, types.SimpleNamespace(
        dataconnect_event_window_hours=24,
        dataconnect_freshness_interval=86400,
    ))

    timestamped = {name.lower(): contract.domain
                   for name, contract in VIEW_CONTRACTS.items() if contract.time_column}
    assert len(client.sql) == len(timestamped)
    tacacs_sql = [sql for sql in client.sql if "TACACS_" in sql]
    assert len(tacacs_sql) == 3
    assert all("EPOCH_TIME >= 1999913600" in sql and "INTERVAL '2' DAY" not in sql
               for sql in tacacs_sql)
    assert all("NUMTODSINTERVAL(24, 'HOUR')" in sql
               for sql in client.sql if "TACACS_" not in sql)
    assert all("COUNT(" not in sql and "MIN(" not in sql and "MAX(" not in sql
               for sql in client.sql)
    assert all("FETCH FIRST 1 ROWS ONLY" in sql for sql in client.sql)
    assert all("DESC NULLS LAST" in sql for sql in client.sql)

    rows = _rows(metrics.ise_dataconnect_view_has_rows)
    assert set(rows) == {(view, domain) for view, domain in timestamped.items()}
    assert rows[("radius_authentications", "radius_auth")] == 1
    assert rows[("radius_accounting", "radius_accounting")] == 0
    assert _rows(metrics.ise_dataconnect_view_newest_event_timestamp)[
        ("radius_authentications", "radius_auth")] == pytest.approx(1784003400)


def test_freshness_honors_lower_production_scan_ceiling(monkeypatch):
    client = DataConnect()
    monkeypatch.setattr(dataconnect_freshness.time, "time", lambda: 2_000_000_000)

    dataconnect_freshness.collect(client, types.SimpleNamespace(
        dataconnect_event_window_hours=4,
        dataconnect_freshness_interval=86400,
    ))

    assert all("EPOCH_TIME >= 1999985600" in sql
               for sql in client.sql if "TACACS_" in sql)
    assert all("NUMTODSINTERVAL(4, 'HOUR')" in sql
               for sql in client.sql if "TACACS_" not in sql)


@pytest.mark.parametrize(("value", "expected"), [
    (None, 0),
    (1784003400, 1784003400),
    (1784003400000, 1784003400),
    (datetime(2026, 7, 14, 4, 30), 1784003400),
])
def test_timestamp_normalization(value, expected):
    assert dataconnect_freshness._timestamp(value) == pytest.approx(expected)
