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
                "rows_in_window": 162,
                "oldest_event": datetime(2026, 7, 13, tzinfo=timezone.utc),
                "newest_event": datetime(2026, 7, 14, 4, 30, tzinfo=timezone.utc),
            }]
        return []


def test_collects_row_coverage_and_event_time_boundaries_for_every_timestamped_view():
    client = DataConnect()
    dataconnect_freshness.collect(client, types.SimpleNamespace())

    timestamped = {name.lower(): contract.domain
                   for name, contract in VIEW_CONTRACTS.items() if contract.time_column}
    assert len(client.sql) == len(timestamped)
    assert all("INTERVAL '2' DAY" in sql for sql in client.sql)

    rows = _rows(metrics.ise_dataconnect_view_rows)
    assert set(rows) == {(view, domain) for view, domain in timestamped.items()}
    assert rows[("radius_authentications", "radius_auth")] == 162
    assert _rows(metrics.ise_dataconnect_view_newest_event_timestamp)[
        ("radius_authentications", "radius_auth")] == pytest.approx(1784003400)
    assert _rows(metrics.ise_dataconnect_view_oldest_event_timestamp)[
        ("radius_authentications", "radius_auth")] == pytest.approx(1783900800)


@pytest.mark.parametrize(("value", "expected"), [
    (None, 0),
    (1784003400, 1784003400),
    (1784003400000, 1784003400),
    (datetime(2026, 7, 14, 4, 30), 1784003400),
])
def test_timestamp_normalization(value, expected):
    assert dataconnect_freshness._timestamp(value) == pytest.approx(expected)
