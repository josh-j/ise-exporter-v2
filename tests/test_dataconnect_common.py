import types

import pytest

from ise_exporter.collectors.dataconnect_common import (
    event_window_hours,
    hourly_rollup_window_hours,
    integer,
    query_set,
)


@pytest.mark.parametrize("value", (-1, -0.1, 1.5))
def test_count_normalization_rejects_negative_and_fractional_values(value):
    with pytest.raises(ValueError, match="non-negative integer"):
        integer(value)


@pytest.mark.parametrize("value, expected", ((None, 0), ("invalid", 0), ("12", 12)))
def test_count_normalization_preserves_missing_defaults_and_valid_counts(value, expected):
    assert integer(value) == expected


def test_event_window_tracks_cadence_and_never_exceeds_ceiling():
    cfg = types.SimpleNamespace(dataconnect_event_window_hours=24)

    assert event_window_hours(cfg, 3600) == 1
    assert event_window_hours(cfg, 21600) == 6
    assert event_window_hours(cfg, 86400) == 6
    assert event_window_hours(cfg, 90000) == 6


def test_event_window_allows_explicit_lower_pressure_sampling_ceiling():
    cfg = types.SimpleNamespace(dataconnect_event_window_hours=4)

    assert event_window_hours(cfg, 86400) == 4


def test_hourly_rollup_window_does_not_shrink_with_fast_polling():
    cfg = types.SimpleNamespace(dataconnect_event_window_hours=6)

    assert hourly_rollup_window_hours(cfg, 900) == 6


def test_query_set_prefers_atomic_client_batch():
    class Client:
        def query_many(self, statements, parameters):
            return {"statements": statements, "parameters": parameters}

    statements = {"one": "SELECT 1 FROM endpoints_data"}
    parameters = {"one": {"value": 1}}

    assert query_set(Client(), statements, parameters) == {
        "statements": statements, "parameters": parameters}


def test_query_set_retains_simple_test_and_extension_client_compatibility():
    class Client:
        def query(self, sql, parameters=None):
            return [(sql, parameters)]

    assert query_set(
        Client(), {"one": "SELECT 1", "two": "SELECT 2"},
        {"two": {"value": 2}},
    ) == {
        "one": [("SELECT 1", None)],
        "two": [("SELECT 2", {"value": 2})],
    }
