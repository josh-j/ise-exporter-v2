import types

from ise_exporter.collectors.dataconnect_common import event_window_hours, query_set


def test_event_window_tracks_cadence_and_never_exceeds_ceiling():
    cfg = types.SimpleNamespace(dataconnect_event_window_hours=24)

    assert event_window_hours(cfg, 3600) == 1
    assert event_window_hours(cfg, 21600) == 6
    assert event_window_hours(cfg, 86400) == 6
    assert event_window_hours(cfg, 90000) == 6


def test_event_window_allows_explicit_lower_pressure_sampling_ceiling():
    cfg = types.SimpleNamespace(dataconnect_event_window_hours=4)

    assert event_window_hours(cfg, 86400) == 4


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
