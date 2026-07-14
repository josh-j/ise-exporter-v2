import types

from ise_exporter.collectors.dataconnect_common import event_window_hours


def test_event_window_tracks_cadence_and_never_exceeds_ceiling():
    cfg = types.SimpleNamespace(dataconnect_event_window_hours=24)

    assert event_window_hours(cfg, 3600) == 1
    assert event_window_hours(cfg, 21600) == 6
    assert event_window_hours(cfg, 86400) == 24
    assert event_window_hours(cfg, 90000) == 24


def test_event_window_allows_explicit_lower_pressure_sampling_ceiling():
    cfg = types.SimpleNamespace(dataconnect_event_window_hours=4)

    assert event_window_hours(cfg, 86400) == 4
