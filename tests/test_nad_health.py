from datetime import datetime, timezone
import types

import pytest

from ise_exporter import metrics
from ise_exporter.collectors import nad_health
from ise_exporter.util import clear_metric, metric_label


@pytest.fixture(autouse=True)
def _clear():
    for metric in nad_health._METRICS:
        clear_metric(metric)


def _rows(metric, *labels):
    return {tuple(sample.labels[label] for label in labels): sample.value
            for sample in metric.collect()[0].samples}


DEVICES = [{"name": "campus-corp-wired"}, {"name": "branch-switch"}]


class DataConnect:
    def query(self, sql):
        assert "NUMTODSINTERVAL(6, 'HOUR')" in sql
        assert "FROM radius_authentication_summary" in sql
        assert "FROM radius_authentications" not in sql
        return [
            {"nad": "CAMPUS-CORP-WIRED", "passed_events": 132, "failed_events": 29,
             "last_event": datetime(2026, 7, 14, 4, 30, tzinfo=timezone.utc),
             "total_groups": 2, "volume_rank": 1, "recency_rank": 1},
            {"nad": "unknown-client", "passed_events": 2, "failed_events": 5,
             "last_event": datetime(2026, 7, 14, 4, 20, tzinfo=timezone.utc),
             "total_groups": 2, "volume_rank": 2, "recency_rank": 2},
        ]


def test_joins_configured_nads_to_activity_without_exporting_unconfigured_names():
    nad_health.collect(DEVICES, DataConnect(), types.SimpleNamespace())

    assert _rows(metrics.ise_nad_seen_recently, "nad") == {
        ("campus-corp-wired",): 1,
        ("branch-switch",): 0,
    }
    assert _rows(metrics.ise_nad_authentication_events, "nad", "status") == {
        ("campus-corp-wired", "passed"): 132,
        ("campus-corp-wired", "failed"): 29,
    }
    assert _rows(metrics.ise_nad_last_authentication_timestamp, "nad")[
        ("campus-corp-wired",)] == pytest.approx(1784003400)
    assert _rows(metrics.ise_nad_last_authentication_timestamp, "nad")[
        ("branch-switch",)] == 0
    assert metrics.ise_nad_unconfigured_authentication_events_topk._value.get() == 7
    assert metrics.ise_nad_inventory_selected._value.get() == 2
    assert metrics.ise_nad_inventory_total._value.get() == 2
    assert metrics.ise_nad_inventory_truncated._value.get() == 0
    assert metrics.ise_nad_activity_groups_returned._value.get() == 2
    assert metrics.ise_nad_activity_groups_total._value.get() == 2
    assert metrics.ise_nad_activity_groups_truncated._value.get() == 0


class SettableActivity:
    """Fake Data Connect returning a settable per-page ranked batch per cycle.

    The statement ranks the grouped rows two ways (volume_rank for the top-K
    activity surface, recency_rank for the wider last-seen refresh surface).
    `rows` should carry both rank columns already set by the caller;
    _activity_row defaults both ranks to 1 for the common single-row case.

    query() distinguishes the conditional "page 2" statement from "page 1" by
    the ``recency_rank >`` marker unique to page 2's WHERE clause, returning
    `page2_rows` (empty by default) for it. Most tests never trigger page 2
    (their `total_groups` stays under nad_health._PAGE1_RECENCY_CAP).
    """

    def __init__(self):
        self.rows = []
        self.page2_rows = []
        self.queries = []

    def query(self, sql):
        self.queries.append(sql)
        if "recency_rank > " in sql:
            return list(self.page2_rows)
        return list(self.rows)


def _activity_row(nad, last_event, passed=1, failed=0, total_groups=1,
                   volume_rank=1, recency_rank=1):
    return {"nad": nad, "passed_events": passed, "failed_events": failed,
            "last_event": last_event, "total_groups": total_groups,
            "volume_rank": volume_rank, "recency_rank": recency_rank}


def test_accumulator_gives_full_inventory_dead_switch_coverage_across_cycles(tmp_path):
    devices = [{"name": "switch-a"}, {"name": "switch-b"}, {"name": "switch-c"}]
    cfg = types.SimpleNamespace(state_db_path=str(tmp_path / "state.sqlite3"))
    client = SettableActivity()
    now = datetime.now(timezone.utc).timestamp()

    def at(days_ago):
        return datetime.fromtimestamp(now - days_ago * 86400, tz=timezone.utc)

    # Cycle 1: only switch-a authenticates, 10 days ago.
    client.rows = [_activity_row("SWITCH-A", at(10))]
    nad_health.collect(devices, client, cfg)

    activity = _rows(metrics.ise_nad_activity_last_authentication_timestamp, "nad")
    assert activity[("switch-a",)] == pytest.approx(now - 10 * 86400, abs=5)
    assert activity[("switch-b",)] == 0
    assert activity[("switch-c",)] == 0
    assert metrics.ise_nad_activity_tracked_total._value.get() == 1
    assert metrics.ise_nad_activity_never_authenticated_total._value.get() == 2

    # Cycle 2: only switch-b authenticates (1 day ago). switch-a has dropped out of
    # the top-K window, but its accumulated last-auth must persist — that is the
    # whole point of the cache versus the bounded per-cycle top-K signal.
    client.rows = [_activity_row("SWITCH-B", at(1))]
    nad_health.collect(devices, client, cfg)

    activity = _rows(metrics.ise_nad_activity_last_authentication_timestamp, "nad")
    assert activity[("switch-a",)] == pytest.approx(now - 10 * 86400, abs=5)
    assert activity[("switch-b",)] == pytest.approx(now - 1 * 86400, abs=5)
    assert activity[("switch-c",)] == 0
    assert metrics.ise_nad_activity_tracked_total._value.get() == 2
    assert metrics.ise_nad_activity_never_authenticated_total._value.get() == 1
    assert _rows(metrics.ise_nad_activity_silent, "threshold_days") == {
        ("7",): 1,   # switch-a (10d) is silent past 7d; switch-b (1d) is not
        ("30",): 0,
    }

    # Cycle 3: switch-a reappears with an OLDER timestamp; the high-water wins.
    client.rows = [_activity_row("SWITCH-A", at(40))]
    nad_health.collect(devices, client, cfg)
    activity = _rows(metrics.ise_nad_activity_last_authentication_timestamp, "nad")
    assert activity[("switch-a",)] == pytest.approx(now - 10 * 86400, abs=5)


def test_accumulator_prunes_decommissioned_nads(tmp_path):
    cfg = types.SimpleNamespace(state_db_path=str(tmp_path / "state.sqlite3"))
    client = SettableActivity()
    event = datetime(2026, 7, 14, tzinfo=timezone.utc)

    client.rows = [_activity_row("OLD-SWITCH", event)]
    nad_health.collect([{"name": "old-switch"}], client, cfg)
    assert metrics.ise_nad_activity_cache_entries._value.get() == 1

    # old-switch leaves the inventory; the accumulator row is pruned with it.
    client.rows = [_activity_row("NEW-SWITCH", event)]
    nad_health.collect([{"name": "new-switch"}], client, cfg)
    assert metrics.ise_nad_activity_cache_entries._value.get() == 1
    activity = _rows(metrics.ise_nad_activity_last_authentication_timestamp, "nad")
    assert set(activity) == {("new-switch",)}


def test_inventory_failure_does_not_publish_plausible_empty_health():
    nad_health.collect(None, DataConnect(), types.SimpleNamespace())
    assert not _rows(metrics.ise_nad_seen_recently, "nad")


def test_raw_configured_nad_name_is_bounded_only_at_metric_boundary():
    raw_name = "switch-" + "x" * 400

    class LongNameActivity:
        def query(self, _sql):
            return [{
                "nad": raw_name.upper(), "passed_events": 1, "failed_events": 0,
                "last_event": datetime(2026, 7, 14, tzinfo=timezone.utc),
                "total_groups": 1, "volume_rank": 1, "recency_rank": 1,
            }]

    nad_health.collect(
        [{"name": raw_name}], LongNameActivity(), types.SimpleNamespace())

    bounded = metric_label(raw_name)
    assert len(bounded.encode("utf-8")) <= 256
    assert _rows(metrics.ise_nad_authentication_events, "nad", "status") == {
        (bounded, "passed"): 1,
        (bounded, "failed"): 0,
    }


def test_nad_health_exports_full_inventory_while_bounding_event_count_topk():
    """dataconnect.max_groups only bounds the top-K volume-ranked telemetry now
    (ise_nad_authentication_events / ise_nad_activity_groups_*). The per-NAD
    seen_recently / last_authentication_timestamp export and
    ise_nad_inventory_selected/truncated cover the FULL configured inventory
    regardless of this limit -- this is the production fix: NAD Inventory
    Export Coverage no longer caps out at dataconnect.max_groups."""
    devices = [{"name": f"switch-{index}"} for index in range(4)]

    class BoundedActivity:
        def query(self, sql):
            assert "COUNT(*) OVER () AS total_groups" in sql
            assert (f"WHERE volume_rank <= 2 OR "
                    f"recency_rank <= {nad_health._PAGE1_RECENCY_CAP}") in sql
            return [
                {"nad": "switch-3", "passed_events": 10, "failed_events": 0,
                 "last_event": datetime(2026, 7, 14, tzinfo=timezone.utc),
                 "total_groups": 3, "volume_rank": 1, "recency_rank": 1},
                {"nad": "unknown-client", "passed_events": 5, "failed_events": 1,
                 "last_event": datetime(2026, 7, 14, tzinfo=timezone.utc),
                 "total_groups": 3, "volume_rank": 2, "recency_rank": 2},
            ]

    nad_health.collect(
        devices, BoundedActivity(),
        types.SimpleNamespace(dataconnect_max_groups=2))

    # Full inventory export: all 4 configured switches get a series, not just
    # the 2 admitted by the (now telemetry-only) dataconnect.max_groups.
    assert _rows(metrics.ise_nad_seen_recently, "nad") == {
        ("switch-0",): 0, ("switch-1",): 0, ("switch-2",): 0, ("switch-3",): 1,
    }
    assert metrics.ise_nad_inventory_selected._value.get() == 4
    assert metrics.ise_nad_inventory_total._value.get() == 4
    assert metrics.ise_nad_inventory_truncated._value.get() == 0
    # Top-K event-count / activity-group telemetry stays bounded by design.
    assert metrics.ise_nad_activity_groups_returned._value.get() == 2
    assert metrics.ise_nad_activity_groups_total._value.get() == 3
    assert metrics.ise_nad_activity_groups_truncated._value.get() == 1
    assert metrics.ise_nad_unconfigured_authentication_events_topk._value.get() == 6


def test_full_inventory_export_survives_a_configured_count_above_the_old_group_limit():
    """The production symptom this fixes: ~3700 configured NADs used to cap
    per-NAD export at dataconnect.max_groups (<=1000). 1500 configured NADs at
    the default 1000 group limit must ALL get a series now, with
    inventory_truncated staying 0 (well under the 10000 safety ceiling)."""
    devices = [{"name": f"switch-{index}"} for index in range(1500)]

    class EmptyActivity:
        def query(self, _sql):
            return []

    nad_health.collect(devices, EmptyActivity(), types.SimpleNamespace())

    assert metrics.ise_nad_inventory_selected._value.get() == 1500
    assert metrics.ise_nad_inventory_total._value.get() == 1500
    assert metrics.ise_nad_inventory_truncated._value.get() == 0
    assert len(_rows(metrics.ise_nad_seen_recently, "nad")) == 1500


def test_safety_ceiling_truncates_only_when_configured_exceeds_it(monkeypatch):
    """The full-inventory export is bounded by a hard safety ceiling
    (_NAD_EXPORT_CEILING), mirroring the devices collector's hard 10000-per-
    pass ceiling. Below it every configured NAD gets a series; above it,
    inventory_truncated finally goes to 1."""
    monkeypatch.setattr(nad_health, "_NAD_EXPORT_CEILING", 5)
    devices = [{"name": f"switch-{index}"} for index in range(8)]

    class EmptyActivity:
        def query(self, _sql):
            return []

    nad_health.collect(devices, EmptyActivity(), types.SimpleNamespace())

    assert metrics.ise_nad_inventory_selected._value.get() == 5
    assert metrics.ise_nad_inventory_total._value.get() == 8
    assert metrics.ise_nad_inventory_truncated._value.get() == 1
    assert len(_rows(metrics.ise_nad_seen_recently, "nad")) == 5


def test_page_two_fires_only_when_total_groups_exceeds_page_one_recency_cap(tmp_path):
    """When active groups this cycle stay within _PAGE1_RECENCY_CAP, only one
    statement is issued (see test_single_statement_scans_the_view_once_with_
    both_rankings). Once total_groups exceeds it -- as expected at a ~5k-NAD
    deployment -- a conditional second statement fetches the remaining
    recency-ranked groups, so a NAD quiet enough to fall outside BOTH the
    top-K volume subset and page 1's recency window still gets full credit."""
    devices = [{"name": "switch-a"}, {"name": "switch-far"}]
    cfg = types.SimpleNamespace(state_db_path=str(tmp_path / "state.sqlite3"),
                                 dataconnect_max_groups=1)
    client = SettableActivity()
    now = datetime.now(timezone.utc).timestamp()

    def at(days_ago):
        return datetime.fromtimestamp(now - days_ago * 86400, tz=timezone.utc)

    page1_total = nad_health._PAGE1_RECENCY_CAP + 1
    # switch-a wins the (deliberately tiny) top-K volume subset; total_groups
    # is set just above _PAGE1_RECENCY_CAP to force page 2.
    client.rows = [
        _activity_row("SWITCH-A", at(0), passed=1000, total_groups=page1_total,
                      volume_rank=1, recency_rank=1),
    ]
    # switch-far is outside the top-K volume subset AND outside page 1's
    # recency window -- only page 2's wider recency window reaches it.
    client.page2_rows = [
        _activity_row("SWITCH-FAR", at(2), passed=3, total_groups=page1_total,
                      volume_rank=2, recency_rank=page1_total),
    ]

    nad_health.collect(devices, client, cfg)

    assert len(client.queries) == 2
    assert "recency_rank > " not in client.queries[0]
    assert "recency_rank > " in client.queries[1]
    assert _rows(metrics.ise_nad_seen_recently, "nad") == {
        ("switch-a",): 1, ("switch-far",): 1,
    }
    assert _rows(metrics.ise_nad_last_authentication_timestamp, "nad")[
        ("switch-far",)] == pytest.approx(now - 2 * 86400, abs=5)
    assert _rows(metrics.ise_nad_authentication_events, "nad", "status")[
        ("switch-far", "passed")] == 3


def test_paged_queries_cannot_exceed_the_data_connect_result_row_ceiling():
    """No constructible input can make either paged statement return >=
    MAX_RESULT_ROWS (6000) rows, the hard ceiling clients/dataconnect.py
    enforces. Page 1's worst case is the hard max group_limit (1000) plus its
    recency cap; page 2's worst case is the width between the two caps."""
    from ise_exporter.clients.dataconnect import MAX_RESULT_ROWS

    worst_case_page1 = 1000 + nad_health._PAGE1_RECENCY_CAP
    worst_case_page2 = nad_health._LAST_SEEN_ROW_CAP - nad_health._PAGE1_RECENCY_CAP

    assert worst_case_page1 < MAX_RESULT_ROWS
    assert worst_case_page2 < MAX_RESULT_ROWS


def test_refresh_statement_updates_last_seen_for_nads_below_topk_cutoff(tmp_path):
    """A NAD ranked out of the top-K activity subset by event volume still gets
    its accumulated last-seen timestamp refreshed via the recency-ranked
    subset of the SAME single-scan statement, and is therefore not wrongly
    counted silent. It also gets full credit on the per-window
    seen_recently / last_authentication_timestamp / authentication_events
    series -- the wide paged surface, not just the top-K activity subset,
    feeds those now."""
    devices = [{"name": "switch-a"}, {"name": "switch-b"}]
    cfg = types.SimpleNamespace(state_db_path=str(tmp_path / "state.sqlite3"))
    client = SettableActivity()
    now = datetime.now(timezone.utc).timestamp()

    def at(days_ago):
        return datetime.fromtimestamp(now - days_ago * 86400, tz=timezone.utc)

    # switch-a is busy enough to rank into the top-K activity subset
    # (volume_rank 1, within the default 1000 limit). switch-b is quiet
    # (volume_rank 1500 simulates falling below the top-K cutoff in a real
    # deployment with >1000 active NADs) but authenticated recently -- only
    # its recency_rank <= _PAGE1_RECENCY_CAP admits it into the refresh subset.
    client.rows = [
        _activity_row("SWITCH-A", at(0), passed=1000, total_groups=2,
                      volume_rank=1, recency_rank=2),
        _activity_row("SWITCH-B", at(1), passed=3, total_groups=2,
                      volume_rank=1500, recency_rank=1),
    ]
    nad_health.collect(devices, client, cfg)

    activity = _rows(metrics.ise_nad_activity_last_authentication_timestamp, "nad")
    assert activity[("switch-b",)] == pytest.approx(now - 1 * 86400, abs=5)
    assert metrics.ise_nad_activity_tracked_total._value.get() == 2
    assert _rows(metrics.ise_nad_activity_silent, "threshold_days") == {
        ("7",): 0,
        ("30",): 0,
    }

    # Wide-surface per-window export: switch-b is present only via the
    # recency-ranked refresh subset (outside the top-K volume subset), yet its
    # seen_recently / last_authentication_timestamp / authentication_events
    # are all populated as if it had been in the top-K.
    assert _rows(metrics.ise_nad_seen_recently, "nad")[("switch-b",)] == 1
    assert _rows(metrics.ise_nad_last_authentication_timestamp, "nad")[
        ("switch-b",)] == pytest.approx(now - 1 * 86400, abs=5)
    assert _rows(metrics.ise_nad_authentication_events, "nad", "status")[
        ("switch-b", "passed")] == 3


def test_refresh_truncation_metrics_set_when_total_exceeds_returned(tmp_path):
    devices = [{"name": "switch-a"}]
    cfg = types.SimpleNamespace(state_db_path=str(tmp_path / "state.sqlite3"))
    client = SettableActivity()
    event = datetime(2026, 7, 14, tzinfo=timezone.utc)

    client.rows = [_activity_row("SWITCH-A", event, total_groups=9000,
                                  volume_rank=1, recency_rank=1)]
    nad_health.collect(devices, client, cfg)

    assert metrics.ise_nad_activity_refresh_groups_returned._value.get() == 1
    assert metrics.ise_nad_activity_refresh_groups_total._value.get() == 9000
    assert metrics.ise_nad_activity_refresh_truncated._value.get() == 1


def test_single_statement_scans_the_view_once_with_both_rankings():
    """LE-8: the merged statement must compute both the top-K volume ranking
    and the wider recency ranking over ONE scan/aggregation of the 6h window,
    not two separate statements each scanning radius_authentication_summary.
    When total_groups stays within _PAGE1_RECENCY_CAP (as here, an empty
    result), the conditional page-2 statement never fires either."""
    captured = {}

    class CapturingActivity:
        def __init__(self):
            self.calls = 0

        def query(self, sql):
            self.calls += 1
            captured["sql"] = sql
            return []

    client = CapturingActivity()
    nad_health.collect(DEVICES, client, types.SimpleNamespace())

    sql = captured["sql"]
    assert "volume_rank" in sql
    assert "recency_rank" in sql
    assert sql.lower().count("radius_authentication_summary") == 1
    assert client.calls == 1
