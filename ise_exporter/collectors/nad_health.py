"""Configured network-device activity health.

ERS is authoritative for the configured NAD inventory while Data Connect is
authoritative for recent authentication activity. The scheduler passes the last
successful REST-owned inventory into this Data Connect-only collector, avoiding
cross-plane network calls on the serialized database worker.
"""
from __future__ import annotations

from collections import defaultdict
from datetime import datetime, timezone
import logging
import time

from .. import metrics
from ..snapshots import replace_metric_snapshot
from ..state import StateStore
from ..util import metric_label, parse_ise_date
from . import CollectorFailed, observe
from .dataconnect_common import (
    event_window_hours,
    group_limit,
    integer,
    recent_event_predicate,
    schema_expression,
)


logger = logging.getLogger(__name__)

# Silence thresholds for the accumulated full-inventory "dead switch" signal.
_SILENT_DAYS = (7, 30)

# Data Connect's client-side result-row safety ceiling (MAX_RESULT_ROWS in
# clients/dataconnect.py) hard-fails ANY single statement at >=6000 rows. The
# grouped 6h scan below is ranked two ways: volume top-K (<=1000, group_limit)
# feeds ise_nad_authentication_events' bounded activity-group telemetry;
# recency rank feeds the much wider last-seen refresh surface that the per-NAD
# seen_recently / last_authentication_timestamp export and the restart-
# persistent accumulator are actually sourced from (see `collect()`). A single
# statement bounded by `volume_rank <= limit OR recency_rank <= cap` would need
# `cap` kept small to stay under 6000 rows -- too narrow for a ~5000-NAD /
# ~90k-endpoint deployment, where active groups in one 6h window can run well
# past a few thousand.
#
# Instead the scan is PAGED across up to two statements built from the
# identical grouped/ranked CTE:
#   Page 1 (always issued): `volume_rank <= limit OR recency_rank <=
#           _PAGE1_RECENCY_CAP`. Worst case <= 1000 + 4500 = 5500 rows,
#           comfortably under 6000.
#   Page 2 (fires only when page 1's exact `total_groups` -- computed by
#           COUNT(*) OVER () before either page's row bound, so it is never
#           itself truncated -- exceeds _PAGE1_RECENCY_CAP, meaning active
#           groups remain outside page 1's recency coverage): recency_rank in
#           (_PAGE1_RECENCY_CAP, _LAST_SEEN_ROW_CAP], excluding volume_rank <=
#           limit rows page 1 already returned. Worst case <= 9500 - 4500 =
#           5000 rows, also comfortably under 6000.
# Together the two pages reconstruct exactly the coverage a single unbounded
# `volume_rank <= limit OR recency_rank <= _LAST_SEEN_ROW_CAP` statement would
# give, without either statement risking the 6000-row ceiling. Recency-ranked
# groups beyond _LAST_SEEN_ROW_CAP are the least-recently-active tail, the
# safest to leave until next cycle. These are fixed module constants rather
# than a runtime config knob: raising the covered surface safely requires
# raising BOTH together while keeping each page's own worst case under 6000,
# not a value an operator can set in isolation. Raise them (in code) if a
# deployment's active-group count approaches _LAST_SEEN_ROW_CAP; today's
# largest known deployment (2608 active groups in a 6h window) is comfortably
# inside page 1 alone.
_PAGE1_RECENCY_CAP = 4500
_LAST_SEEN_ROW_CAP = 9500

# Hard per-cycle ceiling on individually labeled NAD series
# (ise_nad_seen_recently, ise_nad_last_authentication_timestamp), mirroring the
# devices collector's hard 10000-per-pass ceiling (DETAIL_REQUEST_CEILING).
# Below this, every configured NAD gets its own series regardless of
# dataconnect.max_groups, which only bounds the top-K volume-ranked telemetry
# below (ise_nad_activity_groups_*) -- it no longer caps the per-NAD export.
# Above the ceiling, the busiest/most-recently-seen NADs this cycle are kept
# and the remainder of the inventory fills in sorted order until the ceiling
# is reached; any NADs still left out only miss these two per-window series --
# the restart-persistent ise_nad_activity_last_authentication_timestamp
# accumulator has no such ceiling.
_NAD_EXPORT_CEILING = 10000

_METRICS = (
    metrics.ise_nad_authentication_events,
    metrics.ise_nad_last_authentication_timestamp,
    metrics.ise_nad_seen_recently,
    metrics.ise_nad_unconfigured_authentication_events_topk,
    metrics.ise_nad_inventory_selected,
    metrics.ise_nad_inventory_total,
    metrics.ise_nad_inventory_truncated,
    metrics.ise_nad_activity_groups_returned,
    metrics.ise_nad_activity_groups_total,
    metrics.ise_nad_activity_groups_truncated,
    metrics.ise_nad_activity_last_authentication_timestamp,
    metrics.ise_nad_activity_tracked_total,
    metrics.ise_nad_activity_never_authenticated_total,
    metrics.ise_nad_activity_silent,
    metrics.ise_nad_activity_cache_entries,
    metrics.ise_nad_activity_refresh_groups_returned,
    metrics.ise_nad_activity_refresh_groups_total,
    metrics.ise_nad_activity_refresh_truncated,
)


def _timestamp(value):
    if value is None:
        return 0.0
    if isinstance(value, datetime):
        if value.tzinfo is None:
            value = value.replace(tzinfo=timezone.utc)
        return value.timestamp()
    parsed = parse_ise_date(str(value))
    if not parsed:
        return 0.0
    if parsed.tzinfo is None:
        parsed = parsed.replace(tzinfo=timezone.utc)
    return parsed.timestamp()


def collect(devices, dataconnect, cfg):
    """Publish recent activity only for configured NAD labels."""
    with observe("dataconnect_nad_health"):
        if devices is None or not isinstance(devices, list):
            raise CollectorFailed("network device inventory unavailable for NAD health")
        configured = {}
        canonical = {}
        for row in devices:
            if not isinstance(row, dict):
                continue
            raw_name = str(row.get("name") or "").strip()
            if not raw_name:
                continue
            bounded_name = metric_label(raw_name)
            configured[bounded_name] = row
            # Match the reporting view against ISE's full configured name, but
            # publish only the deterministic byte-bounded metric identity.
            canonical[raw_name.casefold()] = bounded_name

        recent = recent_event_predicate(
            "timestamp", event_window_hours(
                cfg, getattr(cfg, "dataconnect_nad_health_interval", 21600)))
        limit = group_limit(cfg)
        schema = getattr(dataconnect, "schema", None)
        view = "RADIUS_AUTHENTICATION_SUMMARY"
        device = schema_expression(schema, view, "device_name", "'unknown'")
        cte = f"""
            WITH grouped_activity AS (
                SELECT NVL({device}, 'unknown') AS nad,
                       SUM(NVL(passed_count, 0)) AS passed_events,
                       SUM(NVL(failed_count, 0)) AS failed_events,
                       MAX(timestamp) AS last_event,
                       COUNT(*) OVER () AS total_groups
                FROM radius_authentication_summary
                WHERE {recent}
                GROUP BY NVL({device}, 'unknown')
            ), ranked_activity AS (
                SELECT grouped_activity.*,
                       ROW_NUMBER() OVER (
                           ORDER BY passed_events + failed_events DESC, nad
                       ) AS volume_rank,
                       ROW_NUMBER() OVER (
                           ORDER BY last_event DESC, nad
                       ) AS recency_rank
                FROM grouped_activity
            )
        """

        # Page 1: see the module comment above _PAGE1_RECENCY_CAP for the row-
        # ceiling math. Always issued; covers every deployment on its own
        # unless this cycle's active groups exceed _PAGE1_RECENCY_CAP.
        page1_sql = cte + f"""
            SELECT * FROM ranked_activity
            WHERE volume_rank <= {limit} OR recency_rank <= {_PAGE1_RECENCY_CAP}
        """
        combined = list(dataconnect.query(page1_sql))
        total_groups = integer(combined[0].get("total_groups")) if combined else 0

        # Page 2: only when page 1's exact total_groups shows active groups
        # remain outside its recency coverage. `volume_rank > {limit}` excludes
        # rows page 1 already returned via its volume clause, so the two pages
        # never return the same group twice.
        if total_groups > _PAGE1_RECENCY_CAP:
            page2_sql = cte + f"""
                SELECT * FROM ranked_activity
                WHERE recency_rank > {_PAGE1_RECENCY_CAP}
                      AND recency_rank <= {_LAST_SEEN_ROW_CAP}
                      AND volume_rank > {limit}
            """
            combined.extend(dataconnect.query(page2_sql))
            achieved_recency_cap = _LAST_SEEN_ROW_CAP
        else:
            achieved_recency_cap = _PAGE1_RECENCY_CAP

        # `activity` (top-K by event volume) and `refresh` (recency-ranked, up
        # to whichever cap this cycle achieved) exist only to preserve the
        # bounded-by-design ise_nad_activity_groups_* / refresh_groups_*
        # telemetry below, exactly as the old standalone "activity"/"refresh"
        # statements did. Actual per-NAD event counts and last-seen timestamps
        # are sourced from ALL of `combined` (both pages merged, see the loop
        # below) -- every configured NAD the scan saw this cycle gets full
        # credit, not just the top-K by volume.
        activity = [row for row in combined if integer(row.get("volume_rank")) <= limit]
        if total_groups < len(activity):
            raise CollectorFailed("NAD activity total was smaller than returned groups")

        refresh = [row for row in combined
                   if integer(row.get("recency_rank")) <= achieved_recency_cap]
        if total_groups < len(refresh):
            raise CollectorFailed("NAD last-seen refresh total was smaller than returned groups")
        refresh_total_groups = total_groups

        # ise_nad_unconfigured_authentication_events_topk stays scoped to the
        # top-K volume subset, exactly matching its own name/documented meaning.
        unconfigured = 0
        for row in activity:
            reported = str(row.get("nad") or "unknown").strip()
            if canonical.get(reported.casefold()) is None:
                unconfigured += (integer(row.get("passed_events"))
                                  + integer(row.get("failed_events")))

        # Full-surface consumption: every row either page returned, regardless
        # of volume or recency rank, feeds per-NAD event counts and last-seen.
        # A quiet-but-alive NAD that ranked out of the top-K volume subset but
        # was still returned via page 1's or page 2's recency clause gets full
        # credit here -- that is the whole point of the wide paged surface.
        counts = defaultdict(int)
        last_seen = defaultdict(float)
        # dict preserves first-seen row order while keeping membership O(1);
        # the paged surface can reach ~9500 rows on the serialized worker lane.
        active_configured = {}
        for row in combined:
            reported = str(row.get("nad") or "unknown").strip()
            name = canonical.get(reported.casefold())
            if name is None:
                continue
            passed = integer(row.get("passed_events"))
            failed = integer(row.get("failed_events"))
            active_configured[name] = True
            counts[(name, "passed")] += passed
            counts[(name, "failed")] += failed
            last_seen[name] = max(last_seen[name], _timestamp(row.get("last_event")))

        # Every configured NAD gets a per-window seen_recently /
        # last_authentication_timestamp series up to _NAD_EXPORT_CEILING (see
        # module comment) -- dataconnect.max_groups no longer caps this export.
        # Preserve the most operationally useful active devices first, then
        # fill the remaining ceiling budget deterministically with the rest of
        # the configured inventory.
        selected = list(active_configured)[:_NAD_EXPORT_CEILING]
        chosen = set(selected)
        selected.extend(
            name for name in sorted(configured, key=str.casefold)
            if name not in chosen and len(selected) < _NAD_EXPORT_CEILING)

        now = time.time()
        store = StateStore(getattr(cfg, "state_db_path", ":memory:"))
        try:
            for name, seen_at in last_seen.items():
                if seen_at > 0:
                    store.put_nad_activity(name, seen_at, now=now)
            store.commit()
            store.finish_nad_activity_cycle(list(configured), now=now)
            cached_activity = store.nad_activity_all()
            activity_cache_entries = store.nad_activity_count()
        finally:
            store.close()

        tracked = len(cached_activity)
        never_authenticated = max(0, len(configured) - tracked)
        silent = {
            days: sum(1 for seen_at in cached_activity.values()
                      if 0 < seen_at < now - days * 86400)
            for days in _SILENT_DAYS
        }

        writers = [
            lambda: metrics.ise_nad_unconfigured_authentication_events_topk.set(
                unconfigured),
            lambda: metrics.ise_nad_inventory_selected.set(len(selected)),
            lambda: metrics.ise_nad_inventory_total.set(len(configured)),
            lambda: metrics.ise_nad_inventory_truncated.set(
                int(len(configured) > len(selected))),
            lambda: metrics.ise_nad_activity_groups_returned.set(len(activity)),
            lambda: metrics.ise_nad_activity_groups_total.set(total_groups),
            lambda: metrics.ise_nad_activity_groups_truncated.set(
                int(total_groups > len(activity))),
            lambda: metrics.ise_nad_activity_refresh_groups_returned.set(len(refresh)),
            lambda: metrics.ise_nad_activity_refresh_groups_total.set(
                refresh_total_groups),
            lambda: metrics.ise_nad_activity_refresh_truncated.set(
                int(refresh_total_groups > len(refresh))),
        ]
        for name in selected:
            writers.extend((
                lambda name=name: metrics.ise_nad_seen_recently.labels(nad=name).set(
                    int(last_seen[name] > 0)),
                lambda name=name: metrics.ise_nad_last_authentication_timestamp.labels(
                    nad=name).set(last_seen[name]),
            ))
        writers.extend(
            lambda name=name, status=status, count=count:
                metrics.ise_nad_authentication_events.labels(
                    nad=name, status=status).set(count)
            for (name, status), count in counts.items()
        )
        # Full-inventory accumulated dead-switch coverage. One timestamp series
        # per configured NAD (0 = never observed); dashboards threshold on age.
        writers.extend(
            lambda name=name, seen_at=cached_activity.get(name, 0.0):
                metrics.ise_nad_activity_last_authentication_timestamp.labels(
                    nad=name).set(seen_at)
            for name in configured
        )
        writers.extend((
            lambda: metrics.ise_nad_activity_tracked_total.set(tracked),
            lambda: metrics.ise_nad_activity_never_authenticated_total.set(
                never_authenticated),
            lambda: metrics.ise_nad_activity_cache_entries.set(
                activity_cache_entries),
        ))
        writers.extend(
            lambda days=days, count=count: metrics.ise_nad_activity_silent.labels(
                threshold_days=str(days)).set(count)
            for days, count in silent.items()
        )
        replace_metric_snapshot(_METRICS, writers)
