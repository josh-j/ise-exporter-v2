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

# The volume ranking below (top-K by event count, capped at `group_limit`,
# <=1000) alone would starve quiet-but-alive NADs below that cutoff of a
# last-seen refresh. A second ranking of the SAME grouped rows by recency
# (MAX(timestamp) DESC) gives the accumulator a wider refresh surface, unioned
# into one result via `volume_rank <= limit OR recency_rank <= _LAST_SEEN_ROW_CAP`
# so the window is scanned/aggregated only once. The union is bounded by
# limit + _LAST_SEEN_ROW_CAP (<=1000 + 5000 = 6000), comfortably at the Data
# Connect client's per-statement row ceiling; recency-ranked rows dropped past
# the cap are the least-recently-active tail, the safest rows to leave stale.
_LAST_SEEN_ROW_CAP = 5000

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
        sql = f"""
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
            SELECT * FROM ranked_activity
            WHERE volume_rank <= {limit} OR recency_rank <= {_LAST_SEEN_ROW_CAP}
        """
        combined = dataconnect.query(sql)

        # One scan of the 6h window, ranked two ways. `activity` is the top-K
        # by event volume (feeds event counts / selection, exactly what the old
        # standalone "activity" statement fed); `refresh` is the wider
        # recency-ranked surface (feeds the last-seen accumulator, exactly what
        # the old standalone "refresh" statement fed). A row can appear in both
        # when it is both busy and recent.
        activity = [row for row in combined if integer(row.get("volume_rank")) <= limit]
        refresh = [row for row in combined
                   if integer(row.get("recency_rank")) <= _LAST_SEEN_ROW_CAP]

        total_groups = integer(combined[0].get("total_groups")) if combined else 0
        if total_groups < len(activity):
            raise CollectorFailed("NAD activity total was smaller than returned groups")

        # Both rankings are computed over the same single grouped scan, so they
        # share one total_groups value.
        refresh_total_groups = total_groups
        if refresh_total_groups < len(refresh):
            raise CollectorFailed("NAD last-seen refresh total was smaller than returned groups")

        counts = defaultdict(int)
        last_seen = defaultdict(float)
        unconfigured = 0
        active_configured = []
        for row in activity:
            reported = str(row.get("nad") or "unknown").strip()
            name = canonical.get(reported.casefold())
            passed = integer(row.get("passed_events"))
            failed = integer(row.get("failed_events"))
            if name is None:
                unconfigured += passed + failed
                continue
            if name not in active_configured:
                active_configured.append(name)
            counts[(name, "passed")] += passed
            counts[(name, "failed")] += failed
            last_seen[name] = max(last_seen[name], _timestamp(row.get("last_event")))

        # Preserve the most operationally useful active devices, then fill the
        # remaining bounded budget deterministically with inactive inventory.
        selected = active_configured[:limit]
        selected.extend(
            name for name in sorted(configured, key=str.casefold)
            if name not in selected and len(selected) < limit)

        # Recency-ranked refresh rows for the accumulator (see _LAST_SEEN_ROW_CAP
        # comment): a much wider surface than the top-K activity rows, which
        # rank by event volume and starve quiet-but-alive NADs of a refresh.
        refresh_last_seen = defaultdict(float)
        for row in refresh:
            reported = str(row.get("nad") or "unknown").strip()
            name = canonical.get(reported.casefold())
            if name is None:
                continue
            refresh_last_seen[name] = max(
                refresh_last_seen[name], _timestamp(row.get("last_event")))

        # Accumulate the high-water last-authentication timestamp for every
        # configured NAD across cycles. Drive the accumulation primarily from the
        # recency-ranked refresh rows (wide coverage); also fold in the
        # top-K activity rows (a subset, harmless) so both surfaces agree.
        accumulate = defaultdict(float)
        for name, seen_at in refresh_last_seen.items():
            accumulate[name] = max(accumulate[name], seen_at)
        for name, seen_at in last_seen.items():
            accumulate[name] = max(accumulate[name], seen_at)

        now = time.time()
        store = StateStore(getattr(cfg, "state_db_path", ":memory:"))
        try:
            for name, seen_at in accumulate.items():
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
