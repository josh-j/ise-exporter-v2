"""Configured network-device activity health.

ERS is authoritative for the configured NAD inventory while Data Connect is
authoritative for recent authentication activity.  Joining the two inside one
collector exposes never-seen devices and unconfigured-client traffic without
exporting endpoint or user identity.
"""
from __future__ import annotations

from collections import defaultdict
from datetime import datetime, timezone

from .. import metrics
from ..snapshots import replace_metric_snapshot
from ..util import parse_ise_date
from . import CollectorFailed, observe
from .dataconnect_common import integer


_METRICS = (
    metrics.ise_nad_authentication_events,
    metrics.ise_nad_last_authentication_timestamp,
    metrics.ise_nad_seen_recently,
    metrics.ise_nad_unconfigured_authentication_events_total,
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


def collect(client, dataconnect, cfg):
    """Publish recent activity only for configured NAD labels."""
    del cfg
    with observe("dataconnect_nad_health"):
        devices = client.get_ers("/config/networkdevice", {"size": 100}, get_all=True,
                                 api_name="ers_nad_health_devices")
        if devices is None or not isinstance(devices, list):
            raise CollectorFailed("network device inventory unavailable for NAD health")
        configured = {str(row.get("name") or "").strip(): row for row in devices
                      if isinstance(row, dict) and str(row.get("name") or "").strip()}
        canonical = {name.casefold(): name for name in configured}

        activity = dataconnect.query("""
            SELECT NVL(device_name, 'unknown') AS nad,
                   CASE WHEN NVL(failed, 0) > 0 THEN 'failed' ELSE 'passed' END AS status,
                   COUNT(*) AS events,
                   MAX(timestamp) AS last_event
            FROM radius_authentications
            WHERE timestamp >= SYSTIMESTAMP - INTERVAL '2' DAY
            GROUP BY NVL(device_name, 'unknown'),
                     CASE WHEN NVL(failed, 0) > 0 THEN 'failed' ELSE 'passed' END
        """)

        counts = defaultdict(int)
        last_seen = defaultdict(float)
        unconfigured = 0
        for row in activity:
            reported = str(row.get("nad") or "unknown").strip()
            name = canonical.get(reported.casefold())
            events = integer(row.get("events"))
            if name is None:
                unconfigured += events
                continue
            status = str(row.get("status") or "unknown").strip().lower()
            counts[(name, status)] += events
            last_seen[name] = max(last_seen[name], _timestamp(row.get("last_event")))

        writers = [
            lambda: metrics.ise_nad_unconfigured_authentication_events_total.set(unconfigured)
        ]
        for name in configured:
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
        replace_metric_snapshot(_METRICS, writers)
