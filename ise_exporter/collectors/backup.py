"""backup collector (port of collect_backup_metrics). Last config-backup status
via PAN OpenAPI: success timestamp, age in hours, and whether backup is configured."""
import logging
import math
from datetime import datetime, timezone

from .. import metrics
from ..snapshots import replace_metric_snapshot
from ..util import parse_ise_date
from . import CollectorFailed, observe

logger = logging.getLogger(__name__)

_METRICS = (
    metrics.ise_backup_configured,
    metrics.ise_backup_last_success_timestamp,
    metrics.ise_backup_age_hours,
)
_STATUSES = frozenset({"COMPLETED", "ERROR", "IN_PROGRESS"})
_MAX_FUTURE_SKEW_SECONDS = 300


def collect(client, cfg):
    with observe("backup"):
        backup = client.get_pan_api("/backup-restore/config/last-backup-status", api_name="pan_backup")
        if backup is None:
            raise CollectorFailed("backup status request failed")
        if not isinstance(backup, dict):
            raise CollectorFailed("backup status response was not an object")

        status = backup.get("status")
        start_date = backup.get("startDate")
        if not status and not start_date:
            replace_metric_snapshot(_METRICS, ())
            return
        if not isinstance(status, str) or status not in _STATUSES:
            raise CollectorFailed("backup status response contained an invalid status")

        if status == "COMPLETED" and not start_date:
            raise CollectorFailed("completed backup returned no startDate")
        ts = parse_ise_date(start_date) if (start_date and status == "COMPLETED") else None
        if status == "COMPLETED" and ts is None:
            raise CollectorFailed("completed backup returned an invalid startDate")
        now = datetime.now(timezone.utc).timestamp()
        if ts and ts.timestamp() > now + _MAX_FUTURE_SKEW_SECONDS:
            raise CollectorFailed("completed backup returned a future startDate")
        previous_success = metrics.ise_backup_last_success_timestamp._value.get()
        if (not math.isfinite(previous_success) or previous_success < 0
                or previous_success > now + _MAX_FUTURE_SKEW_SECONDS):
            previous_success = 0
        last_success = ts.timestamp() if ts else previous_success
        age_hours = max(0.0, (now - last_success) / 3600) if last_success else 0

        def publish():
            metrics.ise_backup_configured.set(1)
            if last_success:
                metrics.ise_backup_last_success_timestamp.set(last_success)
                metrics.ise_backup_age_hours.set(age_hours)

        replace_metric_snapshot(_METRICS, (publish,))
        if not ts:
            logger.info("Backup: last status was %s (not a completed backup)", status)
        if last_success:
            logger.info("Backup: last success %.1f hours ago", age_hours)
