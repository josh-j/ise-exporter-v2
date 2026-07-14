"""backup collector (port of collect_backup_metrics). Last config-backup status
via PAN OpenAPI: success timestamp, age in hours, and whether backup is configured."""
import logging
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

        ts = parse_ise_date(start_date) if (start_date and status == "COMPLETED") else None
        if status == "COMPLETED" and start_date and ts is None:
            raise CollectorFailed("completed backup returned an invalid startDate")
        previous_success = metrics.ise_backup_last_success_timestamp._value.get()
        last_success = ts.timestamp() if ts else previous_success
        age_hours = ((datetime.now(timezone.utc).timestamp() - last_success) / 3600
                     if last_success else 0)

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
