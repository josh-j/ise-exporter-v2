"""backup collector (port of collect_backup_metrics). Last config-backup status
via PAN OpenAPI: success timestamp, age in hours, and whether backup is configured."""
import logging
from datetime import datetime, timezone

from .. import metrics
from ..util import parse_ise_date
from . import observe

logger = logging.getLogger(__name__)


def collect(client, cfg, mappings):
    with observe("backup"):
        backup = client.get_pan_api("/backup-restore/config/last-backup-status", api_name="pan_backup")
        if not backup:
            metrics.ise_backup_configured.set(0)
            return

        status = backup.get("status")
        start_date = backup.get("startDate")
        if not status and not start_date:
            metrics.ise_backup_configured.set(0)
            return
        metrics.ise_backup_configured.set(1)

        ts = parse_ise_date(start_date) if (start_date and status == "COMPLETED") else None
        if ts:
            metrics.ise_backup_last_success_timestamp.set(ts.timestamp())
        else:
            logger.info("Backup: last status was %s (not a completed backup)", status)

        # Recompute age on EVERY poll from the last known success timestamp — not just when
        # the current status is COMPLETED. Otherwise a stuck/failed/in-progress backup freezes
        # age_hours at its last value and a 'backup too old' alert never fires during the
        # outage. 0.0 == never seen a completed backup, so leave age unset in that case.
        last_success = metrics.ise_backup_last_success_timestamp._value.get()
        if last_success:
            age_hours = (datetime.now(timezone.utc).timestamp() - last_success) / 3600
            metrics.ise_backup_age_hours.set(age_hours)
            logger.info("Backup: last success %.1f hours ago", age_hours)
