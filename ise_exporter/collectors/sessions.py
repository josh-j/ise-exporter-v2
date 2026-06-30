"""sessions collector (port of collect_session_metrics). MnT Session/ActiveList
fanned out by NAD IP, ops-owner, and PSN. Every known NAD gets a series (zero
included) so a NAD dropping to zero sessions is visible rather than vanishing.
Skipped when streaming is on — the pxGrid session topic feeds these gauges then."""
import logging
from collections import defaultdict

from .. import metrics
from ..util import clear_metric
from . import observe, CollectorFailed

logger = logging.getLogger(__name__)


def collect(client, cfg, mappings):
    with observe("sessions"):
        result = client.get_mnt_xml("/Session/ActiveList", api_name="mnt_sessions")
        if result is None:
            raise CollectorFailed("no ActiveList response")
        total = result.get("total", 0)
        sessions = result.get("sessions", [])

        metrics.ise_active_sessions.set(total)
        clear_metric(metrics.ise_radius_sessions_by_nad)
        clear_metric(metrics.ise_radius_sessions_by_ops_owner)
        clear_metric(metrics.ise_radius_sessions_by_psn)

        nad_counts = defaultdict(int)
        ops_counts = defaultdict(int)
        psn_counts = defaultdict(int)
        host_map = mappings["hostname"]
        loc_map = mappings["location"]
        ops_map = mappings["ops_owner"]

        for s in sessions:
            nas_ip = s.get("nas_ip_address", "unknown")
            nad_counts[nas_ip] += 1
            owner = ops_map.get(nas_ip, "unknown")
            if owner != "unknown":
                ops_counts[owner] += 1
            psn_counts[s.get("server", "unknown")] += 1

        # union of known NADs and NADs seen in sessions -> zero-fill known ones
        for ip in set(host_map) | set(nad_counts):
            hostname = host_map.get(ip, ip)
            location = loc_map.get(ip, "Unknown")
            metrics.ise_radius_sessions_by_nad.labels(
                nas_hostname=hostname, location=location).set(nad_counts.get(ip, 0))
        for owner, n in ops_counts.items():
            metrics.ise_radius_sessions_by_ops_owner.labels(ops_owner=owner).set(n)
        for psn, n in psn_counts.items():
            metrics.ise_radius_sessions_by_psn.labels(psn=psn).set(n)
        logger.info("Sessions: %d total across %d PSNs", total, len(psn_counts))
