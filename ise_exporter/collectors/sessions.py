"""sessions collector (port of collect_session_metrics). MnT Session/ActiveList
fanned out by NAD IP, ops-owner, and PSN. Every known NAD gets a series (zero
included) so a NAD dropping to zero sessions is visible rather than vanishing.

Runs in BOTH modes: in stream mode it self-limits to ise_radius_sessions_by_psn —
the one session gauge the pxGrid topic can't feed (the session directory object
carries no owning-PSN field, only the MnT ActiveList `server` does). The projector
owns active_sessions / by_nad / by_ops_owner then, so this collector must not touch
those, mirroring how authz.py self-limits."""
import logging
from collections import defaultdict

from .. import metrics
from ..util import clear_metric
from . import observe, CollectorFailed, stream_active
from .devices import nad_labels

logger = logging.getLogger(__name__)
_UNSET = object()


def collect(client, cfg, mappings, active_list=_UNSET):
    with observe("sessions"):
        result = active_list
        if result is _UNSET:
            result = client.get_mnt_xml("/Session/ActiveList", api_name="mnt_sessions")
        if result is None:
            raise CollectorFailed("no ActiveList response")
        total = result.get("total", 0)
        sessions = result.get("sessions", [])
        # self-limit to PSN-only only while the stream is actually UP; if it's down we
        # fall back to the full poll so session metrics don't go stale.
        streaming = stream_active(cfg)

        # PSN breakdown — owned by this collector in both modes.
        psn_counts = defaultdict(int)
        for s in sessions:
            psn_counts[s.get("server", "unknown")] += 1
        clear_metric(metrics.ise_radius_sessions_by_psn)
        for psn, n in psn_counts.items():
            metrics.ise_radius_sessions_by_psn.labels(psn=psn).set(n)

        if streaming:
            # projector owns the rest; emit PSN only so we don't fight it.
            logger.info("Sessions (stream mode): %d active across %d PSNs (PSN-only)",
                        total, len(psn_counts))
            return

        metrics.ise_active_sessions.set(total)
        clear_metric(metrics.ise_radius_sessions_by_nad)
        clear_metric(metrics.ise_radius_sessions_by_ops_owner)

        nad_counts = defaultdict(int)
        ops_counts = defaultdict(int)
        host_map = mappings["hostname"]
        ops_map = mappings["ops_owner"]

        for s in sessions:
            nas_ip = s.get("nas_ip_address", "unknown")
            hostname, location, owner = nad_labels(mappings, nas_ip)
            nad_counts[(hostname, location)] += 1
            if owner != "unknown":
                ops_counts[owner] += 1

        # union of known NADs and NADs seen in sessions -> zero-fill known ones
        known_nads = {
            (hostname, nad_labels(mappings, ip)[1])
            for ip, hostname in host_map.items()
        }
        for hostname, location in known_nads | set(nad_counts):
            count = nad_counts.get((hostname, location), 0)
            metrics.ise_radius_sessions_by_nad.labels(
                nas_hostname=hostname, location=location).set(count)
        # zero-fill every known ops owner too (like by_nad above), so an owner dropping to
        # zero sessions reports 0 rather than vanishing from the series.
        known_owners = {o for o in ops_map.values() if o != "unknown"}
        known_owners |= {
            owner for _, _, _, owner in mappings.get("networks", [])
            if owner != "unknown"
        }
        for owner in known_owners | set(ops_counts):
            metrics.ise_radius_sessions_by_ops_owner.labels(
                ops_owner=owner).set(ops_counts.get(owner, 0))
        logger.info("Sessions: %d total across %d PSNs", total, len(psn_counts))
