"""certificates collector (port of collect_certificate_metrics). Per-node system
certificates plus the shared trusted store, emitting days-to-expiry and
30/60/90-day expiring-soon rollups. Fetches the node list itself (the monolith
received it from the deployment collector)."""
import logging
from datetime import datetime, timezone

from .. import metrics
from ..util import clear_metric, parse_ise_date
from . import observe, CollectorFailed
from .nodes import get_nodes

logger = logging.getLogger(__name__)


def collect(client, cfg, mappings):
    with observe("certificates"):
        nodes = get_nodes(client, cfg)   # reuse the deployment collector's recent fetch
        if not nodes:
            raise CollectorFailed("no deployment node list for cert scan")
        clear_metric(metrics.ise_certificate_expiry_days)
        now = datetime.now(timezone.utc)
        counts = {"exp_30": 0, "exp_60": 0, "exp_90": 0, "expired": 0}

        def process(cert, hostname, cert_type):
            expiry = parse_ise_date(cert.get("expirationDate", ""))
            if not expiry:
                return
            if expiry.tzinfo is None:
                expiry = expiry.replace(tzinfo=timezone.utc)
            days = (expiry - now).days
            metrics.ise_certificate_expiry_days.labels(
                hostname=hostname,
                cert_name=cert.get("friendlyName", cert.get("id", "unknown")),
                cert_type=cert_type,
                usage=cert.get("usedBy", cert.get("trustedFor", "unknown"))).set(days)
            # cumulative thresholds: a cert expiring in 10 days counts in 30/60/90,
            # matching the "expiring within N days" reading of the metric
            if days < 0:
                counts["expired"] += 1
            else:
                if days <= 30:
                    counts["exp_30"] += 1
                if days <= 60:
                    counts["exp_60"] += 1
                if days <= 90:
                    counts["exp_90"] += 1

        for node in nodes:
            hostname = node.get("hostname")
            if not hostname:
                continue
            certs = client.get_pan_api(f"/certs/system-certificate/{hostname}", api_name="pan_sys_certs")
            if certs:
                for cert in (certs if isinstance(certs, list) else [certs]):
                    process(cert, hostname, "system")

        trusted = client.get_pan_api("/certs/trusted-certificate", api_name="pan_trusted_certs")
        if trusted:
            for cert in (trusted if isinstance(trusted, list) else [trusted]):
                process(cert, "trust_store", "trusted")

        metrics.ise_certificates_expiring_soon.labels(threshold_days="30").set(counts["exp_30"])
        metrics.ise_certificates_expiring_soon.labels(threshold_days="60").set(counts["exp_60"])
        metrics.ise_certificates_expiring_soon.labels(threshold_days="90").set(counts["exp_90"])
        metrics.ise_certificate_expired.set(counts["expired"])
        logger.info("Certificates: %d expiring <30d, %d expired", counts["exp_30"], counts["expired"])
