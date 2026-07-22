"""certificates collector (port of collect_certificate_metrics). Per-node system
certificates plus the shared trusted store, emitting days-to-expiry and
30/60/90-day expiring-soon rollups. Fetches the node list itself (the monolith
received it from the deployment collector)."""
import logging
from datetime import datetime, timezone

from .. import metrics
from ..compatibility import MAX_CERTIFICATES_PER_STORE, MAX_CERTIFICATE_ROWS
from ..snapshots import replace_metric_snapshot
from ..util import metric_label, parse_ise_date
from . import observe, CollectorFailed
from .nodes import get_nodes

logger = logging.getLogger(__name__)

_METRICS = (
    metrics.ise_certificate_expiry_days,
    metrics.ise_certificates_expiring_soon,
    metrics.ise_certificate_expired,
)


def collect(client, cfg):
    with observe("certificates"):
        nodes = get_nodes(client, cfg)   # reuse the deployment collector's recent fetch
        if not nodes:
            raise CollectorFailed("no deployment node list for cert scan")
        now = datetime.now(timezone.utc)
        counts = {"exp_30": 0, "exp_60": 0, "exp_90": 0, "expired": 0}
        rows = []
        identities = set()

        def process(cert, hostname, cert_type):
            if not isinstance(cert, dict):
                raise CollectorFailed(f"invalid {cert_type} certificate response")
            expiry = parse_ise_date(cert.get("expirationDate", ""))
            if not expiry:
                raise CollectorFailed(f"{cert_type} certificate has invalid expirationDate")
            if expiry.tzinfo is None:
                expiry = expiry.replace(tzinfo=timezone.utc)
            # selfSigned/keySize are no longer published as metrics, but the response
            # is still validated fail-closed: a malformed value here is a sign the
            # whole cert payload is untrustworthy, not just these two fields.
            self_signed = cert.get("selfSigned", False)
            if not isinstance(self_signed, bool):
                raise CollectorFailed(
                    f"{cert_type} certificate has invalid selfSigned value")
            try:
                key_size = int(cert.get("keySize") or 0)
            except (TypeError, ValueError) as error:
                raise CollectorFailed(
                    f"{cert_type} certificate has invalid keySize") from error
            if not 0 <= key_size <= 65_536:
                raise CollectorFailed(
                    f"{cert_type} certificate has invalid keySize")
            raw_name = str(cert.get("friendlyName") or cert.get("id") or "").strip()
            if not raw_name:
                raise CollectorFailed(f"{cert_type} certificate has no identity")
            hostname_label = metric_label(hostname)
            name_label = metric_label(raw_name)
            identity = (hostname_label, name_label, cert_type)
            if identity in identities:
                raise CollectorFailed(
                    f"{cert_type} certificate inventory contained a duplicate identity")
            identities.add(identity)
            days = (expiry - now).days
            rows.append({
                "hostname": hostname_label,
                "name": name_label,
                "type": cert_type,
                "usage": metric_label(
                    cert.get("usedBy", cert.get("trustedFor", "unknown"))),
                "days": days,
            })
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
            certs = client.get_pan_api_all(
                f"/certs/system-certificate/{hostname}",
                params={"size": 100}, max_pages=10,
                max_rows=MAX_CERTIFICATES_PER_STORE, api_name="pan_sys_certs")
            if certs is None:
                raise CollectorFailed(f"system certificate request failed for {hostname}")
            if len(rows) + len(certs) > MAX_CERTIFICATE_ROWS:
                raise CollectorFailed("certificate inventory exceeded the row ceiling")
            for cert in certs:
                process(cert, hostname, "system")

        trusted = client.get_pan_api_all(
            "/certs/trusted-certificate", params={"size": 100}, max_pages=10,
            max_rows=MAX_CERTIFICATES_PER_STORE, api_name="pan_trusted_certs")
        if trusted is None:
            raise CollectorFailed("trusted certificate request failed")
        if len(rows) + len(trusted) > MAX_CERTIFICATE_ROWS:
            raise CollectorFailed("certificate inventory exceeded the row ceiling")
        for cert in trusted:
            process(cert, "trust_store", "trusted")

        def publish():
            for row in rows:
                metrics.ise_certificate_expiry_days.labels(
                    hostname=row["hostname"], cert_name=row["name"], cert_type=row["type"],
                    usage=str(row["usage"] or "unknown")).set(row["days"])
            for threshold in (30, 60, 90):
                metrics.ise_certificates_expiring_soon.labels(
                    threshold_days=str(threshold)).set(counts[f"exp_{threshold}"])
            metrics.ise_certificate_expired.set(counts["expired"])

        replace_metric_snapshot(_METRICS, (publish,))
        logger.info("Certificates: %d expiring <30d, %d expired", counts["exp_30"], counts["expired"])
