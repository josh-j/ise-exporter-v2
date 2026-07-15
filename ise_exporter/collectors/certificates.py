"""certificates collector (port of collect_certificate_metrics). Per-node system
certificates plus the shared trusted store, emitting days-to-expiry and
30/60/90-day expiring-soon rollups. Fetches the node list itself (the monolith
received it from the deployment collector)."""
import logging
from datetime import datetime, timezone

from .. import metrics
from ..snapshots import replace_metric_snapshot
from ..util import metric_label, parse_ise_date
from . import observe, CollectorFailed
from .nodes import get_nodes

logger = logging.getLogger(__name__)
MAX_CERTIFICATES_PER_STORE = 1000
MAX_CERTIFICATE_ROWS = 5000

_METRICS = (
    metrics.ise_certificate_expiry_days,
    metrics.ise_certificates_expiring_soon,
    metrics.ise_certificate_expired,
    metrics.ise_certificate_key_size_bits,
    metrics.ise_certificate_weak_signature,
    metrics.ise_certificate_self_signed,
    metrics.ise_certificate_binding,
    metrics.ise_certificate_issuer_present_in_trust_store,
)

_ROLE_TOKENS = {
    "admin": ("admin",),
    "eap": ("eap",),
    "radius_dtls": ("radius", "dtls"),
    "portal": ("portal",),
    "saml": ("saml",),
    "ise_auth": ("ise auth", "authentication within ise"),
    "client_auth": ("client auth",),
    "cisco_services": ("cisco services",),
}


def _roles(value):
    text = str(value or "").casefold()
    return [role for role, tokens in _ROLE_TOKENS.items()
            if any(token in text for token in tokens)] or ["none"]


def _issuer_matches(issuer, trusted_subjects):
    value = str(issuer or "").strip().casefold()
    return bool(value and any(value == subject or value in subject
                              for subject in trusted_subjects))


def collect(client, cfg):
    with observe("certificates"):
        nodes = get_nodes(client, cfg)   # reuse the deployment collector's recent fetch
        if not nodes:
            raise CollectorFailed("no deployment node list for cert scan")
        now = datetime.now(timezone.utc)
        counts = {"exp_30": 0, "exp_60": 0, "exp_90": 0, "expired": 0}
        rows = []

        def process(cert, hostname, cert_type):
            if not isinstance(cert, dict):
                raise CollectorFailed(f"invalid {cert_type} certificate response")
            expiry = parse_ise_date(cert.get("expirationDate", ""))
            if not expiry:
                raise CollectorFailed(f"{cert_type} certificate has invalid expirationDate")
            if expiry.tzinfo is None:
                expiry = expiry.replace(tzinfo=timezone.utc)
            self_signed = cert.get("selfSigned", False)
            if not isinstance(self_signed, bool):
                raise CollectorFailed(
                    f"{cert_type} certificate has invalid selfSigned value")
            days = (expiry - now).days
            rows.append({
                "hostname": metric_label(hostname),
                "name": metric_label(
                    cert.get("friendlyName", cert.get("id", "unknown"))),
                "type": cert_type,
                "usage": metric_label(
                    cert.get("usedBy", cert.get("trustedFor", "unknown"))),
                "days": days,
                "key_size": int(cert.get("keySize") or 0),
                "signature": str(cert.get("signatureAlgorithm") or "").casefold(),
                "self_signed": self_signed,
                "issuer": cert.get("issuedBy", ""),
                "subject": cert.get("subject", cert.get("issuedTo", "")),
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

        trusted_subjects = {
            str(row["subject"] or "").strip().casefold()
            for row in rows if row["type"] == "trusted" and row["subject"]}

        def publish():
            for row in rows:
                metrics.ise_certificate_expiry_days.labels(
                    hostname=row["hostname"], cert_name=row["name"], cert_type=row["type"],
                    usage=str(row["usage"] or "unknown")).set(row["days"])
                metrics.ise_certificate_key_size_bits.labels(
                    hostname=row["hostname"], cert_name=row["name"],
                    cert_type=row["type"]).set(row["key_size"])
                metrics.ise_certificate_weak_signature.labels(
                    hostname=row["hostname"], cert_name=row["name"],
                    cert_type=row["type"]).set(
                        int("sha1" in row["signature"] or "md5" in row["signature"]))
                for role in _roles(row["usage"]):
                    metrics.ise_certificate_binding.labels(
                        hostname=row["hostname"], cert_name=row["name"],
                        cert_type=row["type"], role=role).set(1)
                if row["type"] == "system":
                    metrics.ise_certificate_self_signed.labels(
                        hostname=row["hostname"], cert_name=row["name"]).set(
                            int(row["self_signed"]))
                    metrics.ise_certificate_issuer_present_in_trust_store.labels(
                        hostname=row["hostname"], cert_name=row["name"]).set(
                            int(_issuer_matches(row["issuer"], trusted_subjects)))
            for threshold in (30, 60, 90):
                metrics.ise_certificates_expiring_soon.labels(
                    threshold_days=str(threshold)).set(counts[f"exp_{threshold}"])
            metrics.ise_certificate_expired.set(counts["expired"])

        replace_metric_snapshot(_METRICS, (publish,))
        logger.info("Certificates: %d expiring <30d, %d expired", counts["exp_30"], counts["expired"])
