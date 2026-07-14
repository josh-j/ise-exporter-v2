"""Single source of truth for runtime config. Replaces the ~40 scattered
module-level os.getenv() constants with one immutable object loaded once."""
from __future__ import annotations
import logging
import os
from dataclasses import dataclass

logger = logging.getLogger(__name__)


def _s(v, d=""):
    # strip() guards against a trailing \r (CRLF env files) or stray whitespace —
    # both parse "successfully" into a wrong value with no error anywhere.
    raw = os.getenv(v)
    return raw.strip() if raw is not None else d


def _i(v, d):
    raw = _s(v, None)
    if not raw:
        return d
    try:
        return int(raw)
    except ValueError:
        logger.warning("%s=%r is not a valid integer — defaulting to %s", v, raw, d)
        return d


def _b(v, d):
    raw = _s(v, None)
    if raw is None:
        return d
    # Accept common boolean spellings and strip quotes left by some
    # EnvironmentFile parsers. A genuinely unparseable value still warns.
    low = raw.strip().strip("\"'").lower()
    if low in ("true", "1", "yes", "on"):
        return True
    if low in ("false", "0", "no", "off"):
        return False
    logger.warning("%s=%r is not a recognized boolean — defaulting to %s "
                   "(use true/false, 1/0, yes/no, or on/off)", v, raw, d)
    return d


@dataclass(frozen=True)
class Config:
    log_level: str = "INFO"
    ise_host: str = ""
    ise_mnt_host: str = ""
    ise_user: str = "ers.readonly"
    ise_pass: str = ""
    ers_port: int = 9060
    rest_ca_bundle: str = ""
    rest_ssl_verify: bool = True
    mnt_ca_bundle: str = ""
    mnt_ssl_verify: bool = True
    exporter_port: int = 9618
    scrape_interval: int = 120
    fast_interval: int = 60
    medium_interval: int = 300
    slow_interval: int = 3600
    max_workers: int = 10
    auth_failure_backoff: int = 900
    auth_failure_threshold: int = 3
    device_cache_ttl: int = 10800
    collect_device_details: bool = True
    collect_certificates: bool = True
    collect_licensing: bool = True
    collect_backup_status: bool = True
    collect_patches: bool = True
    collect_tacacs: bool = True
    tacacs_internal_user_max: int = 1000
    tacacs_unused_account_days: int = 180
    dataconnect_host: str = ""
    dataconnect_port: int = 2484
    dataconnect_service: str = "cpm10"
    dataconnect_user: str = "dataconnect"
    dataconnect_password: str = ""
    dataconnect_ca_bundle: str = ""
    dataconnect_ssl_verify: bool = True
    dataconnect_query_timeout: int = 30
    dataconnect_max_groups: int = 5000
    @property
    def dataconnect_ready(self) -> bool:
        return bool(self.dataconnect_host and self.dataconnect_user
                    and self.dataconnect_password)

    def summary(self) -> str:
        """Secret-redacted one-liner of the toggles/paths that most commonly cause
        silent misconfiguration. Log this once at startup — ise_pass is excluded."""
        return (f"collect_tacacs={self.collect_tacacs} "
                f"dataconnect_ready={self.dataconnect_ready} "
                f"ise_host={self.ise_host!r} ise_mnt_host={self.ise_mnt_host!r} "
                f"ise_user={self.ise_user!r}")

    @classmethod
    def from_env(cls) -> "Config":
        return cls(
            log_level=_s("LOG_LEVEL", "INFO").upper(),
            ise_host=_s("ISE_HOST"), ise_mnt_host=_s("ISE_MNT_HOST"),
            ise_user=_s("ISE_USER", "ers.readonly"), ise_pass=_s("ISE_PASS"),
            ers_port=_i("ERS_PORT", 9060), exporter_port=_i("EXPORTER_PORT", 9618),
            rest_ca_bundle=_s("ISE_REST_CA_BUNDLE"),
            rest_ssl_verify=_b("ISE_REST_SSL_VERIFY", True),
            mnt_ca_bundle=_s("ISE_MNT_CA_BUNDLE", _s("ISE_REST_CA_BUNDLE")),
            mnt_ssl_verify=_b(
                "ISE_MNT_SSL_VERIFY", _b("ISE_REST_SSL_VERIFY", True)),
            scrape_interval=_i("SCRAPE_INTERVAL", 120), fast_interval=_i("FAST_INTERVAL", 60),
            medium_interval=_i("MEDIUM_INTERVAL", 300), slow_interval=_i("SLOW_INTERVAL", 3600),
            max_workers=_i("MAX_WORKERS", 10),
            auth_failure_backoff=_i("AUTH_FAILURE_BACKOFF", 900),
            auth_failure_threshold=_i("AUTH_FAILURE_THRESHOLD", 3),
            device_cache_ttl=_i("DEVICE_CACHE_TTL", 10800),
            collect_device_details=_b("COLLECT_DEVICE_DETAILS", True),
            collect_certificates=_b("COLLECT_CERTIFICATES", True),
            collect_licensing=_b("COLLECT_LICENSING", True),
            collect_backup_status=_b("COLLECT_BACKUP_STATUS", True),
            collect_patches=_b("COLLECT_PATCHES", True),
            collect_tacacs=_b("COLLECT_TACACS", True),
            tacacs_internal_user_max=_i("TACACS_INTERNAL_USER_MAX", 1000),
            tacacs_unused_account_days=_i("TACACS_UNUSED_ACCOUNT_DAYS", 180),
            dataconnect_host=_s("ISE_DATACONNECT_HOST", _s("ISE_MNT_HOST")),
            dataconnect_port=_i("ISE_DATACONNECT_PORT", 2484),
            dataconnect_service=_s("ISE_DATACONNECT_SERVICE", "cpm10"),
            dataconnect_user=_s("ISE_DATACONNECT_USER", "dataconnect"),
            dataconnect_password=_s("ISE_DATACONNECT_PASSWORD"),
            dataconnect_ca_bundle=_s("ISE_DATACONNECT_CA_BUNDLE"),
            dataconnect_ssl_verify=_b("ISE_DATACONNECT_SSL_VERIFY", True),
            dataconnect_query_timeout=_i("ISE_DATACONNECT_QUERY_TIMEOUT", 30),
            dataconnect_max_groups=_i("ISE_DATACONNECT_MAX_GROUPS", 5000),
        )
