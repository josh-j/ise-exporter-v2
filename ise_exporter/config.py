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


def _f(v, d):
    raw = _s(v, None)
    if not raw:
        return d
    try:
        return float(raw)
    except ValueError:
        logger.warning("%s=%r is not a valid number — defaulting to %s", v, raw, d)
        return d


def _bounded_i(v, d, minimum=None, maximum=None):
    value = _i(v, d)
    bounded = value
    if minimum is not None:
        bounded = max(minimum, bounded)
    if maximum is not None:
        bounded = min(maximum, bounded)
    if bounded != value:
        logger.warning("%s=%s is outside the production-safe range — using %s",
                       v, value, bounded)
    return bounded


def _bounded_f(v, d, minimum=None, maximum=None):
    value = _f(v, d)
    bounded = value
    if minimum is not None:
        bounded = max(minimum, bounded)
    if maximum is not None:
        bounded = min(maximum, bounded)
    if bounded != value:
        logger.warning("%s=%s is outside the production-safe range — using %s",
                       v, value, bounded)
    return bounded


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
    state_db_path: str = "/var/lib/ise-exporter/state.sqlite3"
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
    collect_mnt_active_posture: bool = True
    mnt_active_posture_interval: int = 900
    mnt_active_posture_max_active_list_sessions: int = 10000
    mnt_active_posture_max_sessions: int = 1000
    mnt_active_posture_workers: int = 2
    mnt_active_posture_max_requests_per_cycle: int = 250
    mnt_active_posture_refresh_ttl: int = 3600
    mnt_active_posture_request_interval_ms: int = 500
    tacacs_internal_user_max: int = 1000
    tacacs_internal_user_detail_max_requests: int = 100
    tacacs_internal_user_detail_ttl: int = 604800
    tacacs_internal_user_detail_request_interval_ms: int = 250
    tacacs_unused_account_days: int = 180
    dataconnect_host: str = ""
    dataconnect_port: int = 2484
    dataconnect_service: str = "cpm10"
    dataconnect_user: str = "dataconnect"
    dataconnect_password: str = ""
    dataconnect_ca_bundle: str = ""
    dataconnect_ssl_verify: bool = True
    # Production-safe guardrails for deployments up to 100k endpoints. Data
    # Connect can route work across ISE personas, so these limits protect the
    # deployment rather than assuming the secondary MnT absorbs every query.
    dataconnect_query_timeout: int = 15
    dataconnect_max_groups: int = 1000
    dataconnect_min_query_interval_ms: int = 2000
    dataconnect_max_duty_cycle_percent: float = 0.5
    dataconnect_event_window_hours: int = 24
    dataconnect_radius_interval: int = 86400
    dataconnect_radius_active_interval: int = 1800
    dataconnect_performance_interval: int = 3600
    dataconnect_posture_interval: int = 21600
    dataconnect_endpoints_interval: int = 86400
    dataconnect_freshness_interval: int = 43200
    dataconnect_nad_health_interval: int = 21600
    dataconnect_tacacs_interval: int = 21600
    dataconnect_shared_pacing_file: str = "/var/lib/ise-exporter/dataconnect.pacing"
    cli_production_safe: bool = True
    cli_allow_expensive: bool = False
    cli_max_rows: int = 1000
    @property
    def dataconnect_ready(self) -> bool:
        return bool(self.dataconnect_host and self.dataconnect_user
                    and self.dataconnect_password)

    def summary(self) -> str:
        """Secret-redacted one-liner of the toggles/paths that most commonly cause
        silent misconfiguration. Log this once at startup — ise_pass is excluded."""
        return (f"collect_tacacs={self.collect_tacacs} "
                f"collect_mnt_active_posture={self.collect_mnt_active_posture} "
                f"mnt_active_list_ceiling="
                f"{self.mnt_active_posture_max_active_list_sessions} "
                f"dataconnect_ready={self.dataconnect_ready} "
                f"dataconnect_event_window_ceiling_hours="
                f"{self.dataconnect_event_window_hours} "
                f"ise_host={self.ise_host!r} ise_mnt_host={self.ise_mnt_host!r} "
                f"ise_user={self.ise_user!r}")

    @classmethod
    def from_env(cls) -> "Config":
        return cls(
            log_level=_s("LOG_LEVEL", "INFO").upper(),
            ise_host=_s("ISE_HOST"), ise_mnt_host=_s("ISE_MNT_HOST"),
            ise_user=_s("ISE_USER", "ers.readonly"), ise_pass=_s("ISE_PASS"),
            ers_port=_i("ERS_PORT", 9060), exporter_port=_i("EXPORTER_PORT", 9618),
            state_db_path=_s("ISE_EXPORTER_STATE_DB", "/var/lib/ise-exporter/state.sqlite3"),
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
            collect_mnt_active_posture=_b("COLLECT_MNT_ACTIVE_POSTURE", True),
            mnt_active_posture_interval=_bounded_i(
                "MNT_ACTIVE_POSTURE_INTERVAL", 900, 900),
            mnt_active_posture_max_active_list_sessions=_bounded_i(
                "MNT_ACTIVE_POSTURE_MAX_ACTIVE_LIST_SESSIONS", 10000, 1, 250000),
            mnt_active_posture_max_sessions=_bounded_i(
                "MNT_ACTIVE_POSTURE_MAX_SESSIONS", 1000, 1, 1000),
            mnt_active_posture_workers=_bounded_i(
                "MNT_ACTIVE_POSTURE_WORKERS", 2, 1, 4),
            mnt_active_posture_max_requests_per_cycle=_bounded_i(
                "MNT_ACTIVE_POSTURE_MAX_REQUESTS_PER_CYCLE", 250, 1, 250),
            mnt_active_posture_refresh_ttl=_bounded_i(
                "MNT_ACTIVE_POSTURE_REFRESH_TTL", 3600, 900),
            mnt_active_posture_request_interval_ms=_bounded_i(
                "MNT_ACTIVE_POSTURE_REQUEST_INTERVAL_MS", 500, 250),
            tacacs_internal_user_max=_bounded_i(
                "TACACS_INTERNAL_USER_MAX", 1000, 1, 1000),
            tacacs_internal_user_detail_max_requests=_bounded_i(
                "TACACS_INTERNAL_USER_DETAIL_MAX_REQUESTS", 100, 1, 250),
            tacacs_internal_user_detail_ttl=_bounded_i(
                "TACACS_INTERNAL_USER_DETAIL_TTL", 604800, 86400),
            tacacs_internal_user_detail_request_interval_ms=_bounded_i(
                "TACACS_INTERNAL_USER_DETAIL_REQUEST_INTERVAL_MS", 250, 100),
            tacacs_unused_account_days=_i("TACACS_UNUSED_ACCOUNT_DAYS", 180),
            dataconnect_host=_s("ISE_DATACONNECT_HOST", _s("ISE_MNT_HOST")),
            dataconnect_port=_i("ISE_DATACONNECT_PORT", 2484),
            dataconnect_service=_s("ISE_DATACONNECT_SERVICE", "cpm10"),
            dataconnect_user=_s("ISE_DATACONNECT_USER", "dataconnect"),
            dataconnect_password=_s("ISE_DATACONNECT_PASSWORD"),
            dataconnect_ca_bundle=_s("ISE_DATACONNECT_CA_BUNDLE"),
            dataconnect_ssl_verify=_b("ISE_DATACONNECT_SSL_VERIFY", True),
            dataconnect_query_timeout=_bounded_i(
                "ISE_DATACONNECT_QUERY_TIMEOUT", 15, 5, 15),
            dataconnect_max_groups=_bounded_i(
                "ISE_DATACONNECT_MAX_GROUPS", 1000, 1, 2000),
            dataconnect_min_query_interval_ms=_bounded_i(
                "ISE_DATACONNECT_MIN_QUERY_INTERVAL_MS", 2000, 500),
            dataconnect_max_duty_cycle_percent=_bounded_f(
                "ISE_DATACONNECT_MAX_DUTY_CYCLE_PERCENT", 0.5, 0.1, 2.0),
            dataconnect_event_window_hours=_bounded_i(
                "ISE_DATACONNECT_EVENT_WINDOW_HOURS", 24, 1, 24),
            dataconnect_radius_interval=_bounded_i(
                "ISE_DATACONNECT_RADIUS_INTERVAL", 86400, 21600),
            dataconnect_radius_active_interval=_bounded_i(
                "ISE_DATACONNECT_RADIUS_ACTIVE_INTERVAL", 1800, 900),
            dataconnect_performance_interval=_bounded_i(
                "ISE_DATACONNECT_PERFORMANCE_INTERVAL", 3600, 900),
            dataconnect_posture_interval=_bounded_i(
                "ISE_DATACONNECT_POSTURE_INTERVAL", 21600, 1800),
            dataconnect_endpoints_interval=_bounded_i(
                "ISE_DATACONNECT_ENDPOINTS_INTERVAL", 86400, 21600),
            dataconnect_freshness_interval=_bounded_i(
                "ISE_DATACONNECT_FRESHNESS_INTERVAL", 43200, 3600),
            dataconnect_nad_health_interval=_bounded_i(
                "ISE_DATACONNECT_NAD_HEALTH_INTERVAL", 21600, 1800),
            dataconnect_tacacs_interval=_bounded_i(
                "ISE_DATACONNECT_TACACS_INTERVAL", 21600, 1800),
            dataconnect_shared_pacing_file=_s(
                "ISE_DATACONNECT_SHARED_PACING_FILE",
                "/var/lib/ise-exporter/dataconnect.pacing"),
            cli_production_safe=_b("ISE_CLI_PRODUCTION_SAFE", True),
            cli_allow_expensive=_b("ISE_CLI_ALLOW_EXPENSIVE", False),
            cli_max_rows=_bounded_i("ISE_CLI_MAX_ROWS", 1000, 100, 5000),
        )
