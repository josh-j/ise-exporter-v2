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
    # accept the common boolean spellings AND strip stray quotes — the class of bug that
    # cost real debugging time was COLLECT_PXGRID_STREAM=1 or ="true" (literal quotes some
    # EnvironmentFile parsers don't strip) reading as neither and silently becoming the
    # default with no indication why. A genuinely-unparseable value still warns.
    low = raw.strip().strip("\"'").lower()
    if low in ("true", "1", "yes", "on"):
        return True
    if low in ("false", "0", "no", "off"):
        return False
    logger.warning("%s=%r is not a recognized boolean — defaulting to %s "
                   "(use true/false, 1/0, yes/no, or on/off)", v, raw, d)
    return d


def _csv(v, d=()):
    raw = _s(v, None)
    if raw is None:
        return tuple(d)
    return tuple(part.strip() for part in raw.split(",") if part.strip())


@dataclass(frozen=True)
class Config:
    log_level: str = "INFO"
    ise_host: str = ""
    ise_mnt_host: str = ""
    ise_user: str = "ers.readonly"
    ise_pass: str = ""
    ers_port: int = 9060
    exporter_port: int = 9618
    scrape_interval: int = 120
    fast_interval: int = 60
    medium_interval: int = 300
    slow_interval: int = 3600
    max_workers: int = 10
    auth_failure_backoff: int = 900
    auth_failure_threshold: int = 3
    device_cache_ttl: int = 10800
    session_detail_cache_ttl: int = 86400
    session_detail_cache_file: str = "/tmp/ise-exporter-session-details-cache.json"
    max_detail_fetches_per_cycle: int = 2000
    recent_auth_status_max: int = 25
    collect_device_details: bool = True
    collect_certificates: bool = True
    collect_licensing: bool = True
    collect_backup_status: bool = True
    collect_patches: bool = True
    collect_authz: bool = True
    collect_tacacs: bool = True
    tacacs_internal_user_max: int = 1000
    tacacs_unused_account_days: int = 180
    collect_tacacs_dataconnect: bool = False
    dataconnect_host: str = ""
    dataconnect_port: int = 2484
    dataconnect_service: str = "cpm10"
    dataconnect_user: str = "dataconnect"
    dataconnect_password: str = ""
    dataconnect_ca_bundle: str = ""
    dataconnect_ssl_verify: bool = True
    dataconnect_query_timeout: int = 30
    dataconnect_max_groups: int = 5000
    collect_pxgrid_endpoints: bool = True
    collect_pxgrid_stream: bool = False
    # Legacy ERS endpoint profiling-policy breakdown, used only when the richer
    # per-endpoint ERS attribute sweep below is disabled. ISE 3.3 normally uses
    # the richer sweep as its endpoint inventory baseline.
    collect_ers_endpoint_fallback: bool = True
    ers_endpoint_profile_max: int = 1500   # covers ISE's ~900 built-in profiles + custom
    # Slow, cached ERS endpoint profile-attribute sweep. This reads
    # /ers/config/endpoint/{id}, which exposes endpoint configuration, MFC fields,
    # and custom attributes but is per-endpoint and expensive at scale.
    collect_ers_endpoint_attributes: bool = True
    ers_endpoint_attribute_page_size: int = 500
    ers_endpoint_attribute_cache_ttl: int = 604800
    ers_endpoint_attribute_cache_file: str = "/tmp/ise-exporter-endpoint-attributes-cache.json"
    ers_endpoint_attribute_value_max_len: int = 80
    ers_endpoint_custom_attribute_keys: tuple[str, ...] = ()
    pxgrid_host: str = ""
    pxgrid_port: int = 8910
    pxgrid_node_name: str = ""
    pxgrid_client_cert: str = ""
    pxgrid_client_key: str = ""
    pxgrid_ca_bundle: str = ""
    pxgrid_min_count: int = 1
    pxgrid_query_timeout: int = 120
    pxgrid_endpoint_zero_backoff: int = 3600
    # Prefer the base session topic (/topic/com.cisco.ise.session) by default — it's
    # available on every ISE and authorized for any client granted the session service.
    # sessionTopicAll (/…​.session.all) only exists on 3.3p2/3.4+ and needs the client's
    # pxGrid group to be authorized for it; opt in with PXGRID_SESSION_TOPIC_ALL=true.
    pxgrid_session_topic_all: bool = False
    # pxGrid endpoint enrichment comes from the getEndpoints REST poll, NOT the
    # pxGrid endpoint topic, by default. On ISE 3.3 this REST poll commonly returns
    # zero forever, so ERS remains the baseline and getEndpoints is retried on a
    # slower zero-result backoff. Opt into the live topic with
    # PXGRID_SUBSCRIBE_ENDPOINT_TOPIC=true when the pxGrid group/policy supports it.
    pxgrid_subscribe_endpoint_topic: bool = False
    pxgrid_endpoint_refresh_interval: int = 900
    profiler_hierarchy_ttl: int = 3600
    project_interval: int = 30
    resync_interval: int = 3600
    watchdog_timeout: int = 90
    reconnect_max_backoff: int = 60

    @property
    def pxgrid_ready(self) -> bool:
        return bool(self.pxgrid_host and self.pxgrid_node_name
                    and self.pxgrid_client_cert and self.pxgrid_client_key)

    @property
    def dataconnect_ready(self) -> bool:
        return bool(self.collect_tacacs_dataconnect and self.dataconnect_host
                    and self.dataconnect_user and self.dataconnect_password)

    def summary(self) -> str:
        """Secret-redacted one-liner of the toggles/paths that most commonly cause
        silent misconfiguration. Log this once at startup — ise_pass is excluded."""
        return (f"collect_pxgrid_stream={self.collect_pxgrid_stream} "
                f"collect_pxgrid_endpoints={self.collect_pxgrid_endpoints} "
                f"collect_ers_endpoint_attributes={self.collect_ers_endpoint_attributes} "
                f"collect_tacacs={self.collect_tacacs} "
                f"collect_tacacs_dataconnect={self.collect_tacacs_dataconnect} "
                f"dataconnect_ready={self.dataconnect_ready} "
                f"pxgrid_ready={self.pxgrid_ready} pxgrid_host={self.pxgrid_host!r} "
                f"pxgrid_node_name={self.pxgrid_node_name!r} "
                f"pxgrid_client_cert={self.pxgrid_client_cert!r} "
                f"pxgrid_client_key={self.pxgrid_client_key!r} "
                f"pxgrid_ca_bundle={self.pxgrid_ca_bundle!r} "
                f"ise_host={self.ise_host!r} ise_mnt_host={self.ise_mnt_host!r} "
                f"ise_user={self.ise_user!r}")

    @classmethod
    def from_env(cls) -> "Config":
        return cls(
            log_level=_s("LOG_LEVEL", "INFO").upper(),
            ise_host=_s("ISE_HOST"), ise_mnt_host=_s("ISE_MNT_HOST"),
            ise_user=_s("ISE_USER", "ers.readonly"), ise_pass=_s("ISE_PASS"),
            ers_port=_i("ERS_PORT", 9060), exporter_port=_i("EXPORTER_PORT", 9618),
            scrape_interval=_i("SCRAPE_INTERVAL", 120), fast_interval=_i("FAST_INTERVAL", 60),
            medium_interval=_i("MEDIUM_INTERVAL", 300), slow_interval=_i("SLOW_INTERVAL", 3600),
            max_workers=_i("MAX_WORKERS", 10),
            auth_failure_backoff=_i("AUTH_FAILURE_BACKOFF", 900),
            auth_failure_threshold=_i("AUTH_FAILURE_THRESHOLD", 3),
            device_cache_ttl=_i("DEVICE_CACHE_TTL", 10800),
            session_detail_cache_ttl=_i("SESSION_DETAIL_CACHE_TTL", 86400),
            session_detail_cache_file=_s(
                "SESSION_DETAIL_CACHE_FILE",
                "/tmp/ise-exporter-session-details-cache.json"),
            max_detail_fetches_per_cycle=_i("MAX_DETAIL_FETCHES_PER_CYCLE", 2000),
            recent_auth_status_max=_i("RECENT_AUTH_STATUS_MAX", 25),
            collect_device_details=_b("COLLECT_DEVICE_DETAILS", True),
            collect_certificates=_b("COLLECT_CERTIFICATES", True),
            collect_licensing=_b("COLLECT_LICENSING", True),
            collect_backup_status=_b("COLLECT_BACKUP_STATUS", True),
            collect_patches=_b("COLLECT_PATCHES", True),
            collect_authz=_b("COLLECT_AUTHZ", True),
            collect_tacacs=_b("COLLECT_TACACS", True),
            tacacs_internal_user_max=_i("TACACS_INTERNAL_USER_MAX", 1000),
            tacacs_unused_account_days=_i("TACACS_UNUSED_ACCOUNT_DAYS", 180),
            collect_tacacs_dataconnect=_b("COLLECT_TACACS_DATACONNECT", False),
            dataconnect_host=_s("ISE_DATACONNECT_HOST", _s("ISE_MNT_HOST")),
            dataconnect_port=_i("ISE_DATACONNECT_PORT", 2484),
            dataconnect_service=_s("ISE_DATACONNECT_SERVICE", "cpm10"),
            dataconnect_user=_s("ISE_DATACONNECT_USER", "dataconnect"),
            dataconnect_password=_s("ISE_DATACONNECT_PASSWORD"),
            dataconnect_ca_bundle=_s("ISE_DATACONNECT_CA_BUNDLE"),
            dataconnect_ssl_verify=_b("ISE_DATACONNECT_SSL_VERIFY", True),
            dataconnect_query_timeout=_i("ISE_DATACONNECT_QUERY_TIMEOUT", 30),
            dataconnect_max_groups=_i("ISE_DATACONNECT_MAX_GROUPS", 5000),
            collect_pxgrid_endpoints=_b("COLLECT_PXGRID_ENDPOINTS", True),
            collect_pxgrid_stream=_b("COLLECT_PXGRID_STREAM", False),
            collect_ers_endpoint_fallback=_b("COLLECT_ERS_ENDPOINT_FALLBACK", True),
            ers_endpoint_profile_max=_i("ERS_ENDPOINT_PROFILE_MAX", 1500),
            collect_ers_endpoint_attributes=_b("COLLECT_ERS_ENDPOINT_ATTRIBUTES", True),
            ers_endpoint_attribute_page_size=_i("ERS_ENDPOINT_ATTRIBUTE_PAGE_SIZE", 500),
            ers_endpoint_attribute_cache_ttl=_i("ERS_ENDPOINT_ATTRIBUTE_CACHE_TTL", 604800),
            ers_endpoint_attribute_cache_file=_s(
                "ERS_ENDPOINT_ATTRIBUTE_CACHE_FILE",
                "/tmp/ise-exporter-endpoint-attributes-cache.json"),
            ers_endpoint_attribute_value_max_len=_i("ERS_ENDPOINT_ATTRIBUTE_VALUE_MAX_LEN", 80),
            ers_endpoint_custom_attribute_keys=_csv("ERS_ENDPOINT_CUSTOM_ATTRIBUTE_KEYS"),
            pxgrid_host=_s("PXGRID_HOST"), pxgrid_port=_i("PXGRID_PORT", 8910),
            pxgrid_node_name=_s("PXGRID_NODE_NAME"),
            pxgrid_client_cert=_s("PXGRID_CLIENT_CERT"),
            pxgrid_client_key=_s("PXGRID_CLIENT_KEY"),
            pxgrid_ca_bundle=_s("PXGRID_CA_BUNDLE"),
            pxgrid_min_count=_i("PXGRID_MIN_COUNT", 1),
            pxgrid_query_timeout=_i("PXGRID_QUERY_TIMEOUT", 120),
            pxgrid_endpoint_zero_backoff=_i("PXGRID_ENDPOINT_ZERO_BACKOFF", 3600),
            pxgrid_session_topic_all=_b("PXGRID_SESSION_TOPIC_ALL", False),
            pxgrid_subscribe_endpoint_topic=_b("PXGRID_SUBSCRIBE_ENDPOINT_TOPIC", False),
            pxgrid_endpoint_refresh_interval=_i("PXGRID_ENDPOINT_REFRESH_INTERVAL", 900),
            profiler_hierarchy_ttl=_i("PXGRID_PROFILER_HIERARCHY_TTL", 3600),
            project_interval=_i("PXGRID_PROJECT_INTERVAL", 30),
            resync_interval=_i("PXGRID_RESYNC_INTERVAL", 3600),
            watchdog_timeout=_i("PXGRID_WATCHDOG_TIMEOUT", 90),
            reconnect_max_backoff=_i("PXGRID_RECONNECT_MAX_BACKOFF", 60),
        )
