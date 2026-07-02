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
    low = raw.lower()
    if low == "true":
        return True
    if low == "false":
        return False
    # this is exactly the class of bug that cost real debugging time: COLLECT_PXGRID_STREAM=1
    # or ="true" (literal quotes some EnvironmentFile parsers don't strip) reads as
    # neither true nor false and previously just became False with zero indication why.
    logger.warning('%s=%r is not "true" or "false" — defaulting to %s '
                   "(stray quotes, or a value like 1/yes instead of true?)", v, raw, d)
    return d


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
    device_cache_ttl: int = 10800
    session_detail_cache_ttl: int = 86400
    max_detail_fetches_per_cycle: int = 2000
    collect_device_details: bool = True
    collect_certificates: bool = True
    collect_licensing: bool = True
    collect_backup_status: bool = True
    collect_patches: bool = True
    collect_authz: bool = True
    collect_pxgrid_endpoints: bool = True
    collect_pxgrid_stream: bool = False
    pxgrid_host: str = ""
    pxgrid_port: int = 8910
    pxgrid_node_name: str = ""
    pxgrid_client_cert: str = ""
    pxgrid_client_key: str = ""
    pxgrid_ca_bundle: str = ""
    pxgrid_min_count: int = 1
    pxgrid_query_timeout: int = 120
    profiler_hierarchy_ttl: int = 3600
    project_interval: int = 30
    resync_interval: int = 3600
    watchdog_timeout: int = 90
    reconnect_max_backoff: int = 60

    @property
    def pxgrid_ready(self) -> bool:
        return bool(self.pxgrid_host and self.pxgrid_node_name
                    and self.pxgrid_client_cert and self.pxgrid_client_key)

    def summary(self) -> str:
        """Secret-redacted one-liner of the toggles/paths that most commonly cause
        silent misconfiguration. Log this once at startup — ise_pass is excluded."""
        return (f"collect_pxgrid_stream={self.collect_pxgrid_stream} "
                f"collect_pxgrid_endpoints={self.collect_pxgrid_endpoints} "
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
            device_cache_ttl=_i("DEVICE_CACHE_TTL", 10800),
            session_detail_cache_ttl=_i("SESSION_DETAIL_CACHE_TTL", 86400),
            max_detail_fetches_per_cycle=_i("MAX_DETAIL_FETCHES_PER_CYCLE", 2000),
            collect_device_details=_b("COLLECT_DEVICE_DETAILS", True),
            collect_certificates=_b("COLLECT_CERTIFICATES", True),
            collect_licensing=_b("COLLECT_LICENSING", True),
            collect_backup_status=_b("COLLECT_BACKUP_STATUS", True),
            collect_patches=_b("COLLECT_PATCHES", True),
            collect_authz=_b("COLLECT_AUTHZ", True),
            collect_pxgrid_endpoints=_b("COLLECT_PXGRID_ENDPOINTS", True),
            collect_pxgrid_stream=_b("COLLECT_PXGRID_STREAM", False),
            pxgrid_host=_s("PXGRID_HOST"), pxgrid_port=_i("PXGRID_PORT", 8910),
            pxgrid_node_name=_s("PXGRID_NODE_NAME"),
            pxgrid_client_cert=_s("PXGRID_CLIENT_CERT"),
            pxgrid_client_key=_s("PXGRID_CLIENT_KEY"),
            pxgrid_ca_bundle=_s("PXGRID_CA_BUNDLE"),
            pxgrid_min_count=_i("PXGRID_MIN_COUNT", 1),
            pxgrid_query_timeout=_i("PXGRID_QUERY_TIMEOUT", 120),
            profiler_hierarchy_ttl=_i("PXGRID_PROFILER_HIERARCHY_TTL", 3600),
            project_interval=_i("PXGRID_PROJECT_INTERVAL", 30),
            resync_interval=_i("PXGRID_RESYNC_INTERVAL", 3600),
            watchdog_timeout=_i("PXGRID_WATCHDOG_TIMEOUT", 90),
            reconnect_max_backoff=_i("PXGRID_RECONNECT_MAX_BACKOFF", 60),
        )
