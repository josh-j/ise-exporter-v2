"""Single source of truth for runtime config. Replaces the ~40 scattered
module-level os.getenv() constants with one immutable object loaded once."""
from __future__ import annotations
import os
from dataclasses import dataclass


def _b(v, d): return os.getenv(v, str(d)).lower() == "true"
def _i(v, d): return int(os.getenv(v, str(d)))
def _s(v, d=""): return os.getenv(v, d)


@dataclass(frozen=True)
class Config:
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
    project_interval: int = 30
    resync_interval: int = 3600
    watchdog_timeout: int = 90
    reconnect_max_backoff: int = 60

    @property
    def pxgrid_ready(self) -> bool:
        return bool(self.pxgrid_host and self.pxgrid_node_name
                    and self.pxgrid_client_cert and self.pxgrid_client_key)

    @classmethod
    def from_env(cls) -> "Config":
        return cls(
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
            project_interval=_i("PXGRID_PROJECT_INTERVAL", 30),
            resync_interval=_i("PXGRID_RESYNC_INTERVAL", 3600),
            watchdog_timeout=_i("PXGRID_WATCHDOG_TIMEOUT", 90),
            reconnect_max_backoff=_i("PXGRID_RECONNECT_MAX_BACKOFF", 60),
        )
