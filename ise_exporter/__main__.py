"""Entrypoint for the explicit two-plane collection architecture.

REST/OpenAPI owns appliance and configuration state. Data Connect owns reporting
datasets. MnT exists only in separate operator diagnostics and never participates
in the metric runtime.
"""
import os
import sys
import json
import signal
import argparse
import logging
import threading

import urllib3
from dotenv import load_dotenv
from prometheus_client import start_http_server

from .config import Config
from .clients.rest import ISERestClient
from .clients.dataconnect import DataConnectClient
from .compatibility import ISECompatibilityError, validate_ise_compatibility
from .scheduler import PollScheduler

logging.basicConfig(level=logging.INFO, format="%(asctime)s - %(name)s - %(levelname)s - %(message)s")
logger = logging.getLogger("ise_exporter")
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

# systemd installs config here (deploy/install.sh); load it too so a manual
# manual diagnostics from any cwd pick up the same env the service uses.
# Override with ISE_EXPORTER_ENV_FILE. load_dotenv never overrides an already-set var,
# so the running service's systemd EnvironmentFile still wins.
DEPLOY_ENV_FILE = os.environ.get("ISE_EXPORTER_ENV_FILE", "/etc/ise-exporter/ise-exporter.env")


def dataconnect_check(cfg):
    if not cfg.dataconnect_ready:
        logger.error("Data Connect check requires ISE_DATACONNECT_HOST, "
                     "ISE_DATACONNECT_USER, and ISE_DATACONNECT_PASSWORD")
        return 1
    client = DataConnectClient(cfg)
    try:
        rows = client.query("SELECT COUNT(*) AS view_count FROM user_views")
        count = int(rows[0]["view_count"]) if rows else 0
        logger.info("Data Connect check passed: %d readable views", count)
        return 0
    except Exception as exc:
        logger.error("Data Connect check failed: %s", exc)
        return 1
    finally:
        client.close()


def dataconnect_schema(cfg):
    """Print metadata for reporting views without reading event rows."""
    if not cfg.dataconnect_ready:
        logger.error("Data Connect schema requires ISE_DATACONNECT_HOST, "
                     "ISE_DATACONNECT_USER, and ISE_DATACONNECT_PASSWORD")
        return 1
    client = DataConnectClient(cfg)
    try:
        rows = client.query("""
            SELECT table_name, column_id, column_name, data_type, data_length, nullable
            FROM user_tab_columns
            WHERE table_name IN (
                'RADIUS_AUTHENTICATIONS', 'RADIUS_ACCOUNTING', 'RADIUS_ERRORS_VIEW',
                'POSTURE_ASSESSMENT_BY_ENDPOINT', 'POSTURE_ASSESSMENT_BY_CONDITION',
                'ENDPOINTS_DATA', 'PROFILED_ENDPOINTS_SUMMARY',
                'KEY_PERFORMANCE_METRICS', 'SYSTEM_SUMMARY', 'AAA_DIAGNOSTICS_VIEW',
                'SYSTEM_DIAGNOSTICS_VIEW', 'TACACS_AUTHENTICATION_LAST_TWO_DAYS',
                'TACACS_AUTHORIZATION_LAST_TWO_DAYS',
                'TACACS_ACCOUNTING_LAST_TWO_DAYS')
            ORDER BY table_name, column_id
        """)
        print(json.dumps(rows, indent=2, default=str))
        return 0
    except Exception as exc:
        logger.error("Data Connect schema failed: %s", exc)
        return 1
    finally:
        client.close()


def _load_env():
    """Load ./.env (dev convenience) then the systemd deployment env file if present,
    so diagnostics work from any directory on a deployed host.

    Values are configuration data, not shell templates.  Disabling interpolation
    preserves the entire value after the first ``=`` literally, including additional
    equals signs and password/token text such as ``${NAME}``.
    """
    load_dotenv(interpolate=False)
    if os.path.isfile(DEPLOY_ENV_FILE):
        load_dotenv(DEPLOY_ENV_FILE, interpolate=False)
        logger.info("loaded config from %s", DEPLOY_ENV_FILE)


def main(argv=None):
    parser = argparse.ArgumentParser()
    parser.add_argument("--dataconnect-check", action="store_true",
                        help="validate Data Connect credentials, TLS, and view access")
    parser.add_argument("--dataconnect-schema", action="store_true",
                        help="print reporting-view column metadata as JSON")
    args = parser.parse_args(argv)

    _load_env()
    cfg = Config.from_env()
    logging.getLogger().setLevel(cfg.log_level)
    logger.info("config: %s", cfg.summary())

    if args.dataconnect_check:
        return dataconnect_check(cfg)
    if args.dataconnect_schema:
        return dataconnect_schema(cfg)

    if not cfg.ise_host:
        logger.error("ISE_HOST not configured")
        return 1
    if not cfg.dataconnect_ready:
        logger.error("Data Connect credentials are required for reporting collection")
        return 1

    client = ISERestClient(cfg)
    try:
        compatibility = validate_ise_compatibility(client)
    except ISECompatibilityError as exc:
        logger.error("%s", exc)
        return 1
    logger.info("validated Cisco ISE %s Patch %d on %s",
                compatibility.ise_version, compatibility.patch_level,
                ", ".join(compatibility.deployment_nodes))

    shutdown = threading.Event()
    signal.signal(signal.SIGTERM, lambda *_: shutdown.set())
    signal.signal(signal.SIGINT, lambda *_: shutdown.set())

    start_http_server(cfg.exporter_port)
    logger.info("metrics on :%d (REST/OpenAPI config + Data Connect reporting)",
                cfg.exporter_port)

    dataconnect = DataConnectClient(cfg)
    scheduler = PollScheduler(cfg, client, dataconnect=dataconnect)

    scheduler.loop(shutdown)   # blocks until SIGTERM/SIGINT
    if dataconnect is not None:
        dataconnect.close()
    logger.info("shutdown complete")
    return 0


if __name__ == "__main__":
    sys.exit(main())
