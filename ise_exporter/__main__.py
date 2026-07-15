"""Entrypoint for the explicit collection-plane architecture.

REST/OpenAPI owns appliance and configuration state. Data Connect owns reporting
datasets. MnT owns only a bounded current active-session posture snapshot.
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

from . import __version__, build_revision, SUPPORTED_ISE_RELEASE, version_string
from . import metrics
from .config import Config
from .clients.rest import ISEControlPlaneClient, MnTActiveSessionClient, RestAuthGuard
from .clients.dataconnect import DataConnectClient
from .compatibility import (
    ISECompatibilityError,
    valid_hostname,
    validate_ise_compatibility,
)
from .dataconnect_schema import (
    metadata_rows,
    validate_dataconnect_schema,
)
from .scheduler import PollScheduler
from .snapshots import LockedCollectorRegistry
from .state import (
    acquire_runtime_lock,
    release_runtime_lock,
    reset_exporter_state,
)

logging.basicConfig(level=logging.INFO, format="%(asctime)s - %(name)s - %(levelname)s - %(message)s")
logger = logging.getLogger("ise_exporter")
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

# systemd installs config here (deploy/install.sh); load it too so a manual
# manual diagnostics from any cwd pick up the same env the service uses.
# Override with ISE_EXPORTER_ENV_FILE. load_dotenv never overrides an already-set var,
# so the running service's systemd EnvironmentFile still wins.
DEPLOY_ENV_FILE = os.environ.get("ISE_EXPORTER_ENV_FILE", "/etc/ise-exporter/ise-exporter.env")


def _close_quietly(resource, name):
    if resource is None:
        return
    try:
        resource.close()
    except Exception as error:
        logger.warning("could not close %s: %s", name, error)


def _stop_metrics_server(started):
    """Release the Prometheus listener returned by supported client versions."""
    if not isinstance(started, tuple) or not started:
        return
    server = started[0]
    thread = started[1] if len(started) > 1 else None
    try:
        server.shutdown()
    except Exception as error:
        logger.warning("could not stop metrics listener: %s", error)
    try:
        server.server_close()
    except Exception as error:
        logger.warning("could not close metrics listener: %s", error)
    if thread is not None:
        thread.join(timeout=2)
        if thread.is_alive():
            logger.warning("metrics listener thread did not stop within 2s")


def dataconnect_check(cfg):
    if not cfg.dataconnect_ready:
        logger.error("Data Connect check requires ISE_DATACONNECT_HOST, "
                     "ISE_DATACONNECT_USER, and ISE_DATACONNECT_PASSWORD")
        return 1
    client = None
    try:
        client = DataConnectClient(cfg)
        schema = validate_dataconnect_schema(
            client, include_tacacs=getattr(cfg, "collect_tacacs", True))
        logger.info("Data Connect check passed: %d required reporting views", len(schema))
        return 0
    except Exception as exc:
        logger.error("Data Connect check failed: %s", exc)
        return 1
    finally:
        _close_quietly(client, "Data Connect check client")


def dataconnect_schema(cfg):
    """Print metadata for reporting views without reading event rows."""
    if not cfg.dataconnect_ready:
        logger.error("Data Connect schema requires ISE_DATACONNECT_HOST, "
                     "ISE_DATACONNECT_USER, and ISE_DATACONNECT_PASSWORD")
        return 1
    client = None
    try:
        client = DataConnectClient(cfg)
        rows = metadata_rows(client)
        print(json.dumps(rows, indent=2, default=str))
        return 0
    except Exception as exc:
        logger.error("Data Connect schema failed: %s", exc)
        return 1
    finally:
        _close_quietly(client, "Data Connect schema client")


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
    parser.add_argument("--version", action="version", version=version_string("ise-exporter"))
    parser.add_argument("--dataconnect-check", action="store_true",
                        help="validate Data Connect credentials, TLS, and view access")
    parser.add_argument("--dataconnect-schema", action="store_true",
                        help="print reporting-view column metadata as JSON")
    parser.add_argument("--reset-state", action="store_true",
                        help="clear exporter caches, snapshots, auth backoff, and DB pacing")
    args = parser.parse_args(argv)

    _load_env()
    metrics.ise_exporter_build_info.labels(
        version=__version__, revision=build_revision(),
        target_ise_release=SUPPORTED_ISE_RELEASE).set(1)
    cfg = Config.from_env()
    logging.getLogger().setLevel(cfg.log_level)
    logger.info("config: %s", cfg.summary())

    if args.dataconnect_check:
        return dataconnect_check(cfg)
    if args.dataconnect_schema:
        return dataconnect_schema(cfg)
    if args.reset_state:
        try:
            removed = reset_exporter_state(
                cfg.state_db_path,
                (
                    cfg.rest_auth_guard_file,
                    cfg.dataconnect_auth_guard_file,
                    cfg.dataconnect_shared_pacing_file,
                ),
            )
        except Exception as exc:
            logger.error("exporter state reset failed: %s", exc)
            return 1
        logger.warning("exporter state reset complete; removed %d files", len(removed))
        for path in removed:
            logger.warning("reset removed %s", path)
        return 0

    if not cfg.ise_host:
        logger.error("ISE_HOST not configured")
        return 1
    if not valid_hostname(cfg.ise_host):
        logger.error("ISE_HOST must be a bare DNS hostname or IPv4 address")
        return 1
    if not cfg.dataconnect_ready:
        logger.error("Data Connect credentials are required for reporting collection")
        return 1
    if not valid_hostname(cfg.dataconnect_host):
        logger.error(
            "ISE_DATACONNECT_HOST must be a bare DNS hostname or IPv4 address")
        return 1
    if cfg.collect_mnt_active_posture and not cfg.ise_mnt_host:
        logger.error("ISE_MNT_HOST is required when COLLECT_MNT_ACTIVE_POSTURE=true")
        return 1
    if cfg.collect_mnt_active_posture and not valid_hostname(cfg.ise_mnt_host):
        logger.error("ISE_MNT_HOST must be a bare DNS hostname or IPv4 address")
        return 1
    runtime_lock = None
    try:
        runtime_lock = acquire_runtime_lock(cfg.state_db_path)
    except Exception as exc:
        logger.error("could not acquire exporter runtime state: %s", exc)
        return 1
    client = None
    dataconnect = None
    mnt = None
    scheduler = None
    metrics_server = None
    try:
        rest_auth_guard = RestAuthGuard(cfg)
        client = ISEControlPlaneClient(cfg, auth_guard=rest_auth_guard)
        try:
            compatibility = validate_ise_compatibility(client)
        except ISECompatibilityError as exc:
            logger.error("%s", exc)
            return 1
        logger.info("validated Cisco ISE %s Patch %d on %s",
                    compatibility.ise_version, compatibility.patch_level,
                    ", ".join(compatibility.deployment_nodes))

        dataconnect = DataConnectClient(cfg)
        logger.info(
            "Data Connect schema discovery is scheduled on the serialized reporting lane")
        mnt = (MnTActiveSessionClient(cfg, auth_guard=rest_auth_guard)
               if cfg.collect_mnt_active_posture else None)

        shutdown = threading.Event()
        signal.signal(signal.SIGTERM, lambda *_: shutdown.set())
        signal.signal(signal.SIGINT, lambda *_: shutdown.set())

        metrics_server = start_http_server(
            cfg.exporter_port, registry=LockedCollectorRegistry())
        logger.info("metrics on :%d (REST/OpenAPI config + Data Connect reporting + "
                    "bounded MnT active posture)",
                    cfg.exporter_port)
        scheduler = PollScheduler(cfg, client, dataconnect=dataconnect, mnt=mnt)

        scheduler.loop(shutdown)   # blocks until SIGTERM/SIGINT
    finally:
        if dataconnect is not None and not (
                scheduler is not None and scheduler.dataconnect_worker_alive):
            _close_quietly(dataconnect, "Data Connect client")
        elif dataconnect is not None:
            # The worker is a daemon and the process is already shutting down. Do
            # not close its database connection from another thread mid-call.
            logger.warning("leaving Data Connect client open for process teardown because "
                           "the worker is still stopping")
        if mnt is not None and not (
                scheduler is not None and scheduler.mnt_worker_alive):
            _close_quietly(mnt, "MnT client")
        elif mnt is not None:
            logger.warning("leaving MnT client open for process teardown because "
                           "the worker is still stopping")
        _close_quietly(client, "control-plane client")
        _stop_metrics_server(metrics_server)
        release_runtime_lock(runtime_lock)
    logger.info("shutdown complete")
    return 0


if __name__ == "__main__":
    sys.exit(main())
