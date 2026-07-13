"""Entrypoint. Wires config -> clients -> two execution engines:
  * PollScheduler  (main thread) — REST poll tiers for the health plane + NAD
    inventory + (optionally) sessions/authz/models.
  * PxGridStreamer (daemon thread) — when COLLECT_PXGRID_STREAM=true, owns
    sessions/endpoints/models via topics; the scheduler then skips those.
Both write to the same metrics registry."""
import os
import sys
import signal
import argparse
import logging
import threading

import urllib3
from dotenv import load_dotenv
from prometheus_client import start_http_server

from .config import Config
from .clients.rest import ISERestClient
from .clients.pxgrid import SESSION_SERVICE, PxGridControl
from .scheduler import PollScheduler
from .streaming import PxGridStreamer

logging.basicConfig(level=logging.INFO, format="%(asctime)s - %(name)s - %(levelname)s - %(message)s")
logger = logging.getLogger("ise_exporter")
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

# systemd installs config here (deploy/install.sh); load it too so a manual
# `ise-exporter --pxgrid-check` from any cwd picks up the same env the service uses.
# Override with ISE_EXPORTER_ENV_FILE. load_dotenv never overrides an already-set var,
# so the running service's systemd EnvironmentFile still wins.
DEPLOY_ENV_FILE = os.environ.get("ISE_EXPORTER_ENV_FILE", "/etc/ise-exporter/ise-exporter.env")


def _missing_pxgrid(cfg):
    return [n for n, v in (("PXGRID_HOST", cfg.pxgrid_host),
                           ("PXGRID_NODE_NAME", cfg.pxgrid_node_name),
                           ("PXGRID_CLIENT_CERT", cfg.pxgrid_client_cert),
                           ("PXGRID_CLIENT_KEY", cfg.pxgrid_client_key)) if not v]


def pxgrid_check(cfg, *, check_stream=False):
    missing = _missing_pxgrid(cfg)
    if missing:
        logger.error("pxGrid check cannot run: missing %s", ", ".join(missing))
        return 1

    try:
        import importlib.metadata as _md
        logger.info("pxGrid check: ise-exporter %s (host=%s node_name=%s)",
                    _md.version("ise-exporter"), cfg.pxgrid_host, cfg.pxgrid_node_name)
    except Exception:
        pass

    ctl = PxGridControl(cfg)
    needs_stream = check_stream or cfg.collect_pxgrid_stream
    needs_endpoints = cfg.collect_pxgrid_endpoints or needs_stream
    ok = True

    # Each probe is independent: a failure in one (e.g. the session/pubsub stage on a
    # deployment with a scoped pxGrid group) is logged but must NOT hide the others —
    # otherwise the endpoint/posture diagnostics never run.
    try:
        ctl.account_activate()
        logger.info("pxGrid check: account active")
    except Exception as e:
        logger.error("pxGrid check: account activation FAILED: %s", e)
        ok = False

    if needs_stream:
        try:
            session_base, session_topic = ctl.session_topic()
            pubsub_peer, ws_urls, _ = ctl.resolve_pubsub()
            logger.info("pxGrid check: session rest=%s topic=%s", session_base, session_topic)
            logger.info("pxGrid check: pubsub peer=%s wsUrl=%s secret=ok", pubsub_peer, ws_urls)
            sessions = ctl.rest_query(SESSION_SERVICE, "getSessions", {},
                                      timeout=cfg.pxgrid_query_timeout)
            session_count = len(sessions.get("sessions", [])) if isinstance(sessions, dict) else 0
            logger.info("pxGrid check: getSessions ok sessions=%d", session_count)
        except Exception as e:
            logger.error("pxGrid check: session/pubsub probe FAILED: %s", e)
            ok = False

    if needs_endpoints:
        try:
            # pull a small page (not just 1) so the posture-attribute check below is
            # representative — posture attrs only exist on posture-assessed endpoints.
            endpoints = ctl.get_endpoints(page_size=50, max_pages=1,
                                          timeout=cfg.pxgrid_query_timeout)
            profiles = ctl.get_profiler_profiles(timeout=cfg.pxgrid_query_timeout)
            logger.info("pxGrid check: getEndpoints probe ok endpoints=%d (first page)", len(endpoints))
            if endpoints:
                from .collectors.models import _ep_attr
                from .util import POSTURE_REPORT_KEYS, SECURECLIENT_VERSION_KEYS
                ep = endpoints[0]
                # dump the attribute keys — top level AND any nested attribute maps — so we
                # can see exactly what getEndpoints returns and where posture attrs live.
                logger.info("pxGrid check: sample endpoint top-level keys: %s", sorted(ep.keys()))
                for container in ("customAttributes", "attributes", "otherAttributes"):
                    sub = ep.get(container)
                    if isinstance(sub, dict):
                        logger.info("pxGrid check: sample endpoint %s keys: %s",
                                    container, sorted(sub.keys()))
                n_report = sum(1 for e in endpoints if _ep_attr(e, *POSTURE_REPORT_KEYS))
                n_version = sum(1 for e in endpoints if _ep_attr(e, *SECURECLIENT_VERSION_KEYS))
                logger.info("pxGrid check: posture attrs in sample — PostureReport on %d/%d, "
                            "PostureAgentVersion on %d/%d endpoints",
                            n_report, len(endpoints), n_version, len(endpoints))
                if not n_report and not n_version:
                    logger.warning("pxGrid check: NO posture attributes on any sampled endpoint. If "
                                   "PostureReport/PostureAgentVersion are visible in ISE Context "
                                   "Visibility but absent here, getEndpoints isn't returning them for "
                                   "this deployment — the Secure Client posture panels can't populate. "
                                   "Send the attribute-key lines above so the collector can be pointed "
                                   "at the right attribute name.")
            else:
                logger.warning("pxGrid check: getEndpoints returned 0. This is expected on "
                               "ISE 3.3; ERS remains the baseline endpoint/profile source, "
                               "and pxGrid endpoint snapshots only enrich MFC/Secure Client "
                               "fields when ISE publishes them.")
            logger.info("pxGrid check: getProfiles ok profiles=%d", len(profiles))
        except Exception as e:
            logger.error("pxGrid check: endpoint/profiler probe FAILED: %s", e)
            ok = False

    if check_stream:
        try:
            shutdown = threading.Event()
            streamer = PxGridStreamer(ctl, {"hostname": {}, "location": {}, "ops_owner": {}},
                                      shutdown)
            try:
                streamer._connect_ws()
            finally:
                streamer._close_ws()
            logger.info("pxGrid check: WSS/STOMP connect+subscribe ok")
        except Exception as e:
            logger.error("pxGrid check: WSS/STOMP connect FAILED: %s", e)
            ok = False

    if ok:
        logger.info("pxGrid check passed")
        return 0
    logger.error("pxGrid check: one or more probes FAILED (see above)")
    return 1


def _load_env():
    """Load ./.env (dev convenience) then the systemd deployment env file if present,
    so `ise-exporter --pxgrid-check` works from any directory on a deployed host.

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
    parser.add_argument("--pxgrid-check", action="store_true",
                        help="validate pxGrid account, services, topics, and REST probes")
    parser.add_argument("--pxgrid-check-stream", action="store_true",
                        help="also validate pxGrid WSS/STOMP connect+subscribe")
    args = parser.parse_args(argv)

    _load_env()
    cfg = Config.from_env()
    logging.getLogger().setLevel(cfg.log_level)
    logger.info("config: %s", cfg.summary())

    if args.pxgrid_check or args.pxgrid_check_stream:
        return pxgrid_check(cfg, check_stream=args.pxgrid_check_stream or cfg.collect_pxgrid_stream)

    if not cfg.ise_host or not cfg.ise_mnt_host:
        logger.error("ISE_HOST / ISE_MNT_HOST not configured")
        return 1

    shutdown = threading.Event()
    signal.signal(signal.SIGTERM, lambda *_: shutdown.set())
    signal.signal(signal.SIGINT, lambda *_: shutdown.set())

    start_http_server(cfg.exporter_port)
    logger.info("metrics on :%d  (stream=%s)", cfg.exporter_port, cfg.collect_pxgrid_stream)

    client = ISERestClient(cfg)
    if cfg.pxgrid_ready:
        pxgrid = PxGridControl(cfg)
    else:
        pxgrid = None
        # spell out exactly which of the four required vars is missing
        missing = _missing_pxgrid(cfg)
        if cfg.collect_pxgrid_stream or cfg.collect_pxgrid_endpoints:
            logger.warning("pxGrid disabled (stream=%s endpoints=%s): missing %s",
                           cfg.collect_pxgrid_stream, cfg.collect_pxgrid_endpoints,
                           ", ".join(missing))

    scheduler = PollScheduler(cfg, client, pxgrid=pxgrid)

    if cfg.collect_pxgrid_stream and pxgrid:
        streamer = PxGridStreamer(pxgrid, scheduler.mappings, shutdown)
        threading.Thread(target=streamer.run, name="pxgrid-stream", daemon=True).start()
        logger.info("pxGrid streaming engine started")

    scheduler.loop(shutdown)   # blocks until SIGTERM/SIGINT
    logger.info("shutdown complete")
    return 0


if __name__ == "__main__":
    sys.exit(main())
