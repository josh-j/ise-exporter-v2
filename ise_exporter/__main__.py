"""Entrypoint. Wires config -> clients -> two execution engines:
  * PollScheduler  (main thread) — REST poll tiers for the health plane + NAD
    inventory + (optionally) sessions/authz/models.
  * PxGridStreamer (daemon thread) — when COLLECT_PXGRID_STREAM=true, owns
    sessions/endpoints/models via topics; the scheduler then skips those.
Both write to the same metrics registry."""
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

    ctl = PxGridControl(cfg)
    try:
        needs_stream = check_stream or cfg.collect_pxgrid_stream
        needs_endpoints = cfg.collect_pxgrid_endpoints or needs_stream

        ctl.account_activate()
        logger.info("pxGrid check: account active")

        if needs_stream:
            session_base, session_topic = ctl.session_topic()
            pubsub_peer, ws_urls, _ = ctl.resolve_pubsub()
            logger.info("pxGrid check: session rest=%s topic=%s", session_base, session_topic)
            logger.info("pxGrid check: pubsub peer=%s wsUrl=%s secret=ok", pubsub_peer, ws_urls)

            sessions = ctl.rest_query(SESSION_SERVICE, "getSessions", {},
                                      timeout=cfg.pxgrid_query_timeout)
            session_count = len(sessions.get("sessions", [])) if isinstance(sessions, dict) else 0
            logger.info("pxGrid check: getSessions ok sessions=%d", session_count)

        if needs_endpoints:
            endpoints = ctl.get_endpoints(page_size=1, max_pages=1,
                                          timeout=cfg.pxgrid_query_timeout)
            profiles = ctl.get_profiler_profiles(timeout=cfg.pxgrid_query_timeout)
            logger.info("pxGrid check: getEndpoints one-page probe ok endpoints=%d", len(endpoints))
            if endpoints:
                # dump the attribute keys of a sample endpoint so we can see exactly
                # which attributes ISE publishes (MFC/profile fields, and whether
                # posture attrs like PostureReport/PostureAgentVersion are present).
                logger.info("pxGrid check: sample endpoint attribute keys: %s",
                            sorted(endpoints[0].keys()))
            else:
                logger.warning("pxGrid check: getEndpoints returned 0 — endpoint model / "
                               "profile / posture-attribute metrics will be empty until ISE "
                               "publishes endpoint context to pxGrid (see the warning above)")
            logger.info("pxGrid check: getProfiles ok profiles=%d", len(profiles))

        if check_stream:
            shutdown = threading.Event()
            streamer = PxGridStreamer(ctl, {"hostname": {}, "location": {}, "ops_owner": {}},
                                      shutdown)
            try:
                streamer._connect_ws()
            finally:
                streamer._close_ws()
            logger.info("pxGrid check: WSS/STOMP connect+subscribe ok")
    except Exception as e:
        logger.error("pxGrid check failed: %s", e)
        return 1
    logger.info("pxGrid check passed")
    return 0


def main(argv=None):
    parser = argparse.ArgumentParser()
    parser.add_argument("--pxgrid-check", action="store_true",
                        help="validate pxGrid account, services, topics, and REST probes")
    parser.add_argument("--pxgrid-check-stream", action="store_true",
                        help="also validate pxGrid WSS/STOMP connect+subscribe")
    args = parser.parse_args(argv)

    load_dotenv()
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
