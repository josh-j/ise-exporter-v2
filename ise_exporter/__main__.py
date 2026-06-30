"""Entrypoint. Wires config -> clients -> two execution engines:
  * PollScheduler  (main thread) — REST poll tiers for the health plane + NAD
    inventory + (optionally) sessions/authz/models.
  * PxGridStreamer (daemon thread) — when COLLECT_PXGRID_STREAM=true, owns
    sessions/endpoints/models via topics; the scheduler then skips those.
Both write to the same metrics registry."""
import sys
import signal
import logging
import threading

import urllib3
from dotenv import load_dotenv
from prometheus_client import start_http_server

from .config import Config
from .clients.rest import ISERestClient
from .clients.pxgrid import PxGridControl
from .scheduler import PollScheduler
from .streaming import PxGridStreamer

logging.basicConfig(level=logging.INFO, format="%(asctime)s - %(levelname)s - %(message)s")
logger = logging.getLogger("ise_exporter")
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)


def main():
    load_dotenv()
    cfg = Config.from_env()
    if not cfg.ise_host or not cfg.ise_mnt_host:
        logger.error("ISE_HOST / ISE_MNT_HOST not configured")
        return 1

    shutdown = threading.Event()
    signal.signal(signal.SIGTERM, lambda *_: shutdown.set())
    signal.signal(signal.SIGINT, lambda *_: shutdown.set())

    start_http_server(cfg.exporter_port)
    logger.info("metrics on :%d  (stream=%s)", cfg.exporter_port, cfg.collect_pxgrid_stream)

    client = ISERestClient(cfg)
    pxgrid = PxGridControl(cfg) if cfg.pxgrid_ready else None
    if cfg.collect_pxgrid_endpoints and not pxgrid:
        logger.warning("pxGrid model collector requested but pxGrid creds incomplete")

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
