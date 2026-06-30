"""endpoints collector (port of collect_endpoint_metrics). The cheap scalar count
of registered endpoints via an ERS size=1 query. The model/manufacturer/OS
breakdown lives in collectors/models.py (pxGrid bulk)."""
import logging

from .. import metrics
from . import observe, CollectorFailed

logger = logging.getLogger(__name__)


def collect(client, cfg, mappings):
    with observe("endpoints"):
        count = client.get_ers_total("/config/endpoint", api_name="ers_endpoints")
        if count is None:
            raise CollectorFailed("no endpoint count returned")
        metrics.ise_endpoints_total.set(count)
        logger.info("Endpoints: %s", count)
