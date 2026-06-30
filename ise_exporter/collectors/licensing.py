"""licensing collector (port of collect_license_metrics). Smart-licensing tier
state via PAN OpenAPI: per-tier consumption counter, enabled flag, compliance."""
import logging

from .. import metrics
from ..util import clear_metric
from . import observe, CollectorFailed

logger = logging.getLogger(__name__)


def collect(client, cfg, mappings):
    with observe("licensing"):
        # /license/system/tier-state returns a bare list (no `response` envelope)
        tiers = client.get_pan_api("/license/system/tier-state", api_name="pan_license", unwrap=False)
        if not tiers:
            raise CollectorFailed("no license tier-state")

        clear_metric(metrics.ise_license_consumption)
        clear_metric(metrics.ise_license_compliance)
        clear_metric(metrics.ise_license_enabled)

        for tier in (tiers if isinstance(tiers, list) else [tiers]):
            name = tier.get("name", "unknown")
            metrics.ise_license_consumption.labels(tier=name).set(tier.get("consumptionCounter", 0))
            metrics.ise_license_enabled.labels(tier=name).set(
                1 if tier.get("status", "DISABLED") == "ENABLED" else 0)
            compliance = tier.get("compliance", "")
            is_compliant = "IN_COMPLIANCE" in compliance.upper() if compliance else True
            metrics.ise_license_compliance.labels(tier=name).set(1 if is_compliant else 0)
        logger.info("Licensing: %d tiers", len(tiers) if isinstance(tiers, list) else 1)
