"""licensing collector (port of collect_license_metrics). Smart-licensing tier
state via PAN OpenAPI: per-tier consumption counter, enabled flag, compliance."""
import logging
import math

from .. import metrics
from ..snapshots import replace_metric_snapshot
from . import observe, CollectorFailed

logger = logging.getLogger(__name__)
_METRICS = (
    metrics.ise_license_consumption,
    metrics.ise_license_compliance,
    metrics.ise_license_enabled,
)
_COMPLIANT_STATES = frozenset({
    "COMPLIANT",
    "FULL_COMPLIANCE",
    "RESERVED_IN_COMPLIANCE",
})
_COMPLIANCE_STATES = _COMPLIANT_STATES | frozenset({
    "EVALUATION", "EVALUATION_EXPIRED", "NONCOMPLIANT", "RELEASED_ENTITLEMENT",
})
_STATUS_STATES = frozenset({"DISABLED", "ENABLED"})


def collect(client, cfg):
    with observe("licensing"):
        # /license/system/tier-state returns a bare list (no `response` envelope)
        tiers = client.get_pan_api("/license/system/tier-state", api_name="pan_license", unwrap=False)
        if not tiers:
            raise CollectorFailed("no license tier-state")
        if not isinstance(tiers, (dict, list)):
            raise CollectorFailed("license tier-state was not an object or list")

        rows = []
        names = set()
        for tier in (tiers if isinstance(tiers, list) else [tiers]):
            if not isinstance(tier, dict):
                raise CollectorFailed("license tier-state contained a non-object")
            name = str(tier.get("name") or "").strip()
            if not name or len(name) > 256 or name in names:
                raise CollectorFailed("license tier-state contained an invalid tier name")
            names.add(name)
            if "consumptionCounter" not in tier:
                raise CollectorFailed(f"license tier {name} omitted consumption")
            try:
                consumption = float(tier.get("consumptionCounter", 0) or 0)
            except (TypeError, ValueError) as error:
                raise CollectorFailed(
                    f"license tier {name} contained invalid consumption") from error
            if not math.isfinite(consumption) or consumption < 0:
                raise CollectorFailed(f"license tier {name} contained invalid consumption")
            compliance = str(tier.get("compliance") or "").strip().upper()
            status = str(tier.get("status") or "").strip().upper()
            if compliance not in _COMPLIANCE_STATES:
                raise CollectorFailed(f"license tier {name} contained invalid compliance")
            if status not in _STATUS_STATES:
                raise CollectorFailed(f"license tier {name} contained invalid status")
            # These values come from ISE 3.3's TierStateSettings enum. Exact
            # membership avoids both false positives and the former false
            # negatives for COMPLIANT and FULL_COMPLIANCE.
            is_compliant = compliance in _COMPLIANT_STATES
            rows.append({
                "name": name,
                "consumption": consumption,
                "enabled": int(status == "ENABLED"),
                "compliant": int(is_compliant),
            })

        writers = []
        for row in rows:
            writers.extend((
                lambda row=row: metrics.ise_license_consumption.labels(
                    tier=row["name"]).set(row["consumption"]),
                lambda row=row: metrics.ise_license_enabled.labels(
                    tier=row["name"]).set(row["enabled"]),
                lambda row=row: metrics.ise_license_compliance.labels(
                    tier=row["name"]).set(row["compliant"]),
            ))
        replace_metric_snapshot(_METRICS, writers)
        logger.info("Licensing: %d tiers", len(rows))
