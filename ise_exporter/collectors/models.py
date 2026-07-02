"""Device-model collector: one bulk pxGrid getEndpoints, aggregated in-process by
MFC attributes (hardware model / manufacturer / endpoint type / OS / policy). No
per-endpoint fan-out. Manufacturer falls back model->oui->unknown so OUI lifts
coverage where MFC manufacturer is blank; unclassified buckets to 'unknown' so
gaps stay visible. Also emits MFC coverage fractions per attribute."""
import logging
from collections import defaultdict

from .. import metrics
from ..util import clear_metric, first_nonempty
logger = logging.getLogger(__name__)

# pxGrid emits camelCase; Context Visibility / ERS show PascalCase. Read both.
_MODEL_KEYS = ("mfcInfoHardwareModel", "MFCInfoHardwareModel")
_MFG_KEYS = ("mfcInfoHardwareManufacturer", "MFCInfoHardwareManufacturer")
_TYPE_KEYS = ("mfcInfoEndpointType", "MFCInfoEndpointType", "mfcInfoDeviceType")
_OS_KEYS = ("mfcInfoOperatingSystem", "MFCInfoOperatingSystem")
_POLICY_KEYS = ("endPointPolicy", "EndPointPolicy", "MFCInfoEndpointPolicy")
_OUI_KEYS = ("oui", "OUI")


def collect(pxgrid, cfg):
    try:
        endpoints = pxgrid.get_endpoints(timeout=cfg.pxgrid_query_timeout)
    except Exception as e:
        logger.warning("pxGrid getEndpoints failed: %s", e)
        return
    if not endpoints:
        return
    emit_endpoint_metrics(endpoints)


def emit_endpoint_metrics(endpoints):
    """Aggregate a list of pxGrid endpoint attribute maps onto the model gauges.
    Shared by the poll collector (collect) and the stream projector."""
    by_model = defaultdict(int)
    by_mfg = defaultdict(int)
    by_type = defaultdict(int)
    by_os = defaultdict(int)
    by_policy = defaultdict(int)
    coverage = {"model": 0, "manufacturer": 0, "endpoint_type": 0, "os": 0}
    total = 0

    for ep in endpoints:
        total += 1
        model = first_nonempty(ep, *_MODEL_KEYS)
        mfg = first_nonempty(ep, *_MFG_KEYS)
        oui = first_nonempty(ep, *_OUI_KEYS)
        etype = first_nonempty(ep, *_TYPE_KEYS)
        os_ = first_nonempty(ep, *_OS_KEYS)
        policy = first_nonempty(ep, *_POLICY_KEYS)

        if model:
            coverage["model"] += 1
        # manufacturer: MFC field, then OUI fallback
        mfg_final = mfg or oui
        if mfg_final:
            coverage["manufacturer"] += 1
        if etype:
            coverage["endpoint_type"] += 1
        if os_:
            coverage["os"] += 1

        by_model[model or "unknown"] += 1
        by_mfg[mfg_final or "unknown"] += 1
        by_type[etype or "unknown"] += 1
        by_os[os_ or "unknown"] += 1
        by_policy[policy or "unknown"] += 1

    for metric in (metrics.ise_endpoints_by_hardware_model, metrics.ise_endpoints_by_manufacturer,
                   metrics.ise_endpoints_by_endpoint_type, metrics.ise_endpoints_by_os,
                   metrics.ise_endpoints_by_policy, metrics.ise_endpoint_mfc_coverage):
        clear_metric(metric)

    for model, n in by_model.items():
        metrics.ise_endpoints_by_hardware_model.labels(model=model).set(n)
    for mfg, n in by_mfg.items():
        metrics.ise_endpoints_by_manufacturer.labels(manufacturer=mfg).set(n)
    for etype, n in by_type.items():
        metrics.ise_endpoints_by_endpoint_type.labels(endpoint_type=etype).set(n)
    for os_, n in by_os.items():
        metrics.ise_endpoints_by_os.labels(os=os_).set(n)
    for policy, n in by_policy.items():
        metrics.ise_endpoints_by_policy.labels(policy=policy).set(n)

    metrics.ise_endpoints_pxgrid_total.set(total)
    for attr, hit in coverage.items():
        metrics.ise_endpoint_mfc_coverage.labels(attribute=attr).set(hit / total if total else 0.0)
    logger.debug("models: %d endpoints, model coverage %.0f%%",
                 total, 100 * coverage["model"] / total if total else 0)
