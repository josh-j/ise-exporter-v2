"""ERS fallback for the endpoint profiling-policy breakdown, used ONLY when pxGrid
getEndpoints returns nothing (ISE not publishing endpoints to pxGrid).

Counts endpoints per profiling policy with ERS filter queries — one lightweight
`size=1` count per profile (`filter=profileId.EQ.<uuid>`), so cost is bounded by the
profile catalog size, NOT the endpoint count. Reuses the cached pxGrid getProfiles
hierarchy (collectors/models._hierarchy) for category/parent when available.

Cannot recover the MFC hardware-model / OS / manufacturer breakdown or Secure Client
posture — ERS doesn't expose those attributes — so those gauges stay empty until pxGrid
endpoint publishing works. This only lights up the endpoint COUNT and the profiling
dashboards."""
import logging
from concurrent.futures import ThreadPoolExecutor

from .. import metrics
from ..util import clear_metric
from . import observe, CollectorFailed

logger = logging.getLogger(__name__)


def _pxgrid_endpoints_present():
    try:
        return metrics.ise_endpoints_pxgrid_total._value.get() > 0
    except Exception:
        return False


def collect(client, cfg):
    # pxGrid getEndpoints is authoritative when it's delivering — only fall back when
    # it's empty, so the two never fight over ise_endpoints_by_policy / _by_profile_all.
    if _pxgrid_endpoints_present():
        return
    with observe("ers_endpoint_profiles"):
        total = client.get_ers_total("/config/endpoint", api_name="ers_endpoint_total")
        if total is not None:
            metrics.ise_endpoints_total.set(total)
        profiles = client.get_ers("/config/profilerprofile", {"size": 100},
                                  get_all=True, api_name="ers_profiles")
        if not profiles:
            raise CollectorFailed("ERS returned no profiler profiles")

        catalog = [(p.get("id"), p.get("name")) for p in profiles
                   if p.get("id") and p.get("name")]
        capped = catalog[:cfg.ers_endpoint_profile_max]
        if len(catalog) > len(capped):
            logger.warning("ERS endpoint fallback: %d profiles in catalog, querying first %d "
                           "(raise ERS_ENDPOINT_PROFILE_MAX to cover all)",
                           len(catalog), len(capped))

        def _count(item):
            pid, name = item
            n = client.get_ers_total("/config/endpoint", {"filter": f"profileId.EQ.{pid}"},
                                     api_name="ers_endpoint_by_profile")
            return name, int(n or 0)

        counts = {}
        with ThreadPoolExecutor(max_workers=cfg.max_workers) as pool:
            for name, n in pool.map(_count, capped):
                if n:
                    counts[name] = counts.get(name, 0) + n

        # join the category/parent hierarchy from the cached pxGrid getProfiles catalog
        # (still reachable even when getEndpoints is empty); falls back to unknown.
        from .models import _hierarchy
        clear_metric(metrics.ise_endpoints_by_policy)
        clear_metric(metrics.ise_endpoints_by_profile_all)
        for name, n in counts.items():
            metrics.ise_endpoints_by_policy.labels(policy=name).set(n)
            category, parent = _hierarchy.get(name, ("unknown", ""))
            metrics.ise_endpoints_by_profile_all.labels(
                category=category, parent=parent, profile=name).set(n)
        logger.info("ERS endpoint fallback: %s endpoints, %d profiles with endpoints "
                    "(pxGrid getEndpoints was empty; models/posture stay pxGrid-only)",
                    total, len(counts))
