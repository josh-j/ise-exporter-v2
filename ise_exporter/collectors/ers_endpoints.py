"""ERS fallback for the endpoint profiling-policy breakdown, used ONLY when pxGrid
getEndpoints returns nothing (ISE not publishing endpoints to pxGrid).

Counts endpoints per profiling policy through the ERS API, picking the cheaper of two
paths from cheap `size=1` totals (enumerating ISE's ~900-profile catalog is slow —
~90s — so we avoid it in the common case):
  * per-endpoint — enumerate endpoints, read each one's profileId, and resolve the few
                   distinct profile names lazily (one cached GET each). Chosen when
                   there are fewer endpoints than catalog profiles. Exact; handles
                   unprofiled endpoints.
  * per-profile  — one `size=1` count query per catalog profile (filter=profileId.EQ.
                   <uuid>), using a long-cached catalog. Chosen when endpoints greatly
                   outnumber profiles.
Reuses the cached pxGrid getProfiles hierarchy (collectors/models._hierarchy) for
category/parent when available.

Cannot recover the MFC hardware-model / OS / manufacturer breakdown or Secure Client
posture — ERS doesn't expose those attributes — so those gauges stay empty until pxGrid
endpoint publishing works."""
import logging
import time
from collections import defaultdict
from concurrent.futures import ThreadPoolExecutor

from .. import metrics
from ..util import clear_metric
from . import observe, CollectorFailed, pxgrid_endpoints_present

logger = logging.getLogger(__name__)

_name_cache = {}          # profileId (uuid) -> profile name; lazy, persistent (ids stable)
_catalog = []             # [(id, name)] full catalog for the per-profile path
_catalog_at = 0.0
_CATALOG_TTL = 21600      # the profiler catalog changes only on ISE upgrade — refresh rarely


def collect(client, cfg):
    # pxGrid getEndpoints is authoritative when it's delivering — only fall back when
    # it's empty, so the two never fight over ise_endpoints_by_policy / _by_profile_all.
    if pxgrid_endpoints_present():
        return
    with observe("ers_endpoint_profiles"):
        total = client.get_ers_total("/config/endpoint", api_name="ers_endpoint_total")
        if total is not None:
            metrics.ise_endpoints_total.set(total)
        clear_metric(metrics.ise_endpoints_by_policy)
        clear_metric(metrics.ise_endpoints_by_profile_all)
        if not total:
            return

        catalog_size = client.get_ers_total("/config/profilerprofile",
                                             api_name="ers_profile_count") or 0
        if total <= max(catalog_size, 1):
            counts, mode = _count_by_endpoint(client, cfg), "per-endpoint"
        else:
            counts, mode = _count_by_profile(client, cfg), "per-profile"

        from .models import _hierarchy
        for name, n in counts.items():
            metrics.ise_endpoints_by_policy.labels(policy=name).set(n)
            category, parent = _hierarchy.get(name, ("unknown", ""))
            metrics.ise_endpoints_by_profile_all.labels(
                category=category, parent=parent, profile=name).set(n)
        logger.info("ERS endpoint fallback (%s): %s endpoints, %d profiles with endpoints "
                    "(pxGrid getEndpoints was empty; models/posture stay pxGrid-only)",
                    mode, total, len(counts))


def _resolve_name(client, pid):
    """profileId -> profile name, one cached GET per distinct profile (never the whole
    slow catalog). Unknown/blank ids fall back to the raw id."""
    if pid not in _name_cache:
        d = client.get_ers(f"/config/profilerprofile/{pid}", api_name="ers_profile_name")
        p = (d or {}).get("ProfilerProfile", {}) if isinstance(d, dict) else {}
        _name_cache[pid] = p.get("name") or pid
    return _name_cache[pid]


def _count_by_endpoint(client, cfg):
    eps = client.get_ers("/config/endpoint", {"size": 100}, get_all=True,
                         api_name="ers_endpoint_list") or []
    ids = [e["id"] for e in eps if isinstance(e, dict) and e.get("id")]
    to_fetch = ids[:cfg.max_detail_fetches_per_cycle]
    if len(ids) > len(to_fetch):
        logger.warning("ERS endpoint fallback: %d endpoints, detailing first %d this cycle "
                       "(raise MAX_DETAIL_FETCHES_PER_CYCLE)", len(ids), len(to_fetch))

    def _pid(eid):
        d = client.get_ers(f"/config/endpoint/{eid}", api_name="ers_endpoint_detail")
        ep = (d or {}).get("ERSEndPoint", {}) if isinstance(d, dict) else {}
        return ep.get("profileId")

    with ThreadPoolExecutor(max_workers=cfg.max_workers) as pool:
        pids = [p for p in pool.map(_pid, to_fetch) if p]
    counts = defaultdict(int)
    for pid in pids:                              # few distinct ids, resolved+cached
        counts[_resolve_name(client, pid)] += 1
    return dict(counts)


def _catalog_ids(client):
    global _catalog, _catalog_at
    if _catalog and (time.time() - _catalog_at) < _CATALOG_TTL:
        return _catalog
    profiles = client.get_ers("/config/profilerprofile", {"size": 100},
                              get_all=True, api_name="ers_profiles")
    if profiles:
        _catalog = [(p["id"], p["name"]) for p in profiles if p.get("id") and p.get("name")]
        _catalog_at = time.time()
    return _catalog


def _count_by_profile(client, cfg):
    catalog = _catalog_ids(client)
    if not catalog:
        raise CollectorFailed("ERS returned no profiler profiles")
    items = catalog[:cfg.ers_endpoint_profile_max]
    if len(catalog) > len(items):
        logger.warning("ERS endpoint fallback: %d profiles in catalog, querying first %d "
                       "(raise ERS_ENDPOINT_PROFILE_MAX to cover all)",
                       len(catalog), len(items))

    def _count(item):
        pid, name = item
        n = client.get_ers_total("/config/endpoint", {"filter": f"profileId.EQ.{pid}"},
                                 api_name="ers_endpoint_by_profile")
        return name, int(n or 0)

    counts = {}
    with ThreadPoolExecutor(max_workers=cfg.max_workers) as pool:
        for name, n in pool.map(_count, items):
            if n:
                counts[name] = counts.get(name, 0) + n
    return counts
