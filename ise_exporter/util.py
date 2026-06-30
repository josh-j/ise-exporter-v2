"""Stateless helpers shared across collectors. (Moved verbatim from the
monolithic ise_exporter.py.)"""
from datetime import datetime, timezone
import logging

logger = logging.getLogger(__name__)


def clear_metric(metric):
    try:
        metric._metrics.clear()
    except Exception:
        pass


def normalize_mac(mac):
    if not mac:
        return ""
    return mac.strip().upper().replace("-", ":")


def normalize_location(loc_str):
    if not loc_str:
        return "Unknown"
    parts = loc_str.split("#")
    if parts and parts[0] == "All Locations" and len(parts) > 1:
        return "#".join(parts[1:])
    return loc_str


def parse_other_attr_string(s):
    if not s:
        return {}
    result = {}
    for part in s.split(":!:"):
        if "=" not in part:
            continue
        k, _, v = part.partition("=")
        k, v = k.strip(), v.strip()
        if k and v:
            result[k] = v
    return result


def first_nonempty(attrs, *keys):
    for k in keys:
        v = attrs.get(k)
        if v is not None and str(v).strip():
            return str(v).strip()
    return ""


def parse_ise_date(date_str):
    if not date_str:
        return None
    for fmt in ("%a %b %d %H:%M:%S UTC %Y", "%a %b %d %H:%M:%S %Y", "%a %b %d %H:%M:%S %Z %Y"):
        try:
            dt = datetime.strptime(date_str, fmt)
            return dt.replace(tzinfo=timezone.utc) if dt.tzinfo is None else dt
        except ValueError:
            continue
    logger.debug("Could not parse date: %s", date_str)
    return None
