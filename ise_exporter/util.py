"""Stateless helpers shared across collectors. (Moved verbatim from the
monolithic ise_exporter.py.)"""
from datetime import datetime, timezone
import logging
import re

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


# Canonical posture labels — collapse the spelling variants ISE emits across the
# pxGrid session topic (`postureStatus`) and MnT session detail (`posture_status`)
# into one stable set so dashboards can group/alert reliably.
_POSTURE_CANON = {
    "compliant": "Compliant",
    "noncompliant": "NonCompliant",
    "pending": "Pending",
    "notapplicable": "NotApplicable",
    "na": "NotApplicable",
    "unknown": "Unknown",
    "error": "Error",
}


def normalize_posture(value):
    """Map a raw posture status to a canonical label. Empty/missing -> 'NotApplicable'
    (no posture assessment ran for the session — the common case for endpoints not
    subject to a posture policy)."""
    v = (value or "").strip()
    if not v:
        return "NotApplicable"
    key = v.lower().replace("-", "").replace("_", "").replace(" ", "")
    return _POSTURE_CANON.get(key, v)


def normalize_bool_label(value):
    """Coerce an ISE boolean-ish attribute (mdmCompliant, mdmRegistered, ...) to a
    stable 'true' | 'false' | 'unknown' label."""
    v = (value or "").strip().lower()
    if v in ("true", "yes", "1", "compliant", "registered", "enabled"):
        return "true"
    if v in ("false", "no", "0", "noncompliant", "unregistered", "disabled"):
        return "false"
    return "unknown"


# Each top-level posture policy in a PostureReport looks like
#   <PolicyName>\;<Result>\;(<requirement detail>), <PolicyName>\;<Result>\;(...)
# where '\;' is ISE's escaped semicolon. The requirement detail inside the parens
# reuses '\;' between requirements and ':' inside condition lists, so we anchor on
# the exact "<name>\;<Result>\;(" shape to pick out ONLY the policy-level roll-up.
_POSTURE_POLICY_RE = re.compile(
    r'([A-Za-z0-9_.\-]+)\\?;'
    r'(Passed|Failed|Pending|Skipped|Error|Unknown|NotApplicable|Compliant|NonCompliant)'
    r'\\?;\(')


def parse_posture_report(report):
    """Parse an ISE MnT `PostureReport` (from a session's other_attr_string) into a
    list of (policy_name, result) at the posture-POLICY level, e.g.
    [('C2CP-WIN-FIREWALL', 'Passed'), ('C2CP-WIN-AM', 'Failed'), ...]. Requirement/
    condition detail is intentionally dropped — too high-cardinality for a gauge; the
    policy name already encodes which check it is (FIREWALL, AM, DE-BITLOCKER, ...)."""
    if not report:
        return []
    return [(m.group(1), m.group(2)) for m in _POSTURE_POLICY_RE.finditer(report)]


def normalize_agent_version(value):
    """'Posture Agent for Windows 5.1.17.3394' -> 'Windows 5.1.17.3394'. Keeps the OS
    qualifier + version, drops the boilerplate prefix so the series stays readable."""
    v = (value or "").strip()
    if not v:
        return ""
    return v.replace("Posture Agent for ", "").strip()


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
