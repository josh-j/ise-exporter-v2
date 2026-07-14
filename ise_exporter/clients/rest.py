"""Transport layer for ERS / PAN OpenAPI / MnT XML. This is the ISECollector
class from the monolith with the FEATURE methods removed — those (get_active_sessions,
get_network_devices, ...) collapse into the collectors, which now call the generic
get_ers / get_ers_total / get_pan_api / get_mnt_xml directly. Pure plumbing, no
metric writes except the api_requests/api_errors counters."""
import logging
import time
import warnings
import xml.etree.ElementTree as ET

import requests
from requests.auth import HTTPBasicAuth
from requests.adapters import HTTPAdapter
from urllib3.util.retry import Retry
from urllib3.exceptions import InsecureRequestWarning

from ..metrics import ise_api_requests_total, ise_api_errors_total

logger = logging.getLogger(__name__)


def _strip_ns(tag):
    return tag.split("}", 1)[-1] if "}" in tag else tag


class ISERestClient:
    """Compatibility client spanning both planes; new runtime code uses the
    plane-specific clients below."""

    def __init__(self, cfg, *, include_control=True, include_mnt=True):
        self.cfg = cfg
        self.host = cfg.ise_host
        self.mnt_host = cfg.ise_mnt_host
        self.ers_url = f"https://{cfg.ise_host}:{cfg.ers_port}/ers"
        self.pan_url = f"https://{cfg.ise_host}/api/v1"
        self.mnt_xml_url = f"https://{cfg.ise_mnt_host}/admin/API/mnt"
        self.auth = HTTPBasicAuth(cfg.ise_user, cfg.ise_pass)
        self.session = self._mk(
            "application/json", self._tls_verify("rest")) if include_control else None
        self.mnt_session = self._mk(
            "application/xml", self._tls_verify("mnt")) if include_mnt else None
        self._auth_failures = 0
        self._auth_block_until = 0.0

    def _tls_verify(self, plane):
        enabled = bool(getattr(self.cfg, f"{plane}_ssl_verify", True))
        if not enabled:
            return False
        bundle = str(getattr(self.cfg, f"{plane}_ca_bundle", "") or "").strip()
        return bundle or True

    def _mk(self, content_type, verify=True):
        s = requests.Session()
        s.auth = self.auth
        s.verify = verify
        # Keep trust deterministic: explicit configuration, not ambient process
        # REQUESTS_CA_BUNDLE/CURL_CA_BUNDLE state, owns each plane's trust policy.
        s.trust_env = False
        retry = Retry(total=3, backoff_factor=1, status_forcelist=[429, 500, 502, 503, 504])
        s.mount("https://", HTTPAdapter(max_retries=retry))
        # Accept-only — Content-Type on a GET is non-standard and has tripped DoD WAFs.
        s.headers.update({"Accept": content_type})
        return s

    def _request(self, session, url, params=None, timeout=30, api_name="unknown"):
        now = time.time()
        if self._auth_block_until and now < self._auth_block_until:
            ise_api_requests_total.labels(api=api_name, status="auth_blocked").inc()
            ise_api_errors_total.labels(api=api_name, error_type="auth_blocked",
                                        http_code="401").inc()
            return None
        try:
            # Suppress only urllib3's warning when an operator explicitly selected
            # unverified lab TLS; this keeps CLI JSON/table output machine-readable.
            with warnings.catch_warnings():
                warnings.simplefilter("ignore", InsecureRequestWarning)
                r = session.get(url, params=params, timeout=timeout)
            r.raise_for_status()
            self._auth_failures = 0
            self._auth_block_until = 0.0
            ise_api_requests_total.labels(api=api_name, status="success").inc()
            return r
        except requests.exceptions.Timeout:
            logger.warning("Timeout for %s", url)
            ise_api_requests_total.labels(api=api_name, status="timeout").inc()
            ise_api_errors_total.labels(api=api_name, error_type="timeout", http_code="0").inc()
            return None
        except requests.exceptions.ConnectionError as e:
            logger.warning("Connection error for %s: %s", url, e)
            ise_api_requests_total.labels(api=api_name, status="connection_error").inc()
            ise_api_errors_total.labels(api=api_name, error_type="connection_error", http_code="0").inc()
            return None
        except requests.exceptions.HTTPError as e:
            if e.response is not None:
                status = e.response.status_code
                try:
                    snippet = e.response.text[:200].replace("\n", " ").replace("\r", " ")
                except Exception:
                    snippet = ""
                logger.warning("HTTP %s for %s  body: %s", status, url, snippet)
                if status == 401:
                    self._record_auth_failure()
            else:
                status = "no_response"
                logger.warning("HTTP error with no response for %s: %s", url, e)
            ise_api_requests_total.labels(api=api_name, status=f"http_{status}").inc()
            ise_api_errors_total.labels(api=api_name, error_type="http_error", http_code=str(status)).inc()
            return None
        except Exception as e:
            logger.error("Request failed for %s: %s", url, e)
            ise_api_requests_total.labels(api=api_name, status="error").inc()
            ise_api_errors_total.labels(api=api_name, error_type="unknown", http_code="0").inc()
            return None

    def _record_auth_failure(self):
        self._auth_failures += 1
        threshold = max(1, getattr(self.cfg, "auth_failure_threshold", 3))
        if self._auth_failures < threshold:
            return
        backoff = max(0, getattr(self.cfg, "auth_failure_backoff", 900))
        if not backoff:
            return
        self._auth_block_until = time.time() + backoff
        logger.error("ISE API authentication failed %d times; suppressing further API requests "
                     "for %ds to avoid account lockout", self._auth_failures, backoff)

    def _get_json(self, session, url, params=None, api_name="unknown"):
        """GET + JSON-decode, returning the parsed body or None on request/parse failure.
        Collapses the request→None-guard→json()→ValueError-guard boilerplate the JSON
        accessors below all share."""
        r = self._request(session, url, params, api_name=api_name)
        if r is None:
            return None
        try:
            return r.json()
        except ValueError:
            return None

    # --- generic accessors used by collectors ---
    def get_ers(self, path, params=None, get_all=False, api_name="ers"):
        """ERS JSON GET. Returns the SearchResult.resources LIST (following
        nextPage.href when get_all), or the raw dict when there's no SearchResult.

        A failed or malformed page invalidates the complete enumeration. Returning
        a partial list would make collectors publish a plausible but incorrect
        inventory, so failures return ``None`` while a valid empty result remains
        the distinct value ``[]``.
        """
        url = f"{self.ers_url}{path}"
        data = self._get_json(self.session, url, params, api_name=api_name)
        if data is None:
            return None
        if "SearchResult" not in data:
            return data

        sr = data["SearchResult"]
        if not isinstance(sr, dict):
            logger.warning("Malformed ERS SearchResult for %s", url)
            return None
        resources = sr.get("resources", [])
        if not isinstance(resources, list):
            logger.warning("Malformed ERS resources for %s", url)
            return None
        resources = list(resources)
        expected_total = sr.get("total")
        visited = set()
        # follow nextPage.href iteratively — recursion would be one frame per page
        # and blow the stack on large result sets (tens of thousands of NADs)
        while get_all:
            next_page = sr.get("nextPage")
            if next_page is None:
                break
            if not isinstance(next_page, dict):
                logger.warning("Malformed ERS nextPage for %s", url)
                return None
            href = next_page.get("href", "")
            if not isinstance(href, str) or "/ers" not in href or href in visited:
                logger.warning("Invalid ERS nextPage href for %s: %r", url, href)
                return None
            visited.add(href)
            page = self._get_json(self.session, f"{self.ers_url}{href.split('/ers', 1)[1]}",
                                  api_name=api_name)
            if not isinstance(page, dict):
                return None
            sr = page.get("SearchResult")
            if not isinstance(sr, dict) or not isinstance(sr.get("resources", []), list):
                logger.warning("Malformed ERS pagination response for %s", href)
                return None
            resources.extend(sr.get("resources", []))
        if get_all and expected_total is not None:
            try:
                expected_total = int(expected_total)
            except (TypeError, ValueError):
                logger.warning("Malformed ERS total for %s: %r", url, expected_total)
                return None
            if len(resources) != expected_total:
                logger.warning("Incomplete ERS pagination for %s: got %d of %d rows",
                               url, len(resources), expected_total)
                return None
        return resources

    def get_ers_total(self, path, params=None, api_name="ers"):
        """SearchResult.total for an ERS search (size=1, no enumeration)."""
        url = f"{self.ers_url}{path}"
        p = dict(params or {})
        p.setdefault("size", 1)
        data = self._get_json(self.session, url, p, api_name=api_name)
        if data is None:
            return None
        return data.get("SearchResult", {}).get("total")

    def get_pan_api(self, path, api_name="pan_api", unwrap=True, params=None):
        """PAN OpenAPI JSON GET. Unwraps the `response` envelope by default; pass
        unwrap=False for endpoints that return a bare body (e.g. license tier-state)."""
        url = f"{self.pan_url}{path}"
        data = self._get_json(self.session, url, params, api_name=api_name)
        if data is None:
            return None
        return data.get("response", data) if (unwrap and isinstance(data, dict)) else data

    def get_mnt_xml(self, path, api_name="mnt_xml"):
        """MnT XML GET. For ActiveList-style responses returns
        {"total": noOfActiveSession, "sessions": [ {tag: text}, ... ]}; for a
        single-record response (Session/MACAddress detail) returns the flattened
        record as the sole session, namespace-stripped, populated fields only."""
        url = f"{self.mnt_xml_url}{path}"
        r = self._request(self.mnt_session, url, api_name=api_name)
        if r is None or not r.content:
            return None
        try:
            root = ET.fromstring(r.content)
        except ET.ParseError as e:
            ise_api_errors_total.labels(api=api_name, error_type="parse", http_code="0").inc()
            logger.error("XML parse error from %s: %s", url, e)
            return None

        active = root.findall(".//activeSession")
        if active:
            total = root.attrib.get("noOfActiveSession", str(len(active)))
            try:
                total = int(total)
            except ValueError:
                total = len(active)
            sessions = [{_strip_ns(c.tag): (c.text or "").strip() for c in item} for item in active]
            return {"total": total, "sessions": sessions}

        auth_status = root.findall(".//authStatusElements")
        if auth_status:
            sessions = [{_strip_ns(c.tag): (c.text or "").strip() for c in item}
                        for item in auth_status]
            return {"total": len(sessions), "sessions": sessions}

        detail = {}
        for c in root:
            if c.text and c.text.strip():
                detail[_strip_ns(c.tag)] = c.text.strip()
        return {"total": 1 if detail else 0, "sessions": [detail] if detail else []}

    def health_check(self):
        health = {"pan": False, "mnt": False}
        if self.session is not None:
            try:
                r = self.session.get(f"https://{self.host}:{self.cfg.ers_port}/ers",
                                     timeout=5, allow_redirects=False)
                health["pan"] = r.status_code < 500
            except Exception as e:
                logger.debug("PAN health check failed: %s", e)
        if self.mnt_session is not None:
            try:
                r = self.mnt_session.get(
                    f"https://{self.mnt_host}/admin", timeout=5, allow_redirects=False)
                health["mnt"] = r.status_code < 500
            except Exception as e:
                logger.debug("MnT health check failed: %s", e)
        return health


class ISEControlPlaneClient(ISERestClient):
    """ERS and PAN OpenAPI transport used by the exporter runtime."""

    def __init__(self, cfg):
        super().__init__(cfg, include_control=True, include_mnt=False)


class MnTDiagnosticsClient(ISERestClient):
    """MnT XML transport used only by explicit operator diagnostics."""

    def __init__(self, cfg):
        super().__init__(cfg, include_control=False, include_mnt=True)


class ISEOperatorClient:
    """Composition used by ise-cli when commands span control and MnT planes."""

    def __init__(self, cfg):
        self.control = ISEControlPlaneClient(cfg)
        self.mnt = MnTDiagnosticsClient(cfg)
        self.host = self.control.host
        self.mnt_host = self.mnt.mnt_host

    def get_ers(self, *args, **kwargs):
        return self.control.get_ers(*args, **kwargs)

    def get_ers_total(self, *args, **kwargs):
        return self.control.get_ers_total(*args, **kwargs)

    def get_pan_api(self, *args, **kwargs):
        return self.control.get_pan_api(*args, **kwargs)

    def get_mnt_xml(self, *args, **kwargs):
        return self.mnt.get_mnt_xml(*args, **kwargs)

    def health_check(self):
        control = self.control.health_check()
        diagnostics = self.mnt.health_check()
        return {"pan": control["pan"], "mnt": diagnostics["mnt"]}
