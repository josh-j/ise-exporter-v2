"""Transport layer for ERS / PAN OpenAPI / MnT XML. This is the ISECollector
class from the monolith with the FEATURE methods removed — those (get_active_sessions,
get_network_devices, ...) collapse into the collectors, which now call the generic
get_ers / get_ers_total / get_pan_api / get_mnt_xml directly. Pure plumbing, no
metric writes except the api_requests/api_errors counters."""
import logging
import xml.etree.ElementTree as ET

import requests
from requests.auth import HTTPBasicAuth
from requests.adapters import HTTPAdapter
from urllib3.util.retry import Retry

from ..metrics import ise_api_requests_total, ise_api_errors_total

logger = logging.getLogger(__name__)


def _strip_ns(tag):
    return tag.split("}", 1)[-1] if "}" in tag else tag


class ISERestClient:
    def __init__(self, cfg):
        self.cfg = cfg
        self.host = cfg.ise_host
        self.mnt_host = cfg.ise_mnt_host
        self.ers_url = f"https://{cfg.ise_host}:{cfg.ers_port}/ers"
        self.pan_url = f"https://{cfg.ise_host}/api/v1"
        self.mnt_xml_url = f"https://{cfg.ise_mnt_host}/admin/API/mnt"
        self.auth = HTTPBasicAuth(cfg.ise_user, cfg.ise_pass)
        self.session = self._mk("application/json")
        self.mnt_session = self._mk("application/xml")

    def _mk(self, content_type):
        s = requests.Session()
        s.auth = self.auth
        s.verify = False
        # ISE presents a self-signed cert; verify=False is intentional. trust_env=False
        # stops requests from silently overriding that with an ambient REQUESTS_CA_BUNDLE
        # / CURL_CA_BUNDLE (e.g. under Nix), which otherwise forces verification and fails.
        s.trust_env = False
        retry = Retry(total=3, backoff_factor=1, status_forcelist=[429, 500, 502, 503, 504])
        s.mount("https://", HTTPAdapter(max_retries=retry))
        # Accept-only — Content-Type on a GET is non-standard and has tripped DoD WAFs.
        s.headers.update({"Accept": content_type})
        return s

    def _request(self, session, url, params=None, timeout=30, api_name="unknown"):
        try:
            r = session.get(url, params=params, timeout=timeout)
            r.raise_for_status()
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
        nextPage.href when get_all), or the raw dict when there's no SearchResult."""
        url = f"{self.ers_url}{path}"
        data = self._get_json(self.session, url, params, api_name=api_name)
        if data is None:
            return None
        if "SearchResult" not in data:
            return data

        sr = data["SearchResult"]
        resources = sr.get("resources", [])
        # follow nextPage.href iteratively — recursion would be one frame per page
        # and blow the stack on large result sets (tens of thousands of NADs)
        while get_all:
            href = (sr.get("nextPage") or {}).get("href", "")
            if "/ers" not in href:
                break
            page = self._get_json(self.session, f"{self.ers_url}{href.split('/ers', 1)[1]}",
                                  api_name=api_name)
            if page is None:
                break
            sr = page.get("SearchResult", {})
            resources.extend(sr.get("resources", []))
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

    def get_pan_api(self, path, api_name="pan_api", unwrap=True):
        """PAN OpenAPI JSON GET. Unwraps the `response` envelope by default; pass
        unwrap=False for endpoints that return a bare body (e.g. license tier-state)."""
        url = f"{self.pan_url}{path}"
        data = self._get_json(self.session, url, api_name=api_name)
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

        detail = {}
        for c in root:
            if c.text and c.text.strip():
                detail[_strip_ns(c.tag)] = c.text.strip()
        return {"total": 1 if detail else 0, "sessions": [detail] if detail else []}

    def health_check(self):
        health = {"pan": False, "mnt": False}
        try:
            r = self.session.get(f"https://{self.host}:{self.cfg.ers_port}/ers",
                                 timeout=5, allow_redirects=False)
            health["pan"] = r.status_code < 500
        except Exception as e:
            logger.debug("PAN health check failed: %s", e)
        try:
            r = self.mnt_session.get(f"https://{self.mnt_host}/admin", timeout=5, allow_redirects=False)
            health["mnt"] = r.status_code < 500
        except Exception as e:
            logger.debug("MnT health check failed: %s", e)
        return health
