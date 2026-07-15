"""Transport layer for ERS / PAN OpenAPI / MnT XML. This is the ISECollector
class from the monolith with the FEATURE methods removed — those (get_active_sessions,
get_network_devices, ...) collapse into the collectors, which now call the generic
get_ers / get_ers_total / get_pan_api / get_mnt_xml directly. Pure plumbing, no
metric writes except the api_requests/api_errors counters."""
import logging
import re
import threading
import time
import warnings
import xml.etree.ElementTree as ET

import requests
from requests.auth import HTTPBasicAuth
from requests.adapters import HTTPAdapter
from urllib3.util.retry import Retry
from urllib3.exceptions import InsecureRequestWarning

from ..auth_guard import PersistentAuthGuard
from ..metrics import ise_api_requests_total, ise_api_errors_total

logger = logging.getLogger(__name__)

# ISE ERS pages contain at most 100 resources in the runtime and CLI callers.
# This ceiling still permits inventories twice the supported 100k endpoint scale,
# while bounding a broken server that emits an endless chain of unique next links.
ERS_MAX_PAGES = 2000
ERS_MAX_ROWS = 200000
PAN_MAX_PAGES = 100
HTTP_READ_CHUNK_BYTES = 64 * 1024
MAX_HTTP_RESPONSE_BYTES = 64 * 1024 * 1024
HTTP_ERROR_SNIPPET_BYTES = 200
MAX_XML_ELEMENTS = 2_000_000
MAX_XML_DEPTH = 64
MAX_XML_SESSIONS = 250_000
MAX_XML_FIELDS_PER_SESSION = 128
UNSAFE_XML_DECLARATION = re.compile(br"<!DOCTYPE|<!ENTITY", re.IGNORECASE)
_SENSITIVE_LOG_JSON = re.compile(
    r'(?i)(["\']?(?:password|passwd|passphrase|secret|token|authorization|cookie)'
    r'["\']?\s*:\s*)["\'][^"\']*["\']')
_SENSITIVE_LOG_PAIR = re.compile(
    r'(?i)(\b(?:password|passwd|passphrase|secret|token|authorization|cookie)\s*=)'
    r'[^&\s,;]+')
_SENSITIVE_LOG_XML = re.compile(
    r'(?i)(<(?:password|passwd|passphrase|secret|token|authorization|cookie)\b[^>]*>)'
    r'.*?(</(?:password|passwd|passphrase|secret|token|authorization|cookie)>)')
_SENSITIVE_LOG_BEARER = re.compile(r'(?i)(\bBearer\s+)[A-Za-z0-9._~+/=-]+')


class ResponseTooLarge(RuntimeError):
    """The remote API attempted to return more data than this process retains."""


class XMLResponseTooComplex(RuntimeError):
    """The bounded MnT XML shape exceeded safe structural limits."""


def _redact_log_text(value):
    """Remove common credential forms from bounded remote error text."""
    text = str(value or "")
    text = _SENSITIVE_LOG_JSON.sub(r'\1"<redacted>"', text)
    text = _SENSITIVE_LOG_PAIR.sub(r'\1<redacted>', text)
    text = _SENSITIVE_LOG_XML.sub(r'\1<redacted>\2', text)
    return _SENSITIVE_LOG_BEARER.sub(r'\1<redacted>', text)


class RestAuthGuard(PersistentAuthGuard):
    """Account-wide failed-authentication backoff shared across planes/processes."""

    def __init__(self, cfg):
        super().__init__(
            getattr(cfg, "rest_auth_guard_file", ""),
            (getattr(cfg, "ise_user", ""), getattr(cfg, "ise_host", ""),
             getattr(cfg, "ise_mnt_host", "")),
            "REST authentication",
        )


def _strip_ns(tag):
    return tag.split("}", 1)[-1] if "}" in tag else tag


def _parse_mnt_xml(content):
    """Pull-parse MnT XML while releasing completed nodes immediately."""
    parser = ET.XMLPullParser(events=("start", "end"))
    stack = []
    elements = 0
    raw_total = None
    active_sessions = []
    auth_sessions = []
    detail = {}
    active_record = None
    auth_record = None
    active_fields = 0
    auth_fields = 0

    def process_events():
        nonlocal elements, raw_total, active_record, auth_record
        nonlocal active_fields, auth_fields
        for event, element in parser.read_events():
            name = _strip_ns(element.tag)
            if event == "start":
                elements += 1
                if elements > MAX_XML_ELEMENTS:
                    raise XMLResponseTooComplex(
                        f"MnT XML exceeded {MAX_XML_ELEMENTS} elements")
                if len(stack) + 1 > MAX_XML_DEPTH:
                    raise XMLResponseTooComplex(
                        f"MnT XML exceeded {MAX_XML_DEPTH} levels")
                if not stack:
                    raw_total = next((
                        value for key, value in element.attrib.items()
                        if _strip_ns(key) == "noOfActiveSession"), None)
                if name == "activeSession":
                    if active_record is not None:
                        raise XMLResponseTooComplex("MnT XML nested activeSession records")
                    active_record = {}
                    active_fields = 0
                elif name == "authStatusElements":
                    if auth_record is not None:
                        raise XMLResponseTooComplex(
                            "MnT XML nested authStatusElements records")
                    auth_record = {}
                    auth_fields = 0
                stack.append(element)
                continue

            parent_name = _strip_ns(stack[-2].tag) if len(stack) >= 2 else ""
            text = (element.text or "").strip()
            if parent_name == "activeSession" and active_record is not None:
                active_fields += 1
                if active_fields > MAX_XML_FIELDS_PER_SESSION:
                    raise XMLResponseTooComplex(
                        "MnT activeSession exceeded the field ceiling")
                active_record[name] = text
            elif parent_name == "authStatusElements" and auth_record is not None:
                auth_fields += 1
                if auth_fields > MAX_XML_FIELDS_PER_SESSION:
                    raise XMLResponseTooComplex(
                        "MnT authStatusElements exceeded the field ceiling")
                auth_record[name] = text
            elif len(stack) == 2 and text:
                detail[name] = text

            if name == "activeSession":
                if len(active_sessions) >= MAX_XML_SESSIONS:
                    raise XMLResponseTooComplex(
                        f"MnT XML exceeded {MAX_XML_SESSIONS} active sessions")
                active_sessions.append(active_record or {})
                active_record = None
            elif name == "authStatusElements":
                if len(auth_sessions) >= MAX_XML_SESSIONS:
                    raise XMLResponseTooComplex(
                        f"MnT XML exceeded {MAX_XML_SESSIONS} auth-status records")
                auth_sessions.append(auth_record or {})
                auth_record = None

            stack.pop()
            if stack:
                try:
                    stack[-1].remove(element)
                except ValueError:
                    pass
            element.clear()

    for offset in range(0, len(content), HTTP_READ_CHUNK_BYTES):
        parser.feed(content[offset:offset + HTTP_READ_CHUNK_BYTES])
        process_events()
    parser.close()
    process_events()
    return raw_total, active_sessions, auth_sessions, detail


class ISERestClient:
    """Compatibility client spanning both planes; new runtime code uses the
    plane-specific clients below."""

    def __init__(self, cfg, *, include_control=True, include_mnt=True,
                 auth_guard=None):
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
        self._auth_guard = auth_guard or RestAuthGuard(cfg)
        self._request_lock = threading.RLock()
        self.shutdown_event = None

    def set_shutdown_event(self, shutdown):
        if shutdown is not None and not isinstance(shutdown, threading.Event):
            raise TypeError("shutdown must be a threading.Event")
        self.shutdown_event = shutdown

    def close(self):
        """Close every owned connection pool; safe to call more than once."""
        errors = []
        with self._transport_lock():
            for attribute in ("session", "mnt_session"):
                session = getattr(self, attribute, None)
                # Detach first so a failed close is still idempotent and cannot
                # leave a half-closed pool available to later callers.
                setattr(self, attribute, None)
                if session is None:
                    continue
                try:
                    session.close()
                except Exception as error:
                    errors.append(error)
        if errors:
            raise errors[0]

    def _transport_lock(self):
        # A few compatibility tests construct the client with __new__. Lazily
        # initializing preserves that surface while ensuring a requests.Session
        # and its shared auth-backoff state are never used concurrently.
        lock = getattr(self, "_request_lock", None)
        if lock is None:
            lock = threading.RLock()
            self._request_lock = lock
        return lock

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
        # One scheduled request must equal one wire attempt and one telemetry
        # observation. urllib3 retries happen below _request(), so four physical
        # calls previously appeared as one Prometheus request and could multiply
        # ISE pressure and shutdown latency. Dataset cadence and the persistent
        # authentication guard are the explicit, observable retry boundary.
        retry = Retry(
            total=0,
            connect=0,
            read=0,
            status=0,
            other=0,
            redirect=0,
            allowed_methods=frozenset({"GET"}),
            backoff_factor=0,
            respect_retry_after_header=False,
            raise_on_status=False,
        )
        s.mount("https://", HTTPAdapter(max_retries=retry))
        # Accept-only — Content-Type on a GET is non-standard and has tripped DoD WAFs.
        s.headers.update({"Accept": content_type})
        return s

    def _request(self, session, url, params=None, timeout=30, api_name="unknown"):
        with self._transport_lock():
            return self._request_serialized(
                session, url, params=params, timeout=timeout, api_name=api_name)

    def _request_serialized(self, session, url, params=None, timeout=30, api_name="unknown"):
        shutdown = getattr(self, "shutdown_event", None)
        if shutdown is not None and shutdown.is_set():
            ise_api_requests_total.labels(api=api_name, status="shutdown").inc()
            return None
        now = time.time()
        try:
            auth_blocked = self._auth_guard_state().blocked(now)
        except Exception as error:
            logger.error("REST authentication guard unavailable: %s", error)
            ise_api_requests_total.labels(api=api_name, status="auth_guard_error").inc()
            ise_api_errors_total.labels(
                api=api_name, error_type="auth_guard", http_code="0").inc()
            return None
        if auth_blocked:
            ise_api_requests_total.labels(api=api_name, status="auth_blocked").inc()
            ise_api_errors_total.labels(api=api_name, error_type="auth_blocked",
                                        http_code="401").inc()
            return None
        try:
            # Suppress only urllib3's warning when an operator explicitly selected
            # unverified lab TLS; this keeps CLI JSON/table output machine-readable.
            with warnings.catch_warnings():
                warnings.simplefilter("ignore", InsecureRequestWarning)
                r = session.get(
                    url, params=params, timeout=timeout, stream=True,
                    allow_redirects=False)
            status = int(getattr(r, "status_code", 200))
            if not 200 <= status < 300:
                snippet = self._read_error_snippet(r)
                logger.warning("HTTP %s for %s  body: %s", status, url, snippet)
                if status == 401:
                    self._record_auth_failure()
                ise_api_requests_total.labels(
                    api=api_name, status=f"http_{status}").inc()
                ise_api_errors_total.labels(
                    api=api_name, error_type="http_error", http_code=str(status)).inc()
                return None
            self._buffer_response(r)
            self._auth_guard_state().success()
            ise_api_requests_total.labels(api=api_name, status="success").inc()
            return r
        except ResponseTooLarge as error:
            logger.warning("Oversized response for %s: %s", url, error)
            ise_api_requests_total.labels(
                api=api_name, status="response_too_large").inc()
            ise_api_errors_total.labels(
                api=api_name, error_type="response_too_large", http_code="0").inc()
            return None
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
                snippet = self._read_error_snippet(e.response)
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

    @staticmethod
    def _close_response(response):
        close = getattr(response, "close", None)
        if callable(close):
            close()

    @classmethod
    def _buffer_response(cls, response):
        """Retain a successful body only when it fits the hard process ceiling."""
        raw_length = str(getattr(response, "headers", {}).get(
            "Content-Length", "") or "").strip()
        try:
            content_length = int(raw_length)
        except (TypeError, ValueError):
            content_length = None
        if content_length is not None and content_length > MAX_HTTP_RESPONSE_BYTES:
            cls._close_response(response)
            raise ResponseTooLarge(
                f"Content-Length {content_length} exceeds {MAX_HTTP_RESPONSE_BYTES} bytes")

        iterator = getattr(response, "iter_content", None)
        if not callable(iterator):
            body = bytes(getattr(response, "content", b"") or b"")
            if len(body) > MAX_HTTP_RESPONSE_BYTES:
                cls._close_response(response)
                raise ResponseTooLarge(
                    f"body exceeds {MAX_HTTP_RESPONSE_BYTES} bytes")
        else:
            retained = bytearray()
            try:
                for chunk in iterator(chunk_size=HTTP_READ_CHUNK_BYTES):
                    if not chunk:
                        continue
                    if len(retained) + len(chunk) > MAX_HTTP_RESPONSE_BYTES:
                        raise ResponseTooLarge(
                            f"streamed body exceeds {MAX_HTTP_RESPONSE_BYTES} bytes")
                    retained.extend(chunk)
                body = bytes(retained)
            finally:
                cls._close_response(response)

        # requests.Response uses these fields for content/text/json after a
        # streamed body is consumed. Lightweight test doubles simply accept them.
        response._content = body
        response._content_consumed = True

    @classmethod
    def _read_error_snippet(cls, response):
        """Read at most a log-sized prefix from an error without retaining its body."""
        iterator = getattr(response, "iter_content", None)
        try:
            if callable(iterator):
                body = bytearray()
                for chunk in iterator(chunk_size=HTTP_ERROR_SNIPPET_BYTES):
                    if chunk:
                        body.extend(chunk[:HTTP_ERROR_SNIPPET_BYTES - len(body)])
                    if len(body) >= HTTP_ERROR_SNIPPET_BYTES:
                        break
                raw = bytes(body)
            else:
                content = getattr(response, "content", None)
                if content is None:
                    content = str(getattr(response, "text", "") or "").encode(
                        "utf-8", "replace")
                raw = bytes(content)[:HTTP_ERROR_SNIPPET_BYTES]
        except Exception:
            raw = b""
        finally:
            cls._close_response(response)
        text = raw.decode("utf-8", "replace").replace("\n", " ").replace("\r", " ")
        return _redact_log_text(text)

    def _record_auth_failure(self):
        cfg = getattr(self, "cfg", None)
        threshold = max(1, min(5, int(getattr(
            cfg, "auth_failure_threshold", 3))))
        backoff = max(300, min(86400, int(getattr(
            cfg, "auth_failure_backoff", 900))))
        failures, deadline = self._auth_guard_state().failure(
            threshold, backoff, time.time())
        if deadline:
            logger.error("ISE API authentication failed %d times; suppressing further API "
                         "requests for %ds to avoid account lockout", failures, backoff)

    def _auth_guard_state(self):
        guard = getattr(self, "_auth_guard", None)
        if guard is None:
            guard = RestAuthGuard(getattr(self, "cfg", None))
            self._auth_guard = guard
        return guard

    def _get_json(self, session, url, params=None, api_name="unknown"):
        """GET + JSON-decode, returning the parsed body or None on request/parse failure.
        Collapses the request→None-guard→json()→ValueError-guard boilerplate the JSON
        accessors below all share."""
        r = self._request(session, url, params, api_name=api_name)
        if r is None:
            return None
        try:
            return r.json()
        except (RecursionError, ValueError) as error:
            status = str(getattr(r, "status_code", 0) or 0)
            logger.warning("Invalid JSON from %s: %s", url, error)
            ise_api_errors_total.labels(
                api=api_name, error_type="parse", http_code=status).inc()
            return None

    @staticmethod
    def _ers_protocol_error(api_name, message, *args):
        logger.warning(message, *args)
        ise_api_errors_total.labels(
            api=api_name, error_type="protocol", http_code="200").inc()

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
        if not isinstance(data, dict):
            self._ers_protocol_error(
                api_name, "Malformed ERS response envelope for %s", url)
            return None
        if "SearchResult" not in data:
            if get_all:
                self._ers_protocol_error(
                    api_name, "Missing ERS SearchResult for complete enumeration %s", url)
                return None
            return data

        sr = data["SearchResult"]
        if not isinstance(sr, dict):
            self._ers_protocol_error(
                api_name, "Malformed ERS SearchResult for %s", url)
            return None
        resources = sr.get("resources", [])
        if not isinstance(resources, list):
            self._ers_protocol_error(api_name, "Malformed ERS resources for %s", url)
            return None
        resources = list(resources)
        if len(resources) > ERS_MAX_ROWS:
            self._ers_protocol_error(
                api_name, "ERS response exceeded %d rows for %s", ERS_MAX_ROWS, url)
            return None
        expected_total = sr.get("total")
        if get_all:
            try:
                expected_total = int(expected_total)
            except (TypeError, ValueError):
                self._ers_protocol_error(
                    api_name, "Malformed ERS total for %s: %r", url, expected_total)
                return None
            if not 0 <= expected_total <= ERS_MAX_ROWS:
                self._ers_protocol_error(
                    api_name, "ERS total outside the 0-%d row bound for %s: %r",
                    ERS_MAX_ROWS, url, expected_total)
                return None
        visited = set()
        pages = 1
        resource_path = path.split("?", 1)[0]
        # follow nextPage.href iteratively — recursion would be one frame per page
        # and blow the stack on large result sets (tens of thousands of NADs)
        while get_all:
            next_page = sr.get("nextPage")
            if next_page is None:
                break
            if pages >= ERS_MAX_PAGES:
                self._ers_protocol_error(
                    api_name, "ERS pagination exceeded %d pages for %s",
                    ERS_MAX_PAGES, url)
                return None
            if not isinstance(next_page, dict):
                self._ers_protocol_error(
                    api_name, "Malformed ERS nextPage for %s", url)
                return None
            href = next_page.get("href", "")
            if not isinstance(href, str) or "/ers" not in href or href in visited:
                self._ers_protocol_error(
                    api_name, "Invalid ERS nextPage href for %s: %r", url, href)
                return None
            visited.add(href)
            next_path = href.split("/ers", 1)[1]
            if next_path.split("?", 1)[0] != resource_path:
                self._ers_protocol_error(
                    api_name, "ERS nextPage changed resource path for %s: %r", url, href)
                return None
            page = self._get_json(self.session, f"{self.ers_url}{next_path}",
                                  api_name=api_name)
            if page is None:
                return None
            if not isinstance(page, dict):
                self._ers_protocol_error(
                    api_name, "Malformed ERS pagination envelope for %s", href)
                return None
            sr = page.get("SearchResult")
            if not isinstance(sr, dict) or not isinstance(sr.get("resources", []), list):
                self._ers_protocol_error(
                    api_name, "Malformed ERS pagination response for %s", href)
                return None
            page_resources = sr.get("resources", [])
            if len(resources) + len(page_resources) > ERS_MAX_ROWS:
                self._ers_protocol_error(
                    api_name, "ERS pagination exceeded %d rows for %s",
                    ERS_MAX_ROWS, url)
                return None
            resources.extend(page_resources)
            pages += 1
        if get_all:
            if len(resources) != expected_total:
                self._ers_protocol_error(
                    api_name, "Incomplete ERS pagination for %s: got %d of %d rows",
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
        if not isinstance(data, dict) or not isinstance(data.get("SearchResult"), dict):
            self._ers_protocol_error(
                api_name, "Malformed ERS total response for %s", url)
            return None
        total = data["SearchResult"].get("total")
        try:
            total = int(total)
        except (TypeError, ValueError):
            self._ers_protocol_error(
                api_name, "Malformed ERS total for %s: %r", url, total)
            return None
        if not 0 <= total <= ERS_MAX_ROWS:
            self._ers_protocol_error(
                api_name, "ERS total outside the 0-%d row bound for %s: %d",
                ERS_MAX_ROWS, url, total)
            return None
        return total

    def get_pan_api(self, path, api_name="pan_api", unwrap=True, params=None):
        """PAN OpenAPI JSON GET. Unwraps the `response` envelope by default; pass
        unwrap=False for endpoints that return a bare body (e.g. license tier-state)."""
        url = f"{self.pan_url}{path}"
        data = self._get_json(self.session, url, params, api_name=api_name)
        if data is None:
            return None
        return data.get("response", data) if (unwrap and isinstance(data, dict)) else data

    def get_pan_api_all(self, path, api_name="pan_api", params=None, *,
                        max_pages=PAN_MAX_PAGES, max_rows=10000):
        """Enumerate a schema-confirmed paginated PAN OpenAPI list fail-closed.

        ISE's OpenAPI pagination has no total-count field. Completeness therefore
        means following every valid ``nextPage.href`` until the server omits it.
        The href's host is deliberately ignored and each page is reconstructed
        under the configured PAN origin to prevent cross-host credential sends.
        """
        if not 1 <= max_pages <= PAN_MAX_PAGES or not 1 <= max_rows <= 100000:
            raise ValueError("invalid PAN pagination bound")
        url = f"{self.pan_url}{path}"
        data = self._get_json(self.session, url, params, api_name=api_name)
        if data is None:
            # _get_json already recorded the actual transport, HTTP, or parse
            # failure. Do not manufacture a second protocol error for the same
            # request; protocol errors are reserved for successful malformed JSON.
            return None
        rows = []
        visited = set()
        pages = 0
        resource_path = path.lstrip("/").split("?", 1)[0]
        while True:
            pages += 1
            if (not isinstance(data, dict) or "response" not in data
                    or not isinstance(data["response"], list)):
                self._ers_protocol_error(
                    api_name, "Malformed PAN pagination envelope for %s", url)
                return None
            page_rows = data["response"]
            if len(rows) + len(page_rows) > max_rows:
                self._ers_protocol_error(
                    api_name, "PAN pagination exceeded %d rows for %s", max_rows, url)
                return None
            rows.extend(page_rows)
            next_page = data.get("nextPage")
            if next_page is None:
                return rows
            if pages >= max_pages:
                self._ers_protocol_error(
                    api_name, "PAN pagination exceeded %d pages for %s", max_pages, url)
                return None
            if not isinstance(next_page, dict):
                self._ers_protocol_error(
                    api_name, "Malformed PAN nextPage for %s", url)
                return None
            href = next_page.get("href", "")
            if (not isinstance(href, str) or "/api/v1/" not in href
                    or href in visited):
                self._ers_protocol_error(
                    api_name, "Invalid PAN nextPage href for %s: %r", url, href)
                return None
            visited.add(href)
            next_path = href.split("/api/v1/", 1)[1]
            if next_path.split("?", 1)[0] != resource_path:
                self._ers_protocol_error(
                    api_name, "PAN nextPage changed resource path for %s: %r", url, href)
                return None
            url = f"{self.pan_url}/{next_path}"
            data = self._get_json(self.session, url, api_name=api_name)
            if data is None:
                return None

    def get_mnt_xml(self, path, api_name="mnt_xml"):
        """MnT XML GET. For ActiveList-style responses returns
        {"total": noOfActiveSession, "sessions": [ {tag: text}, ... ]}; for a
        single-record response (Session/MACAddress detail) returns the flattened
        record as the sole session, namespace-stripped, populated fields only."""
        url = f"{self.mnt_xml_url}{path}"
        r = self._request(self.mnt_session, url, api_name=api_name)
        if r is None or not r.content:
            return None
        if UNSAFE_XML_DECLARATION.search(r.content):
            ise_api_errors_total.labels(
                api=api_name, error_type="unsafe_xml", http_code="200").inc()
            logger.error("Rejected XML with a DTD or entity declaration from %s", url)
            return None
        try:
            raw_total, active, auth_status, detail = _parse_mnt_xml(r.content)
        except ET.ParseError as e:
            ise_api_errors_total.labels(api=api_name, error_type="parse", http_code="0").inc()
            logger.error("XML parse error from %s: %s", url, e)
            return None
        except XMLResponseTooComplex as error:
            ise_api_errors_total.labels(
                api=api_name, error_type="response_too_complex", http_code="200").inc()
            logger.error("Rejected structurally complex XML from %s: %s", url, error)
            return None

        if active:
            try:
                total = len(active) if raw_total is None else int(raw_total)
            except (TypeError, ValueError):
                total = -1
            if total != len(active):
                ise_api_errors_total.labels(
                    api=api_name, error_type="protocol", http_code="200").inc()
                logger.error(
                    "MnT ActiveList count mismatch from %s: declared %r, parsed %d",
                    url, raw_total, len(active))
                return None
            return {"total": total, "sessions": active}

        if auth_status:
            return {"total": len(auth_status), "sessions": auth_status}

        return {"total": 1 if detail else 0, "sessions": [detail] if detail else []}

    def health_check(self):
        def probe(session, url, *, params=None):
            result = {"reachable": False, "authenticated": False, "http_status": 0}
            response = None
            try:
                if self._auth_guard_state().blocked(time.time()):
                    result["http_status"] = 401
                    return result
                with self._transport_lock():
                    with warnings.catch_warnings():
                        warnings.simplefilter("ignore", InsecureRequestWarning)
                        response = session.get(
                            url, params=params, timeout=5, stream=True,
                            allow_redirects=False)
                result["reachable"] = True
                result["http_status"] = response.status_code
                # Redirects are deliberately not followed. A 3xx commonly points
                # at an interactive login page and does not prove API credentials.
                result["authenticated"] = 200 <= response.status_code < 300
                if response.status_code == 401:
                    self._record_auth_failure()
                elif result["authenticated"]:
                    self._auth_guard_state().success()
            except Exception as error:
                logger.debug("health probe failed for %s: %s", url, error)
            finally:
                if response is not None:
                    self._close_response(response)
            return result

        health = {
            "pan": {"reachable": False, "authenticated": False, "http_status": 0},
            "mnt": {"reachable": False, "authenticated": False, "http_status": 0},
        }
        if self.session is not None:
            # A real one-row ERS resource request verifies both routing and the
            # supplied credentials without enumerating inventory.
            health["pan"] = probe(
                self.session,
                f"https://{self.host}:{self.cfg.ers_port}/ers/config/networkdevice",
                params={"size": 1, "page": 1},
            )
        if self.mnt_session is not None:
            # ActiveCount is authenticated but does not return ActiveList rows.
            health["mnt"] = probe(
                self.mnt_session,
                f"https://{self.mnt_host}/admin/API/mnt/Session/ActiveCount",
            )
        return health


class ISEControlPlaneClient(ISERestClient):
    """ERS and PAN OpenAPI transport used by the exporter runtime."""

    def __init__(self, cfg, *, auth_guard=None):
        super().__init__(cfg, include_control=True, include_mnt=False,
                         auth_guard=auth_guard)


class MnTActiveSessionClient(ISERestClient):
    """MnT XML transport scoped to active-session detail and diagnostics."""

    def __init__(self, cfg, *, auth_guard=None):
        super().__init__(cfg, include_control=False, include_mnt=True,
                         auth_guard=auth_guard)


class MnTDiagnosticsClient(MnTActiveSessionClient):
    """Compatibility name used by explicit operator diagnostics."""


class ISEOperatorClient:
    """Composition used by ise-cli when commands span control and MnT planes."""

    def __init__(self, cfg):
        auth_guard = RestAuthGuard(cfg)
        self.control = ISEControlPlaneClient(cfg, auth_guard=auth_guard)
        self.mnt = MnTDiagnosticsClient(cfg, auth_guard=auth_guard)
        self.host = self.control.host
        self.mnt_host = self.mnt.mnt_host

    def get_ers(self, *args, **kwargs):
        return self.control.get_ers(*args, **kwargs)

    def get_ers_total(self, *args, **kwargs):
        return self.control.get_ers_total(*args, **kwargs)

    def get_pan_api(self, *args, **kwargs):
        return self.control.get_pan_api(*args, **kwargs)

    def get_pan_api_all(self, *args, **kwargs):
        return self.control.get_pan_api_all(*args, **kwargs)

    def get_mnt_xml(self, *args, **kwargs):
        return self.mnt.get_mnt_xml(*args, **kwargs)

    def health_check(self):
        control = self.control.health_check()
        diagnostics = self.mnt.health_check()
        return {"pan": control["pan"], "mnt": diagnostics["mnt"]}

    def close(self):
        """Release both plane-specific pools even if one close fails."""
        errors = []
        for client in (self.control, self.mnt):
            try:
                client.close()
            except Exception as error:
                errors.append(error)
        if errors:
            raise errors[0]
