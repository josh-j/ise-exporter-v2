"""ISERestClient.get_ers must follow nextPage.href across all pages iteratively
(no per-page recursion that would blow the stack on large result sets)."""
import threading
import types
import warnings

import requests
from urllib3.exceptions import InsecureRequestWarning

import ise_exporter.clients.rest as rest_module
from ise_exporter.clients.rest import (
    ISEControlPlaneClient,
    ISEOperatorClient,
    ISERestClient,
    MnTActiveSessionClient,
    MnTDiagnosticsClient,
    RestAuthGuard,
)
from ise_exporter.metrics import ise_api_errors_total


def test_sessions_verify_by_default_and_use_plane_specific_ca_bundles():
    cfg = types.SimpleNamespace(ise_host="h", ise_mnt_host="m", ers_port=9060,
                                ise_user="u", ise_pass="p",
                                rest_ssl_verify=True, rest_ca_bundle="/ca/rest.pem",
                                mnt_ssl_verify=True, mnt_ca_bundle="/ca/mnt.pem")
    c = ISERestClient(cfg)
    assert c.session.verify == "/ca/rest.pem"
    assert c.mnt_session.verify == "/ca/mnt.pem"
    assert c.session.trust_env is False
    assert c.mnt_session.trust_env is False


def test_tls_verification_can_be_explicitly_disabled_for_an_isolated_lab():
    cfg = types.SimpleNamespace(
        ise_host="h", ise_mnt_host="m", ers_port=9060, ise_user="u", ise_pass="p",
        rest_ssl_verify=False, mnt_ssl_verify=False,
    )
    client = ISERestClient(cfg)
    assert client.session.verify is False
    assert client.mnt_session.verify is False


def test_runtime_and_diagnostics_clients_do_not_construct_the_other_plane():
    cfg = types.SimpleNamespace(
        ise_host="h", ise_mnt_host="m", ers_port=9060, ise_user="u", ise_pass="p")
    control = ISEControlPlaneClient(cfg)
    diagnostics = MnTDiagnosticsClient(cfg)
    active = MnTActiveSessionClient(cfg)
    operator = ISEOperatorClient(cfg)
    assert control.session is not None and control.mnt_session is None
    assert diagnostics.session is None and diagnostics.mnt_session is not None
    assert active.session is None and active.mnt_session is not None
    assert operator.control.mnt_session is None
    assert operator.mnt.session is None
    assert operator.control._auth_guard is operator.mnt._auth_guard


def test_operator_client_delegates_bounded_pan_pagination():
    operator = ISEOperatorClient.__new__(ISEOperatorClient)

    class Control:
        def get_pan_api_all(self, *args, **kwargs):
            return args, kwargs

    operator.control = Control()

    assert operator.get_pan_api_all(
        "/certs/trusted-certificate", max_pages=10, max_rows=1000) == (
            ("/certs/trusted-certificate",),
            {"max_pages": 10, "max_rows": 1000},
        )


class _Resp:
    def __init__(self, data):
        self._data = data
        self.content = data if isinstance(data, bytes) else b""

    def json(self):
        return self._data


def test_api_families_route_to_their_configured_hosts():
    cfg = types.SimpleNamespace(
        ise_host="pan.example.mil", ise_mnt_host="mnt.example.mil", ers_port=9060,
        ise_user="u", ise_pass="p",
    )
    client = ISERestClient(cfg)
    json_calls = []

    def fake_json(session, url, params=None, api_name="x"):
        json_calls.append((session, url))
        return {"response": {"ok": True}} if "/api/v1/" in url else {"ERSEndPoint": {}}

    client._get_json = fake_json
    client.get_ers("/config/endpoint/id-1")
    client.get_pan_api("/deployment/node")

    mnt_calls = []

    def fake_request(session, url, params=None, timeout=30, api_name="x"):
        mnt_calls.append((session, url))
        return _Resp(b"<session><other_attr_string>PostureStatus=Compliant</other_attr_string></session>")

    client._request = fake_request
    result = client.get_mnt_xml("/Session/MACAddress/AA:BB:CC:DD:EE:FF")

    assert json_calls == [
        (client.session, "https://pan.example.mil:9060/ers/config/endpoint/id-1"),
        (client.session, "https://pan.example.mil/api/v1/deployment/node"),
    ]
    assert mnt_calls == [(
        client.mnt_session,
        "https://mnt.example.mil/admin/API/mnt/Session/MACAddress/AA:BB:CC:DD:EE:FF",
    )]
    assert result["sessions"][0]["other_attr_string"] == "PostureStatus=Compliant"


def test_mnt_active_count_preserves_the_count_field_for_safe_preflight():
    client = ISERestClient.__new__(ISERestClient)
    client.mnt_xml_url = "https://mnt.example.mil/admin/API/mnt"
    client.mnt_session = object()
    client._request = lambda *_args, **_kwargs: _Resp(
        b"<sessionCount><count>12345</count></sessionCount>")

    result = client.get_mnt_xml("/Session/ActiveCount")

    assert result == {"total": 1, "sessions": [{"count": "12345"}]}


def test_mnt_active_list_accepts_namespace_qualified_ise_xml():
    client = ISERestClient.__new__(ISERestClient)
    client.mnt_xml_url = "https://mnt.example.mil/admin/API/mnt"
    client.mnt_session = object()
    client._request = lambda *_args, **_kwargs: _Resp(b"""
        <activeList xmlns="urn:cisco:ise:mnt" noOfActiveSession="2">
          <activeSession><user_name>alice</user_name><server>psn-1</server></activeSession>
          <activeSession><user_name>bob</user_name><server>psn-2</server></activeSession>
        </activeList>
    """)

    assert client.get_mnt_xml("/Session/ActiveList") == {
        "total": 2,
        "sessions": [
            {"user_name": "alice", "server": "psn-1"},
            {"user_name": "bob", "server": "psn-2"},
        ],
    }


def test_mnt_active_list_rejects_declared_count_mismatch():
    client = ISERestClient.__new__(ISERestClient)
    client.mnt_xml_url = "https://mnt.example.mil/admin/API/mnt"
    client.mnt_session = object()
    client._request = lambda *_args, **_kwargs: _Resp(b"""
        <activeList noOfActiveSession="2">
          <activeSession><user_name>only-row</user_name></activeSession>
        </activeList>
    """)
    counter = ise_api_errors_total.labels(
        api="mnt_count_contract", error_type="protocol", http_code="200")
    before = counter._value.get()

    assert client.get_mnt_xml(
        "/Session/ActiveList", api_name="mnt_count_contract") is None
    assert counter._value.get() == before + 1


def test_mnt_auth_status_accepts_namespace_qualified_ise_xml():
    client = ISERestClient.__new__(ISERestClient)
    client.mnt_xml_url = "https://mnt.example.mil/admin/API/mnt"
    client.mnt_session = object()
    client._request = lambda *_args, **_kwargs: _Resp(b"""
        <authStatus xmlns="urn:cisco:ise:mnt">
          <authStatusElements><user_name>alice</user_name><status>Passed</status></authStatusElements>
        </authStatus>
    """)

    assert client.get_mnt_xml("/AuthStatus/MACAddress/AA:BB:CC:DD:EE:FF/60/10") == {
        "total": 1,
        "sessions": [{"user_name": "alice", "status": "Passed"}],
    }


def test_openapi_get_passes_query_parameters():
    client = ISERestClient.__new__(ISERestClient)
    client.pan_url = "https://ise.example/api/v1"
    client.session = object()
    seen = []

    def fake_json(session, url, params=None, api_name="x"):
        seen.append((session, url, params, api_name))
        return {"response": []}

    client._get_json = fake_json
    result = client.get_pan_api(
        "/endpoint", params={"filter": "ipAddress.EQ.192.0.2.25"},
        api_name="endpoint_lookup")

    assert result == []
    assert seen == [(
        client.session, "https://ise.example/api/v1/endpoint",
        {"filter": "ipAddress.EQ.192.0.2.25"}, "endpoint_lookup")]


def test_get_ers_paginates_iteratively():
    c = ISERestClient.__new__(ISERestClient)
    c.ers_url = "https://h:9060/ers"
    c.session = None
    base = "https://h:9060/ers/config/networkdevice"
    pages = {
        base: {"SearchResult": {"total": 3, "resources": [{"id": "1"}],
                                "nextPage": {"href": base + "?page=2"}}},
        base + "?page=2": {"SearchResult": {"resources": [{"id": "2"}],
                                            "nextPage": {"href": base + "?page=3"}}},
        base + "?page=3": {"SearchResult": {"resources": [{"id": "3"}]}},
    }
    seen = []

    def fake_request(session, url, params=None, timeout=30, api_name="x"):
        seen.append(url)
        return _Resp(pages[url])

    c._request = fake_request
    res = c.get_ers("/config/networkdevice", {"size": 1}, get_all=True)
    assert [r["id"] for r in res] == ["1", "2", "3"]
    assert len(seen) == 3  # one request per page, no recursion


def test_get_ers_single_page_when_not_get_all():
    c = ISERestClient.__new__(ISERestClient)
    c.ers_url = "https://h:9060/ers"
    c.session = None
    c._request = lambda *a, **k: _Resp(
        {"SearchResult": {"resources": [{"id": "1"}], "nextPage": {"href": "x/ers/more"}}})
    res = c.get_ers("/config/networkdevice")
    assert [r["id"] for r in res] == ["1"]


def test_get_pan_api_all_follows_pages_under_configured_origin():
    client = ISERestClient.__new__(ISERestClient)
    client.pan_url = "https://ise.example/api/v1"
    client.session = None
    first = f"{client.pan_url}/certs/trusted-certificate"
    second = f"{client.pan_url}/certs/trusted-certificate?page=2"
    pages = {
        first: {
            "response": [{"id": "1"}],
            # A server-supplied origin must never receive the authenticated request.
            "nextPage": {"href": "https://attacker.invalid/api/v1/"
                         "certs/trusted-certificate?page=2"},
        },
        second: {"response": [{"id": "2"}]},
    }
    seen = []

    def fake_json(_session, url, params=None, api_name="x"):
        seen.append((url, params))
        return pages[url]

    client._get_json = fake_json

    assert client.get_pan_api_all(
        "/certs/trusted-certificate", params={"size": 100}) == [
            {"id": "1"}, {"id": "2"}]
    assert seen == [(first, {"size": 100}), (second, None)]


def test_get_pan_api_all_fails_closed_on_later_page_failure():
    client = ISERestClient.__new__(ISERestClient)
    client.pan_url = "https://ise.example/api/v1"
    client.session = None
    calls = 0

    def fake_json(*_args, **_kwargs):
        nonlocal calls
        calls += 1
        if calls == 1:
            return {"response": [{"id": "partial"}], "nextPage": {
                "href": "https://ise.example/api/v1/certs/trusted-certificate?page=2",
            }}
        return None

    client._get_json = fake_json

    assert client.get_pan_api_all("/certs/trusted-certificate") is None
    assert calls == 2


def test_get_pan_api_all_initial_request_failure_is_not_double_counted_as_protocol():
    client = ISERestClient.__new__(ISERestClient)
    client.pan_url = "https://ise.example/api/v1"
    client.session = None
    client._get_json = lambda *_args, **_kwargs: None
    protocol = ise_api_errors_total.labels(
        api="pan_initial_failure", error_type="protocol", http_code="200")
    before = protocol._value.get()

    assert client.get_pan_api_all(
        "/certs/trusted-certificate", api_name="pan_initial_failure") is None
    assert protocol._value.get() == before


def test_get_pan_api_all_enforces_row_and_page_bounds():
    client = ISERestClient.__new__(ISERestClient)
    client.pan_url = "https://ise.example/api/v1"
    client.session = None
    calls = 0

    def fake_json(*_args, **_kwargs):
        nonlocal calls
        calls += 1
        return {
            "response": [{"id": str(calls)}],
            "nextPage": {"href": f"https://ise.example/api/v1/certs/"
                         f"trusted-certificate?page={calls + 1}"},
        }

    client._get_json = fake_json

    assert client.get_pan_api_all(
        "/certs/trusted-certificate", max_pages=2, max_rows=10) is None
    assert calls == 2

    calls = 0
    assert client.get_pan_api_all(
        "/certs/trusted-certificate", max_pages=10, max_rows=1) is None
    assert calls == 2


def test_get_pan_api_all_rejects_missing_response_and_resource_path_change():
    client = ISERestClient.__new__(ISERestClient)
    client.pan_url = "https://ise.example/api/v1"
    client.session = None
    client._get_json = lambda *_args, **_kwargs: {}

    assert client.get_pan_api_all("/certs/trusted-certificate") is None

    client._get_json = lambda *_args, **_kwargs: {
        "response": [{"id": "partial"}],
        "nextPage": {"href": "https://ise.example/api/v1/deployment/node?page=2"},
    }

    assert client.get_pan_api_all("/certs/trusted-certificate") is None

def test_get_ers_discards_all_rows_when_a_later_page_fails():
    c = ISERestClient.__new__(ISERestClient)
    c.ers_url = "https://h:9060/ers"
    c.session = None
    first = "https://h:9060/ers/config/internaluser"
    second = first + "?page=2"

    def fake_json(session, url, params=None, api_name="x"):
        if url == first:
            return {"SearchResult": {
                "resources": [{"id": "partial"}],
                "nextPage": {"href": second},
            }}
        return None

    c._get_json = fake_json

    assert c.get_ers("/config/internaluser", get_all=True) is None


def test_get_ers_preserves_valid_empty_search_result():
    c = ISERestClient.__new__(ISERestClient)
    c.ers_url = "https://h:9060/ers"
    c.session = None
    c._get_json = lambda *args, **kwargs: {
        "SearchResult": {"total": 0, "resources": []}}

    assert c.get_ers("/config/internaluser", get_all=True) == []


def test_get_ers_complete_enumeration_rejects_missing_search_result():
    c = ISERestClient.__new__(ISERestClient)
    c.ers_url = "https://h:9060/ers"
    c.session = None
    c._get_json = lambda *args, **kwargs: {"InternalUser": {"id": "unexpected"}}

    assert c.get_ers(
        "/config/internaluser", get_all=True,
        api_name="ers_missing_search_result") is None
    # A non-enumerating detail request still legitimately returns a raw object.
    assert c.get_ers("/config/internaluser/id") == {
        "InternalUser": {"id": "unexpected"}}


def test_get_ers_rejects_missing_pages_when_total_is_larger():
    c = ISERestClient.__new__(ISERestClient)
    c.ers_url = "https://h:9060/ers"
    c.session = None
    c._get_json = lambda *args, **kwargs: {"SearchResult": {
        "total": 2,
        "resources": [{"id": "partial"}],
    }}

    assert c.get_ers("/config/internaluser", get_all=True) is None


def test_get_ers_bounds_unique_next_page_chain_and_reports_protocol_error(monkeypatch):
    monkeypatch.setattr(rest_module, "ERS_MAX_PAGES", 2)
    c = ISERestClient.__new__(ISERestClient)
    c.ers_url = "https://h:9060/ers"
    c.session = None
    calls = 0

    def fake_json(*_args, **_kwargs):
        nonlocal calls
        calls += 1
        return {"SearchResult": {
            "total": 100,
            "resources": [{"id": str(calls)}],
            "nextPage": {"href": f"https://h:9060/ers/config/endpoint?page={calls + 1}"},
        }}

    c._get_json = fake_json
    counter = ise_api_errors_total.labels(
        api="ers_endpoint", error_type="protocol", http_code="200")
    before = counter._value.get()

    assert c.get_ers(
        "/config/endpoint", get_all=True, api_name="ers_endpoint") is None
    assert calls == 2
    assert counter._value.get() == before + 1


def test_get_ers_all_requires_bounded_total_and_same_resource_path(monkeypatch):
    client = ISERestClient.__new__(ISERestClient)
    client.ers_url = "https://ise.example:9060/ers"
    client.session = None
    client._get_json = lambda *_args, **_kwargs: {
        "SearchResult": {"resources": []}}

    assert client.get_ers("/config/endpoint", get_all=True) is None

    monkeypatch.setattr(rest_module, "ERS_MAX_ROWS", 2)
    client._get_json = lambda *_args, **_kwargs: {
        "SearchResult": {"total": 3, "resources": []}}
    assert client.get_ers("/config/endpoint", get_all=True) is None

    client._get_json = lambda *_args, **_kwargs: {"SearchResult": {
        "total": 2,
        "resources": [{"id": "one"}],
        "nextPage": {
            "href": "https://ise.example:9060/ers/config/internaluser?page=2",
        },
    }}
    assert client.get_ers("/config/endpoint", get_all=True) is None


def test_get_ers_total_rejects_malformed_envelope_without_raising():
    c = ISERestClient.__new__(ISERestClient)
    c.ers_url = "https://h:9060/ers"
    c.session = None
    c._get_json = lambda *_args, **_kwargs: []
    counter = ise_api_errors_total.labels(
        api="ers_total", error_type="protocol", http_code="200")
    before = counter._value.get()

    assert c.get_ers_total("/config/endpoint", api_name="ers_total") is None
    assert counter._value.get() == before + 1


def test_get_ers_total_returns_a_nonnegative_integer():
    c = ISERestClient.__new__(ISERestClient)
    c.ers_url = "https://h:9060/ers"
    c.session = None
    c._get_json = lambda *_args, **_kwargs: {"SearchResult": {"total": "100000"}}

    assert c.get_ers_total("/config/endpoint") == 100000


def test_401s_trip_auth_backoff_before_more_requests():
    cfg = types.SimpleNamespace(auth_failure_threshold=2, auth_failure_backoff=60)
    c = ISERestClient.__new__(ISERestClient)
    c.cfg = cfg
    c._auth_failures = 0
    c._auth_block_until = 0.0

    class Resp:
        status_code = 401
        text = ""

        def raise_for_status(self):
            raise requests.exceptions.HTTPError(response=self)

    class Session:
        calls = 0

        def get(self, *a, **k):
            self.calls += 1
            return Resp()

    session = Session()
    assert c._request(session, "https://ise/ers", api_name="x") is None
    assert c._request(session, "https://ise/ers", api_name="x") is None
    assert c._request(session, "https://ise/ers", api_name="x") is None

    assert session.calls == 2


def test_programmatic_config_cannot_disable_rest_auth_backoff(monkeypatch):
    captured = {}

    class Guard:
        def failure(self, threshold, backoff, now):
            captured.update(threshold=threshold, backoff=backoff, now=now)
            return threshold, now + backoff

    client = ISERestClient.__new__(ISERestClient)
    client.cfg = types.SimpleNamespace(
        auth_failure_threshold=999, auth_failure_backoff=0)
    client._auth_guard = Guard()
    monkeypatch.setattr(rest_module.time, "time", lambda: 1000)

    client._record_auth_failure()

    assert captured == {"threshold": 5, "backoff": 300, "now": 1000}


def test_auth_backoff_is_shared_across_planes_processes_and_restarts(
        monkeypatch, tmp_path):
    path = tmp_path / "rest-auth.guard"
    cfg = types.SimpleNamespace(
        ise_host="pan.example", ise_mnt_host="mnt.example", ers_port=9060,
        ise_user="readonly", ise_pass="wrong",
        auth_failure_threshold=2, auth_failure_backoff=60,
        rest_auth_guard_file=str(path),
    )
    monkeypatch.setattr(rest_module.time, "time", lambda: 1_000)

    class Resp:
        status_code = 401
        headers = {}
        text = ""

        def close(self):
            pass

    class Session:
        def __init__(self):
            self.calls = 0

        def get(self, *args, **kwargs):
            self.calls += 1
            return Resp()

    control = ISEControlPlaneClient(cfg)
    mnt = MnTActiveSessionClient(cfg)
    control_session = Session()
    mnt_session = Session()

    assert control._request(control_session, "https://pan/ers", api_name="ers") is None
    assert mnt._request(mnt_session, "https://mnt/mnt", api_name="mnt") is None
    restarted = ISEControlPlaneClient(cfg)
    restarted_session = Session()
    assert restarted._request(
        restarted_session, "https://pan/ers", api_name="ers") is None

    assert control_session.calls == 1
    assert mnt_session.calls == 1
    assert restarted_session.calls == 0
    assert RestAuthGuard(cfg).blocked(1_001) is True
    assert path.stat().st_mode & 0o777 == 0o660
    assert "wrong" not in path.read_text()


def test_auth_guard_state_is_scoped_to_account_and_cluster(tmp_path):
    path = tmp_path / "rest-auth.guard"
    base = dict(
        ise_host="pan.example", ise_mnt_host="mnt.example", ise_user="readonly",
        rest_auth_guard_file=str(path),
    )
    first = RestAuthGuard(types.SimpleNamespace(**base))
    first.failure(1, 60, 1_000)

    changed = RestAuthGuard(types.SimpleNamespace(**{
        **base, "ise_user": "different-readonly",
    }))

    assert first.blocked(1_001) is True
    assert changed.blocked(1_001) is False


def test_auth_guard_caps_future_deadline_after_clock_correction(tmp_path):
    cfg = types.SimpleNamespace(
        ise_host="pan.example", ise_mnt_host="mnt.example", ise_user="readonly",
        rest_auth_guard_file=str(tmp_path / "rest-auth.guard"),
    )
    guard = RestAuthGuard(cfg)
    guard.failure(1, 86400, 1_000_000)

    assert guard.blocked(1_000) is True
    assert float((tmp_path / "rest-auth.guard").read_text().split()[3]) == 87_400
    assert guard.blocked(87_401) is False


def test_unverified_https_warning_is_suppressed_at_request_boundary():
    client = ISERestClient.__new__(ISERestClient)
    client._auth_failures = 0
    client._auth_block_until = 0.0

    class Response:
        def raise_for_status(self):
            return None

    class Session:
        def get(self, *args, **kwargs):
            warnings.warn("unverified test request", InsecureRequestWarning)
            return Response()

    with warnings.catch_warnings(record=True) as caught:
        warnings.simplefilter("always")
        assert client._request(Session(), "https://ise.example/ers") is not None

    assert not [item for item in caught if issubclass(item.category, InsecureRequestWarning)]


def test_api_requests_stream_without_redirects_and_reject_login_redirects():
    client = ISERestClient.__new__(ISERestClient)
    client._auth_failures = 0
    client._auth_block_until = 0.0

    class Response:
        status_code = 302
        headers = {}

        def iter_content(self, chunk_size):
            assert chunk_size == rest_module.HTTP_ERROR_SNIPPET_BYTES
            yield b"interactive login"

    class Session:
        def __init__(self):
            self.kwargs = None

        def get(self, *_args, **kwargs):
            self.kwargs = kwargs
            return Response()

    session = Session()
    assert client._request(session, "https://ise.example/ers") is None
    assert session.kwargs["stream"] is True
    assert session.kwargs["allow_redirects"] is False


def test_api_response_content_length_is_rejected_before_body_read(monkeypatch):
    monkeypatch.setattr(rest_module, "MAX_HTTP_RESPONSE_BYTES", 10)
    client = ISERestClient.__new__(ISERestClient)
    client._auth_failures = 0
    client._auth_block_until = 0.0

    class Response:
        status_code = 200
        headers = {"Content-Length": "11"}
        closed = False

        def iter_content(self, chunk_size):
            raise AssertionError("oversized body should not be read")

        def close(self):
            self.closed = True

    response = Response()
    session = types.SimpleNamespace(get=lambda *_args, **_kwargs: response)
    counter = ise_api_errors_total.labels(
        api="bounded", error_type="response_too_large", http_code="0")
    before = counter._value.get()

    assert client._request(session, "https://ise.example/api", api_name="bounded") is None
    assert response.closed is True
    assert counter._value.get() == before + 1


def test_chunked_api_response_is_stopped_at_hard_byte_ceiling(monkeypatch):
    monkeypatch.setattr(rest_module, "MAX_HTTP_RESPONSE_BYTES", 10)
    client = ISERestClient.__new__(ISERestClient)
    client._auth_failures = 0
    client._auth_block_until = 0.0

    class Response:
        status_code = 200
        headers = {}
        closed = False

        def iter_content(self, chunk_size):
            yield b"123456"
            yield b"78901"

        def close(self):
            self.closed = True

    response = Response()
    session = types.SimpleNamespace(get=lambda *_args, **_kwargs: response)

    assert client._request(session, "https://ise.example/api") is None
    assert response.closed is True


def test_transport_never_hides_wire_retries_below_request_telemetry():
    cfg = types.SimpleNamespace(
        ise_host="h", ise_mnt_host="m", ers_port=9060, ise_user="u", ise_pass="p")
    client = ISERestClient(cfg)
    retry = client.session.get_adapter("https://").max_retries

    assert retry.allowed_methods == frozenset({"GET"})
    assert retry.total == 0
    assert retry.connect == 0
    assert retry.read == 0
    assert retry.status == 0
    assert retry.other == 0
    assert retry.redirect == 0
    assert retry.backoff_factor == 0
    assert retry.respect_retry_after_header is False
    assert retry.raise_on_status is False


def test_invalid_json_is_reported_as_api_parse_error():
    client = ISERestClient.__new__(ISERestClient)

    class Response:
        status_code = 200

        def json(self):
            raise ValueError("HTML login page is not JSON")

    client._request = lambda *_args, **_kwargs: Response()
    counter = ise_api_errors_total.labels(
        api="ers_endpoint", error_type="parse", http_code="200")
    before = counter._value.get()

    assert client._get_json(
        object(), "https://ise.example/ers/config/endpoint",
        api_name="ers_endpoint") is None
    assert counter._value.get() == before + 1


def test_mnt_xml_rejects_dtd_and_entity_declarations():
    client = ISERestClient.__new__(ISERestClient)
    client.mnt_xml_url = "https://mnt.example/admin/API/mnt"
    client.mnt_session = object()
    client._request = lambda *_args, **_kwargs: _Resp(
        b'<!DOCTYPE session [<!ENTITY value "expanded">]>'
        b'<session><value>&value;</value></session>')
    counter = ise_api_errors_total.labels(
        api="mnt_safe_xml", error_type="unsafe_xml", http_code="200")
    before = counter._value.get()

    assert client.get_mnt_xml("/Session/test", api_name="mnt_safe_xml") is None
    assert counter._value.get() == before + 1


def test_control_plane_transport_serializes_concurrent_session_use():
    client = ISERestClient.__new__(ISERestClient)
    client._auth_failures = 0
    client._auth_block_until = 0.0
    entered = threading.Event()
    release = threading.Event()
    active = 0
    maximum = 0
    state_lock = threading.Lock()

    class Response:
        def raise_for_status(self):
            return None

    class Session:
        def get(self, *args, **kwargs):
            nonlocal active, maximum
            with state_lock:
                active += 1
                maximum = max(maximum, active)
            entered.set()
            assert release.wait(1)
            with state_lock:
                active -= 1
            return Response()

    session = Session()
    first = threading.Thread(target=client._request, args=(session, "https://ise/first"))
    second = threading.Thread(target=client._request, args=(session, "https://ise/second"))
    first.start()
    assert entered.wait(1)
    second.start()
    release.set()
    first.join(1)
    second.join(1)

    assert not first.is_alive() and not second.is_alive()
    assert maximum == 1


def test_unverified_https_warning_is_suppressed_for_health_checks():
    client = ISERestClient.__new__(ISERestClient)
    client.host = "pan.example"
    client.mnt_host = "mnt.example"
    client.cfg = types.SimpleNamespace(ers_port=9060)

    class Response:
        status_code = 200

        def __init__(self):
            self.closed = False

        def close(self):
            self.closed = True

    class Session:
        def __init__(self):
            self.calls = []
            self.responses = []

        def get(self, *args, **kwargs):
            self.calls.append((args, kwargs))
            warnings.warn("unverified health request", InsecureRequestWarning)
            response = Response()
            self.responses.append(response)
            return response

    client.session = Session()
    client.mnt_session = Session()
    with warnings.catch_warnings(record=True) as caught:
        warnings.simplefilter("always")
        assert client.health_check() == {
            "pan": {"reachable": True, "authenticated": True, "http_status": 200},
            "mnt": {"reachable": True, "authenticated": True, "http_status": 200},
        }

    assert not [item for item in caught if issubclass(item.category, InsecureRequestWarning)]
    assert client.session.calls[0][0][0].endswith("/ers/config/networkdevice")
    assert client.session.calls[0][1]["params"] == {"size": 1, "page": 1}
    assert client.session.calls[0][1]["stream"] is True
    assert client.mnt_session.calls[0][0][0].endswith("/Session/ActiveCount")
    assert client.mnt_session.calls[0][1]["stream"] is True
    assert client.session.responses[0].closed is True
    assert client.mnt_session.responses[0].closed is True


def test_health_check_does_not_report_auth_failure_as_healthy():
    client = ISERestClient.__new__(ISERestClient)
    client.host = "pan.example"
    client.mnt_host = "mnt.example"
    client.cfg = types.SimpleNamespace(ers_port=9060)

    class Response:
        status_code = 401

    class Session:
        def get(self, *args, **kwargs):
            return Response()

    client.session = Session()
    client.mnt_session = Session()
    expected = {"reachable": True, "authenticated": False, "http_status": 401}
    assert client.health_check() == {"pan": expected, "mnt": expected}


def test_health_check_does_not_treat_login_redirect_as_authenticated():
    client = ISERestClient.__new__(ISERestClient)
    client.host = "pan.example"
    client.mnt_host = "mnt.example"
    client.cfg = types.SimpleNamespace(ers_port=9060)

    class Response:
        status_code = 302

    class Session:
        def get(self, *args, **kwargs):
            return Response()

    client.session = Session()
    client.mnt_session = Session()
    expected = {"reachable": True, "authenticated": False, "http_status": 302}
    assert client.health_check() == {"pan": expected, "mnt": expected}
