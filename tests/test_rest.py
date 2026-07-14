"""ISERestClient.get_ers must follow nextPage.href across all pages iteratively
(no per-page recursion that would blow the stack on large result sets)."""
import threading
import types
import warnings

import requests
from urllib3.exceptions import InsecureRequestWarning

from ise_exporter.clients.rest import (
    ISEControlPlaneClient,
    ISEOperatorClient,
    ISERestClient,
    MnTActiveSessionClient,
    MnTDiagnosticsClient,
)


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
        base: {"SearchResult": {"resources": [{"id": "1"}],
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
    c._get_json = lambda *args, **kwargs: {"SearchResult": {"resources": []}}

    assert c.get_ers("/config/internaluser", get_all=True) == []


def test_get_ers_rejects_missing_pages_when_total_is_larger():
    c = ISERestClient.__new__(ISERestClient)
    c.ers_url = "https://h:9060/ers"
    c.session = None
    c._get_json = lambda *args, **kwargs: {"SearchResult": {
        "total": 2,
        "resources": [{"id": "partial"}],
    }}

    assert c.get_ers("/config/internaluser", get_all=True) is None


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

    class Session:
        def __init__(self):
            self.calls = []

        def get(self, *args, **kwargs):
            self.calls.append((args, kwargs))
            warnings.warn("unverified health request", InsecureRequestWarning)
            return Response()

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
    assert client.mnt_session.calls[0][0][0].endswith("/Session/ActiveCount")


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
