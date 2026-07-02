import types

import pytest
import requests

from ise_exporter.clients.pxgrid import ENDPOINT_BULK_START, ENDPOINT_SERVICE, PxGridControl


class _Resp:
    def __init__(self, data, status=200):
        self._data = data
        self.status_code = status
        self.text = str(data)

    def json(self):
        return self._data

    def raise_for_status(self):
        if self.status_code >= 400:
            error = requests.exceptions.HTTPError(self.status_code)
            error.response = self
            raise error


class _Session:
    def __init__(self, handler):
        self.handler = handler
        self.cert = None
        self.verify = None
        self.auth = None
        self.headers = {}
        self.calls = []

    def post(self, url, json=None, auth=None, timeout=30):
        op = url.rstrip("/").rsplit("/", 1)[-1]
        self.calls.append((op, json or {}, auth))
        return _Resp(self.handler(op, json or {}, auth))


def _cfg():
    return types.SimpleNamespace(
        pxgrid_host="px.example",
        pxgrid_port=8910,
        pxgrid_node_name="ise-exporter",
        pxgrid_client_cert="/cert.pem",
        pxgrid_client_key="/key.pem",
        pxgrid_ca_bundle="/ca.pem",
    )


def test_rest_query_activates_before_lookup_and_uses_access_secret():
    def handler(op, body, auth):
        if op == "AccountActivate":
            return {"accountState": "ENABLED", "version": "2.0"}
        if op == "ServiceLookup":
            assert body == {"name": ENDPOINT_SERVICE}
            return {"services": [{
                "nodeName": "ise-node",
                "properties": {"restBaseUrl": "https://ise:8910/pxgrid/ise/endpoint"},
            }]}
        if op == "AccessSecret":
            assert body == {"peerNodeName": "ise-node"}
            return {"secret": "secret"}
        if op == "getEndpoints":
            assert auth.username == "ise-exporter"
            assert auth.password == "secret"
            return {"endpoints": []}
        raise AssertionError(op)

    control = PxGridControl(_cfg())
    control.session = _Session(handler)

    assert control.rest_query(ENDPOINT_SERVICE, "getEndpoints", {}) == {"endpoints": []}
    assert [call[0] for call in control.session.calls] == [
        "AccountActivate", "ServiceLookup", "AccessSecret", "getEndpoints",
    ]


def test_rest_query_tries_next_provider_when_first_is_down():
    class Session(_Session):
        def post(self, url, json=None, auth=None, timeout=30):
            op = url.rstrip("/").rsplit("/", 1)[-1]
            self.calls.append((op, url, json or {}, auth))
            if url.startswith("https://bad/"):
                raise requests.exceptions.ConnectionError("down")
            return _Resp(self.handler(op, json or {}, auth))

    def handler(op, body, auth):
        if op == "AccountActivate":
            return {"accountState": "ENABLED"}
        if op == "ServiceLookup":
            return {"services": [
                {"nodeName": "bad-node",
                 "properties": {"restBaseUrl": "https://bad/pxgrid/ise/endpoint"}},
                {"nodeName": "good-node",
                 "properties": {"restBaseUrl": "https://good/pxgrid/ise/endpoint"}},
            ]}
        if op == "AccessSecret":
            return {"secret": f"secret-for-{body['peerNodeName']}"}
        if op == "getEndpoints":
            assert auth.username == "ise-exporter"
            assert auth.password == "secret-for-good-node"
            return {"endpoints": []}
        raise AssertionError(op)

    control = PxGridControl(_cfg())
    control.session = Session(handler)

    assert control.rest_query(ENDPOINT_SERVICE, "getEndpoints", {}) == {"endpoints": []}
    urls = [call[1] for call in control.session.calls if call[0] == "getEndpoints"]
    assert urls == [
        "https://bad/pxgrid/ise/endpoint/getEndpoints",
        "https://good/pxgrid/ise/endpoint/getEndpoints",
    ]


def test_pending_account_stops_before_service_lookup():
    control = PxGridControl(_cfg())
    control.session = _Session(lambda op, body, auth: {"accountState": "PENDING"})

    with pytest.raises(RuntimeError, match="PENDING"):
        control.service_lookup(ENDPOINT_SERVICE)
    assert [call[0] for call in control.session.calls] == ["AccountActivate"]


def test_get_endpoints_uses_required_timestamp_and_pages():
    pages = {
        0: [{"macAddress": "00:00:00:00:00:01"}, {"macAddress": "00:00:00:00:00:02"}],
        2: [{"macAddress": "00:00:00:00:00:03"}],
    }
    bodies = []

    def handler(op, body, auth):
        if op == "AccountActivate":
            return {"accountState": "ENABLED"}
        if op == "ServiceLookup":
            return {"services": [{
                "nodeName": "ise-node",
                "properties": {"restBaseUrl": "https://ise:8910/pxgrid/ise/endpoint"},
            }]}
        if op == "AccessSecret":
            return {"secret": "secret"}
        if op == "getEndpoints":
            bodies.append(body)
            return {"endpoints": pages[body["startIndex"]]}
        raise AssertionError(op)

    control = PxGridControl(_cfg())
    control.session = _Session(handler)

    endpoints = control.get_endpoints(page_size=2)

    assert [endpoint["macAddress"] for endpoint in endpoints] == [
        "00:00:00:00:00:01",
        "00:00:00:00:00:02",
        "00:00:00:00:00:03",
    ]
    assert bodies == [
        {"startCreateTimestamp": ENDPOINT_BULK_START, "startIndex": 0, "count": 2, "order": "ASC"},
        {"startCreateTimestamp": ENDPOINT_BULK_START, "startIndex": 2, "count": 2, "order": "ASC"},
    ]


def test_get_endpoints_can_limit_pages_for_probe():
    bodies = []

    def handler(op, body, auth):
        if op == "AccountActivate":
            return {"accountState": "ENABLED"}
        if op == "ServiceLookup":
            return {"services": [{
                "nodeName": "ise-node",
                "properties": {"restBaseUrl": "https://ise:8910/pxgrid/ise/endpoint"},
            }]}
        if op == "AccessSecret":
            return {"secret": "secret"}
        if op == "getEndpoints":
            bodies.append(body)
            return {"endpoints": [{"macAddress": "00:00:00:00:00:01"}]}
        raise AssertionError(op)

    control = PxGridControl(_cfg())
    control.session = _Session(handler)

    assert control.get_endpoints(page_size=1, max_pages=1) == [
        {"macAddress": "00:00:00:00:00:01"}
    ]
    assert len(bodies) == 1


def test_session_topic_prefers_session_topic_all_when_available():
    def handler(op, body, auth):
        if op == "AccountActivate":
            return {"accountState": "ENABLED"}
        if op == "ServiceLookup":
            return {"services": [{
                "nodeName": "ise-node",
                "properties": {
                    "restBaseUrl": "https://ise:8910/pxgrid/ise/session",
                    "sessionTopic": "/topic/com.cisco.ise.session",
                    "sessionTopicAll": "/topic/com.cisco.ise.session.all",
                },
            }]}
        raise AssertionError(op)

    control = PxGridControl(_cfg())
    control.session = _Session(handler)

    assert control.session_topic() == (
        "https://ise:8910/pxgrid/ise/session",
        "/topic/com.cisco.ise.session.all",
    )
