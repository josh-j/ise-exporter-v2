from types import SimpleNamespace

import pytest

from ise_exporter.clients.pxgrid import PxGridControl
from ise_exporter.config import Config


class Response:
    def __init__(self, body):
        self._body = body
        self.content = b"{}"
        self.headers = {}

    def raise_for_status(self):
        return None

    def json(self):
        return self._body


def config(**values):
    return Config(
        pxgrid_host="ise.example.com", pxgrid_node_name="ise-cli",
        pxgrid_password="secret", **values)


def test_pxgrid_password_auth_activation_and_read_query(monkeypatch):
    calls = []

    def post(_self, url, **kwargs):
        calls.append((url, kwargs))
        if url.endswith("AccountActivate"):
            return Response({"accountState": "ENABLED", "version": "2.0"})
        if url.endswith("ServiceLookup"):
            return Response({"services": [{"nodeName": "ise01", "properties": {
                "restBaseUrl": "https://ise.example.com:8910/pxgrid/session",
                "sessionTopic": "/topic/com.cisco.ise.session",
            }}]})
        if url.endswith("AccessSecret"):
            return Response({"secret": "peer-secret"})
        return Response({"sessions": [{"userName": "alice"}]})

    monkeypatch.setattr("requests.Session.post", post)
    client = PxGridControl(config())
    try:
        assert client.activate()["accountState"] == "ENABLED"
        assert client.query("sessions") == [{"userName": "alice"}]
    finally:
        client.close()

    assert calls[0][0].endswith("/pxgrid/control/AccountActivate")
    assert calls[-1][1]["timeout"] == 30
    assert calls[-1][1]["auth"].password == "peer-secret"


def test_pxgrid_topic_discovery_returns_flat_objects(monkeypatch):
    client = object.__new__(PxGridControl)
    client.services = lambda _name=None: [{
        "serviceName": "com.cisco.ise.session", "nodeName": "ise01",
        "properties": {"restBaseURL": "https://ise/pxgrid", "sessionTopic": "/topic/session"},
    }]
    assert client.topics() == [{
        "serviceName": "com.cisco.ise.session", "nodeName": "ise01",
        "property": "sessionTopic", "topic": "/topic/session",
    }]


def test_pxgrid_service_discovery_removes_case_colliding_properties():
    client = object.__new__(PxGridControl)
    client.lookup = lambda _name: [{
        "nodeName": "ise01",
        "properties": {
            "restBaseURL": "https://ise/legacy",
            "restBaseUrl": "https://ise/current",
            "sessionTopic": "/topic/session",
        },
    }]

    assert client.services("com.cisco.ise.session") == [{
        "serviceName": "com.cisco.ise.session",
        "nodeName": "ise01",
        "properties": {
            "restBaseUrl": "https://ise/current",
            "sessionTopic": "/topic/session",
        },
    }]


def test_pxgrid_rejects_non_https_service_url(monkeypatch):
    client = object.__new__(PxGridControl)
    client._services = {}
    client.lookup = lambda _name: [{
        "nodeName": "ise01", "properties": {"restBaseUrl": "http://ise/pxgrid"}}]
    with pytest.raises(RuntimeError, match="unsafe REST URL"):
        client._provider("com.cisco.ise.session")


def test_pxgrid_requires_credentials():
    with pytest.raises(RuntimeError, match="not configured"):
        PxGridControl(SimpleNamespace(pxgrid_ready=False))
