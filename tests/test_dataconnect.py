import types

import pytest

from ise_exporter.clients import dataconnect
from ise_exporter import metrics


class Cursor:
    description = [types.SimpleNamespace(name="USERNAME"), types.SimpleNamespace(name="HITS")]

    def __enter__(self):
        return self

    def __exit__(self, *_):
        return None

    def execute(self, sql, parameters):
        self.executed = (sql, parameters)

    def fetchall(self):
        return [("netadmin", 3)]


class Connection:
    call_timeout = 0
    closed = False

    def cursor(self):
        return Cursor()

    def close(self):
        self.closed = True


def test_query_uses_tcps_and_returns_lowercase_mappings(monkeypatch):
    connection = Connection()
    calls = []

    def connect(**kwargs):
        calls.append(kwargs)
        return connection

    monkeypatch.setattr(dataconnect.oracledb, "connect", connect)
    cfg = types.SimpleNamespace(
        dataconnect_host="mnt.example.mil", dataconnect_port=2484,
        dataconnect_service="cpm10", dataconnect_user="dataconnect",
        dataconnect_password="secret", dataconnect_ca_bundle="",
        dataconnect_ssl_verify=False, dataconnect_query_timeout=12,
        auth_failure_threshold=3, auth_failure_backoff=900,
    )
    client = dataconnect.DataConnectClient(cfg)

    assert client.query("SELECT username, COUNT(*) hits FROM example") == [
        {"username": "netadmin", "hits": 3}]
    assert calls[0]["protocol"] == "tcps"
    assert calls[0]["ssl_server_dn_match"] is False
    assert calls[0]["tcp_connect_timeout"] == 12
    assert connection.call_timeout == 12000

    client.close()
    assert connection.closed is True


def test_queries_are_paced_and_publish_bounded_view_telemetry(monkeypatch):
    connection = Connection()
    monkeypatch.setattr(dataconnect.oracledb, "connect", lambda **kwargs: connection)
    clock = iter((0.0, 0.0, 0.0, 0.1, 0.2, 0.35, 0.4))
    monkeypatch.setattr(dataconnect.time, "monotonic", lambda: next(clock))
    sleeps = []
    monkeypatch.setattr(dataconnect.time, "sleep", sleeps.append)
    cfg = types.SimpleNamespace(
        dataconnect_host="mnt.example.mil", dataconnect_port=2484,
        dataconnect_service="cpm10", dataconnect_user="dataconnect",
        dataconnect_password="secret", dataconnect_ca_bundle="",
        dataconnect_ssl_verify=False, dataconnect_query_timeout=12,
        dataconnect_min_query_interval_ms=250,
        auth_failure_threshold=3, auth_failure_backoff=900,
    )
    client = dataconnect.DataConnectClient(cfg)
    counter = metrics.ise_dataconnect_queries_total.labels(
        view="radius_authentications", result="success")
    before = counter._value.get()

    client.query("SELECT username FROM radius_authentications")
    client.query("SELECT username FROM radius_authentications")

    assert sleeps == [pytest.approx(1.8)]
    assert counter._value.get() == before + 2
    assert metrics.ise_dataconnect_query_rows.labels(
        view="radius_authentications")._value.get() == 1
    assert metrics.ise_dataconnect_query_cooldown_seconds.labels(
        view="radius_authentications")._value.get() == pytest.approx(0.95)
    assert dataconnect._query_view("SELECT * FROM arbitrary_table") == "other"


def test_connection_backoff_protects_dataconnect_account(monkeypatch):
    attempts = 0

    def fail(**_kwargs):
        nonlocal attempts
        attempts += 1
        raise RuntimeError("invalid credentials")

    monkeypatch.setattr(dataconnect.oracledb, "connect", fail)
    monkeypatch.setattr(dataconnect.time, "monotonic", lambda: 100.0)
    cfg = types.SimpleNamespace(
        dataconnect_host="mnt.example.mil", dataconnect_port=2484,
        dataconnect_service="cpm10", dataconnect_user="dataconnect",
        dataconnect_password="bad", dataconnect_ca_bundle="",
        dataconnect_ssl_verify=False, dataconnect_query_timeout=12,
        auth_failure_threshold=3, auth_failure_backoff=900,
    )
    client = dataconnect.DataConnectClient(cfg)

    for _ in range(3):
        with pytest.raises(RuntimeError, match="invalid credentials"):
            client.connect()
    with pytest.raises(RuntimeError, match="reconnect suppressed"):
        client.connect()

    assert attempts == 3


def test_query_materializes_endpoint_clob_and_binary_fields(monkeypatch):
    class Lob:
        def __init__(self, value):
            self.value = value

        def read(self):
            return self.value

    class LobCursor(Cursor):
        description = [types.SimpleNamespace(name="CUSTOM_ATTRIBUTES"),
                       types.SimpleNamespace(name="PROBE_DATA")]

        def fetchall(self):
            return [(Lob('{"Ops Owner":"Campus Operations"}'), Lob(b"probe"))]

    class LobConnection(Connection):
        def cursor(self):
            return LobCursor()

    monkeypatch.setattr(dataconnect.oracledb, "connect", lambda **kwargs: LobConnection())
    cfg = types.SimpleNamespace(
        dataconnect_host="mnt.example", dataconnect_port=2484,
        dataconnect_service="cpm10", dataconnect_user="dataconnect",
        dataconnect_password="secret", dataconnect_ca_bundle="",
        dataconnect_ssl_verify=False, dataconnect_query_timeout=12,
        auth_failure_threshold=3, auth_failure_backoff=900,
    )

    assert dataconnect.DataConnectClient(cfg).query("SELECT fields FROM endpoints_data") == [{
        "custom_attributes": '{"Ops Owner":"Campus Operations"}',
        "probe_data": "base64:cHJvYmU=",
    }]
