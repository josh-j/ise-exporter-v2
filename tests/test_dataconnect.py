import types

from ise_exporter.clients import dataconnect


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
