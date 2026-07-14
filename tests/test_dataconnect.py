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
    clock = iter((0.0, 0.0, 0.0, 0.0, 0.1, 0.2, 0.35, 0.4, 0.45))
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

    assert sleeps == [pytest.approx(19.8)]
    assert counter._value.get() == before + 2
    assert metrics.ise_dataconnect_query_rows.labels(
        view="radius_authentications")._value.get() == 1
    assert metrics.ise_dataconnect_query_cooldown_seconds.labels(
        view="radius_authentications")._value.get() == pytest.approx(9.95)
    assert dataconnect._query_view("SELECT * FROM arbitrary_table") == "other"


def test_schema_validation_is_not_mislabeled_as_reporting_activity():
    sql = """
        SELECT table_name, column_name
        FROM user_tab_columns
        WHERE table_name IN ('TACACS_AUTHENTICATION_LAST_TWO_DAYS',
                             'RADIUS_AUTHENTICATIONS')
    """

    assert dataconnect._query_view(sql) == "schema_metadata"


def test_shared_pacing_gate_serializes_independent_clients(monkeypatch, tmp_path):
    monkeypatch.setattr(dataconnect.oracledb, "connect", lambda **kwargs: Connection())
    monotonic = [0.0]

    def tick():
        value = monotonic[0]
        monotonic[0] += 0.1
        return value

    monkeypatch.setattr(dataconnect.time, "monotonic", tick)
    monkeypatch.setattr(dataconnect.time, "time", lambda: 100.0)
    sleeps = []
    monkeypatch.setattr(dataconnect.time, "sleep", sleeps.append)
    cfg = types.SimpleNamespace(
        dataconnect_host="mnt.example.mil", dataconnect_port=2484,
        dataconnect_service="cpm10", dataconnect_user="dataconnect",
        dataconnect_password="secret", dataconnect_ca_bundle="",
        dataconnect_ssl_verify=False, dataconnect_query_timeout=12,
        dataconnect_min_query_interval_ms=500,
        dataconnect_max_duty_cycle_percent=2,
        dataconnect_shared_pacing_file=str(tmp_path / "dataconnect.pacing"),
        auth_failure_threshold=3, auth_failure_backoff=900,
    )

    dataconnect.DataConnectClient(cfg).query("SELECT username FROM radius_authentications")
    dataconnect.DataConnectClient(cfg).query("SELECT username FROM radius_authentications")

    assert len(sleeps) == 1
    assert sleeps[0] > 0
    assert (tmp_path / "dataconnect.pacing").stat().st_mode & 0o777 == 0o660


def test_shared_pacing_gate_acquisition_failure_is_counted(monkeypatch):
    cfg = types.SimpleNamespace(
        dataconnect_host="mnt.example.mil", dataconnect_port=2484,
        dataconnect_service="cpm10", dataconnect_user="dataconnect",
        dataconnect_password="secret", dataconnect_ca_bundle="",
        dataconnect_ssl_verify=False, dataconnect_query_timeout=12,
        dataconnect_min_query_interval_ms=500,
        dataconnect_shared_pacing_file="/unavailable/dataconnect.pacing",
        auth_failure_threshold=3, auth_failure_backoff=900,
    )
    client = dataconnect.DataConnectClient(cfg)
    monkeypatch.setattr(
        client, "_shared_gate", lambda: (_ for _ in ()).throw(
            RuntimeError("shared pacing gate unavailable")))
    counter = metrics.ise_dataconnect_queries_total.labels(
        view="radius_authentications", result="error")
    before = counter._value.get()

    with pytest.raises(RuntimeError, match="shared pacing gate unavailable"):
        client.query("SELECT username FROM radius_authentications")

    assert counter._value.get() == before + 1
    assert client._connection is None
    assert client._next_query_at > 0


def test_shared_pacing_gate_release_failure_marks_query_error(monkeypatch):
    monkeypatch.setattr(dataconnect.oracledb, "connect", lambda **kwargs: Connection())
    cfg = types.SimpleNamespace(
        dataconnect_host="mnt.example.mil", dataconnect_port=2484,
        dataconnect_service="cpm10", dataconnect_user="dataconnect",
        dataconnect_password="secret", dataconnect_ca_bundle="",
        dataconnect_ssl_verify=False, dataconnect_query_timeout=12,
        dataconnect_min_query_interval_ms=500,
        dataconnect_shared_pacing_file="/tmp/dataconnect.pacing",
        auth_failure_threshold=3, auth_failure_backoff=900,
    )
    client = dataconnect.DataConnectClient(cfg)
    monkeypatch.setattr(client, "_shared_gate", lambda: 123)
    monkeypatch.setattr(
        client, "_release_shared_gate", lambda *_: (_ for _ in ()).throw(
            OSError("pacing deadline write failed")))
    success = metrics.ise_dataconnect_queries_total.labels(
        view="radius_authentications", result="success")
    errors = metrics.ise_dataconnect_queries_total.labels(
        view="radius_authentications", result="error")
    success_before = success._value.get()
    errors_before = errors._value.get()

    with pytest.raises(OSError, match="pacing deadline write failed"):
        client.query("SELECT username FROM radius_authentications")

    assert success._value.get() == success_before
    assert errors._value.get() == errors_before + 1


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


def test_query_reconnects_once_after_ise_expires_session(monkeypatch):
    class ExpiredCursor(Cursor):
        def execute(self, sql, parameters):
            raise RuntimeError("ORA-02399: exceeded maximum connect time")

    class ExpiredConnection(Connection):
        def cursor(self):
            return ExpiredCursor()

    connections = iter((ExpiredConnection(), Connection()))
    attempts = []

    def connect(**_kwargs):
        attempts.append(True)
        return next(connections)

    monkeypatch.setattr(dataconnect.oracledb, "connect", connect)
    cfg = types.SimpleNamespace(
        dataconnect_host="mnt.example.mil", dataconnect_port=2484,
        dataconnect_service="cpm10", dataconnect_user="dataconnect",
        dataconnect_password="secret", dataconnect_ca_bundle="",
        dataconnect_ssl_verify=False, dataconnect_query_timeout=12,
        dataconnect_shared_pacing_file="",
        auth_failure_threshold=3, auth_failure_backoff=900,
    )

    result = dataconnect.DataConnectClient(cfg).query("SELECT username FROM endpoints_data")

    assert result == [{"username": "netadmin", "hits": 3}]
    assert len(attempts) == 2


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
