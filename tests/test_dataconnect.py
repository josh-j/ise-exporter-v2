import fcntl
import os
import threading
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

    def fetchmany(self, size):
        if getattr(self, "returned", False):
            return []
        self.returned = True
        return self.fetchall()[:size]


class Connection:
    call_timeout = 0
    closed = False

    def cursor(self):
        return Cursor()

    def close(self):
        self.closed = True


def test_client_retains_normalized_startup_schema_without_querying(caplog):
    cfg = types.SimpleNamespace(
        dataconnect_host="mnt.example.mil", dataconnect_port=2484,
        dataconnect_service="cpm10", dataconnect_user="dataconnect",
        dataconnect_password="secret", dataconnect_ca_bundle="",
        dataconnect_ssl_verify=False, dataconnect_query_timeout=12,
        auth_failure_threshold=3, auth_failure_backoff=900,
    )
    client = dataconnect.DataConnectClient(cfg)

    client.set_schema({
        "radius_authentications": {"policy_set_name": "varchar2"},
        "radius_accounting": {"acct_status_type": "varchar2"},
    })

    assert client.schema == {
        "RADIUS_AUTHENTICATIONS": {"POLICY_SET_NAME": "VARCHAR2"},
        "RADIUS_ACCOUNTING": {"ACCT_STATUS_TYPE": "VARCHAR2"},
    }
    assert "using POLICY_SET_NAME" in caplog.text
    assert "using 'none'" in caplog.text


def test_client_warns_when_authentication_policy_dimensions_are_absent(caplog):
    cfg = types.SimpleNamespace(
        dataconnect_host="mnt.example.mil", dataconnect_port=2484,
        dataconnect_service="cpm10", dataconnect_user="dataconnect",
        dataconnect_password="secret", dataconnect_ca_bundle="",
        dataconnect_ssl_verify=False, dataconnect_query_timeout=12,
        auth_failure_threshold=3, auth_failure_backoff=900,
    )
    client = dataconnect.DataConnectClient(cfg)

    client.set_schema({
        "radius_authentications": {"authentication_method": "varchar2"},
    })

    assert "no optional authorization-policy column" in caplog.text
    assert "using 'none'" in caplog.text


def test_connection_disables_parallel_query_before_reporting_sql(monkeypatch):
    statements = []

    class RecordingCursor(Cursor):
        def execute(self, sql, parameters=None):
            statements.append((sql, parameters))

    class RecordingConnection(Connection):
        def cursor(self):
            return RecordingCursor()

    connection = RecordingConnection()
    monkeypatch.setattr(dataconnect.oracledb, "connect", lambda **kwargs: connection)
    cfg = types.SimpleNamespace(
        dataconnect_host="mnt.example.mil", dataconnect_port=2484,
        dataconnect_service="cpm10", dataconnect_user="dataconnect",
        dataconnect_password="secret", dataconnect_ca_bundle="",
        dataconnect_ssl_verify=False, dataconnect_query_timeout=12,
        auth_failure_threshold=3, auth_failure_backoff=900,
    )

    client = dataconnect.DataConnectClient(cfg)
    client.query("SELECT username, COUNT(*) hits FROM example")

    assert statements == [
        ("ALTER SESSION DISABLE PARALLEL QUERY", {}),
        ("SELECT username, COUNT(*) hits FROM example", {}),
    ]


def test_rejected_session_safety_setup_closes_connection_and_fails_closed(monkeypatch):
    class FailingCursor(Cursor):
        def execute(self, sql, parameters=None):
            raise RuntimeError("ALTER SESSION rejected")

    class FailingConnection(Connection):
        def cursor(self):
            return FailingCursor()

    connection = FailingConnection()
    monkeypatch.setattr(dataconnect.oracledb, "connect", lambda **kwargs: connection)
    cfg = types.SimpleNamespace(
        dataconnect_host="mnt.example.mil", dataconnect_port=2484,
        dataconnect_service="cpm10", dataconnect_user="dataconnect",
        dataconnect_password="secret", dataconnect_ca_bundle="",
        dataconnect_ssl_verify=False, dataconnect_query_timeout=12,
        auth_failure_threshold=3, auth_failure_backoff=900,
    )

    client = dataconnect.DataConnectClient(cfg)
    with pytest.raises(RuntimeError, match="ALTER SESSION rejected"):
        client.connect()

    assert connection.closed is True
    assert client._connection is None


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


def test_client_hard_caps_oracle_call_timeout(monkeypatch):
    connection = Connection()
    monkeypatch.setattr(dataconnect.oracledb, "connect", lambda **kwargs: connection)
    cfg = types.SimpleNamespace(
        dataconnect_host="mnt.example.mil", dataconnect_port=2484,
        dataconnect_service="cpm10", dataconnect_user="dataconnect",
        dataconnect_password="secret", dataconnect_ca_bundle="",
        dataconnect_ssl_verify=False, dataconnect_query_timeout=3600,
        auth_failure_threshold=3, auth_failure_backoff=900,
    )

    client = dataconnect.DataConnectClient(cfg)
    client.connect()

    assert client.timeout == 15
    assert connection.call_timeout == 15000
    assert metrics.ise_dataconnect_query_timeout_seconds._value.get() == 15
    assert metrics.ise_dataconnect_max_duty_cycle_percent._value.get() == 0.1
    assert metrics.ise_dataconnect_result_row_ceiling._value.get() == (
        dataconnect.MAX_RESULT_ROWS)
    assert metrics.ise_dataconnect_result_byte_ceiling._value.get() == (
        dataconnect.MAX_RESULT_BYTES)


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

    assert sleeps == [pytest.approx(99.8)]
    assert counter._value.get() == before + 2
    assert metrics.ise_dataconnect_query_rows.labels(
        view="radius_authentications")._value.get() == 1
    assert metrics.ise_dataconnect_query_cooldown_seconds.labels(
        view="radius_authentications")._value.get() == pytest.approx(49.95)
    assert metrics.ise_dataconnect_query_last_duration_seconds.labels(
        view="radius_authentications", result="success")._value.get() == pytest.approx(0.05)
    assert dataconnect._query_view("SELECT * FROM arbitrary_table") == "other"


def test_atomic_query_batch_uses_fixed_gaps_then_one_aggregate_cooldown(monkeypatch):
    connection = Connection()
    monkeypatch.setattr(dataconnect.oracledb, "connect", lambda **kwargs: connection)
    clock = [0.0]

    def tick():
        clock[0] += 0.1
        return clock[0]

    monkeypatch.setattr(dataconnect.time, "monotonic", tick)
    sleeps = []
    cfg = types.SimpleNamespace(
        dataconnect_host="mnt.example.mil", dataconnect_port=2484,
        dataconnect_service="cpm10", dataconnect_user="dataconnect",
        dataconnect_password="secret", dataconnect_ca_bundle="",
        dataconnect_ssl_verify=False, dataconnect_query_timeout=12,
        dataconnect_min_query_interval_ms=5000,
        dataconnect_shared_pacing_file="",
        auth_failure_threshold=3, auth_failure_backoff=900,
    )
    client = dataconnect.DataConnectClient(cfg)
    monkeypatch.setattr(client, "_wait", sleeps.append)

    result = client.query_many({
        "authentication": "SELECT username FROM radius_authentications",
        "accounting": "SELECT username FROM radius_accounting",
    })

    assert result == {
        "authentication": [{"username": "netadmin", "hits": 3}],
        "accounting": [{"username": "netadmin", "hits": 3}],
    }
    assert sleeps == [5.0]
    assert client._next_query_at > clock[0] + 100
    assert client._batch_active is False


def test_atomic_query_batch_advances_shared_crash_lease_per_statement(
        monkeypatch, tmp_path):
    connection = Connection()
    monkeypatch.setattr(dataconnect.oracledb, "connect", lambda **kwargs: connection)
    monkeypatch.setattr(dataconnect.time, "time", lambda: 100.0)
    clock = [0.0]

    def tick():
        clock[0] += 0.1
        return clock[0]

    monkeypatch.setattr(dataconnect.time, "monotonic", tick)
    cfg = types.SimpleNamespace(
        dataconnect_host="mnt", dataconnect_port=2484, dataconnect_service="cpm10",
        dataconnect_user="reader", dataconnect_password="secret",
        dataconnect_ca_bundle="", dataconnect_ssl_verify=False,
        dataconnect_query_timeout=15,
        dataconnect_shared_pacing_file=str(tmp_path / "dataconnect.pacing"),
    )
    client = dataconnect.DataConnectClient(cfg)
    monkeypatch.setattr(client, "_wait", lambda _seconds: None)
    writes = []
    real_write = client._write_shared_deadline

    def record_write(descriptor, deadline):
        writes.append(deadline)
        real_write(descriptor, deadline)

    monkeypatch.setattr(client, "_write_shared_deadline", record_write)

    client.query_many({
        "authentication": "SELECT username FROM radius_authentications",
        "accounting": "SELECT username FROM radius_accounting",
    })

    # Initial one-statement lease, completed-work lease, next-statement lease,
    # then the second completed-work lease. Final unlock is class-owned.
    assert len(writes) == 4
    expected_initial = 100.0 + (
        dataconnect.MAX_STATEMENT_TIMEOUT_PERIODS * client.timeout
        * (100 / client.max_duty_cycle - 1))
    assert writes[0] == pytest.approx(expected_initial)
    assert writes[1] < writes[0]
    assert writes[2] > writes[1]


def test_query_batch_has_a_hard_statement_ceiling():
    cfg = types.SimpleNamespace(
        dataconnect_host="mnt", dataconnect_port=2484, dataconnect_service="cpm10",
        dataconnect_user="reader", dataconnect_password="secret",
        dataconnect_ca_bundle="", dataconnect_ssl_verify=False,
        dataconnect_query_timeout=15,
    )

    with pytest.raises(ValueError, match="5-query ceiling"):
        dataconnect.DataConnectClient(cfg).query_many({
            str(index): "SELECT 1 FROM endpoints_data" for index in range(6)
        })


def test_query_batch_applies_result_row_ceiling_across_statements(monkeypatch):
    monkeypatch.setattr(dataconnect.oracledb, "connect", lambda **kwargs: Connection())
    monkeypatch.setattr(dataconnect, "MAX_BATCH_RESULT_ROWS", 2)
    cfg = types.SimpleNamespace(
        dataconnect_host="mnt", dataconnect_port=2484, dataconnect_service="cpm10",
        dataconnect_user="reader", dataconnect_password="secret",
        dataconnect_ca_bundle="", dataconnect_ssl_verify=False,
        dataconnect_query_timeout=15, dataconnect_shared_pacing_file="",
    )
    client = dataconnect.DataConnectClient(cfg)
    monkeypatch.setattr(client, "_wait", lambda _seconds: None)

    with pytest.raises(RuntimeError, match="batch exceeded the hard 2-row safety ceiling"):
        client.query_many({
            "one": "SELECT username FROM endpoints_data",
            "two": "SELECT username FROM endpoints_data",
            "three": "SELECT username FROM endpoints_data",
        })

    assert client._batch_rows == 0


def test_query_keeps_individual_statement_row_ceiling_inside_batch(monkeypatch):
    class ThreeRowCursor(Cursor):
        def fetchall(self):
            return [("one", 1), ("two", 2), ("three", 3)]

    class ThreeRowConnection(Connection):
        def cursor(self):
            return ThreeRowCursor()

    monkeypatch.setattr(
        dataconnect.oracledb, "connect", lambda **kwargs: ThreeRowConnection())
    monkeypatch.setattr(dataconnect, "MAX_RESULT_ROWS", 2)
    monkeypatch.setattr(dataconnect, "MAX_BATCH_RESULT_ROWS", 10)
    cfg = types.SimpleNamespace(
        dataconnect_host="mnt", dataconnect_port=2484, dataconnect_service="cpm10",
        dataconnect_user="reader", dataconnect_password="secret",
        dataconnect_ca_bundle="", dataconnect_ssl_verify=False,
        dataconnect_query_timeout=15, dataconnect_shared_pacing_file="",
    )
    client = dataconnect.DataConnectClient(cfg)

    with pytest.raises(RuntimeError, match="hard 2-row safety ceiling"):
        client.query_many({"one": "SELECT username FROM endpoints_data"})


def test_query_batch_applies_result_byte_ceiling_across_statements(monkeypatch):
    monkeypatch.setattr(dataconnect.oracledb, "connect", lambda **kwargs: Connection())
    monkeypatch.setattr(dataconnect, "MAX_RESULT_BYTES", 40)
    cfg = types.SimpleNamespace(
        dataconnect_host="mnt", dataconnect_port=2484, dataconnect_service="cpm10",
        dataconnect_user="reader", dataconnect_password="secret",
        dataconnect_ca_bundle="", dataconnect_ssl_verify=False,
        dataconnect_query_timeout=15, dataconnect_shared_pacing_file="",
    )
    client = dataconnect.DataConnectClient(cfg)
    monkeypatch.setattr(client, "_wait", lambda _seconds: None)

    with pytest.raises(RuntimeError, match="40-byte safety ceiling"):
        client.query_many({
            "one": "SELECT username FROM endpoints_data",
            "two": "SELECT username FROM endpoints_data",
        })

    assert client._batch_result_bytes == 0


def test_client_respects_explicit_pacing_but_preserves_auth_safety():
    cfg = types.SimpleNamespace(
        dataconnect_host="mnt.example.mil", dataconnect_port=2484,
        dataconnect_service="cpm10", dataconnect_user="dataconnect",
        dataconnect_password="secret", dataconnect_ca_bundle="",
        dataconnect_ssl_verify=False, dataconnect_query_timeout=12,
        dataconnect_min_query_interval_ms=1,
        dataconnect_max_duty_cycle_percent=100,
        auth_failure_threshold=999, auth_failure_backoff=0,
    )

    client = dataconnect.DataConnectClient(cfg)

    assert client.max_duty_cycle == 100
    assert client.min_query_interval == 0.001
    assert client.failure_threshold == 5
    assert client.failure_backoff == 300


@pytest.mark.parametrize("host", (
    "tcps://mnt.example", "user@mnt.example", "mnt.example/cpm10", "mnt.example:2484",
))
def test_dataconnect_rejects_non_bare_database_hosts(host):
    cfg = types.SimpleNamespace(
        dataconnect_host=host, dataconnect_port=2484,
        dataconnect_service="cpm10", dataconnect_user="dataconnect",
        dataconnect_password="secret", dataconnect_ca_bundle="",
        dataconnect_ssl_verify=True, dataconnect_query_timeout=15,
    )

    with pytest.raises(ValueError, match="bare DNS hostname or IPv4 address"):
        dataconnect.DataConnectClient(cfg)


def test_client_honors_more_conservative_duty_cycle():
    cfg = types.SimpleNamespace(
        dataconnect_host="mnt.example.mil", dataconnect_port=2484,
        dataconnect_service="cpm10", dataconnect_user="dataconnect",
        dataconnect_password="secret", dataconnect_ca_bundle="",
        dataconnect_ssl_verify=False, dataconnect_query_timeout=12,
        dataconnect_max_duty_cycle_percent=0.05,
        auth_failure_threshold=3, auth_failure_backoff=900,
    )

    assert dataconnect.DataConnectClient(cfg).max_duty_cycle == 0.05


def test_client_honors_extremely_conservative_duty_cycle_and_deadline():
    cfg = types.SimpleNamespace(
        dataconnect_host="mnt.example.mil", dataconnect_port=2484,
        dataconnect_service="cpm10", dataconnect_user="dataconnect",
        dataconnect_password="secret", dataconnect_ca_bundle="",
        dataconnect_ssl_verify=False, dataconnect_query_timeout=15,
        dataconnect_max_duty_cycle_percent=0.001,
        auth_failure_threshold=3, auth_failure_backoff=900,
    )

    client = dataconnect.DataConnectClient(cfg)

    assert client.max_duty_cycle == 0.001
    assert client.max_shared_pacing_future_seconds > 300 * 86400


def test_query_timeout_is_total_across_execute_and_fetch_round_trips(monkeypatch):
    connection = Connection()
    monkeypatch.setattr(dataconnect.oracledb, "connect", lambda **kwargs: connection)
    clock = iter((0.0, 0.0, 14.9, 15.1))
    monkeypatch.setattr(dataconnect.time, "perf_counter", lambda: next(clock))
    cfg = types.SimpleNamespace(
        dataconnect_host="mnt.example.mil", dataconnect_port=2484,
        dataconnect_service="cpm10", dataconnect_user="dataconnect",
        dataconnect_password="secret", dataconnect_ca_bundle="",
        dataconnect_ssl_verify=False, dataconnect_query_timeout=15,
        auth_failure_threshold=3, auth_failure_backoff=900,
    )

    with pytest.raises(TimeoutError, match="hard attempt timeout"):
        dataconnect.DataConnectClient(cfg).query(
            "SELECT username FROM radius_authentications")

    assert connection.call_timeout == pytest.approx(100)


def test_schema_validation_is_not_mislabeled_as_reporting_activity():
    sql = """
        SELECT table_name, column_name
        FROM user_tab_columns
        WHERE table_name IN ('TACACS_AUTHENTICATION_LAST_TWO_DAYS',
                             'RADIUS_AUTHENTICATIONS')
    """

    assert dataconnect._query_view(sql) == "schema_metadata"


def test_catalog_query_uses_only_minimum_gap_not_reporting_duty(monkeypatch):
    connection = Connection()
    monkeypatch.setattr(dataconnect.oracledb, "connect", lambda **kwargs: connection)
    monotonic = iter((0.0, 0.0, 0.0, 0.0, 1.0))
    monkeypatch.setattr(dataconnect.time, "monotonic", lambda: next(monotonic))
    releases = []
    cfg = types.SimpleNamespace(
        dataconnect_host="mnt.example.mil", dataconnect_port=2484,
        dataconnect_service="cpm10", dataconnect_user="dataconnect",
        dataconnect_password="secret", dataconnect_ca_bundle="",
        dataconnect_ssl_verify=False, dataconnect_query_timeout=12,
        dataconnect_min_query_interval_ms=5000,
        dataconnect_max_duty_cycle_percent=0.1,
        auth_failure_threshold=3, auth_failure_backoff=900,
    )
    client = dataconnect.DataConnectClient(cfg)
    monkeypatch.setattr(client, "_shared_gate", lambda **kwargs: 123)
    monkeypatch.setattr(
        client, "_release_shared_gate", lambda descriptor, deadline:
        releases.append((descriptor, deadline)))
    monkeypatch.setattr(dataconnect.time, "time", lambda: 100.0)

    client.query_catalog("SELECT column_name FROM user_tab_columns")

    assert client._next_query_at == pytest.approx(6.0)
    assert releases == [(123, pytest.approx(105.0))]


@pytest.mark.parametrize("sql", (
    "SELECT * FROM radius_authentications",
    "SELECT * FROM user_tab_columns JOIN radius_authentications ON 1 = 1",
    "DELETE FROM user_tab_columns",
))
def test_catalog_query_cannot_bypass_reporting_duty_cycle(sql):
    cfg = types.SimpleNamespace(
        dataconnect_host="mnt", dataconnect_port=2484, dataconnect_service="cpm10",
        dataconnect_user="reader", dataconnect_password="secret",
        dataconnect_ca_bundle="", dataconnect_ssl_verify=False,
        dataconnect_query_timeout=15,
    )
    client = dataconnect.DataConnectClient(cfg)

    with pytest.raises(ValueError, match="allowed dictionary view"):
        client.query_catalog(sql)


def test_catalog_crash_lease_is_bounded_to_metadata_attempt(monkeypatch, tmp_path):
    path = tmp_path / "dataconnect.pacing"
    monkeypatch.setattr(dataconnect.time, "time", lambda: 100.0)
    cfg = types.SimpleNamespace(
        dataconnect_host="mnt", dataconnect_port=2484, dataconnect_service="cpm10",
        dataconnect_user="reader", dataconnect_password="secret",
        dataconnect_ca_bundle="", dataconnect_ssl_verify=False,
        dataconnect_query_timeout=15, dataconnect_shared_pacing_file=str(path),
    )
    client = dataconnect.DataConnectClient(cfg)

    descriptor = client._shared_gate(adaptive_duty=False)
    try:
        assert float(path.read_text().strip()) == pytest.approx(160.0)
    finally:
        client._release_shared_gate(descriptor, 0)


def test_radius_summary_has_its_own_bounded_telemetry_label():
    assert dataconnect._query_view(
        "SELECT SUM(passed_count) FROM radius_authentication_summary"
    ) == "radius_authentication_summary"


def test_combined_freshness_probe_has_its_own_bounded_telemetry_label():
    sql = """/* ise_exporter:dataconnect_freshness */
        SELECT * FROM tacacs_authentication_last_two_days
        UNION ALL SELECT * FROM radius_authentications
    """

    assert dataconnect._query_view(sql) == "freshness_probe"


def test_adaptive_pacing_wait_is_interruptible_during_shutdown():
    cfg = types.SimpleNamespace(
        dataconnect_host="mnt.example.mil", dataconnect_port=2484,
        dataconnect_service="cpm10", dataconnect_user="dataconnect",
        dataconnect_password="secret", dataconnect_ca_bundle="",
        dataconnect_ssl_verify=False, dataconnect_query_timeout=12,
        auth_failure_threshold=3, auth_failure_backoff=900,
    )
    shutdown = threading.Event()
    client = dataconnect.DataConnectClient(cfg)
    client.set_shutdown_event(shutdown)
    shutdown.set()

    with pytest.raises(RuntimeError, match="cancelled during exporter shutdown"):
        client._wait(3600)


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


def test_shared_pacing_gate_inherits_state_directory_group(monkeypatch, tmp_path):
    cfg = types.SimpleNamespace(
        dataconnect_host="mnt", dataconnect_port=2484, dataconnect_service="cpm10",
        dataconnect_user="reader", dataconnect_password="secret",
        dataconnect_ca_bundle="", dataconnect_ssl_verify=False,
        dataconnect_query_timeout=15, dataconnect_shared_pacing_file=str(
            tmp_path / "dataconnect.pacing"),
    )
    client = dataconnect.DataConnectClient(cfg)
    calls = []
    real_fchown = dataconnect.os.fchown

    def record_fchown(descriptor, uid, gid):
        calls.append((uid, gid))
        real_fchown(descriptor, uid, gid)

    monkeypatch.setattr(dataconnect.os, "fchown", record_fchown)
    descriptor = client._shared_gate()
    client._release_shared_gate(descriptor, 0)

    assert calls == [(-1, tmp_path.stat().st_gid)]


def test_shared_pacing_gate_publishes_crash_safe_lease_before_query(
        monkeypatch, tmp_path):
    path = tmp_path / "dataconnect.pacing"
    monkeypatch.setattr(dataconnect.time, "time", lambda: 100.0)
    cfg = types.SimpleNamespace(
        dataconnect_host="mnt", dataconnect_port=2484, dataconnect_service="cpm10",
        dataconnect_user="reader", dataconnect_password="secret",
        dataconnect_ca_bundle="", dataconnect_ssl_verify=False,
        dataconnect_query_timeout=15, dataconnect_shared_pacing_file=str(path),
    )
    client = dataconnect.DataConnectClient(cfg)

    descriptor = client._shared_gate()
    try:
        deadline = float(path.read_text().strip())
        expected_cooldown = (
            dataconnect.MAX_STATEMENT_TIMEOUT_PERIODS * client.timeout
            * (100 / client.max_duty_cycle - 1))
        assert deadline == pytest.approx(100.0 + expected_cooldown)
    finally:
        client._release_shared_gate(descriptor, 0)


def test_shared_pacing_gate_rejects_non_regular_file(tmp_path):
    if not hasattr(os, "mkfifo"):
        pytest.skip("FIFO support unavailable")
    path = tmp_path / "dataconnect.pacing"
    os.mkfifo(path)
    cfg = types.SimpleNamespace(
        dataconnect_host="mnt", dataconnect_port=2484, dataconnect_service="cpm10",
        dataconnect_user="reader", dataconnect_password="secret",
        dataconnect_ca_bundle="", dataconnect_ssl_verify=False,
        dataconnect_query_timeout=15, dataconnect_shared_pacing_file=str(path),
    )

    with pytest.raises(RuntimeError, match="not a regular file"):
        dataconnect.DataConnectClient(cfg)._shared_gate()


@pytest.mark.parametrize("state", (b"nan\n", b"inf\n", b"-1\n", b"1\xff\n", b"1" * 65))
def test_shared_pacing_gate_rejects_corrupt_deadline_state(tmp_path, state):
    path = tmp_path / "dataconnect.pacing"
    path.write_bytes(state)
    cfg = types.SimpleNamespace(
        dataconnect_host="mnt", dataconnect_port=2484, dataconnect_service="cpm10",
        dataconnect_user="reader", dataconnect_password="secret",
        dataconnect_ca_bundle="", dataconnect_ssl_verify=False,
        dataconnect_query_timeout=15, dataconnect_shared_pacing_file=str(path),
    )

    with pytest.raises(RuntimeError, match="shared pacing gate unavailable"):
        dataconnect.DataConnectClient(cfg)._shared_gate()


def test_shared_pacing_gate_rejects_implausibly_distant_deadline(
        monkeypatch, tmp_path):
    path = tmp_path / "dataconnect.pacing"
    path.write_text(str(dataconnect.MAX_SHARED_PACING_FUTURE_SECONDS + 101))
    monkeypatch.setattr(dataconnect.time, "time", lambda: 100.0)
    cfg = types.SimpleNamespace(
        dataconnect_host="mnt", dataconnect_port=2484, dataconnect_service="cpm10",
        dataconnect_user="reader", dataconnect_password="secret",
        dataconnect_ca_bundle="", dataconnect_ssl_verify=False,
        dataconnect_query_timeout=15, dataconnect_shared_pacing_file=str(path),
    )

    with pytest.raises(RuntimeError, match="implausibly far in the future"):
        dataconnect.DataConnectClient(cfg)._shared_gate()


def test_shared_pacing_deadline_cannot_strand_collection_for_a_year():
    assert dataconnect.MAX_SHARED_PACING_FUTURE_SECONDS == 36 * 86400


def test_shared_pacing_lock_wait_is_interruptible_during_shutdown(tmp_path):
    path = tmp_path / "dataconnect.pacing"
    owner = path.open("w+")
    fcntl.flock(owner.fileno(), fcntl.LOCK_EX)
    cfg = types.SimpleNamespace(
        dataconnect_host="mnt.example.mil", dataconnect_port=2484,
        dataconnect_service="cpm10", dataconnect_user="dataconnect",
        dataconnect_password="secret", dataconnect_ca_bundle="",
        dataconnect_ssl_verify=False, dataconnect_query_timeout=12,
        dataconnect_min_query_interval_ms=500,
        dataconnect_shared_pacing_file=str(path),
        auth_failure_threshold=3, auth_failure_backoff=900,
    )
    shutdown = threading.Event()
    shutdown.set()
    client = dataconnect.DataConnectClient(cfg)
    client.set_shutdown_event(shutdown)

    try:
        with pytest.raises(RuntimeError, match="cancelled during exporter shutdown"):
            client._shared_gate()
    finally:
        fcntl.flock(owner.fileno(), fcntl.LOCK_UN)
        owner.close()


def test_completion_query_does_not_wait_for_local_cooldown(monkeypatch):
    cfg = types.SimpleNamespace(
        dataconnect_host="mnt.example.mil", dataconnect_port=2484,
        dataconnect_service="cpm10", dataconnect_user="dataconnect",
        dataconnect_password="secret", dataconnect_ca_bundle="",
        dataconnect_ssl_verify=False, dataconnect_query_timeout=12,
        auth_failure_threshold=3, auth_failure_backoff=900,
    )
    client = dataconnect.DataConnectClient(cfg)
    client._next_query_at = dataconnect.time.monotonic() + 3600
    monkeypatch.setattr(client, "_wait", lambda _seconds: pytest.fail("completion waited"))
    monkeypatch.setattr(
        client, "_shared_gate", lambda **_kwargs: pytest.fail("gate was acquired"))

    assert client.query_if_ready("SELECT username FROM radius_authentications") is None


def test_completion_query_does_not_wait_for_shared_gate(monkeypatch, tmp_path):
    path = tmp_path / "dataconnect.pacing"
    owner = path.open("w+")
    fcntl.flock(owner.fileno(), fcntl.LOCK_EX)
    cfg = types.SimpleNamespace(
        dataconnect_host="mnt.example.mil", dataconnect_port=2484,
        dataconnect_service="cpm10", dataconnect_user="dataconnect",
        dataconnect_password="secret", dataconnect_ca_bundle="",
        dataconnect_ssl_verify=False, dataconnect_query_timeout=12,
        dataconnect_shared_pacing_file=str(path),
        auth_failure_threshold=3, auth_failure_backoff=900,
    )
    client = dataconnect.DataConnectClient(cfg)
    monkeypatch.setattr(
        dataconnect.oracledb, "connect", lambda **_kwargs: pytest.fail("Oracle queried"))

    try:
        assert client.query_if_ready(
            "SELECT username FROM radius_authentications") is None
    finally:
        fcntl.flock(owner.fileno(), fcntl.LOCK_UN)
        owner.close()


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
        client, "_shared_gate", lambda **_kwargs: (_ for _ in ()).throw(
            RuntimeError("shared pacing gate unavailable")))
    counter = metrics.ise_dataconnect_queries_total.labels(
        view="radius_authentications", result="error")
    before = counter._value.get()
    metrics.ise_dataconnect_query_rows.labels(
        view="radius_authentications").set(7)

    with pytest.raises(RuntimeError, match="shared pacing gate unavailable"):
        client.query("SELECT username FROM radius_authentications")

    assert counter._value.get() == before + 1
    assert metrics.ise_dataconnect_query_rows.labels(
        view="radius_authentications")._value.get() == 0
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
    monkeypatch.setattr(client, "_shared_gate", lambda **_kwargs: 123)
    monkeypatch.setattr(
        client, "_release_shared_gate", lambda *_: (_ for _ in ()).throw(
            OSError("pacing deadline write failed")))
    success = metrics.ise_dataconnect_queries_total.labels(
        view="radius_authentications", result="success")
    errors = metrics.ise_dataconnect_queries_total.labels(
        view="radius_authentications", result="error")
    success_before = success._value.get()
    errors_before = errors._value.get()
    metrics.ise_dataconnect_query_rows.labels(
        view="radius_authentications").set(7)

    with pytest.raises(OSError, match="pacing deadline write failed"):
        client.query("SELECT username FROM radius_authentications")

    assert success._value.get() == success_before
    assert errors._value.get() == errors_before + 1
    assert metrics.ise_dataconnect_query_rows.labels(
        view="radius_authentications")._value.get() == 0


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


def test_authentication_backoff_survives_processes_and_cli_invocations(
        monkeypatch, tmp_path):
    attempts = 0
    path = tmp_path / "dataconnect-auth.guard"

    def fail(**_kwargs):
        nonlocal attempts
        attempts += 1
        raise RuntimeError("ORA-01017: invalid username/password")

    monkeypatch.setattr(dataconnect.oracledb, "connect", fail)
    monkeypatch.setattr(dataconnect.time, "time", lambda: 1_000.0)
    cfg = types.SimpleNamespace(
        dataconnect_host="mnt2.example.mil", dataconnect_port=2484,
        dataconnect_service="cpm10", dataconnect_user="dataconnect",
        dataconnect_password="must-not-persist", dataconnect_ca_bundle="",
        dataconnect_ssl_verify=False, dataconnect_query_timeout=12,
        dataconnect_auth_guard_file=str(path),
        auth_failure_threshold=2, auth_failure_backoff=900,
    )

    with pytest.raises(RuntimeError, match="ORA-01017"):
        dataconnect.DataConnectClient(cfg).connect()
    with pytest.raises(RuntimeError, match="ORA-01017"):
        dataconnect.DataConnectClient(cfg).connect()
    with pytest.raises(RuntimeError, match="shared authentication guard"):
        dataconnect.DataConnectClient(cfg).connect()

    assert attempts == 2
    assert path.stat().st_mode & 0o777 == 0o660
    assert "must-not-persist" not in path.read_text()


def test_dataconnect_auth_guard_is_scoped_to_oracle_target(tmp_path):
    path = tmp_path / "dataconnect-auth.guard"
    base = dict(
        dataconnect_host="mnt2.example.mil", dataconnect_port=2484,
        dataconnect_service="cpm10", dataconnect_user="dataconnect",
        dataconnect_password="secret", dataconnect_ca_bundle="",
        dataconnect_ssl_verify=False, dataconnect_query_timeout=12,
        dataconnect_auth_guard_file=str(path),
        auth_failure_threshold=1, auth_failure_backoff=900,
    )
    first = dataconnect.DataConnectClient(types.SimpleNamespace(**base))
    first._auth_guard.failure(1, 900, 1_000)
    changed = dataconnect.DataConnectClient(types.SimpleNamespace(**{
        **base, "dataconnect_host": "replacement-mnt.example.mil",
    }))

    assert first._auth_guard.blocked(1_001) is True
    assert changed._auth_guard.blocked(1_001) is False


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

        def size(self):
            return len(self.value)

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


def test_query_refuses_to_materialize_more_than_hard_result_ceiling(monkeypatch):
    class UnboundedCursor(Cursor):
        def fetchmany(self, size):
            return [(f"user-{index}", index) for index in range(size)]

    class UnboundedConnection(Connection):
        def cursor(self):
            return UnboundedCursor()

    connection = UnboundedConnection()
    monkeypatch.setattr(dataconnect.oracledb, "connect", lambda **kwargs: connection)
    cfg = types.SimpleNamespace(
        dataconnect_host="mnt.example", dataconnect_port=2484,
        dataconnect_service="cpm10", dataconnect_user="dataconnect",
        dataconnect_password="secret", dataconnect_ca_bundle="",
        dataconnect_ssl_verify=False, dataconnect_query_timeout=12,
        auth_failure_threshold=3, auth_failure_backoff=900,
    )
    client = dataconnect.DataConnectClient(cfg)
    counter = metrics.ise_dataconnect_queries_total.labels(
        view="endpoints_data", result="error")
    before = counter._value.get()
    metrics.ise_dataconnect_query_rows.labels(view="endpoints_data").set(7)

    with pytest.raises(RuntimeError, match="5000-row safety ceiling"):
        client.query("SELECT fields FROM endpoints_data")

    assert connection.closed is True
    assert counter._value.get() == before + 1
    assert metrics.ise_dataconnect_query_rows.labels(
        view="endpoints_data")._value.get() == 0


def test_query_rejects_oversized_lob_before_reading_it(monkeypatch):
    class OversizedLob:
        read_called = False

        def size(self):
            return dataconnect.MAX_FIELD_BYTES + 1

        def read(self):
            self.read_called = True
            return "should not be read"

    lob = OversizedLob()

    class LobCursor(Cursor):
        description = [types.SimpleNamespace(name="CUSTOM_ATTRIBUTES")]

        def fetchmany(self, size):
            del size
            if getattr(self, "returned", False):
                return []
            self.returned = True
            return [(lob,)]

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

    with pytest.raises(RuntimeError, match="field exceeded"):
        dataconnect.DataConnectClient(cfg).query("SELECT custom_attributes FROM endpoints_data")

    assert lob.read_called is False


def test_query_rejects_unsized_lob_before_reading_it(monkeypatch):
    class UnsizedLob:
        read_called = False

        def read(self):
            self.read_called = True
            return "should not be read"

    lob = UnsizedLob()

    class LobCursor(Cursor):
        description = [types.SimpleNamespace(name="CUSTOM_ATTRIBUTES")]

        def fetchmany(self, size):
            del size
            if getattr(self, "returned", False):
                return []
            self.returned = True
            return [(lob,)]

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

    with pytest.raises(RuntimeError, match="no bounded size metadata"):
        dataconnect.DataConnectClient(cfg).query(
            "SELECT custom_attributes FROM endpoints_data")

    assert lob.read_called is False


def test_nested_field_is_bounded_during_materialization(monkeypatch):
    monkeypatch.setattr(dataconnect, "MAX_FIELD_BYTES", 32)

    with pytest.raises(RuntimeError, match="nested field exceeded"):
        dataconnect._materialize(["x" * 16, "y" * 17])

    value = "leaf"
    for _index in range(dataconnect.MAX_FIELD_NESTING_DEPTH + 1):
        value = [value]
    with pytest.raises(RuntimeError, match="nesting ceiling"):
        dataconnect._materialize(value)


def test_query_caps_total_materialized_result_bytes(monkeypatch):
    monkeypatch.setattr(dataconnect, "MAX_RESULT_BYTES", 20)

    class PayloadCursor(Cursor):
        description = [types.SimpleNamespace(name="VALUE")]

        def fetchmany(self, size):
            del size
            if getattr(self, "returned", False):
                return []
            self.returned = True
            return [("a" * 20,)]

    class PayloadConnection(Connection):
        def cursor(self):
            return PayloadCursor()

    monkeypatch.setattr(
        dataconnect.oracledb, "connect", lambda **kwargs: PayloadConnection())
    cfg = types.SimpleNamespace(
        dataconnect_host="mnt.example", dataconnect_port=2484,
        dataconnect_service="cpm10", dataconnect_user="dataconnect",
        dataconnect_password="secret", dataconnect_ca_bundle="",
        dataconnect_ssl_verify=False, dataconnect_query_timeout=12,
        auth_failure_threshold=3, auth_failure_backoff=900,
    )

    with pytest.raises(RuntimeError, match="20-byte safety ceiling"):
        dataconnect.DataConnectClient(cfg).query("SELECT value FROM endpoints_data")
