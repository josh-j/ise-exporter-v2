"""Read-only Cisco ISE Data Connect client.

Data Connect is Oracle-compatible SQL over TCPS on the MnT node. The exporter
queries Cisco reporting views read-only, with time-bounded event statements,
aggregated output, and a hard result-row ceiling.
"""
import base64
import fcntl
import logging
import os
import ssl
import stat
import threading
import time

import oracledb

from .. import metrics

logger = logging.getLogger(__name__)

# This matches the operator CLI's absolute row limit and is five times larger
# than any scheduled top-K result. Even if a SQL/view contract regresses, the
# exporter will not materialize an unbounded slice of the MnT database.
MAX_RESULT_ROWS = 5000
FETCH_BATCH_ROWS = 100
MAX_FIELD_BYTES = 1024 * 1024
MAX_RESULT_BYTES = 64 * 1024 * 1024


_QUERY_VIEWS = (
    "tacacs_authentication_last_two_days",
    "tacacs_authorization_last_two_days",
    "tacacs_accounting_last_two_days",
    "posture_assessment_by_condition",
    "posture_assessment_by_endpoint",
    "profiled_endpoints_summary",
    "radius_authentication_summary",
    "radius_authentications",
    "radius_accounting",
    "radius_errors_view",
    "key_performance_metrics",
    "system_diagnostics_view",
    "aaa_diagnostics_view",
    "system_summary",
    "endpoints_data",
)


def _query_view(sql):
    """Return a bounded metric label; never put arbitrary SQL into Prometheus."""
    normalized = str(sql or "").lower()
    # Schema validation embeds every reporting view name in an IN clause. Classify
    # metadata access before scanning those literals or startup looks like a real
    # query against whichever reporting view happens to appear first.
    if "user_tab_columns" in normalized:
        return "schema_metadata"
    for view in _QUERY_VIEWS:
        if view in normalized:
            return view
    return "other"


def _materialize(value):
    """Convert Oracle LOB/binary values into deterministic CLI-safe data."""
    if hasattr(value, "read") and callable(value.read):
        size = getattr(value, "size", None)
        if callable(size) and int(size()) > MAX_FIELD_BYTES:
            raise RuntimeError(
                f"Data Connect field exceeded the hard {MAX_FIELD_BYTES}-byte safety ceiling")
        value = value.read()
    if isinstance(value, memoryview):
        value = value.tobytes()
    if isinstance(value, bytes):
        if len(value) > MAX_FIELD_BYTES:
            raise RuntimeError(
                f"Data Connect field exceeded the hard {MAX_FIELD_BYTES}-byte safety ceiling")
        return "base64:" + base64.b64encode(value).decode("ascii")
    if isinstance(value, str) and len(value.encode("utf-8")) > MAX_FIELD_BYTES:
        raise RuntimeError(
            f"Data Connect field exceeded the hard {MAX_FIELD_BYTES}-byte safety ceiling")
    if isinstance(value, list):
        return [_materialize(item) for item in value]
    if isinstance(value, dict):
        return {key: _materialize(item) for key, item in value.items()}
    return value


def _materialized_size(value):
    """Approximate retained result bytes after deterministic materialization."""
    if value is None:
        return 0
    if isinstance(value, str):
        return len(value.encode("utf-8"))
    if isinstance(value, (bytes, bytearray, memoryview)):
        return len(value)
    if isinstance(value, dict):
        return sum(_materialized_size(key) + _materialized_size(item)
                   for key, item in value.items())
    if isinstance(value, (list, tuple)):
        return sum(_materialized_size(item) for item in value)
    return 8


def _retryable_disconnect(error):
    message = str(error).upper()
    return any(code in message for code in (
        "ORA-02399", "ORA-03113", "ORA-03114", "ORA-03135",
        "DPY-1001", "DPY-4010", "DPY-4011",
    ))


class DataConnectClient:
    def __init__(self, cfg):
        self.host = cfg.dataconnect_host
        self.port = cfg.dataconnect_port
        self.service = cfg.dataconnect_service
        self.user = cfg.dataconnect_user
        self.password = cfg.dataconnect_password
        self.ca_bundle = cfg.dataconnect_ca_bundle
        self.verify = cfg.dataconnect_ssl_verify
        self.timeout = max(1, cfg.dataconnect_query_timeout)
        self.failure_threshold = max(1, getattr(cfg, "auth_failure_threshold", 3))
        self.failure_backoff = max(0, getattr(cfg, "auth_failure_backoff", 900))
        # These are hard client invariants, not only environment-parser defaults.
        # CLI/tests/extensions can construct a client from another config object;
        # none may silently relax the production database-pressure ceiling.
        self.min_query_interval = max(
            2.0, getattr(cfg, "dataconnect_min_query_interval_ms", 2000) / 1000.0)
        self.max_duty_cycle = max(0.1, min(0.5, float(getattr(
            cfg, "dataconnect_max_duty_cycle_percent", 0.5))))
        self.shared_pacing_file = str(getattr(
            cfg, "dataconnect_shared_pacing_file", "") or "")
        self._connection = None
        self._connect_failures = 0
        self._blocked_until = 0.0
        self._next_query_at = 0.0
        self._shutdown = None
        metrics.ise_dataconnect_query_pacing_seconds.set(self.min_query_interval)

    def set_shutdown_event(self, shutdown):
        """Make long adaptive pacing waits interruptible during service stop."""
        if shutdown is not None and not isinstance(shutdown, threading.Event):
            raise TypeError("shutdown must be a threading.Event")
        self._shutdown = shutdown

    def _wait(self, seconds):
        if seconds <= 0:
            return
        if self._shutdown is not None:
            if self._shutdown.wait(seconds):
                raise RuntimeError("Data Connect query cancelled during exporter shutdown")
        else:
            time.sleep(seconds)

    def _shared_gate(self):
        """Serialize and pace queries across exporter and CLI processes.

        The installed service and authorized CLI operators share this small lock
        file. Refusing an inaccessible configured gate is safer than silently
        allowing parallel production queries.
        """
        if not self.shared_pacing_file:
            return None
        path = os.path.abspath(os.path.expanduser(self.shared_pacing_file))
        try:
            descriptor = os.open(
                path,
                os.O_RDWR | os.O_CREAT | getattr(os, "O_CLOEXEC", 0)
                | getattr(os, "O_NOFOLLOW", 0),
                0o660,
            )
            metadata = os.fstat(descriptor)
            if not stat.S_ISREG(metadata.st_mode):
                raise OSError("pacing gate is not a regular file")
            if metadata.st_uid == os.geteuid():
                # Authorized CLI users may create the gate before the service.
                # Match the state directory's group explicitly in addition to
                # requiring setgid deployment directories, so both processes
                # retain access regardless of the creator's primary group.
                os.fchown(descriptor, -1, os.stat(os.path.dirname(path)).st_gid)
                os.fchmod(descriptor, 0o660)
            # A blocking flock cannot be interrupted by threading.Event. That
            # matters when another CLI process owns the gate through a long
            # adaptive cooldown: service shutdown must not wait minutes for the
            # kernel lock. Poll non-blocking acquisition through the same
            # cancellable wait used by local pacing.
            while True:
                try:
                    fcntl.flock(descriptor, fcntl.LOCK_EX | fcntl.LOCK_NB)
                    break
                except BlockingIOError:
                    self._wait(0.25)
            raw = os.read(descriptor, 64).decode("ascii", "ignore").strip()
            deadline = float(raw) if raw else 0.0
            remaining = deadline - time.time()
            if remaining > 0:
                self._wait(remaining)
            # Persist a conservative lease *before* Oracle work begins. A normal
            # completion replaces it with the measured duty-cycle cooldown, but
            # SIGKILL, host loss, or interpreter failure cannot release the flock
            # and leave the next process free to hit a large MnT immediately.
            worst_case_duration = 2 * self.timeout  # one reconnect is permitted
            crash_cooldown = max(
                self.min_query_interval,
                worst_case_duration * (100 / self.max_duty_cycle - 1),
            )
            self._write_shared_deadline(
                descriptor, time.time() + crash_cooldown)
            return descriptor
        except Exception as error:
            try:
                os.close(descriptor)
            except (NameError, OSError):
                pass
            raise RuntimeError(
                f"Data Connect shared pacing gate unavailable at {path}: {error}") from error

    @staticmethod
    def _write_shared_deadline(descriptor, deadline):
        os.lseek(descriptor, 0, os.SEEK_SET)
        os.ftruncate(descriptor, 0)
        os.write(descriptor, f"{deadline:.6f}\n".encode("ascii"))
        os.fsync(descriptor)

    @classmethod
    def _release_shared_gate(cls, descriptor, deadline):
        if descriptor is None:
            return
        try:
            cls._write_shared_deadline(descriptor, deadline)
        finally:
            fcntl.flock(descriptor, fcntl.LOCK_UN)
            os.close(descriptor)

    def _ssl_context(self):
        if not self.verify:
            return ssl._create_unverified_context()
        return ssl.create_default_context(cafile=self.ca_bundle or None)

    def connect(self):
        if self._connection is None:
            remaining = self._blocked_until - time.monotonic()
            if remaining > 0:
                raise RuntimeError(
                    f"Data Connect reconnect suppressed for {remaining:.0f}s after "
                    f"{self._connect_failures} connection failures")
            try:
                self._connection = oracledb.connect(
                    user=self.user, password=self.password, host=self.host,
                    port=self.port, service_name=self.service, protocol="tcps",
                    ssl_context=self._ssl_context(), ssl_server_dn_match=self.verify,
                    tcp_connect_timeout=self.timeout,
                )
            except Exception:
                self._connect_failures += 1
                if self._connect_failures >= self.failure_threshold:
                    self._blocked_until = time.monotonic() + self.failure_backoff
                raise
            self._connect_failures = 0
            self._blocked_until = 0.0
            self._connection.call_timeout = self.timeout * 1000
        return self._connection

    def query(self, sql, parameters=None):
        remaining = self._next_query_at - time.monotonic()
        if remaining > 0:
            self._wait(remaining)
        attempt_started = time.monotonic()
        shared_gate = None
        started = None
        view = _query_view(sql)
        result = "error"
        try:
            shared_gate = self._shared_gate()
            started = time.monotonic()
            for attempt in range(2):
                try:
                    with self.connect().cursor() as cursor:
                        cursor.execute(sql, parameters or {})
                        columns = [column.name.lower() for column in cursor.description]
                        rows = []
                        result_bytes = 0
                        while True:
                            batch = cursor.fetchmany(FETCH_BATCH_ROWS)
                            if not batch:
                                break
                            for raw_row in batch:
                                if len(rows) >= MAX_RESULT_ROWS:
                                    raise RuntimeError(
                                        f"Data Connect result exceeded the hard "
                                        f"{MAX_RESULT_ROWS}-row safety ceiling")
                                row = dict(zip(
                                    columns, (_materialize(value) for value in raw_row)))
                                result_bytes += _materialized_size(row)
                                if result_bytes > MAX_RESULT_BYTES:
                                    raise RuntimeError(
                                        f"Data Connect result exceeded the hard "
                                        f"{MAX_RESULT_BYTES}-byte safety ceiling")
                                rows.append(row)
                    result = "success"
                    metrics.ise_dataconnect_query_rows.labels(view=view).set(len(rows))
                    return rows
                except Exception as error:
                    # ISE expires otherwise healthy Data Connect sessions after a
                    # fixed maximum connection lifetime. Reconnect once inside the
                    # same paced query so an idle period does not cost a full
                    # scheduler interval. Authentication/query errors are never retried.
                    try:
                        self.close()
                    except Exception:
                        pass
                    if attempt == 0 and _retryable_disconnect(error):
                        logger.info("Data Connect session expired; reconnecting once")
                        continue
                    raise
        finally:
            finished = time.monotonic()
            duration = max(0.0, finished - (
                started if started is not None else attempt_started))
            duty_cycle_cooldown = duration * (100 / self.max_duty_cycle - 1)
            cooldown = max(self.min_query_interval, duty_cycle_cooldown)
            metrics.ise_dataconnect_query_cooldown_seconds.labels(view=view).set(cooldown)
            self._next_query_at = finished + cooldown
            query_failed = result == "error"
            try:
                self._release_shared_gate(shared_gate, time.time() + cooldown)
            except Exception:
                # A failed release means the cross-process safety deadline was
                # not durably published. Do not report an otherwise successful
                # database query as healthy. Preserve an existing query error,
                # which is more useful than masking it with cleanup failure.
                result = "error"
                if query_failed:
                    logger.exception(
                        "Data Connect shared pacing gate release also failed")
                else:
                    raise
            finally:
                metrics.ise_dataconnect_queries_total.labels(
                    view=view, result=result).inc()
                metrics.ise_dataconnect_query_duration_seconds.labels(
                    view=view, result=result).observe(duration)

    def close(self):
        if self._connection is not None:
            try:
                self._connection.close()
            finally:
                self._connection = None
