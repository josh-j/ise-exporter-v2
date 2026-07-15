"""Read-only Cisco ISE Data Connect client.

Data Connect is Oracle-compatible SQL over TCPS on the MnT node. The exporter
queries Cisco reporting views read-only, with time-bounded event statements,
aggregated output, and a hard result-row ceiling.
"""
import base64
import fcntl
import logging
import math
import os
import re
import ssl
import stat
import threading
import time

import oracledb

from .. import metrics
from ..auth_guard import PersistentAuthGuard
from ..compatibility import valid_hostname

logger = logging.getLogger(__name__)

# This matches the operator CLI's absolute row limit and is five times larger
# than any scheduled top-K result. Even if a SQL/view contract regresses, the
# exporter will not materialize an unbounded slice of the MnT database.
MAX_RESULT_ROWS = 5000
# Atomic scheduled domains intentionally contain several individually bounded
# top-K statements. At the supported 1,000-group ceiling, RADIUS can return
# 6,001 aggregate rows and TACACS 6,000; a 5,000-row whole-batch cap therefore
# rejected valid maximum collection. Keep each statement at 5,000 while allowing
# the complete fixed-size batch enough room without approaching snapshot limits.
MAX_BATCH_RESULT_ROWS = 10000
FETCH_BATCH_ROWS = 100
MAX_FIELD_BYTES = 1024 * 1024
MAX_RESULT_BYTES = 64 * 1024 * 1024
MAX_FIELD_NESTING_DEPTH = 16
MAX_BATCH_QUERIES = 5
RECOMMENDED_MIN_DUTY_CYCLE_PERCENT = 0.01
RECOMMENDED_MAX_DUTY_CYCLE_PERCENT = 0.1
# One statement may spend one timeout connecting and one executing, then repeat
# both after the single permitted disconnect retry. Crash leases must reserve
# all four periods because the flock disappears when the process dies.
MAX_STATEMENT_TIMEOUT_PERIODS = 4
# Five maximally slow statements at the 0.01% hard duty floor require just under
# 35 days of cooldown. Anything beyond 36 days cannot be produced by this client
# and is a stale/corrupt deadline or a corrected wall clock, not valid pacing.
MAX_SHARED_PACING_FUTURE_SECONDS = 36 * 86400
_PACING_BUSY = object()


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
    if "ise_exporter:dataconnect_freshness" in normalized:
        return "freshness_probe"
    # Schema validation embeds every reporting view name in an IN clause. Classify
    # metadata access before scanning those literals or startup looks like a real
    # query against whichever reporting view happens to appear first.
    if "user_tab_columns" in normalized or "user_views" in normalized:
        return "schema_metadata"
    for view in _QUERY_VIEWS:
        if view in normalized:
            return view
    return "other"


def _materialize(value, *, _depth=0):
    """Convert one Oracle field without expanding an unbounded nested value."""
    if _depth > MAX_FIELD_NESTING_DEPTH:
        raise RuntimeError(
            f"Data Connect field exceeded the hard "
            f"{MAX_FIELD_NESTING_DEPTH}-level nesting ceiling")
    if hasattr(value, "read") and callable(value.read):
        size = getattr(value, "size", None)
        if not callable(size):
            raise RuntimeError(
                "Data Connect LOB has no bounded size metadata; refusing to read it")
        if int(size()) > MAX_FIELD_BYTES:
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
        result = []
        retained = 0
        for item in value:
            materialized = _materialize(item, _depth=_depth + 1)
            retained += _materialized_size(materialized, _depth=_depth + 1)
            if retained > MAX_FIELD_BYTES:
                raise RuntimeError(
                    f"Data Connect nested field exceeded the hard "
                    f"{MAX_FIELD_BYTES}-byte safety ceiling")
            result.append(materialized)
        return result
    if isinstance(value, dict):
        result = {}
        retained = 0
        for key, item in value.items():
            materialized = _materialize(item, _depth=_depth + 1)
            retained += _materialized_size(key, _depth=_depth + 1)
            retained += _materialized_size(materialized, _depth=_depth + 1)
            if retained > MAX_FIELD_BYTES:
                raise RuntimeError(
                    f"Data Connect nested field exceeded the hard "
                    f"{MAX_FIELD_BYTES}-byte safety ceiling")
            result[key] = materialized
        return result
    return value


def _materialized_size(value, *, _depth=0):
    """Approximate retained result bytes after deterministic materialization."""
    if _depth > MAX_FIELD_NESTING_DEPTH:
        raise RuntimeError(
            f"Data Connect field exceeded the hard "
            f"{MAX_FIELD_NESTING_DEPTH}-level nesting ceiling")
    if value is None:
        return 0
    if isinstance(value, str):
        return len(value.encode("utf-8"))
    if isinstance(value, (bytes, bytearray, memoryview)):
        return len(value)
    if isinstance(value, dict):
        return sum(_materialized_size(key, _depth=_depth + 1)
                   + _materialized_size(item, _depth=_depth + 1)
                   for key, item in value.items())
    if isinstance(value, (list, tuple)):
        return sum(_materialized_size(item, _depth=_depth + 1) for item in value)
    return 8


def _retryable_disconnect(error):
    message = str(error).upper()
    return any(code in message for code in (
        "ORA-02399", "ORA-03113", "ORA-03114", "ORA-03135",
        "DPY-1001", "DPY-4010", "DPY-4011",
    ))


def _authentication_failure(error):
    message = str(error).upper()
    return any(marker in message for marker in (
        "ORA-01005", "ORA-01017", "ORA-28000", "ORA-28001", "DPY-4001",
        "INVALID CREDENTIAL", "INVALID USERNAME/PASSWORD",
    ))


class DataConnectClient:
    def __init__(self, cfg):
        if not valid_hostname(cfg.dataconnect_host):
            raise ValueError(
                "ISE_DATACONNECT_HOST must be a bare DNS hostname or IPv4 address")
        self.host = cfg.dataconnect_host
        self.port = cfg.dataconnect_port
        self.service = cfg.dataconnect_service
        self.user = cfg.dataconnect_user
        self.password = cfg.dataconnect_password
        self.ca_bundle = cfg.dataconnect_ca_bundle
        self.verify = cfg.dataconnect_ssl_verify
        # ``call_timeout`` is the last server-work boundary after SQL predicates.
        # Keep it hard here as well as in the environment parser: CLI callers,
        # tests, and integrations can construct Config-like objects directly.
        self.timeout = max(1, min(15, int(cfg.dataconnect_query_timeout)))
        self.failure_threshold = max(1, min(5, int(getattr(
            cfg, "auth_failure_threshold", 3))))
        self.failure_backoff = max(300, min(86400, int(getattr(
            cfg, "auth_failure_backoff", 900))))
        # Valid explicit pacing is operator-owned. Config warns when it falls
        # outside the production recommendation, but the runtime must not
        # silently replace a deliberately more conservative setting.
        self.min_query_interval = max(
            0.0, getattr(cfg, "dataconnect_min_query_interval_ms", 5000) / 1000.0)
        configured_duty = float(getattr(
            cfg, "dataconnect_max_duty_cycle_percent", 0.1))
        self.max_duty_cycle = configured_duty \
            if math.isfinite(configured_duty) and configured_duty > 0 else 0.1
        worst_case_batch = (
            MAX_BATCH_QUERIES * MAX_STATEMENT_TIMEOUT_PERIODS * self.timeout
            * max(0.0, 100 / self.max_duty_cycle - 1)
        )
        self.max_shared_pacing_future_seconds = max(
            MAX_SHARED_PACING_FUTURE_SECONDS, worst_case_batch + 86400)
        self.shared_pacing_file = str(getattr(
            cfg, "dataconnect_shared_pacing_file", "") or "")
        self._auth_guard = PersistentAuthGuard(
            getattr(cfg, "dataconnect_auth_guard_file", ""),
            (self.user, self.host, self.port, self.service),
            "Data Connect authentication",
        )
        self._connection = None
        self._connect_failures = 0
        self._blocked_until = 0.0
        self._next_query_at = 0.0
        self._shutdown = None
        self._batch_active = False
        self._batch_gate = None
        self._batch_duration = 0.0
        self._batch_views = []
        self._batch_rows = 0
        self._batch_result_bytes = 0
        self.schema = {}
        self.schema_ready = False
        self.dataset_schema_failures = {}
        metrics.ise_dataconnect_query_pacing_seconds.set(self.min_query_interval)
        metrics.ise_dataconnect_max_duty_cycle_percent.set(self.max_duty_cycle)
        metrics.ise_dataconnect_query_timeout_seconds.set(self.timeout)
        metrics.ise_dataconnect_result_row_ceiling.set(MAX_RESULT_ROWS)
        metrics.ise_dataconnect_result_byte_ceiling.set(MAX_RESULT_BYTES)

    def set_schema(self, schema, dataset_failures=None):
        """Retain startup-discovered view capabilities without another DB query."""
        if not isinstance(schema, dict):
            raise TypeError("Data Connect schema must be a table mapping")
        self.schema = {
            str(table).upper(): {
                str(column).upper(): str(data_type).upper()
                for column, data_type in columns.items()
            }
            for table, columns in schema.items()
            if isinstance(columns, dict)
        }
        self.dataset_schema_failures = dict(dataset_failures or {})
        self.schema_ready = True
        radius_columns = self.schema.get("RADIUS_AUTHENTICATIONS", {})
        if (radius_columns and "AUTHORIZATION_POLICY" not in radius_columns
                and "POLICY_SET_NAME" in radius_columns):
            logger.warning(
                "RADIUS_AUTHENTICATIONS has no optional AUTHORIZATION_POLICY column; "
                "using POLICY_SET_NAME for the authorization-policy metric dimension")
        elif (radius_columns and "AUTHORIZATION_POLICY" not in radius_columns
              and "POLICY_SET_NAME" not in radius_columns):
            logger.warning(
                "RADIUS_AUTHENTICATIONS has no optional authorization-policy column; "
                "using 'none' for the authorization-policy metric dimension")
        accounting_columns = self.schema.get("RADIUS_ACCOUNTING", {})
        if accounting_columns and "AUTHORIZATION_POLICY" not in accounting_columns:
            logger.warning(
                "RADIUS_ACCOUNTING has no optional AUTHORIZATION_POLICY column; "
                "using 'none' for the authorization-policy metric dimension")

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

    def _shared_gate(self, *, wait=True, adaptive_duty=True, view="other"):
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
            if metadata.st_size > 64:
                raise OSError("pacing gate state exceeds 64 bytes")
            if metadata.st_uid == os.geteuid():
                # Authorized CLI users may create the gate before the service.
                # Match the shared directory's group explicitly in addition to
                # requiring a setgid deployment directory, so both processes
                # retain access regardless of the creator's primary group.
                os.fchown(descriptor, -1, os.stat(os.path.dirname(path)).st_gid)
                os.fchmod(descriptor, 0o660)
            # A blocking flock cannot be interrupted by threading.Event. That
            # matters when another CLI process owns the gate through a long
            # adaptive cooldown: service shutdown must not wait minutes for the
            # kernel lock. Poll non-blocking acquisition through the same
            # cancellable wait used by local pacing.
            lock_wait_logged = False
            while True:
                try:
                    fcntl.flock(descriptor, fcntl.LOCK_EX | fcntl.LOCK_NB)
                    break
                except BlockingIOError:
                    if not wait:
                        os.close(descriptor)
                        return _PACING_BUSY
                    if not lock_wait_logged:
                        logger.info(
                            "Data Connect query waiting view=%s "
                            "reason=shared_gate_in_use resume=when_current_query_finishes",
                            view,
                        )
                        lock_wait_logged = True
                    self._wait(0.25)
            raw = os.read(descriptor, 64).decode("ascii").strip()
            deadline = float(raw) if raw else 0.0
            if not math.isfinite(deadline) or deadline < 0:
                raise OSError("pacing gate deadline is not a finite non-negative value")
            remaining = deadline - time.time()
            if remaining > self.max_shared_pacing_future_seconds:
                raise OSError("pacing gate deadline is implausibly far in the future")
            if remaining > 0 and adaptive_duty:
                if not wait:
                    fcntl.flock(descriptor, fcntl.LOCK_UN)
                    os.close(descriptor)
                    return _PACING_BUSY
                logger.info(
                    "Data Connect query waiting view=%s wait_seconds=%.1f "
                    "resume_at=%s reason=adaptive_duty_cycle_database_protection",
                    view,
                    remaining,
                    time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime(deadline)),
                )
                self._wait(remaining)
            # Persist a conservative lease *before* Oracle work begins. A normal
            # completion replaces it with the measured duty-cycle cooldown, but
            # SIGKILL, host loss, or interpreter failure cannot release the flock
            # and leave the next process free to hit a large MnT immediately.
            # One reconnect is permitted for the immediately pending statement.
            # Multi-statement batches advance this lease before each later query.
            worst_case_duration = MAX_STATEMENT_TIMEOUT_PERIODS * self.timeout
            crash_cooldown = max(
                self.min_query_interval,
                (worst_case_duration * (100 / self.max_duty_cycle - 1)
                 if adaptive_duty else worst_case_duration),
            )
            lease_deadline = time.time() + crash_cooldown
            if not adaptive_duty:
                # Catalog metadata is bounded independently of reporting data.
                # It may validate a restarted exporter while an earlier reporting
                # query's adaptive cooldown remains active, but must never shorten
                # that cooldown for the reporting work queued behind it.
                lease_deadline = max(deadline, lease_deadline)
            self._write_shared_deadline(descriptor, lease_deadline)
            return (descriptor, deadline) if not adaptive_duty else descriptor
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
        preserved_deadline = 0.0
        if isinstance(descriptor, tuple):
            descriptor, preserved_deadline = descriptor
        try:
            cls._write_shared_deadline(descriptor, max(deadline, preserved_deadline))
        finally:
            fcntl.flock(descriptor, fcntl.LOCK_UN)
            os.close(descriptor)

    def _ssl_context(self):
        if not self.verify:
            return ssl._create_unverified_context()
        return ssl.create_default_context(cafile=self.ca_bundle or None)

    def connect(self):
        if self._connection is None:
            try:
                auth_blocked = self._auth_guard.blocked(time.time())
            except Exception as error:
                raise RuntimeError(
                    f"Data Connect authentication guard unavailable: {error}") from error
            if auth_blocked:
                raise RuntimeError(
                    "Data Connect reconnect suppressed by the shared authentication guard")
            remaining = self._blocked_until - time.monotonic()
            if remaining > 0:
                raise RuntimeError(
                    f"Data Connect reconnect suppressed for {remaining:.0f}s after "
                    f"{self._connect_failures} connection failures")
            try:
                connection = oracledb.connect(
                    user=self.user, password=self.password, host=self.host,
                    port=self.port, service_name=self.service, protocol="tcps",
                    ssl_context=self._ssl_context(), ssl_server_dn_match=self.verify,
                    tcp_connect_timeout=self.timeout,
                )
                connection.call_timeout = self.timeout * 1000
                # A bounded aggregate result can still consume disproportionate
                # cluster resources if Oracle parallelizes the underlying reporting
                # view scan. Data Connect is monitoring, never a batch workload.
                with connection.cursor() as cursor:
                    cursor.execute("ALTER SESSION DISABLE PARALLEL QUERY", {})
            except Exception as error:
                try:
                    connection.close()
                except Exception:
                    pass
                self._connect_failures += 1
                if self._connect_failures >= self.failure_threshold:
                    self._blocked_until = time.monotonic() + self.failure_backoff
                if _authentication_failure(error):
                    self._auth_guard.failure(
                        self.failure_threshold, self.failure_backoff, time.time())
                raise
            try:
                self._auth_guard.success()
            except Exception:
                connection.close()
                raise
            self._connection = connection
            self._connect_failures = 0
            self._blocked_until = 0.0
        return self._connection

    @staticmethod
    def _apply_attempt_timeout(connection, deadline):
        """Bound all Oracle round trips to one total per-attempt time budget."""
        remaining = deadline - time.perf_counter()
        if remaining <= 0:
            raise TimeoutError("Data Connect query exceeded the hard attempt timeout")
        connection.call_timeout = max(1, math.ceil(remaining * 1000))

    def _query(self, sql, parameters=None, *, wait_for_pacing=True,
               adaptive_duty=True):
        view = _query_view(sql)
        if not self._batch_active:
            remaining = self._next_query_at - time.monotonic()
            if remaining > 0:
                if not wait_for_pacing:
                    return None
                logger.info(
                    "Data Connect query waiting view=%s wait_seconds=%.1f "
                    "reason=local_duty_cycle_database_protection",
                    view,
                    remaining,
                )
                self._wait(remaining)
        attempt_started = time.monotonic()
        shared_gate = self._batch_gate
        started = None
        result = "error"
        try:
            if not self._batch_active:
                shared_gate = self._shared_gate(
                    wait=wait_for_pacing, adaptive_duty=adaptive_duty, view=view)
        except Exception:
            finished = time.monotonic()
            duration = max(0.0, finished - attempt_started)
            cooldown = max(
                self.min_query_interval,
                (duration * (100 / self.max_duty_cycle - 1)
                 if adaptive_duty else duration),
            )
            self._next_query_at = finished + cooldown
            metrics.ise_dataconnect_query_cooldown_seconds.labels(view=view).set(cooldown)
            metrics.ise_dataconnect_queries_total.labels(
                view=view, result="error").inc()
            metrics.ise_dataconnect_query_duration_seconds.labels(
                view=view, result="error").observe(duration)
            metrics.ise_dataconnect_query_last_duration_seconds.labels(
                view=view, result="error").set(duration)
            metrics.ise_dataconnect_query_rows.labels(view=view).set(0)
            raise
        if shared_gate is _PACING_BUSY:
            return None
        try:
            started = time.monotonic()
            for attempt in range(2):
                try:
                    connection = self.connect()
                    deadline = time.perf_counter() + self.timeout
                    with connection.cursor() as cursor:
                        self._apply_attempt_timeout(connection, deadline)
                        cursor.execute(sql, parameters or {})
                        columns = [column.name.lower() for column in cursor.description]
                        rows = []
                        result_bytes = 0
                        while True:
                            self._apply_attempt_timeout(connection, deadline)
                            batch = cursor.fetchmany(FETCH_BATCH_ROWS)
                            if not batch:
                                break
                            for raw_row in batch:
                                if len(rows) >= MAX_RESULT_ROWS:
                                    raise RuntimeError(
                                        f"Data Connect result exceeded the hard "
                                        f"{MAX_RESULT_ROWS}-row safety ceiling")
                                if (self._batch_active
                                        and self._batch_rows + len(rows)
                                        >= MAX_BATCH_RESULT_ROWS):
                                    raise RuntimeError(
                                        f"Data Connect batch exceeded the hard "
                                        f"{MAX_BATCH_RESULT_ROWS}-row safety ceiling")
                                row = dict(zip(
                                    columns, (_materialize(value) for value in raw_row)))
                                result_bytes += _materialized_size(row)
                                retained_bytes = (
                                    self._batch_result_bytes if self._batch_active else 0)
                                if retained_bytes + result_bytes > MAX_RESULT_BYTES:
                                    raise RuntimeError(
                                        f"Data Connect result exceeded the hard "
                                        f"{MAX_RESULT_BYTES}-byte safety ceiling")
                                rows.append(row)
                    result = "success"
                    if self._batch_active:
                        self._batch_rows += len(rows)
                        self._batch_result_bytes += result_bytes
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
            if self._batch_active:
                self._batch_duration += duration
                self._batch_views.append(view)
                cooldown = None
            else:
                duty_cycle_cooldown = (
                    duration * (100 / self.max_duty_cycle - 1)
                    if adaptive_duty else duration)
                cooldown = max(self.min_query_interval, duty_cycle_cooldown)
                metrics.ise_dataconnect_query_cooldown_seconds.labels(
                    view=view).set(cooldown)
                self._next_query_at = finished + cooldown
            query_failed = result == "error"
            try:
                if not self._batch_active:
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
                metrics.ise_dataconnect_query_last_duration_seconds.labels(
                    view=view, result=result).set(duration)
                if result == "error":
                    metrics.ise_dataconnect_query_rows.labels(view=view).set(0)

    def query_many(self, statements, parameters=None):
        """Run one small atomic domain batch under a single duty-cycle lease.

        Statements remain individually timeout- and result-bounded. The shared
        gate stays locked across fixed five-second-or-longer gaps, then publishes
        one cooldown based on total Oracle work. This makes multi-view snapshots
        achievable without increasing long-run database duty cycle.
        """
        items = list(statements.items())
        if not items:
            return {}
        if len(items) > MAX_BATCH_QUERIES:
            raise ValueError(
                f"Data Connect batch exceeds the hard {MAX_BATCH_QUERIES}-query ceiling")
        if self._batch_active:
            raise RuntimeError("nested Data Connect batches are not supported")
        remaining = self._next_query_at - time.monotonic()
        if remaining > 0:
            self._wait(remaining)
        # Acquire with a one-statement crash lease. The lease is advanced below
        # immediately before each later statement, so a kill early in the batch
        # cannot strand all Data Connect work behind a multi-day worst-case lease.
        views = ",".join(dict.fromkeys(_query_view(sql) for _name, sql in items))
        gate = self._shared_gate(view=views)
        self._batch_active = True
        self._batch_gate = gate
        self._batch_duration = 0.0
        self._batch_views = []
        self._batch_rows = 0
        self._batch_result_bytes = 0
        batch_failed = False
        try:
            results = {}
            parameter_sets = parameters or {}
            for index, (name, sql) in enumerate(items):
                if index:
                    self._wait(self.min_query_interval)
                    worst_case_duration = (
                        self._batch_duration
                        + MAX_STATEMENT_TIMEOUT_PERIODS * self.timeout)
                    crash_cooldown = max(
                        self.min_query_interval,
                        worst_case_duration * (100 / self.max_duty_cycle - 1),
                    )
                    if gate is not None:
                        self._write_shared_deadline(
                            gate, time.time() + crash_cooldown)
                results[name] = self.query(sql, parameter_sets.get(name))
                completed_cooldown = max(
                    self.min_query_interval,
                    self._batch_duration * (100 / self.max_duty_cycle - 1),
                )
                if gate is not None:
                    self._write_shared_deadline(
                        gate, time.time() + completed_cooldown)
            return results
        except BaseException:
            batch_failed = True
            raise
        finally:
            finished = time.monotonic()
            duty_cycle_cooldown = (
                self._batch_duration * (100 / self.max_duty_cycle - 1))
            cooldown = max(self.min_query_interval, duty_cycle_cooldown)
            self._next_query_at = finished + cooldown
            for view in set(self._batch_views):
                metrics.ise_dataconnect_query_cooldown_seconds.labels(
                    view=view).set(cooldown)
            self._batch_active = False
            self._batch_gate = None
            self._batch_duration = 0.0
            self._batch_views = []
            self._batch_rows = 0
            self._batch_result_bytes = 0
            try:
                self._release_shared_gate(gate, time.time() + cooldown)
            except Exception:
                if batch_failed:
                    logger.exception(
                        "Data Connect batch pacing gate release also failed")
                else:
                    raise

    def query_if_ready(self, sql, parameters=None):
        """Issue a statement only when the production pacing gate is ready now.

        Interactive completion uses this path so pressing Tab never queues behind
        an exporter cooldown. ``None`` means no Oracle statement was issued; an
        empty list remains a successful query with no matching rows.
        """
        return self.query(sql, parameters, wait_for_pacing=False)

    def query_interactive(self, sql, parameters=None):
        """Run an operator query without queueing behind an adaptive cooldown.

        A generic CLI search first reads catalog metadata so identifiers can be
        validated safely.  Honor the short local gap created by that catalog
        read, then probe the shared reporting gate without waiting.  ``None``
        means an exporter or earlier CLI query still owns an adaptive lease.
        """
        remaining = self._next_query_at - time.monotonic()
        if remaining > 0:
            self._wait(remaining)
        return self.query(sql, parameters, wait_for_pacing=False)

    def query(self, sql, parameters=None, *, wait_for_pacing=True):
        """Execute a reporting query under adaptive production duty pacing."""
        return self._query(
            sql, parameters, wait_for_pacing=wait_for_pacing, adaptive_duty=True)

    @staticmethod
    def _validate_endpoint_lookup_query(sql):
        """Restrict the interactive cooldown bypass to one bounded point lookup."""
        normalized = " ".join(str(sql or "").lower().split())
        referenced = re.findall(
            r"\b(?:from|join)\s+([a-z][a-z0-9_$#.]*)", normalized)
        indexed_predicate = (
            "endpoint_ip = :identifier" in normalized
            or "hostname in (:identifier, :identifier_lower, :identifier_upper)"
            in normalized
        )
        if (not normalized.startswith("select ")
                or referenced != ["endpoints_data"]
                or not indexed_predicate
                or " fetch first 10 rows only" not in normalized
                or any(token in normalized for token in (
                    ";", "--", "/*", " union ", " group by ", " having "))):
            raise ValueError(
                "endpoint lookup must be a bounded indexed SELECT from ENDPOINTS_DATA")

    def query_endpoint_lookup(self, sql, parameters=None):
        """Run one exact operator lookup without waiting through aggregate duty pacing.

        The strict query shape, ten-row ceiling, normal global lock, hard Oracle
        timeout, and existing cooldown preservation keep this materially cheaper
        than the scheduled aggregate scans that create the adaptive delay.
        """
        self._validate_endpoint_lookup_query(sql)
        return self._query(
            sql, parameters, wait_for_pacing=False, adaptive_duty=False)

    @staticmethod
    def _validate_catalog_query(sql):
        """Allow fixed Oracle dictionary reads, never reporting-view bypasses."""
        normalized = " ".join(str(sql or "").lower().split())
        referenced = set(re.findall(
            r"\b(?:from|join)\s+([a-z][a-z0-9_$#.]*)", normalized))
        allowed = {"user_tab_columns", "user_views"}
        if (not normalized.startswith("select ") or not referenced
                or not referenced <= allowed):
            raise ValueError("catalog query must be a SELECT from an allowed dictionary view")

    def query_catalog(self, sql, parameters=None, *, wait_for_pacing=True):
        """Read bounded schema metadata without reporting-scan duty amplification.

        Catalog reads still use the global lock, hard timeout, result ceilings,
        session parallel-query prohibition, and minimum inter-query gap. They do
        not scale with the 80--200 GB MnT reporting database, so charging their
        duration as reporting-view duty can delay the first useful collection by
        minutes or hours without reducing production load.
        """
        self._validate_catalog_query(sql)
        return self._query(
            sql, parameters, wait_for_pacing=wait_for_pacing, adaptive_duty=False)

    def query_catalog_if_ready(self, sql, parameters=None):
        """Non-blocking catalog lookup for interactive completion and health."""
        return self.query_catalog(sql, parameters, wait_for_pacing=False)

    def close(self):
        if self._connection is not None:
            try:
                self._connection.close()
            finally:
                self._connection = None
