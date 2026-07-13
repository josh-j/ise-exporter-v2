"""Read-only Cisco ISE Data Connect client.

Data Connect is Oracle-compatible SQL over TCPS on the MnT node.  The exporter
only queries Cisco's bounded ``*_LAST_TWO_DAYS`` TACACS views and never mutates
the database.
"""
import ssl
import time

import oracledb


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
        self._connection = None
        self._connect_failures = 0
        self._blocked_until = 0.0

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
        try:
            with self.connect().cursor() as cursor:
                cursor.execute(sql, parameters or {})
                columns = [column.name.lower() for column in cursor.description]
                return [dict(zip(columns, row)) for row in cursor.fetchall()]
        except Exception:
            # A shared Thin connection can become unusable after an MnT restart or
            # network interruption. Drop it so the next scheduled domain can
            # reconnect under the account-protection backoff.
            try:
                self.close()
            except Exception:
                pass
            raise

    def close(self):
        if self._connection is not None:
            try:
                self._connection.close()
            finally:
                self._connection = None
