"""Read-only Cisco ISE Data Connect client.

Data Connect is Oracle-compatible SQL over TCPS on the MnT node.  The exporter
only queries Cisco's bounded ``*_LAST_TWO_DAYS`` TACACS views and never mutates
the database.
"""
import ssl

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
        self._connection = None

    def _ssl_context(self):
        if not self.verify:
            return ssl._create_unverified_context()
        return ssl.create_default_context(cafile=self.ca_bundle or None)

    def connect(self):
        if self._connection is None:
            self._connection = oracledb.connect(
                user=self.user,
                password=self.password,
                host=self.host,
                port=self.port,
                service_name=self.service,
                protocol="tcps",
                ssl_context=self._ssl_context(),
                ssl_server_dn_match=self.verify,
                tcp_connect_timeout=self.timeout,
            )
            self._connection.call_timeout = self.timeout * 1000
        return self._connection

    def query(self, sql, parameters=None):
        with self.connect().cursor() as cursor:
            cursor.execute(sql, parameters or {})
            columns = [column.name.lower() for column in cursor.description]
            return [dict(zip(columns, row)) for row in cursor.fetchall()]

    def close(self):
        if self._connection is not None:
            self._connection.close()
            self._connection = None
