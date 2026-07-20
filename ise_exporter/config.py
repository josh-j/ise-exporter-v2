"""Typed TOML configuration for the exporter, CLI, and collectors."""
from __future__ import annotations

from dataclasses import dataclass, fields, replace
import logging
import math
import os
from pathlib import Path

try:
    import tomllib
except ModuleNotFoundError:  # pragma: no cover - Python 3.10 compatibility
    import tomli as tomllib


logger = logging.getLogger(__name__)
DEFAULT_CONFIG_FILE = "/etc/ise-exporter/config.toml"
DEFAULT_DATACONNECT_RADIUS_ACTIVE_INTERVAL = 300
MAX_DATACONNECT_RADIUS_ACTIVE_INTERVAL = 3600


class ConfigError(ValueError):
    """The TOML configuration is missing, malformed, or unsafe."""


@dataclass(frozen=True)
class Config:
    config_file: str = ""
    log_level: str = "INFO"
    ise_host: str = ""
    ise_mnt_host: str = ""
    ise_user: str = "ers.readonly"
    ise_pass: str = ""
    ers_port: int = 9060
    request_timeout: int = 30
    rest_ca_bundle: str = ""
    rest_ssl_verify: bool = True
    mnt_ca_bundle: str = ""
    mnt_ssl_verify: bool = True
    exporter_port: int = 9618
    state_db_path: str = "/var/lib/ise-exporter/state.sqlite3"
    scrape_interval: int = 60
    medium_interval: int = 300
    slow_interval: int = 21600
    startup_rate_limit_seconds: int = 5
    auth_failure_backoff: int = 900
    auth_failure_threshold: int = 3
    rest_auth_guard_file: str = "/var/lib/ise-exporter/shared/rest-auth.guard"
    device_cache_ttl: int = 2592000
    device_detail_max_requests: int = 25
    device_detail_request_interval_ms: int = 250
    collect_device_details: bool = True
    collect_certificates: bool = True
    collect_licensing: bool = True
    collect_backup_status: bool = True
    collect_patches: bool = True
    collect_tacacs: bool = True
    collect_mnt_active_posture: bool = True
    mnt_active_posture_interval: int = 300
    mnt_active_posture_max_active_list_sessions: int = 10000
    mnt_active_posture_max_sessions: int = 1000
    mnt_active_posture_workers: int = 2
    mnt_active_posture_max_requests_per_cycle: int = 80
    mnt_active_posture_refresh_ttl: int = 3600
    mnt_active_posture_request_interval_ms: int = 500
    tacacs_internal_user_max: int = 1000
    tacacs_internal_user_detail_max_requests: int = 100
    tacacs_internal_user_detail_ttl: int = 604800
    tacacs_internal_user_detail_request_interval_ms: int = 250
    tacacs_policy_set_max: int = 100
    tacacs_policy_rule_refresh_max: int = 10
    tacacs_policy_rule_ttl: int = 604800
    tacacs_policy_rule_request_interval_ms: int = 250
    tacacs_unused_account_days: int = 180
    dataconnect_host: str = ""
    dataconnect_port: int = 2484
    dataconnect_service: str = "cpm10"
    dataconnect_user: str = "dataconnect"
    dataconnect_password: str = ""
    dataconnect_ca_bundle: str = ""
    dataconnect_ssl_verify: bool = True
    dataconnect_query_timeout: int = 15
    dataconnect_max_groups: int = 1000
    dataconnect_min_query_interval_ms: int = 5000
    dataconnect_max_duty_cycle_percent: float = 0.1
    dataconnect_event_window_hours: int = 6
    dataconnect_schema_interval: int = 86400
    dataconnect_radius_interval: int = 1800
    dataconnect_radius_active_interval: int = \
        DEFAULT_DATACONNECT_RADIUS_ACTIVE_INTERVAL
    dataconnect_performance_interval: int = 300
    dataconnect_posture_interval: int = 21600
    dataconnect_endpoints_interval: int = 21600
    dataconnect_freshness_interval: int = 86400
    dataconnect_nad_health_interval: int = 21600
    dataconnect_tacacs_interval: int = 21600
    dataconnect_shared_pacing_file: str = "/var/lib/ise-exporter/shared/dataconnect.pacing"
    dataconnect_auth_guard_file: str = "/var/lib/ise-exporter/shared/dataconnect-auth.guard"
    pxgrid_host: str = ""
    pxgrid_port: int = 8910
    pxgrid_node_name: str = ""
    pxgrid_password: str = ""
    pxgrid_client_cert: str = ""
    pxgrid_client_key: str = ""
    pxgrid_ca_bundle: str = ""
    pxgrid_ssl_verify: bool = True
    pxgrid_request_timeout: int = 30
    cli_production_safe: bool = True
    cli_allow_expensive: bool = False
    cli_max_rows: int = 1000

    @property
    def dataconnect_ready(self) -> bool:
        return bool(self.dataconnect_host and self.dataconnect_user
                    and self.dataconnect_password)

    @property
    def pxgrid_ready(self) -> bool:
        credentials = self.pxgrid_password or (
            self.pxgrid_client_cert and self.pxgrid_client_key)
        return bool(self.pxgrid_host and self.pxgrid_node_name and credentials)

    def summary(self) -> str:
        """Return a secret-redacted startup summary."""
        return (f"config_file={self.config_file!r} "
                f"collect_tacacs={self.collect_tacacs} "
                f"collect_mnt_active_posture={self.collect_mnt_active_posture} "
                f"mnt_active_list_ceiling="
                f"{self.mnt_active_posture_max_active_list_sessions} "
                f"dataconnect_ready={self.dataconnect_ready} "
                f"pxgrid_ready={self.pxgrid_ready} "
                f"dataconnect_target={self.dataconnect_host!r}:"
                f"{self.dataconnect_port}/{self.dataconnect_service} "
                f"dataconnect_query_timeout_seconds={self.dataconnect_query_timeout} "
                f"dataconnect_min_query_interval_ms="
                f"{self.dataconnect_min_query_interval_ms} "
                f"dataconnect_max_duty_cycle_percent="
                f"{self.dataconnect_max_duty_cycle_percent} "
                f"dataconnect_max_groups={self.dataconnect_max_groups} "
                f"rest_request_timeout_seconds={self.request_timeout} "
                f"startup_rate_limit_seconds={self.startup_rate_limit_seconds} "
                f"dataconnect_event_window_ceiling_hours="
                f"{self.dataconnect_event_window_hours} "
                f"ise_host={self.ise_host!r} ise_mnt_host={self.ise_mnt_host!r} "
                f"ise_user={self.ise_user!r}")

    @classmethod
    def load(cls, path=None) -> "Config":
        configured = path or os.getenv("ISE_EXPORTER_CONFIG")
        config_path = Path(configured) if configured else Path(DEFAULT_CONFIG_FILE)
        if not config_path.exists():
            if configured:
                raise ConfigError(f"configuration file does not exist: {config_path}")
            document = {}
            source = ""
        else:
            try:
                with config_path.open("rb") as stream:
                    document = tomllib.load(stream)
            except (OSError, tomllib.TOMLDecodeError) as error:
                raise ConfigError(f"cannot load TOML config {config_path}: {error}") from error
            source = str(config_path)

        flattened = _flatten(document)
        unknown = sorted(set(flattened) - set(_TOML_FIELDS))
        if unknown:
            suffix = "s" if len(unknown) != 1 else ""
            raise ConfigError(f"unknown TOML config key{suffix}: {', '.join(unknown)}")

        defaults = cls()
        values = {"config_file": source}
        for key, raw in flattened.items():
            name = _TOML_FIELDS[key]
            values[name] = _typed_value(key, raw, getattr(defaults, name))

        # MnT TLS follows REST unless it is configured explicitly.
        if "ise.mnt_tls.ca_bundle" not in flattened:
            values["mnt_ca_bundle"] = values.get(
                "rest_ca_bundle", defaults.rest_ca_bundle)
        if "ise.mnt_tls.verify" not in flattened:
            values["mnt_ssl_verify"] = values.get(
                "rest_ssl_verify", defaults.rest_ssl_verify)

        # Secrets are intentionally the only environment overrides.
        if "ISE_PASS" in os.environ:
            values["ise_pass"] = os.environ["ISE_PASS"]
        if "ISE_DATACONNECT_PASSWORD" in os.environ:
            values["dataconnect_password"] = os.environ[
                "ISE_DATACONNECT_PASSWORD"]
        if "ISE_PXGRID_PASSWORD" in os.environ:
            values["pxgrid_password"] = os.environ["ISE_PXGRID_PASSWORD"]

        return _validate(replace(defaults, **values))

    @classmethod
    def from_env(cls) -> "Config":
        """Compatibility call site; configuration itself is TOML-based."""
        return cls.load()


_TOML_FIELDS = {
    "exporter.log_level": "log_level",
    "exporter.port": "exporter_port",
    "exporter.state_db": "state_db_path",
    "exporter.scrape_interval_seconds": "scrape_interval",
    "exporter.medium_interval_seconds": "medium_interval",
    "exporter.slow_interval_seconds": "slow_interval",
    "exporter.startup_rate_limit_seconds": "startup_rate_limit_seconds",
    "ise.host": "ise_host",
    "ise.mnt_host": "ise_mnt_host",
    "ise.user": "ise_user",
    "ise.password": "ise_pass",
    "ise.ers_port": "ers_port",
    "ise.request_timeout_seconds": "request_timeout",
    "ise.auth_failure_backoff_seconds": "auth_failure_backoff",
    "ise.auth_failure_threshold": "auth_failure_threshold",
    "ise.auth_guard_file": "rest_auth_guard_file",
    "ise.rest_tls.ca_bundle": "rest_ca_bundle",
    "ise.rest_tls.verify": "rest_ssl_verify",
    "ise.mnt_tls.ca_bundle": "mnt_ca_bundle",
    "ise.mnt_tls.verify": "mnt_ssl_verify",
    "collectors.device_details": "collect_device_details",
    "collectors.certificates": "collect_certificates",
    "collectors.licensing": "collect_licensing",
    "collectors.backup_status": "collect_backup_status",
    "collectors.patches": "collect_patches",
    "collectors.tacacs": "collect_tacacs",
    "collectors.mnt_active_posture": "collect_mnt_active_posture",
    "devices.cache_ttl_seconds": "device_cache_ttl",
    "devices.detail_max_requests": "device_detail_max_requests",
    "devices.detail_request_interval_ms": "device_detail_request_interval_ms",
    "mnt_active_posture.interval_seconds": "mnt_active_posture_interval",
    "mnt_active_posture.max_active_list_sessions":
        "mnt_active_posture_max_active_list_sessions",
    "mnt_active_posture.max_sessions": "mnt_active_posture_max_sessions",
    "mnt_active_posture.workers": "mnt_active_posture_workers",
    "mnt_active_posture.max_requests_per_cycle":
        "mnt_active_posture_max_requests_per_cycle",
    "mnt_active_posture.refresh_ttl_seconds": "mnt_active_posture_refresh_ttl",
    "mnt_active_posture.request_interval_ms": "mnt_active_posture_request_interval_ms",
    "tacacs.unused_account_days": "tacacs_unused_account_days",
    "tacacs.users.max": "tacacs_internal_user_max",
    "tacacs.users.detail_max_requests": "tacacs_internal_user_detail_max_requests",
    "tacacs.users.detail_ttl_seconds": "tacacs_internal_user_detail_ttl",
    "tacacs.users.detail_request_interval_ms":
        "tacacs_internal_user_detail_request_interval_ms",
    "tacacs.policies.max_sets": "tacacs_policy_set_max",
    "tacacs.policies.rule_refresh_max": "tacacs_policy_rule_refresh_max",
    "tacacs.policies.rule_ttl_seconds": "tacacs_policy_rule_ttl",
    "tacacs.policies.rule_request_interval_ms": "tacacs_policy_rule_request_interval_ms",
    "dataconnect.host": "dataconnect_host",
    "dataconnect.port": "dataconnect_port",
    "dataconnect.service": "dataconnect_service",
    "dataconnect.user": "dataconnect_user",
    "dataconnect.password": "dataconnect_password",
    "dataconnect.ca_bundle": "dataconnect_ca_bundle",
    "dataconnect.verify_tls": "dataconnect_ssl_verify",
    "dataconnect.query_timeout_seconds": "dataconnect_query_timeout",
    "dataconnect.max_groups": "dataconnect_max_groups",
    "dataconnect.min_query_interval_ms": "dataconnect_min_query_interval_ms",
    "dataconnect.max_duty_cycle_percent": "dataconnect_max_duty_cycle_percent",
    "dataconnect.event_window_hours": "dataconnect_event_window_hours",
    "dataconnect.shared_pacing_file": "dataconnect_shared_pacing_file",
    "dataconnect.auth_guard_file": "dataconnect_auth_guard_file",
    "dataconnect.intervals.schema_seconds": "dataconnect_schema_interval",
    "dataconnect.intervals.radius_seconds": "dataconnect_radius_interval",
    "dataconnect.intervals.radius_active_seconds": "dataconnect_radius_active_interval",
    "dataconnect.intervals.performance_seconds": "dataconnect_performance_interval",
    "dataconnect.intervals.posture_seconds": "dataconnect_posture_interval",
    "dataconnect.intervals.endpoints_seconds": "dataconnect_endpoints_interval",
    "dataconnect.intervals.freshness_seconds": "dataconnect_freshness_interval",
    "dataconnect.intervals.nad_health_seconds": "dataconnect_nad_health_interval",
    "dataconnect.intervals.tacacs_seconds": "dataconnect_tacacs_interval",
    "pxgrid.host": "pxgrid_host",
    "pxgrid.port": "pxgrid_port",
    "pxgrid.node_name": "pxgrid_node_name",
    "pxgrid.password": "pxgrid_password",
    "pxgrid.client_cert": "pxgrid_client_cert",
    "pxgrid.client_key": "pxgrid_client_key",
    "pxgrid.ca_bundle": "pxgrid_ca_bundle",
    "pxgrid.verify_tls": "pxgrid_ssl_verify",
    "pxgrid.request_timeout_seconds": "pxgrid_request_timeout",
    "cli.production_safe": "cli_production_safe",
    "cli.allow_expensive": "cli_allow_expensive",
    "cli.max_rows": "cli_max_rows",
}


_HARD_RANGES = {
    "ers_port": (1, 65535),
    "request_timeout": (5, 30),
    "exporter_port": (1, 65535),
    "auth_failure_backoff": (300, 86400),
    "auth_failure_threshold": (1, 5),
    "device_detail_max_requests": (1, 100),
    "mnt_active_posture_max_active_list_sessions": (1, 250000),
    "mnt_active_posture_max_sessions": (1, 1000),
    "mnt_active_posture_workers": (1, 4),
    "mnt_active_posture_max_requests_per_cycle": (1, 250),
    "tacacs_internal_user_max": (1, 1000),
    "tacacs_internal_user_detail_max_requests": (1, 250),
    "tacacs_policy_set_max": (1, 1000),
    "tacacs_policy_rule_refresh_max": (1, 25),
    "tacacs_unused_account_days": (1, 3650),
    "dataconnect_port": (1, 65535),
    "dataconnect_query_timeout": (5, 15),
    "dataconnect_max_groups": (1, 1000),
    "dataconnect_event_window_hours": (1, 6),
    "pxgrid_port": (1, 65535),
    "pxgrid_request_timeout": (5, 30),
    "cli_max_rows": (100, 5000),
}

_POSITIVE_FIELDS = {
    "scrape_interval", "medium_interval", "slow_interval", "device_cache_ttl",
    "mnt_active_posture_interval", "mnt_active_posture_refresh_ttl",
    "tacacs_internal_user_detail_ttl", "tacacs_policy_rule_ttl",
    "dataconnect_schema_interval", "dataconnect_radius_interval",
    "dataconnect_radius_active_interval", "dataconnect_performance_interval",
    "dataconnect_posture_interval", "dataconnect_endpoints_interval",
    "dataconnect_freshness_interval", "dataconnect_nad_health_interval",
    "dataconnect_tacacs_interval",
}

_NONEMPTY_PATHS = {
    "state_db_path", "rest_auth_guard_file", "dataconnect_shared_pacing_file",
    "dataconnect_auth_guard_file",
}


def _flatten(value, prefix=""):
    flattened = {}
    for key, item in value.items():
        path = f"{prefix}.{key}" if prefix else key
        if isinstance(item, dict):
            flattened.update(_flatten(item, path))
        else:
            flattened[path] = item
    return flattened


def _typed_value(key, value, default):
    expected = type(default)
    if expected is bool:
        valid = type(value) is bool
    elif expected is int:
        valid = type(value) is int
    elif expected is float:
        valid = type(value) in (int, float) and math.isfinite(value)
    else:
        valid = isinstance(value, expected)
    if not valid:
        raise ConfigError(
            f"{key} must be {expected.__name__}, got {type(value).__name__}")
    return float(value) if expected is float else value


def _validate(config):
    values = {field.name: getattr(config, field.name) for field in fields(config)}
    level = config.log_level.upper()
    if level == "WARN":
        level = "WARNING"
    if level not in {"DEBUG", "INFO", "WARNING", "ERROR", "CRITICAL"}:
        raise ConfigError(f"exporter.log_level is unsupported: {config.log_level!r}")
    values["log_level"] = level

    for name, (minimum, maximum) in _HARD_RANGES.items():
        value = values[name]
        if value < minimum or value > maximum:
            key = next(key for key, field in _TOML_FIELDS.items() if field == name)
            raise ConfigError(f"{key} must be between {minimum} and {maximum}")
    for name in _POSITIVE_FIELDS:
        if values[name] < 1:
            key = next(key for key, field in _TOML_FIELDS.items() if field == name)
            raise ConfigError(f"{key} must be at least 1")
    if values["dataconnect_radius_active_interval"] > \
            MAX_DATACONNECT_RADIUS_ACTIVE_INTERVAL:
        logger.warning(
            "dataconnect.intervals.radius_active_seconds=%d exceeds the hard "
            "one-hour active-session stale window; using %d seconds",
            values["dataconnect_radius_active_interval"],
            MAX_DATACONNECT_RADIUS_ACTIVE_INTERVAL,
        )
        values["dataconnect_radius_active_interval"] = \
            MAX_DATACONNECT_RADIUS_ACTIVE_INTERVAL
    for name in (
            "startup_rate_limit_seconds", "device_detail_request_interval_ms",
            "mnt_active_posture_request_interval_ms",
            "tacacs_internal_user_detail_request_interval_ms",
            "tacacs_policy_rule_request_interval_ms",
            "dataconnect_min_query_interval_ms"):
        if values[name] < 0:
            key = next(key for key, field in _TOML_FIELDS.items() if field == name)
            raise ConfigError(f"{key} cannot be negative")
    if config.dataconnect_max_duty_cycle_percent <= 0:
        raise ConfigError("dataconnect.max_duty_cycle_percent must be greater than 0")
    for name in _NONEMPTY_PATHS:
        if not values[name].strip():
            key = next(key for key, field in _TOML_FIELDS.items() if field == name)
            raise ConfigError(f"{key} cannot be empty")
    if bool(config.pxgrid_client_cert) != bool(config.pxgrid_client_key):
        raise ConfigError("pxgrid.client_cert and pxgrid.client_key must be configured together")
    return replace(config, **values)
