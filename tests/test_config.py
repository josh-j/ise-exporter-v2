import logging
from pathlib import Path

from dotenv import dotenv_values

from ise_exporter.config import Config, _b, _f, _i, _log_level, _s


def test_b_accepts_true_false_case_insensitive(monkeypatch):
    monkeypatch.setenv("X", "TRUE")
    assert _b("X", False) is True
    monkeypatch.setenv("X", "False")
    assert _b("X", True) is False


def test_b_strips_trailing_cr_and_whitespace(monkeypatch):
    monkeypatch.setenv("X", "true\r")
    assert _b("X", False) is True
    monkeypatch.setenv("X", "  false  ")
    assert _b("X", True) is False


def test_b_accepts_common_boolean_spellings(monkeypatch):
    for truthy in ("1", "yes", "on", "TRUE", '"true"'):
        monkeypatch.setenv("X", truthy)
        assert _b("X", False) is True, truthy
    for falsy in ("0", "no", "off", "False", "'false'"):
        monkeypatch.setenv("X", falsy)
        assert _b("X", True) is False, falsy


def test_b_falls_back_to_default_and_warns_on_garbage(monkeypatch, caplog):
    monkeypatch.setenv("X", "maybe")
    with caplog.at_level(logging.WARNING):
        assert _b("X", True) is True
        assert _b("X", False) is False
    assert any("not a recognized boolean" in r.message for r in caplog.records)


def test_b_uses_default_when_unset(monkeypatch):
    monkeypatch.delenv("X", raising=False)
    assert _b("X", True) is True
    assert _b("X", False) is False


def test_i_strips_whitespace_and_parses(monkeypatch):
    monkeypatch.setenv("X", " 45\r")
    assert _i("X", 1) == 45


def test_i_falls_back_and_warns_on_non_integer(monkeypatch, caplog):
    monkeypatch.setenv("X", "120s")
    with caplog.at_level(logging.WARNING):
        assert _i("X", 120) == 120
    assert any("not a valid integer" in r.message for r in caplog.records)


def test_f_rejects_non_finite_values(monkeypatch, caplog):
    for value in ("nan", "inf", "-inf"):
        monkeypatch.setenv("X", value)
        with caplog.at_level(logging.WARNING):
            assert _f("X", 0.1) == 0.1
    assert sum("not a finite number" in record.message
               for record in caplog.records) == 3


def test_log_level_normalizes_warn_and_rejects_invalid_values(monkeypatch, caplog):
    monkeypatch.setenv("LOG_LEVEL", "warn")
    assert _log_level() == "WARNING"

    monkeypatch.setenv("LOG_LEVEL", "verbose")
    with caplog.at_level(logging.WARNING):
        assert _log_level() == "INFO"
    assert any("not a supported log level" in record.message
               for record in caplog.records)


def test_s_strips_trailing_cr(monkeypatch):
    monkeypatch.setenv("X", "/etc/ise-exporter/certs/ise-ca.cer\r")
    assert _s("X") == "/etc/ise-exporter/certs/ise-ca.cer"


def test_s_default_when_unset(monkeypatch):
    monkeypatch.delenv("X", raising=False)
    assert _s("X", "fallback") == "fallback"


def test_summary_excludes_password(monkeypatch):
    monkeypatch.setenv("ISE_PASS", "super-secret")
    monkeypatch.setenv("ISE_DATACONNECT_PASSWORD", "database-secret")
    monkeypatch.setenv("ISE_DATACONNECT_HOST", "mnt2.example.mil")
    monkeypatch.setenv("ISE_MNT_HOST", "mnt1.example.mil")
    monkeypatch.setenv("ISE_HOST", "pan1.example.mil")
    cfg = Config.from_env()
    assert "super-secret" not in cfg.summary()
    assert "database-secret" not in cfg.summary()
    assert "pan1.example.mil" in cfg.summary()
    assert cfg.dataconnect_ready is True
    assert cfg.dataconnect_host == "mnt2.example.mil"


def test_dataconnect_host_never_falls_back_to_mnt_host(monkeypatch):
    monkeypatch.setenv("ISE_MNT_HOST", "primary-mnt.example.mil")
    monkeypatch.setenv("ISE_DATACONNECT_PASSWORD", "database-secret")
    monkeypatch.delenv("ISE_DATACONNECT_HOST", raising=False)

    cfg = Config.from_env()

    assert cfg.dataconnect_host == ""
    assert cfg.dataconnect_ready is False


def test_rest_and_mnt_tls_are_verified_by_default_with_independent_overrides(monkeypatch):
    for name in ("ISE_REST_SSL_VERIFY", "ISE_REST_CA_BUNDLE",
                 "ISE_MNT_SSL_VERIFY", "ISE_MNT_CA_BUNDLE"):
        monkeypatch.delenv(name, raising=False)
    cfg = Config.from_env()
    assert cfg.rest_ssl_verify is True
    assert cfg.mnt_ssl_verify is True

    monkeypatch.setenv("ISE_REST_SSL_VERIFY", "false")
    monkeypatch.setenv("ISE_REST_CA_BUNDLE", "/ca/rest.pem")
    monkeypatch.setenv("ISE_MNT_SSL_VERIFY", "true")
    monkeypatch.setenv("ISE_MNT_CA_BUNDLE", "/ca/mnt.pem")
    cfg = Config.from_env()
    assert cfg.rest_ssl_verify is False
    assert cfg.rest_ca_bundle == "/ca/rest.pem"
    assert cfg.mnt_ssl_verify is True
    assert cfg.mnt_ca_bundle == "/ca/mnt.pem"


def test_env_example_is_parseable_ise33_100k_production_profile():
    path = Path(__file__).parents[1] / ".env.example"
    values = dotenv_values(path, interpolate=False)

    assert "FAST_INTERVAL" not in values
    assert "MAX_WORKERS" not in values
    assert values["ISE_DATACONNECT_MAX_GROUPS"] == "1000"
    assert values["ISE_DATACONNECT_QUERY_TIMEOUT"] == "15"
    assert values["ISE_DATACONNECT_MIN_QUERY_INTERVAL_MS"] == "5000"
    assert values["ISE_DATACONNECT_MAX_DUTY_CYCLE_PERCENT"] == "0.1"
    assert values["ISE_DATACONNECT_EVENT_WINDOW_HOURS"] == "6"
    assert values["ISE_DATACONNECT_RADIUS_INTERVAL"] == "86400"
    assert values["ISE_DATACONNECT_RADIUS_ACTIVE_INTERVAL"] == "1800"
    assert values["ISE_DATACONNECT_PERFORMANCE_INTERVAL"] == "3600"
    assert values["ISE_DATACONNECT_POSTURE_INTERVAL"] == "21600"
    assert values["ISE_DATACONNECT_ENDPOINTS_INTERVAL"] == "86400"
    assert values["ISE_DATACONNECT_FRESHNESS_INTERVAL"] == "86400"
    assert values["ISE_DATACONNECT_NAD_HEALTH_INTERVAL"] == "21600"
    assert values["ISE_DATACONNECT_TACACS_INTERVAL"] == "21600"
    assert values["ISE_DATACONNECT_SERVICE"] == "cpm10"
    assert values["ISE_DATACONNECT_SSL_VERIFY"] == "true"
    assert values["ISE_REST_SSL_VERIFY"] == "true"
    assert values["ISE_REST_AUTH_GUARD_FILE"] == \
        "/var/lib/ise-exporter/shared/rest-auth.guard"
    assert values["ISE_MNT_SSL_VERIFY"] == "true"
    assert values["COLLECT_MNT_ACTIVE_POSTURE"] == "true"
    assert values["MNT_ACTIVE_POSTURE_INTERVAL"] == "900"
    assert values["MNT_ACTIVE_POSTURE_MAX_ACTIVE_LIST_SESSIONS"] == "10000"
    assert values["MNT_ACTIVE_POSTURE_MAX_SESSIONS"] == "1000"
    assert values["MNT_ACTIVE_POSTURE_WORKERS"] == "2"
    assert values["MNT_ACTIVE_POSTURE_MAX_REQUESTS_PER_CYCLE"] == "250"
    assert values["MNT_ACTIVE_POSTURE_REFRESH_TTL"] == "3600"
    assert values["MNT_ACTIVE_POSTURE_REQUEST_INTERVAL_MS"] == "500"
    assert values["ISE_EXPORTER_STATE_DB"] == "/var/lib/ise-exporter/state.sqlite3"
    assert "ISE_DATACONNECT_INCREMENTAL_ENABLED" not in values
    assert "ISE_DATACONNECT_RECONCILE_INTERVAL" not in values
    assert "ISE_DATACONNECT_MAX_BACKFILL_SECONDS" not in values
    assert values["ISE_DATACONNECT_SHARED_PACING_FILE"] == \
        "/var/lib/ise-exporter/shared/dataconnect.pacing"
    assert values["ISE_CLI_PRODUCTION_SAFE"] == "true"
    assert values["ISE_CLI_ALLOW_EXPENSIVE"] == "false"
    assert values["ISE_CLI_MAX_ROWS"] == "1000"
    # systemd EnvironmentFile= does not support trailing inline comments; keeping
    # comments on their own lines prevents them becoming part of numeric/boolean values.
    assignments = [line for line in path.read_text().splitlines()
                   if line.strip() and not line.lstrip().startswith("#")]
    assert all(" #" not in line for line in assignments)


def test_dataconnect_production_guardrails_clamp_unsafe_overrides(monkeypatch):
    unsafe = {
        "ISE_DATACONNECT_QUERY_TIMEOUT": "999",
        "ISE_DATACONNECT_MAX_GROUPS": "999999",
        "ISE_DATACONNECT_MIN_QUERY_INTERVAL_MS": "0",
        "ISE_DATACONNECT_MAX_DUTY_CYCLE_PERCENT": "99",
        "ISE_DATACONNECT_EVENT_WINDOW_HOURS": "999",
        "ISE_DATACONNECT_RADIUS_INTERVAL": "1",
        "ISE_DATACONNECT_RADIUS_ACTIVE_INTERVAL": "1",
        "ISE_DATACONNECT_PERFORMANCE_INTERVAL": "1",
        "ISE_DATACONNECT_POSTURE_INTERVAL": "1",
        "ISE_DATACONNECT_ENDPOINTS_INTERVAL": "1",
        "ISE_DATACONNECT_FRESHNESS_INTERVAL": "1",
        "ISE_DATACONNECT_NAD_HEALTH_INTERVAL": "1",
        "ISE_DATACONNECT_TACACS_INTERVAL": "1",
        "MNT_ACTIVE_POSTURE_MAX_ACTIVE_LIST_SESSIONS": "999999",
        "TACACS_INTERNAL_USER_MAX": "999999",
        "TACACS_INTERNAL_USER_DETAIL_MAX_REQUESTS": "999999",
        "TACACS_INTERNAL_USER_DETAIL_TTL": "1",
        "TACACS_INTERNAL_USER_DETAIL_REQUEST_INTERVAL_MS": "0",
        "ERS_PORT": "99999",
        "EXPORTER_PORT": "0",
        "SCRAPE_INTERVAL": "1",
        "MEDIUM_INTERVAL": "1",
        "SLOW_INTERVAL": "-1",
        "AUTH_FAILURE_BACKOFF": "-1",
        "AUTH_FAILURE_THRESHOLD": "999",
        "DEVICE_CACHE_TTL": "0",
        "ISE_DATACONNECT_PORT": "99999",
        "TACACS_UNUSED_ACCOUNT_DAYS": "0",
    }
    for name, value in unsafe.items():
        monkeypatch.setenv(name, value)

    cfg = Config.from_env()

    assert cfg.dataconnect_query_timeout == 15
    assert cfg.dataconnect_max_groups == 1000
    assert cfg.dataconnect_min_query_interval_ms == 5000
    assert cfg.dataconnect_max_duty_cycle_percent == 0.1
    assert cfg.dataconnect_event_window_hours == 6
    assert cfg.dataconnect_radius_interval == 86400
    assert cfg.dataconnect_radius_active_interval == 1800
    assert cfg.dataconnect_performance_interval == 3600
    assert cfg.dataconnect_posture_interval == 21600
    assert cfg.dataconnect_endpoints_interval == 86400
    assert cfg.dataconnect_freshness_interval == 86400
    assert cfg.dataconnect_nad_health_interval == 21600
    assert cfg.dataconnect_tacacs_interval == 21600
    assert cfg.mnt_active_posture_max_active_list_sessions == 250000
    assert cfg.tacacs_internal_user_max == 1000
    assert cfg.tacacs_internal_user_detail_max_requests == 250
    assert cfg.tacacs_internal_user_detail_ttl == 86400
    assert cfg.tacacs_internal_user_detail_request_interval_ms == 100
    assert cfg.ers_port == 65535
    assert cfg.exporter_port == 1
    assert cfg.scrape_interval == 60
    assert cfg.medium_interval == 300
    assert cfg.slow_interval == 3600
    assert cfg.auth_failure_backoff == 300
    assert cfg.auth_failure_threshold == 5
    assert cfg.device_cache_ttl == 3600
    assert cfg.dataconnect_port == 65535
    assert cfg.tacacs_unused_account_days == 1


def test_empty_shared_pacing_path_cannot_disable_cross_process_guard(monkeypatch):
    monkeypatch.setenv("ISE_DATACONNECT_SHARED_PACING_FILE", "")

    cfg = Config.from_env()

    assert cfg.dataconnect_shared_pacing_file == \
        "/var/lib/ise-exporter/shared/dataconnect.pacing"


def test_empty_state_path_cannot_disable_restart_persistence(monkeypatch):
    monkeypatch.setenv("ISE_EXPORTER_STATE_DB", "")

    cfg = Config.from_env()

    assert cfg.state_db_path == "/var/lib/ise-exporter/state.sqlite3"


def test_empty_rest_auth_guard_path_cannot_disable_lockout_protection(monkeypatch):
    monkeypatch.setenv("ISE_REST_AUTH_GUARD_FILE", "")

    cfg = Config.from_env()

    assert cfg.rest_auth_guard_file == \
        "/var/lib/ise-exporter/shared/rest-auth.guard"
