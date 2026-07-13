import logging
from pathlib import Path

from dotenv import dotenv_values

from ise_exporter.config import Config, _b, _csv, _i, _s


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


def test_s_strips_trailing_cr(monkeypatch):
    monkeypatch.setenv("X", "/etc/ise-exporter/certs/ise-ca.cer\r")
    assert _s("X") == "/etc/ise-exporter/certs/ise-ca.cer"


def test_s_default_when_unset(monkeypatch):
    monkeypatch.delenv("X", raising=False)
    assert _s("X", "fallback") == "fallback"


def test_csv_strips_and_drops_empty_parts(monkeypatch):
    monkeypatch.setenv("X", " asset_tag, ,ops_owner ")
    assert _csv("X") == ("asset_tag", "ops_owner")


def test_csv_preserves_spaces_inside_attribute_names(monkeypatch):
    monkeypatch.setenv("X", "Ops Owner, Asset Category")
    assert _csv("X") == ("Ops Owner", "Asset Category")


def test_summary_excludes_password(monkeypatch):
    monkeypatch.setenv("ISE_PASS", "super-secret")
    monkeypatch.setenv("ISE_DATACONNECT_PASSWORD", "database-secret")
    monkeypatch.setenv("COLLECT_TACACS_DATACONNECT", "true")
    monkeypatch.setenv("ISE_MNT_HOST", "mnt1.example.mil")
    monkeypatch.setenv("ISE_HOST", "pan1.example.mil")
    monkeypatch.setenv("PXGRID_HOST", "pxgrid1.example.mil")
    monkeypatch.setenv("PXGRID_NODE_NAME", "ise-exporter")
    monkeypatch.setenv("PXGRID_CLIENT_CERT", "/certs/client.cer")
    monkeypatch.setenv("PXGRID_CLIENT_KEY", "/certs/client.key")
    cfg = Config.from_env()
    assert "super-secret" not in cfg.summary()
    assert "database-secret" not in cfg.summary()
    assert "pxgrid1.example.mil" in cfg.summary()
    assert "collect_ers_endpoint_attributes=True" in cfg.summary()
    assert cfg.pxgrid_ready is True
    assert cfg.dataconnect_ready is True
    assert cfg.dataconnect_host == "mnt1.example.mil"


def test_env_example_is_parseable_ise33_80k_production_profile():
    path = Path(__file__).parents[1] / ".env.example"
    values = dotenv_values(path, interpolate=False)

    assert values["COLLECT_PXGRID_STREAM"] == "true"
    assert values["COLLECT_ERS_ENDPOINT_ATTRIBUTES"] == "true"
    assert values["COLLECT_ERS_ENDPOINT_FALLBACK"] == "false"
    assert values["ERS_ENDPOINT_ATTRIBUTE_PAGE_SIZE"] == "1000"
    assert values["ERS_ENDPOINT_ATTRIBUTE_CACHE_TTL"] == "604800"
    assert values["MAX_WORKERS"] == "12"
    assert values["MAX_DETAIL_FETCHES_PER_CYCLE"] == "1000"
    assert values["SESSION_DETAIL_CACHE_FILE"] == \
        "/var/lib/ise-exporter/session-details-cache.json"
    assert values["ERS_ENDPOINT_CUSTOM_ATTRIBUTE_KEYS"] == "Ops Owner"
    assert values["COLLECT_TACACS_DATACONNECT"] == "true"
    assert values["ISE_DATACONNECT_MAX_GROUPS"] == "5000"
    assert values["PXGRID_SESSION_TOPIC_ALL"] == "false"
    assert values["PXGRID_SUBSCRIBE_ENDPOINT_TOPIC"] == "false"
    # systemd EnvironmentFile= does not support trailing inline comments; keeping
    # comments on their own lines prevents them becoming part of numeric/boolean values.
    assignments = [line for line in path.read_text().splitlines()
                   if line.strip() and not line.lstrip().startswith("#")]
    assert all(" #" not in line for line in assignments)
