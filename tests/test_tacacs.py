import types
import time

import pytest

from ise_exporter import metrics
from ise_exporter.collectors import tacacs
from ise_exporter.state import StateStore
from ise_exporter.util import clear_metric


@pytest.fixture(autouse=True)
def _clear_metrics():
    for metric in tacacs._CONFIG_METRICS + tacacs._ACTIVITY_METRICS:
        clear_metric(metric)
    metrics.ise_tacacs_internal_users_total.set(0)
    metrics.ise_tacacs_internal_user_detail_coverage.set(0)
    metrics.ise_tacacs_dataconnect_up.set(0)


def _rows(metric, *labels):
    return {tuple(sample.labels[label] for label in labels): sample.value
            for sample in metric.collect()[0].samples}


class Client:
    def get_ers(self, path, params=None, get_all=False, api_name="x"):
        if path == "/config/internaluser":
            return [{"id": "u1", "name": "netadmin"}]
        if path == "/config/internaluser/u1":
            return {"InternalUser": {
                "id": "u1", "name": "netadmin", "enabled": True,
                "passwordNeverExpires": False, "changePassword": False,
                "passwordIDStore": "Internal Users", "dateCreated": "2026-07-01",
                "dateModified": "2026-07-06", "password": "must-not-persist",
            }}
        return None

    def get_pan_api(self, path, api_name="x"):
        if path == "/policy/device-admin/policy-set":
            return [{"id": "p1", "name": "Default", "state": "enabled",
                     "serviceName": "Default Device Admin", "hitCounts": 0}]
        if path == "/policy/device-admin/policy-set/p1/authentication":
            return [{"rule": {"name": "Default", "state": "enabled", "hitCounts": 0},
                     "identitySourceName": "All_User_ID_Stores"}]
        if path == "/policy/device-admin/policy-set/p1/authorization":
            return [{"rule": {"name": "Default", "state": "enabled", "hitCounts": 0},
                     "profile": "Deny All Shell Profile", "commands": ["DenyAllCommands"]}]
        if path == "/policy/device-admin/command-sets":
            return [{"name": "DenyAllCommands"}]
        if path == "/policy/device-admin/shell-profiles":
            return [{"name": "Deny All Shell Profile"}, {"name": "Default Shell Profile"}]
        return None


def test_collects_tacacs_inventory_rules_and_suspected_unused_account():
    tacacs.collect_config(Client(), types.SimpleNamespace(
        tacacs_internal_user_max=1000, tacacs_unused_account_days=1))

    assert metrics.ise_tacacs_internal_users_total._value.get() == 1
    assert _rows(metrics.ise_tacacs_internal_user_info, "username", "enabled") == {
        ("netadmin", "true"): 1.0}
    assert _rows(metrics.ise_tacacs_suspected_unused_internal_user,
                 "username", "reason") == {
        ("netadmin", "no_activity_or_change_1d"): 1.0}
    assert metrics.ise_tacacs_unused_account_review_seconds._value.get() == 86400
    assert metrics.ise_tacacs_internal_user_detail_coverage._value.get() == 1.0
    assert _rows(metrics.ise_tacacs_policy_objects_total, "object_type") == {
        ("policy_sets",): 1.0,
        ("authentication_rules",): 1.0,
        ("authorization_rules",): 1.0,
        ("command_sets",): 1.0,
        ("shell_profiles",): 2.0,
    }


def test_account_not_flagged_when_account_object_is_recent():
    client = Client()
    original = client.get_pan_api

    def get_pan_api(path, api_name="x"):
        result = original(path, api_name)
        if path == "/policy/device-admin/policy-set":
            result[0]["hitCounts"] = 7
        return result

    client.get_pan_api = get_pan_api
    original_ers = client.get_ers

    def get_ers(path, params=None, get_all=False, api_name="x"):
        result = original_ers(path, params, get_all, api_name)
        if path == "/config/internaluser/u1":
            result["InternalUser"]["dateModified"] = "2999-01-01"
        return result

    client.get_ers = get_ers
    tacacs.collect_config(client, types.SimpleNamespace(
        tacacs_internal_user_max=1000))

    assert metrics.ise_tacacs_suspected_unused_internal_user.collect()[0].samples == []


def test_internal_user_detail_failure_publishes_partial_coverage():
    metrics.ise_tacacs_internal_user_info.labels(
        username="previous", enabled="true", password_never_expires="false",
        change_password="false", identity_store="Internal Users").set(1)
    metrics.ise_tacacs_internal_users_total.set(1)
    client = Client()
    original = client.get_ers

    def get_ers(path, params=None, get_all=False, api_name="x"):
        if path == "/config/internaluser/u1":
            return None
        return original(path, params, get_all, api_name)

    client.get_ers = get_ers
    tacacs.collect_config(client, types.SimpleNamespace(
        tacacs_internal_user_max=1000, tacacs_unused_account_days=180))

    assert _rows(metrics.ise_tacacs_internal_user_info, "username") == {}
    assert metrics.ise_tacacs_internal_users_total._value.get() == 1
    assert metrics.ise_tacacs_internal_user_detail_coverage._value.get() == 0
    assert metrics.ise_tacacs_internal_user_detail_refresh_failures._value.get() == 1


def test_internal_user_detail_cache_survives_restart_and_detail_failure(tmp_path):
    state_path = str(tmp_path / "state.sqlite3")
    cfg = types.SimpleNamespace(
        state_db_path=state_path, tacacs_internal_user_max=1000,
        tacacs_unused_account_days=180,
        tacacs_internal_user_detail_max_requests=100,
        tacacs_internal_user_detail_ttl=604800)
    tacacs.collect_config(Client(), cfg)

    class NoDetail(Client):
        detail_requests = 0

        def get_ers(self, path, params=None, get_all=False, api_name="x"):
            if path.startswith("/config/internaluser/"):
                self.detail_requests += 1
                return None
            return super().get_ers(path, params, get_all, api_name)

    client = NoDetail()
    tacacs.collect_config(client, cfg)

    assert client.detail_requests == 0
    assert _rows(metrics.ise_tacacs_internal_user_info, "username") == {
        ("netadmin",): 1.0}
    assert metrics.ise_tacacs_internal_user_detail_coverage._value.get() == 1
    assert metrics.ise_tacacs_internal_user_detail_cache_entries._value.get() == 1

    store = StateStore(state_path)
    cached = store.tacacs_user_entries(["u1"])["u1"]["detail"]
    store.close()
    assert set(cached) <= set(tacacs._INTERNAL_USER_DETAIL_FIELDS)
    assert "password" not in cached


def test_internal_user_detail_refresh_is_bounded_and_converges(tmp_path):
    class ManyUsers(Client):
        detail_requests = []

        def get_ers(self, path, params=None, get_all=False, api_name="x"):
            if path == "/config/internaluser":
                return [{"id": f"u{number}", "name": f"user-{number}"}
                        for number in range(3)]
            if path.startswith("/config/internaluser/"):
                user_id = path.rsplit("/", 1)[-1]
                self.detail_requests.append(user_id)
                return {"InternalUser": {
                    "id": user_id, "name": f"user-{user_id[1:]}", "enabled": True,
                }}
            return super().get_ers(path, params, get_all, api_name)

    cfg = types.SimpleNamespace(
        state_db_path=str(tmp_path / "state.sqlite3"), tacacs_internal_user_max=1000,
        tacacs_unused_account_days=180,
        tacacs_internal_user_detail_max_requests=2,
        tacacs_internal_user_detail_ttl=604800)
    client = ManyUsers()

    tacacs.collect_config(client, cfg)
    assert client.detail_requests == ["u0", "u1"]
    assert metrics.ise_tacacs_internal_user_detail_coverage._value.get() == pytest.approx(2 / 3)
    assert metrics.ise_tacacs_internal_user_detail_refresh_deferred._value.get() == 1

    tacacs.collect_config(client, cfg)
    assert client.detail_requests == ["u0", "u1", "u2"]
    assert metrics.ise_tacacs_internal_user_detail_coverage._value.get() == 1
    assert metrics.ise_tacacs_internal_user_detail_refresh_deferred._value.get() == 0


def test_internal_user_selection_is_stable_and_reports_inventory_truncation(tmp_path):
    class UnstableOrder(Client):
        detail_requests = []

        def get_ers(self, path, params=None, get_all=False, api_name="x"):
            if path == "/config/internaluser":
                return [
                    {"id": "u3", "name": "zeta"},
                    {"id": "u1", "name": "alpha"},
                    {"id": "u2", "name": "beta"},
                ]
            if path.startswith("/config/internaluser/"):
                user_id = path.rsplit("/", 1)[-1]
                self.detail_requests.append(user_id)
                return {"InternalUser": {
                    "id": user_id, "name": {"u1": "alpha", "u2": "beta"}[user_id],
                    "enabled": True,
                }}
            return super().get_ers(path, params, get_all, api_name)

    cfg = types.SimpleNamespace(
        state_db_path=str(tmp_path / "state.sqlite3"), tacacs_internal_user_max=2,
        tacacs_unused_account_days=180,
        tacacs_internal_user_detail_max_requests=2,
        tacacs_internal_user_detail_ttl=604800)
    client = UnstableOrder()

    tacacs.collect_config(client, cfg)

    assert client.detail_requests == ["u1", "u2"]
    assert metrics.ise_tacacs_internal_users_total._value.get() == 3
    assert metrics.ise_tacacs_internal_user_inventory_selected._value.get() == 2
    assert metrics.ise_tacacs_internal_user_inventory_truncated._value.get() == 1
    assert metrics.ise_tacacs_internal_user_detail_coverage._value.get() == pytest.approx(2 / 3)


def test_internal_user_detail_refresh_stops_after_three_failures(tmp_path):
    class BrokenDetails(Client):
        detail_requests = 0

        def get_ers(self, path, params=None, get_all=False, api_name="x"):
            if path == "/config/internaluser":
                return [{"id": f"u{number}", "name": f"user-{number}"}
                        for number in range(10)]
            if path.startswith("/config/internaluser/"):
                self.detail_requests += 1
                return None
            return super().get_ers(path, params, get_all, api_name)

    cfg = types.SimpleNamespace(
        state_db_path=str(tmp_path / "state.sqlite3"), tacacs_internal_user_max=1000,
        tacacs_unused_account_days=180,
        tacacs_internal_user_detail_max_requests=10,
        tacacs_internal_user_detail_ttl=604800,
        tacacs_internal_user_detail_request_interval_ms=0)
    client = BrokenDetails()

    tacacs.collect_config(client, cfg)

    assert client.detail_requests == 3
    assert metrics.ise_tacacs_internal_user_detail_refresh_requests._value.get() == 3
    assert metrics.ise_tacacs_internal_user_detail_refresh_failures._value.get() == 3
    assert metrics.ise_tacacs_internal_user_detail_refresh_deferred._value.get() == 7


def test_valid_empty_tacacs_configuration_clears_stale_labels():
    metrics.ise_tacacs_internal_user_info.labels(
        username="previous", enabled="true", password_never_expires="false",
        change_password="false", identity_store="Internal Users").set(1)

    class EmptyClient:
        def get_ers(self, path, params=None, get_all=False, api_name="x"):
            return []

        def get_pan_api(self, path, api_name="x"):
            return []

    tacacs.collect_config(EmptyClient(), types.SimpleNamespace(
        tacacs_internal_user_max=1000, tacacs_unused_account_days=180))

    assert not metrics.ise_tacacs_internal_user_info._metrics
    assert metrics.ise_tacacs_internal_users_total._value.get() == 0
    assert metrics.ise_tacacs_internal_user_detail_coverage._value.get() == 1


def test_malformed_device_admin_rule_preserves_previous_snapshot():
    metrics.ise_tacacs_policy_objects_total.labels(object_type="policy_sets").set(9)
    old_rows = _rows(metrics.ise_tacacs_policy_objects_total, "object_type")

    class MalformedRule(Client):
        def get_pan_api(self, path, api_name="x"):
            if path.endswith("/authentication"):
                return [None]
            return super().get_pan_api(path, api_name)

    tacacs.collect_config(MalformedRule(), types.SimpleNamespace(
        tacacs_internal_user_max=1000, tacacs_unused_account_days=180))

    assert _rows(metrics.ise_tacacs_policy_objects_total, "object_type") == old_rows


def test_collects_dataconnect_account_attribution(monkeypatch):
    class DataConnect:
        closed = False

        def __init__(self):
            self.sql = []
            self.parameters = []

        def query(self, sql, parameters=None):
            self.sql.append(sql)
            self.parameters.append(parameters)
            if "tacacs_authentication" in sql:
                return [{
                    "username": "netadmin", "status": "Fail", "device_name": "switch-1",
                    "authentication_policy": "Default >> Default",
                    "identity_store": "Internal Users", "failure_class": "credentials",
                    "hits": 2, "last_seen": 100, "total_events": 20,
                    "total_groups": 4,
                }]
            if "tacacs_authorization" in sql:
                return [{
                    "username": "netadmin", "status": "Pass", "device_name": "switch-1",
                    "authorization_policy": "Admins", "shell_profile": "Privilege 15",
                    "matched_command_set": "PermitAll", "command_from_device": "show run",
                    "hits": 3, "last_seen": 110, "total_events": 30,
                    "total_groups": 5,
                }]
            return [{
                "username": "netadmin", "status": "Pass", "device_name": "switch-1",
                "command_family": "show", "hits": 4, "last_seen": 120,
                "total_events": 40, "total_groups": 6,
            }]

        def close(self):
            self.closed = True

    monkeypatch.setattr(tacacs.time, "time", lambda: 100000)
    dataconnect = DataConnect()
    tacacs.collect_activity(dataconnect, types.SimpleNamespace(dataconnect_max_groups=50))

    assert dataconnect.closed is False
    assert all("WHERE epoch_time >= :minimum_epoch" in sql for sql in dataconnect.sql)
    assert dataconnect.parameters == [{"minimum_epoch": 78400}] * 3
    assert metrics.ise_tacacs_dataconnect_up._value.get() == 1
    assert _rows(metrics.ise_tacacs_account_authentication_events,
                 "username", "status", "device", "failure_class") == {
        ("netadmin", "Fail", "switch-1", "credentials"): 2.0}
    assert _rows(metrics.ise_tacacs_account_authorization_events,
                 "username", "command_set") == {
        ("netadmin", "PermitAll"): 3.0}
    assert _rows(metrics.ise_tacacs_accounting_events,
                 "username", "command_family") == {
        ("netadmin", "show"): 4.0}
    assert _rows(metrics.ise_tacacs_account_last_seen_timestamp,
                 "username", "event_type") == {
        ("netadmin", "authentication"): 100.0,
        ("netadmin", "authorization"): 110.0,
        ("netadmin", "accounting"): 120.0,
    }
    assert _rows(metrics.ise_tacacs_events_total, "event_type") == {
        ("authentication",): 20.0,
        ("authorization",): 30.0,
        ("accounting",): 40.0,
    }
    assert _rows(metrics.ise_tacacs_topk_truncated, "event_type") == {
        ("authentication",): 1.0,
        ("authorization",): 1.0,
        ("accounting",): 1.0,
    }


def test_internal_last_seen_survives_view_rollover_and_restart(tmp_path):
    state_path = str(tmp_path / "state.sqlite3")
    cfg = types.SimpleNamespace(
        dataconnect_max_groups=50, state_db_path=state_path,
        tacacs_internal_user_max=1000, tacacs_unused_account_days=1)
    tacacs.collect_config(Client(), cfg)
    now = int(time.time())

    class CurrentActivity:
        def query(self, sql, parameters=None):
            event_type = next(kind for kind in tacacs._EVENT_TYPES if f"tacacs_{kind}" in sql)
            return [{
                "username": "netadmin", "status": "Pass", "device_name": "switch-1",
                "authentication_policy": "Default", "identity_store": "Internal Users",
                "failure_class": "none", "authorization_policy": "Admins",
                "shell_profile": "Privilege 15", "matched_command_set": "PermitAll",
                "command_family": "show", "hits": 1, "last_seen": now,
                "total_events": 1, "total_groups": 1, "event_type": event_type,
            }, {
                "username": "external-user", "status": "Pass", "device_name": "switch-1",
                "authentication_policy": "Default", "identity_store": "Active Directory",
                "failure_class": "none", "authorization_policy": "Admins",
                "shell_profile": "Privilege 15", "matched_command_set": "PermitAll",
                "command_family": "show", "hits": 1, "last_seen": now,
                "total_events": 1, "total_groups": 2,
            }]

    tacacs.collect_activity(CurrentActivity(), cfg)
    for metric in tacacs._ACTIVITY_METRICS:
        clear_metric(metric)

    class RolledOverViews:
        def query(self, sql, parameters=None):
            return []

    tacacs.collect_activity(RolledOverViews(), cfg)

    assert _rows(metrics.ise_tacacs_account_last_seen_timestamp,
                 "username", "event_type") == {
        ("netadmin", "authentication"): float(now),
        ("netadmin", "authorization"): float(now),
        ("netadmin", "accounting"): float(now),
    }
    assert all(row[0] != "external-user" for row in _rows(
        metrics.ise_tacacs_account_last_seen_timestamp, "username", "event_type"))

    for metric in tacacs._CONFIG_METRICS:
        clear_metric(metric)
    tacacs.collect_config(Client(), cfg)
    assert metrics.ise_tacacs_suspected_unused_internal_user.collect()[0].samples == []


def test_internal_account_last_seen_is_not_lost_outside_dimensional_topk(tmp_path):
    state_path = str(tmp_path / "state.sqlite3")
    cfg = types.SimpleNamespace(
        dataconnect_max_groups=1, state_db_path=state_path,
        tacacs_internal_user_max=1000, tacacs_unused_account_days=1)
    tacacs.collect_config(Client(), cfg)
    now = int(time.time())

    class Activity:
        def __init__(self):
            self.sql = []
            self.parameters = []

        def query(self, sql, parameters=None):
            self.sql.append(sql)
            self.parameters.append(parameters)
            return [{
                "breakdown": "detail", "username": "high-volume-ad-user",
                "status": "Pass", "device_name": "switch-1", "hits": 100,
                "last_seen": now, "total_events": 101, "total_groups": 2,
            }, {
                "breakdown": "internal_last_seen", "username": "netadmin",
                "hits": 1, "last_seen": now, "total_events": 101,
                "total_groups": 2,
            }]

    activity = Activity()
    tacacs.collect_activity(activity, cfg)

    assert all("GROUP BY GROUPING SETS" in sql for sql in activity.sql)
    assert all(parameters["internal_user_0"] == "netadmin"
               for parameters in activity.parameters)
    last_seen = _rows(metrics.ise_tacacs_account_last_seen_timestamp,
                      "username", "event_type")
    assert {key: value for key, value in last_seen.items() if key[0] == "netadmin"} == {
        ("netadmin", "authentication"): float(now),
        ("netadmin", "authorization"): float(now),
        ("netadmin", "accounting"): float(now),
    }

    tacacs.collect_config(Client(), cfg)
    assert metrics.ise_tacacs_suspected_unused_internal_user.collect()[0].samples == []
