import types

import pytest

from ise_exporter import metrics
from ise_exporter.collectors import tacacs
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
                "dateModified": "2026-07-06",
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
        tacacs_internal_user_max=1000, tacacs_unused_account_days=1, max_workers=2))

    assert metrics.ise_tacacs_internal_users_total._value.get() == 1
    assert _rows(metrics.ise_tacacs_internal_user_info, "username", "enabled") == {
        ("netadmin", "true"): 1.0}
    assert _rows(metrics.ise_tacacs_suspected_unused_internal_user,
                 "username", "reason") == {
        ("netadmin", "object_not_modified_1d"): 1.0}
    assert metrics.ise_tacacs_internal_user_detail_coverage._value.get() == 1.0
    assert _rows(metrics.ise_tacacs_policy_objects_total, "object_type") == {
        ("policy_sets",): 1.0,
        ("authentication_rules",): 1.0,
        ("authorization_rules",): 1.0,
        ("command_sets",): 1.0,
        ("shell_profiles",): 2.0,
    }


def test_account_not_flagged_when_device_admin_policy_has_hits():
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
        tacacs_internal_user_max=1000, max_workers=2))

    assert metrics.ise_tacacs_suspected_unused_internal_user.collect()[0].samples == []


def test_internal_user_detail_failure_preserves_previous_snapshot():
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
        tacacs_internal_user_max=1000, tacacs_unused_account_days=180, max_workers=2))

    assert _rows(metrics.ise_tacacs_internal_user_info, "username") == {
        ("previous",): 1.0}
    assert metrics.ise_tacacs_internal_users_total._value.get() == 1


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
        tacacs_internal_user_max=1000, tacacs_unused_account_days=180, max_workers=2))

    assert not metrics.ise_tacacs_internal_user_info._metrics
    assert metrics.ise_tacacs_internal_users_total._value.get() == 0
    assert metrics.ise_tacacs_internal_user_detail_coverage._value.get() == 1


def test_collects_dataconnect_account_attribution():
    class DataConnect:
        closed = False

        def query(self, sql):
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

    dataconnect = DataConnect()
    tacacs.collect_activity(dataconnect, types.SimpleNamespace(dataconnect_max_groups=50))

    assert dataconnect.closed is False
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
