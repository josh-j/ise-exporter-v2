import types

import pytest

from ise_exporter import metrics
from ise_exporter.collectors import tacacs
from ise_exporter.util import clear_metric


@pytest.fixture(autouse=True)
def _clear_metrics():
    for metric in tacacs._METRICS:
        clear_metric(metric)
    metrics.ise_tacacs_internal_users_total.set(0)


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
    tacacs.collect(Client(), types.SimpleNamespace(
        tacacs_internal_user_max=1000, max_workers=2))

    assert metrics.ise_tacacs_internal_users_total._value.get() == 1
    assert _rows(metrics.ise_tacacs_internal_user_info, "username", "enabled") == {
        ("netadmin", "true"): 1.0}
    assert _rows(metrics.ise_tacacs_suspected_unused_internal_user,
                 "username", "reason") == {
        ("netadmin", "no_device_admin_policy_hits"): 1.0}
    assert _rows(metrics.ise_tacacs_policy_set_hits, "policy_set") == {
        ("Default",): 0.0}
    assert _rows(metrics.ise_tacacs_authentication_rule_hits,
                 "policy_set", "rule", "identity_source") == {
        ("Default", "Default", "All_User_ID_Stores"): 0.0}
    assert _rows(metrics.ise_tacacs_authorization_rule_hits,
                 "profile", "command_sets") == {
        ("Deny All Shell Profile", "DenyAllCommands"): 0.0}
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
    tacacs.collect(client, types.SimpleNamespace(
        tacacs_internal_user_max=1000, max_workers=2))

    assert metrics.ise_tacacs_suspected_unused_internal_user.collect()[0].samples == []
