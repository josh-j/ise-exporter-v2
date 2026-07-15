import types

import pytest

from ise_exporter import metrics
from ise_exporter.collectors import backup, certificates, deployment, licensing, patches
from ise_exporter.util import clear_metric


@pytest.fixture(autouse=True)
def _clear_metrics():
    for metric in (
        *backup._METRICS,
        *certificates._METRICS,
        *deployment._METRICS,
    ):
        clear_metric(metric)
        if hasattr(metric, "_value"):
            metric.set(0)
    metrics.ise_up.set(0)
    for metric in licensing._METRICS:
        clear_metric(metric)
    metrics.ise_version_info.info({})
    metrics.ise_patch_level.set(0)
    clear_metric(metrics.ise_patch_installed)


def _cfg():
    return types.SimpleNamespace(medium_interval=300)


def test_backup_transport_failure_preserves_previous_snapshot():
    metrics.ise_backup_configured.set(1)
    metrics.ise_backup_last_success_timestamp.set(100)
    metrics.ise_backup_age_hours.set(5)

    class Client:
        def get_pan_api(self, *args, **kwargs):
            return None

    backup.collect(Client(), _cfg())

    assert metrics.ise_backup_configured._value.get() == 1
    assert metrics.ise_backup_last_success_timestamp._value.get() == 100
    assert metrics.ise_backup_age_hours._value.get() == 5


def test_backup_valid_empty_response_clears_stale_snapshot():
    metrics.ise_backup_configured.set(1)
    metrics.ise_backup_last_success_timestamp.set(100)
    metrics.ise_backup_age_hours.set(5)

    class Client:
        def get_pan_api(self, *args, **kwargs):
            return {}

    backup.collect(Client(), _cfg())

    assert metrics.ise_backup_configured._value.get() == 0
    assert metrics.ise_backup_last_success_timestamp._value.get() == 0
    assert metrics.ise_backup_age_hours._value.get() == 0


def test_certificate_page_failure_preserves_previous_snapshot(monkeypatch):
    metrics.ise_certificate_expiry_days.labels(
        hostname="old", cert_name="old", cert_type="system", usage="Admin").set(10)
    old_keys = set(metrics.ise_certificate_expiry_days._metrics)
    monkeypatch.setattr(
        certificates, "get_nodes",
        lambda *args, **kwargs: [{"hostname": "psn-1"}, {"hostname": "psn-2"}],
    )

    class Client:
        def get_pan_api(self, path, **kwargs):
            if path.endswith("psn-1"):
                return []
            return None

    certificates.collect(Client(), _cfg())

    assert set(metrics.ise_certificate_expiry_days._metrics) == old_keys


def test_certificate_valid_empty_stores_clear_stale_labels(monkeypatch):
    metrics.ise_certificate_expiry_days.labels(
        hostname="old", cert_name="old", cert_type="system", usage="Admin").set(10)
    monkeypatch.setattr(
        certificates, "get_nodes", lambda *args, **kwargs: [{"hostname": "psn-1"}],
    )

    class Client:
        def get_pan_api(self, path, **kwargs):
            return []

    certificates.collect(Client(), _cfg())

    assert not metrics.ise_certificate_expiry_days._metrics
    assert set(metrics.ise_certificates_expiring_soon._metrics) == {("30",), ("60",), ("90",)}
    assert all(child._value.get() == 0
               for child in metrics.ise_certificates_expiring_soon._metrics.values())


def test_certificate_security_binding_and_issuer_coverage(monkeypatch):
    monkeypatch.setattr(
        certificates, "get_nodes", lambda *args, **kwargs: [{"hostname": "psn-1"}],
    )

    class Client:
        def get_pan_api(self, path, **kwargs):
            if "system-certificate" in path:
                return [{
                    "friendlyName": "EAP cert", "expirationDate": "2030-01-01",
                    "usedBy": "Admin, EAP Authentication", "keySize": 2048,
                    "signatureAlgorithm": "SHA256withRSA", "selfSigned": False,
                    "issuedBy": "Lab Issuing CA",
                }]
            return [{
                "friendlyName": "Lab CA", "expirationDate": "2035-01-01",
                "trustedFor": "Authentication within ISE", "keySize": 4096,
                "signatureAlgorithm": "SHA256withRSA", "subject": "CN=Lab Issuing CA",
            }]

    certificates.collect(Client(), _cfg())

    assert metrics.ise_certificate_binding.labels(
        hostname="psn-1", cert_name="EAP cert", cert_type="system", role="eap"
    )._value.get() == 1
    assert metrics.ise_certificate_key_size_bits.labels(
        hostname="psn-1", cert_name="EAP cert", cert_type="system")._value.get() == 2048
    assert metrics.ise_certificate_weak_signature.labels(
        hostname="psn-1", cert_name="EAP cert", cert_type="system")._value.get() == 0
    assert metrics.ise_certificate_issuer_present_in_trust_store.labels(
        hostname="psn-1", cert_name="EAP cert")._value.get() == 1


def test_deployment_pan_ha_failure_preserves_previous_labelsets(monkeypatch):
    metrics.ise_deployment_status.labels(
        node="old", roles="PSN", services="none").state("Connected")
    metrics.ise_node_count.labels(role="PSN").set(1)
    old_status = set(metrics.ise_deployment_status._metrics)
    old_counts = set(metrics.ise_node_count._metrics)
    monkeypatch.setattr(
        deployment, "get_nodes",
        lambda *args, **kwargs: [{
            "hostname": "new", "nodeStatus": "Connected",
            "roles": [], "services": [],
        }],
    )

    class Client:
        host = "ise.example"

        def get_pan_api(self, *args, **kwargs):
            return None

    deployment.collect(Client(), _cfg())

    assert set(metrics.ise_deployment_status._metrics) == old_status
    assert set(metrics.ise_node_count._metrics) == old_counts
    assert metrics.ise_up._value.get() == 0


def test_deployment_success_replaces_removed_nodes(monkeypatch):
    metrics.ise_deployment_status.labels(
        node="old", roles="PSN", services="none").state("Connected")
    monkeypatch.setattr(
        deployment, "get_nodes",
        lambda *args, **kwargs: [{
            "hostname": "new", "nodeStatus": "Connected",
            "roles": ["PrimaryAdmin"], "services": ["Session"],
        }],
    )

    class Client:
        host = "ise.example"

        def get_pan_api(self, *args, **kwargs):
            return {"isEnabled": False}

    deployment.collect(Client(), _cfg())

    keys = set(metrics.ise_deployment_status._metrics)
    assert all("old" not in key for key in keys)
    assert any("new" in key for key in keys)
    assert metrics.ise_pan_ha_enabled._value.get() == 0
    assert metrics.ise_up._value.get() == 1


@pytest.mark.parametrize("pan_ha", ({"isEnabled": "false"}, {"isEnabled": 1}, {}))
def test_deployment_rejects_non_boolean_pan_ha_without_replacing_snapshot(
        monkeypatch, pan_ha):
    metrics.ise_deployment_status.labels(
        node="old", roles="PSN", services="none").state("Connected")
    old_status = set(metrics.ise_deployment_status._metrics)
    monkeypatch.setattr(
        deployment, "get_nodes",
        lambda *args, **kwargs: [{
            "hostname": "new", "nodeStatus": "Connected",
            "roles": [], "services": [],
        }],
    )

    class Client:
        host = "ise.example"

        def get_pan_api(self, *args, **kwargs):
            return pan_ha

    deployment.collect(Client(), _cfg())

    assert set(metrics.ise_deployment_status._metrics) == old_status
    assert metrics.ise_up._value.get() == 0


@pytest.mark.parametrize(("field", "value"), (
    ("roles", "PrimaryAdmin"),
    ("services", "Session"),
))
def test_deployment_rejects_non_list_role_fields(monkeypatch, field, value):
    node = {
        "hostname": "laba-ise-001", "nodeStatus": "Connected",
        "roles": [], "services": [],
    }
    node[field] = value
    monkeypatch.setattr(deployment, "get_nodes", lambda *args, **kwargs: [node])

    class Client:
        host = "ise.example"

        def get_pan_api(self, *args, **kwargs):
            raise AssertionError("invalid nodes must fail before PAN HA is queried")

    deployment.collect(Client(), _cfg())

    assert metrics.ise_up._value.get() == 0
    assert not metrics.ise_deployment_status._metrics


@pytest.mark.parametrize("state, expected", [
    ("COMPLIANT", 1),
    ("FULL_COMPLIANCE", 1),
    ("RESERVED_IN_COMPLIANCE", 1),
    ("NONCOMPLIANT", 0),
    ("EVALUATION", 0),
    ("EVALUATION_EXPIRED", 0),
    ("RELEASED_ENTITLEMENT", 0),
    ("", 0),
])
def test_license_compliance_matches_ise_33_enum(state, expected):
    class Client:
        def get_pan_api(self, *args, **kwargs):
            return [{
                "name": "Advantage",
                "consumptionCounter": 42,
                "status": "ENABLED",
                "compliance": state,
            }]

    licensing.collect(Client(), _cfg())

    assert metrics.ise_license_compliance.labels(
        tier="Advantage")._value.get() == expected
    assert metrics.ise_license_consumption.labels(tier="Advantage")._value.get() == 42


def test_malformed_license_tier_preserves_previous_snapshot():
    metrics.ise_license_consumption.labels(tier="old").set(7)
    metrics.ise_license_compliance.labels(tier="old").set(1)
    metrics.ise_license_enabled.labels(tier="old").set(1)

    class Client:
        def get_pan_api(self, *args, **kwargs):
            return [
                {"name": "new", "consumptionCounter": 8},
                {"name": "broken", "consumptionCounter": "not-a-number"},
            ]

    licensing.collect(Client(), _cfg())

    assert set(metrics.ise_license_consumption._metrics) == {("old",)}
    assert metrics.ise_license_consumption.labels(tier="old")._value.get() == 7


def test_malformed_patch_entry_preserves_version_and_patch_snapshot():
    metrics.ise_version_info.info({"version": "3.3.0-old"})
    metrics.ise_patch_level.set(10)
    metrics.ise_patch_installed.labels(patch_number="10").set(1)

    class Client:
        def get_pan_api(self, *args, **kwargs):
            return {
                "iseVersion": "3.3.0-new",
                "patchVersion": [{"patchNumber": 11}, {"patchNumber": "broken"}],
            }

    patches.collect(Client(), _cfg())

    assert metrics.ise_version_info._value == {"version": "3.3.0-old"}
    assert metrics.ise_patch_level._value.get() == 10
    assert set(metrics.ise_patch_installed._metrics) == {("10",)}


def test_patch_success_atomically_replaces_version_and_installed_set():
    metrics.ise_version_info.info({"version": "3.2.0"})
    metrics.ise_patch_level.set(9)
    metrics.ise_patch_installed.labels(patch_number="9").set(1)

    class Client:
        def get_pan_api(self, *args, **kwargs):
            return {
                "iseVersion": "3.3.0.430",
                "patchVersion": [{"patchNumber": "10"}, {"patchNumber": 11}],
            }

    patches.collect(Client(), _cfg())

    assert metrics.ise_version_info._value == {"version": "3.3.0.430"}
    assert metrics.ise_patch_level._value.get() == 11
    assert set(metrics.ise_patch_installed._metrics) == {("10",), ("11",)}


@pytest.mark.parametrize("patch_versions", (
    [],
    [{"patchNumber": 10}],
    [{"patchNumber": 11}, {"patchNumber": 12}],
))
def test_patch_runtime_rejects_partial_or_unsupported_patch_level(patch_versions):
    metrics.ise_version_info.info({"version": "3.3.0.430"})
    metrics.ise_patch_level.set(11)
    metrics.ise_patch_installed.labels(patch_number="11").set(1)

    class Client:
        def get_pan_api(self, *args, **kwargs):
            return {
                "iseVersion": "3.3.0.430",
                "patchVersion": patch_versions,
            }

    patches.collect(Client(), _cfg())

    assert metrics.ise_patch_level._value.get() == 11
    assert set(metrics.ise_patch_installed._metrics) == {("11",)}
