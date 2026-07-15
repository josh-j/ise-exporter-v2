import pytest

from ise_exporter.compatibility import (
    ISECompatibilityError,
    validate_ise_compatibility,
)


class Client:
    def __init__(self, patch=None, nodes=None):
        self.patch = patch
        self.nodes = nodes
        self.calls = []

    def get_pan_api(self, path, api_name=""):
        self.calls.append((path, api_name))
        return self.patch if path == "/patch" else self.nodes


def compatible_client():
    return Client(
        patch={
            "iseVersion": "3.3.0.430",
            "patchVersion": [{"patchNumber": 11, "installDate": "2026-01-01"}],
        },
        nodes=[{
            "hostname": "laba-ise-001",
            "nodeStatus": "Connected",
            "roles": ["PrimaryAdmin", "PrimaryMonitoring"],
            "services": ["Session", "Profiler", "DeviceAdmin"],
        }],
    )


def test_validates_exact_lab_release_and_deployment_schema():
    client = compatible_client()

    result = validate_ise_compatibility(client)

    assert result.ise_version == "3.3.0.430"
    assert result.patch_level == 11
    assert result.installed_patches == (11,)
    assert result.deployment_nodes == ("laba-ise-001",)
    assert client.calls == [
        ("/patch", "compatibility_patch"),
        ("/deployment/node", "compatibility_deployment"),
    ]


@pytest.mark.parametrize("version", ["3.2.0.542", "3.3.0.430-Patch11", "3.4.0.608", None])
def test_rejects_every_other_ise_version(version):
    client = compatible_client()
    client.patch["iseVersion"] = version

    with pytest.raises(ISECompatibilityError, match="requires exactly 3.3.0.430 Patch 11"):
        validate_ise_compatibility(client)

    assert client.calls == [("/patch", "compatibility_patch")]


@pytest.mark.parametrize("patches, detected", [([], 0), ([{"patchNumber": 10}], 10),
                                                ([{"patchNumber": 11}, {"patchNumber": 12}], 12)])
def test_rejects_every_other_patch_level(patches, detected):
    client = compatible_client()
    client.patch["patchVersion"] = patches

    with pytest.raises(ISECompatibilityError,
                       match=rf"unsupported Cisco ISE patch level {detected}"):
        validate_ise_compatibility(client)


@pytest.mark.parametrize("payload, message", [
    (None, "returned no response"),
    ({"iseVersion": "3.3.0.430"}, "returned no patchVersion list"),
    ({"iseVersion": "3.3.0.430", "patchVersion": [{}]}, "invalid patchVersion entry"),
    ({"iseVersion": "3.3.0.430", "patchVersion": [{"patchNumber": "eleven"}]},
     "invalid patchNumber"),
])
def test_rejects_unusable_patch_responses(payload, message):
    client = compatible_client()
    client.patch = payload

    with pytest.raises(ISECompatibilityError, match=message):
        validate_ise_compatibility(client)


@pytest.mark.parametrize("nodes, message", [
    (None, "returned no deployment nodes"),
    ([], "returned no deployment nodes"),
    ([{"hostname": "laba-ise-001"}], "missing fields: nodeStatus, roles, services"),
    ([{"hostname": "laba-ise-001", "nodeStatus": "Connected", "roles": "PAN",
       "services": []}], "invalid status, roles, or services"),
    ([{"hostname": "laba-ise-001", "nodeStatus": "Syncing", "roles": [],
       "services": []}], "invalid status, roles, or services"),
    ([{"hostname": "laba-ise-001", "nodeStatus": "Connected", "roles": ["PAN"],
       "services": []}], "invalid status, roles, or services"),
])
def test_rejects_incompatible_deployment_responses(nodes, message):
    client = compatible_client()
    client.nodes = nodes

    with pytest.raises(ISECompatibilityError, match=message):
        validate_ise_compatibility(client)
