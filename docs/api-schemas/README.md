# Cisco ISE API Schemas

This directory contains the OpenAPI schemas captured from the lab ISE node used
for exporter development. The capture metadata below is intentionally
historical. The same VM has since been renamed and moved; see the
[current rooted-appliance snapshot](../rooted-ise-ground-truth.md).

Capture source:

- Host: `ise01`
- Address: `10.81.0.10`
- Cisco ISE version: `3.3.0.430`
- Patch: `11`
- Captured at: `2026-07-11T15:11:02+02:00`
- Index endpoint: `GET /api/swagger-resources`

Current appliance identity verified at `2026-07-14T05:25:38Z`:

- Host: `laba-ise-001` / `laba-ise-001.ise.lab`
- Address: `10.200.30.10`
- Cisco ISE version: `3.3.0.430`, Patch `11`

The schema files remain the July 11 capture. Renaming or moving a node does not
retroactively change an artifact's provenance.

The raw resource index is in [`swagger-resources.json`](swagger-resources.json).
Each group schema is stored under [`openapi/`](openapi/), with a machine-readable
summary in [`openapi-manifest.tsv`](openapi-manifest.tsv).

## OpenAPI Groups

| Group | File | Paths | Schemas |
|---|---:|---:|---:|
| Backup Restore | [`backup-restore.json`](openapi/backup-restore.json) | 5 | 12 |
| Certificates | [`certificates.json`](openapi/certificates.json) | 16 | 52 |
| CustomAttributes | [`customattributes.json`](openapi/customattributes.json) | 3 | 3 |
| Dataconnect | [`dataconnect.json`](openapi/dataconnect.json) | 5 | 10 |
| Deployment | [`deployment.json`](openapi/deployment.json) | 15 | 31 |
| Duo Identity Sync | [`duo-identity-sync.json`](openapi/duo-identity-sync.json) | 7 | 16 |
| Endpoint Replication | [`endpoint-replication.json`](openapi/endpoint-replication.json) | 1 | 6 |
| Endpoints | [`endpoints.json`](openapi/endpoints.json) | 5 | 5 |
| FiveG | [`fiveg.json`](openapi/fiveg.json) | 10 | 19 |
| IPsec | [`ipsec.json`](openapi/ipsec.json) | 6 | 14 |
| Integration Catalog | [`integration-catalog.json`](openapi/integration-catalog.json) | 5 | 7 |
| LSD Settings | [`lsd-settings.json`](openapi/lsd-settings.json) | 1 | 2 |
| License | [`license.json`](openapi/license.json) | 7 | 18 |
| MFA | [`mfa.json`](openapi/mfa.json) | 5 | 11 |
| Patch | [`patch.json`](openapi/patch.json) | 6 | 12 |
| Policy | [`policy.json`](openapi/policy.json) | 74 | 53 |
| Repository | [`repository.json`](openapi/repository.json) | 3 | 15 |
| SGT Reservation | [`sgt-reservation.json`](openapi/sgt-reservation.json) | 3 | 11 |
| System Settings | [`system-settings.json`](openapi/system-settings.json) | 2 | 5 |
| Task Service | [`task-service.json`](openapi/task-service.json) | 2 | 2 |
| TrustSec | [`trustsec.json`](openapi/trustsec.json) | 7 | 8 |
| Upgrade | [`upgrade.json`](openapi/upgrade.json) | 8 | 15 |
| pxGrid Cloud | [`pxgrid-cloud.json`](openapi/pxgrid-cloud.json) | 5 | 13 |
| pxGrid Direct | [`pxgrid-direct.json`](openapi/pxgrid-direct.json) | 6 | 19 |

## Notes

- These are PAN OpenAPI schemas exposed by ISE's `/api` plane. They do not cover
  all ERS or MnT endpoints used by the exporter.
- The obvious ERS SDK paths on this node returned the SDK HTML, not JSON
  OpenAPI documents.
- The files are schema artifacts only. They contain model fields and example
  strings from ISE documentation, not captured credentials or live response data.

## Refresh

From a host that can reach the lab ISE node and read the UI admin secret:

```sh
pw=$(sudo cat /run/secrets/lab_ise_ui_admin_pw)
curl --fail --silent --show-error --cacert /path/to/ise-admin-ca.pem \
  -u "admin:$pw" https://laba-ise-001.ise.lab/api/swagger-resources
curl --fail --silent --show-error --cacert /path/to/ise-admin-ca.pem \
  -u "admin:$pw" --get \
  --data-urlencode "group=Policy" \
  https://laba-ise-001.ise.lab/api/v3/api-docs
```

For a full refresh, iterate the `.name` values from `swagger-resources.json` and
write each `group` response to the matching file in `openapi/`.
