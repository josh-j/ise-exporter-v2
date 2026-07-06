# Grafana dashboards

Six dashboards, each scoped to one part of the exporter's metric surface
(`ise_exporter/metrics.py`):

| File | Covers | Notes |
|------|--------|-------|
| `ise-overview.json` | Deployment health, node status, scrape/API error rates, collector health, certs, licensing, backup, patch level | Start here — the one to put on a wallboard/alert off of |
| `ise-sessions-auth.json` | Active sessions by NAD/site/ops-owner, session status, failure reasons, auth methods, authz profiles/rules/policy sets | Populated by poll mode (MnT) or pxGrid streaming, whichever is active — see below. "Sessions by PSN" is poll-mode only |
| `ise-endpoints-devices.json` | Endpoint profiling (model/manufacturer/OS/policy breakdown, MFC coverage) and network device inventory | Model/manufacturer/OS panels require `COLLECT_PXGRID_ENDPOINTS=true` (default) |
| `ise-endpoint-profiles.json` | Endpoints broken down by ISE's profiler policy hierarchy — category/parent/profile, filterable table, catalog size, cache freshness | Requires `COLLECT_PXGRID_ENDPOINTS=true` (default) — see below |
| `ise-secureclient.json` | Posture compliance (Compliant/NonCompliant/Pending) with overall %, by-site + by-ops-owner; MDM device trust; Secure Client agent version | Posture works in stream (best-effort poll); MDM is stream-only; agent version is best-effort — see below |
| `ise-pxgrid-health.json` | pxGrid stream connection state, event throughput, resync counts, streamed state size | Only populated when `COLLECT_PXGRID_STREAM=true`; all panels correctly show "No data" in poll mode |

## Import

Grafana UI: **Dashboards → New → Import**, upload the JSON file (or paste it),
then select your Prometheus datasource when prompted for the `DS_PROMETHEUS`
input. Repeat for each file.

Or provision them automatically alongside Prometheus/Grafana in
`docker-compose`/Kubernetes by mounting this folder and adding a
`dashboardProviders` config, e.g.:

```yaml
apiVersion: 1
providers:
  - name: ise-exporter
    folder: ISE
    type: file
    options:
      path: /etc/grafana/provisioning/dashboards/ise-exporter
```

(mount this `dashboards/` folder to that path in the Grafana container).

## Poll vs. streaming mode

`ise-sessions-auth.json`'s status/method/profile panels are fed by
`collectors/authz.py`'s per-MAC fan-out in poll mode (subject to
`SESSION_DETAIL_CACHE_TTL` warmup — watch the "Authz Cache Warmup" stat) or by
the pxGrid session topic directly in streaming mode (no warmup lag). Either
way the same panels populate; only the freshness/latency differs. Failure
reasons, matched authz rule, and policy set always come from the MnT fan-out
in both modes — pxGrid's session topic doesn't carry those fields.

**Per-site vs. per-PSN.** For a geographic breakdown use **"Sessions by Site
(Location)"** (`sum by (location) (ise_radius_sessions_by_nad)`, derived from
each session's NAD → Network Device Group Location). It works in both modes.
The separate **"Sessions by PSN"** panel is **poll-mode only**: the pxGrid
session directory object carries no owning-PSN field (only `nasIpAddress` and
friends), so in streaming mode there is no way to attribute a session to a PSN
and the panel correctly shows "No data" rather than collapsing every session
under a single placeholder node. If "Sessions by Site" shows mostly `Unknown`,
the session's `nasIpAddress` isn't matching a device IP in the ERS inventory —
check `COLLECT_DEVICE_DETAILS=true` (default) and that the NAD's RADIUS source
IP is one of its registered `NetworkDeviceIPList` addresses.

## Secure Client / posture compliance

`ise-secureclient.json` reads three data sources with different availability:

- **Posture status** (`ise_session_posture_status{status, location, ops_owner}`) —
  unique endpoints by posture verdict. In stream mode it comes from the pxGrid
  session object's `postureStatus`; in poll mode from MnT session detail
  (top-level `posture_status`, falling back to the `other_attr_string`). Status is
  canonicalized to `Compliant` / `NonCompliant` / `Pending` / `NotApplicable` /
  `Unknown` / `Error`; an endpoint with no posture assessment buckets to
  `NotApplicable`, so **compliance %** is computed over `Compliant + NonCompliant`
  only. Poll mode is best-effort — if your ISE version doesn't return posture on
  the MnT session record, those panels stay empty in poll mode (stream is
  authoritative).
- **MDM device trust** (`ise_session_mdm_status{dimension, value, location}`) —
  `dimension` ∈ registered/compliant/disk_encrypted/jailbroken/pin_locked,
  `value` ∈ true/false/unknown. **Stream mode only** (the pxGrid session object
  carries the `mdm*` fields; MnT ActiveList doesn't). Emitted only for
  MDM-managed sessions, so non-enrolled endpoints don't flood it.
- **Secure Client agent version**
  (`ise_endpoints_by_secureclient_version{version}`) — from `getEndpoints`
  attributes, best-effort across several attribute spellings. **May be empty**:
  ISE does not reliably publish an agent-version attribute over pxGrid
  `getEndpoints`, in which case the panel shows "No data" rather than a bogus
  `unknown` bar. The OS panel beside it reuses the always-available
  `ise_endpoints_by_os`.

## Endpoint profile hierarchy

`ise-endpoint-profiles.json` joins two separate pxGrid calls: the per-endpoint
profile counts from `getEndpoints` (same data `ise-endpoints-devices.json`'s
"Profiling Policy" panel uses, via `ise_endpoints_by_policy`) and the ISE-wide
policy *catalog* — category/parent hierarchy — from a second pxGrid service,
`com.cisco.ise.config.profiler`'s `getProfiles`. The catalog rarely changes,
so it's cached and refreshed at most every `PXGRID_PROFILER_HIERARCHY_TTL`
seconds (default 3600) regardless of poll/stream mode — see "Hierarchy Cache
Age" on the dashboard.

If your pxGrid client is scoped to a pxGrid Group that doesn't include the
profiler config service (see the "Approve the client" step in the main
README's pxGrid setup section), the catalog fetch fails, is logged as a
warning (`pxGrid getProfiles (profiler hierarchy) failed: ...`), and every
profile falls back to `category="unknown", parent=""` — the per-profile
endpoint counts themselves are unaffected, only the hierarchy grouping is
lost until the client is granted access to that service.

## Prometheus scrape config

```yaml
scrape_configs:
  - job_name: ise-exporter
    scrape_interval: 120s      # match/exceed SCRAPE_INTERVAL (default 120s) so points aren't stale
    static_configs:
      - targets: ["<exporter-host>:9618"]
```

## Notes

- None of these dashboards filter by `job`/`instance` — they assume one Prometheus target per ISE deployment. Running more than one ise-exporter (e.g. separate prod/dev ISE clusters) against the same Prometheus? Either point each dashboard at a differently-scoped data source, or add `job`/`instance` template variables and append `{job=~"$job"}` to the queries.
- `ise-overview.json`'s "Additional Signals" row covers the remaining metrics not in the other rows: `ise_license_enabled`, `ise_patch_installed`, `ise_backup_configured`/`ise_backup_last_success_timestamp`, `ise_api_requests_total`, `ise_collector_duration_seconds`, and `ise_last_successful_scrape_timestamp` staleness — between all six dashboards, every metric in `metrics.py` has a panel.
