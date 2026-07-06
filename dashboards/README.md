# Grafana dashboards

Six dashboards, each scoped to one part of the exporter's metric surface
(`ise_exporter/metrics.py`):

| File | Covers | Notes |
|------|--------|-------|
| `ise-overview.json` | Deployment health, node status, scrape/API error rates, collector health, certs, licensing, backup, patch level | Start here — the one to put on a wallboard/alert off of |
| `ise-sessions-auth.json` | Active sessions by NAD/ops-owner, session status, failure reasons, auth methods, authz profiles/rules/policy sets | Populated by poll mode (MnT) or pxGrid streaming, whichever is active — see below. "Sessions by PSN" is poll-mode only |
| `ise-endpoints-devices.json` | Endpoint profiling (model/manufacturer/OS/policy breakdown, MFC coverage) and network device inventory | Model/manufacturer/OS panels require `COLLECT_PXGRID_ENDPOINTS=true` (default) |
| `ise-endpoint-profiles.json` | Endpoints broken down by ISE's profiler policy hierarchy — category/parent/profile, filterable table, catalog size, cache freshness | Requires `COLLECT_PXGRID_ENDPOINTS=true` (default) — see below |
| `ise-secureclient.json` | Posture compliance % and Passed/Failed/Pending by ops-owner; per-policy pass/fail (which posture check failed); MDM device trust; posture agent version | Overall status + per-policy results work in both modes (per-policy via authz fan-out); MDM is stream-only — see below |
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

**Grouping dimension: ops owner.** These dashboards group by **ops owner** (the
`Ops Owner` Network Device Group), not by site/Location — most panels that used
to break down by Location now use `ops_owner`. Ops owner and location are both
derived from each session's NAD (`nasIpAddress` → device → NDG), so **"Sessions
by Ops Owner"** (`ise_radius_sessions_by_ops_owner`) works in both poll and
stream mode. The separate **"Sessions by PSN"** panel is **poll-mode only**: the
pxGrid session directory object carries no owning-PSN field (only `nasIpAddress`
and friends), so in streaming mode there is no way to attribute a session to a
PSN and the panel correctly shows "No data" rather than collapsing every session
under a single placeholder node. If ops-owner breakdowns show mostly `unknown`,
the session's `nasIpAddress` isn't matching a device IP in the ERS inventory —
check `COLLECT_DEVICE_DETAILS=true` (default) and that the NAD's RADIUS source
IP is one of its registered `NetworkDeviceIPList` addresses.

## Secure Client / posture compliance

`ise-secureclient.json` reads several data sources with different availability:

- **Overall posture status** (`ise_session_posture_status{status, location, ops_owner}`) —
  unique endpoints by posture verdict. In stream mode from the pxGrid session
  object's `postureStatus`; in poll mode from MnT session detail (top-level
  `posture_status`, falling back to `other_attr_string`). Canonicalized to
  `Compliant`/`NonCompliant`/`Pending`/`NotApplicable`/`Unknown`/`Error`; no
  assessment ⇒ `NotApplicable`, so **compliance %** is over `Compliant + NonCompliant`.
  Note: in many deployments the overall `postureStatus`/`PostureAssessmentStatus`
  is `NotApplicable` even though posture ran — in that case the **per-policy**
  results below are the real signal.
- **Per-policy pass/fail** (`ise_posture_policy_result{policy, result, ops_owner}`) —
  the "Posture Policy Results" section. Parsed from each session's `PostureReport`
  in MnT session detail (the authz per-MAC fan-out), so it carries in **both** poll
  and stream mode (subject to the authz cache warmup). `policy` is the ISE posture
  policy name (encodes the check: `…-FIREWALL`, `…-AM`, `…-DE-BITLOCKER`,
  `…-PM-PATCH`, …); `result` is the policy-level roll-up (`Passed`/`Failed`/…).
  Requirement/condition detail is intentionally dropped (too high-cardinality).
- **Posture agent version** (`ise_posture_agent_version{version, ops_owner}`) —
  from the session's `PostureAgentVersion` (MnT detail), the reliable source. The
  version panel falls back to `ise_endpoints_by_secureclient_version{version}`
  (from `getEndpoints` attributes) if the session source is empty.
- **MDM device trust** (`ise_session_mdm_status{dimension, value, ops_owner}`) —
  `dimension` ∈ registered/compliant/disk_encrypted/jailbroken/pin_locked,
  `value` ∈ true/false/unknown. **Stream mode only** (the pxGrid session object
  carries the `mdm*` fields; MnT ActiveList doesn't). Emitted only for
  MDM-managed sessions, so non-enrolled endpoints don't flood it.

## Endpoint dashboards show "No data"

Both `ise-endpoint-profiles.json` and the endpoint (model/OS/manufacturer) panels
on `ise-endpoints-devices.json` are driven by pxGrid `getEndpoints`. If they're
empty while the **network-device** panels (ERS-sourced) still populate, the
endpoint feed is returning **0 endpoints**. Check the "Endpoints Profiled
(pxGrid)" stat — if it's 0, so is everything downstream. Fix on the ISE side:
the pxGrid client's approved Group must include the **EndpointService**
(`com.cisco.ise.endpoint`) and ISE must actually have endpoints in Context
Visibility. Run `ise-exporter --pxgrid-check` — it prints `getEndpoints … endpoints=N`;
`N=0` confirms it. (The profiler dashboard's `Category` variable now pins
`allValue: .*`, so once endpoints flow the "All" selection can't get stuck empty.)

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
