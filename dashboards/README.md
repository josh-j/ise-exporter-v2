# Grafana dashboards

Nine dashboards, each scoped to one part of the exporter's metric surface
(`ise_exporter/metrics.py`):

| File | Covers | Notes |
|------|--------|-------|
| `ise-overview.json` | Deployment health, node status, scrape/API error rates, collector health, certs, licensing, backup, patch level | Start here — the one to put on a wallboard/alert off of |
| `ise-sessions-auth.json` | Active sessions by NAD/ops-owner, session status, failure reasons, auth methods, authz profiles/rules/policy sets | Populated by poll mode (MnT) or pxGrid streaming, whichever is active — see below. "Sessions by PSN" is poll-mode only |
| `ise-endpoints-devices.json` | Endpoint profiling (ERS profiler-source/OS/type/group attributes plus optional pxGrid MFC model/manufacturer enrichment) and network device inventory | ERS profiler attributes use the slow cached `COLLECT_ERS_ENDPOINT_ATTRIBUTES` baseline sweep |
| `ise-endpoint-profiles.json` | Endpoints broken down by ISE's profiler policy hierarchy — category/parent/profile, filterable table, catalog size, cache freshness | ERS endpoint attributes are the baseline; pxGrid getEndpoints can enrich when it is non-empty |
| `ise-secureclient.json` | Posture compliance % and Passed/Failed/Pending by ops-owner; per-policy pass/fail (which posture check failed); MDM device trust; posture agent version | Overall status is session-sourced; per-policy + agent version come from getEndpoints when available; MDM is stream-only — see below |
| `ise-auth-troubleshooting.json` | AuthC+AuthZ triage workflow: pass rate, failure reasons (decoded), auth methods, the authz pipeline (policy set → matched rule → assigned profile), failure heatmaps by site/owner, and a per-NAD work queue | Failure data is authz-sourced (watch "Authz Cache Warmup"); filters by ops-owner/location/reason-code |
| `ise-failure-triage.json` | RADIUS failure triage (headline counts, failure-code trend + leaderboard with decoded codes, failure×location/×ops-owner heatmaps, per-ops-owner failure rate, cert/PKI stat, NAD work queue) | Same metrics as auth-troubleshooting, different framing; filters by ops-owner/location/reason-code |
| `ise-pxgrid-health.json` | pxGrid stream connection state, event throughput, resync counts, streamed state size | Only populated when `COLLECT_PXGRID_STREAM=true`; all panels correctly show "No data" in poll mode |
| `ise-psn-troubleshooting.json` | PSN session distribution, deployment/collector/API health, total/client authentication latency, and per-execution-step latency | PSN session attribution is MnT poll-sourced; latency samples are recorded once per newly fetched session detail |

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
way the same panels populate; only the freshness/latency differs.

**Automatic fallback.** "Streaming mode" is a live decision, not just a config
flag: the session/authz collectors defer to the projector only while the stream
is actually connected (`ise_pxgrid_connected == 1`). If the stream drops — pxGrid
unreachable, subscription rejected, creds missing, or just not up yet — the
collectors automatically run the **full MnT poll** so the auth/authz dashboards
keep updating instead of freezing at their last streamed values. It flips back
when the stream recovers; `journalctl` logs each transition
(`scheduler: pxGrid stream DOWN — … full MnT/REST polling (fallback)`). Failure
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
  the "Posture Policy Results" section. Parsed from each endpoint's `PostureReport`
  attribute, collected via the **getEndpoints REST poll** (not the endpoint topic,
  not MnT). `policy` is the ISE posture policy name (encodes the check: `…-FIREWALL`,
  `…-AM`, `…-DE-BITLOCKER`, `…-PM-PATCH`, …); `result` is the policy-level roll-up
  (`Passed`/`Failed`/…); requirement/condition detail is dropped (too
  high-cardinality). `ops_owner` is joined from the endpoint's live session (stream
  mode) and is `unknown` when no session matches. Needs ISE endpoint publishing on
  (see the "No data" section below); refreshes every `PXGRID_ENDPOINT_REFRESH_INTERVAL`.
- **Posture agent version** (`ise_endpoints_by_secureclient_version{version}`) —
  from the endpoint's `PostureAgentVersion` / `SecureClientVersion` attribute via
  getEndpoints (prefix like "Posture Agent for " stripped). Same source/gating as
  the per-policy results.
- **MDM device trust** (`ise_session_mdm_status{dimension, value, ops_owner}`) —
  `dimension` ∈ registered/compliant/disk_encrypted/jailbroken/pin_locked,
  `value` ∈ true/false/unknown. **Stream mode only** (the pxGrid session object
  carries the `mdm*` fields; MnT ActiveList doesn't). Emitted only for
  MDM-managed sessions, so non-enrolled endpoints don't flood it.

## Endpoint Data Sources

The endpoint dashboards use ERS as the baseline endpoint inventory source and
pxGrid endpoint snapshots as optional enrichment:

- ERS `/config/endpoint/{id}/attributes` for production-tested profiler attributes
  such as `MatchedPolicy`, `EndPointSource`, `Operating System`, `Device Type`, `OUI`,
  MDM fields, identity group/static assignment, and selected custom endpoint attributes.
- pxGrid `getEndpoints` for fields ERS does not expose: MFC model/manufacturer/type/OS,
  Secure Client version, and endpoint `PostureReport`.

On ISE 3.3, pxGrid `getEndpoints` commonly returns **0 endpoints** even when ERS
and Context Visibility have endpoint records. That is expected. The exporter keeps
ERS-backed endpoint/profile panels populated from `COLLECT_ERS_ENDPOINT_ATTRIBUTES`
and backs off pxGrid endpoint probes for `PXGRID_ENDPOINT_ZERO_BACKOFF` seconds after
an empty result. If you later upgrade to a release/config where `getEndpoints` starts
returning endpoints, the pxGrid MFC/Secure Client panels will begin populating
automatically.

`COLLECT_ERS_ENDPOINT_ATTRIBUTES=true` walks the rich per-endpoint profile-attribute
schema slowly, owns the ERS baseline endpoint/profile gauges while pxGrid endpoint
snapshots are empty, and fills the ERS profiler-attribute row on
`ise-endpoints-devices.json`. It intentionally avoids raw high-cardinality
attributes; use `ERS_ENDPOINT_CUSTOM_ATTRIBUTE_KEYS` for specific custom endpoint
attributes worth bucketing. The sweep persists its multi-cycle cache to
`ERS_ENDPOINT_ATTRIBUTE_CACHE_FILE` so a restart does not lose progress.

If pxGrid-only panels remain empty on ISE 3.4/3.5, run `ise-exporter --pxgrid-check`
and check `getEndpoints … endpoints=N`. Also confirm the pxGrid client's group grants
the **EndpointService** (`com.cisco.ise.endpoint`) and the pubsub
`subscribe /topic/com.cisco.ise.endpoint` policy. The endpoint topic is change-driven
(events only fire when a non-timestamp endpoint attribute changes), so the bulk
snapshot still comes from `getEndpoints`. The legacy `COLLECT_ERS_ENDPOINT_FALLBACK`
profile-count collector is only used when the richer ERS attribute sweep is disabled.

## Endpoint profile hierarchy

`ise-endpoint-profiles.json` shows per-profile endpoint counts from the ERS
baseline (`/config/endpoint/{id}` plus `/attributes`) unless pxGrid `getEndpoints`
is actually returning endpoint enrichment. It can also join the ISE-wide policy
*catalog* — category/parent hierarchy — from pxGrid
`com.cisco.ise.config.profiler` `getProfiles`. The catalog rarely changes, so it's
cached and refreshed at most every `PXGRID_PROFILER_HIERARCHY_TTL` seconds
(default 3600) regardless of poll/stream mode — see "Hierarchy Cache Age" on the
dashboard.

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
- `ise-overview.json`'s "Additional Signals" row covers the remaining metrics not in the other rows: `ise_license_enabled`, `ise_patch_installed`, `ise_backup_configured`/`ise_backup_last_success_timestamp`, `ise_api_requests_total`, `ise_collector_duration_seconds`, and `ise_last_successful_scrape_timestamp` staleness — between all nine dashboards, every metric in `metrics.py` has a panel.
