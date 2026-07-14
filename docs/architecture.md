# Architecture and collection boundaries

`ise-exporter` has one deliberately narrow compatibility target and three runtime
collection boundaries. It is not a general-purpose exporter for every Cisco ISE
release.

## Supported ISE contract

The sole supported appliance release is:

```text
Cisco ISE 3.3.0.430 Patch 11
```

This is the release running in the lab on `laba-ise-001`. At every normal
startup, the exporter validates the connected deployment with the supported,
read-only OpenAPI routes `GET /api/v1/patch` and
`GET /api/v1/deployment/node`. Startup fails closed when:

- `iseVersion` is not exactly `3.3.0.430`;
- the highest installed patch is not exactly `11`; or
- the deployment-node response does not satisfy the expected Patch 11 schema.

This exact-version check is intentional. A newer patch, ISE 3.4, or an older
ISE 3.3 patch must be evaluated and tested explicitly before the compatibility
contract is changed. The exporter uses supported remote interfaces only; it
never requires SSH, an appliance shell, database-table access, or root access
to ISE.

The hostname, version, patch, service, listener, and certificate statements in
this document were reconciled with the
[2026-07-14 rooted-appliance snapshot](rooted-ise-ground-truth.md). Root evidence
validates the lab environment; it is not an exporter interface.

## Three-boundary runtime

```text
                         +-----------------------+
PAN ERS/OpenAPI -------->| platform/configuration|---+
                         +-----------------------+   |
                                                     +--> Prometheus metrics
                         +-----------------------+   |
MnT Data Connect ------->| monitoring/reporting  |---+
                         +-----------------------+   |
                                                     |
MnT XML (bounded) ------>| current active posture|---+
```

The boundaries have fixed ownership. A collector does not inspect another
collector's metrics, choose a source dynamically, or fall back to a transport
with different semantics.

### REST/OpenAPI control plane

REST/OpenAPI owns appliance and configuration state:

- deployment nodes, personas, services, and PAN HA;
- network-device inventory and device-group classification;
- certificates and trust-store expiry;
- licensing state and consumption;
- backup status;
- installed version and patch inventory; and
- Device Administration configuration objects and internal-account inventory.

ERS and OpenAPI requests go to `ISE_HOST`. They are not used for bulk endpoint,
authentication, posture, session, or performance reporting.

### Data Connect reporting plane

Data Connect owns historical monitoring and reporting state:

- RADIUS authentication, errors, response latency, and accounting;
- endpoint inventory and profiling aggregates;
- posture policies, conditions, failures, endpoint OS, and Secure Client agent
  version;
- PSN KPIs, node resource utilization, and AAA/system diagnostics; and
- TACACS authentication, authorization, accounting, command, and per-account
  activity.

Queries are read-only, aggregated in Oracle, time-bounded where the view is an
event history, and capped by `ISE_DATACONNECT_MAX_GROUPS`. Endpoint identities,
session IDs, raw posture reports, and free-form failure text must not become
unbounded Prometheus labels.

Data Connect safety applies to the whole ISE deployment. Connecting to a
secondary MnT does not imply that every exposed view is executed only on that
node. Production defaults for up to 100,000 endpoints use one sequential
connection, two-second statement pacing, a 0.5% adaptive query-duty-cycle ceiling,
15-second statement timeouts, and independent 30-minute to 24-hour domain
cadences. Summary and top-group results share one Oracle aggregation wherever
possible so completeness telemetry does not require a duplicate event scan. Exact
RADIUS volume, failure totals, and distinct endpoint/user counts come from Cisco's
`RADIUS_AUTHENTICATION_SUMMARY` aggregate view, including failure class,
authorization profile, and location weighted by `FAILED_COUNT`. The raw
authentication view remains bounded and is used only for dimensions the summary
does not expose: method, protocol, exact authorization policy, and status-specific
latency. NAD activity health also uses a single per-device aggregation from the
summary view, not an additional raw authentication scan.
The steady-state scheduled workload is about 9 statements per hour after startup.
Daily RADIUS reporting scans 24 hours, while a disjoint active-session query
scans only its configured stale window every 30 minutes. No historical windows
are merged locally, so a reconciliation baseline cannot silently grow into a
three-day reporting window.
Other scheduled event scans match their cadence: one hour for PSN performance
and diagnostics, six hours for posture and NAD health, and 24 hours for endpoint
profiling. `ISE_DATACONNECT_EVENT_WINDOW_HOURS` is an absolute 24-hour-or-lower
ceiling; setting it below a domain cadence is an explicit sampling tradeoff.
TACACS also runs every six hours and applies an `EPOCH_TIME` lower bound to
Cisco's two-day views before grouping, so the view's retention does not become
the exporter's scan size.
The exporter and CLI also serialize through one persistent pacing gate so separate
processes cannot bypass the cooldown. The former shared-tier design issued 1,437
statements per hour, so the 100k profile removes more than 95% of scheduled query
invocations before adaptive cooldown is considered.
Data Connect runs on one dedicated serialized worker lane, while the single MnT
active-posture dataset runs on its own non-overlapping lane. Long adaptive cooldowns
and paced endpoint-detail cycles therefore cannot delay REST/OpenAPI health or each
other. Service shutdown interrupts pending query and detail pacing waits instead of
waiting for their full deadlines. Cold starts prioritize the bounded active-session,
performance, and NAD-health datasets before historical reporting; duplicate due
events are coalesced while a domain is queued or running.
The REST-owned network-device collector passes its latest successful in-memory
inventory to NAD activity correlation. The Data Connect worker never performs an
ERS request, never repeats the NAD enumeration, and refuses to publish NAD health
after a failed current inventory refresh.
Cross-process lock acquisition is non-blocking and cancellation-aware, so a CLI
process holding the shared pacing gate cannot strand exporter shutdown behind a
kernel lock during a long adaptive cooldown.
The Data Quality dashboard exposes per-view statement rate, p95 duration, rows
returned, configured/effective cadence, pacing, and shared statement cooldown.
The scheduler does not apply that cooldown a second time when calculating its
next domain run. ISE-expired Oracle sessions are reconnected and retried once;
authentication errors and SQL failures are never retried. Before a
100,000-endpoint rollout, capture an ISE AWR report as a baseline and repeat it
under representative load. If exporter statements appear among the highest-cost
queries, increase the affected per-domain interval; do not add exporter replicas.
Cisco's [ISE 3.3 Data Connect guidance](https://www.cisco.com/c/en/us/td/docs/security/ise/3-3/admin_guide/b_ise_admin_3_3/b_ISE_admin_33_basic_setup.html#Cisco_Concept.dita_b2bd25d1-ae61-4e7d-87ab-b580531a3033)
recommends enabling Data Connect only when reports are required and identifies an
AWR report in an ISE support bundle as the way to find the five queries consuming
the most time and resources.

### Bounded MnT active-session plane

MnT XML owns only a current, bounded active-session dataset:

- an ActiveCount preflight that refuses the unpaged ActiveList above the configured
  production ceiling;
- ActiveList session and unique endpoint candidate counts;
- posture status, applicability, assessment state, OS, and Secure Client version;
- posture policy passed/failed aggregates parsed from `PostureReport`; and
- numeric authentication-step and total-authentication latency aggregates.

The collector avoids ActiveList entirely when ActiveCount is zero and marks the
dataset unavailable without downloading the list when ActiveCount exceeds
`MNT_ACTIVE_POSTURE_MAX_ACTIVE_LIST_SESSIONS`. It otherwise deduplicates active
MACs and tracks no more than
`MNT_ACTIVE_POSTURE_MAX_SESSIONS` endpoints. Details are stored in the private
`ISE_EXPORTER_STATE_DB`; departed sessions are removed immediately, new or changed
sessions are prioritized, and unchanged sessions are refreshed in oldest-first
rotation. Production defaults allow 250 requests per 15-minute cycle, two workers,
500ms request pacing, and a one-hour refresh target. A restart reuses valid cached
details rather than creating a cold-start burst. Coverage, cache age, deferred
refreshes, candidate count, and truncation qualify every sample.

RADIUS history is not accumulated in SQLite. The daily reporting collection
recomputes an exact, bounded recent-window aggregate from Data Connect and persists only
the resulting bounded Prometheus snapshot. Current active-session reconstruction
is a separate, one-query dataset with its own 30-minute cadence and snapshot.
Neither path stores raw RADIUS identities, credentials, events, or session rows.

Successful Data Connect domains store their complete bounded Prometheus
gauge snapshots and completion timestamps in that private database. A restart
atomically rehydrates compatible, still-fresh snapshots and retains each domain's
next scheduled deadline instead of immediately repeating every reporting query.
Stale, corrupt, or schema-incompatible snapshots are ignored and collected from
ISE immediately.

TACACS hygiene adds one deliberately smaller persistent record: at most three
last-observed activity timestamps for each currently configured internal account,
bounded by `TACACS_INTERNAL_USER_MAX`. Per-account ERS details are held in a
restart-persistent, seven-day cache and refreshed under a paced, hard per-cycle
request budget. Three detail failures stop that cycle; incomplete or failed
refreshes reduce explicit coverage signals instead of invalidating the entire
Device Administration snapshot. Selection is deterministic and coverage is
measured against the complete enumerated inventory, so a configured cap cannot
masquerade as 100 percent coverage. It does not retain external identities, raw
TACACS events, commands, sessions, or MnT rows. Its size therefore follows the
small internal-account inventory rather than the MnT database or event volume.

MnT metrics never contain MAC addresses, usernames, session IDs, raw
`PostureReport`, or free-form attributes. Only bounded aggregate dimensions such
as status, OS family, PSN, normalized agent version, policy/result, and numeric
step code are labels.

### No pxGrid runtime

pxGrid is not part of the architecture. There is no pxGrid client,
certificate credential, account activation, snapshot, WebSocket subscription,
topic consumer, or live-event overlay in the exporter runtime. Likely-active
session counts are reconstructed from Data Connect accounting and therefore
have the freshness and completeness of the records supplied by the NADs.
Current active posture is the separate bounded MnT sample described above.
The rooted appliance currently has pxGrid Direct running, but its port `8910`
certificate still identifies the pre-rename host `ise01.ise.lab`. That confirms
why appliance service health and usable client connectivity are different
questions, and it does not justify adding pxGrid back to the exporter.

### MnT CLI diagnostics are separate

The scheduled MnT collector above is the only MnT metric source. MnT commands in
`ise-cli` and the curl probes remain explicit, read-only operator actions for
inspecting a particular session, authentication, or Secure Client record. They
do not read, update, or broaden the scheduled runtime snapshot.

The CLI also exposes bounded, curated Data Connect reports and uses
`ENDPOINTS_DATA` as its preferred IP/hostname resolver. Those queries are
operator-initiated and do not change metric ownership: REST/OpenAPI still owns
configuration detail, Data Connect owns historical reporting, and MnT remains a
live diagnostic fallback within CLI resolution only.

## One-owner dataset matrix

| Dataset | Sole metric owner | Interface | Runtime cadence |
|---|---|---|---|
| ISE compatibility, version, patches | Platform | PAN OpenAPI | startup / slow |
| Deployment, personas, services, PAN HA | Platform | PAN OpenAPI | medium |
| Network devices and group classification | Configuration | ERS | medium |
| Certificates | Platform | PAN OpenAPI | slow |
| Licensing | Platform | PAN OpenAPI | slow |
| Backup status | Platform | PAN OpenAPI | slow |
| Device Admin policy configuration | Configuration | ERS/OpenAPI | slow |
| RADIUS authentication, failures, and latency | Reporting | Data Connect | fast |
| RADIUS accounting and session duration | Reporting | Data Connect | fast |
| Endpoint inventory and profiling | Reporting | Data Connect | slow |
| Historical posture and Secure Client | Reporting | Data Connect | medium |
| Current active-session posture and latency sample | Current state | MnT XML | configured, default medium |
| PSN performance and diagnostics | Reporting | Data Connect | fast |
| TACACS account and command activity | Reporting | Data Connect | medium |

There is one writer for each metric family. Control-plane configuration and
reporting-plane activity may describe the same feature, such as TACACS, but
they emit distinct metric families and never substitute for one another.

## Failure semantics

- Failure of one dataset records collector failure without changing ownership.
- The exporter retries the same authoritative source at its configured cadence;
  it never switches between Data Connect, MnT XML, pxGrid, or per-endpoint ERS.
- A reporting-plane failure must not be represented as a valid empty snapshot.
- Successful grouped query results replace their metric snapshot atomically so
  removed groups do not linger.
- Repeated collector failure is rate-limited by the scheduler to protect ISE.
- Failure of the exact-version startup check prevents the metrics server from
  starting against an unsupported appliance.

## Ubuntu Noble, Data Connect, and MnT requirements

Ubuntu Server 24.04 LTS (Noble Numbat) is the native production target. The
installer uses standard Ubuntu packages for Python, virtual environments,
certificates, users, and systemd. Application dependencies live in
`/opt/ise-exporter/.venv`; Ubuntu's externally managed system Python is not
modified.

`python-oracledb` runs in Thin mode. Oracle Instant Client, Oracle apt
repositories, compilers, and Oracle development headers are not required. The
Python package must be installed from PyPI, an internal Python index, or an
offline wheelhouse.

Data Connect requires:

- Data Connect enabled on the ISE 3.3 Patch 11 MnT node;
- the fixed `dataconnect` username and a configured, non-expired password;
- outbound TCPS from Ubuntu to the MnT hostname on port `2484`;
- the fixed Oracle service name `cpm10`; and
- the MnT Admin certificate's complete issuing CA chain when TLS verification
  is enabled.

The hostname must match the Admin certificate. Data Connect credentials and CA
material are read by the unprivileged `ise-exporter` service account. No ISE
root credential or appliance filesystem access is used.

The optional bounded MnT dataset requires HTTPS from Ubuntu to
`ISE_MNT_HOST`, the same read-only ISE API credential, and the MnT Admin issuing
CA through `ISE_MNT_CA_BUNDLE`. Disable `COLLECT_MNT_ACTIVE_POSTURE` when current
active posture is not required; historical Data Connect posture remains
independent.

On a fresh Ubuntu installation, the systemd unit is enabled but not started.
The operator must replace the seeded example hosts and passwords, install the CA
chain, and pass `ise-exporter --dataconnect-check` before explicitly starting the
service. The installer refuses to start or restart the unit while sample
placeholders remain. Upgrades restart a configured service only when it was
already active; an intentionally stopped service remains stopped.

## Configuration principle

Configuration selects domains and intervals, not competing transports. Normal
production operation always uses REST/OpenAPI for the control plane and Data
Connect for historical reporting, with bounded MnT XML optionally owning current
active posture. If a source is unavailable, its datasets are unavailable; they
do not silently acquire different definitions from another boundary.
