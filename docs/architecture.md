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
Authenticated REST, MnT, and Data Connect targets are validated as bare DNS
hostnames or IPv4 addresses before a client is constructed. Schemes, user-info,
paths, and embedded ports are rejected so configuration parsing cannot change the
credential destination.

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
unbounded Prometheus labels. Every reporting-derived label is capped at 256 UTF-8
bytes (128 bytes for current MnT policy, agent, and PSN labels); values that exceed
the cap retain a hash suffix so shared prefixes cannot silently merge distinct
series.

Data Connect safety applies to the whole ISE deployment. Connecting to a
secondary MnT does not imply that every exposed view is executed only on that
node. `ISE_DATACONNECT_HOST` is therefore mandatory when Data Connect is enabled
and never inherits `ISE_MNT_HOST`; this prevents an XML API routing choice from
silently becoming the Oracle target. Production defaults for up to 100,000
endpoints use one sequential connection, five-second statement pacing, a 0.1%
adaptive query-duty-cycle ceiling, 15-second total Oracle-attempt timeouts, and independent
two-hour to 24-hour domain cadences. Valid explicit pacing, duty-cycle, startup
spacing, and cadence values are honored; values outside this production profile
produce startup warnings instead of being silently replaced. The client retains
a hard 15-second Oracle-call timeout and refuses to
run reporting SQL until the session accepts `ALTER SESSION DISABLE PARALLEL
QUERY`; this prevents a small aggregate result from fanning out across parallel
database workers. The client also refuses to materialize more than 5,000 rows
from any individual statement or 10,000 rows across a complete fixed-size domain
batch. The separate batch ceiling accommodates the valid 6,001-row worst-case
RADIUS aggregate and 6,000-row TACACS aggregate at the supported 1,000-group
profile without relaxing operator-query limits. Results are streamed in 100-row
fetches, with 1 MiB per-field and 64 MiB
retained-payload ceilings per standalone statement or complete batch, even when
a CLI caller or alternate
configuration object requests a more aggressive value; grouped output is likewise
capped at 1,000 series per breakdown. Operators may lower the duty-cycle below
0.01% for exceptionally low-pressure collection; the shared-deadline validity
window expands with the configured duty cycle so a deliberate long cooldown is
not mistaken for corrupt pacing state.
Schema discovery is a single allowlisted `USER_TAB_COLUMNS` dictionary read on
the serialized Data Connect scheduler lane. The metrics listener and independent
REST/MnT collection start before this database operation, so Oracle routing,
authentication, TLS, or availability failures cannot take down control-plane
metrics. Until discovery succeeds, reporting datasets remain visibly blocked by
`schema_validation_pending`; the `dataconnect_schema` dataset reports the bounded
failure category and retries under the normal protected Data Connect failure
cadence: hourly for the first five failures, then at the configured daily schema
interval by default. A later success unblocks compatible datasets without a
process restart.
The catalog read retains the global cross-process lock, session safety setup,
15-second timeout, and all result ceilings, but uses only the configured post-query
gap instead of multiplying its duration by the reporting-view duty-cycle ratio.
Oracle dictionary size does not scale with the 80--200 GB event history, and this
prevents a harmless one-second compatibility check from postponing the first real
reporting query by roughly 17 minutes. Arbitrary views and joins cannot use this
catalog-only path. Schema incompatibility is contained by an explicit
dataset-to-view dependency map: the exporter starts its REST/OpenAPI and compatible
reporting collectors, marks each affected dataset unavailable with a bounded reason,
and never issues SQL for that dataset. Restart-persistent reporting snapshots are
restored only after live discovery proves their dataset contract compatible. The
operator-only `--dataconnect-check` remains strict and returns a failure if any
enabled contract is inaccessible or incompatible.
Multi-view domains execute as atomic batches of at most five statements under one
shared lease. Statements remain sequential and retain the fixed five-second gap;
the adaptive cooldown is calculated from their combined Oracle execution time and
begins after the complete snapshot is available. This preserves the long-run duty
cycle without imposing a multi-hour cooldown between the statements required for
one dashboard update. The crash-safe deadline rolls forward one statement at a
time, so an early exporter failure cannot leave a pessimistic whole-batch lease.
The 5,000-row and 64 MiB retained-result ceilings cover the whole batch rather
than multiplying by its statement count.
Summary and top-group results share one Oracle aggregation wherever
possible so completeness telemetry does not require a duplicate event scan. Exact
RADIUS volume, failure totals, and distinct endpoint/user counts come from Cisco's
`RADIUS_AUTHENTICATION_SUMMARY` aggregate view, including failure class,
authorization profile, and location weighted by `FAILED_COUNT`. The raw
authentication view remains bounded and is used only for dimensions the summary
does not expose: method, protocol, exact authorization policy, and status-specific
latency. NAD activity health also uses a single per-device aggregation from the
summary view, not an additional raw authentication scan.
The three large daily RADIUS sources each use one `GROUPING SETS` statement for
their paired breakdowns (authentication/latency, volume/failure context, and
accounting/session duration), rather than rescanning the same six-hour window.
The nominal due workload is below two statements per hour after startup.
Cold-start attempts across REST, MnT, and Data Connect share an interruptible
startup limiter. `ISE_STARTUP_RATE_LIMIT_SECONDS` sets the minimum spacing
between each dataset's first attempt (five seconds by default, zero disables it)
without changing any recurring collection cadence.
Daily RADIUS reporting samples six hours, while a disjoint active-session query
scans at most its hard 60-minute stale window every two hours. No historical windows
are merged locally, so a reconciliation baseline cannot silently grow into a
three-day reporting window.
Other scheduled event scans match their cadence: six hours for PSN performance
and diagnostics, and daily for posture, NAD health, and endpoint profiling.
`ISE_DATACONNECT_EVENT_WINDOW_HOURS` is an absolute six-hour-or-lower ceiling;
daily domains intentionally sample rather than aggregating a full day.
The posture snapshot materializes its bounded latest-assessment set once and uses
one `GROUPING SETS` pass for status/version and failure breakdowns plus eligible
endpoint coverage; it does not rebuild the same assessment window per dashboard.
TACACS also runs daily and applies an `EPOCH_TIME` lower bound to
Cisco's two-day views before grouping, so the view's retention does not become
the exporter's scan size. The 14-view source-freshness diagnostic runs daily as
one bounded `UNION ALL` statement, applying the same at-most-six-hour timestamp or
numeric-epoch ceiling to every view. This avoids 14 adaptive pacing waits holding
the serialized worker while retaining one atomic freshness snapshot.
Production cadence settings are minimum intervals: operators may collect less
often, but environment overrides cannot restore the former aggressive schedule.
The scheduler enforces those minima independently of environment parsing, so a
direct `Config(...)` or Config-like integration cannot issue the same statements
at a faster cadence.
The exporter and CLI also serialize through one persistent pacing gate so separate
processes cannot bypass the cooldown. An empty pacing-path environment value is
normalized back to the protected service-state path rather than disabling this
guard. The gate publishes a conservative two-attempt lease before Oracle work
starts, then replaces it with the measured cooldown; process or host loss during
a reporting query therefore cannot turn restart into an immediate second database
hit. The fixed metadata lookup publishes a two-attempt timeout lease rather than
an hours-long reporting lease.
Authentication failures use a second identity-scoped shared guard. It persists
only a hash of the Oracle target identity, failure count, and bounded deadline;
the password is never written. Exporter restarts and separate `ise-cli`
invocations therefore cannot reset the Data Connect account backoff. A successful
connection clears the state, and changing the configured user, host, port, or
service starts an independent guard identity.
The former shared-tier design issued 1,437
statements per hour, so the 100k profile removes more than 95% of scheduled query
invocations before adaptive cooldown is considered.
The daily endpoint inventory uses one Oracle `GROUPING SETS` scan for current-row
coverage, endpoint-policy, and identity-group dimensions; it does not scan
`ENDPOINTS_DATA` separately for each breakdown. This keeps that
work proportional to the current endpoint inventory (up to 100,000 rows), not
to an 80--200 GB MnT event-history database.
Data Connect runs on one dedicated serialized worker lane, while the single MnT
active-posture dataset runs on its own non-overlapping lane. Long adaptive cooldowns
and paced endpoint-detail cycles therefore cannot delay REST/OpenAPI health or each
other. Service shutdown interrupts pending query and detail pacing waits instead of
waiting for their full deadlines. Cold starts prioritize the bounded active-session,
performance, and NAD-health datasets before historical reporting. The queue keeps
that priority after startup as domains become due again, so daily endpoint inventory
and the multi-view freshness probe cannot strand current operational data behind a
long low-duty-cycle backlog. Duplicate due events are coalesced while a domain is
queued or running; priority never introduces concurrent database statements.
The REST-owned network-device collector passes its latest successful in-memory
inventory to NAD activity correlation. The Data Connect worker never performs an
ERS request, never repeats the NAD enumeration, and refuses to publish NAD health
after a failed current inventory refresh.
REST authentication failures from the control and MnT planes share one persistent,
cross-process guard keyed by a hash of the configured account and cluster hosts.
The exporter and authorized `ise-cli` users therefore observe one failure threshold
and backoff across process restarts; the guard contains no credential material and
fails closed if its protected state is unavailable or malformed.
REST and MnT transports make exactly one wire attempt per recorded API request;
urllib3 retries are disabled because they occur beneath exporter telemetry and
would otherwise hide appliance pressure. Dataset scheduling owns subsequent
attempts, so retry timing and failure counters remain observable.
`ISE_REST_REQUEST_TIMEOUT` is hard-bounded to 5--30 seconds and split into
connect and read phase timeouts whose sum equals that configured budget; a scalar
Requests timeout is not used because it would permit the full value once per phase.
Cross-process lock acquisition is non-blocking and cancellation-aware, so a CLI
process holding the shared pacing gate cannot strand exporter shutdown behind a
kernel lock during a long adaptive cooldown.
The Data Quality dashboard exposes per-view statement rate, latest duration, rows
returned, configured/effective cadence, pacing, shared statement cooldown, and
the effective configured duty-cycle and the hard timeout, result-row, and
materialized-byte ceilings. Production monitoring therefore proves the running
process rather than relying on a sample environment file.
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
- numeric authentication-step and total-authentication latency aggregates. Step
  identifiers are normalized to ISE's five-digit numeric domain and publication
  is capped at the 256 most-sampled codes per snapshot.

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
Persisted rows contain only bounded posture, agent, PSN, and latency inputs needed
to reconstruct these metrics. Usernames, addresses, authorization results, and the
rest of the MnT session-detail response are discarded before storage. Text limits
are measured as UTF-8 bytes, not characters; a compact posture row is capped at
128 KiB and an internal-user detail row at 64 KiB before SQLite accepts it.

RADIUS history is not accumulated in SQLite. The daily reporting collection
recomputes an exact, bounded recent-window aggregate from Data Connect and persists only
the resulting bounded Prometheus snapshot. Current active-session reconstruction
is a separate, one-query dataset with its own two-hour cadence and snapshot.
Neither path stores raw RADIUS identities, credentials, events, or session rows.

Successful Data Connect domains store their complete bounded Prometheus
gauge snapshots and completion timestamps in that private database. A restart
atomically rehydrates compatible, still-fresh snapshots and retains each domain's
next scheduled deadline instead of immediately repeating every reporting query.
Each domain snapshot is capped at 20,000 samples and 32 MiB on both write and
restore, and restored labels must satisfy the same 256-byte limit as live
collection. Across the eight persisted reporting domains, even the theoretical
size ceiling remains under 256 MiB; this cannot become a local copy of an
80--200 GB MnT database. Stale, corrupt, oversized, or schema-incompatible
snapshots are ignored and collected from ISE immediately.
The same 20,000-sample ceiling is enforced at every live atomic publication
boundary, including non-persisted REST and MnT domains. Free-form active-posture
status, agent-version, and policy labels and NAD classification labels have
smaller domain-specific ceilings; overflow is aggregated into `Other` while
preserving totals. A collector regression therefore rolls back instead of
turning a bounded query or API response into row-like Prometheus state.
Successful domain values, availability, freshness, and completion timestamps
commit under that same scrape lock. A failed collector discards its staged
replacement, while restart restoration rehydrates values and validity metadata
within one boundary, so Prometheus cannot pair a new snapshot with old health.
The state layer validates its exact table contract at startup and bounds all keys,
values, and reconciliation sets before materialization. Explicit SQLite physical
corruption is recovered under a cross-process lock by preserving the original
database and sidecars as private `.corrupt.*` files, retaining the two newest
generations, and rebuilding an empty cache.
Newer or structurally incompatible schemas are left untouched for operator review.

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
ISE 3.3 exposes Device Admin authentication and authorization rule lists through
two separate per-policy-set endpoints. Complete rule-count pairs are therefore
cached for seven days and refreshed for at most ten policy sets per cycle, with
250 ms between PAN requests. Rule counts, cache coverage, deferred policy sets,
and failures are separate metrics; incomplete cache coverage cannot look like an
authoritative zero. The cache retains only two bounded integers per selected
policy set, never rule conditions or policy content.

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
| Deployment, personas, services, PAN HA | Platform | PAN OpenAPI | 15 minutes |
| Network devices and group classification | Configuration | ERS | 6 hours |
| Certificates | Platform | PAN OpenAPI | 6 hours |
| Licensing | Platform | PAN OpenAPI | 6 hours |
| Backup status | Platform | PAN OpenAPI | 6 hours |
| Device Admin policy configuration | Configuration | ERS/OpenAPI | 6 hours |
| RADIUS authentication, failures, and latency | Reporting | Data Connect | 24 hours |
| RADIUS accounting and session duration | Reporting | Data Connect | 24 hours |
| Endpoint inventory and profiling | Reporting | Data Connect | 24 hours |
| Historical posture and Secure Client | Reporting | Data Connect | 24 hours |
| Current active-session posture and latency sample | Current state | MnT XML | 15 minutes |
| PSN performance and diagnostics | Reporting | Data Connect | 6 hours |
| TACACS account and command activity | Reporting | Data Connect | medium |

There is one writer for each metric family. Control-plane configuration and
reporting-plane activity may describe the same feature, such as TACACS, but
they emit distinct metric families and never substitute for one another.

## Failure semantics

- Failure of one dataset records collector failure without changing ownership.
  `ise_dataset_last_failure_info` retains the bounded category and
  `ise_dataset_last_failure_detail_info` adds one bounded, single-line operator
  explanation. Both are removed after recovery. The data-quality dashboard lists
  dataset, source, category, and explanation; when none are unavailable it shows
  an explicit healthy row instead of an ambiguous empty table.
- Data Connect schema discovery is itself a retryable dataset. Its transport or
  authentication failure leaves REST and MnT collection running and never allows
  reporting SQL before a live contract has been discovered.
- A missing Data Connect view or required column blocks only the datasets that
  depend on it. Incompatible datasets remain enabled-but-unavailable, are listed
  with their schema reason, do not restore an older snapshot, and issue no SQL.
- The exporter retries the same authoritative source and never switches between
  Data Connect, MnT XML, pxGrid, or per-endpoint ERS. An early Data Connect failure
  retries no faster than five minutes and normally at the one-hour slow interval,
  so one transient startup failure cannot leave a daily dashboard empty for 24
  hours. Five consecutive Data Connect failures return to the full protected
  domain cadence. REST and MnT datasets instead retry at the slower of their own
  cadence and the persistent authentication-guard backoff, so a fast health
  dataset does not inherit the unrelated six-hour configuration tier.
- A reporting-plane failure must not be represented as a valid empty snapshot.
- Successful grouped query results replace their metric snapshot atomically so
  removed groups do not linger.
- Licensing and version/patch payloads are fully validated and replace all related
  gauges and Info labels in one rollback-capable snapshot.
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
