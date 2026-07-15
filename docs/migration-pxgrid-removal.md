# pxGrid removal and explicit-boundary migration roadmap

This checklist tracks the migration from overlapping ERS, MnT, and pxGrid
collectors to the exact ISE 3.3.0.430 Patch 11 architecture documented in
[`architecture.md`](architecture.md).

The final boundaries were checked against the
[current rooted appliance](rooted-ise-ground-truth.md). The appliance still runs
pxGrid Direct, but that is deliberately separate from whether this exporter uses
pxGrid; it does not.

## Compatibility contract

- [x] Define `3.3.0.430` Patch `11` as the only supported Cisco ISE release.
- [x] Validate the exact version and highest installed patch before starting
  the metric endpoint.
- [x] Validate the Patch 11 deployment-node response shape.
- [x] Fail closed with an actionable error for every other version or patch.
- [x] Keep compatibility validation on supported, read-only OpenAPI calls; no
  appliance shell or root access.
- [x] Capture a repeatable live-lab compatibility smoke-test transcript for
  `laba-ise-001` after the complete migration is assembled.

## Runtime boundaries

- [x] Establish REST/OpenAPI as the sole platform/configuration plane.
- [x] Establish Data Connect as the sole historical monitoring/reporting plane.
- [x] Establish one bounded MnT current active-session posture/latency dataset
  with separate metric ownership, coverage, and truncation signals.
- [x] Use an immutable scheduler plan rather than runtime source selection.
- [x] Prohibit collector-to-collector metric inspection and semantic fallback.
- [x] Require usable Data Connect configuration for normal exporter startup.
- [x] Keep MnT XML outside general reporting; permit only the explicitly bounded
  active-posture collector and operator-initiated CLI diagnostics.
- [x] Add first-class dataset availability and snapshot-age metrics so every
  dashboard can distinguish unavailable data from a legitimate zero.
- [x] Add integration assertions that the control client cannot call MnT and the
  scheduler passes only the dedicated MnT client to active-posture collection.

## pxGrid removal

- [x] Remove the pxGrid client and control-plane implementation.
- [x] Remove session and endpoint topic streaming.
- [x] Remove pxGrid session, endpoint, model, and authorization collectors.
- [x] Remove stream-mode runtime startup and fallback behavior.
- [x] Remove pxGrid unit tests tied to the deleted runtime.
- [x] Complete a repository-wide search and remove stale pxGrid configuration,
  commands, documentation, dependency, and dashboard references.
- [x] Add a regression check that rejects new runtime imports or environment
  variables containing `PXGRID`.

## Data Connect reporting ownership

- [x] Collect grouped RADIUS authentication outcomes, methods, protocols,
  authorization policies, NADs, PSNs, and response latency.
- [x] Collect grouped RADIUS accounting events and session-duration aggregates.
- [x] Collect RADIUS error aggregates by message code, NAD, method, and PSN.
- [x] Collect endpoint totals, profiles, identity groups, posture applicability,
  and bounded profiling activity.
- [x] Collect posture status, OS, Secure Client agent version, policy,
  condition, enforcement, and failure aggregates.
- [x] Collect PSN request volume, MnT log volume, noise, suppression, load,
  latency, TPS, node resources, and diagnostic aggregates.
- [x] Collect TACACS authentication, authorization, accounting, command, and
  per-account activity from the bounded Patch 11 views.
- [x] Aggregate in the database, cap grouped rows, and avoid endpoint/session
  identity in general-purpose Prometheus labels.
- [x] Validate every SQL column and view against a clean ISE 3.3 Patch 11 lab
  after representative RADIUS, posture, profiling, PSN, and TACACS events exist.
- [x] Document accounting-data expectations for NAD Start, Interim-Update, and
  Stop records now that pxGrid is not available for live session transitions.

## Bounded MnT current-state ownership

- [x] Limit MnT runtime ownership to current active-session posture, Secure
  Client version, posture policy result, and latency aggregates.
- [x] Deduplicate active endpoint MACs and cap detail requests independently of
  total endpoint inventory.
- [x] Export detail coverage, source-field coverage, candidate count, and
  truncation so a 100,000-endpoint deployment can interpret the bounded sample.
- [x] Exclude MAC, username, session ID, raw posture report, and free-form text
  from Prometheus labels.
- [x] Keep MnT CLI calls operator initiated and separate from scheduler state.

## REST/OpenAPI control-plane ownership

- [x] Retain deployment, node status, persona/service, and PAN HA collection.
- [x] Retain authoritative NAD inventory and group classification.
- [x] Retain certificate, licensing, backup, version, and patch collection.
- [x] Separate TACACS configuration metrics from Data Connect activity metrics.
- [x] Eliminate ERS endpoint-detail crawling from the metric runtime.
- [x] Eliminate unbounded MnT per-MAC authentication/session fan-out; retain only
  the capped active-posture detail budget.
- [x] Review remaining REST collectors against the captured Patch 11 OpenAPI
  schemas and remove parameters or routes not present in that exact release.

## Metrics and dashboards

- [x] Give the Data Connect domains distinct metric families with one writer
  per family.
- [x] Atomically replace successful Data Connect grouped snapshots.
- [x] Convert Grafana dashboards from removed pxGrid and legacy overlapping MnT,
  session, authz, endpoint-attribute, and model metrics to one-owner families.
- [x] Separate current bounded MnT panels from historical Data Connect posture
  panels and expose MnT sample quality.
- [x] Add explicit “dataset unavailable” and “last successful snapshot age”
  panels to the global exporter-health dashboard.
- [x] Verify every dashboard in a browser against live Patch 11 data, including
  empty-data and Data Connect outage cases.
- [x] Remove dashboard variables and joins that depend on deprecated session or
  endpoint identity labels.

## Debian 12/13 and Ubuntu Server 24.04 LTS

- [x] Keep application dependencies in an isolated `/opt/ise-exporter/.venv`.
- [x] Use `python-oracledb` Thin mode without Oracle Instant Client or an Oracle
  package repository.
- [x] Install the exporter and `ise-cli` system-wide with systemd and an
  unprivileged service account.
- [x] Document Data Connect host, port `2484`, service `cpm10`, password, and CA
  prerequisites.
- [x] Preserve configuration and certificate directories across idempotent
  installer upgrades.
- [x] Exercise the final package and systemd unit on clean Debian and Ubuntu hosts,
  including a real Data Connect TLS connection to the lab.
- [x] Document offline wheelhouse installation for production networks without
  direct PyPI access.

## CLI and operator diagnostics

- [x] Retain `ise-cli` as a read-only operator tool independent of metric
  ownership.
- [x] Label MnT XML commands as explicit diagnostics only.
- [x] Keep local schema output available without credentials or network access.
- [x] Add a Data Connect schema/view inventory command that does not execute
  reporting queries.
- [x] Ensure CLI documentation and help contain no pxGrid credential or setup
  language.

## Release gates

- [x] Run Ruff and the complete pytest suite after all parallel migration work
  is merged.
- [x] Build and inspect both wheel and source distribution.
- [x] Run the Debian and Ubuntu installation CI jobs.
- [x] Run the complete live-lab collection cycle against `laba-ise-001` and
  confirm all enabled collectors report success.
- [x] Verify Prometheus queries and every Grafana dashboard against the live
  exporter.
- [x] Confirm a repository-wide search has no unrelated assistant-vendor references.
- [x] Commit the complete migration as one reviewed change and push the tracking
  branch only after every required gate passes.
