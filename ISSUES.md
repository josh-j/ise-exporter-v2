# ISE Dashboard Issues — Status Log

Status key: `[x]` fixed · `[~]` addressed with a caveat / needs a deployment-side
check · `[i]` explained in-panel (info text). Panels are more time-series oriented:
headline counts, ratios, and coverage now render as trend graphs so behaviour over
the selected range is visible, while categorical top-K views stay as current-snapshot
bars.

## ISE Secure Client & Posture Dashboard
- [i] **MnT Detail Truncated — what does this mean?** Panel description now spells it
  out: TRUNCATED means active sessions exceeded the selection ceiling
  (`mnt_active_posture.max_sessions`, capped at 1000), so posture detail covered only
  the first 1000 endpoints and the compliance sample is a subset.
- [x] **Historical Policy/Condition Results should count endpoints, not policy/condition
  hits.** Renamed to "Historical Assessed Endpoints by Policy" and repointed to
  `ise_dataconnect_posture_endpoint_assessments` grouped by `(policy, status)` — each
  endpoint counted once (the old query summed distinct-endpoint rows across conditions,
  double-counting).
- [x] **Same for Historical Failed Conditions.** The value column is now labelled
  **Endpoints** and the description states it is distinct endpoints failing each
  condition, not condition-hit counts.

## ISE Access Troubleshooting
- [x] **Doesn't update much from 1 → 3 → 6 hours.** The headline tiles (Pass Rate,
  Failed Auth, Active Sessions, Acct Starts) are now trend graphs, so the selected time
  range actually shapes the view. Note the value at each point is still a server-side
  bounded-window count (that window is fixed in ISE Data Connect); the trend line, not
  the single number, is what the range now changes.
- [x] **Top Error Codes — can they be translated?** Yes. The exporter now attaches a
  `message_text` label (curated ISE message-code map in `dataconnect_radius.py`) and the
  panel legend shows `code · text`. Unmapped codes show the bare number; extend the map
  to name more.
- [x] **Errors by ops owner.** New "Errors by Ops Owner" panel joins each error's NAD to
  the network-device group assignment (`nad → ops_owner`).
- [x] **Failed Authorization and Identity Summary — device_type/security_group/
  identity_group/identity_store all show similar massive numbers.** Each identity
  dimension independently re-partitions the *same* failed-event total, so the bars were
  the same events counted four ways. The panel now hides dimensions collapsed to a
  single value (unpopulated in this deployment) and the description explains bars are
  comparable within a dimension but never additive across dimensions.
- [x] **RADIUS Failure Work Queue needs an ops-owner column.** Added via the same
  `nad → ops_owner` join; failures at NADs with no group assignment still appear with a
  blank owner.
- [~] **Need high-repeat troubleshooting.** Added "Repeat Auth Intensity" (attempts per
  distinct endpoint) as a trend, and the Failing NADs / Failure Work Queue localise
  repeats. Per-endpoint repeat-offender identity is *not* exported: the Data Connect
  contract has no bounded per-endpoint repeat counter and MAC/username are never labels.

## ISE Endpoints & Network Devices
- [x] **Endpoints by Identity Group is one row with the total.** The endpoint-inventory
  identity group is an opaque ID that collapses to one value; the panel (and the Identity
  Groups count) now use the human-readable group name from the profiling reporting view.
- [i] **What does Posture Applicability mean?** Description added: whether an endpoint is
  subject to a posture policy (eligible for assessment), which is *not* the same as being
  assessed or compliant.
- [x] **NAD Group Detail coverage stuck at 10% (prod ~4k NADs).** Two fixes: (1) the
  per-NAD detail refresh now runs on **its own background worker, off the synchronous
  REST lane** — it no longer has to drip 25/6h to avoid blocking certificates/licensing/
  backup/patches. `devices.detail_max_requests` now **auto-sizes to the inventory** by
  default (`0`), so a 4k inventory fills in one paced off-lane pass (bounded by a hard
  10000/pass ceiling; periodic commits keep the shared state DB unblocked). Set a
  positive value only to cap it explicitly. (2) Coverage counts any cached NAD (stale
  included), so it reaches 100% and holds. If it *stays* flat, it's persistence —
  **verify `exporter.state_db` is writable/non-memory** or ERS IDs are stable. Panel is
  now a trend with the fill-time explanation.
- [x] **Which switches went silent? (dead-switch coverage across all ~4k NADs).** The
  per-NAD RADIUS activity query is top-K bounded (≤`dataconnect.max_groups`, ≤1000), so
  the live per-device last-seen signal covered at most 1000 NADs and which 1000 churned
  each cycle. A restart-persistent accumulator now keeps the **high-water last-auth
  timestamp for every configured NAD** across cycles: `ise_nad_activity_last_authentication_timestamp{nad}`
  (0 = never seen) reaches full inventory coverage, with `ise_nad_activity_silent{threshold_days}`
  and `ise_nad_activity_never_authenticated_total` as fleet dead-switch rollups. Rows are
  pruned when a NAD leaves ERS inventory.

## ISE Exporter Health
- [~] **Operational panels barely refresh at scale (Data Connect duty cycle).** Every
  reporting query schedules a single global cooldown of `duration × (100/duty − 1)`, so
  at the old `0.1%` default a 5s query froze **all** Data Connect datasets for ~83 min —
  configured cadences were largely fictional on a large deployment. The default is now
  **`1.0%`** (~8 min cooldown for a 5s query); large fleets tune toward `2.0%`. A startup
  advisory now fires (and `ise_dataconnect_duty_cycle_advisory` = ±1) when the configured
  value sits outside the recommended `0.1–2.0%` band — previously this recommendation was
  dead code, so nobody was told. Per-view cooldowns remain visible in
  `ise_dataconnect_query_cooldown_seconds`. Multiple exporter instances still share one
  budget.
- [x] **Posture Coverage stuck at 17%.** This was a mislabeled metric, not a stuck one.
  Replaced the "Posture Coverage" ratio with **"Posture Re-Assessment (6h): Assessed vs
  Backlog"** — two stacked count trends (endpoints assessed in the last 6h vs the backlog
  not assessed in that window). Because endpoints posture on connect / periodically (not
  every 6h) and offline endpoints never enter the window, a persistent backlog is normal
  and there is **no 100% target**. Watch the backlog trend and drops in the assessed
  line. For posture health, use the compliance ratio and assessed-endpoint counts on the
  Secure Client dashboard.

## ISE PAN and MnT Troubleshooting
- [~] **MnT Detail Coverage stuck at 28%.** Now a trend graph with an explanation:
  budget-bound at `mnt_active_posture.max_requests_per_cycle` (default 80) per 5-min
  cycle, so heavy session churn or >1000 active sessions plateau it below 100%. Raise
  `max_requests_per_cycle` (max 250) and/or `refresh_ttl` to lift it.
- [i] **MnT Active Session Latency — what is this? MnT nodes don't authenticate, PSNs
  do.** Correct. The section is renamed "MnT Active Session Latency (PSN-measured, read
  from MnT)" and the panels state the latency is measured on the authenticating PSN and
  only read from the MnT session store.

## Large-Environment Scale Hardening (2026-07-22)
- [x] **Second collection-path review pass: cheaper steady-state cycles, wider NAD
  coverage, one loud-collector off the main lane.** The serialized Data Connect worker
  queue now ages queued items by wait time (one static-priority level crossed per 15
  minutes queued), so a low-priority dataset can no longer starve indefinitely behind a
  busy high-priority one. `dataconnect_freshness` splits its per-view probe across a
  batch of statements (≤4 branches each) instead of one large UNION ALL, so a slow branch
  on a big MnT can no longer blow the whole dataset's timeout. `nad_health` now ranks the
  same 6h activity scan two ways (volume and recency) in a single statement instead of
  two separate scans, widening last-seen refresh coverage past the top-K activity cutoff
  at no extra duty cost; the new `ise_nad_activity_refresh_groups_returned`,
  `ise_nad_activity_refresh_groups_total`, and `ise_nad_activity_refresh_truncated`
  metrics expose that refresh surface. Device detail refresh auto-sizing now budgets
  `uncached + ceil(inventory × poll_interval / device_cache_ttl)` requests per cycle
  instead of one full-inventory burst at the TTL boundary, turning the refresh into a
  continuous trickle. The MnT posture cache prunes with a grace window equal to the
  posture refresh TTL, so an endpoint transiently missing from one cycle's ActiveList
  keeps its cached detail instead of forcing a refetch on reappearance. The RADIUS
  volume-summary statement no longer computes `COUNT(DISTINCT calling_station_id)` /
  `COUNT(DISTINCT username)` on every GROUPING SETS row; those now live in their own
  small statement (reporting batch stays at 5, the client's per-batch ceiling).
  `tacacs_config` (a full ERS internal-user enumeration plus policy-rule walks) now runs
  on its own scheduler worker lane, mirroring the existing devices worker, instead of
  blocking every other dataset trigger behind it in the synchronous cycle. The id-tail
  engine splits its `MIN(id)`/`MAX(id)` metadata probe into two single-aggregate
  statements (Oracle's index MIN/MAX optimization applies per aggregate) and runs the
  unbounded-below `floor_skipped` audit subquery only when the cursor stalled past the
  backfill floor, so steady-state tail cycles stay driven by the `id` predicate. MnT
  detail sampling selects endpoints by a stable content hash of the MAC instead of
  first-N ActiveList order, removing appliance-ordering bias while keeping the detail
  cache convergent. `endpoint_fleet` refreshes its posture-eligible denominator (a full
  `endpoints_data` count) at most every 6 h from a persisted cache instead of every
  cycle. The Data Connect crash lease (the pessimistic pre-work pacing deadline that
  survives a SIGKILL) is capped at one hour instead of the former ~16.6 h worst case at
  the default duty cycle; measured post-completion cooldowns stay uncapped



# New issues

dataconnect_error_counters
dataconnect
database_failed
ORA-01722: invalid number Help: https://docs.oracle.com/error-help/db/ora-01722/

## Secure Client Dash
Needs breakdowns by ops owner


## ISE Exporter Health Dash
This is a confusing mess. Needs to clearly show what data has been collected, when it was collected, when it will next collect (or the failure states).
Needs to also highlight issues with collection (priority causing some collections to not be updated, limited duty, limited rows ect)
Also needs to show when each collections dataset will be usable for dashboard purposes.

NAD Inventory Export Coverage

selected
1000
configured total
3693
truncated
1
NAD Activity Group Coverage
returned
1000
groups total
2608
truncated
1


Needs to work and sample needs to be configured for prod env
.
