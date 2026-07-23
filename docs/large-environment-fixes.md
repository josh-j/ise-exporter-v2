# Large-environment collection fixes

Source: 2026-07-22 review of the full collection path (Data Connect client and
pacing model, serialized scheduler lane, id-tail engine, ERS walk, MnT active
posture, accumulators). Items below are ordered by severity. Status boxes are
updated as fixes land. All six fixes are implemented (2026-07-22, landed with
the round-2 items in 5761847); full test suite green (835 passed) and ruff
clean.

## To fix

- [x] **LE-1 Data Connect lane starvation under adaptive cooldown.**
  The post-query cooldown (`duration * (100/duty - 1)`) gates the whole lane,
  and the worker queue uses static priorities with no aging
  (`scheduler.py:77-92`). On a large MnT the P0/P1 datasets re-arrive faster
  than the lane's service time, so `dataconnect_posture` (P5),
  `dataconnect_endpoints` (P6), `dataconnect_freshness` (P7), and
  `endpoint_fleet` (P8) can starve forever.
  *Fix: wait-time priority aging in the serialized Data Connect worker so every
  queued dataset eventually runs, with deterministic tie-breaks and unchanged
  shutdown/dedupe semantics.*

- [x] **LE-2 Id-tail meta/audit statements scale with table size.**
  `SELECT MIN(id), MAX(id)` in one statement defeats Oracle's single-aggregate
  MIN/MAX index optimization (`dataconnect_tail.py:40-42`), and the
  `floor_skipped` scalar subquery's `timestamp < floor_cut` predicate is
  unbounded below (`dataconnect_tail.py:92-93`), so a plan driven from the
  timestamp column re-reads the whole table every cycle.
  *Fix: split the min/max probe into two statements; return `updated_at` from
  the persisted tail cursor and only include the floor audit subquery when the
  cursor is old enough for a floor gap to be possible.*

- [x] **LE-3 NAD dead-switch false positives above the top-K cutoff.**
  Only NADs inside the top `limit` (<=1000) activity groups refresh their
  persisted last-seen timestamp (`nad_health.py:121-154`); with more than 1000
  active NADs per window, quiet-but-alive devices drift into the
  silent-7/30-day buckets.
  *Fix: a second bounded per-device `MAX(timestamp)` statement (recency-ordered,
  5000-row cap) in the same batch drives last-seen accumulation, plus refresh
  truncation telemetry.*

- [x] **LE-4 MnT detail sample is biased by ActiveList order.**
  Detail selection takes the first N ActiveList entries
  (`mnt_active_posture.py:422-425`), so posture/agent ratios are skewed by
  whatever ordering MnT returns.
  *Fix: stable hash-spread selection over candidate MACs — unbiased, and the
  same endpoints stay selected while active so the cache still converges.*

- [x] **LE-5 Fleet eligible denominator is a full scan every cycle.**
  `endpoint_fleet` re-counts `endpoints_data WHERE posture_applicable=1` every
  15 minutes (`endpoint_fleet.py:115-121`) for a number that changes daily.
  *Fix: refresh the eligible count at most every 6 h, persisting
  `{value, fetched_at}` in the state store and reusing it between refreshes.*

- [x] **LE-6 Crash lease can strand collection for ~16 h.**
  The pessimistic pre-work lease is `4 * timeout * (100/duty - 1)`
  (`clients/dataconnect.py:463-478`): a SIGKILL/OOM at the default duty cycle
  blocks all Data Connect work for up to ~16.6 h.
  *Fix: cap crash-lease deadlines at one hour (measured post-completion
  cooldowns stay uncapped); a crash-looping service still cannot hammer the
  MnT.*

## Round 2 (2026-07-22, second review pass)

Source: review of the remaining collection path (performance/freshness/TACACS
collectors, REST inventory collectors, snapshot plumbing, state-store
internals) plus an adversarial re-read of the round-1 diff (which found no
functional defects, but exposed LE-8). All seven items are implemented
(2026-07-22, landed in 5761847); full suite green (855 passed), ruff clean.
Incident note: a git stash during round 2 briefly reverted the round-1 edits
to the tail engine, endpoint_fleet, the Data Connect client, and their tests;
everything was recovered from the dropped stash commit and re-verified, and
the load-budget contract tests were updated for the deliberate LE-12 trade
(reporting batch 4 -> 5 statements, summary view scanned exactly twice).

- [x] **LE-7 tacacs_config blocks the main scheduler lane.**
  `run_cycle` runs `tacacs_config` synchronously (`scheduler.py:1208`); on a
  large deployment that is a full ERS internal-user enumeration (up to 2000
  pages), up to 100 paced detail requests, policy-rule walks, and two PAN
  enumerations — minutes of wall time that delay every dataset trigger behind
  it, exactly the problem the devices collector already got its own worker for.
  *Fix: give tacacs_config its own worker lane mirroring `_run_devices`.*

- [x] **LE-8 NAD health now scans the activity window twice.**
  The LE-3 fix added a second full aggregation of the same 6 h
  `radius_authentication_summary` window (`nad_health.py`), doubling the
  dataset's duty charge.
  *Fix: merge both rankings into one single-scan statement (volume rank for the
  top-K breakdown, recency rank for the last-seen refresh).*

- [x] **LE-9 Freshness probe is one 16-branch statement under one 15 s timeout.**
  `dataconnect_freshness` UNION ALLs a per-view top-1 probe for every reporting
  view into a single statement (`dataconnect_freshness.py:111-122`); on a large
  MnT the combined statement can exceed the hard timeout and the whole dataset
  fails, even though each branch alone is cheap.
  *Fix: split the branches across a small query_set batch (≤4 branches per
  statement) so each statement gets its own timeout budget.*

- [x] **LE-10 Devices detail refresh has a monthly thundering herd.**
  All NAD details are refreshed in one burst, so they all expire together after
  `device_cache_ttl` (30 d) and the auto budget then issues up to 10 000 paced
  ERS requests in one pass (`devices.py:152-155`).
  *Fix: auto budget = uncached count + `ceil(inventory × interval / ttl)` so
  cold start converges fast but TTL refresh becomes a continuous trickle.*

- [x] **LE-11 MnT posture cache is pruned to each cycle's exact selection.**
  `_finish_cache_cycle` deletes any cached detail absent from the current
  cycle's list (`state.py:497-533`), so one transiently incomplete ActiveList
  read discards still-valid same-session details and forces re-fetches.
  *Fix: optional grace window in the cycle pruning; MnT passes its refresh TTL.*

- [x] **LE-12 COUNT(DISTINCT) rides every RADIUS grouping set.**
  The volume_summary statement computes `COUNT(DISTINCT calling_station_id)`
  and `COUNT(DISTINCT username)` inside GROUPING SETS
  (`dataconnect_radius.py:320-321`) although only the top-level row is
  published — Oracle pays the distinct aggregation for every group.
  *Fix: move the two distincts into their own small batch statement (batch goes
  4 → 5, at the client ceiling).*

- [x] **LE-13 Docs drifted behind rounds 1–2.**
  `docs/incremental-tailing-plan.md` still describes the combined MIN/MAX probe
  and unconditional floor audit; ISSUES.md has no status entry for this work.
  *Fix: sync the tailing plan doc, append a dated ISSUES.md status entry, touch
  README only if it documents affected behavior.*

## Tracked, no code change here

- **Active-session reconstruction cost.** The 60-minute `RADIUS_ACCOUNTING`
  scan with `ROW_NUMBER` dedup is inherent to the feature; on very large fleets
  it dominates the duty budget or hits the 15 s timeout. RESOLVED 2026-07-22 by
  demotion: the default `dataconnect_radius_active_interval` is now 1800 s (a
  periodic truth-check), with the accounting id-tail delta and the MnT active
  count as the live signals; operators can still opt back to 300 s.
- **Id-tail execution plans need verification on a production-size MnT.**
  LE-2 reduces exposure, but an EXPLAIN PLAN of the tail query on a large
  deployment should confirm Oracle drives from the ID column.
- **Per-NAD series cardinality.** `ise_network_device_ndg_assignment` and
  `ise_nad_activity_last_authentication_timestamp` emit one series per
  configured NAD by design; at tens of thousands of NADs this is the dominant
  scrape cost. Accepted trade for per-device visibility.
- **Fleet scan-cap starvation.** Already flagged in-code
  (`endpoint_fleet.py:148-160`): if the fleet re-postures faster than
  `endpoint_fleet_max_rows` every cycle, the oldest re-postures stay dropped
  until the cap is raised.
- **MnT active posture above 10 k sessions.** The preflight refusal is a
  designed protection; above the ceiling the dataset is intentionally dark and
  the 64 MiB response cap makes very large ceilings unreachable.
