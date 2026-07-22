# Plan: incremental event tailing → lean on the Prometheus TSDB

Status: **proposal / not started.** Gated on Slice 0 (id-monotonicity validation).

## 1. Problem & goal

The reporting collectors publish **windowed-count gauges**: each cycle they re-run
a bounded server-side aggregate ("count events in the last N hours, grouped by
dimensions") against ISE Data Connect. This has three costs:

1. **DB duty cycle.** Every query schedules a global cooldown proportional to its
   duration. Re-scanning a window each cycle is the dominant reporting spend, and
   it gets *worse* the faster you poll (a 1h window every 5 min = 12x row overlap).
2. **Wrong time-series semantics.** A gauge holding a windowed count cannot be
   `rate()`d. Dashboards just re-sample the same fixed-window number — ISSUES.md
   already flags this: *"the value at each point is still a server-side
   bounded-window count."* The window is fixed server-side, not chosen per panel.
3. **Coupling of freshness to cost.** Fresher panels require polling the same big
   window more often, multiplying overlap.

**Goal:** for the *event-rate* datasets, stop re-aggregating a fixed window. Pull
only rows newer than a persisted high-water mark, feed them into **monotonic
counters**, and let Prometheus own the windowing (`rate()`, `increase()`,
`sum_over_time()`). Each event is scanned ~once instead of ~2x (and polling can be
made much more frequent without a proportional cost increase). Complements the
duty-cycle default raise (fix #1): fix #1 raised the budget, this reduces the spend.

**Non-goals (stay as they are):**
- Current-state *levels* — active sessions, endpoint/NAD inventory, PSN
  CPU/mem/latency/TPS, licensing, certs. Prometheus already stores and trends
  their scraped history; there is nothing to pull less of.
- Response-time avg/max — native histograms would need per-event samples, which is
  *more* data, not less.
- Distinct endpoints/users in a window — set-cardinality cannot be reconstructed
  from counters; must stay a server-side `DISTINCT`.

## 2. The tailing mechanism

### 2.1 Cursor (high-water mark)

Per view, persist a cursor in a new state table (§4). Two kinds:

- **id-tail** (preferred): views with a monotonic `ID` assigned at insert.
  `RADIUS_ACCOUNTING` and `POSTURE_ASSESSMENT_BY_ENDPOINT` contract `ID`
  (`dataconnect_schema.py` VIEW_CONTRACTS). Query `WHERE id > :hwm_id`.
- **timestamp-tail** (fallback, weaker): views with only `TIMESTAMP`
  (`RADIUS_AUTHENTICATIONS`, `RADIUS_ERRORS_VIEW`). Timestamp is not unique and
  late arrivals can land below the cursor, so exactly-once is not achievable
  without an id. **Deferred** — see §7.

### 2.2 Incremental query (id-tail)

```sql
SELECT acct_status_type AS event_type, NVL(ise_node,'unknown') AS psn,
       COUNT(*) AS events, MAX(id) AS max_id
FROM radius_accounting
WHERE id > :hwm_id
  AND timestamp >= CAST(SYSTIMESTAMP - NUMTODSINTERVAL(:floor_hours,'HOUR')
                        AS TIMESTAMP)
GROUP BY acct_status_type, NVL(ise_node,'unknown')
```

- `id > :hwm_id` returns only new rows since the last cycle — small, index-friendly.
- The `timestamp >=` floor is a **cost backstop** only: it bounds a cold-start or a
  corrupt/stale cursor to `floor_hours` of scan regardless of the id gap. In steady
  state it is a no-op (all new rows are recent).
- Bounded by the existing hard result-row ceiling (`MAX_RESULT_ROWS`).

### 2.3 Exactly-once, cursor advance & the commit-order hazard

- Advance the cursor **only after** the counter increment commits, in the same
  state-DB transaction. A failed cycle re-scans the same rows next time → no lost
  events, no double count.
- Late *inserts* get a higher `id` even if their event timestamp is old → captured
  on a later cycle. This is the clean property id-tail buys us.
- **The real subtlety — out-of-commit-order visibility.** An Oracle sequence can be
  *consumed* out of commit order: row `id=100` may still be an uncommitted
  transaction when our SELECT already sees `id=101`. If we advance the cursor to
  `MAX(id)=101`, row 100 becomes visible later but is below the cursor → **lost
  forever**. This hazard is independent of the global-vs-per-node question and is the
  one that actually matters. Mitigation — a **watermark with lateness**: do not
  advance to `MAX(id)`; advance only past ids whose add-`TIMESTAMP` is older than a
  small settle delay (e.g. `AND timestamp < SYSTIMESTAMP - :settle_seconds`), so
  in-flight commits have landed before the cursor passes their id band. Equivalent
  form: keep the cursor a fixed id-gap behind `MAX(id)` and re-scan that gap each
  cycle (counts are idempotent only if we also dedup — so the time-settle form is
  preferred since it needs no dedup). `settle_seconds` ≈ a few multiples of the
  MnT ingestion lag (start ~30s, make it configurable).
- **Honest semantics.** This is **effectively-once for a rate metric**, not a ledger
  guarantee: a row that commits out of order *beyond* `settle_seconds` with an id
  below the advanced cursor is rarely missed. That is fine for troubleshooting
  rates/trends (Prometheus rates are already approximate) and is tunable via
  `settle_seconds`. To keep the common path one query, the collector **commits the
  cursor advance to the state DB before `.inc()`-ing the counters**, so a failed/retry
  cycle re-scans rather than double-counts (the likelier failure mode); a crash
  between commit and inc loses at most one cycle (counters reset on boot anyway).

### 2.4 Cold start

- No cursor → seed `hwm_id = SELECT MAX(id) FROM radius_accounting` (cheap, indexed)
  and count forward. Dashboards build from empty; document this.
- The `MIN(id)`/`MAX(id)` metadata probes run as two separate single-aggregate
  statements (one batch lease): Oracle only applies the index MIN/MAX optimization
  when a statement contains exactly one such aggregate, so a combined
  `SELECT MIN(id), MAX(id)` would fast-full-scan the index on a large table every
  cycle.
- Alternative (optional): seed to `MAX(id)` then let the `floor_hours` guard backfill
  the last window on the first cycle. Start simple (count-forward); add backfill only
  if the empty-start gap matters operationally.

### 2.5 Restart continuity

- **Persist the cursor** (not the counter value). On restart, tail from the persisted
  cursor → downtime backlog is caught up (bounded by `floor_hours`), no data loss.
- Counters restart at 0. Prometheus `rate()`/`increase()` are **reset-aware**, so a
  boot reset costs at most one scrape interval of the spanning window — the standard,
  idiomatic exporter behavior (node_exporter counters reset on restart the same way).
- This means **no counter-value persistence and no new snapshot family** — much less
  new machinery. (Decision D1 in §9 revisits this if continuous counters are wanted.)

## 3. Metric model & cardinality

Counters never shed series, unlike the current snapshot-replaced top-K gauges.
**Keep counters low-cardinality; keep top-K gauges for per-entity breakdowns.**

New (Slice 1):
- `ise_radius_accounting_events_total{event_type, psn}` — Counter. `event_type` is a
  small closed set (start/stop/interim/…); `psn` is a handful of nodes. Low card.

Retire / replace:
- `ise_dataconnect_radius_active_session_delta` (reconstructed 5-min start−stop) →
  derived in Grafana as `rate(...{event_type="start"}) - rate(...{event_type="stop"})`.
  The exporter should not reconstruct a rate Prometheus computes for free.

Unchanged:
- `ise_dataconnect_radius_accounting_events{nad,...}` and `_session_seconds{nad,psn}`
  (per-NAD / per-PSN breakdowns) stay windowed top-K gauges — converting them to
  counters would grow series unbounded.
- `ise_dataconnect_radius_active_sessions{nad,psn}` (the *level*) stays a gauge.

## 4. State DB schema

One new table (in `state.py`, added via `CREATE TABLE IF NOT EXISTS` +
`_REQUIRED_SCHEMA`, same pattern as `nad_activity_cache`):

```sql
CREATE TABLE dataconnect_tail_cursor (
    view         TEXT PRIMARY KEY,   -- 'radius_accounting'
    cursor_kind  TEXT NOT NULL,      -- 'id' | 'timestamp'
    cursor_value REAL NOT NULL,      -- last id (id-tail) or last epoch (ts-tail)
    updated_at   REAL NOT NULL
);
```

Methods: `tail_cursor(view) -> (kind, value) | None`, `set_tail_cursor(view, kind,
value, now)`. No counter-value table needed under Decision D1 (§9).

If Decision D1 later requires continuous counters, add a bounded
`dataconnect_event_counter(metric, labels_json, value, updated_at)` table with a
`MAX_CACHE_CYCLE_KEYS`-style cardinality cap and overflow-to-"other".

## 5. Collector & scheduler changes

- `dataconnect_radius.py`: add `collect_accounting_counters(dataconnect, cfg)` (or fold
  into `collect_active`, which already reads `radius_accounting`, to reuse one lease).
  It opens a `StateStore`, reads the cursor, issues the §2.2 query, `.inc()`s the
  counter per group, and advances the cursor transactionally.
- `scheduler.py`: register the counter step under the existing DC serialized worker
  and duty-cycle gate. Initially reuse the accounting cadence; the tail is cheap
  enough to lower later (freshness is now a poll-cadence + dashboard-window choice).
- `metrics.py`: add the Counter; retire `active_session_delta*` after dashboards move.

## 6. Dashboard changes

- Access / PSN troubleshooting accounting panels → `increase(ise_radius_accounting_events_total{event_type="start"}[$__range])`
  or `rate(...[5m])` for a live-rate view.
- Session-delta panel → `rate(start) - rate(stop)`, or drop it (the active-sessions
  level trend already shows growth/shrink).
- Per-NAD accounting panels unchanged (still on gauges).
- Files: `dashboards/ise-access-troubleshooting.json`, `ise-psn-troubleshooting.json`.

## 7. Errors & auth

Cisco's data dictionary (developer.cisco.com/docs/dataconnect/database-views) confirms:

- `RADIUS_AUTHENTICATIONS` **does have an `ID`** ("Database unique ID") — our schema
  contract just doesn't reference it yet. So auth is **id-tailable** too (Slice 3),
  not limited to summary-bucket tailing. `RADIUS_AUTHENTICATION_SUMMARY` remains a
  pre-aggregated ISE-side rollup (`PASSED_COUNT`/`FAILED_COUNT`) and is an
  alternative low-volume source for the headline pass/fail rate.
- `RADIUS_ERRORS_VIEW`: **not yet confirmed** to carry `ID` (dictionary not fetched
  for it). If it does, id-tail it in a later slice; if only `TIMESTAMP`, keep the
  windowed gauge (timestamp-tail can't dedup late arrivals without a unique key).
  Verify against the live schema (`ise-cli dataconnect-schema`) before deciding.

## 8. Risks & mitigations

| Risk | Mitigation |
|---|---|
| **Out-of-commit-order id visibility** (a lower id commits after we passed it) — the primary correctness risk, independent of node topology | **Implemented in Slice 1** (post-review): the cursor advances only through the *contiguous settled prefix* — it counts rows only up to the first still-unsettled id (`boundary.first_unsettled`), so a settled high id can never advance past a not-yet-settled lower id. `settle_seconds` sizes the settle window. |
| Sequence reset (upgrade/rebuild), including a **fast refill that climbs past the old cursor before the next poll** so `id > hwm` stays non-empty | **Implemented in Slice 1** (post-review): a low-water **anchor** (smallest id seen) is persisted; purge only raises the minimum id, so a *drop below the anchor* means the id space was rebuilt → re-seed to the new bottom and rescan. The reset-then-quiet case (absolute `MAX(id)` below the cursor) is also covered. |
| `radius_accounting.id` not globally monotonic (per-PSN sequences) | **Likely a non-issue by architecture**: MnT consolidates all PSN syslog into one Oracle DB, so `ID` ("Database unique ID") is almost certainly a single DB-assigned sequence, not per-PSN. **But undocumented** → still confirm on a multi-PSN deployment (the single-node lab cannot) before enabling. If per-PSN, switch to per-`(view, ise_node)` cursor rows (schema is already `(view, scope)`). |
| Backfill floor drops accounting older than `tail_max_backfill_hours` after a long downtime | Bounded by design; now **visible** via the `floor_backfill_gap` warning (`floor_skipped` count) rather than silent. The audit count itself only runs when the cursor stalled past the floor (its `timestamp < floor` predicate is unbounded below, so steady-state cycles skip it and stay driven by the `id` predicate). |
| Counter series growth | Only low-card labels on counters; per-entity stays top-K gauges. |
| Late-arriving rows | id-tail captures them (higher id). |
| Cold start / restart empty dashboards | Counters build from start; `rate()`/`increase()` reset-aware; persisted cursor catches downtime backlog (bounded). Documented. |
| Duty-cycle gate contention (one more query) | Tail is cheap; net cost drops once it replaces the windowed headline. Keep on accounting cadence in Slice 1 and measure. |
| Row purge on retention | Purge removes low ids; high-water tail unaffected. |

## 9. Open decisions

- **D1 — counter persistence.** Recommend: real Counters + persisted cursor, accept
  boot resets (idiomatic, minimal machinery). Alternative: persist per-tuple counter
  values for continuous series across restarts (more machinery, bounded-card table).
- **D2 — feature flag.** Recommend: `[dataconnect] accounting_event_counters = false`
  default off for Slice 1; flip to on after lab validation. De-risks rollout.
- **D3 — gauge retirement.** Recommend: ship counters alongside the old gauges for one
  release, migrate dashboards, then remove `active_session_delta*` (breaking for any
  custom dashboards — call out in the changelog).
- **D4 — cadence.** Whether to poll the counter faster than the 30-min accounting
  cadence for fresher rates. Decide after measuring Slice 1 cost.

## 10. Testing

- **Unit:** cursor advance; cold-start seeding; exactly-once across mock id batches;
  failed-cycle does *not* advance cursor; boot-reset continuity; `floor_hours` bounds
  a stale cursor; cardinality bound.
- **State DB:** cursor CRUD + schema validation (mirror `nad_activity_cache` tests).
- **Collector:** mock DataConnect returning incremental id batches across cycles;
  assert counter `.inc()` totals and cursor advance; assert idempotency on replay.
- **Lab (manual, Slice 0):** confirm `radius_accounting.id` monotonicity and that
  tailed counts match the existing windowed counts over the same interval.

## 11. Phasing

- **Slice 0 — validate** the `id` model. Two parts:
  - *Shape (lab or docs):* `ID` exists on `RADIUS_ACCOUNTING` — **confirmed** via the
    Cisco data dictionary. A lab smoke test (needs Data Connect enabled on the lab —
    unconfirmed — plus the adws fleet generating accounting) can exercise the tailing
    code but **cannot** answer the multi-PSN sequencing question (lab is one node).
  - *Sequencing (production):* a read-only probe on the real multi-PSN deployment is
    the authoritative check — see below. **Everything below is gated on this**, though
    the §2.3 watermark + reset hedge make Slice 1 robust even if the answer is
    imperfect.
- **Slice 1 — accounting id-tail counters** (additive, flagged) + retire
  session-delta panel. Measure DB cost and rate correctness. **Done** — gate
  passed (id sequence validated **GLOBAL** on the multi-PSN lab); shipped
  default-off behind `dataconnect.accounting_event_counters`.
- **Slice 2 — posture-assessment id-tail counters.** **Done** — the Slice 1 tail
  engine was extracted into a shared `dataconnect_tail` module and applied to
  `POSTURE_ASSESSMENT_BY_ENDPOINT` (already id-based), publishing cumulative
  `status x psn` counters (`ise_dataconnect_posture_assessment_tail_total`) behind
  `dataconnect.posture_event_counters` (default-off). This is the assessment
  *throughput* signal; `endpoint_fleet` still owns per-endpoint coverage/compliance.
- **Slice 3 — authentication id-tail counters.** **Done (code, default-off)** — tails
  `RADIUS_AUTHENTICATIONS` (which carries the same global `ID`; added to the schema
  contract) with the shared engine, mapping the numeric `FAILED` flag to a
  `result=passed/failed` label in SQL and publishing
  `ise_dataconnect_radius_authentication_tail_total{result,psn}` behind
  `dataconnect.authentication_event_counters`. The tail engine gained an optional
  derived-expression per label (for the FAILED→string mapping, also Oracle-type-safe)
  and an ID-presence guard: an id-tail self-skips if the live schema shows the view has
  no `ID`. `RADIUS_AUTHENTICATION_SUMMARY` remains an alternative pre-aggregated source
  if per-event tailing is ever undesirable. **Not enabled** — flip on after confirming
  `RADIUS_AUTHENTICATIONS.ID` on the live schema (the guard makes this safe by default).
- **Slice 4 — RADIUS error id-tail counters.** **Done (code, default-off)** — confirmed
  `RADIUS_ERRORS_VIEW` carries `ID` on the live schema, so it tails with the shared engine
  into `ise_dataconnect_radius_error_tail_total{message_code,psn}` behind
  `dataconnect.error_event_counters`. Complements (does not replace) the windowed top-K
  `ise_dataconnect_radius_errors` gauge. The ID-presence guard keeps it safe if a view
  ever lacks `ID`.

## Appendix A — Slice 0 probe queries (read-only, bounded)

Run against a **multi-PSN** deployment (production). All are read-only, time-bounded,
and `FETCH FIRST`-capped — safe to run via any Data Connect client (Excel/SQL
Developer per Cisco's guide, or a standalone script using the exporter's
`DataConnectClient`, which enforces timeout + pacing).

```sql
-- A1. Range + volume sanity (does id exist, is it numeric, how dense).
SELECT MIN(id) AS min_id, MAX(id) AS max_id, COUNT(*) AS n
FROM   radius_accounting
WHERE  timestamp >= SYSTIMESTAMP - INTERVAL '1' HOUR;

-- A2. GLOBAL vs PER-PSN sequence — the decisive query.
--     Interleaved [min_id,max_id] across nodes  => single global sequence (good, one cursor).
--     Disjoint clustered ranges per node        => per-PSN sequences (need per-node cursors).
SELECT ise_node, MIN(id) AS min_id, MAX(id) AS max_id, COUNT(*) AS n
FROM   radius_accounting
WHERE  timestamp >= SYSTIMESTAMP - INTERVAL '1' HOUR
GROUP  BY ise_node
ORDER  BY min_id;

-- A3. Monotonic-with-insert-time + commit-lateness (sizes settle_seconds).
--     id DESC should track TIMESTAMP(add-time) DESC; large inversions => lateness.
--     Note EVENT_TIMESTAMP (event time) will legitimately differ from TIMESTAMP.
SELECT id, timestamp, event_timestamp, ise_node
FROM   radius_accounting
WHERE  timestamp >= SYSTIMESTAMP - INTERVAL '10' MINUTE
ORDER  BY id DESC
FETCH FIRST 100 ROWS ONLY;
```

Decision from results: A2 interleaved + A3 tight correlation → proceed with a single
id cursor + a modest `settle_seconds`. A2 disjoint → switch the design to per-node
cursors (one `dataconnect_tail_cursor` row per `(view, ise_node)`), which is a small
change to §2/§4. Either way the §2.3 watermark stands.
