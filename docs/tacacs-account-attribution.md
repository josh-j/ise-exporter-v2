# TACACS account attribution

ISE's Device Admin policy OpenAPI returns cumulative `hitCounts` without a
username. The exporter intentionally omits these misleading lifetime counters;
account attribution comes from bounded Data Connect activity.

The [rooted lab snapshot](rooted-ise-ground-truth.md) confirms that TACACS+ TCP
`49` and Data Connect TCP `2484` are listening on the current appliance. Listener
state does not establish account activity; the bounded Data Connect views below
remain the reporting authority.

ISE 3.3 exposes the required account evidence through the read-only Data Connect
service on the MnT node. The exporter uses the performance-oriented two-day views
but applies a numeric `EPOCH_TIME` lower bound before grouping:

- `TACACS_AUTHENTICATION_LAST_TWO_DAYS` for username, status, device, identity
  store, and authentication activity.
- `TACACS_AUTHORIZATION_LAST_TWO_DAYS` for username, authorization policy, shell
  profile, matched command set, and command activity.
- `TACACS_ACCOUNTING_LAST_TWO_DAYS` for username and session accounting activity.

Useful read-only queries are:

```sql
SELECT username, status, device_name, COUNT(*) AS hits,
       MAX(epoch_time) AS last_seen
FROM tacacs_authentication_last_two_days
WHERE epoch_time >= :minimum_epoch
GROUP BY username, status, device_name;

SELECT username, authorization_policy, shell_profile, matched_command_set,
       COUNT(*) AS hits, MAX(epoch_time) AS last_seen
FROM tacacs_authorization_last_two_days
WHERE epoch_time >= :minimum_epoch
GROUP BY username, authorization_policy, shell_profile, matched_command_set;
```

The exporter does not guess account usage from deployment-wide lifetime policy hit
counts. Each of the three existing scans uses `GROUPING SETS` to return the
dimensional top-K plus one last-seen row for each configured internal account in
the same statement. A low-volume internal account therefore cannot disappear
behind a high-volume dimensional top-K and be falsely marked unused. The output
remains bounded to 1,000 troubleshooting groups plus at most 1,000 configured
internal accounts per statement. Its hygiene queue combines internal-account
object age with activity that the exporter has actually observed through Data
Connect. Because ISE's efficient
views roll over after two days, the private exporter state database retains only a
high-water timestamp for authentication, authorization, and accounting for each
currently configured internal account. At the default cap this is no more than
3,000 scalar timestamps. External/AD usernames, raw rows, commands, and session
history are not retained, so storage does not grow with an 80--200 GB MnT database.

## Exporter configuration

Enable Device Administration and Data Connect in ISE, set the Data Connect
password, then configure:

```toml
[dataconnect]
host = "mnt1.example.com"
port = 2484
service = "cpm10"
user = "dataconnect"
password = "use-a-secret-store"
ca_bundle = "/etc/ise-exporter/certs/ise-ca.cer"
verify_tls = true
query_timeout_seconds = 15
max_groups = 1000
event_window_hours = 6

[dataconnect.intervals]
tacacs_seconds = 21600

[tacacs.policies]
max_sets = 100
rule_refresh_max = 10
rule_ttl_seconds = 604800
rule_request_interval_ms = 250
```

With the defaults, TACACS runs every six hours and scans six hours rather than
regrouping the complete two-day view. Lowering the event-window ceiling below the
collector cadence deliberately changes this to sampling.

ISE 3.3 Patch 11 exposes authentication and authorization rule inventories as
two per-policy-set PAN requests. The exporter caches only their complete counts,
refreshes at most ten policy sets per configuration cycle, and publishes coverage,
deferred, and failure metrics alongside the totals. A partial cache is visible and
does not masquerade as a complete zero-rule configuration.

The collector emits snapshot gauges for the bounded view slice:

- `ise_tacacs_account_authentication_events` by account, status, NAD, policy,
  identity store, and bounded failure class.
- `ise_tacacs_account_authorization_events` by account, status, NAD, policy,
  shell profile, and command set.
- `ise_tacacs_accounting_events` by account, status, NAD, and bounded command family.
- `ise_tacacs_events_total` provides exact per-view event totals even when the
  dimensional top-K is truncated. Raw failure text and complete commands remain
  available through `Get-IseTacacsActivity`; they are intentionally not labels.
- `ise_tacacs_account_last_seen_timestamp` by account and event type. Current-view
  accounts are exported directly; only internal-account high-water values survive
  view rollover and exporter restart.
- `ise_tacacs_unused_account_review_seconds` exposes the configured review period
  used by the hygiene dashboard.
- `ise_tacacs_dataconnect_up` for query health.

These are bounded evidence gauges, not raw history or monotonic event counters.
An account remains a review candidate rather than proof of disuse: activity that
predates the exporter's first observation cannot be reconstructed.
