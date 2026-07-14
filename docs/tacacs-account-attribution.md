# TACACS account attribution

ISE's Device Admin policy OpenAPI returns cumulative `hitCounts` without a
username. The exporter intentionally omits these misleading lifetime counters;
account attribution comes from bounded Data Connect activity.

ISE 3.3 exposes the required account evidence through the read-only Data Connect
service on the MnT node. For production queries, use the performance-oriented
two-day views:

- `TACACS_AUTHENTICATION_LAST_TWO_DAYS` for username, status, device, identity
  store, and authentication activity.
- `TACACS_AUTHORIZATION_LAST_TWO_DAYS` for username, authorization policy, shell
  profile, matched command set, and command activity.
- `TACACS_ACCOUNTING_LAST_TWO_DAYS` for username and session accounting activity.

Useful read-only queries are:

```sql
SELECT username, status, device_name, COUNT(*) AS hits,
       MAX(generated_time) AS last_seen
FROM tacacs_authentication_last_two_days
GROUP BY username, status, device_name;

SELECT username, authorization_policy, shell_profile, matched_command_set,
       COUNT(*) AS hits, MAX(logged_time) AS last_seen
FROM tacacs_authorization_last_two_days
GROUP BY username, authorization_policy, shell_profile, matched_command_set;
```

The exporter API collector intentionally does not guess account usage from object
modification dates or deployment-wide lifetime hit counts. The TACACS dashboard
uses object age only as a clearly labelled review hint and shows bounded activity
by account over the selected Grafana range.

## Exporter configuration

Enable Device Administration and Data Connect in ISE, set the Data Connect
password, then configure:

```dotenv
ISE_DATACONNECT_HOST=mnt1.example.mil
ISE_DATACONNECT_PORT=2484
ISE_DATACONNECT_SERVICE=cpm10
ISE_DATACONNECT_USER=dataconnect
ISE_DATACONNECT_PASSWORD=use-a-secret-store
ISE_DATACONNECT_CA_BUNDLE=/etc/ise-exporter/certs/ise-ca.cer
ISE_DATACONNECT_SSL_VERIFY=true
ISE_DATACONNECT_QUERY_TIMEOUT=30
ISE_DATACONNECT_MAX_GROUPS=5000
```

The collector emits snapshot gauges for the two-day views:

- `ise_tacacs_account_authentication_events` by account, status, NAD, policy,
  identity store, and bounded failure class.
- `ise_tacacs_account_authorization_events` by account, status, NAD, policy,
  shell profile, and command set.
- `ise_tacacs_accounting_events` by account, status, NAD, and bounded command family.
- `ise_tacacs_events_total` provides exact per-view event totals even when the
  dimensional top-K is truncated. Raw failure text and complete commands remain
  available through `ise-cli tacacs-activity`; they are intentionally not labels.
- `ise_tacacs_account_last_seen_timestamp` by account and event type.
- `ise_tacacs_dataconnect_up` for query health.

These are bounded recent-evidence gauges, not monotonic lifetime counters. An
account absent from the two-day views has no evidence in that window; that alone
does not prove it is unused for a longer period.
