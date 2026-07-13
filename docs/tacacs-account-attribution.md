# TACACS account attribution

ISE's Device Admin policy OpenAPI returns cumulative `hitCounts` for policy sets
and rules. Those responses do not include a username, so aggregate policy counters
cannot be accurately divided among internal accounts.

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
uses object age only as a clearly labelled review hint and shows policy/rule
counter changes over the selected Grafana range.
