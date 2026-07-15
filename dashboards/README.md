# Grafana dashboards

These dashboards target **Cisco ISE 3.3 Patch 11**. Their ownership boundaries match the exporter architecture:

The lab version and active appliance services/listeners were independently
checked against the [rooted ISE snapshot](../docs/rooted-ise-ground-truth.md).
Dashboard values still come only from Prometheus; rooted state is validation
evidence, not a hidden Grafana data source.

- Data Connect owns bounded monitoring and reporting datasets: RADIUS, posture, endpoints, profiling, PSN performance, diagnostics, and TACACS activity.
- REST/OpenAPI owns appliance and configuration state: deployment, certificates, licenses, backups, patches, network devices, and Device Administration configuration.
- Exporter self-observability owns request, scrape, duration, freshness, and failure metrics.

There is no live-event or dynamic source fallback layer. A missing dataset remains visibly missing rather than being replaced with a source that has different semantics.

## Dashboard inventory

| Dashboard | Purpose | Source |
|---|---|---|
| `ise-overview.json` | Deployment, certificates, licensing, backups, and patches | REST/OpenAPI |
| `ise-access-troubleshooting.json` | RADIUS authentication, accounting-derived sessions, latency, and failure triage | Data Connect |
| `ise-endpoints-devices.json` | Endpoint/profile summary and authoritative NAD inventory | Data Connect and REST/OpenAPI |
| `ise-secureclient.json` | Posture status, policies, conditions, agent versions, OS, and failures | Data Connect |
| `ise-psn-troubleshooting.json` | RADIUS workload, latency, TPS, resource utilization, and diagnostics by node | Data Connect plus REST deployment health |
| `ise-tacacs.json` | Device Administration configuration, account hygiene, and attributed TACACS activity | REST/OpenAPI and Data Connect |
| `ise-exporter-health.json` | Dataset availability, collection and source freshness, coverage, worker queues, query safety, and build identity | Exporter telemetry and Data Connect |

`ISE Exporter Health` is the single home for exporter availability, freshness,
coverage, queue, and collection-safety diagnostics. Domain dashboards keep their
small availability/age headers so an empty panel remains distinguishable from a
healthy zero, but they do not duplicate exporter internals.

## Semantics

Data Connect metrics are snapshots of Cisco's bounded reporting views. Dashboard values are event or distinct-endpoint counts over that view's retention window; they are not monotonically increasing Prometheus counters.

RADIUS accounting shows starts, updates, stops, and session-duration aggregates.
The likely-active count uses each session ID's latest record and excludes Stop;
it is an accounting reconstruction, not a guaranteed live-session directory,
and depends on NAD Start, Interim-Update, and Stop quality.

Endpoint metrics expose the fields currently normalized by the exporter: profile, identity group, posture applicability, and profile-event source/action. Hardware manufacturer/model and a profiler category hierarchy are not displayed because the current Data Connect metric contract does not expose them.

Posture policy and condition panels use the normalized Data Connect status labels. They preserve the policy, policy result, condition, condition result, enforcement, PSN, OS, and agent-version dimensions exported by the collector.

The data-quality dashboard deliberately separates collection freshness from
source-event freshness. A successful query can remain green even when the newest
row in an ISE reporting view is old or the bounded view is empty.

## Import

Import each JSON file in Grafana and select the Prometheus data source when prompted or use Grafana's default Prometheus source. The dashboards use stable `ise_dataconnect_*`, REST control-plane, TACACS, and exporter self-observability metric families.

Set Grafana's dashboard refresh no faster than the corresponding collector interval. Faster browser refreshes do not make bounded Data Connect views real-time and only add Prometheus query load.

## Troubleshooting workflow

The four primary dashboards expose compact navigation links for Overview,
Access, PSN, and Exporter Health. Grafana carries the selected time range and
compatible variables through those links.

- Access filters by PSN, NAD, authentication status, and authorization policy.
  Dimensional panels apply only the filters supported by their metric labels;
  exact headline totals remain deployment-wide because their metric contract is
  intentionally non-dimensional.
- PSN filters every node-dimensional performance, diagnostic, deployment, and
  resource query. Clicking a PSN series opens Access troubleshooting with that
  node selected.
- Exporter Health filters generic health tables by dataset and source. Each
  unavailable or stale row carries a direct link to the dashboard that owns the
  affected operational domain.
- TACACS exposes a username filter; clicking an internal-user or activity row
  focuses the dashboard on that identity. Certificate-expiry rows link to both
  node-scoped Access troubleshooting and certificate dataset health.

Panel links use Grafana's `${__url_time_range}` and field-label variables. When
editing a metric label or dashboard UID, update the link and the assertions in
`tests/test_dashboards.py` together.

## Alerting

`deploy/test-monitoring/grafana/provisioning/alerting/alerting.yml` provisions
panel-linked rules for API availability, unavailable and stale datasets, a Data
Connect queue older than 15 minutes, MnT detail truncation, authentication
safety backoff, and PSN CPU or memory above 85 percent for 10 minutes.

The repository intentionally does not provision a contact point or notification
policy: those contain environment-specific destinations and credentials. The
rules are visible and evaluable in Grafana immediately; configure routing in the
deployment that owns email, webhook, or paging credentials.
