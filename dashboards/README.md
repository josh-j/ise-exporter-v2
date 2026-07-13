# Grafana dashboards

These dashboards target **Cisco ISE 3.3 Patch 11**. Their ownership boundaries match the exporter architecture:

- Data Connect owns bounded monitoring and reporting datasets: RADIUS, posture, endpoints, profiling, PSN performance, diagnostics, and TACACS activity.
- REST/OpenAPI owns appliance and configuration state: deployment, certificates, licenses, backups, patches, network devices, and Device Administration configuration.
- Exporter self-observability owns request, scrape, duration, freshness, and failure metrics.

There is no live-event or dynamic source fallback layer. A missing dataset remains visibly missing rather than being replaced with a source that has different semantics.

## Dashboard inventory

| Dashboard | Purpose | Source |
|---|---|---|
| `ise-overview.json` | Deployment, certificates, licensing, backups, patches, and exporter health | REST/OpenAPI and exporter telemetry |
| `ise-sessions-auth.json` | RADIUS activity, accounting-derived likely active sessions, and duration | Data Connect |
| `ise-auth-troubleshooting.json` | Authentication outcomes, methods, protocols, policy sets, NADs, PSNs, and response time | Data Connect |
| `ise-failure-triage.json` | RADIUS error work queue by code, NAD, method, and PSN | Data Connect |
| `ise-endpoints-devices.json` | Endpoint/profile summary and authoritative NAD inventory | Data Connect and REST/OpenAPI |
| `ise-endpoint-profiles.json` | Current profile distribution and recent profiling activity | Data Connect |
| `ise-secureclient.json` | Posture status, policies, conditions, agent versions, OS, and failures | Data Connect |
| `ise-psn-troubleshooting.json` | RADIUS workload, latency, TPS, resource utilization, and diagnostics by node | Data Connect plus REST deployment health |
| `ise-tacacs.json` | Device Administration configuration, account hygiene, and attributed TACACS activity | REST/OpenAPI and Data Connect |

## Semantics

Data Connect metrics are snapshots of Cisco's bounded reporting views. Dashboard values are event or distinct-endpoint counts over that view's retention window; they are not monotonically increasing Prometheus counters.

RADIUS accounting shows starts, updates, stops, and session-duration aggregates.
The likely-active count uses each session ID's latest record and excludes Stop;
it is an accounting reconstruction, not a guaranteed live-session directory,
and depends on NAD Start, Interim-Update, and Stop quality.

Endpoint metrics expose the fields currently normalized by the exporter: profile, identity group, posture applicability, and profile-event source/action. Hardware manufacturer/model and a profiler category hierarchy are not displayed because the current Data Connect metric contract does not expose them.

Posture policy and condition panels use the normalized Data Connect status labels. They preserve the policy, policy result, condition, condition result, enforcement, PSN, OS, and agent-version dimensions exported by the collector.

## Import

Import each JSON file in Grafana and select the Prometheus data source when prompted or use Grafana's default Prometheus source. The dashboards use stable `ise_dataconnect_*`, REST control-plane, TACACS, and exporter self-observability metric families.

Set Grafana's dashboard refresh no faster than the corresponding collector interval. Faster browser refreshes do not make bounded Data Connect views real-time and only add Prometheus query load.
