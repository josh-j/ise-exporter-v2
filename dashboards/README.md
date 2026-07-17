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

| Dashboard | Purpose | Source | Auto-refresh |
|---|---|---|---|
| `ise-overview.json` | Deployment, certificates, licensing, backups, and patches | REST/OpenAPI | 5 minutes |
| `ise-access-troubleshooting.json` | RADIUS authentication, accounting-derived sessions, latency, and failure triage | Data Connect | 30 minutes |
| `ise-endpoints-devices.json` | Endpoint/profile summary and authoritative NAD inventory | Data Connect and REST/OpenAPI | 6 hours |
| `ise-secureclient.json` | Posture status, policies, conditions, agent versions, OS, and failures | Data Connect | 15 minutes |
| `ise-pan-mnt-troubleshooting.json` | PAN HA, node status, certificates, backup, and bounded MnT collection health | REST/OpenAPI and MnT XML | 5 minutes |
| `ise-psn-troubleshooting.json` | RADIUS workload, latency, TPS, resource utilization, and diagnostics by node | Data Connect plus REST deployment health | 5 minutes |
| `templates/ise-ops-owner-site.json.tmpl` | Source template for one generated, owner-fixed site troubleshooting dashboard per Ops Owner NDG | REST network-device inventory plus Data Connect | 30 minutes |
| `ise-tacacs.json` | Device Administration configuration, account hygiene, and attributed TACACS activity | REST/OpenAPI and Data Connect | 6 hours |
| `ise-exporter-health.json` | Dataset availability, collection and source freshness, coverage, worker queues, query safety, and build identity | Exporter telemetry and Data Connect | 30 seconds |

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

The five primary troubleshooting destinations expose compact navigation links
for Overview, Access, PSN, PAN & MnT, and Exporter Health. Grafana carries the
selected time range and compatible variables through those links.

- Access filters by PSN, NAD, authentication status, and authorization policy.
  Dimensional panels apply only the filters supported by their metric labels;
  exact headline totals remain deployment-wide because their metric contract is
  intentionally non-dimensional.
- PSN filters every node-dimensional performance, diagnostic, deployment, and
  resource query. Clicking a PSN series opens Access troubleshooting with that
  node selected.
- PAN & MnT derives current node choices from deployment roles, separates PAN
  control-plane state from the bounded MnT active-session plane, and keeps
  dataset availability visible when a node-scoped panel is empty.
- Exporter Health filters generic health tables by dataset and source. Each
  unavailable or stale row carries a direct link to the dashboard that owns the
  affected operational domain.
- TACACS exposes a username filter; clicking an internal-user or activity row
  focuses the dashboard on that identity. Certificate-expiry rows link to both
  node-scoped Access troubleshooting and certificate dataset health.

Panel links use Grafana's `${__url_time_range}` and field-label variables. When
editing a metric label or dashboard UID, update the link and the assertions in
`tests/test_dashboards.py` together.

## Ops-owner site dashboards

`ise_network_device_ndg_assignment` retains one bounded assignment row per NAD
with its normalized Location, Ops Owner, and Device Type NDGs. Generated site
dashboards join RADIUS aggregates to that assignment on `instance,nad`, so an
owner sees only its own devices without copying raw network-device details into
Grafana.

Generate one provisionable dashboard per current owner from an exporter metrics
snapshot:

```bash
curl -sS http://EXPORTER:9618/metrics \
  | nix develop -c python tools/generate_ops_owner_dashboards.py --metrics-file -
```

Owners can also be supplied explicitly:

```bash
nix develop -c python tools/generate_ops_owner_dashboards.py \
  "Campus Operations" "Branch Operations"
```

Generated files are named `dashboards/ise-ops-owner-<slug>.json`. Each dashboard
has a fixed owner identity and template variables for deployment, site/location,
and NAD. Regeneration removes only owner dashboards recorded in the generator's
manifest; unrelated dashboards are never pruned. `unknown` and overflow `Other`
classifications are intentionally not treated as owners.

## Alerting

`deploy/test-monitoring/grafana/provisioning/alerting/alerting.yml` provisions
panel-linked rules for API availability, unavailable and stale datasets, a Data
Connect queue older than 15 minutes, MnT detail truncation, authentication
safety backoff, and PSN CPU or memory above 85 percent for 10 minutes.

Grafana forwards notifications to the Prometheus Alertmanager listening on
`127.0.0.1:9093`. Alertmanager remains the single owner of environment-specific
email, webhook, or paging destinations, credentials, inhibition, and retries.
