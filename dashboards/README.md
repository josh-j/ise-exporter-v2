# Grafana dashboards

Four dashboards, each scoped to one part of the exporter's metric surface
(`ise_exporter/metrics.py`):

| File | Covers | Notes |
|------|--------|-------|
| `ise-overview.json` | Deployment health, node status, scrape/API error rates, collector health, certs, licensing, backup, patch level | Start here — the one to put on a wallboard/alert off of |
| `ise-sessions-auth.json` | Active sessions by NAD/PSN/ops-owner, session status, failure reasons, auth methods, authz profiles/rules/policy sets | Populated by poll mode (MnT) or pxGrid streaming, whichever is active — see below |
| `ise-endpoints-devices.json` | Endpoint profiling (model/manufacturer/OS/policy breakdown, MFC coverage) and network device inventory | Model/manufacturer/OS panels require `COLLECT_PXGRID_ENDPOINTS=true` (default) |
| `ise-pxgrid-health.json` | pxGrid stream connection state, event throughput, resync counts, streamed state size | Only populated when `COLLECT_PXGRID_STREAM=true`; all panels correctly show "No data" in poll mode |

## Import

Grafana UI: **Dashboards → New → Import**, upload the JSON file (or paste it),
then select your Prometheus datasource when prompted for the `DS_PROMETHEUS`
input. Repeat for each file.

Or provision them automatically alongside Prometheus/Grafana in
`docker-compose`/Kubernetes by mounting this folder and adding a
`dashboardProviders` config, e.g.:

```yaml
apiVersion: 1
providers:
  - name: ise-exporter
    folder: ISE
    type: file
    options:
      path: /etc/grafana/provisioning/dashboards/ise-exporter
```

(mount this `dashboards/` folder to that path in the Grafana container).

## Poll vs. streaming mode

`ise-sessions-auth.json`'s status/method/profile panels are fed by
`collectors/authz.py`'s per-MAC fan-out in poll mode (subject to
`SESSION_DETAIL_CACHE_TTL` warmup — watch the "Authz Cache Warmup" stat) or by
the pxGrid session topic directly in streaming mode (no warmup lag). Either
way the same panels populate; only the freshness/latency differs. Failure
reasons, matched authz rule, and policy set always come from the MnT fan-out
in both modes — pxGrid's session topic doesn't carry those fields.

## Prometheus scrape config

```yaml
scrape_configs:
  - job_name: ise-exporter
    scrape_interval: 120s      # match/exceed SCRAPE_INTERVAL (default 120s) so points aren't stale
    static_configs:
      - targets: ["<exporter-host>:9618"]
```

## Notes

- None of these dashboards filter by `job`/`instance` — they assume one Prometheus target per ISE deployment. Running more than one ise-exporter (e.g. separate prod/dev ISE clusters) against the same Prometheus? Either point each dashboard at a differently-scoped data source, or add `job`/`instance` template variables and append `{job=~"$job"}` to the queries.
- `ise-overview.json`'s "Additional Signals" row covers the remaining metrics not in the other rows: `ise_license_enabled`, `ise_patch_installed`, `ise_backup_configured`/`ise_backup_last_success_timestamp`, `ise_api_requests_total`, `ise_collector_duration_seconds`, and `ise_last_successful_scrape_timestamp` staleness — between all four dashboards, every metric in `metrics.py` has a panel.
