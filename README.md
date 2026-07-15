# Cisco ISE exporter

Prometheus exporter and read-only operator CLI for exactly **Cisco ISE
3.3.0.430 Patch 11**, the release used by the `laba-ise-001` lab. Normal startup
checks the appliance version and installed patch and fails closed for any other
release.

The metric runtime has three fixed collection boundaries:

- PAN ERS/OpenAPI owns platform and configuration state: deployment, NADs,
  certificates, licenses, backups, patches, and Device Administration objects.
- MnT Data Connect owns historical reporting state: RADIUS,
  accounting-derived sessions, endpoints, profiling, posture/Secure Client,
  PSN health, diagnostics, and TACACS activity.
- MnT XML owns one bounded current dataset: active-session posture, Secure Client
  version, posture-policy results, and authentication-step latency aggregates.

There is no dynamic source selection or fallback. The bounded MnT runtime
collector has its own metric families and never writes Data Connect history.
Separate MnT commands in `ise-cli` and curl probes remain operator-initiated
diagnostics. No ISE shell, SSH, root access, or Oracle Instant Client is required.
See [architecture](docs/architecture.md) for ownership and failure semantics.
The lab claims in this repository are cross-checked against the
[current rooted-appliance snapshot](docs/rooted-ise-ground-truth.md); the
exporter itself still uses supported remote interfaces only.

## ISE prerequisites

- ISE `3.3.0.430` with Patch `11` installed.
- ERS/OpenAPI enabled and a read-only API account.
- HTTPS access to the MnT XML session API when bounded active posture is enabled.
- Data Connect enabled on the MnT node with an Essentials license.
- The fixed Data Connect user, a non-expired password, TCPS port `2484`, and
  service `cpm10`.
- The MnT Admin certificate's issuing CA chain when TLS verification is enabled.

Data Connect uses `python-oracledb` Thin mode over TCPS. It does not require a
rooted ISE appliance, direct database-table access, or native Oracle libraries.

## Configuration

Copy [ise-exporter.toml.example](ise-exporter.toml.example) to
`/etc/ise-exporter/config.toml`. The file groups settings by purpose, names units
explicitly, and rejects unknown keys. Keep passwords in the service's secret
environment:

```sh
ISE_PASS=use-a-secret-store
ISE_DATACONNECT_PASSWORD=use-a-secret-store
```

Set `ISE_EXPORTER_CONFIG` to use another path. Only `ISE_PASS` and
`ISE_DATACONNECT_PASSWORD` override TOML, allowing secret-manager injection
without recreating the old environment-variable configuration surface. The TOML
sample is production-oriented for up to 100,000 endpoints:
database-side aggregation, collapsed summary/top-group scans, serialized five-second
query pacing, cadence-aligned event scans capped at six hours, daily RADIUS reporting,
two-hour bounded active-session reconstruction, six-hour performance reporting,
daily posture/TACACS/NAD reporting, daily source-freshness checks, and daily
inventory state. A private
SQLite cache survives restarts. MnT fetches at most 250 new or rotating endpoint
details per 15-minute cycle, while cached active details retain dashboard coverage.
RADIUS exact volume, failure, and distinct-identity totals use Cisco's Patch 11
`RADIUS_AUTHENTICATION_SUMMARY` aggregate view. Only method, protocol,
authorization-policy and status-specific latency breakdowns read the bounded raw
authentication view; failure class, authorization profile, and location remain on
the aggregate view. Configured-NAD activity health also sums passed and failed
counts from that aggregate view rather than grouping raw events again. RADIUS
historical gauges come from one exact
configured-window snapshot per day. The
separate active-session dataset scans only the configured stale window every
two hours; no locally merged historical event windows can grow without bound.
TACACS applies a six-hour bound inside Cisco's two-day views, and endpoint totals,
field coverage, and posture applicability share one inventory scan. CLI reports,
context searches, and live completion obey the same event-window ceiling.

Before starting the service, verify the reporting connection:

```bash
ise-exporter --dataconnect-check
ise-exporter --dataconnect-schema  # JSON column metadata; does not read event rows
ise-exporter --reset-state         # one-shot full state reset; stop the service first
ise-exporter --version             # package revision and exact ISE compatibility target
ise-cli --version                   # PowerShell 7 operator module + private backend
```

## Debian 12/13 and Ubuntu Server 24.04 LTS

Debian and Ubuntu are the native production targets. The installer uses standard
distribution packages and puts PyPI dependencies in an isolated venv:

```bash
sudo ./deploy/install.sh
sudoedit /etc/ise-exporter/config.toml
sudo -u ise-exporter /opt/ise-exporter/.venv/bin/ise-exporter --dataconnect-check
sudo systemctl start ise-exporter
curl --fail --silent http://127.0.0.1:9618/metrics | head
```

It installs the PowerShell 7 `Ise.Cli` module and `ise-cli` launcher for all local
users while keeping the TOML file and CA material restricted. The exporter
service itself does not require PowerShell. Re-running the installer upgrades
the application without overwriting configuration. A fresh installation is
enabled but intentionally left stopped because the seeded file contains example
hosts and passwords. The installer also refuses to start or restart the unit
while those placeholders remain. Once configured, re-running the installer
restarts an active service and preserves an intentionally stopped service. Full
details are in the [Debian and Ubuntu guide](docs/ubuntu-noble.md).

## Development and containers

```bash
python3 -m venv .venv
.venv/bin/pip install -e '.[dev]'
.venv/bin/ruff check .
PYTHONPATH=. .venv/bin/pytest -q
```

For Docker, copy `ise-exporter.toml.example` to `ise-exporter.toml`, provide the
CA under `deploy/certs`, then run `docker compose -f deploy/docker-compose.yml up -d`.
Prometheus scrapes port `9618`.

The systemd journal is useful at the default `INFO` level: every real collection
attempt records when and why it was queued or started, its outcome and duration,
whether metrics were published, and its next due or retry time. Per-request and
per-statement traffic remains at `DEBUG`. Long Data Connect safety waits remain
visible at `INFO` with the reporting view, wait duration, resume time, and pacing
reason, without printing SQL.

## Dashboards and diagnostics

Grafana dashboards are in [dashboards](dashboards/README.md). Data Connect panels
show bounded historical/reporting views. The Secure Client dashboard separately
labels its MnT panels as a bounded sample of currently active endpoints and shows
coverage and truncation. Accounting-derived likely-active session counts remain
Data Connect reconstructions and depend on NAD Start/Interim/Stop quality.

The active-session metric labels contain only bounded aggregate dimensions such
as status, OS, PSN, agent version, policy result, and numeric step code. MAC
addresses, session IDs, raw posture reports, usernames, and free-form failure
text are not exported by that dataset.

The read-only PowerShell 7 `Ise.Cli` module and scripts under `tools/` are separate
diagnostic surfaces. Run `ise-cli` with no arguments to start `pwsh` with the
module imported, or import `Ise.Cli` in an existing session. Endpoint cmdlets
accept common MAC formats, IP addresses, hostnames, and ERS ids; Data Connect is
preferred for IP/hostname inventory resolution and bounded RADIUS, posture, PSN,
and TACACS reports. Each curl probe supports `--schema-only`, which needs no
credentials or network. The Secure Client probe calls the same MnT path and parser
but is a separate operator action; it does not read or mutate the scheduled
snapshot. `Find-IseEndpoint -Criteria FIELD=PATTERN` provides schema-aware searches
across endpoint inventory and recent authorization, location, accounting, error,
and posture context; `Get-IseEndpointField` lists fields available from the
connected ISE schema.

Additional references:

- [Rooted ISE ground truth](docs/rooted-ise-ground-truth.md)
- [Migration roadmap](docs/migration-pxgrid-removal.md)
- [TACACS account attribution](docs/tacacs-account-attribution.md)
- [PowerShell 7 operator CLI](docs/ise-cli-powershell.md)
- [CLI backend contract and schema probes](docs/ise-cli.md)
