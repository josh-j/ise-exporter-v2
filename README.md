# Cisco ISE exporter

Prometheus exporter and read-only operator CLI for exactly **Cisco ISE
3.3.0.430 Patch 11**, the release used by the `laba-ise-001` lab. Normal startup
checks the appliance version and installed patch and fails closed for any other
release.

The metric runtime has two fixed collection planes:

- PAN ERS/OpenAPI owns platform and configuration state: deployment, NADs,
  certificates, licenses, backups, patches, and Device Administration objects.
- MnT Data Connect owns reporting state: RADIUS, accounting-derived sessions,
  endpoints, profiling, posture/Secure Client, PSN health, diagnostics, and
  TACACS activity.

There is no dynamic source selection or fallback. Legacy MnT XML remains only
in `ise-cli` and curl probes for explicit operator troubleshooting; it is never
called by a metric collector. No ISE shell, SSH, root access, or Oracle Instant
Client is required. See [architecture](docs/architecture.md) for ownership and
failure semantics.

## ISE prerequisites

- ISE `3.3.0.430` with Patch `11` installed.
- ERS/OpenAPI enabled and a read-only API account.
- Data Connect enabled on the MnT node with an Essentials license.
- The fixed Data Connect user, a non-expired password, TCPS port `2484`, and
  service `cpm10`.
- The MnT Admin certificate's issuing CA chain when TLS verification is enabled.

Data Connect uses `python-oracledb` Thin mode over TCPS. It does not require a
rooted ISE appliance, direct database-table access, or native Oracle libraries.

## Configuration

Copy [.env.example](.env.example) and set at least:

```dotenv
ISE_HOST=pan1.example.mil
ISE_MNT_HOST=mnt1.example.mil
ISE_USER=ers.readonly
ISE_PASS=use-a-secret-store

ISE_DATACONNECT_HOST=mnt1.example.mil
ISE_DATACONNECT_USER=dataconnect
ISE_DATACONNECT_PASSWORD=use-a-secret-store
ISE_DATACONNECT_CA_BUNDLE=/etc/ise-exporter/certs/ise-ca.cer
```

Values are parsed literally after the first `=`; `${NAME}` and additional `=`
characters in passwords are preserved. Inline comments on integer values are
not supported. The sample is production-oriented for roughly 80,000 endpoints:
database-side aggregation, bounded result groups, 60-second fast reporting,
five-minute posture/config reporting, and hourly inventory/slow state.

Before starting the service, verify the reporting connection:

```bash
ise-exporter --dataconnect-check
ise-exporter --dataconnect-schema  # JSON column metadata; does not read event rows
```

## Ubuntu Server 24.04 LTS

Noble Numbat is the native production target. The installer uses standard
Ubuntu packages and puts PyPI dependencies in an isolated venv:

```bash
sudo ./deploy/install.sh
sudoedit /etc/ise-exporter/ise-exporter.env
sudo -u ise-exporter /opt/ise-exporter/.venv/bin/ise-exporter --dataconnect-check
sudo systemctl start ise-exporter
curl --fail --silent http://127.0.0.1:9618/metrics | head
```

It installs `ise-cli` in `/usr/local/bin` for all local users while keeping the
environment file and CA material restricted. Re-running the installer upgrades
the application without overwriting configuration. A fresh installation is
enabled but intentionally left stopped because the seeded file contains example
hosts and passwords. The installer also refuses to start or restart the unit
while those placeholders remain. Once configured, re-running the installer
restarts an active service and preserves an intentionally stopped service. Full details are in the
[Ubuntu Noble guide](docs/ubuntu-noble.md).

## Development and containers

```bash
python3 -m venv .venv
.venv/bin/pip install -e '.[dev]'
.venv/bin/ruff check .
PYTHONPATH=. .venv/bin/pytest -q
```

For Docker, copy `.env.example` to `.env`, provide the CA under
`deploy/certs`, then run `docker compose -f deploy/docker-compose.yml up -d`.
Prometheus scrapes port `9618`.

## Dashboards and diagnostics

Grafana dashboards are in [dashboards](dashboards/README.md). They use the new
Data Connect metric families directly and show only dimensions supported by the
Patch 11 reporting views. Current-session counts are inferred from each RADIUS
accounting session ID's latest Start/Interim/Stop record, so correctness depends
on NAD accounting quality.

The read-only `ise-cli` and scripts under `tools/` are separate diagnostic
surfaces. Run `ise-cli` with no arguments for an interactive shell (`?` lists
commands), or use one-shot commands in scripts. Endpoint commands accept common
MAC formats, IP addresses, hostnames, and ERS ids; Data Connect is preferred for
IP/hostname inventory resolution and bounded RADIUS, posture, PSN, and TACACS
reports. Each curl probe supports `--schema-only`, which needs no credentials or
network. The Secure Client probe calls the same MnT diagnostic path and parser as
the CLI; it does not participate in exporter collection. Within the shell,
`endpoints FIELD=PATTERN` provides schema-aware searches across endpoint inventory
and recent authorization, location, accounting, error, and posture context;
`endpoint-fields` lists the fields actually available from the connected ISE schema.

Additional references:

- [Migration roadmap](docs/migration-pxgrid-removal.md)
- [TACACS account attribution](docs/tacacs-account-attribution.md)
- [CLI and schema probes](docs/ise-cli.md)
