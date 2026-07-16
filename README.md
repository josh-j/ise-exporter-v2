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

Complete these steps on ISE before installing the exporter. Menu names below are
for ISE `3.3.0.430` Patch `11`; Cisco's [ISE 3.3 documentation
collection](https://www.cisco.com/c/en/us/td/docs/security/ise/collections/ise-3-3.html)
is the vendor reference.

### 1. Deployment, DNS, licenses, and firewall

- Install Patch `11` on every node. The exporter deliberately rejects any other
  ISE release or patch.
- Give every PAN, MnT, and pxGrid node a stable FQDN. The configured hostname
  must resolve from the exporter host and appear in that service certificate's
  DNS SAN. Do not configure an IP address when hostname verification is enabled
  unless the certificate also contains that IP SAN.
- Keep an Essentials license compliant for Data Connect. Enabling the pxGrid
  persona requires the applicable ISE Advantage entitlement.
- Permit the exporter host to reach the required node addresses:

  | Data plane | Destination persona | Port |
  |---|---|---:|
  | Admin/OpenAPI HTTPS | PAN | TCP `443` |
  | ERS HTTPS and SDK | PAN | TCP `9060` |
  | OpenAPI, when exposed separately | PAN | TCP `9070` |
  | MnT XML active-session API | MnT | TCP `443` |
  | Data Connect Oracle TCPS | Active Data Connect MnT | TCP `2484` |
  | pxGrid 2.0 REST and WebSocket | pxGrid node | TCP `8910` |

No inbound connection from ISE to the exporter is required. Prometheus is the
only system that needs access to the exporter's TCP `9618` listener.

### 2. Enable ERS/OpenAPI and create the API account

1. In ISE, open **Administration > System > Settings > API Settings > API
   Service Settings**.
2. Enable **ERS (Read/Write)** and **Open API (Read/Write)** on the primary PAN.
   Enable the read-only services on other nodes only if they will be queried.
3. Save the settings. Cisco documents this under [Enable API
   Service](https://developer.cisco.com/docs/identity-services-engine/latest/).
4. Create a dedicated network-admin account and grant only the ERS Operator and
   OpenAPI/read permissions needed by this deployment. Do not reuse a human
   Super Admin account. Put its password in `ISE_PASS`; never put it in Git.
5. Confirm that the account can read ERS inventory on `9060`, OpenAPI on the
   PAN, and the MnT XML session API on `443` when
   `collectors.mnt_active_posture = true`.

The exporter never writes through ERS/OpenAPI. ISE calls the PAN toggle
"Read/Write" because it enables that API service; the exporter account should
still be restricted to read-only administration roles.

### 3. Enable and configure Data Connect

1. Open **Administration > System > Settings > Data Connect**.
2. Enable Data Connect on the monitoring node. In a two-MnT deployment, record
   which node ISE selects as active.
3. Set a unique Data Connect password and an operationally appropriate expiry.
   ISE fixes the username to `dataconnect`, the service name to `cpm10`, and the
   TCPS port to `2484`; they are not ordinary Oracle accounts or listener
   settings.
4. Store the password in `ISE_DATACONNECT_PASSWORD`. Monitor its expiry and
   rotate it before it expires.
5. On the same Data Connect page, choose **Export Data Connect Certificate** and
   download the public certificate/chain. This is the supported source for the
   client trust material. Cisco's [Data Connect
   procedure](https://www.cisco.com/c/en/us/td/docs/security/ise/3-3/admin_guide/b_ise_admin_3_3.pdf)
   also notes that moving Data Connect to another MnT requires downloading the
   new certificate again.

Data Connect uses the selected MnT Admin certificate. Put its issuing
intermediate CA certificates followed by the root CA certificate in one PEM
file; do not copy a private key. Configure the MnT FQDN, not an unmatched IP:

```toml
[dataconnect]
host = "mnt1.example.com"
port = 2484
service = "cpm10"
user = "dataconnect"
ca_bundle = "/etc/ise-exporter/certs/ise-dataconnect-ca.pem"
verify_tls = true
```

You can also inspect exactly what the live TCPS listener presents. This is a
diagnostic capture, not a substitute for authenticating the CA fingerprint
through the ISE certificate page or your CA administrator:

```bash
ISE_MNT=mnt1.example.com
openssl s_client -connect "${ISE_MNT}:2484" -servername "$ISE_MNT" \
  -showcerts </dev/null 2>/dev/null |
  sed -n '/-----BEGIN CERTIFICATE-----/,/-----END CERTIFICATE-----/p' \
  >ise-dataconnect-observed-chain.pem

openssl crl2pkcs7 -nocrl -certfile ise-dataconnect-observed-chain.pem |
  openssl pkcs7 -print_certs -noout
openssl s_client -connect "${ISE_MNT}:2484" -servername "$ISE_MNT" \
  -CAfile /etc/ise-exporter/certs/ise-dataconnect-ca.pem \
  -verify_return_error </dev/null
```

The first certificate normally shown by `s_client` is the MnT leaf certificate;
the remaining certificates are its advertised issuing chain. Trust only the CA
certificates whose SHA-256 fingerprints you verified independently. If ISE does
not advertise a root, export that root from **Administration > System >
Certificates > Trusted Certificates** or obtain it directly from the issuing
CA. Cisco documents certificate export and PEM/DER formats in [Import and Export
Certificates in ISE](https://www.cisco.com/c/en/us/support/docs/security/identity-services-engine/215927-how-to-import-and-export-certificate-fro.html).

### 4. Configure certificate trust for REST and MnT HTTPS

Identify the system certificate bound to the Admin service on each queried PAN
or MnT node. Export its issuing intermediate/root certificates from ISE's
Trusted Certificates store or from the issuing CA, concatenate them into a PEM
bundle, and configure both TLS planes:

```toml
[ise.rest_tls]
verify = true
ca_bundle = "/etc/ise-exporter/certs/ise-rest-ca.pem"

[ise.mnt_tls]
verify = true
ca_bundle = "/etc/ise-exporter/certs/ise-mnt-ca.pem"
```

To view the presented chains without credentials, repeat the `s_client` command
against `${ISE_PAN}:443`, `${ISE_PAN}:9060`, and `${ISE_MNT}:443`. Always pass
`-servername` so virtual-host/SNI selection and hostname diagnostics match the
configured FQDN. Cisco recommends that ISE system certificates carry the node
FQDN and IP address in SAN and describes the certificate roles in [Configure
TLS/SSL Certificates in
ISE](https://www.cisco.com/c/en/us/support/docs/security/identity-services-engine/215621-tls-ssl-certificates-in-ise.html).

### 5. Enable pxGrid 2.0 for the PowerShell CLI

pxGrid is an optional operator data source for `ise-cli`; scheduled exporter
collectors do not depend on it.

1. Open **Administration > System > Deployment**, edit at least one node, and
   enable its **pxGrid** persona.
2. Bind a pxGrid system certificate whose DNS SAN contains every FQDN that ISE
   advertises in pxGrid service URLs. The certificate needs server and client
   authentication suitability. Do not reuse the client certificate as the
   pxGrid server certificate.
3. For this CLI's password-authentication mode, open **Administration > pxGrid
   Services > Settings**, enable **Allow password based account creation**, and
   save. Leave automatic approval disabled in production.
4. Create the client once with `AccountCreate`, storing the generated password
   immediately in a secret manager. The endpoint is unauthenticated but its TLS
   server must already be verified:

   ```bash
   ISE_PXGRID=pxgrid1.example.com
   NODE_NAME=ise-cli-hostname
   curl --fail --silent --show-error \
     --cacert /etc/ise-exporter/certs/ise-pxgrid-ca.pem \
     -H 'Content-Type: application/json' \
     -d "{\"userName\":\"${NODE_NAME}\"}" \
     "https://${ISE_PXGRID}:8910/pxgrid/api/AccountCreate"
   ```

5. Put the returned password in `ISE_PXGRID_PASSWORD`, configure `[pxgrid]`
   with the same node name and CA bundle, then run `Test-IsePxGrid`. The first
   activation request normally becomes `PENDING`.
6. In **Administration > pxGrid Services > Client Management > Clients**, select
   the new client and approve it. Assign only the groups/policies needed for the
   read-only services. Run `Test-IsePxGrid` again until it returns `ENABLED`.
7. Run `Get-IsePxGridService` and confirm that expected providers advertise
   resolvable HTTPS/WSS URLs. Cisco describes approval, policies, diagnostics,
   and password-based accounts in the [ISE 3.3 pxGrid
   guide](https://www.cisco.com/c/en/us/td/docs/security/ise/3-3/admin_guide/b_ise_admin_3_3/b_ISE_admin_33_pxgrid.html)
   and the [pxGrid technical
   overview](https://developer.cisco.com/docs/pxgrid/technical-overview/).

For certificate-authenticated pxGrid, generate a separate client certificate,
configure `client_cert` and `client_key`, and omit the password. Keep the client
private key readable only by the CLI backend/service account.

### 6. Validate the ISE side before starting collection

From the exporter host, verify DNS, listeners, certificates, credentials, and
provider registration in that order:

```bash
getent hosts pan1.example.com mnt1.example.com pxgrid1.example.com
openssl s_client -connect mnt1.example.com:2484 -servername mnt1.example.com \
  -CAfile /etc/ise-exporter/certs/ise-dataconnect-ca.pem \
  -verify_return_error </dev/null
ise-exporter --dataconnect-check
ise-exporter --dataconnect-schema
```

```powershell
Test-IseHealth
Test-IseDataConnect
Test-IsePxGrid
Get-IsePxGridService | Format-Table serviceName,nodeName
```

If Data Connect is failed over, disabled/re-enabled on another node, or its
Admin certificate is renewed, retrieve and verify the replacement CA chain
before reconnecting. Apply the same rule to Admin/MnT and pxGrid certificate
renewals.

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
