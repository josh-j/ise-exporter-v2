# Ubuntu Server 24.04 LTS installation

Ubuntu Server 24.04 LTS (Noble Numbat) is a supported native systemd target.
The deployment uses Ubuntu's standard `python3`, `python3-venv`,
`ca-certificates`, user-management, and systemd packages. Application Python
dependencies are isolated under `/opt/ise-exporter/.venv`; the installer never
uses `sudo pip` or changes Ubuntu's externally managed system Python.

The production host requirements below were reconciled with the lab's
[rooted ISE snapshot](rooted-ise-ground-truth.md), including live listeners on
Admin/OpenAPI HTTPS, MnT/ERS, and Data Connect TCPS. Root access to ISE is never
required by the Ubuntu service.

The `oracledb` dependency uses its pure network thin mode. TACACS and other Data
Connect collectors therefore do not require Oracle Instant Client, an Oracle apt
repository, a compiler, or database development headers.

`python-oracledb` itself is an application dependency installed from PyPI into
the private venv; it is not an Ubuntu Noble apt package. Consequently, a normal
installation needs outbound package access to PyPI (directly or through an
internal mirror). For disconnected installations, provide a pre-populated pip
wheelhouse or internal Python package index. Nothing is installed into Ubuntu's
system Python.

For an offline production host, build a wheelhouse on a connected Ubuntu Noble
machine and copy it with the checkout:

```bash
python3 -m pip download --dest wheelhouse '.[dev]'
python3 -m venv /opt/ise-exporter/.venv
/opt/ise-exporter/.venv/bin/pip install --no-index --find-links wheelhouse .
```

The normal installer uses the configured pip index; point pip at an internal
mirror with `/etc/pip.conf` when direct PyPI access is prohibited.

## Clean server installation

Clone or copy the repository to the server, then run:

```bash
sudo ./deploy/install.sh
sudoedit /etc/ise-exporter/ise-exporter.env
# Install the Data Connect CA chain under /etc/ise-exporter/certs, then preflight:
sudo -u ise-exporter /opt/ise-exporter/.venv/bin/ise-exporter --dataconnect-check
sudo systemctl start ise-exporter
sudo systemctl status ise-exporter
curl --fail --silent http://127.0.0.1:9618/metrics | head
```

The fresh install is enabled for boot but intentionally left stopped. The seeded
configuration contains example hosts and `changeme` passwords; the installer
will not start or restart the service while any of those placeholders remain.
This prevents a systemd restart loop from repeatedly sending invalid credentials
to ISE.

The installer is idempotent. Re-run it from an updated checkout to upgrade the
virtual environment, command-line tools, and systemd unit while preserving
`/etc/ise-exporter/ise-exporter.env` and certificates. A configured service that
was active is restarted during an upgrade. An intentionally stopped service
remains stopped.

It creates:

- the locked `ise-exporter` system account;
- `/opt/ise-exporter/.venv` for application code and dependencies;
- `/etc/ise-exporter/ise-exporter.env` and `/etc/ise-exporter/certs`;
- `/usr/local/bin/ise-cli` for all local users;
- `/etc/systemd/system/ise-exporter.service`.

The exporter needs outbound HTTPS to the PAN for REST/OpenAPI, HTTPS to
`ISE_MNT_HOST` when bounded active posture is enabled, and TCPS port 2484 to the
MnT node for Data Connect. Port 9618 must be reachable by Prometheus if it runs
on another host.

## Data Connect prerequisites

On Cisco ISE:

- an active Essentials license;
- Data Connect enabled on the MnT node that the exporter will query;
- the fixed `dataconnect` username and a configured, non-expired password;
- the fixed `cpm10` service on TCP 2484 reachable from the Ubuntu server;
- the MnT Admin certificate or its complete issuing CA chain exported as PEM.

Use a hostname that appears in the Admin certificate when TLS verification is
enabled. Install the PEM chain under `/etc/ise-exporter/certs`, owned by
`root:ise-exporter`, and configure:

```dotenv
ISE_REST_SSL_VERIFY=true
ISE_REST_CA_BUNDLE=/etc/ise-exporter/certs/ise-rest-ca.pem
# MnT serves bounded current active posture and explicit CLI diagnostics.
ISE_MNT_HOST=mnt1.example.mil
ISE_MNT_SSL_VERIFY=true
ISE_MNT_CA_BUNDLE=/etc/ise-exporter/certs/ise-mnt-ca.pem
COLLECT_MNT_ACTIVE_POSTURE=true
MNT_ACTIVE_POSTURE_INTERVAL=900
MNT_ACTIVE_POSTURE_MAX_SESSIONS=1000
MNT_ACTIVE_POSTURE_WORKERS=2
MNT_ACTIVE_POSTURE_MAX_REQUESTS_PER_CYCLE=250
MNT_ACTIVE_POSTURE_REFRESH_TTL=3600
MNT_ACTIVE_POSTURE_REQUEST_INTERVAL_MS=500
ISE_EXPORTER_STATE_DB=/var/lib/ise-exporter/state.sqlite3
ISE_DATACONNECT_HOST=mnt1.example.mil
ISE_DATACONNECT_PORT=2484
ISE_DATACONNECT_SERVICE=cpm10
ISE_DATACONNECT_USER=dataconnect
ISE_DATACONNECT_PASSWORD=use-a-secret-store
ISE_DATACONNECT_CA_BUNDLE=/etc/ise-exporter/certs/ise-dataconnect-ca.pem
ISE_DATACONNECT_SSL_VERIFY=true
ISE_DATACONNECT_MIN_QUERY_INTERVAL_MS=2000
ISE_DATACONNECT_MAX_DUTY_CYCLE_PERCENT=0.5
ISE_DATACONNECT_SHARED_PACING_FILE=/var/lib/ise-exporter/dataconnect.pacing
```

At the production defaults, the MnT collector deduplicates ActiveList MACs and
tracks at most 1,000 currently active endpoints and performs no more than 250
new/changed/rotating detail requests every 15 minutes with two paced workers.
The systemd `StateDirectory` preserves cached details and incremental RADIUS
aggregate windows across restarts. This bound is independent of the 100,000-endpoint
inventory.
Authorized `ise-cli` users must belong to the `ise-exporter` group so their Data
Connect queries participate in the same serialized pacing gate as the service.
The resulting metrics are current aggregate samples with coverage/truncation
signals; they never expose endpoint identity, session identity, or raw/free-form
attributes as Prometheus labels. Data Connect remains the historical posture and
reporting source.

ISE accepts a Data Connect password lifetime of 1 through 3650 days and defaults
to 90 days. Rotate the password before expiry and restart the exporter. More than
five incorrect connection attempts locks the account for 24 hours unless the
password is reset, so do not deploy an unverified password to multiple exporter
instances.

## Verification

```bash
sudo -u ise-exporter /opt/ise-exporter/.venv/bin/ise-exporter --dataconnect-check
ise-cli --help
ise-cli  # enter the interactive shell; type ? and then quit
ise-cli dataconnect-schema ENDPOINTS_DATA --output json
journalctl -u ise-exporter -n 100 --no-pager
```

The install path is continuously exercised on an `ubuntu-24.04` GitHub Actions
runner, including package installation, Python imports, global CLI availability,
systemd-unit validation, and the safe fresh-install state: enabled, inactive, and
with zero restarts while placeholders remain. Live startup and the metrics endpoint
require the exact supported ISE and Data Connect credentials, so those are covered
by the lab smoke test rather than public CI.
