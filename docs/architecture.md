# Architecture and collection boundaries

`ise-exporter` has one deliberately narrow compatibility target and two runtime
collection planes. It is not a general-purpose exporter for every Cisco ISE
release.

## Supported ISE contract

The sole supported appliance release is:

```text
Cisco ISE 3.3.0.430 Patch 11
```

This is the release running in the lab on `laba-ise-001`. At every normal
startup, the exporter validates the connected deployment with the supported,
read-only OpenAPI routes `GET /api/v1/patch` and
`GET /api/v1/deployment/node`. Startup fails closed when:

- `iseVersion` is not exactly `3.3.0.430`;
- the highest installed patch is not exactly `11`; or
- the deployment-node response does not satisfy the expected Patch 11 schema.

This exact-version check is intentional. A newer patch, ISE 3.4, or an older
ISE 3.3 patch must be evaluated and tested explicitly before the compatibility
contract is changed. The exporter uses supported remote interfaces only; it
never requires SSH, an appliance shell, database-table access, or root access
to ISE.

## Two-plane runtime

```text
                         +-----------------------+
PAN ERS/OpenAPI -------->| platform/configuration|---+
                         +-----------------------+   |
                                                     +--> Prometheus metrics
                         +-----------------------+   |
MnT Data Connect ------->| monitoring/reporting  |---+
                         +-----------------------+
```

The planes have fixed ownership. A collector does not inspect another
collector's metrics, choose a source dynamically, or fall back to a transport
with different semantics.

### REST/OpenAPI control plane

REST/OpenAPI owns appliance and configuration state:

- deployment nodes, personas, services, and PAN HA;
- network-device inventory and device-group classification;
- certificates and trust-store expiry;
- licensing state and consumption;
- backup status;
- installed version and patch inventory; and
- Device Administration configuration objects and internal-account inventory.

ERS and OpenAPI requests go to `ISE_HOST`. They are not used for bulk endpoint,
authentication, posture, session, or performance reporting.

### Data Connect reporting plane

Data Connect owns monitoring and reporting state:

- RADIUS authentication, errors, response latency, and accounting;
- endpoint inventory and profiling aggregates;
- posture policies, conditions, failures, endpoint OS, and Secure Client agent
  version;
- PSN KPIs, node resource utilization, and AAA/system diagnostics; and
- TACACS authentication, authorization, accounting, command, and per-account
  activity.

Queries are read-only, aggregated in Oracle, time-bounded where the view is an
event history, and capped by `ISE_DATACONNECT_MAX_GROUPS`. Endpoint identities,
session IDs, raw posture reports, and free-form failure text must not become
unbounded Prometheus labels.

### No pxGrid runtime

pxGrid is not part of the architecture. There is no pxGrid client,
certificate credential, account activation, snapshot, WebSocket subscription,
topic consumer, or live-event overlay in the exporter runtime. Current-session
reporting is derived from Data Connect accounting data and therefore has the
freshness and completeness of the accounting records supplied by the NADs.

### No MnT metric runtime

The legacy MnT XML API is not a metric source. It must not be called by the
scheduler or any metric collector. MnT XML remains available only in `ise-cli`
and the curl probes as an explicit, read-only troubleshooting surface for an
operator inspecting a particular session, authentication, or Secure Client
record.

## One-owner dataset matrix

| Dataset | Sole metric owner | Interface | Runtime cadence |
|---|---|---|---|
| ISE compatibility, version, patches | Platform | PAN OpenAPI | startup / slow |
| Deployment, personas, services, PAN HA | Platform | PAN OpenAPI | medium |
| Network devices and group classification | Configuration | ERS | medium |
| Certificates | Platform | PAN OpenAPI | slow |
| Licensing | Platform | PAN OpenAPI | slow |
| Backup status | Platform | PAN OpenAPI | slow |
| Device Admin policy configuration | Configuration | ERS/OpenAPI | slow |
| RADIUS authentication, failures, and latency | Reporting | Data Connect | fast |
| RADIUS accounting and session duration | Reporting | Data Connect | fast |
| Endpoint inventory and profiling | Reporting | Data Connect | slow |
| Posture and Secure Client | Reporting | Data Connect | medium |
| PSN performance and diagnostics | Reporting | Data Connect | fast |
| TACACS account and command activity | Reporting | Data Connect | medium |

There is one writer for each metric family. Control-plane configuration and
reporting-plane activity may describe the same feature, such as TACACS, but
they emit distinct metric families and never substitute for one another.

## Failure semantics

- Failure of one dataset records collector failure without changing ownership.
- The exporter retries the same authoritative source at its configured cadence;
  it never switches to pxGrid, MnT XML, or per-endpoint ERS fan-out.
- A reporting-plane failure must not be represented as a valid empty snapshot.
- Successful grouped query results replace their metric snapshot atomically so
  removed groups do not linger.
- Repeated collector failure is rate-limited by the scheduler to protect ISE.
- Failure of the exact-version startup check prevents the metrics server from
  starting against an unsupported appliance.

## Ubuntu Noble and Data Connect requirements

Ubuntu Server 24.04 LTS (Noble Numbat) is the native production target. The
installer uses standard Ubuntu packages for Python, virtual environments,
certificates, users, and systemd. Application dependencies live in
`/opt/ise-exporter/.venv`; Ubuntu's externally managed system Python is not
modified.

`python-oracledb` runs in Thin mode. Oracle Instant Client, Oracle apt
repositories, compilers, and Oracle development headers are not required. The
Python package must be installed from PyPI, an internal Python index, or an
offline wheelhouse.

Data Connect requires:

- Data Connect enabled on the ISE 3.3 Patch 11 MnT node;
- the fixed `dataconnect` username and a configured, non-expired password;
- outbound TCPS from Ubuntu to the MnT hostname on port `2484`;
- the fixed Oracle service name `cpm10`; and
- the MnT Admin certificate's complete issuing CA chain when TLS verification
  is enabled.

The hostname must match the Admin certificate. Data Connect credentials and CA
material are read by the unprivileged `ise-exporter` service account. No ISE
root credential or appliance filesystem access is used.

## Configuration principle

Configuration selects domains and intervals, not competing transports. Normal
production operation always uses REST/OpenAPI for the control plane and Data
Connect for the reporting plane. If Data Connect is unavailable, reporting
datasets are unavailable; they do not silently acquire different definitions
from legacy APIs.
