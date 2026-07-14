# Rooted ISE ground truth

This is the current appliance-level reference for the lab used to develop and
validate the exporter. It records only non-secret facts observed read-only on
the rooted ISE host. Runtime API responses and Data Connect rows remain the
authority for their own data planes; root access does not turn internal files or
database tables into supported exporter interfaces.

## Evidence snapshot

Captured at `2026-07-14T05:25:38Z` from the rooted appliance at
`10.200.30.10`:

| Fact | Rooted observation |
|---|---|
| Appliance hostname | `laba-ise-001` |
| Appliance FQDN | `laba-ise-001.ise.lab` |
| Cisco ISE release | `3.3.0.430` |
| Installed patch | `11` |
| Base OS | Red Hat Enterprise Linux 8.4, kernel `4.18.0-509.el8.x86_64` |
| Virtualization | QEMU VM, 4 vCPU, 15 GiB RAM |
| Appliance address | `10.200.30.10/24`, gateway `10.200.30.1` |
| Storage at capture | `/` 29 GiB with 17% used; `/opt` 255 GiB with 21% used |
| DNS resolver | `10.200.20.10`, search domain `ise.lab` |

The installed application reports ISE `3.3.0.430` and Patch 11 directly through
`/opt/CSCOcpm/bin/cpmversion.sh`. The exporter independently verifies the same
release through supported OpenAPI at startup.

## Current service state

`/opt/CSCOcpm/bin/cpmcontrol.sh status` reported these relevant services
running at capture time:

- Database Listener and Database Server;
- Application Server, Profiler Database, ISE Indexing Engine, and AD Connector;
- M&T Session Database and M&T Log Processor;
- Certificate Authority and EST services;
- ISE Messaging, API Gateway Database, and API Gateway;
- ISE pxGrid Direct;
- ISE Node Exporter, Prometheus, and Grafana;
- ISE Native IPSec and MFC Profiler.

SXP, PassiveID, DHCP, DNS, REST Auth, SSE Connector, pxGrid Cloud, Meraki Sync,
Duo Sync, segmentation policy, and the M&T Elasticsearch/Logstash/Kibana stack
were disabled. This is a point-in-time operational snapshot, not a declaration
that every running appliance service belongs in this exporter.

The rooted filesystem and process list also confirmed the expected ISE stack:
`/opt/CSCOcpm`, Oracle, Postgres, Redis, RabbitMQ, Kong, `/opt/xgrid`,
`/opt/sp-hub`, Prometheus, node_exporter, and Grafana.

## Listener evidence

The root socket table showed these externally relevant listeners:

| Interface | Listener |
|---|---|
| TACACS+ | TCP `49` |
| Admin/OpenAPI gateway | TCP `443` |
| Oracle listener | TCP `1521` |
| RADIUS authentication/accounting | UDP `1812` and `1813` |
| Data Connect TCPS | TCP `2484` |
| pxGrid control/data services | TCP `8910`, `8911`, `9060`, `9080`, `9090` |
| Embedded node exporter | TCP `9100` |

An open listener proves that a service is accepting connections. It does not
prove credentials, authorization, dataset freshness, or end-to-end exporter
success.

## TLS and hostname caveat

The current Admin/OpenAPI certificate on ports `443` and `9060` has subject and
only SAN `laba-ise-001.ise.lab`. The pxGrid control certificate on port `8910`
still has subject/SAN `ise01.ise.lab`. The appliance itself resolves
`laba-ise-001.ise.lab` to `10.200.30.10` but did not resolve the former
`ise01.ise.lab` name during this capture.

That split identity is important operational evidence: pxGrid Direct is running,
but a hostname-verifying pxGrid client can still fail until the pxGrid
certificate/service identity is regenerated for the renamed node or the legacy
name is deliberately restored in DNS. The exporter runtime intentionally does
not use pxGrid, so this appliance defect does not change its collection
boundaries.

## Authority by question

Use the narrowest authoritative source:

| Question | Ground truth |
|---|---|
| Installed version, processes, listeners, files, local DNS, service state | Rooted appliance evidence in this document |
| Supported PAN configuration and deployment objects | ERS/OpenAPI responses |
| Historical RADIUS, endpoint, posture, PSN, and TACACS reporting | Data Connect views |
| Current bounded active-session posture and latency | MnT XML active-session sample |
| What is actually exported | Exporter metric contract and `/metrics` |
| What Grafana can display | Prometheus series plus dashboard queries |

Do not infer a reporting metric merely because a process, package, listener, or
internal database exists on the appliance. The exporter remains read-only and
uses supported remote interfaces only.

## Reproduction

The non-secret rooted checks used for this snapshot were:

```sh
hostnamectl
/opt/CSCOcpm/bin/cpmversion.sh
/opt/CSCOcpm/bin/cpmcontrol.sh status
ss -lntup
ip -brief address show scope global
getent hosts laba-ise-001.ise.lab ise01.ise.lab
```

Root access is a documentation and diagnosis tool, not a runtime prerequisite.
Never copy credentials, private keys, internal account material, or unredacted
configuration and logs into this repository.
