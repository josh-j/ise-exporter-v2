# ise-cli backend contract and migration reference

The public operator interface is now the PowerShell 7 module documented in
[Ise.Cli for PowerShell 7](ise-cli-powershell.md). This document retains the
backend subcommand contract, API ownership, endpoint-search semantics, and safety
model used by the PowerShell module and by scripts migrating from the former
Python-rendered CLI.

The private `ise-cli-backend` is a read-only interface over ERS, OpenAPI, Data
Connect, and selected MnT XML diagnostics. `Ise.Cli` invokes it through bounded
JSON and completion protocols; operators normally use PowerShell cmdlets rather
than invoking the backend directly.

For lab-specific appliance version, service, listener, and TLS facts, use the
[rooted ISE ground-truth snapshot](rooted-ise-ground-truth.md). CLI output remains
authoritative for the supported remote API or reporting query it actually runs;
it must not be used to infer rooted process state.

The compatibility launcher `ise-cli` with no arguments starts `pwsh` with the
module imported. The former Python REPL remains private backend implementation
code during migration and is not installed as the public command.

Tab completion is context-aware. It completes commands, valid options, enum values,
output/select fields, generic GET families and known paths, and Data Connect view
names. Where credentials are configured, it also offers bounded, prefix-filtered
endpoint identifiers and profiles from the 100k-scale endpoint inventory, plus ISE
nodes, NADs, and internal TACACS usernames from REST configuration inventories.
Field-name completion remains fully schema-aware. Production-safe completion never
scans a RADIUS, TACACS, posture, accounting, diagnostic, or performance event view
merely because an operator pressed Tab: live values from those views require
`cli.allow_expensive = true`. Remote suggestions are capped at 25 rows and cached
for five minutes. A Tab press never waits behind the exporter's shared Data Connect
cooldown; it simply omits live suggestions when the pacing gate is busy. Completion
failures are silent and never prevent command entry.
Press Tab twice to display all matching choices.

```powershell
ise-cli
Get-Command -Module Ise.Cli
Get-IseEndpoint aabb.ccdd.eeff
Get-IseRadiusAuthentication -Identifier client-25.example.test -Limit 20
```

The exporter runtime uses MnT XML only for its separately bounded current
active-session posture/latency dataset. MnT commands in this CLI remain explicit,
operator-initiated diagnostics for inspecting individual session, authentication,
or Secure Client records; they do not access or modify that scheduled snapshot.

## Configuration and routing

The backend reads `ISE_EXPORTER_CONFIG` (default
`/etc/ise-exporter/config.toml`) or an explicit `--config` path. REST/OpenAPI
commands require `ise.host`, `ise.user`, and `ise.password`; only MnT XML
commands additionally require `ise.mnt_host`. Data Connect reporting commands
can run with only the `[dataconnect]` settings; when both
credential sets are present, endpoint resolution can enrich Data Connect inventory
rows with ERS detail. Authenticated targets must be bare DNS hostnames or IPv4
addresses, never URLs, user-info, paths, or `host:port` strings; ports and service
names have their own settings.

API routing is fixed by family:

| Family | Host | Base path |
|---|---|---|
| ERS | `ise.host` | `https://HOST:ERS_PORT/ers` |
| OpenAPI | `ise.host` | `https://HOST/api/v1` |
| MnT XML CLI diagnostics | `ise.mnt_host` | `https://HOST/admin/API/mnt` |
| Data Connect reporting | `dataconnect.host` | Oracle TCPS, service `cpm10` by default |

Collection ownership is explicit:

- Data Connect is preferred for reporting, and for IP/hostname lookup through
  `ENDPOINTS_DATA` without bulk ERS enumeration.
- ERS/OpenAPI supplies configuration inventory and detailed endpoint objects.
- Within the CLI, MnT is used only for operator-requested live session,
  auth-status, and Secure Client diagnostics, or as a resolution fallback when
  no inventory row exists.

This table describes CLI ownership. In the exporter process, a dedicated MnT
client uses only ActiveList and bounded per-MAC session details to publish
identity-free current posture and latency aggregates. It is not a CLI fallback
and does not replace Data Connect historical reports.

## Endpoint identifiers

`endpoint`, `resolve`, `session`, `auth-status`, `secure-client`, and the
`--identifier` filters on reporting commands accept endpoint identifiers wherever
the underlying data permits:

- MAC addresses in colon, hyphen, Cisco dotted, bare hexadecimal, or whitespace
  format;
- IPv4 and IPv6 addresses;
- hostnames (case-insensitive through Data Connect inventory);
- ERS endpoint UUIDs (`endpoint` and `resolve` auto-detect UUIDs; `--id` is also
  available).

Resolution uses Data Connect first for IP/hostname, then live MnT session data
(including DNS-to-IP fallback for hostnames), and finally ERS detail. A resolved
MAC is canonicalized as `AA:BB:CC:DD:EE:FF`
before use with ERS or MnT.

`resolve` reports `candidate_count` and `ambiguous` when an identifier maps to
multiple inventory rows. Commands that require one MAC (`session`, `auth-status`,
`secure-client`, and filtered reports) refuse an ambiguous hostname instead of
silently choosing a different endpoint; rerun with the intended MAC or ERS ID.

The compound `endpoint-summary` and `troubleshoot-auth` workflows preserve a
successful endpoint resolution when an optional MnT session or authentication
lookup is unavailable. The affected section is returned with
`status=unavailable` and a bounded diagnostic instead of failing the entire
workflow.
Valid empty MnT responses are reported as `status=no_results`, so every requested
section remains visible even when there is no current session or recent event.

## Commands

| Command | Purpose |
|---|---|
| `overview` | Read a cached local exporter/deployment summary without querying ISE |
| `collector-status [PATTERN]` | Show cached dataset availability, freshness, age, and failures |
| `endpoint-summary IDENTIFIER` | Build a bounded endpoint and current-session summary |
| `troubleshoot-auth IDENTIFIER` | Correlate endpoint resolution, current session, and recent MnT authentication |
| `psn-summary PSN [--live]` | Prefer cached PSN metrics with an optional bounded Data Connect refresh |
| `nad-summary NAD [--live]` | Prefer cached NAD metrics with an optional ERS refresh |
| `pxgrid-status [--live]` | Explain pxGrid ownership and optionally inspect deployment service assignment |
| `pxgrid-check` | Check pxGrid 2.0 activation and provider discovery |
| `pxgrid-account` | Return the pxGrid 2.0 activation state |
| `pxgrid-services`, `pxgrid-topics` | Discover pxGrid providers and topics |
| `pxgrid-query OPERATION` | Private bounded backend for PowerShell pxGrid cmdlets |
| `health` | Check reachability and authentication independently for PAN/ERS, MnT, and configured Data Connect |
| `ers-check` | Check ERS reachability, credentials, and authorization with one inventory row |
| `openapi-check` | Check OpenAPI reachability, credentials, and deployment-read authorization |
| `mnt-check` | Check MnT reachability and credentials with bounded `ActiveCount` |
| `nodes` | List deployment nodes from OpenAPI |
| `nads` | List Network Access Devices from ERS |
| `endpoints [[FIELD=]PATTERN ...]` | Search endpoints by inventory and recent context attributes |
| `endpoint-fields [PATTERN]` | List every searchable field exposed by the live Data Connect schema |
| `endpoint IDENTIFIER` | Resolve and inspect one endpoint; optionally join its MnT session |
| `resolve IDENTIFIER` | Show identifier kind, resolution source, MAC/IP/hostname, endpoint, and sessions |
| `sessions` | List active MnT sessions |
| `session IDENTIFIER` | Inspect one active session by MAC, IP, hostname, or endpoint id |
| `auth-status IDENTIFIER` | Show recent accept/reject records for an endpoint |
| `secure-client IDENTIFIER` | Parse Secure Client/Posture fields using the exporter's parser |
| `profiles` | List profiler policies |
| `tacacs-users` | List internal users used by Device Administration |
| `identity-groups`, `network-device-groups` | List ERS grouping inventory |
| `licenses`, `patches`, `backup-status`, `repositories` | Inspect platform state through OpenAPI |
| `network-policy-sets`, `authorization-profiles` | Inspect Network Access policy configuration |
| `device-admin-policy-sets`, `tacacs-command-sets`, `tacacs-shell-profiles` | Inspect Device Administration configuration |
| `certificates` | List system and trusted certificates, optionally by node/store |
| `endpoint-report` | Query bounded endpoint inventory directly from Data Connect |
| `radius-auth`, `radius-errors`, `radius-accounting` | Query the configured bounded RADIUS window from Data Connect; `radius-auth` supports PSN, policy, wildcard username, status, and hour filters |
| `posture`, `psn-metrics`, `tacacs-activity` | Query bounded posture, PSN, and TACACS reports from Data Connect |
| `dataconnect-query TABLE` | Safely search any discovered reporting view with validated columns and bound filters |
| `dataconnect-health` | Diagnose the authenticated Oracle session and accessible Data Connect catalog |
| `dataconnect-catalog [PATTERN]` | List all tables/views visible to the Data Connect account without scanning their rows |
| `dataconnect-schema [TABLE]` | Show reporting-view column metadata without reading event rows |
| `schema [COMMAND]` | Return API routes and contracts without credentials or network access |
| `get FAMILY PATH` | Perform an explicit generic GET against `ers`, `openapi`, or `mnt` |

Inventory commands return at most 100 rows by default and 1,000 rows without an
explicit production-impact acknowledgement. Complete enumeration requires both
`--all` and `--allow-expensive`. MnT ActiveList retrieval and leading-wildcard
searches such as `*LAPTOP*` likewise require `--allow-expensive`.

### Data Connect investigation

Use schema discovery to choose a reporting view, inspect its columns, then query
real rows as ordinary PowerShell objects:

```powershell
Get-IseDataConnectTable
Get-IseDataConnectTable '*TACACS*' | Get-IseDataConnectColumn
Get-IseDataConnectColumn TACACS_AUTHORIZATION_LAST_TWO_DAYS

Get-IseDataConnectRow TACACS_AUTHORIZATION_LAST_TWO_DAYS `
  -Column LOGGED_TIME,USERNAME,DEVICE_NAME,AUTHORIZATION_POLICY,COMMAND_FROM_DEVICE `
  -Like @{ USERNAME = 'admin*' } -Limit 100 |
  Format-Table -AutoSize
```

Exact filters use `-Where`; wildcard filters use `-Like` with `*` and `?`.
Hashtables make multiple criteria readable, and the result remains composable:

```powershell
Get-IseDataConnectRow RADIUS_AUTHENTICATIONS `
  -Column TIMESTAMP,USERNAME,CALLING_STATION_ID,DEVICE_NAME,POLICY_SET_NAME,FAILED `
  -Where @{ DEVICE_NAME = 'laba-sw-001' } -Like @{ USERNAME = 'svc-*' } `
  -OrderBy TIMESTAMP -Descending -Limit 200 |
  Group-Object POLICY_SET_NAME | Sort-Object Count -Descending

Get-IseDataConnectRow TACACS_AUTHORIZATION_LAST_TWO_DAYS `
  -Column USERNAME,DEVICE_NAME,AUTHORIZATION_POLICY,COMMAND_FROM_DEVICE `
  -Like @{ COMMAND_FROM_DEVICE = 'show*' } -Hours 48 -AllowExpensive |
  Export-Csv ./tacacs-show-commands.csv -NoTypeInformation
```

The backend validates every table and column against live metadata and binds every
filter value. It never accepts arbitrary SQL. Event views default to the configured
recent window (at most six hours); widening it up to 48 hours is explicit and needs
`-AllowExpensive`. Results default to 100 rows, with the same production ceiling as
the other bulk commands. Tab completion is available for table and column names.

The PowerShell module also provides focused diagnostic commands:

```powershell
Get-IseAlert -Severity ERROR -Hours 24 -AllowExpensive
Get-IseSystemDiagnostic -Category 'System Health' -Limit 50
Get-IseAaaDiagnostic -Username alice -Message '*timeout*' | Format-Table
Test-IseDataConnect | Format-List
```

`Test-IseDataConnect` reports the Oracle instance/service/schema, database and
session time zones, accessible view/column counts, query latency, and the active
connection safety settings without exposing credentials.

### Endpoint search grammar

`Find-IseEndpoint` accepts a bare pattern for endpoint name/hostname searches and
qualified `FIELD=PATTERN` criteria for other Context Visibility attributes:

```powershell
Find-IseEndpoint 'LAB-*'
Find-IseEndpoint 'authorization-policy=PermitAccess*'
Find-IseEndpoint 'location=Berlin-*','endpoint-policy=Windows*'
Find-IseEndpoint 'posture-status=Compliant','agent-version=5.1.*'
Find-IseEndpoint 'username=alice','nad=access-switch-*'
```

`*` matches any text and `?` matches one character. Different fields are combined
with AND. Repeating one field supplies alternatives with OR:

```powershell
Find-IseEndpoint 'location=Berlin-*','location=London-*','posture-status=Compliant'
Find-IseEndpoint '*LAPTOP*' -AllowExpensive
```

Searches run in Data Connect with bound values, a default 100-row limit, and the
configured bounded event window (at most six hours) for context views. They correlate context records to
`ENDPOINTS_DATA` by ISE's native MAC key and return every text, numeric, and timestamp
endpoint inventory column made available by the live schema. Results also include
`matched_context`, containing the actual authorization policy, location, posture,
or other context value that matched each requested field, while `matched_filters`
records the requested patterns.

`--all` is intentionally unavailable for Data Connect attribute searches because
the process has a non-relaxable 5,000-row materialization ceiling; silently calling
that subset complete would be incorrect. Narrow the pattern and use `--limit` (up
to 5,000 with `--allow-expensive`). Bare ERS inventory enumeration still supports
explicit `--all --allow-expensive` when a complete configuration export is required.

ISE 3.3 can store historical `PROBE_DATA` or `CUSTOM_ATTRIBUTES` bytes that are not
valid UTF-8. The CLI asks Oracle for an ASCII-safe projection so one legacy value
cannot break the entire search. JSON custom attributes and ISE's length-prefixed
probe attributes are rendered as normal key/value objects (including keys with
spaces such as `Ops Owner`); an unrecognized payload is preserved verbatim.

The field catalog is schema-driven rather than tied to a guessed ISE column list:

```powershell
Get-IseEndpointField
Get-IseEndpointField '*policy*'
Get-IseEndpointField '*location*'
```

Short operator aliases include `name`, `mac`, `ip`, `endpoint-policy`, `profile`,
`identity-group`, `authorization-policy`, `authentication-policy`, `policy-set`,
`authorization-profile`, `location`, `nad`, `device-type`, `device-groups`,
`username`, `identity-store`, `psn`, `posture-status`, `posture-policy`,
`posture-report`, `agent-version`, `mdm-server`, `security-group`, and
`response-time`. Every correlatable text, numeric, or timestamp field is also exposed
with a qualified name such as `endpoint.endpoint-policy`,
`auth.authorization-policy`, `accounting.authorization-policy`,
`error.failure-reason`, or `posture.posture-status`. Tab completion lists every
available field name and safe inventory/configuration values. Distinct event-view
values are offered only with the expensive-query opt-in. If a view or column does
not exist on the target ISE 3.3 Patch 11 deployment, it is not advertised.

Endpoint name and attribute searches require Data Connect. ISE 3.3 Patch 11's ERS
endpoint collection rejects the `name` filter, and ERS does not own authorization,
accounting, or posture context. Without Data Connect, `endpoints` still provides a
bounded unfiltered ERS inventory and accepts explicitly supplied advanced filters
that the appliance supports. In a normal OS shell, quote wildcard arguments so the
local shell does not expand them.

## Legacy subcommand compatibility

The public launcher still maps the former subcommand grammar through PowerShell
for migration. It asks the private backend for JSON, recreates the requested
terminal format at the process boundary, and preserves `--select`; use native
cmdlets for new scripts and pipelines.

```console
ise-cli health
ise-cli nodes --output json
ise-cli endpoints --limit 25 --select id,name,description
ise-cli endpoints 'LAB-*' --limit 25
ise-cli endpoints 'authorization-policy=PermitAccess*' 'location=Berlin-*'
ise-cli endpoint-fields '*policy*'
ise-cli endpoints --filter 'groupId.EQ.abc-123' --output csv
ise-cli endpoint AA:BB:CC:DD:EE:FF --include-session --output json
ise-cli endpoint aabb.ccdd.eeff
ise-cli resolve 192.0.2.25 --output json
ise-cli session client-25.example.test
ise-cli sessions --limit 200 --allow-expensive --output jsonl
ise-cli auth-status 192.0.2.25 --seconds 3600 --limit 50
ise-cli secure-client client-25.example.test --include-all --output json
ise-cli endpoint-report --profile Windows10-Workstation --limit 25
ise-cli radius-auth --identifier aabbccddeeff --status failed --limit 50
ise-cli radius-auth --psn-like 'laba-ise-*' --policy-set-like 'host*-*-*' --status failed --hours 1
ise-cli radius-errors --nad access-switch-01 --output csv
ise-cli posture --identifier client-25.example.test --conditions
ise-cli psn-metrics --psn laba-ise-001
ise-cli tacacs-activity --event-type accounting --username netadmin
ise-cli dataconnect-schema ENDPOINTS_DATA --output json
ise-cli certificates --node laba-ise-001
ise-cli schema secure-client --output json
ise-cli get ers /config/identitygroup --param size=25 --output json
ise-cli get openapi /license/system/tier-state --no-unwrap --output json
ise-cli get mnt /Session/ActiveList --allow-expensive --output json
```

Compatibility calls retain `--output table|json|jsonl|csv` and `--select`. Native
PowerShell callers use `Format-Table`, `ConvertTo-Json`, `Export-Csv`, and
`Select-Object` at the pipeline boundary.

## Read-only safety model

- REST/OpenAPI/MnT commands only call GET methods.
- Data Connect commands use fixed `SELECT` templates, discover available columns
  from Oracle metadata, bind user values, enforce six-hour windows where a timestamp
  is available, and cap output at 5,000 rows.
- The normal production ceiling is 1,000 rows. Higher limits, full inventories,
  leading-wildcard scans, and MnT ActiveList require `--allow-expensive`.
- `auth-status` defaults to 10 minutes and 20 results. Requests beyond one hour
  or 100 results require `--allow-expensive`, while the hard ceiling remains one
  day and 1,000 results. Generic MnT `AuthStatus` paths always require the same
  acknowledgement so they cannot bypass the curated command's bounds.
- MnT hostname/IP resolution does not silently download ActiveList; the operator
  must pass `--allow-active-list-scan` when that fallback is genuinely required.
- Exporter and CLI Data Connect queries share a file-locked pacing deadline, so
  concurrent CLI processes cannot bypass the configured duty-cycle cooldown.
  Operator-issued queries queue behind the current exporter or CLI owner and
  wait for its cooldown instead of failing with a busy-gate error. Ctrl-C still
  cancels a waiting CLI process without changing the shared deadline.
  Setting the pacing-file environment value to an empty string does not disable
  the gate; it restores the protected service-state default.
- Tab completion uses only bounded inventory/metadata Data Connect views and REST
  configuration inventory by default. High-volume event-view value completion
  requires the global expensive-query opt-in; a result-row cap alone does not
  bound Oracle scan work. Completion uses a non-blocking gate acquisition, so it
  cannot make the interactive prompt appear hung behind a production cooldown.
- The generic command requires a family-relative path, rejects full URLs and `..`,
  and exposes no HTTP method flag.
- Inventory enumeration is bounded unless `--all` is explicit.
- Passwords are loaded from TOML or the two supported secret overrides and are never rendered.
- Explicitly disabled lab TLS does not emit urllib3 warnings into structured CLI
  output; production deployments should still install the CA chain and enable
  verification.
- `schema` is local-only and does not load credentials or construct a client.

The standalone scripts under `tools/curl_*` remain useful for comparing raw API
responses with the normalized CLI output.

`health` uses a one-row ERS request and MnT `Session/ActiveCount`, not an
unauthenticated landing page or the expensive session list. Its `reachable` field
distinguishes network routing from `authenticated`; `http_status` exposes rejected
REST credentials without printing them. The Data Connect probe queues behind the
shared pacing gate and reports a completed result when its turn arrives. Data
Connect-only installations can run `health` without configuring REST/MnT.

## System-wide installation

`sudo ./deploy/install.sh` installs `/usr/local/bin/ise-cli` for every local user.
The package and interpreter are globally readable/executable, but the shared
`/etc/ise-exporter/config.toml`, Data Connect password, and certificate
material remain restricted to `root:ise-exporter`. An operator can either supply
their own TOML file with `--config` or be explicitly added to the `ise-exporter`
group when reuse of the service account configuration and shared pacing gate is
intended. A user who cannot access the configured pacing gate is refused rather
than allowed to issue an uncoordinated Data Connect query.

On NixOS, put authorized users and the service in a dedicated operator group and
pre-create the dedicated shared pacing directory and runtime file as group-writable.
Keep the parent state directory non-writable to the CLI group so the private SQLite
cache cannot be replaced. Do not point the CLI
at a `DynamicUser` state directory under `/var/lib/private`, which normal operator
sessions cannot traverse.
