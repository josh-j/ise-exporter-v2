# ise-cli: read-only Cisco ISE operator CLI

`ise-cli` is a read-only operator interface over ERS, OpenAPI, Data Connect, and
selected MnT XML diagnostics. It provides a PowerCLI-like surface for discovery,
troubleshooting, reporting, and automation without exposing write operations.

Running `ise-cli` without a subcommand enters an interactive shell. `?` lists
commands, `help COMMAND` shows command-specific options, and `exit`, `quit`, or
Ctrl-D leave the shell. Interactive history is retained in
`~/.local/state/ise-cli/history` (override with `ISE_CLI_HISTORY`).

Tab completion is context-aware. It completes commands, valid options, enum values,
output/select fields, generic GET families and known paths, and Data Connect view
names. Where credentials are configured, it also offers bounded,
prefix-filtered endpoint identifiers, ISE nodes/PSNs, profiles, NADs, and usernames.
Remote suggestions are capped at 25 rows and cached for 30 seconds; completion
failures are silent and never prevent command entry. Press Tab twice to display all
matching choices.

```console
$ ise-cli
Cisco ISE read-only shell. Type ? for commands, help COMMAND for details.
ise> ?
ise> endpoint aabb.ccdd.eeff
ise> radius-auth --identifier client-25.example.test --limit 20
ise> quit
```

The exporter metric runtime does not use MnT XML. Its reporting plane is Data
Connect, while MnT commands in this CLI are explicit, operator-initiated diagnostics
for inspecting individual session, authentication, or Secure Client records.

## Configuration and routing

The CLI loads `./.env`, then `ISE_EXPORTER_ENV_FILE` (default
`/etc/ise-exporter/ise-exporter.env`) without overriding variables already present in
the process environment. REST and MnT commands require `ISE_HOST`, `ISE_MNT_HOST`,
`ISE_USER`, and `ISE_PASS`. Data Connect reporting commands can run with only the
`ISE_DATACONNECT_*` settings; when both credential sets are present, endpoint
resolution can enrich Data Connect inventory rows with ERS detail.

API routing is fixed by family:

| Family | Host | Base path |
|---|---|---|
| ERS | `ISE_HOST` | `https://HOST:ERS_PORT/ers` |
| OpenAPI | `ISE_HOST` | `https://HOST/api/v1` |
| MnT XML diagnostics only | `ISE_MNT_HOST` | `https://HOST/admin/API/mnt` |
| Data Connect reporting | `ISE_DATACONNECT_HOST` | Oracle TCPS, service `cpm10` by default |

Collection ownership is explicit:

- Data Connect is preferred for reporting, and for IP/hostname lookup through
  `ENDPOINTS_DATA` without bulk ERS enumeration.
- ERS/OpenAPI supplies configuration inventory and detailed endpoint objects.
- MnT is used only for operator-requested live session, auth-status, and Secure
  Client diagnostics, or as a resolution fallback when no inventory row exists.

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

## Commands

| Command | Purpose |
|---|---|
| `health` | Check PAN/ERS and MnT reachability independently |
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
| `radius-auth`, `radius-errors`, `radius-accounting` | Query bounded two-day RADIUS reports from Data Connect |
| `posture`, `psn-metrics`, `tacacs-activity` | Query bounded posture, PSN, and TACACS reports from Data Connect |
| `dataconnect-schema [TABLE]` | Show reporting-view column metadata without reading event rows |
| `schema [COMMAND]` | Return API routes and contracts without credentials or network access |
| `get FAMILY PATH` | Perform an explicit generic GET against `ers`, `openapi`, or `mnt` |

Inventory commands return at most 100 rows by default. Use `--limit N` for a larger
bounded query or `--all` to explicitly enumerate the complete inventory. On an
80,000-endpoint deployment, prefer bounded queries and server-side filters during
interactive work.

### Friendly endpoint searches

Inside `ise-cli`, a bare pattern searches the endpoint name/hostname. A qualified
pattern uses `FIELD=PATTERN`:

```console
ise> endpoints LAB-*
ise> endpoints authorization-policy=PermitAccess*
ise> endpoints location=Berlin-* endpoint-policy=Windows*
ise> endpoints posture-status=Compliant agent-version=5.1.*
ise> endpoints username=alice nad=access-switch-*
```

`*` matches any text and `?` matches one character. Different fields are combined
with AND. Repeating one field supplies alternatives with OR:

```console
ise> endpoints location=Berlin-* location=London-* posture-status=Compliant
```

Searches run in Data Connect with bound values, a default 100-row limit, and a
two-day window for event/context views. They correlate context records to
`ENDPOINTS_DATA` by ISE's native MAC key and return every text, numeric, and timestamp
endpoint inventory column made available by the live schema. Results also include
`matched_context`, containing the actual authorization policy, location, posture,
or other context value that matched each requested field, while `matched_filters`
records the requested patterns.

The field catalog is schema-driven rather than tied to a guessed ISE column list:

```console
ise> endpoint-fields
ise> endpoint-fields *policy*
ise> endpoint-fields *location*
```

Short operator aliases include `name`, `mac`, `ip`, `endpoint-policy`, `profile`,
`identity-group`, `authorization-policy`, `authentication-policy`, `policy-set`,
`authorization-profile`, `location`, `nad`, `device-type`, `device-groups`,
`username`, `identity-store`, `psn`, `posture-status`, `posture-policy`,
`posture-report`, `agent-version`, `mdm-server`, `security-group`, and
`response-time`. Every correlatable text, numeric, or timestamp field is also exposed
with a qualified name such as `endpoint.endpoint-policy`,
`auth.authorization-policy`, `accounting.authorization-policy`,
`error.failure-reason`, or `posture.posture-status`. Tab completion lists available
field names and distinct live values. If a view or column does not exist on the
target ISE 3.3 Patch 11 deployment, it is not advertised.

When Data Connect is unavailable, one bare endpoint-name pattern still falls back to
the ERS server-side `EQ`, `STARTSW`, `ENDSW`, or `CONTAINS` filter. Attribute searches
require Data Connect because ERS does not own authorization, accounting, or posture
context. In a normal OS shell, quote wildcard arguments so the local shell does not
expand them.

## Examples

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
ise-cli sessions --limit 200 --output jsonl
ise-cli auth-status 192.0.2.25 --seconds 3600 --limit 50
ise-cli secure-client client-25.example.test --include-all --output json
ise-cli endpoint-report --profile Windows10-Workstation --limit 25
ise-cli radius-auth --identifier aabbccddeeff --status failed --limit 50
ise-cli radius-errors --nad access-switch-01 --output csv
ise-cli posture --identifier client-25.example.test --conditions
ise-cli psn-metrics --psn laba-ise-001
ise-cli tacacs-activity --event-type accounting --username netadmin
ise-cli dataconnect-schema ENDPOINTS_DATA --output json
ise-cli certificates --node laba-ise-001
ise-cli schema secure-client --output json
ise-cli get ers /config/identitygroup --param size=25 --output json
ise-cli get openapi /license/system/tier-state --no-unwrap --output json
ise-cli get mnt /Session/ActiveList --output json
```

Every data command supports `--output table|json|jsonl|csv` and `--select`.
`jsonl`, `csv`, and field selection provide pipeline-friendly structured output in
the same spirit as selecting properties from PowerCLI objects.

## Read-only safety model

- REST/OpenAPI/MnT commands only call GET methods.
- Data Connect commands use fixed `SELECT` templates, discover available columns
  from Oracle metadata, bind user values, enforce two-day windows where a timestamp
  is available, and cap output at 5,000 rows.
- The generic command requires a family-relative path, rejects full URLs and `..`,
  and exposes no HTTP method flag.
- Inventory enumeration is bounded unless `--all` is explicit.
- Passwords are loaded from the environment/dotenv source and are never rendered.
- `schema` is local-only and does not load credentials or construct a client.

The standalone scripts under `tools/curl_*` remain useful for comparing raw API
responses with the normalized CLI output.

## System-wide installation

`sudo ./deploy/install.sh` installs `/usr/local/bin/ise-cli` for every local user.
The package and interpreter are globally readable/executable, but the shared
`/etc/ise-exporter/ise-exporter.env`, Data Connect password, and certificate
material remain restricted to `root:ise-exporter`. An operator can either supply
their own environment/`--env-file` or be explicitly added to the `ise-exporter`
group when reuse of the service account configuration is intended.
