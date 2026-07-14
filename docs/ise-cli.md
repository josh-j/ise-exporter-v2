# ise-cli: read-only Cisco ISE operator CLI

`ise-cli` is a read-only operator interface over ERS, OpenAPI, Data Connect, and
selected MnT XML diagnostics. It provides a PowerCLI-like surface for discovery,
troubleshooting, reporting, and automation without exposing write operations.

For lab-specific appliance version, service, listener, and TLS facts, use the
[rooted ISE ground-truth snapshot](rooted-ise-ground-truth.md). CLI output remains
authoritative for the supported remote API or reporting query it actually runs;
it must not be used to infer rooted process state.

Running `ise-cli` without a subcommand enters an interactive shell. `?` lists
commands, `help COMMAND` shows command-specific options, and `exit`, `quit`, or
Ctrl-D leave the shell. Interactive history is retained in
`~/.local/state/ise-cli/history` (override with `ISE_CLI_HISTORY`).

Tab completion is context-aware. It completes commands, valid options, enum values,
output/select fields, generic GET families and known paths, and Data Connect view
names. Where credentials are configured, it also offers bounded, prefix-filtered
endpoint identifiers and profiles from the 100k-scale endpoint inventory, plus ISE
nodes, NADs, and internal TACACS usernames from REST configuration inventories.
Field-name completion remains fully schema-aware. Production-safe completion never
scans a RADIUS, TACACS, posture, accounting, diagnostic, or performance event view
merely because an operator pressed Tab: live values from those views require
`ISE_CLI_ALLOW_EXPENSIVE=true`. Remote suggestions are capped at 25 rows and cached
for five minutes; completion failures are silent and never prevent command entry.
Press Tab twice to display all matching choices.

```console
$ ise-cli
Cisco ISE read-only shell. Type ? for commands, help COMMAND for details.
ise> ?
ise> endpoint aabb.ccdd.eeff
ise> radius-auth --identifier client-25.example.test --limit 20
ise> quit
```

The exporter runtime uses MnT XML only for its separately bounded current
active-session posture/latency dataset. MnT commands in this CLI remain explicit,
operator-initiated diagnostics for inspecting individual session, authentication,
or Secure Client records; they do not access or modify that scheduled snapshot.

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
| MnT XML CLI diagnostics | `ISE_MNT_HOST` | `https://HOST/admin/API/mnt` |
| Data Connect reporting | `ISE_DATACONNECT_HOST` | Oracle TCPS, service `cpm10` by default |

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

## Commands

| Command | Purpose |
|---|---|
| `health` | Check reachability and authentication independently for PAN/ERS, MnT, and configured Data Connect |
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
| `radius-auth`, `radius-errors`, `radius-accounting` | Query the configured bounded RADIUS window from Data Connect |
| `posture`, `psn-metrics`, `tacacs-activity` | Query bounded posture, PSN, and TACACS reports from Data Connect |
| `dataconnect-schema [TABLE]` | Show reporting-view column metadata without reading event rows |
| `schema [COMMAND]` | Return API routes and contracts without credentials or network access |
| `get FAMILY PATH` | Perform an explicit generic GET against `ers`, `openapi`, or `mnt` |

Inventory commands return at most 100 rows by default and 1,000 rows without an
explicit production-impact acknowledgement. Complete enumeration requires both
`--all` and `--allow-expensive`. MnT ActiveList retrieval and leading-wildcard
searches such as `*LAPTOP*` likewise require `--allow-expensive`.

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
ise> endpoints '*LAPTOP*' --allow-expensive
```

Searches run in Data Connect with bound values, a default 100-row limit, and a
two-day window for event/context views. They correlate context records to
`ENDPOINTS_DATA` by ISE's native MAC key and return every text, numeric, and timestamp
endpoint inventory column made available by the live schema. Results also include
`matched_context`, containing the actual authorization policy, location, posture,
or other context value that matched each requested field, while `matched_filters`
records the requested patterns.

ISE 3.3 can store historical `PROBE_DATA` or `CUSTOM_ATTRIBUTES` bytes that are not
valid UTF-8. The CLI asks Oracle for an ASCII-safe projection so one legacy value
cannot break the entire search. JSON custom attributes and ISE's length-prefixed
probe attributes are rendered as normal key/value objects (including keys with
spaces such as `Ops Owner`); an unrecognized payload is preserved verbatim.

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
ise-cli sessions --limit 200 --allow-expensive --output jsonl
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
ise-cli get mnt /Session/ActiveList --allow-expensive --output json
```

Every data command supports `--output table|json|jsonl|csv` and `--select`.
`jsonl`, `csv`, and field selection provide pipeline-friendly structured output in
the same spirit as selecting properties from PowerCLI objects.

## Read-only safety model

- REST/OpenAPI/MnT commands only call GET methods.
- Data Connect commands use fixed `SELECT` templates, discover available columns
  from Oracle metadata, bind user values, enforce two-day windows where a timestamp
  is available, and cap output at 5,000 rows.
- The normal production ceiling is 1,000 rows. Higher limits, full inventories,
  leading-wildcard scans, and MnT ActiveList require `--allow-expensive`.
- MnT hostname/IP resolution does not silently download ActiveList; the operator
  must pass `--allow-active-list-scan` when that fallback is genuinely required.
- Exporter and CLI Data Connect queries share a file-locked pacing deadline, so
  concurrent CLI processes cannot bypass the configured duty-cycle cooldown.
  Setting the pacing-file environment value to an empty string does not disable
  the gate; it restores the protected service-state default.
- Tab completion uses only bounded inventory/metadata Data Connect views and REST
  configuration inventory by default. High-volume event-view value completion
  requires the global expensive-query opt-in; a result-row cap alone does not
  bound Oracle scan work.
- The generic command requires a family-relative path, rejects full URLs and `..`,
  and exposes no HTTP method flag.
- Inventory enumeration is bounded unless `--all` is explicit.
- Passwords are loaded from the environment/dotenv source and are never rendered.
- Explicitly disabled lab TLS does not emit urllib3 warnings into structured CLI
  output; production deployments should still install the CA chain and enable
  verification.
- `schema` is local-only and does not load credentials or construct a client.

The standalone scripts under `tools/curl_*` remain useful for comparing raw API
responses with the normalized CLI output.

`health` uses a one-row ERS request and MnT `Session/ActiveCount`, not an
unauthenticated landing page or the expensive session list. Its `reachable` field
distinguishes network routing from `authenticated`; `http_status` exposes rejected
REST credentials without printing them. Data Connect-only installations can run
`health` without configuring REST/MnT.

## System-wide installation

`sudo ./deploy/install.sh` installs `/usr/local/bin/ise-cli` for every local user.
The package and interpreter are globally readable/executable, but the shared
`/etc/ise-exporter/ise-exporter.env`, Data Connect password, and certificate
material remain restricted to `root:ise-exporter`. An operator can either supply
their own environment/`--env-file` or be explicitly added to the `ise-exporter`
group when reuse of the service account configuration and shared pacing gate is
intended. A user who cannot access the configured pacing gate is refused rather
than allowed to issue an uncoordinated Data Connect query.

On NixOS, put authorized users and the service in a dedicated operator group and
pre-create the shared runtime pacing file as group-writable. Do not point the CLI
at a `DynamicUser` state directory under `/var/lib/private`, which normal operator
sessions cannot traverse.
