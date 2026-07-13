# ise-cli: read-only Cisco ISE operator CLI

`ise-cli` is a read-only command interface over the same ERS, OpenAPI, and MnT
transport used by the exporter. It is intended to provide a PowerCLI-like operator
surface for discovery, troubleshooting, reporting, and automation without exposing
write operations.

## Configuration and routing

The CLI loads `./.env`, then `ISE_EXPORTER_ENV_FILE` (default
`/etc/ise-exporter/ise-exporter.env`) without overriding variables already present in
the process environment. It requires `ISE_HOST`, `ISE_MNT_HOST`, `ISE_USER`, and
`ISE_PASS`.

API routing is fixed by family:

| Family | Host | Base path |
|---|---|---|
| ERS | `ISE_HOST` | `https://HOST:ERS_PORT/ers` |
| OpenAPI | `ISE_HOST` | `https://HOST/api/v1` |
| MnT XML | `ISE_MNT_HOST` | `https://HOST/admin/API/mnt` |

## Commands

| Command | Purpose |
|---|---|
| `health` | Check PAN/ERS and MnT reachability independently |
| `nodes` | List deployment nodes from OpenAPI |
| `nads` | List Network Access Devices from ERS |
| `endpoints` | List endpoints from ERS |
| `endpoint MAC` | Resolve and inspect one ERS endpoint; optionally join its MnT session |
| `sessions` | List active MnT sessions |
| `auth-status MAC` | Show recent accept/reject records for a MAC |
| `secure-client MAC` | Parse Secure Client/Posture fields using the exporter's parser |
| `profiles` | List profiler policies |
| `tacacs-users` | List internal users used by Device Administration |
| `schema [COMMAND]` | Return API routes and contracts without credentials or network access |
| `get FAMILY PATH` | Perform an explicit generic GET against `ers`, `openapi`, or `mnt` |

Inventory commands return at most 100 rows by default. Use `--limit N` for a larger
bounded query or `--all` to explicitly enumerate the complete inventory. On an
80,000-endpoint deployment, prefer bounded queries and ERS filters during interactive
work.

## Examples

```console
ise-cli health
ise-cli nodes --output json
ise-cli endpoints --limit 25 --select id,name,description
ise-cli endpoints --filter 'groupId.EQ.abc-123' --output csv
ise-cli endpoint AA:BB:CC:DD:EE:FF --include-session --output json
ise-cli sessions --limit 200 --output jsonl
ise-cli auth-status AA:BB:CC:DD:EE:FF --seconds 3600 --limit 50
ise-cli secure-client AA:BB:CC:DD:EE:FF --include-all --output json
ise-cli schema secure-client --output json
ise-cli get ers /config/identitygroup --param size=25 --output json
ise-cli get openapi /license/system/tier-state --no-unwrap --output json
ise-cli get mnt /Session/ActiveList --output json
```

Every data command supports `--output table|json|jsonl|csv` and `--select`.
`jsonl`, `csv`, and field selection provide pipeline-friendly structured output in
the same spirit as selecting properties from PowerCLI objects.

## Read-only safety model

- The CLI only calls the existing client's GET methods.
- The generic command requires a family-relative path, rejects full URLs and `..`,
  and exposes no HTTP method flag.
- Inventory enumeration is bounded unless `--all` is explicit.
- Passwords are loaded from the environment/dotenv source and are never rendered.
- `schema` is local-only and does not load credentials or construct a client.

The standalone scripts under `tools/curl_*` remain useful for comparing raw API
responses with the normalized CLI output.
