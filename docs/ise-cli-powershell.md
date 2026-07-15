# Ise.Cli for PowerShell 7

`Ise.Cli` is the PowerShell-first operator interface for Cisco ISE 3.3 Patch 11.
It returns normal PowerShell objects instead of pre-rendered terminal tables, so
filtering, selection, grouping, CSV export, JSON conversion, and formatting use
the standard PowerShell pipeline.

The exporter service remains Python-only and does not require PowerShell. The
module calls the private `ise-cli-backend` JSON protocol for ISE transport and
queries. This deliberately keeps TLS validation, REST authentication backoff,
Data Connect serialization/pacing, schema discovery, query windows, and hard row
limits in one audited implementation rather than recreating them with a second
Oracle or HTTP client.

## Start PowerShell

The native installer copies the module into PowerShell's system module path and
installs the `ise-cli` launcher:

```console
$ ise-cli
ISE CLI ready. Try Find-Endpoint, ise-help, or Get-Command -Module Ise.Cli.
ISE PS /current/path> Get-Command -Module Ise.Cli
ISE PS /current/path> Find-Endpoint 'LAB-*'  # concise alias for Find-IseEndpoint
```

The launcher uses its own operator profile without changing the normal PowerShell
profile. It provides an `ISE PS` prompt, menu completion on Tab, prefix-based
history search on the arrow keys, and categorized `ise-help` topics (`overview`,
`troubleshooting`, `endpoints`, `reporting`, `configuration`, and `advanced`).

From an existing `pwsh` session:

```powershell
Import-Module Ise.Cli
Get-IseCliVersion
Get-Help Find-IseEndpoint -Full
```

For a checkout that has not been installed:

```powershell
Import-Module ./powershell/Ise.Cli/Ise.Cli.psd1
```

PowerShell 7.2 or newer is required. Windows PowerShell 5.1 is intentionally not
supported. On Ubuntu, PowerShell is an operator-tool dependency obtained from
Microsoft's PowerShell packages; the exporter daemon continues to use only the
standard Ubuntu packages documented in [ubuntu-noble.md](ubuntu-noble.md).

## Native object workflow

```powershell
# Wildcards are passed as values; the shell does not expand them as filesystem globs.
Find-IseEndpoint 'LAB-*'
Find-Endpoint 'LAB-*'  # equivalent convenience alias
Find-IseEndpoint @(
    'authorization-policy=PermitAccess*'
    'location=Berlin-*'
) -Limit 250

# Normal PowerShell selection, filtering, formatting, and export.
Find-IseEndpoint '*LAPTOP*' -AllowExpensive |
    Where-Object posture_status -eq Compliant |
    Select-Object mac_address, hostname, endpoint_policy, matched_context |
    Format-Table

Get-IseRadiusAuthentication -Status failed -Limit 100 |
    Group-Object nad |
    Sort-Object Count -Descending

Get-IseTacacsActivity -EventType accounting -Username netadmin |
    Export-Csv ./tacacs-accounting.csv -NoTypeInformation

Get-IseSecureClient client-25.example.test -IncludeAll |
    ConvertTo-Json -Depth 10
```

PowerShell validates bounded numeric ranges and enum values before starting the
backend. The backend remains authoritative for production-impact checks, including
`-AllowExpensive`, leading-wildcard searches, complete ERS enumeration, MnT
ActiveList, and the hard 5,000-row Data Connect ceiling.

## Command map

| PowerShell command | ISE operation |
|---|---|
| `Get-IseOverview` | Cached local exporter/deployment summary without another ISE query |
| `Get-IseCollectorStatus` | Cached dataset availability, freshness, age, and last failure |
| `Get-IseEndpointSummary` | Bounded live endpoint identity and current-session workflow |
| `Debug-IseAuthentication` | Resolve an endpoint and correlate its bounded MnT authentication history |
| `Debug-IsePsn` | Cached PSN telemetry with an explicit `-Live` Data Connect refresh |
| `Get-IseNadSummary` | Cached NAD activity/health with an explicit `-Live` ERS refresh |
| `Get-IsePxGridStatus` | pxGrid collector ownership and optional live deployment-service visibility |
| `Test-IseHealth` | PAN/ERS, MnT, and Data Connect health |
| `Get-IseNode` | Deployment nodes |
| `Find-IseEndpoint` | Endpoint inventory and context wildcard search |
| `Get-IseEndpointField` | Live searchable-field schema |
| `Get-IseEndpoint`, `Resolve-IseEndpoint` | Endpoint detail and identifier resolution |
| `Get-IseSession`, `Get-IseActiveSession` | One endpoint session or guarded ActiveList |
| `Get-IseAuthenticationStatus` | Bounded MnT authentication status |
| `Get-IseSecureClient` | Parsed posture and Secure Client attributes |
| `Get-IseNetworkDevice`, `Get-IseProfilerProfile` | ERS configuration inventory |
| `Get-IseTacacsUser`, `Get-IseIdentityGroup`, `Get-IseNetworkDeviceGroup` | ERS identity/group inventory |
| `Get-IseLicense`, `Get-IsePatch`, `Get-IseBackupStatus`, `Get-IseRepository` | Platform state |
| `Get-IseNetworkPolicySet`, `Get-IseAuthorizationProfile` | Network Access policy objects |
| `Get-IseDeviceAdminPolicySet`, `Get-IseTacacsCommandSet`, `Get-IseTacacsShellProfile` | Device Administration objects |
| `Get-IseCertificate` | System and trusted certificates |
| `Get-IseRadiusAuthentication`, `Get-IseRadiusError`, `Get-IseRadiusAccounting` | Bounded RADIUS reports |
| `Get-IseEndpointReport` | Data Connect endpoint inventory |
| `Get-IsePostureAssessment` | Endpoint- or condition-level posture reports |
| `Get-IsePsnMetric` | PSN key-performance metrics |
| `Get-IseTacacsActivity` | TACACS authentication, authorization, or accounting |
| `Get-IseDataConnectTable` | Every table or view visible to the Data Connect account |
| `Get-IseDataConnectColumn` | Column metadata for any table or piped table object |
| `Get-IseDataConnectRow` | Bounded, validated rows from any discovered table or view |
| `Get-IseDataConnectSchema`, `Search-IseDataConnect` | Compatibility names for older scripts |
| `Get-IseSchema` | Backend route and response contracts without an ISE call |
| `Invoke-IseReadOnlyRequest` | Explicit GET-only ERS/OpenAPI/MnT diagnostic |
| `Invoke-IseCommand` | Compatibility dispatcher for an existing `ise-cli` subcommand |

Examples for configuration routing, endpoint field semantics, and API ownership
remain in [ise-cli.md](ise-cli.md). PowerShell parameter names replace the former
GNU-style flags:

```powershell
Get-IseAuthenticationStatus 192.0.2.25 -Seconds 3600 -Limit 50
Get-IseCertificate -Node laba-ise-001
Get-IsePostureAssessment -Conditions -Identifier AA:BB:CC:DD:EE:FF
Invoke-IseReadOnlyRequest -Family ers -Path /config/identitygroup -Parameter @{size=25}
```

## Cached data and live fallbacks

Overview, collector, NAD, and PSN workflows read the local exporter's Prometheus
snapshot first. The snapshot endpoint is fixed to a numeric loopback address,
bounded to 16 MiB and 100,000 samples, and read with a two-second timeout. Every
returned row identifies `exporter_cache`, `live_ers`, `live_mnt`,
`live_dataconnect`, or `live_openapi` as its source. A missing NAD or PSN cache
automatically falls back to one bounded live query; `-Live` forces that refresh
even when matching cached metrics exist.

Endpoint identities are deliberately absent from exporter metrics. Consequently,
`Get-IseEndpointSummary` and `Debug-IseAuthentication` use bounded live ERS/MnT
queries while retaining the same authentication guard and Data Connect pacing as
the exporter. This preserves the exporter's identity-free metrics boundary rather
than creating an unreviewed endpoint cache. If an optional MnT lookup is
unavailable, these compound workflows retain the successful endpoint resolution
and mark only the affected section as `unavailable`.
Valid empty responses remain visible as `no_results` sections.

pxGrid collectors are not part of the supported ISE 3.3 Patch 11 exporter
architecture. `Get-IsePxGridStatus` states that ownership directly; `-Live` checks
deployment-node service assignment through OpenAPI but does not claim pxGrid
connectivity or fabricate a collector health signal.

## Completion

PowerShell provides command and parameter completion from the module metadata.
The module additionally registers bounded context-aware completers for endpoint
identifiers, endpoint search fields/values, ISE nodes and PSNs, NADs, usernames,
and endpoint profiles. These completers use the backend's same completion protocol:

- at most 25 suggestions;
- five-minute backend cache;
- no event-view scans unless expensive completion is explicitly enabled;
- non-blocking Data Connect pacing acquisition;
- failures return no suggestions and never block command entry.

Press Tab repeatedly or use PowerShell's menu completion to see multiple choices.

## Walking every Data Connect table

The three generic cmdlets cover the complete live catalog, including tables that
are not used by an exporter collector:

```powershell
$table = Get-IseDataConnectTable 'AAA_DIAGNOSTICS_VIEW' | Select-Object -First 1
$columns = @($table | Get-IseDataConnectColumn)
$rows = @($table | Get-IseDataConnectRow -Limit 20)

$columns | Where-Object data_type -Like '*CHAR*' | Format-Table
$rows | Get-Member
$rows | Group-Object MESSAGE_CODE | Sort-Object Count -Descending
$rows | Export-Csv ./aaa-diagnostics.csv -NoTypeInformation
```

`-Where` supplies exact bound filters, `-Like` supplies wildcard filters, and
`-Column` selects returned properties. `-OrderBy`, `-Descending`, `-Hours`, and
`-Limit` stay native PowerShell parameters. Tab completion discovers table and
column names without requiring backend syntax.

## Configuration and authorization

The backend reads an explicitly supplied `-ConfigFile`, `ISE_EXPORTER_CONFIG`,
or `/etc/ise-exporter/config.toml`, in that order. Only the two password secret
environment overrides take precedence over TOML.

The installed module is readable by all users, but service credentials and CA
material remain restricted to `root:ise-exporter`. Operators may use their own
TOML file or be added deliberately to the `ise-exporter` group. Data
Connect access is refused when the user cannot participate in the shared pacing
and authentication guards; it never falls back to an uncoordinated query.
