$ErrorActionPreference = 'Stop'

Import-Module Ise.Cli -ErrorAction Stop

function global:Show-IseCliHelp {
    param([string]$Topic)
    $categories = [ordered]@{
        'overview' = @(
            'Get-IseOverview                       Cached deployment and exporter summary',
            'Get-IseCollectorStatus [PATTERN]      Dataset health, freshness, age, and failures',
            'Test-IseHealth                        Live PAN/ERS, MnT, and Data Connect probes',
            'Test-IseErs                           ERS login and authorization check',
            'Test-IseOpenApi                       OpenAPI login and authorization check',
            'Test-IseMnt                           MnT login and ActiveCount check')
        'troubleshooting' = @(
            'Get-IseEndpointSummary ID             Endpoint identity and current session',
            'Debug-IseAuthentication ID            Resolve and correlate recent authentication',
            'Debug-IsePsn PSN [-Live]              Cached PSN telemetry with optional live query',
            'Get-IseNadSummary NAD [-Live]         Cached NAD health with optional ERS refresh',
            'Get-IsePxGridStatus [-Live]           pxGrid ownership and deployment visibility')
        'pxgrid' = @(
            'Test-IsePxGrid                        Account and provider-discovery check',
            'Get-IsePxGridService [NAME]           Discover REST/pubsub providers',
            'Get-IsePxGridTopic [SERVICE]          Discover advertised pubsub topics',
            'Get-IsePxGridSession [-IpAddress IP]  Sessions as PowerShell objects',
            'Get-IsePxGridEndpoint [-Limit 100]    Bounded endpoint context snapshot',
            'Get-IsePxGridRadiusFailure [ID]       RADIUS failures',
            'Get-IsePxGridTrustSec -Type TYPE      SGT, ACL, VN, and egress policy data',
            'Get-IsePxGridMdmEndpoint              MDM context',
            'Get-IsePxGridAncPolicy                Read-only ANC policy inventory')
        'endpoints' = @(
            'Find-Endpoint PATTERN                 Endpoint/context wildcard search',
            'Get-IseEndpoint ID                    Detailed endpoint object',
            'Resolve-IseEndpoint ID                Explain MAC/IP/name resolution',
            'Get-IseEndpointField [PATTERN]        Searchable live Data Connect fields',
            'Get-IseSession ID                     Current MnT session',
            'Get-IseAuthenticationStatus ID        Recent MnT authentication records',
            'Get-IseSecureClient ID                Secure Client and posture detail')
        'reporting' = @(
            'Get-IseRadiusAuthentication           Filtered RADIUS authentications',
            'Watch-IseRadiusAuthentication         Live deduplicated RADIUS view',
            'Get-IseRadiusError                    Bounded RADIUS failures',
            'Get-IseRadiusAccounting               Bounded accounting records',
            'Get-IsePostureAssessment              Posture endpoint/condition reports',
            'Get-IsePsnMetric                      Live PSN performance report',
            'Get-IseTacacsActivity                 TACACS auth/authz/accounting',
            'Get-IseAlert                          Recent ISE system alerts',
            'Get-IseSystemDiagnostic               System diagnostic records',
            'Get-IseAaaDiagnostic                  AAA diagnostic records')
        'configuration' = @(
            'Get-IseNode | Get-IseNetworkDevice | Get-IseProfilerProfile',
            'Get-IseLicense | Get-IsePatch | Get-IseBackupStatus',
            'Get-IseNetworkPolicySet | Get-IseAuthorizationProfile',
            'Get-IseDeviceAdminPolicySet | Get-IseTacacsCommandSet',
            'Get-IseCertificate | Get-IseRepository')
        'advanced' = @(
            'Get-IseSchema [COMMAND]               Routes and response contracts',
            'Get-IseDataConnectTable [PATTERN]     List every accessible Oracle table/view',
            'Get-IseDataConnectColumn TABLE        Inspect columns in any table/view',
            'Get-IseDataConnectRow TABLE           Get bounded rows as PowerShell objects',
            'Test-IseDataConnect                   Oracle session and catalog health',
            'Invoke-IseReadOnlyRequest             Explicit bounded GET diagnostic',
            'Get-Command -Module Ise.Cli           Complete command inventory')
    }
    $selected = if ($Topic) {
        $categories.GetEnumerator() | Where-Object Key -Like "$Topic*"
    } else { $categories.GetEnumerator() }
    if (-not $selected) {
        Write-Host "Unknown help topic '$Topic'. Topics: $($categories.Keys -join ', ')"
        return
    }
    Write-Host 'ISE CLI operator commands'
    foreach ($category in $selected) {
        Write-Host "`n$($category.Key.ToUpperInvariant())"
        foreach ($line in $category.Value) { Write-Host "  $line" }
    }
    Write-Host "`nExamples:"
    Write-Host "  Get-IseOverview"
    Write-Host "  Get-IseCollectorStatus '*radius*' | Format-Table"
    Write-Host "  Debug-IseAuthentication 'LAB-PC01' | Group-Object section"
    Write-Host "  Find-Endpoint 'LAB-*' | Select-Object hostname,mac_address,posture_status"
    Write-Host '  Get-IsePxGridSession -IpAddress 10.0.0.10 | Format-List *'
    Write-Host "  Get-IseDataConnectRow RADIUS_AUTHENTICATIONS -Like @{ USERNAME='admin*' } -Limit 50"
    Write-Host "`nUse: ise-help CATEGORY, Get-Help COMMAND -Full, or Get-Command -Module Ise.Cli"
}

Set-Alias -Scope Global -Name ise-help -Value Show-IseCliHelp

if (Get-Module -ListAvailable -Name PSReadLine) {
    Import-Module PSReadLine
    $stateRoot = if ($env:XDG_STATE_HOME) {
        $env:XDG_STATE_HOME
    } else {
        Join-Path $HOME '.local/state'
    }
    $historyDirectory = Join-Path $stateRoot 'ise-cli'
    New-Item -ItemType Directory -Path $historyDirectory -Force | Out-Null
    Set-PSReadLineOption -EditMode Emacs -HistoryNoDuplicates `
        -HistorySearchCursorMovesToEnd -MaximumHistoryCount 4096 `
        -HistorySaveStyle SaveIncrementally `
        -HistorySavePath (Join-Path $historyDirectory 'history.txt') `
        -BellStyle None
    try {
        Set-PSReadLineOption -PredictionSource History -PredictionViewStyle ListView
    } catch {
        # Prediction is unavailable when the host does not support virtual-terminal UI.
    }
    Set-PSReadLineKeyHandler -Key Tab -Function MenuComplete
    Set-PSReadLineKeyHandler -Chord 'Ctrl+Spacebar' -Function MenuComplete
    Set-PSReadLineKeyHandler -Chord 'Ctrl+r' -Function ReverseSearchHistory
    Set-PSReadLineKeyHandler -Key UpArrow -Function HistorySearchBackward
    Set-PSReadLineKeyHandler -Key DownArrow -Function HistorySearchForward
}

function global:prompt {
    $succeeded = $?
    $location = $executionContext.SessionState.Path.CurrentLocation
    $mark = if ($succeeded) { '+' } else { '!' }
    $color = if ($succeeded) { $PSStyle.Foreground.BrightGreen } else { $PSStyle.Foreground.BrightRed }
    "ISE PS $($PSStyle.Foreground.BrightCyan)$location$($PSStyle.Reset) $color[$mark]$($PSStyle.Reset)> "
}

function global:Show-IseCliBanner {
    $version = try { Get-IseCliVersion } catch { 'ise-cli version unavailable' }
    Write-Host ''
    Write-Host '  ISE Operator Console' -ForegroundColor Cyan
    Write-Host "  $version" -ForegroundColor DarkGray
    Write-Host '  Read-only | cached-first | bounded defaults' -ForegroundColor Green
    Write-Host ''
    Write-Host '  Tab       complete commands and live values'
    Write-Host '  Up/Down   search ISE command history'
    Write-Host '  ise-help  command map and examples'
    Write-Host '  Get-Help <command> -Full'
    Write-Host ''
}

$global:FormatEnumerationLimit = 20
$global:ISE_CLI_PROFILE_ACTIVE = $true
Show-IseCliBanner
