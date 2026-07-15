$ErrorActionPreference = 'Stop'

Import-Module Ise.Cli -ErrorAction Stop

function global:Show-IseCliHelp {
    param([string]$Topic)
    $categories = [ordered]@{
        'overview' = @(
            'Get-IseOverview                       Cached deployment and exporter summary',
            'Get-IseCollectorStatus [PATTERN]      Dataset health, freshness, age, and failures',
            'Test-IseHealth                        Live PAN/ERS, MnT, and Data Connect probes')
        'troubleshooting' = @(
            'Get-IseEndpointSummary ID             Endpoint identity and current session',
            'Debug-IseAuthentication ID            Resolve and correlate recent authentication',
            'Debug-IsePsn PSN [-Live]              Cached PSN telemetry with optional live query',
            'Get-IseNadSummary NAD [-Live]         Cached NAD health with optional ERS refresh',
            'Get-IsePxGridStatus [-Live]           pxGrid ownership and deployment visibility')
        'endpoints' = @(
            'Find-Endpoint PATTERN                 Endpoint/context wildcard search',
            'Get-IseEndpoint ID                    Detailed endpoint object',
            'Resolve-IseEndpoint ID                Explain MAC/IP/name resolution',
            'Get-IseEndpointField [PATTERN]        Searchable live Data Connect fields',
            'Get-IseSession ID                     Current MnT session',
            'Get-IseAuthenticationStatus ID        Recent MnT authentication records',
            'Get-IseSecureClient ID                Secure Client and posture detail')
        'reporting' = @(
            'Get-IseRadiusAuthentication           Bounded RADIUS authentications',
            'Get-IseRadiusError                    Bounded RADIUS failures',
            'Get-IseRadiusAccounting               Bounded accounting records',
            'Get-IsePostureAssessment              Posture endpoint/condition reports',
            'Get-IsePsnMetric                      Live PSN performance report',
            'Get-IseTacacsActivity                 TACACS auth/authz/accounting')
        'configuration' = @(
            'Get-IseNode | Get-IseNetworkDevice | Get-IseProfilerProfile',
            'Get-IseLicense | Get-IsePatch | Get-IseBackupStatus',
            'Get-IseNetworkPolicySet | Get-IseAuthorizationProfile',
            'Get-IseDeviceAdminPolicySet | Get-IseTacacsCommandSet',
            'Get-IseCertificate | Get-IseRepository')
        'advanced' = @(
            'Get-IseSchema [COMMAND]               Routes and response contracts',
            'Get-IseDataConnectSchema [TABLE]      Reporting-view metadata',
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
    Write-Host "`nUse: ise-help CATEGORY, Get-Help COMMAND -Full, or Get-Command -Module Ise.Cli"
}

Set-Alias -Scope Global -Name ise-help -Value Show-IseCliHelp

if (Get-Module -ListAvailable -Name PSReadLine) {
    Import-Module PSReadLine
    Set-PSReadLineOption -EditMode Emacs -HistoryNoDuplicates
    Set-PSReadLineKeyHandler -Key Tab -Function MenuComplete
    Set-PSReadLineKeyHandler -Key UpArrow -Function HistorySearchBackward
    Set-PSReadLineKeyHandler -Key DownArrow -Function HistorySearchForward
}

function global:prompt {
    "ISE PS $($executionContext.SessionState.Path.CurrentLocation)> "
}

$global:ISE_CLI_PROFILE_ACTIVE = $true
Write-Host 'ISE CLI ready. Try Get-IseOverview, Debug-IseAuthentication, or ise-help.'
