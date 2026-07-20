Set-StrictMode -Version Latest

$script:IseCommands = @(
    'overview', 'collector-status', 'endpoint-summary', 'troubleshoot-auth',
    'psn-summary', 'nad-summary', 'pxgrid-status', 'pxgrid-check', 'pxgrid-account',
    'pxgrid-services', 'pxgrid-topics', 'pxgrid-query',
    'health', 'ers-check', 'openapi-check', 'mnt-check',
    'nodes', 'endpoints', 'endpoint-fields', 'endpoint', 'resolve',
    'sessions', 'session', 'auth-status', 'secure-client', 'nads', 'profiles',
    'tacacs-users', 'identity-groups', 'network-device-groups', 'licenses',
    'patches', 'backup-status', 'repositories', 'network-policy-sets',
    'device-admin-policy-sets', 'authorization-profiles', 'tacacs-command-sets',
    'tacacs-shell-profiles', 'certificates', 'radius-auth', 'endpoint-report',
    'radius-errors', 'radius-accounting', 'posture', 'psn-metrics',
    'tacacs-activity', 'dataconnect-schema', 'dataconnect-query',
    'dataconnect-health', 'dataconnect-catalog', 'schema', 'get'
)

function Get-IseBackendCommand {
    [CmdletBinding()]
    param()

    if ($env:ISE_CLI_BACKEND) {
        $explicit = Get-Command -Name $env:ISE_CLI_BACKEND -CommandType Application -ErrorAction SilentlyContinue |
            Select-Object -First 1
        if (-not $explicit -and (Test-Path -LiteralPath $env:ISE_CLI_BACKEND -PathType Leaf)) {
            $explicit = Get-Item -LiteralPath $env:ISE_CLI_BACKEND
        }
        if (-not $explicit) {
            throw "ISE_CLI_BACKEND does not identify an executable: $($env:ISE_CLI_BACKEND)"
        }
        $path = if ($explicit.PSObject.Properties['Source']) { $explicit.Source } else { $explicit.FullName }
        return [pscustomobject]@{ FilePath = $path; Prefix = @() }
    }

    $nativeBackend = '/opt/ise-exporter/.venv/bin/ise-cli-backend'
    if (Test-Path -LiteralPath $nativeBackend -PathType Leaf) {
        return [pscustomobject]@{ FilePath = $nativeBackend; Prefix = @() }
    }

    $installed = Get-Command -Name 'ise-cli-backend' -CommandType Application -ErrorAction SilentlyContinue |
        Select-Object -First 1
    if ($installed) {
        return [pscustomobject]@{ FilePath = $installed.Source; Prefix = @() }
    }

    $applicationRoot = [System.IO.Path]::GetFullPath((Join-Path $PSScriptRoot '../..'))
    $venvBackend = Join-Path $applicationRoot '.venv/bin/ise-cli-backend'
    if (Test-Path -LiteralPath $venvBackend -PathType Leaf) {
        return [pscustomobject]@{ FilePath = $venvBackend; Prefix = @() }
    }

    if (Test-Path -LiteralPath (Join-Path $applicationRoot 'ise_exporter/cli.py')) {
        $python = Get-Command -Name 'python3' -CommandType Application -ErrorAction SilentlyContinue
        if ($python) {
            return [pscustomobject]@{
                FilePath = $python.Source
                Prefix = @('-m', 'ise_exporter.cli')
                WorkingDirectory = $applicationRoot
            }
        }
    }

    throw 'ise-cli-backend was not found. Install ise-exporter or set ISE_CLI_BACKEND.'
}

function Invoke-IseBackendProcess {
    [CmdletBinding()]
    param([Parameter(Mandatory)][string[]]$ArgumentList)

    $backend = Get-IseBackendCommand
    $start = [System.Diagnostics.ProcessStartInfo]::new()
    $start.FileName = $backend.FilePath
    $start.UseShellExecute = $false
    $start.RedirectStandardOutput = $true
    $start.RedirectStandardError = $true
    $start.CreateNoWindow = $true
    if ($backend.PSObject.Properties['WorkingDirectory']) {
        $start.WorkingDirectory = $backend.WorkingDirectory
    }
    foreach ($argument in @($backend.Prefix) + $ArgumentList) {
        [void]$start.ArgumentList.Add([string]$argument)
    }

    $process = [System.Diagnostics.Process]::new()
    $process.StartInfo = $start
    if (-not $process.Start()) {
        throw 'Could not start the ISE CLI backend.'
    }
    $stdoutTask = $process.StandardOutput.ReadToEndAsync()
    $stderrTask = $process.StandardError.ReadToEndAsync()
    $process.WaitForExit()
    $stdout = $stdoutTask.GetAwaiter().GetResult()
    $stderr = $stderrTask.GetAwaiter().GetResult().Trim()
    if ($process.ExitCode -ne 0) {
        if (-not $stderr) { $stderr = "ISE CLI backend exited with status $($process.ExitCode)." }
        throw [System.InvalidOperationException]::new($stderr)
    }
    return $stdout
}

function ConvertFrom-IseBackendJson {
    [CmdletBinding()]
    param([AllowEmptyString()][string]$Json, [switch]$QuietEmpty)

    if ([string]::IsNullOrWhiteSpace($Json)) { return }
    if ($Json.Trim() -eq '[]') {
        if (-not $QuietEmpty) { Write-Host 'No results.' -ForegroundColor DarkGray }
        return
    }
    try {
        $value = $Json | ConvertFrom-Json -Depth 100
    }
    catch {
        throw [System.InvalidOperationException]::new(
            'ISE CLI backend returned invalid JSON.', $_.Exception)
    }
    if ($value -is [System.Array]) {
        $value | Write-Output
    }
    else {
        Write-Output $value
    }
}

function Invoke-IseBackend {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)][ValidateSet(
            'overview', 'collector-status', 'endpoint-summary', 'troubleshoot-auth',
            'psn-summary', 'nad-summary', 'pxgrid-status', 'pxgrid-check', 'pxgrid-account',
            'pxgrid-services', 'pxgrid-topics', 'pxgrid-query',
            'health', 'ers-check', 'openapi-check', 'mnt-check',
            'nodes', 'endpoints', 'endpoint-fields', 'endpoint', 'resolve',
            'sessions', 'session', 'auth-status', 'secure-client', 'nads', 'profiles',
            'tacacs-users', 'identity-groups', 'network-device-groups', 'licenses',
            'patches', 'backup-status', 'repositories', 'network-policy-sets',
            'device-admin-policy-sets', 'authorization-profiles', 'tacacs-command-sets',
            'tacacs-shell-profiles', 'certificates', 'radius-auth', 'endpoint-report',
            'radius-errors', 'radius-accounting', 'posture', 'psn-metrics',
            'tacacs-activity', 'dataconnect-schema', 'dataconnect-query',
            'dataconnect-health', 'dataconnect-catalog', 'schema', 'get')]
        [string]$Command,
        [AllowEmptyCollection()][AllowEmptyString()][string[]]$ArgumentList = @(),
        [string]$ConfigFile,
        [switch]$QuietEmpty
    )

    $backendArguments = @()
    if ($ConfigFile) { $backendArguments += @('--config', $ConfigFile) }
    $backendArguments += $Command
    $backendArguments += @($ArgumentList | Where-Object { -not [string]::IsNullOrEmpty($_) })
    if ($backendArguments -contains '--help' -or $backendArguments -contains '-h') {
        return Invoke-IseBackendProcess -ArgumentList $backendArguments
    }
    $backendArguments += @('--output', 'json')
    ConvertFrom-IseBackendJson `
        -Json (Invoke-IseBackendProcess -ArgumentList $backendArguments) `
        -QuietEmpty:$QuietEmpty
}

function Invoke-IseCommand {
    <#
.SYNOPSIS
Runs any bounded legacy command and returns PowerShell objects.
#>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory, Position = 0)]
        [ValidateSet(
            'overview', 'collector-status', 'endpoint-summary', 'troubleshoot-auth',
            'psn-summary', 'nad-summary', 'pxgrid-status', 'pxgrid-check', 'pxgrid-account',
            'pxgrid-services', 'pxgrid-topics', 'pxgrid-query',
            'health', 'ers-check', 'openapi-check', 'mnt-check',
            'nodes', 'endpoints', 'endpoint-fields', 'endpoint', 'resolve',
            'sessions', 'session', 'auth-status', 'secure-client', 'nads', 'profiles',
            'tacacs-users', 'identity-groups', 'network-device-groups', 'licenses',
            'patches', 'backup-status', 'repositories', 'network-policy-sets',
            'device-admin-policy-sets', 'authorization-profiles', 'tacacs-command-sets',
            'tacacs-shell-profiles', 'certificates', 'radius-auth', 'endpoint-report',
            'radius-errors', 'radius-accounting', 'posture', 'psn-metrics',
            'tacacs-activity', 'dataconnect-schema', 'dataconnect-query',
            'dataconnect-health', 'dataconnect-catalog', 'schema', 'get')]
        [string]$Name,
        [Parameter(Position = 1, ValueFromRemainingArguments)]
        [string[]]$ArgumentList = @(),
        [string]$ConfigFile,
        [switch]$Raw
    )
    if ($Raw) {
        $backendArguments = @()
        if ($ConfigFile) { $backendArguments += @('--config', $ConfigFile) }
        $backendArguments += $Name
        $backendArguments += $ArgumentList
        return Invoke-IseBackendProcess -ArgumentList $backendArguments
    }
    Invoke-IseBackend -Command $Name -ArgumentList $ArgumentList -ConfigFile $ConfigFile
}

function Get-IseCliVersion {
    <#
.SYNOPSIS
Returns the backend and exact supported ISE release version.
#>
    [CmdletBinding()]
    param()
    (Invoke-IseBackendProcess -ArgumentList @('--version')).Trim()
}

function Add-IseSwitchArgument {
    param([System.Collections.Generic.List[string]]$Arguments, [switch]$Value, [string]$Name)
    if ($Value) { [void]$Arguments.Add($Name) }
}

function Invoke-IseInventory {
    param(
        [Parameter(Mandatory)][string]$Command,
        [int]$Limit = 100,
        [string[]]$Filter = @(),
        [switch]$All,
        [switch]$AllowExpensive,
        [string]$ConfigFile
    )
    $arguments = [System.Collections.Generic.List[string]]::new()
    [void]$arguments.Add('--limit'); [void]$arguments.Add([string]$Limit)
    foreach ($item in $Filter) {
        [void]$arguments.Add('--filter'); [void]$arguments.Add($item)
    }
    Add-IseSwitchArgument -Arguments $arguments -Value:$All -Name '--all'
    Add-IseSwitchArgument -Arguments $arguments -Value:$AllowExpensive -Name '--allow-expensive'
    Invoke-IseBackend -Command $Command -ArgumentList $arguments.ToArray() -ConfigFile $ConfigFile
}

function Test-IseHealth { [CmdletBinding()] param([string]$ConfigFile) Invoke-IseBackend -Command health -ConfigFile $ConfigFile }
function Test-IseErs {
    <#
.SYNOPSIS
Checks ERS reachability, credentials, and endpoint authorization.
#>
    [CmdletBinding()]
    param([string]$ConfigFile)
    Invoke-IseBackend -Command ers-check -ConfigFile $ConfigFile
}
function Test-IseOpenApi {
    <#
.SYNOPSIS
Checks ISE OpenAPI reachability, credentials, and deployment-read authorization.
#>
    [CmdletBinding()]
    param([string]$ConfigFile)
    Invoke-IseBackend -Command openapi-check -ConfigFile $ConfigFile
}
function Test-IseMnt {
    <#
.SYNOPSIS
Checks the MnT API with a bounded ActiveCount request.
#>
    [CmdletBinding()]
    param([string]$ConfigFile)
    Invoke-IseBackend -Command mnt-check -ConfigFile $ConfigFile
}
function Get-IseNode {
    [CmdletBinding()]
    param([ValidateRange(1,5000)][int]$Limit=50,[switch]$AllowExpensive,[string]$ConfigFile)
    $a=New-IseReportArguments -Limit $Limit -AllowExpensive:$AllowExpensive
    Invoke-IseBackend -Command nodes -ArgumentList $a.ToArray() -ConfigFile $ConfigFile
}
function Get-IseOverview { [CmdletBinding()] param([string]$ConfigFile) Invoke-IseBackend -Command overview -ConfigFile $ConfigFile }
function Get-IseCollectorStatus {
    [CmdletBinding()]
    param([Parameter(Position=0)][string]$Pattern,[string]$ConfigFile)
    $arguments = if ($Pattern) { @($Pattern) } else { @() }
    Invoke-IseBackend -Command collector-status -ArgumentList $arguments -ConfigFile $ConfigFile
}
function Get-IseEndpointSummary {
    [CmdletBinding()]
    param([Parameter(Mandatory,Position=0,ValueFromPipeline)][string]$Identifier,[switch]$AllowActiveListScan,[string]$ConfigFile)
    process {
        $a=[System.Collections.Generic.List[string]]::new(); [void]$a.Add($Identifier)
        Add-IseSwitchArgument -Arguments $a -Value:$AllowActiveListScan -Name '--allow-active-list-scan'
        Invoke-IseBackend -Command endpoint-summary -ArgumentList $a.ToArray() -ConfigFile $ConfigFile
    }
}
function Debug-IseAuthentication {
    [CmdletBinding()]
    param([Parameter(Mandatory,Position=0,ValueFromPipeline)][string]$Identifier,[ValidateRange(1,86400)][int]$Seconds=3600,[ValidateRange(1,100)][int]$Limit=20,[switch]$AllowActiveListScan,[string]$ConfigFile)
    process {
        $a=[System.Collections.Generic.List[string]]::new(); [void]$a.Add($Identifier)
        [void]$a.Add('--seconds'); [void]$a.Add([string]$Seconds); [void]$a.Add('--limit'); [void]$a.Add([string]$Limit)
        Add-IseSwitchArgument -Arguments $a -Value:$AllowActiveListScan -Name '--allow-active-list-scan'
        Invoke-IseBackend -Command troubleshoot-auth -ArgumentList $a.ToArray() -ConfigFile $ConfigFile
    }
}
function Debug-IsePsn {
    [CmdletBinding()]
    param([Parameter(Mandatory,Position=0)][string]$Psn,[ValidateRange(1,5000)][int]$Limit=25,[switch]$Live,[string]$ConfigFile)
    $a=[System.Collections.Generic.List[string]]::new(); [void]$a.Add($Psn); [void]$a.Add('--limit'); [void]$a.Add([string]$Limit)
    Add-IseSwitchArgument -Arguments $a -Value:$Live -Name '--live'
    Invoke-IseBackend -Command psn-summary -ArgumentList $a.ToArray() -ConfigFile $ConfigFile
}
function Get-IseNadSummary {
    [CmdletBinding()]
    param([Parameter(Mandatory,Position=0)][string]$Nad,[switch]$Live,[string]$ConfigFile)
    $a=[System.Collections.Generic.List[string]]::new(); [void]$a.Add($Nad)
    Add-IseSwitchArgument -Arguments $a -Value:$Live -Name '--live'
    Invoke-IseBackend -Command nad-summary -ArgumentList $a.ToArray() -ConfigFile $ConfigFile
}
function Get-IsePxGridStatus {
    [CmdletBinding()]
    param([switch]$Live,[string]$ConfigFile)
    $a=[System.Collections.Generic.List[string]]::new(); Add-IseSwitchArgument -Arguments $a -Value:$Live -Name '--live'
    Invoke-IseBackend -Command pxgrid-status -ArgumentList $a.ToArray() -ConfigFile $ConfigFile
}

function Test-IsePxGrid {
    <#
.SYNOPSIS
Checks pxGrid 2.0 account activation and service-provider discovery.
#>
    [CmdletBinding()]
    param([string]$ConfigFile)
    Invoke-IseBackend -Command pxgrid-check -ConfigFile $ConfigFile
}

function Get-IsePxGridService {
    <#
.SYNOPSIS
Discovers pxGrid 2.0 service providers and their properties.
#>
    [CmdletBinding()]
    param([Parameter(Position=0)][string]$Name,[string]$ConfigFile)
    $a=[System.Collections.Generic.List[string]]::new()
    if ($Name) { [void]$a.Add('--name'); [void]$a.Add($Name) }
    Invoke-IseBackend -Command pxgrid-services -ArgumentList $a.ToArray() -ConfigFile $ConfigFile
}

function Get-IsePxGridTopic {
    <#
.SYNOPSIS
Lists pubsub topic names advertised by pxGrid 2.0 services.
#>
    [CmdletBinding()]
    param([Parameter(Position=0)][string]$Service,[string]$ConfigFile)
    $a=[System.Collections.Generic.List[string]]::new()
    if ($Service) { [void]$a.Add('--service'); [void]$a.Add($Service) }
    Invoke-IseBackend -Command pxgrid-topics -ArgumentList $a.ToArray() -ConfigFile $ConfigFile
}

function Invoke-IsePxGridQuery {
    <#
    .SYNOPSIS Runs an allowlisted read-only pxGrid 2.0 operation and returns objects.
    .DESCRIPTION Write operations such as ANC apply/clear and account creation are intentionally unavailable.
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory,Position=0)][ValidateSet(
            'sessions','session-by-ip','session-by-mac','user-groups','user-group-by-username',
            'system-health','system-performance','trustsec-security-groups','trustsec-acls',
            'trustsec-virtual-networks','trustsec-egress-policies','trustsec-egress-matrices',
            'endpoints','sxp-bindings','radius-failures','radius-failure-by-id','mdm-endpoints',
            'mdm-endpoint-by-mac','mdm-endpoints-by-type','mdm-endpoints-by-os',
            'profiler-profiles','anc-policies','anc-policy-by-name','anc-endpoints',
            'anc-endpoint-by-mac','anc-endpoint-policies')][string]$Operation,
        [hashtable]$Body=@{},
        [ValidateRange(1,5000)][int]$Limit=100,
        [switch]$AllowExpensive,
        [string]$ConfigFile
    )
    $a=[System.Collections.Generic.List[string]]::new()
    [void]$a.Add($Operation)
    [void]$a.Add('--body-json'); [void]$a.Add(($Body | ConvertTo-Json -Compress -Depth 20))
    [void]$a.Add('--limit'); [void]$a.Add([string]$Limit)
    Add-IseSwitchArgument -Arguments $a -Value:$AllowExpensive -Name '--allow-expensive'
    Invoke-IseBackend -Command pxgrid-query -ArgumentList $a.ToArray() -ConfigFile $ConfigFile
}

function Get-IsePxGridSession {
    <#
.SYNOPSIS
Gets bounded pxGrid sessions, optionally by IP address or MAC address.
#>
    [CmdletBinding(DefaultParameterSetName='All')]
    param(
        [Parameter(Mandatory,ParameterSetName='Ip')][ipaddress]$IpAddress,
        [Parameter(Mandatory,ParameterSetName='Mac')][string]$MacAddress,
        [ValidateRange(1,5000)][int]$Limit=100,[switch]$AllowExpensive,[string]$ConfigFile)
    $op='sessions'; $body=@{}
    if ($PSCmdlet.ParameterSetName -eq 'Ip') { $op='session-by-ip'; $body.ipAddress=[string]$IpAddress }
    if ($PSCmdlet.ParameterSetName -eq 'Mac') { $op='session-by-mac'; $body.macAddress=$MacAddress }
    Invoke-IsePxGridQuery $op -Body $body -Limit $Limit -AllowExpensive:$AllowExpensive -ConfigFile $ConfigFile
}

function Get-IsePxGridUserGroup {
    <#
.SYNOPSIS
Gets pxGrid user groups or the group for one username.
#>
    [CmdletBinding()]
    param([Parameter(Position=0)][string]$Username,[ValidateRange(1,5000)][int]$Limit=100,[switch]$AllowExpensive,[string]$ConfigFile)
    $op=if($Username){'user-group-by-username'}else{'user-groups'}; $body=@{}
    if($Username){$body.userName=$Username}
    Invoke-IsePxGridQuery $op -Body $body -Limit $Limit -AllowExpensive:$AllowExpensive -ConfigFile $ConfigFile
}

function Get-IsePxGridSystemHealth { <#
.SYNOPSIS
Gets pxGrid system health objects.
#> [CmdletBinding()] param([ValidateRange(1,5000)][int]$Limit=100,[switch]$AllowExpensive,[string]$ConfigFile) Invoke-IsePxGridQuery system-health -Limit $Limit -AllowExpensive:$AllowExpensive -ConfigFile $ConfigFile }
function Get-IsePxGridSystemPerformance { <#
.SYNOPSIS
Gets pxGrid system performance objects.
#> [CmdletBinding()] param([ValidateRange(1,5000)][int]$Limit=100,[switch]$AllowExpensive,[string]$ConfigFile) Invoke-IsePxGridQuery system-performance -Limit $Limit -AllowExpensive:$AllowExpensive -ConfigFile $ConfigFile }

function Get-IsePxGridTrustSec {
    <#
.SYNOPSIS
Gets one class of TrustSec configuration through pxGrid 2.0.
#>
    [CmdletBinding()]
    param([ValidateSet('SecurityGroup','Acl','VirtualNetwork','EgressPolicy','EgressMatrix')][string]$Type='SecurityGroup',[ValidateRange(1,5000)][int]$Limit=100,[switch]$AllowExpensive,[string]$ConfigFile)
    $ops=@{SecurityGroup='trustsec-security-groups';Acl='trustsec-acls';VirtualNetwork='trustsec-virtual-networks';EgressPolicy='trustsec-egress-policies';EgressMatrix='trustsec-egress-matrices'}
    Invoke-IsePxGridQuery $ops[$Type] -Limit $Limit -AllowExpensive:$AllowExpensive -ConfigFile $ConfigFile
}

function Get-IsePxGridEndpoint {
    <#
.SYNOPSIS
Gets a bounded pxGrid endpoint-context snapshot.
#>
    [CmdletBinding()]
    param([datetime]$Since=[datetime]'1970-01-01T00:00:00Z',[ValidateRange(1,5000)][int]$Limit=100,[switch]$AllowExpensive,[string]$ConfigFile)
    $body=@{startCreateTimestamp=$Since.ToUniversalTime().ToString('yyyy-MM-ddTHH:mm:ss.fffZ');startIndex=0;count=$Limit;order='ASC'}
    Invoke-IsePxGridQuery endpoints -Body $body -Limit $Limit -AllowExpensive:$AllowExpensive -ConfigFile $ConfigFile
}

function Get-IsePxGridSxpBinding { <#
.SYNOPSIS
Gets bounded SXP bindings through pxGrid 2.0.
#> [CmdletBinding()] param([ValidateRange(1,5000)][int]$Limit=100,[switch]$AllowExpensive,[string]$ConfigFile) Invoke-IsePxGridQuery sxp-bindings -Limit $Limit -AllowExpensive:$AllowExpensive -ConfigFile $ConfigFile }

function Get-IsePxGridRadiusFailure {
    <#
.SYNOPSIS
Gets recent pxGrid RADIUS failures or one failure by ID.
#>
    [CmdletBinding()]
    param([Parameter(Position=0)][string]$Id,[ValidateRange(1,5000)][int]$Limit=100,[switch]$AllowExpensive,[string]$ConfigFile)
    $op=if($Id){'radius-failure-by-id'}else{'radius-failures'}; $body=@{}; if($Id){$body.id=$Id}
    Invoke-IsePxGridQuery $op -Body $body -Limit $Limit -AllowExpensive:$AllowExpensive -ConfigFile $ConfigFile
}

function Get-IsePxGridMdmEndpoint {
    <#
.SYNOPSIS
Gets MDM endpoint context, optionally filtered by MAC, device type, or OS type.
#>
    [CmdletBinding(DefaultParameterSetName='All')]
    param([Parameter(Mandatory,ParameterSetName='Mac')][string]$MacAddress,[Parameter(Mandatory,ParameterSetName='Type')][string]$Type,[Parameter(Mandatory,ParameterSetName='Os')][string]$OsType,[ValidateRange(1,5000)][int]$Limit=100,[switch]$AllowExpensive,[string]$ConfigFile)
    $op='mdm-endpoints';$body=@{}
    if($PSCmdlet.ParameterSetName -eq 'Mac'){$op='mdm-endpoint-by-mac';$body.macAddress=$MacAddress}
    if($PSCmdlet.ParameterSetName -eq 'Type'){$op='mdm-endpoints-by-type';$body.type=$Type}
    if($PSCmdlet.ParameterSetName -eq 'Os'){$op='mdm-endpoints-by-os';$body.osType=$OsType}
    Invoke-IsePxGridQuery $op -Body $body -Limit $Limit -AllowExpensive:$AllowExpensive -ConfigFile $ConfigFile
}

function Get-IsePxGridProfilerProfile { <#
.SYNOPSIS
Gets pxGrid profiler policy-tree objects.
#> [CmdletBinding()] param([ValidateRange(1,5000)][int]$Limit=100,[switch]$AllowExpensive,[string]$ConfigFile) Invoke-IsePxGridQuery profiler-profiles -Limit $Limit -AllowExpensive:$AllowExpensive -ConfigFile $ConfigFile }

function Get-IsePxGridAncPolicy {
    <#
.SYNOPSIS
Gets ANC policies through the read-only pxGrid surface.
#>
    [CmdletBinding()] param([Parameter(Position=0)][string]$Name,[ValidateRange(1,5000)][int]$Limit=100,[switch]$AllowExpensive,[string]$ConfigFile)
    $op=if($Name){'anc-policy-by-name'}else{'anc-policies'};$body=@{};if($Name){$body.name=$Name}
    Invoke-IsePxGridQuery $op -Body $body -Limit $Limit -AllowExpensive:$AllowExpensive -ConfigFile $ConfigFile
}

function Get-IsePxGridAncEndpoint {
    <#
.SYNOPSIS
Gets ANC endpoints, optionally by MAC address.
#>
    [CmdletBinding()] param([Parameter(Position=0)][string]$MacAddress,[ValidateRange(1,5000)][int]$Limit=100,[switch]$AllowExpensive,[string]$ConfigFile)
    $op=if($MacAddress){'anc-endpoint-by-mac'}else{'anc-endpoints'};$body=@{};if($MacAddress){$body.macAddress=$MacAddress}
    Invoke-IsePxGridQuery $op -Body $body -Limit $Limit -AllowExpensive:$AllowExpensive -ConfigFile $ConfigFile
}

function Get-IsePxGridAncEndpointPolicy { <#
.SYNOPSIS
Gets ANC endpoint-to-policy assignments.
#> [CmdletBinding()] param([ValidateRange(1,5000)][int]$Limit=100,[switch]$AllowExpensive,[string]$ConfigFile) Invoke-IsePxGridQuery anc-endpoint-policies -Limit $Limit -AllowExpensive:$AllowExpensive -ConfigFile $ConfigFile }

function Find-IseEndpoint {
    [CmdletBinding()]
    param(
        [Parameter(Position = 0)][string[]]$Criteria = @(),
        [ValidateRange(1, 5000)][int]$Limit = 100,
        [string[]]$Filter = @(),
        [switch]$All,
        [switch]$AllowExpensive,
        [string]$ConfigFile
    )
    $arguments = [System.Collections.Generic.List[string]]::new()
    foreach ($criterion in $Criteria) { [void]$arguments.Add($criterion) }
    [void]$arguments.Add('--limit'); [void]$arguments.Add([string]$Limit)
    foreach ($item in $Filter) {
        [void]$arguments.Add('--filter'); [void]$arguments.Add($item)
    }
    Add-IseSwitchArgument -Arguments $arguments -Value:$All -Name '--all'
    Add-IseSwitchArgument -Arguments $arguments -Value:$AllowExpensive -Name '--allow-expensive'
    Invoke-IseBackend -Command endpoints -ArgumentList $arguments.ToArray() -ConfigFile $ConfigFile
}

function Get-IseEndpointField {
    [CmdletBinding()]
    param([Parameter(Position = 0)][string]$Pattern, [string]$ConfigFile)
    $arguments = if ($Pattern) { @($Pattern) } else { @() }
    Invoke-IseBackend -Command endpoint-fields -ArgumentList $arguments -ConfigFile $ConfigFile
}

function Get-IseEndpoint {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory, Position = 0, ValueFromPipeline)][string]$Identifier,
        [switch]$Id, [switch]$IncludeSession, [switch]$AllowActiveListScan,
        [string]$ConfigFile
    )
    process {
        $arguments = [System.Collections.Generic.List[string]]::new()
        [void]$arguments.Add($Identifier)
        Add-IseSwitchArgument -Arguments $arguments -Value:$Id -Name '--id'
        Add-IseSwitchArgument -Arguments $arguments -Value:$IncludeSession -Name '--include-session'
        Add-IseSwitchArgument -Arguments $arguments -Value:$AllowActiveListScan -Name '--allow-active-list-scan'
        Invoke-IseBackend -Command endpoint -ArgumentList $arguments.ToArray() -ConfigFile $ConfigFile
    }
}

function Resolve-IseEndpoint {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory, Position = 0, ValueFromPipeline)][string]$Identifier,
        [switch]$Id, [switch]$AllowActiveListScan, [string]$ConfigFile
    )
    process {
        $arguments = [System.Collections.Generic.List[string]]::new()
        [void]$arguments.Add($Identifier)
        Add-IseSwitchArgument -Arguments $arguments -Value:$Id -Name '--id'
        Add-IseSwitchArgument -Arguments $arguments -Value:$AllowActiveListScan -Name '--allow-active-list-scan'
        Invoke-IseBackend -Command resolve -ArgumentList $arguments.ToArray() -ConfigFile $ConfigFile
    }
}

function Get-IseSession {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory, Position = 0, ValueFromPipeline)][string]$Identifier,
        [switch]$AllowActiveListScan, [string]$ConfigFile
    )
    process {
        $arguments = [System.Collections.Generic.List[string]]::new()
        [void]$arguments.Add($Identifier)
        Add-IseSwitchArgument -Arguments $arguments -Value:$AllowActiveListScan -Name '--allow-active-list-scan'
        Invoke-IseBackend -Command session -ArgumentList $arguments.ToArray() -ConfigFile $ConfigFile
    }
}

function Get-IseActiveSession {
    [CmdletBinding()]
    param(
        [ValidateRange(1, 5000)][int]$Limit = 100,
        [switch]$All,
        [switch]$AllowExpensive,
        [string]$ConfigFile
    )
    $arguments = [System.Collections.Generic.List[string]]::new()
    [void]$arguments.Add('--limit'); [void]$arguments.Add([string]$Limit)
    Add-IseSwitchArgument -Arguments $arguments -Value:$All -Name '--all'
    Add-IseSwitchArgument -Arguments $arguments -Value:$AllowExpensive -Name '--allow-expensive'
    Invoke-IseBackend -Command sessions -ArgumentList $arguments.ToArray() -ConfigFile $ConfigFile
}

function Get-IseAuthenticationStatus {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory, Position = 0, ValueFromPipeline)][string]$Identifier,
        [ValidateRange(1, 86400)][int]$Seconds = 600,
        [ValidateRange(1, 1000)][int]$Limit = 20,
        [switch]$AllowExpensive, [switch]$AllowActiveListScan,
        [string]$ConfigFile
    )
    process {
        $arguments = [System.Collections.Generic.List[string]]::new()
        [void]$arguments.Add($Identifier)
        [void]$arguments.Add('--seconds'); [void]$arguments.Add([string]$Seconds)
        [void]$arguments.Add('--limit'); [void]$arguments.Add([string]$Limit)
        Add-IseSwitchArgument -Arguments $arguments -Value:$AllowExpensive -Name '--allow-expensive'
        Add-IseSwitchArgument -Arguments $arguments -Value:$AllowActiveListScan -Name '--allow-active-list-scan'
        Invoke-IseBackend -Command auth-status -ArgumentList $arguments.ToArray() -ConfigFile $ConfigFile
    }
}

function Get-IseSecureClient {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory, Position = 0, ValueFromPipeline)][string]$Identifier,
        [switch]$IncludeAll, [switch]$AllowActiveListScan, [string]$ConfigFile
    )
    process {
        $arguments = [System.Collections.Generic.List[string]]::new()
        [void]$arguments.Add($Identifier)
        Add-IseSwitchArgument -Arguments $arguments -Value:$IncludeAll -Name '--include-all'
        Add-IseSwitchArgument -Arguments $arguments -Value:$AllowActiveListScan -Name '--allow-active-list-scan'
        Invoke-IseBackend -Command secure-client -ArgumentList $arguments.ToArray() -ConfigFile $ConfigFile
    }
}

function Get-IseNetworkDevice { [CmdletBinding()] param([ValidateRange(1,5000)][int]$Limit=100,[string[]]$Filter=@(),[switch]$All,[switch]$AllowExpensive,[string]$ConfigFile) Invoke-IseInventory -Command nads -Limit $Limit -Filter $Filter -All:$All -AllowExpensive:$AllowExpensive -ConfigFile $ConfigFile }
function Get-IseProfilerProfile { [CmdletBinding()] param([ValidateRange(1,5000)][int]$Limit=100,[string[]]$Filter=@(),[switch]$All,[switch]$AllowExpensive,[string]$ConfigFile) Invoke-IseInventory -Command profiles -Limit $Limit -Filter $Filter -All:$All -AllowExpensive:$AllowExpensive -ConfigFile $ConfigFile }
function Get-IseTacacsUser { [CmdletBinding()] param([ValidateRange(1,5000)][int]$Limit=100,[string[]]$Filter=@(),[switch]$All,[switch]$AllowExpensive,[string]$ConfigFile) Invoke-IseInventory -Command tacacs-users -Limit $Limit -Filter $Filter -All:$All -AllowExpensive:$AllowExpensive -ConfigFile $ConfigFile }
function Get-IseIdentityGroup { [CmdletBinding()] param([ValidateRange(1,5000)][int]$Limit=100,[string[]]$Filter=@(),[switch]$All,[switch]$AllowExpensive,[string]$ConfigFile) Invoke-IseInventory -Command identity-groups -Limit $Limit -Filter $Filter -All:$All -AllowExpensive:$AllowExpensive -ConfigFile $ConfigFile }
function Get-IseNetworkDeviceGroup { [CmdletBinding()] param([ValidateRange(1,5000)][int]$Limit=100,[string[]]$Filter=@(),[switch]$All,[switch]$AllowExpensive,[string]$ConfigFile) Invoke-IseInventory -Command network-device-groups -Limit $Limit -Filter $Filter -All:$All -AllowExpensive:$AllowExpensive -ConfigFile $ConfigFile }

function Invoke-IseBoundedOpenApiInventory {
    param([Parameter(Mandatory)][string]$Command,[int]$Limit=100,[switch]$AllowExpensive,[string]$ConfigFile)
    $a=New-IseReportArguments -Limit $Limit -AllowExpensive:$AllowExpensive
    Invoke-IseBackend -Command $Command -ArgumentList $a.ToArray() -ConfigFile $ConfigFile
}

function Get-IseLicense { [CmdletBinding()] param([string]$ConfigFile) Invoke-IseBackend -Command licenses -ConfigFile $ConfigFile }
function Get-IsePatch { [CmdletBinding()] param([ValidateRange(1,5000)][int]$Limit=100,[switch]$AllowExpensive,[string]$ConfigFile) Invoke-IseBoundedOpenApiInventory -Command patches -Limit $Limit -AllowExpensive:$AllowExpensive -ConfigFile $ConfigFile }
function Get-IseBackupStatus { [CmdletBinding()] param([string]$ConfigFile) Invoke-IseBackend -Command backup-status -ConfigFile $ConfigFile }
function Get-IseRepository { [CmdletBinding()] param([ValidateRange(1,5000)][int]$Limit=100,[switch]$AllowExpensive,[string]$ConfigFile) Invoke-IseBoundedOpenApiInventory -Command repositories -Limit $Limit -AllowExpensive:$AllowExpensive -ConfigFile $ConfigFile }
function Get-IseNetworkPolicySet { [CmdletBinding()] param([ValidateRange(1,5000)][int]$Limit=100,[switch]$AllowExpensive,[string]$ConfigFile) Invoke-IseBoundedOpenApiInventory -Command network-policy-sets -Limit $Limit -AllowExpensive:$AllowExpensive -ConfigFile $ConfigFile }
function Get-IseDeviceAdminPolicySet { [CmdletBinding()] param([ValidateRange(1,5000)][int]$Limit=100,[switch]$AllowExpensive,[string]$ConfigFile) Invoke-IseBoundedOpenApiInventory -Command device-admin-policy-sets -Limit $Limit -AllowExpensive:$AllowExpensive -ConfigFile $ConfigFile }
function Get-IseAuthorizationProfile { [CmdletBinding()] param([ValidateRange(1,5000)][int]$Limit=100,[switch]$AllowExpensive,[string]$ConfigFile) Invoke-IseBoundedOpenApiInventory -Command authorization-profiles -Limit $Limit -AllowExpensive:$AllowExpensive -ConfigFile $ConfigFile }
function Get-IseTacacsCommandSet { [CmdletBinding()] param([ValidateRange(1,5000)][int]$Limit=100,[switch]$AllowExpensive,[string]$ConfigFile) Invoke-IseBoundedOpenApiInventory -Command tacacs-command-sets -Limit $Limit -AllowExpensive:$AllowExpensive -ConfigFile $ConfigFile }
function Get-IseTacacsShellProfile { [CmdletBinding()] param([ValidateRange(1,5000)][int]$Limit=100,[switch]$AllowExpensive,[string]$ConfigFile) Invoke-IseBoundedOpenApiInventory -Command tacacs-shell-profiles -Limit $Limit -AllowExpensive:$AllowExpensive -ConfigFile $ConfigFile }

function Get-IseCertificate {
    [CmdletBinding()]
    param([string]$Node, [switch]$TrustedOnly, [switch]$SystemOnly,
          [ValidateRange(1,5000)][int]$Limit=100,[switch]$AllowExpensive,
          [string]$ConfigFile)
    $arguments = [System.Collections.Generic.List[string]]::new()
    if ($Node) { [void]$arguments.Add('--node'); [void]$arguments.Add($Node) }
    [void]$arguments.Add('--limit'); [void]$arguments.Add([string]$Limit)
    Add-IseSwitchArgument -Arguments $arguments -Value:$TrustedOnly -Name '--trusted-only'
    Add-IseSwitchArgument -Arguments $arguments -Value:$SystemOnly -Name '--system-only'
    Add-IseSwitchArgument -Arguments $arguments -Value:$AllowExpensive -Name '--allow-expensive'
    Invoke-IseBackend -Command certificates -ArgumentList $arguments.ToArray() -ConfigFile $ConfigFile
}

function New-IseReportArguments {
    param([int]$Limit, [switch]$AllowExpensive)
    $arguments = [System.Collections.Generic.List[string]]::new()
    [void]$arguments.Add('--limit'); [void]$arguments.Add([string]$Limit)
    Add-IseSwitchArgument -Arguments $arguments -Value:$AllowExpensive -Name '--allow-expensive'
    Write-Output -NoEnumerate $arguments
}

function Add-IseValueArgument {
    param([System.Collections.Generic.List[string]]$Arguments,[string]$Name,[AllowNull()]$Value)
    if ($null -ne $Value -and [string]$Value -ne '') {
        [void]$Arguments.Add($Name); [void]$Arguments.Add([string]$Value)
    }
}

function Get-IseObjectValue {
    param([Parameter(Mandatory)]$InputObject, [Parameter(Mandatory)][string[]]$Name)
    foreach ($candidate in $Name) {
        $property = $InputObject.PSObject.Properties[$candidate]
        if ($null -ne $property -and $null -ne $property.Value -and [string]$property.Value -ne '') {
            return $property.Value
        }
    }
}

function ConvertTo-IseRadiusAuthentication {
    param([Parameter(Mandatory)]$Row)
    $failed = Get-IseObjectValue -InputObject $Row -Name FAILED
    $numericFailed = 0.0
    $isFailed = (($null -ne $failed -and [double]::TryParse(
        [string]$failed, [ref]$numericFailed) -and $numericFailed -gt 0) -or
        [string]$failed -match '^(?i:true|failed|failure)$')
    $result = if ($null -eq $failed) { 'Unknown' } elseif ($isFailed) { 'Failed' } else { 'Passed' }
    $friendly = [ordered]@{
        Time = Get-IseObjectValue -InputObject $Row -Name TIMESTAMP_TIMEZONE,TIMESTAMP
        Result = $result
        Endpoint = Get-IseObjectValue -InputObject $Row -Name CALLING_STATION_ID,FRAMED_IP_ADDRESS
        Nad = Get-IseObjectValue -InputObject $Row -Name DEVICE_NAME,NETWORK_DEVICE_NAME
        Psn = Get-IseObjectValue -InputObject $Row -Name ISE_NODE
        Method = Get-IseObjectValue -InputObject $Row -Name AUTHENTICATION_METHOD
        Protocol = Get-IseObjectValue -InputObject $Row -Name AUTHENTICATION_PROTOCOL
        PolicySet = Get-IseObjectValue -InputObject $Row -Name POLICY_SET_NAME
        AuthorizationPolicy = Get-IseObjectValue -InputObject $Row -Name AUTHORIZATION_POLICY
        ResponseTime = Get-IseObjectValue -InputObject $Row -Name RESPONSE_TIME
    }
    foreach ($name in $friendly.Keys) {
        $Row | Add-Member -NotePropertyName $name -NotePropertyValue $friendly[$name] -Force
    }
    $Row.PSObject.TypeNames.Insert(0, 'Ise.Cli.RadiusAuthentication')
    Write-Output $Row
}

function Invoke-IseRadiusAuthenticationQuery {
    param(
        [string]$Identifier, [string]$Username, [string]$UsernameLike,
        [string]$Nad, [string]$NadLike, [string]$Psn, [string]$PsnLike,
        [string]$PolicySet, [string]$PolicySetLike,
        [string]$AuthorizationPolicy, [string]$AuthorizationPolicyLike,
        [string]$AuthenticationMethod,
        [string]$AuthenticationProtocol,
        [ValidateSet('failed','passed','success')][string]$Status,
        [switch]$Failed,
        [ValidateRange(1,48)][int]$Hours,
        [ValidateRange(1,5000)][int]$Limit = 100,
        [switch]$AllowExpensive, [string]$ConfigFile,
        [switch]$QuietEmpty
    )
    if ($Failed -and $Status -and $Status -ne 'failed') {
        throw '-Failed cannot be combined with a non-failed -Status value.'
    }
    $effectiveStatus = if ($Failed) { 'failed' } else { $Status }
    $arguments = New-IseReportArguments -Limit $Limit -AllowExpensive:$AllowExpensive
    foreach ($item in @(
        @('--identifier', $Identifier), @('--username', $Username),
        @('--username-like', $UsernameLike), @('--nad', $Nad),
        @('--nad-like', $NadLike), @('--psn', $Psn), @('--psn-like', $PsnLike),
        @('--policy-set', $PolicySet), @('--policy-set-like', $PolicySetLike),
        @('--authorization-policy', $AuthorizationPolicy),
        @('--authorization-policy-like', $AuthorizationPolicyLike),
        @('--authentication-method', $AuthenticationMethod),
        @('--authentication-protocol', $AuthenticationProtocol),
        @('--status', $effectiveStatus)
    )) {
        Add-IseValueArgument -Arguments $arguments -Name $item[0] -Value $item[1]
    }
    if ($PSBoundParameters.ContainsKey('Hours')) {
        [void]$arguments.Add('--hours'); [void]$arguments.Add([string]$Hours)
    }
    foreach ($row in @(Invoke-IseBackend -Command radius-auth `
        -ArgumentList $arguments.ToArray() -ConfigFile $ConfigFile -QuietEmpty:$QuietEmpty)) {
        if ($null -ne $row) { ConvertTo-IseRadiusAuthentication $row }
    }
}

function Get-IseRadiusAuthentication {
    <#
    .SYNOPSIS
    Gets recent RADIUS authentications with friendly server-side filters.
    .EXAMPLE
    Get-IseRadiusAuthentication -Psn laba-ise-001 -Failed -PolicySet Wired -Hours 1
    #>
    [CmdletBinding()]
    param(
        [Alias('Endpoint','MacAddress','IpAddress')][string]$Identifier,
        [string]$Username, [string]$UsernameLike,
        [string]$Nad, [string]$NadLike, [string]$Psn, [string]$PsnLike,
        [string]$PolicySet, [string]$PolicySetLike,
        [string]$AuthorizationPolicy, [string]$AuthorizationPolicyLike,
        [Alias('Method')][string]$AuthenticationMethod,
        [Alias('Protocol')][string]$AuthenticationProtocol,
        [Alias('Result')][ValidateSet('failed','passed','success')][string]$Status,
        [switch]$Failed,
        [ValidateRange(1,48)][int]$Hours,
        [ValidateRange(1,5000)][int]$Limit = 100,
        [switch]$AllowExpensive, [string]$ConfigFile
    )
    Invoke-IseRadiusAuthenticationQuery @PSBoundParameters
}

function Watch-IseRadiusAuthentication {
    <#
    .SYNOPSIS
    Watches for new RADIUS authentications through the shared paced Data Connect gate.
    .DESCRIPTION
    Repeats the same bounded query, emits each authentication once in chronological
    order, and keeps at most 10,000 deduplication keys. Press Ctrl-C to stop.
    .EXAMPLE
    Watch-IseRadiusAuthentication -Psn laba-ise-001 -Failed -PolicySet Wired
    #>
    [CmdletBinding()]
    param(
        [Alias('Endpoint','MacAddress','IpAddress')][string]$Identifier,
        [string]$Username, [string]$UsernameLike,
        [string]$Nad, [string]$NadLike, [string]$Psn, [string]$PsnLike,
        [string]$PolicySet, [string]$PolicySetLike,
        [string]$AuthorizationPolicy, [string]$AuthorizationPolicyLike,
        [Alias('Method')][string]$AuthenticationMethod,
        [Alias('Protocol')][string]$AuthenticationProtocol,
        [Alias('Result')][ValidateSet('failed','passed','success')][string]$Status,
        [switch]$Failed,
        [ValidateRange(1,48)][int]$Hours = 1,
        [ValidateRange(1,5000)][int]$Limit = 200,
        [ValidateRange(10,3600)][int]$IntervalSeconds = 30,
        [switch]$Once, [switch]$AllowExpensive, [string]$ConfigFile
    )
    $seen = [System.Collections.Generic.HashSet[string]]::new(
        [System.StringComparer]::Ordinal)
    $order = [System.Collections.Generic.Queue[string]]::new()
    $queryParameters = @{
        Hours = $Hours
        Limit = $Limit
        AllowExpensive = $AllowExpensive
        ConfigFile = $ConfigFile
        QuietEmpty = $true
    }
    foreach ($item in @(
        @('Identifier', $Identifier), @('Username', $Username),
        @('UsernameLike', $UsernameLike), @('Nad', $Nad), @('NadLike', $NadLike),
        @('Psn', $Psn), @('PsnLike', $PsnLike),
        @('PolicySet', $PolicySet), @('PolicySetLike', $PolicySetLike),
        @('AuthorizationPolicy', $AuthorizationPolicy),
        @('AuthorizationPolicyLike', $AuthorizationPolicyLike),
        @('AuthenticationMethod', $AuthenticationMethod),
        @('AuthenticationProtocol', $AuthenticationProtocol),
        @('Status', $Status)
    )) {
        if ($null -ne $item[1] -and [string]$item[1] -ne '') {
            $queryParameters[$item[0]] = $item[1]
        }
    }
    if ($Failed) { $queryParameters.Failed = $true }
    while ($true) {
        $rows = @(Invoke-IseRadiusAuthenticationQuery @queryParameters)
        foreach ($row in @($rows | Sort-Object Time)) {
            $key = ConvertTo-Json -Depth 5 -Compress -InputObject $row
            if ($seen.Contains($key)) { continue }
            [void]$seen.Add($key)
            $order.Enqueue($key)
            if ($order.Count -gt 10000) {
                [void]$seen.Remove($order.Dequeue())
            }
            Write-Output $row
        }
        if ($Once) { break }
        Start-Sleep -Seconds $IntervalSeconds
    }
}

Update-TypeData -TypeName Ise.Cli.RadiusAuthentication `
    -DefaultDisplayPropertySet Time,Result,Endpoint,Nad,Psn,Method,Protocol,PolicySet,AuthorizationPolicy,ResponseTime -Force
function Get-IseEndpointReport {
    [CmdletBinding()]
    param([string]$Identifier,[string]$Profile,[ValidateRange(1,5000)][int]$Limit=100,[switch]$AllowExpensive,[string]$ConfigFile)
    $a=New-IseReportArguments -Limit $Limit -AllowExpensive:$AllowExpensive; Add-IseValueArgument -Arguments $a -Name '--identifier' -Value $Identifier; Add-IseValueArgument -Arguments $a -Name '--profile' -Value $Profile
    Invoke-IseBackend -Command endpoint-report -ArgumentList $a.ToArray() -ConfigFile $ConfigFile
}
function Get-IseRadiusError {
    [CmdletBinding()]
    param([string]$Identifier,[string]$Nad,[string]$MessageCode,[ValidateRange(1,5000)][int]$Limit=100,[switch]$AllowExpensive,[string]$ConfigFile)
    $a=New-IseReportArguments -Limit $Limit -AllowExpensive:$AllowExpensive; Add-IseValueArgument -Arguments $a -Name '--identifier' -Value $Identifier; Add-IseValueArgument -Arguments $a -Name '--nad' -Value $Nad; Add-IseValueArgument -Arguments $a -Name '--message-code' -Value $MessageCode
    Invoke-IseBackend -Command radius-errors -ArgumentList $a.ToArray() -ConfigFile $ConfigFile
}
function Get-IseRadiusAccounting {
    [CmdletBinding()]
    param([string]$Identifier,[string]$Username,[string]$Nad,[ValidateRange(1,5000)][int]$Limit=100,[switch]$AllowExpensive,[string]$ConfigFile)
    $a=New-IseReportArguments -Limit $Limit -AllowExpensive:$AllowExpensive; Add-IseValueArgument -Arguments $a -Name '--identifier' -Value $Identifier; Add-IseValueArgument -Arguments $a -Name '--username' -Value $Username; Add-IseValueArgument -Arguments $a -Name '--nad' -Value $Nad
    Invoke-IseBackend -Command radius-accounting -ArgumentList $a.ToArray() -ConfigFile $ConfigFile
}
function Get-IsePostureAssessment {
    [CmdletBinding()]
    param([string]$Identifier,[string]$Status,[switch]$Conditions,[ValidateRange(1,5000)][int]$Limit=100,[switch]$AllowExpensive,[string]$ConfigFile)
    $a=New-IseReportArguments -Limit $Limit -AllowExpensive:$AllowExpensive; Add-IseValueArgument -Arguments $a -Name '--identifier' -Value $Identifier; Add-IseValueArgument -Arguments $a -Name '--status' -Value $Status; Add-IseSwitchArgument -Arguments $a -Value:$Conditions -Name '--conditions'
    Invoke-IseBackend -Command posture -ArgumentList $a.ToArray() -ConfigFile $ConfigFile
}
function Get-IsePsnMetric {
    [CmdletBinding()]
    param([string]$Psn,[ValidateRange(1,5000)][int]$Limit=100,[switch]$AllowExpensive,[string]$ConfigFile)
    $a=New-IseReportArguments -Limit $Limit -AllowExpensive:$AllowExpensive; Add-IseValueArgument -Arguments $a -Name '--psn' -Value $Psn
    Invoke-IseBackend -Command psn-metrics -ArgumentList $a.ToArray() -ConfigFile $ConfigFile
}
function Get-IseTacacsActivity {
    [CmdletBinding()]
    param([string]$Username,[string]$Device,[ValidateSet('authentication','authorization','accounting')][string]$EventType='authentication',[ValidateRange(1,5000)][int]$Limit=100,[switch]$AllowExpensive,[string]$ConfigFile)
    $a=New-IseReportArguments -Limit $Limit -AllowExpensive:$AllowExpensive; Add-IseValueArgument -Arguments $a -Name '--username' -Value $Username; Add-IseValueArgument -Arguments $a -Name '--device' -Value $Device; Add-IseValueArgument -Arguments $a -Name '--event-type' -Value $EventType
    Invoke-IseBackend -Command tacacs-activity -ArgumentList $a.ToArray() -ConfigFile $ConfigFile
}

function Get-IseDataConnectSchema {
    <#
    .SYNOPSIS
    Lists Data Connect reporting views or the columns in one view.
    .DESCRIPTION
    With no table name, returns one compact summary object per reporting view.
    Supply a table name for column-level objects, or use AllColumns to return
    every column object across every view.
    #>
    [CmdletBinding()]
    param(
        [Parameter(Position=0,ValueFromPipeline,ValueFromPipelineByPropertyName)]
        [Alias('table_name')][string]$Table,
        [switch]$AllColumns,
        [string]$ConfigFile
    )
    process {
        $arguments = if ($Table) { @($Table) } else { @() }
        $rows = @(Invoke-IseBackend -Command dataconnect-schema -ArgumentList $arguments -ConfigFile $ConfigFile)
        if ($Table -in @('--help', '-h', 'help')) {
            $rows | Write-Output
            return
        }
        if (-not $Table -and -not $AllColumns) {
            $rows | Group-Object table_name | Sort-Object Name | ForEach-Object {
                $types = @($_.Group.data_type | Where-Object { $_ } | Sort-Object -Unique)
                [pscustomobject]@{
                    PSTypeName = 'Ise.Cli.DataConnectTable'
                    table_name = $_.Name
                    columns = $_.Count
                    data_types = $types -join ', '
                }
            }
            return
        }
        foreach ($row in $rows) {
            $row.PSObject.TypeNames.Insert(0, 'Ise.Cli.DataConnectColumn')
            Write-Output $row
        }
    }
}

Update-TypeData -TypeName Ise.Cli.DataConnectColumn `
    -DefaultDisplayPropertySet column_id,column_name,data_type,nullable -Force

function Get-IseDataConnectColumn {
    <#
    .SYNOPSIS
    Gets the columns exposed by any Data Connect table or view.
    .DESCRIPTION
    Accepts a table name directly or a table object from Get-IseDataConnectTable.
    Returns normal column metadata objects suitable for filtering and selection.
    .EXAMPLE
    Get-IseDataConnectColumn AAA_DIAGNOSTICS_VIEW
    .EXAMPLE
    Get-IseDataConnectTable '*TACACS*' | Get-IseDataConnectColumn
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory,Position=0,ValueFromPipeline,ValueFromPipelineByPropertyName)]
        [Alias('table_name')][string]$Table,
        [string]$ConfigFile
    )
    process {
        Get-IseDataConnectSchema -Table $Table -ConfigFile $ConfigFile
    }
}

function Invoke-IseDataConnectRowQuery {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory, Position=0)][string]$Table,
        [string[]]$Column = @(),
        [hashtable]$Where = @{},
        [hashtable]$Like = @{},
        [string]$OrderBy,
        [switch]$Descending,
        [ValidateRange(1,48)][int]$Hours,
        [ValidateRange(1,5000)][int]$Limit = 100,
        [switch]$AllowExpensive,
        [string]$ConfigFile
    )
    $arguments = New-IseReportArguments -Limit $Limit -AllowExpensive:$AllowExpensive
    [void]$arguments.Insert(0, $Table)
    foreach ($item in $Column) {
        [void]$arguments.Add('--column'); [void]$arguments.Add($item)
    }
    foreach ($key in ($Where.Keys | Sort-Object)) {
        [void]$arguments.Add('--where'); [void]$arguments.Add("$key=$($Where[$key])")
    }
    foreach ($key in ($Like.Keys | Sort-Object)) {
        [void]$arguments.Add('--like'); [void]$arguments.Add("$key=$($Like[$key])")
    }
    Add-IseValueArgument -Arguments $arguments -Name '--order-by' -Value $OrderBy
    Add-IseSwitchArgument -Arguments $arguments -Value:$Descending -Name '--descending'
    if ($PSBoundParameters.ContainsKey('Hours')) {
        [void]$arguments.Add('--hours'); [void]$arguments.Add([string]$Hours)
    }
    foreach ($row in @(Invoke-IseBackend -Command dataconnect-query -ArgumentList $arguments.ToArray() -ConfigFile $ConfigFile)) {
        if ($row) {
            $row.PSObject.TypeNames.Insert(0, "Ise.Cli.DataConnectRow.$Table")
            $row.PSObject.TypeNames.Insert(1, 'Ise.Cli.DataConnectRow')
        }
        Write-Output $row
    }
}

function Get-IseDataConnectRow {
    <#
    .SYNOPSIS
    Gets bounded rows from any discovered Data Connect table or view.
    .DESCRIPTION
    Table and column names are checked against live Data Connect metadata. Filter
    values are always bound, event views are constrained to the configured recent
    window, and results default to 100 rows. The returned values are normal typed
    PowerShell objects. Use Get-IseDataConnectTable and Get-IseDataConnectColumn to
    walk the database before selecting rows.
    .EXAMPLE
    Get-IseDataConnectRow AAA_DIAGNOSTICS_VIEW -Like @{ MESSAGE_TEXT='*timeout*' }
    .EXAMPLE
    Get-IseDataConnectRow RADIUS_AUTHENTICATIONS -Where @{ USERNAME='alice' } -OrderBy TIMESTAMP -Descending -Limit 50
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory,Position=0,ValueFromPipeline,ValueFromPipelineByPropertyName)]
        [Alias('table_name')][string]$Table,
        [string[]]$Column = @(),
        [hashtable]$Where = @{},
        [hashtable]$Like = @{},
        [string]$OrderBy,
        [switch]$Descending,
        [ValidateRange(1,48)][int]$Hours,
        [ValidateRange(1,5000)][int]$Limit = 100,
        [switch]$AllowExpensive,
        [string]$ConfigFile
    )
    process {
        Invoke-IseDataConnectRowQuery @PSBoundParameters
    }
}

function Search-IseDataConnect {
    <#
.SYNOPSIS
Compatibility name for Get-IseDataConnectRow.
#>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory,Position=0,ValueFromPipeline,ValueFromPipelineByPropertyName)]
        [Alias('table_name')][string]$Table,
        [string[]]$Column = @(), [hashtable]$Where = @{}, [hashtable]$Like = @{},
        [string]$OrderBy, [switch]$Descending,
        [ValidateRange(1,48)][int]$Hours,
        [ValidateRange(1,5000)][int]$Limit = 100,
        [switch]$AllowExpensive, [string]$ConfigFile
    )
    process { Get-IseDataConnectRow @PSBoundParameters }
}

function Get-IseDataConnectTable {
    <#
    .SYNOPSIS Lists every table or view visible to the Data Connect account.
    .DESCRIPTION Returns catalog metadata only; it does not scan reporting rows.
    .EXAMPLE Get-IseDataConnectTable '*TACACS*' | Get-IseDataConnectSchema
    #>
    [CmdletBinding()]
    param([Parameter(Position=0)][string]$Pattern, [string]$ConfigFile)
    $arguments = if ($Pattern) { @($Pattern) } else { @() }
    foreach ($row in @(Invoke-IseBackend -Command dataconnect-catalog -ArgumentList $arguments -ConfigFile $ConfigFile)) {
        $row.PSObject.TypeNames.Insert(0, 'Ise.Cli.DataConnectCatalogTable')
        Write-Output $row
    }
}

Update-TypeData -TypeName Ise.Cli.DataConnectCatalogTable `
    -DefaultDisplayPropertySet table_name,column_count,lob_columns,first_column -Force

function Invoke-IseDiagnosticView {
    param(
        [Parameter(Mandatory)][string]$Table,
        [string[]]$Column,
        [hashtable]$Exact,
        [hashtable]$Pattern,
        [int]$Hours,
        [int]$Limit,
        [switch]$AllowExpensive,
        [string]$ConfigFile,
        [string]$TypeName
    )
    $parameters = @{
        Table = $Table; Column = $Column; Where = $Exact; Like = $Pattern
        Limit = $Limit; AllowExpensive = $AllowExpensive; ConfigFile = $ConfigFile
        OrderBy = 'TIMESTAMP'; Descending = $true
    }
    if ($Hours -gt 0) { $parameters.Hours = $Hours }
    foreach ($row in @(Get-IseDataConnectRow @parameters)) {
        if ($row -and $TypeName) { $row.PSObject.TypeNames.Insert(0, $TypeName) }
        Write-Output $row
    }
}

function Get-IseAlert {
    <#
.SYNOPSIS
Returns recent ISE system alerts from Data Connect.
#>
    [CmdletBinding()]
    param(
        [string]$Severity, [string]$Category, [string]$Node, [string]$Message='*',
        [ValidateRange(1,48)][int]$Hours,
        [ValidateRange(1,5000)][int]$Limit=100,
        [switch]$AllowExpensive, [string]$ConfigFile
    )
    $exact=@{}; $pattern=@{ MESSAGE_TEXT=$Message }
    if($Severity){$exact.MESSAGE_SEVERITY=$Severity}; if($Category){$exact.CATEGORY=$Category}; if($Node){$exact.ISE_NODE=$Node}
    Invoke-IseDiagnosticView -Table SYSTEM_DIAGNOSTICS_VIEW `
        -Column TIMESTAMP,ISE_NODE,MESSAGE_SEVERITY,MESSAGE_CODE,CATEGORY,MESSAGE_TEXT,DIAGNOSTIC_INFO `
        -Exact $exact -Pattern $pattern -Hours $Hours -Limit $Limit `
        -AllowExpensive:$AllowExpensive -ConfigFile $ConfigFile -TypeName Ise.Cli.Alert
}

function Get-IseSystemDiagnostic {
    <#
.SYNOPSIS
Returns recent system diagnostic records from Data Connect.
#>
    [CmdletBinding()]
    param(
        [string]$Severity, [string]$Category, [string]$Node, [string]$Message='*',
        [ValidateRange(1,48)][int]$Hours,
        [ValidateRange(1,5000)][int]$Limit=100,
        [switch]$AllowExpensive, [string]$ConfigFile
    )
    $exact=@{}; $pattern=@{ MESSAGE_TEXT=$Message }
    if($Severity){$exact.MESSAGE_SEVERITY=$Severity}; if($Category){$exact.CATEGORY=$Category}; if($Node){$exact.ISE_NODE=$Node}
    Invoke-IseDiagnosticView -Table SYSTEM_DIAGNOSTICS_VIEW `
        -Column TIMESTAMP,ISE_NODE,MESSAGE_SEVERITY,MESSAGE_CODE,CATEGORY,MESSAGE_TEXT,DIAGNOSTIC_INFO `
        -Exact $exact -Pattern $pattern -Hours $Hours -Limit $Limit `
        -AllowExpensive:$AllowExpensive -ConfigFile $ConfigFile -TypeName Ise.Cli.SystemDiagnostic
}

function Get-IseAaaDiagnostic {
    <#
.SYNOPSIS
Returns recent authentication, authorization, and accounting diagnostics.
#>
    [CmdletBinding()]
    param(
        [string]$Username, [string]$Severity, [string]$Category,
        [string]$Node, [string]$Message='*',
        [ValidateRange(1,48)][int]$Hours,
        [ValidateRange(1,5000)][int]$Limit=100,
        [switch]$AllowExpensive, [string]$ConfigFile
    )
    $exact=@{}; $pattern=@{ MESSAGE_TEXT=$Message }
    if($Username){$exact.USERNAME=$Username}; if($Severity){$exact.MESSAGE_SEVERITY=$Severity}; if($Category){$exact.CATEGORY=$Category}; if($Node){$exact.ISE_NODE=$Node}
    Invoke-IseDiagnosticView -Table AAA_DIAGNOSTICS_VIEW `
        -Column TIMESTAMP,ISE_NODE,USERNAME,MESSAGE_SEVERITY,MESSAGE_CODE,CATEGORY,MESSAGE_TEXT,INFO `
        -Exact $exact -Pattern $pattern -Hours $Hours -Limit $Limit `
        -AllowExpensive:$AllowExpensive -ConfigFile $ConfigFile -TypeName Ise.Cli.AaaDiagnostic
}

function Test-IseDataConnect {
    <#
.SYNOPSIS
Diagnoses the authenticated Oracle Data Connect session and readable catalog.
#>
    [CmdletBinding()]
    param([string]$ConfigFile)
    Invoke-IseBackend -Command dataconnect-health -ConfigFile $ConfigFile
}

Update-TypeData -TypeName Ise.Cli.Alert -DefaultDisplayPropertySet TIMESTAMP,ISE_NODE,MESSAGE_SEVERITY,MESSAGE_CODE,CATEGORY,MESSAGE_TEXT -Force
Update-TypeData -TypeName Ise.Cli.SystemDiagnostic -DefaultDisplayPropertySet TIMESTAMP,ISE_NODE,MESSAGE_SEVERITY,MESSAGE_CODE,CATEGORY,MESSAGE_TEXT -Force
Update-TypeData -TypeName Ise.Cli.AaaDiagnostic -DefaultDisplayPropertySet TIMESTAMP,ISE_NODE,USERNAME,MESSAGE_SEVERITY,MESSAGE_CODE,CATEGORY,MESSAGE_TEXT -Force

function Get-IseSchema {
    <#
.SYNOPSIS
Returns the backend contract for one command or the complete command set.
#>
    [CmdletBinding()]
    param([Parameter(Position=0)][string]$Name, [string]$ConfigFile)
    $arguments = if ($Name) { @($Name) } else { @() }
    Invoke-IseBackend -Command schema -ArgumentList $arguments -ConfigFile $ConfigFile
}

function Invoke-IseReadOnlyRequest {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)][ValidateSet('ers','openapi','mnt')][string]$Family,
        [Parameter(Mandatory)][string]$Path,
        [hashtable]$Parameter = @{},
        [switch]$All, [switch]$NoUnwrap, [switch]$AllowExpensive,
        [string]$ConfigFile
    )
    $arguments=[System.Collections.Generic.List[string]]::new(); [void]$arguments.Add($Family); [void]$arguments.Add($Path)
    foreach($key in ($Parameter.Keys | Sort-Object)){ [void]$arguments.Add('--param'); [void]$arguments.Add("$key=$($Parameter[$key])") }
    Add-IseSwitchArgument -Arguments $arguments -Value:$All -Name '--all'; Add-IseSwitchArgument -Arguments $arguments -Value:$NoUnwrap -Name '--no-unwrap'; Add-IseSwitchArgument -Arguments $arguments -Value:$AllowExpensive -Name '--allow-expensive'
    Invoke-IseBackend -Command get -ArgumentList $arguments.ToArray() -ConfigFile $ConfigFile
}

function Get-IseLegacyCompletion {
    param([string]$Line)
    try {
        $json = Invoke-IseBackendProcess -ArgumentList @('--complete', $Line, '--cursor', [string]$Line.Length)
        @($json | ConvertFrom-Json -Depth 10)
    }
    catch { @() }
}

$identifierCompleter = {
    param($commandName, $parameterName, $wordToComplete, $commandAst, $fakeBoundParameters)
    $legacy = switch ($commandName) {
        'Get-IseEndpoint' { 'endpoint' }
        'Resolve-IseEndpoint' { 'resolve' }
        'Get-IseSession' { 'session' }
        'Get-IseAuthenticationStatus' { 'auth-status' }
        'Get-IseSecureClient' { 'secure-client' }
        'Get-IseEndpointSummary' { 'endpoint-summary' }
        'Debug-IseAuthentication' { 'troubleshoot-auth' }
        'Get-IseRadiusAuthentication' { 'radius-auth --identifier' }
        'Watch-IseRadiusAuthentication' { 'radius-auth --identifier' }
        default { 'endpoint' }
    }
    foreach ($candidate in (Get-IseLegacyCompletion "$legacy $wordToComplete")) {
        [System.Management.Automation.CompletionResult]::new(
            [string]$candidate, ([string]$candidate).Trim(), 'ParameterValue', [string]$candidate)
    }
}
Register-ArgumentCompleter -CommandName @(
    'Get-IseEndpoint','Resolve-IseEndpoint','Get-IseSession',
    'Get-IseAuthenticationStatus','Get-IseSecureClient','Get-IseEndpointSummary',
    'Debug-IseAuthentication','Get-IseRadiusAuthentication',
    'Watch-IseRadiusAuthentication') -ParameterName Identifier -ScriptBlock $identifierCompleter

$criteriaCompleter = {
    param($commandName, $parameterName, $wordToComplete, $commandAst, $fakeBoundParameters)
    foreach ($candidate in (Get-IseLegacyCompletion "endpoints $wordToComplete")) {
        [System.Management.Automation.CompletionResult]::new(
            [string]$candidate, ([string]$candidate).Trim(), 'ParameterValue', [string]$candidate)
    }
}
Register-ArgumentCompleter -CommandName Find-IseEndpoint -ParameterName Criteria -ScriptBlock $criteriaCompleter

function New-IseCompletionResult {
    param([string[]]$Candidate)
    foreach ($item in $Candidate) {
        [System.Management.Automation.CompletionResult]::new(
            [string]$item, ([string]$item).Trim(), 'ParameterValue', [string]$item)
    }
}

$nodeCompleter = {
    param($commandName, $parameterName, $wordToComplete, $commandAst, $fakeBoundParameters)
    $legacy = if ($commandName -in @(
        'Get-IsePsnMetric','Debug-IsePsn','Get-IseRadiusAuthentication',
        'Watch-IseRadiusAuthentication')) {
        'psn-metrics --psn'
    } else { 'certificates --node' }
    New-IseCompletionResult (Get-IseLegacyCompletion "$legacy $wordToComplete")
}
Register-ArgumentCompleter -CommandName Get-IseCertificate -ParameterName Node -ScriptBlock $nodeCompleter
Register-ArgumentCompleter -CommandName Get-IsePsnMetric -ParameterName Psn -ScriptBlock $nodeCompleter
Register-ArgumentCompleter -CommandName Debug-IsePsn -ParameterName Psn -ScriptBlock $nodeCompleter
Register-ArgumentCompleter -CommandName Get-IseRadiusAuthentication,Watch-IseRadiusAuthentication `
    -ParameterName Psn -ScriptBlock $nodeCompleter

$nadCompleter = {
    param($commandName, $parameterName, $wordToComplete, $commandAst, $fakeBoundParameters)
    $legacy = switch ($commandName) {
        'Get-IseRadiusError' { 'radius-errors --nad' }
        'Get-IseRadiusAccounting' { 'radius-accounting --nad' }
        default { 'radius-auth --nad' }
    }
    New-IseCompletionResult (Get-IseLegacyCompletion "$legacy $wordToComplete")
}
Register-ArgumentCompleter -CommandName @(
    'Get-IseRadiusAuthentication','Watch-IseRadiusAuthentication',
    'Get-IseRadiusError','Get-IseRadiusAccounting',
    'Get-IseNadSummary'
) -ParameterName Nad -ScriptBlock $nadCompleter

$usernameCompleter = {
    param($commandName, $parameterName, $wordToComplete, $commandAst, $fakeBoundParameters)
    $legacy = if ($commandName -eq 'Get-IseTacacsActivity') {
        'tacacs-activity --username'
    } else {
        'radius-auth --username'
    }
    New-IseCompletionResult (Get-IseLegacyCompletion "$legacy $wordToComplete")
}
Register-ArgumentCompleter -CommandName @(
    'Get-IseRadiusAuthentication','Watch-IseRadiusAuthentication',
    'Get-IseRadiusAccounting','Get-IseTacacsActivity'
) -ParameterName Username -ScriptBlock $usernameCompleter

$profileCompleter = {
    param($commandName, $parameterName, $wordToComplete, $commandAst, $fakeBoundParameters)
    New-IseCompletionResult (Get-IseLegacyCompletion "endpoint-report --profile $wordToComplete")
}
Register-ArgumentCompleter -CommandName Get-IseEndpointReport -ParameterName Profile -ScriptBlock $profileCompleter

$schemaCompleter = {
    param($commandName, $parameterName, $wordToComplete, $commandAst, $fakeBoundParameters)
    New-IseCompletionResult (Get-IseLegacyCompletion "schema $wordToComplete")
}
Register-ArgumentCompleter -CommandName Get-IseSchema -ParameterName Name -ScriptBlock $schemaCompleter

$dataConnectTableCompleter = {
    param($commandName, $parameterName, $wordToComplete, $commandAst, $fakeBoundParameters)
    New-IseCompletionResult (Get-IseLegacyCompletion "dataconnect-schema $wordToComplete")
}
Register-ArgumentCompleter -CommandName @(
    'Get-IseDataConnectSchema','Get-IseDataConnectColumn',
    'Get-IseDataConnectRow','Search-IseDataConnect'
) -ParameterName Table -ScriptBlock $dataConnectTableCompleter

$dataConnectColumnCompleter = {
    param($commandName, $parameterName, $wordToComplete, $commandAst, $fakeBoundParameters)
    $table = [string]$fakeBoundParameters['Table']
    if (-not $table) { return }
    try {
        $rows = @(Invoke-IseBackend -Command dataconnect-schema -ArgumentList @($table))
        New-IseCompletionResult @($rows.column_name | Where-Object {
            $_ -like "$wordToComplete*"
        } | Sort-Object -Unique)
    }
    catch { return }
}
Register-ArgumentCompleter -CommandName Get-IseDataConnectRow,Search-IseDataConnect `
    -ParameterName Column -ScriptBlock $dataConnectColumnCompleter
Register-ArgumentCompleter -CommandName Get-IseDataConnectRow,Search-IseDataConnect `
    -ParameterName OrderBy -ScriptBlock $dataConnectColumnCompleter

$nativeCompleter = {
    param($wordToComplete, $commandAst, $cursorPosition)
    $line = [string]$commandAst.Extent.Text
    $line = $line -replace '^\s*\S+\s*', ''
    foreach ($candidate in (Get-IseLegacyCompletion $line)) {
        [System.Management.Automation.CompletionResult]::new(
            [string]$candidate, ([string]$candidate).Trim(), 'ParameterValue', [string]$candidate)
    }
}
Register-ArgumentCompleter -Native -CommandName ise-cli -ScriptBlock $nativeCompleter

Set-Alias -Name Find-Endpoint -Value Find-IseEndpoint

Export-ModuleMember -Function @(
    'Invoke-IseCommand','Get-IseCliVersion','Get-IseOverview','Get-IseCollectorStatus',
    'Get-IseEndpointSummary','Debug-IseAuthentication','Debug-IsePsn','Get-IseNadSummary',
    'Get-IsePxGridStatus','Test-IsePxGrid','Get-IsePxGridService','Get-IsePxGridTopic',
    'Invoke-IsePxGridQuery','Get-IsePxGridSession','Get-IsePxGridUserGroup',
    'Get-IsePxGridSystemHealth','Get-IsePxGridSystemPerformance','Get-IsePxGridTrustSec',
    'Get-IsePxGridEndpoint','Get-IsePxGridSxpBinding','Get-IsePxGridRadiusFailure',
    'Get-IsePxGridMdmEndpoint','Get-IsePxGridProfilerProfile','Get-IsePxGridAncPolicy',
    'Get-IsePxGridAncEndpoint','Get-IsePxGridAncEndpointPolicy',
    'Test-IseHealth','Test-IseErs','Test-IseOpenApi','Test-IseMnt',
    'Get-IseNode','Find-IseEndpoint',
    'Get-IseEndpointField','Get-IseEndpoint','Resolve-IseEndpoint','Get-IseSession',
    'Get-IseActiveSession','Get-IseAuthenticationStatus','Get-IseSecureClient',
    'Get-IseNetworkDevice','Get-IseProfilerProfile','Get-IseTacacsUser',
    'Get-IseIdentityGroup','Get-IseNetworkDeviceGroup','Get-IseLicense','Get-IsePatch',
    'Get-IseBackupStatus','Get-IseRepository','Get-IseNetworkPolicySet',
    'Get-IseDeviceAdminPolicySet','Get-IseAuthorizationProfile','Get-IseTacacsCommandSet',
    'Get-IseTacacsShellProfile','Get-IseCertificate','Get-IseRadiusAuthentication',
    'Watch-IseRadiusAuthentication',
    'Get-IseEndpointReport','Get-IseRadiusError','Get-IseRadiusAccounting',
    'Get-IsePostureAssessment','Get-IsePsnMetric','Get-IseTacacsActivity',
    'Get-IseDataConnectTable','Get-IseDataConnectColumn','Get-IseDataConnectRow',
    'Get-IseDataConnectSchema','Search-IseDataConnect','Get-IseAlert',
    'Get-IseSystemDiagnostic','Get-IseAaaDiagnostic','Test-IseDataConnect',
    'Get-IseSchema','Invoke-IseReadOnlyRequest'
) -Alias 'Find-Endpoint'
