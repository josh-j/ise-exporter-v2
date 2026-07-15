Set-StrictMode -Version Latest

$script:IseCommands = @(
    'health', 'nodes', 'endpoints', 'endpoint-fields', 'endpoint', 'resolve',
    'sessions', 'session', 'auth-status', 'secure-client', 'nads', 'profiles',
    'tacacs-users', 'identity-groups', 'network-device-groups', 'licenses',
    'patches', 'backup-status', 'repositories', 'network-policy-sets',
    'device-admin-policy-sets', 'authorization-profiles', 'tacacs-command-sets',
    'tacacs-shell-profiles', 'certificates', 'radius-auth', 'endpoint-report',
    'radius-errors', 'radius-accounting', 'posture', 'psn-metrics',
    'tacacs-activity', 'dataconnect-schema', 'schema', 'get'
)

function Get-IseBackendCommand {
    [CmdletBinding()]
    param()

    if ($env:ISE_CLI_BACKEND) {
        $explicit = Get-Command -Name $env:ISE_CLI_BACKEND -CommandType Application -ErrorAction SilentlyContinue
        if (-not $explicit -and (Test-Path -LiteralPath $env:ISE_CLI_BACKEND -PathType Leaf)) {
            $explicit = Get-Item -LiteralPath $env:ISE_CLI_BACKEND
        }
        if (-not $explicit) {
            throw "ISE_CLI_BACKEND does not identify an executable: $($env:ISE_CLI_BACKEND)"
        }
        $path = if ($explicit.PSObject.Properties['Source']) { $explicit.Source } else { $explicit.FullName }
        return [pscustomobject]@{ FilePath = $path; Prefix = @() }
    }

    $installed = Get-Command -Name 'ise-cli-backend' -CommandType Application -ErrorAction SilentlyContinue
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
    param([AllowEmptyString()][string]$Json)

    if ([string]::IsNullOrWhiteSpace($Json)) { return }
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
            'health', 'nodes', 'endpoints', 'endpoint-fields', 'endpoint', 'resolve',
            'sessions', 'session', 'auth-status', 'secure-client', 'nads', 'profiles',
            'tacacs-users', 'identity-groups', 'network-device-groups', 'licenses',
            'patches', 'backup-status', 'repositories', 'network-policy-sets',
            'device-admin-policy-sets', 'authorization-profiles', 'tacacs-command-sets',
            'tacacs-shell-profiles', 'certificates', 'radius-auth', 'endpoint-report',
            'radius-errors', 'radius-accounting', 'posture', 'psn-metrics',
            'tacacs-activity', 'dataconnect-schema', 'schema', 'get')]
        [string]$Command,
        [string[]]$ArgumentList = @(),
        [string]$EnvironmentFile
    )

    $backendArguments = @()
    if ($EnvironmentFile) { $backendArguments += @('--env-file', $EnvironmentFile) }
    $backendArguments += $Command
    $backendArguments += $ArgumentList
    $backendArguments += @('--output', 'json')
    ConvertFrom-IseBackendJson -Json (Invoke-IseBackendProcess -ArgumentList $backendArguments)
}

function Invoke-IseCommand {
    <# .SYNOPSIS Runs any bounded legacy command and returns PowerShell objects. #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory, Position = 0)]
        [ValidateSet(
            'health', 'nodes', 'endpoints', 'endpoint-fields', 'endpoint', 'resolve',
            'sessions', 'session', 'auth-status', 'secure-client', 'nads', 'profiles',
            'tacacs-users', 'identity-groups', 'network-device-groups', 'licenses',
            'patches', 'backup-status', 'repositories', 'network-policy-sets',
            'device-admin-policy-sets', 'authorization-profiles', 'tacacs-command-sets',
            'tacacs-shell-profiles', 'certificates', 'radius-auth', 'endpoint-report',
            'radius-errors', 'radius-accounting', 'posture', 'psn-metrics',
            'tacacs-activity', 'dataconnect-schema', 'schema', 'get')]
        [string]$Name,
        [Parameter(Position = 1, ValueFromRemainingArguments)]
        [string[]]$ArgumentList = @(),
        [string]$EnvironmentFile,
        [switch]$Raw
    )
    if ($Raw) {
        $backendArguments = @()
        if ($EnvironmentFile) { $backendArguments += @('--env-file', $EnvironmentFile) }
        $backendArguments += $Name
        $backendArguments += $ArgumentList
        return Invoke-IseBackendProcess -ArgumentList $backendArguments
    }
    Invoke-IseBackend -Command $Name -ArgumentList $ArgumentList -EnvironmentFile $EnvironmentFile
}

function Get-IseCliVersion {
    <# .SYNOPSIS Returns the backend and exact supported ISE release version. #>
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
        [string]$EnvironmentFile
    )
    $arguments = [System.Collections.Generic.List[string]]::new()
    [void]$arguments.Add('--limit'); [void]$arguments.Add([string]$Limit)
    foreach ($item in $Filter) {
        [void]$arguments.Add('--filter'); [void]$arguments.Add($item)
    }
    Add-IseSwitchArgument -Arguments $arguments -Value:$All -Name '--all'
    Add-IseSwitchArgument -Arguments $arguments -Value:$AllowExpensive -Name '--allow-expensive'
    Invoke-IseBackend -Command $Command -ArgumentList $arguments.ToArray() -EnvironmentFile $EnvironmentFile
}

function Test-IseHealth { [CmdletBinding()] param([string]$EnvironmentFile) Invoke-IseBackend -Command health -EnvironmentFile $EnvironmentFile }
function Get-IseNode { [CmdletBinding()] param([string]$EnvironmentFile) Invoke-IseBackend -Command nodes -EnvironmentFile $EnvironmentFile }

function Find-IseEndpoint {
    [CmdletBinding()]
    param(
        [Parameter(Position = 0)][string[]]$Criteria = @(),
        [ValidateRange(1, 5000)][int]$Limit = 100,
        [string[]]$Filter = @(),
        [switch]$All,
        [switch]$AllowExpensive,
        [string]$EnvironmentFile
    )
    $arguments = [System.Collections.Generic.List[string]]::new()
    foreach ($criterion in $Criteria) { [void]$arguments.Add($criterion) }
    [void]$arguments.Add('--limit'); [void]$arguments.Add([string]$Limit)
    foreach ($item in $Filter) {
        [void]$arguments.Add('--filter'); [void]$arguments.Add($item)
    }
    Add-IseSwitchArgument -Arguments $arguments -Value:$All -Name '--all'
    Add-IseSwitchArgument -Arguments $arguments -Value:$AllowExpensive -Name '--allow-expensive'
    Invoke-IseBackend -Command endpoints -ArgumentList $arguments.ToArray() -EnvironmentFile $EnvironmentFile
}

function Get-IseEndpointField {
    [CmdletBinding()]
    param([Parameter(Position = 0)][string]$Pattern, [string]$EnvironmentFile)
    $arguments = if ($Pattern) { @($Pattern) } else { @() }
    Invoke-IseBackend -Command endpoint-fields -ArgumentList $arguments -EnvironmentFile $EnvironmentFile
}

function Get-IseEndpoint {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory, Position = 0, ValueFromPipeline)][string]$Identifier,
        [switch]$Id, [switch]$IncludeSession, [switch]$AllowActiveListScan,
        [string]$EnvironmentFile
    )
    process {
        $arguments = [System.Collections.Generic.List[string]]::new()
        [void]$arguments.Add($Identifier)
        Add-IseSwitchArgument -Arguments $arguments -Value:$Id -Name '--id'
        Add-IseSwitchArgument -Arguments $arguments -Value:$IncludeSession -Name '--include-session'
        Add-IseSwitchArgument -Arguments $arguments -Value:$AllowActiveListScan -Name '--allow-active-list-scan'
        Invoke-IseBackend -Command endpoint -ArgumentList $arguments.ToArray() -EnvironmentFile $EnvironmentFile
    }
}

function Resolve-IseEndpoint {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory, Position = 0, ValueFromPipeline)][string]$Identifier,
        [switch]$Id, [switch]$AllowActiveListScan, [string]$EnvironmentFile
    )
    process {
        $arguments = [System.Collections.Generic.List[string]]::new()
        [void]$arguments.Add($Identifier)
        Add-IseSwitchArgument -Arguments $arguments -Value:$Id -Name '--id'
        Add-IseSwitchArgument -Arguments $arguments -Value:$AllowActiveListScan -Name '--allow-active-list-scan'
        Invoke-IseBackend -Command resolve -ArgumentList $arguments.ToArray() -EnvironmentFile $EnvironmentFile
    }
}

function Get-IseSession {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory, Position = 0, ValueFromPipeline)][string]$Identifier,
        [switch]$AllowActiveListScan, [string]$EnvironmentFile
    )
    process {
        $arguments = [System.Collections.Generic.List[string]]::new()
        [void]$arguments.Add($Identifier)
        Add-IseSwitchArgument -Arguments $arguments -Value:$AllowActiveListScan -Name '--allow-active-list-scan'
        Invoke-IseBackend -Command session -ArgumentList $arguments.ToArray() -EnvironmentFile $EnvironmentFile
    }
}

function Get-IseActiveSession {
    [CmdletBinding()]
    param(
        [ValidateRange(1, 5000)][int]$Limit = 100,
        [switch]$All,
        [switch]$AllowExpensive,
        [string]$EnvironmentFile
    )
    $arguments = [System.Collections.Generic.List[string]]::new()
    [void]$arguments.Add('--limit'); [void]$arguments.Add([string]$Limit)
    Add-IseSwitchArgument -Arguments $arguments -Value:$All -Name '--all'
    Add-IseSwitchArgument -Arguments $arguments -Value:$AllowExpensive -Name '--allow-expensive'
    Invoke-IseBackend -Command sessions -ArgumentList $arguments.ToArray() -EnvironmentFile $EnvironmentFile
}

function Get-IseAuthenticationStatus {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory, Position = 0, ValueFromPipeline)][string]$Identifier,
        [ValidateRange(1, 86400)][int]$Seconds = 600,
        [ValidateRange(1, 1000)][int]$Limit = 20,
        [switch]$AllowExpensive, [switch]$AllowActiveListScan,
        [string]$EnvironmentFile
    )
    process {
        $arguments = [System.Collections.Generic.List[string]]::new()
        [void]$arguments.Add($Identifier)
        [void]$arguments.Add('--seconds'); [void]$arguments.Add([string]$Seconds)
        [void]$arguments.Add('--limit'); [void]$arguments.Add([string]$Limit)
        Add-IseSwitchArgument -Arguments $arguments -Value:$AllowExpensive -Name '--allow-expensive'
        Add-IseSwitchArgument -Arguments $arguments -Value:$AllowActiveListScan -Name '--allow-active-list-scan'
        Invoke-IseBackend -Command auth-status -ArgumentList $arguments.ToArray() -EnvironmentFile $EnvironmentFile
    }
}

function Get-IseSecureClient {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory, Position = 0, ValueFromPipeline)][string]$Identifier,
        [switch]$IncludeAll, [switch]$AllowActiveListScan, [string]$EnvironmentFile
    )
    process {
        $arguments = [System.Collections.Generic.List[string]]::new()
        [void]$arguments.Add($Identifier)
        Add-IseSwitchArgument -Arguments $arguments -Value:$IncludeAll -Name '--include-all'
        Add-IseSwitchArgument -Arguments $arguments -Value:$AllowActiveListScan -Name '--allow-active-list-scan'
        Invoke-IseBackend -Command secure-client -ArgumentList $arguments.ToArray() -EnvironmentFile $EnvironmentFile
    }
}

function Get-IseNetworkDevice { [CmdletBinding()] param([ValidateRange(1,5000)][int]$Limit=100,[string[]]$Filter=@(),[switch]$All,[switch]$AllowExpensive,[string]$EnvironmentFile) Invoke-IseInventory -Command nads -Limit $Limit -Filter $Filter -All:$All -AllowExpensive:$AllowExpensive -EnvironmentFile $EnvironmentFile }
function Get-IseProfilerProfile { [CmdletBinding()] param([ValidateRange(1,5000)][int]$Limit=100,[string[]]$Filter=@(),[switch]$All,[switch]$AllowExpensive,[string]$EnvironmentFile) Invoke-IseInventory -Command profiles -Limit $Limit -Filter $Filter -All:$All -AllowExpensive:$AllowExpensive -EnvironmentFile $EnvironmentFile }
function Get-IseTacacsUser { [CmdletBinding()] param([ValidateRange(1,5000)][int]$Limit=100,[string[]]$Filter=@(),[switch]$All,[switch]$AllowExpensive,[string]$EnvironmentFile) Invoke-IseInventory -Command tacacs-users -Limit $Limit -Filter $Filter -All:$All -AllowExpensive:$AllowExpensive -EnvironmentFile $EnvironmentFile }
function Get-IseIdentityGroup { [CmdletBinding()] param([ValidateRange(1,5000)][int]$Limit=100,[string[]]$Filter=@(),[switch]$All,[switch]$AllowExpensive,[string]$EnvironmentFile) Invoke-IseInventory -Command identity-groups -Limit $Limit -Filter $Filter -All:$All -AllowExpensive:$AllowExpensive -EnvironmentFile $EnvironmentFile }
function Get-IseNetworkDeviceGroup { [CmdletBinding()] param([ValidateRange(1,5000)][int]$Limit=100,[string[]]$Filter=@(),[switch]$All,[switch]$AllowExpensive,[string]$EnvironmentFile) Invoke-IseInventory -Command network-device-groups -Limit $Limit -Filter $Filter -All:$All -AllowExpensive:$AllowExpensive -EnvironmentFile $EnvironmentFile }

function Get-IseLicense { [CmdletBinding()] param([string]$EnvironmentFile) Invoke-IseBackend -Command licenses -EnvironmentFile $EnvironmentFile }
function Get-IsePatch { [CmdletBinding()] param([string]$EnvironmentFile) Invoke-IseBackend -Command patches -EnvironmentFile $EnvironmentFile }
function Get-IseBackupStatus { [CmdletBinding()] param([string]$EnvironmentFile) Invoke-IseBackend -Command backup-status -EnvironmentFile $EnvironmentFile }
function Get-IseRepository { [CmdletBinding()] param([string]$EnvironmentFile) Invoke-IseBackend -Command repositories -EnvironmentFile $EnvironmentFile }
function Get-IseNetworkPolicySet { [CmdletBinding()] param([string]$EnvironmentFile) Invoke-IseBackend -Command network-policy-sets -EnvironmentFile $EnvironmentFile }
function Get-IseDeviceAdminPolicySet { [CmdletBinding()] param([string]$EnvironmentFile) Invoke-IseBackend -Command device-admin-policy-sets -EnvironmentFile $EnvironmentFile }
function Get-IseAuthorizationProfile { [CmdletBinding()] param([string]$EnvironmentFile) Invoke-IseBackend -Command authorization-profiles -EnvironmentFile $EnvironmentFile }
function Get-IseTacacsCommandSet { [CmdletBinding()] param([string]$EnvironmentFile) Invoke-IseBackend -Command tacacs-command-sets -EnvironmentFile $EnvironmentFile }
function Get-IseTacacsShellProfile { [CmdletBinding()] param([string]$EnvironmentFile) Invoke-IseBackend -Command tacacs-shell-profiles -EnvironmentFile $EnvironmentFile }

function Get-IseCertificate {
    [CmdletBinding()]
    param([string]$Node, [switch]$TrustedOnly, [switch]$SystemOnly, [string]$EnvironmentFile)
    $arguments = [System.Collections.Generic.List[string]]::new()
    if ($Node) { [void]$arguments.Add('--node'); [void]$arguments.Add($Node) }
    Add-IseSwitchArgument -Arguments $arguments -Value:$TrustedOnly -Name '--trusted-only'
    Add-IseSwitchArgument -Arguments $arguments -Value:$SystemOnly -Name '--system-only'
    Invoke-IseBackend -Command certificates -ArgumentList $arguments.ToArray() -EnvironmentFile $EnvironmentFile
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

function Get-IseRadiusAuthentication {
    [CmdletBinding()]
    param([string]$Identifier,[string]$Username,[string]$Nad,[ValidateSet('failed','passed','success')][string]$Status,[ValidateRange(1,5000)][int]$Limit=100,[switch]$AllowExpensive,[string]$EnvironmentFile)
    $a=New-IseReportArguments -Limit $Limit -AllowExpensive:$AllowExpensive; Add-IseValueArgument -Arguments $a -Name '--identifier' -Value $Identifier; Add-IseValueArgument -Arguments $a -Name '--username' -Value $Username; Add-IseValueArgument -Arguments $a -Name '--nad' -Value $Nad; Add-IseValueArgument -Arguments $a -Name '--status' -Value $Status
    Invoke-IseBackend -Command radius-auth -ArgumentList $a.ToArray() -EnvironmentFile $EnvironmentFile
}
function Get-IseEndpointReport {
    [CmdletBinding()]
    param([string]$Identifier,[string]$Profile,[ValidateRange(1,5000)][int]$Limit=100,[switch]$AllowExpensive,[string]$EnvironmentFile)
    $a=New-IseReportArguments -Limit $Limit -AllowExpensive:$AllowExpensive; Add-IseValueArgument -Arguments $a -Name '--identifier' -Value $Identifier; Add-IseValueArgument -Arguments $a -Name '--profile' -Value $Profile
    Invoke-IseBackend -Command endpoint-report -ArgumentList $a.ToArray() -EnvironmentFile $EnvironmentFile
}
function Get-IseRadiusError {
    [CmdletBinding()]
    param([string]$Identifier,[string]$Nad,[string]$MessageCode,[ValidateRange(1,5000)][int]$Limit=100,[switch]$AllowExpensive,[string]$EnvironmentFile)
    $a=New-IseReportArguments -Limit $Limit -AllowExpensive:$AllowExpensive; Add-IseValueArgument -Arguments $a -Name '--identifier' -Value $Identifier; Add-IseValueArgument -Arguments $a -Name '--nad' -Value $Nad; Add-IseValueArgument -Arguments $a -Name '--message-code' -Value $MessageCode
    Invoke-IseBackend -Command radius-errors -ArgumentList $a.ToArray() -EnvironmentFile $EnvironmentFile
}
function Get-IseRadiusAccounting {
    [CmdletBinding()]
    param([string]$Identifier,[string]$Username,[string]$Nad,[ValidateRange(1,5000)][int]$Limit=100,[switch]$AllowExpensive,[string]$EnvironmentFile)
    $a=New-IseReportArguments -Limit $Limit -AllowExpensive:$AllowExpensive; Add-IseValueArgument -Arguments $a -Name '--identifier' -Value $Identifier; Add-IseValueArgument -Arguments $a -Name '--username' -Value $Username; Add-IseValueArgument -Arguments $a -Name '--nad' -Value $Nad
    Invoke-IseBackend -Command radius-accounting -ArgumentList $a.ToArray() -EnvironmentFile $EnvironmentFile
}
function Get-IsePostureAssessment {
    [CmdletBinding()]
    param([string]$Identifier,[string]$Status,[switch]$Conditions,[ValidateRange(1,5000)][int]$Limit=100,[switch]$AllowExpensive,[string]$EnvironmentFile)
    $a=New-IseReportArguments -Limit $Limit -AllowExpensive:$AllowExpensive; Add-IseValueArgument -Arguments $a -Name '--identifier' -Value $Identifier; Add-IseValueArgument -Arguments $a -Name '--status' -Value $Status; Add-IseSwitchArgument -Arguments $a -Value:$Conditions -Name '--conditions'
    Invoke-IseBackend -Command posture -ArgumentList $a.ToArray() -EnvironmentFile $EnvironmentFile
}
function Get-IsePsnMetric {
    [CmdletBinding()]
    param([string]$Psn,[ValidateRange(1,5000)][int]$Limit=100,[switch]$AllowExpensive,[string]$EnvironmentFile)
    $a=New-IseReportArguments -Limit $Limit -AllowExpensive:$AllowExpensive; Add-IseValueArgument -Arguments $a -Name '--psn' -Value $Psn
    Invoke-IseBackend -Command psn-metrics -ArgumentList $a.ToArray() -EnvironmentFile $EnvironmentFile
}
function Get-IseTacacsActivity {
    [CmdletBinding()]
    param([string]$Username,[string]$Device,[ValidateSet('authentication','authorization','accounting')][string]$EventType='authentication',[ValidateRange(1,5000)][int]$Limit=100,[switch]$AllowExpensive,[string]$EnvironmentFile)
    $a=New-IseReportArguments -Limit $Limit -AllowExpensive:$AllowExpensive; Add-IseValueArgument -Arguments $a -Name '--username' -Value $Username; Add-IseValueArgument -Arguments $a -Name '--device' -Value $Device; Add-IseValueArgument -Arguments $a -Name '--event-type' -Value $EventType
    Invoke-IseBackend -Command tacacs-activity -ArgumentList $a.ToArray() -EnvironmentFile $EnvironmentFile
}

function Get-IseDataConnectSchema {
    [CmdletBinding()]
    param([Parameter(Position=0)][string]$Table,[string]$EnvironmentFile)
    $arguments = if ($Table) { @($Table) } else { @() }
    Invoke-IseBackend -Command dataconnect-schema -ArgumentList $arguments -EnvironmentFile $EnvironmentFile
}

function Get-IseSchema {
    <# .SYNOPSIS Returns the backend contract for one command or the complete command set. #>
    [CmdletBinding()]
    param([Parameter(Position=0)][string]$Name, [string]$EnvironmentFile)
    $arguments = if ($Name) { @($Name) } else { @() }
    Invoke-IseBackend -Command schema -ArgumentList $arguments -EnvironmentFile $EnvironmentFile
}

function Invoke-IseReadOnlyRequest {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)][ValidateSet('ers','openapi','mnt')][string]$Family,
        [Parameter(Mandatory)][string]$Path,
        [hashtable]$Parameter = @{},
        [switch]$All, [switch]$NoUnwrap, [switch]$AllowExpensive,
        [string]$EnvironmentFile
    )
    $arguments=[System.Collections.Generic.List[string]]::new(); [void]$arguments.Add($Family); [void]$arguments.Add($Path)
    foreach($key in ($Parameter.Keys | Sort-Object)){ [void]$arguments.Add('--param'); [void]$arguments.Add("$key=$($Parameter[$key])") }
    Add-IseSwitchArgument -Arguments $arguments -Value:$All -Name '--all'; Add-IseSwitchArgument -Arguments $arguments -Value:$NoUnwrap -Name '--no-unwrap'; Add-IseSwitchArgument -Arguments $arguments -Value:$AllowExpensive -Name '--allow-expensive'
    Invoke-IseBackend -Command get -ArgumentList $arguments.ToArray() -EnvironmentFile $EnvironmentFile
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
        default { 'endpoint' }
    }
    foreach ($candidate in (Get-IseLegacyCompletion "$legacy $wordToComplete")) {
        [System.Management.Automation.CompletionResult]::new(
            [string]$candidate, ([string]$candidate).Trim(), 'ParameterValue', [string]$candidate)
    }
}
Register-ArgumentCompleter -CommandName @(
    'Get-IseEndpoint','Resolve-IseEndpoint','Get-IseSession',
    'Get-IseAuthenticationStatus','Get-IseSecureClient') -ParameterName Identifier -ScriptBlock $identifierCompleter

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
    $legacy = if ($commandName -eq 'Get-IsePsnMetric') { 'psn-metrics --psn' } else { 'certificates --node' }
    New-IseCompletionResult (Get-IseLegacyCompletion "$legacy $wordToComplete")
}
Register-ArgumentCompleter -CommandName Get-IseCertificate -ParameterName Node -ScriptBlock $nodeCompleter
Register-ArgumentCompleter -CommandName Get-IsePsnMetric -ParameterName Psn -ScriptBlock $nodeCompleter

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
    'Get-IseRadiusAuthentication','Get-IseRadiusError','Get-IseRadiusAccounting'
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
    'Get-IseRadiusAuthentication','Get-IseRadiusAccounting','Get-IseTacacsActivity'
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

Export-ModuleMember -Function @(
    'Invoke-IseCommand','Get-IseCliVersion','Test-IseHealth','Get-IseNode','Find-IseEndpoint',
    'Get-IseEndpointField','Get-IseEndpoint','Resolve-IseEndpoint','Get-IseSession',
    'Get-IseActiveSession','Get-IseAuthenticationStatus','Get-IseSecureClient',
    'Get-IseNetworkDevice','Get-IseProfilerProfile','Get-IseTacacsUser',
    'Get-IseIdentityGroup','Get-IseNetworkDeviceGroup','Get-IseLicense','Get-IsePatch',
    'Get-IseBackupStatus','Get-IseRepository','Get-IseNetworkPolicySet',
    'Get-IseDeviceAdminPolicySet','Get-IseAuthorizationProfile','Get-IseTacacsCommandSet',
    'Get-IseTacacsShellProfile','Get-IseCertificate','Get-IseRadiusAuthentication',
    'Get-IseEndpointReport','Get-IseRadiusError','Get-IseRadiusAccounting',
    'Get-IsePostureAssessment','Get-IsePsnMetric','Get-IseTacacsActivity',
    'Get-IseDataConnectSchema','Get-IseSchema','Invoke-IseReadOnlyRequest'
)
