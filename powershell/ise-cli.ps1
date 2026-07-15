#!/usr/bin/env pwsh
[CmdletBinding()]
param(
    [Parameter(Position = 0, ValueFromRemainingArguments)]
    [string[]]$CommandArgument = @()
)

$ErrorActionPreference = 'Stop'
Import-Module (Join-Path $PSScriptRoot 'Ise.Cli/Ise.Cli.psd1') -Force

if ($CommandArgument.Count -eq 0) {
    Write-Host 'ISE PowerShell commands are loaded. Examples:'
    Write-Host '  Find-IseEndpoint LAB-*'
    Write-Host '  Get-IseRadiusAuthentication -Status failed | Format-Table'
    Write-Host '  Get-Command -Module Ise.Cli'
    return
}

$configFile = $null
$legacyArguments = [System.Collections.Generic.List[string]]::new()
for ($index = 0; $index -lt $CommandArgument.Count; $index++) {
    if ($CommandArgument[$index] -eq '--config') {
        if ($index + 1 -ge $CommandArgument.Count) {
            throw '--config requires a path'
        }
        $configFile = $CommandArgument[++$index]
    }
    elseif ($CommandArgument[$index] -match '^--config=(.+)$') {
        $configFile = $Matches[1]
    }
    else {
        [void]$legacyArguments.Add($CommandArgument[$index])
    }
}

if ($legacyArguments.Count -eq 0) {
    throw 'a command is required when ise-cli is invoked with arguments'
}
if ($legacyArguments[0] -in @('--version', '-v')) {
    Get-IseCliVersion
    return
}

$name = $legacyArguments[0]
$remaining = if ($legacyArguments.Count -gt 1) {
    $legacyArguments.GetRange(1, $legacyArguments.Count - 1).ToArray()
} else { @() }
if ($name -in @('--help', '-h', 'help')) {
    if ($remaining.Count -gt 0 -and $remaining[0] -notin @('--help', '-h')) {
        $name = $remaining[0]
        $remaining = @('--help')
    }
    else {
        Get-Command -Module Ise.Cli | Sort-Object Name | Format-Table Name, CommandType
        Write-Host 'Use Get-Help COMMAND -Full for PowerShell parameter help.'
        Write-Host 'Use ise-cli COMMAND --help for compatibility subcommand help.'
        return
    }
    $helpText = Invoke-IseCommand -Name $name -ArgumentList $remaining `
        -ConfigFile $configFile -Raw
    [Console]::Out.Write($helpText)
    return
}
if ($remaining -contains '--help' -or $remaining -contains '-h') {
    $helpText = Invoke-IseCommand -Name $name -ArgumentList $remaining `
        -ConfigFile $configFile -Raw
    [Console]::Out.Write($helpText)
    return
}
$output = 'table'
$backendArguments = [System.Collections.Generic.List[string]]::new()
for ($index = 0; $index -lt $remaining.Count; $index++) {
    if ($remaining[$index] -in @('--output', '-o') -and $index + 1 -lt $remaining.Count) {
        $output = $remaining[$index + 1]
        $index++
    }
    elseif ($remaining[$index] -match '^(?:--output|-o)=(.+)$') {
        $output = $Matches[1]
    }
    else {
        [void]$backendArguments.Add($remaining[$index])
    }
}

$result = Invoke-IseCommand -Name $name -ArgumentList $backendArguments.ToArray() `
    -ConfigFile $configFile
switch ($output) {
    'json' { $result | ConvertTo-Json -Depth 100 }
    'jsonl' { $result | ForEach-Object { $_ | ConvertTo-Json -Depth 100 -Compress } }
    'csv' { $result | ConvertTo-Csv -NoTypeInformation }
    default { $result | Format-Table }
}
