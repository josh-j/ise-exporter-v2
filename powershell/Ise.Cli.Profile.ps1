$ErrorActionPreference = 'Stop'

Import-Module Ise.Cli -ErrorAction Stop

function global:Show-IseCliHelp {
    @'
ISE CLI quick start

  Find-Endpoint VALUE              Find endpoints by MAC, IP, hostname, ID, or pattern
  Get-IseEndpoint VALUE            Get one endpoint and its current context
  Get-IseActiveSession             Show active sessions
  Get-IseAuthenticationStatus ID   Inspect recent RADIUS authentication
  Get-IseSecureClient VALUE        Inspect Secure Client posture details
  Test-IseHealth                   Check configured ISE connectivity

PowerShell objects flow through the normal pipeline:

  Find-Endpoint 'LAB-*' | Format-Table
  Find-Endpoint '*LAPTOP*' | Select-Object hostname, mac_address, posture_status
  Get-Command -Module Ise.Cli
  Get-Help Find-IseEndpoint -Full
'@ | Write-Host
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
Write-Host 'ISE CLI ready. Try Find-Endpoint, ise-help, or Get-Command -Module Ise.Cli.'
