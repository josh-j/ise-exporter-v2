@{
    RootModule = 'Ise.Cli.psm1'
    ModuleVersion = '2.0.0'
    GUID = '76078ed9-aaef-45ca-b5d4-8f0fce74f311'
    Author = 'ise-exporter contributors'
    CompanyName = 'Community'
    Copyright = '(c) ise-exporter contributors'
    Description = 'PowerShell 7 operator commands for Cisco ISE 3.3 Patch 11.'
    PowerShellVersion = '7.2'
    CompatiblePSEditions = @('Core')
    FunctionsToExport = @(
        'Invoke-IseCommand',
        'Get-IseCliVersion',
        'Get-IseOverview',
        'Get-IseCollectorStatus',
        'Get-IseEndpointSummary',
        'Debug-IseAuthentication',
        'Debug-IsePsn',
        'Get-IseNadSummary',
        'Get-IsePxGridStatus',
        'Test-IseHealth',
        'Get-IseNode',
        'Find-IseEndpoint',
        'Get-IseEndpointField',
        'Get-IseEndpoint',
        'Resolve-IseEndpoint',
        'Get-IseSession',
        'Get-IseActiveSession',
        'Get-IseAuthenticationStatus',
        'Get-IseSecureClient',
        'Get-IseNetworkDevice',
        'Get-IseProfilerProfile',
        'Get-IseTacacsUser',
        'Get-IseIdentityGroup',
        'Get-IseNetworkDeviceGroup',
        'Get-IseLicense',
        'Get-IsePatch',
        'Get-IseBackupStatus',
        'Get-IseRepository',
        'Get-IseNetworkPolicySet',
        'Get-IseDeviceAdminPolicySet',
        'Get-IseAuthorizationProfile',
        'Get-IseTacacsCommandSet',
        'Get-IseTacacsShellProfile',
        'Get-IseCertificate',
        'Get-IseRadiusAuthentication',
        'Get-IseEndpointReport',
        'Get-IseRadiusError',
        'Get-IseRadiusAccounting',
        'Get-IsePostureAssessment',
        'Get-IsePsnMetric',
        'Get-IseTacacsActivity',
        'Get-IseDataConnectSchema',
        'Get-IseSchema',
        'Invoke-IseReadOnlyRequest'
    )
    CmdletsToExport = @()
    VariablesToExport = @()
    AliasesToExport = @('Find-Endpoint')
    PrivateData = @{
        PSData = @{
            Tags = @('Cisco', 'ISE', 'Security', 'Operations')
            ProjectUri = 'https://github.com/josh-j/ise-exporter-v2'
        }
    }
}
