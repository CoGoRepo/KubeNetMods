@{
    RootModule        = 'KubeNetMods.psm1'
    ModuleVersion     = '0.2.0'
    GUID              = 'd53bc721-0f9c-4ed5-bb16-8d01a3f64a86'
    Author            = 'CoGoRepo'
    CompanyName       = 'CoGoRepo'
    Copyright         = '(c) 2026 CoGoRepo. All rights reserved.'
    Description       = 'PowerShell Kubernetes network and network-adjacent troubleshooting module.'
    PowerShellVersion = '5.1'
    FunctionsToExport = @(
        'ConvertTo-KubeNetAlert',
        'ConvertTo-KubeNetServiceParameters',
        'Invoke-KubeNetAlertTriage',
        'Test-KubeNetEgress',
        'Test-KubeNetIngress',
        'Test-KubeNetService'
    )
    CmdletsToExport   = @()
    VariablesToExport = '*'
    AliasesToExport   = @()
    PrivateData       = @{
        PSData = @{
            Tags       = @('Kubernetes', 'Networking', 'Troubleshooting', 'kubectl')
            ProjectUri = 'https://github.com/CoGoRepo/KubeNetMods'
        }
    }
}
