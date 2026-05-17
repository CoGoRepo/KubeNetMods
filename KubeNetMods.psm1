$moduleRoot = $PSScriptRoot

foreach ($folder in @('Private', 'Reports', 'Public')) {
    $folderPath = Join-Path $moduleRoot $folder
    if (-not (Test-Path -LiteralPath $folderPath)) { continue }
    Get-ChildItem -LiteralPath $folderPath -Filter '*.ps1' | Sort-Object Name | ForEach-Object {
        . $_.FullName
    }
}

Export-ModuleMember -Function @(
    'ConvertTo-KubeNetAlert',
    'ConvertTo-KubeNetServiceParameters',
    'Invoke-KubeNetAlertTriage',
    'Test-KubeNetEgress',
    'Test-KubeNetIngress',
    'Test-KubeNetService'
)
