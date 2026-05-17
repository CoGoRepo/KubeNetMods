function New-KubeNetReport {
    param(
        [object]$State,
        [hashtable]$Metadata,
        [ValidateSet('Service', 'Egress', 'Ingress')]
        [string]$Mode = 'Service',
        [string]$ExportJson = '',
        [string]$ExportHtml = '',
        [switch]$PassThru,
        [switch]$Quiet
    )

    $allResults = @($State.Results)
    $failures = @($allResults | Where-Object { $_.Status -eq 'FAIL' })
    $warnings = @($allResults | Where-Object { $_.Status -eq 'WARN' })
    $summary = @($allResults | Group-Object Status | Sort-Object Name | ForEach-Object { [PSCustomObject]@{ Status = $_.Name; Count = $_.Count } })
    $exitCode = if ($failures.Count -gt 0) { 1 } else { 0 }
    $finalDiagnoses = @(Get-KubeNetFinalDiagnoses -Diagnoses @($State.Diagnoses) -Results $allResults -Mode $Mode)

    if (-not $Metadata.ContainsKey('Timestamp')) {
        $Metadata.Timestamp = (Get-Date).ToString('o')
    }

    $report = [PSCustomObject]@{
        Target        = [PSCustomObject]$Metadata
        Diagnoses     = $finalDiagnoses
        StatusSummary = $summary
        Failures      = @($failures | Select-Object Layer, Check, Status, Message, Data)
        Warnings      = @($warnings | Select-Object Layer, Check, Status, Message, Data)
        RawResults    = $allResults
        ExitCode      = $exitCode
    }

    if (-not $Quiet) {
        Write-KubeNetSection -State $State -Name 'Summary'
        foreach ($item in $summary) { Write-Host "$($item.Status): $($item.Count)" }
        Write-KubeNetSection -State $State -Name 'Diagnosis'
        if ($finalDiagnoses.Count -eq 0) {
            Write-Host 'No dominant diagnosis inferred.' -ForegroundColor Green
        } else {
            foreach ($diagnosis in $finalDiagnoses) { Write-Host " - $diagnosis" -ForegroundColor Yellow }
        }
    }

    if (-not [string]::IsNullOrWhiteSpace($ExportJson)) {
        $report | ConvertTo-Json -Depth 30 | Set-Content -LiteralPath $ExportJson -Encoding UTF8
        if (-not $Quiet) { Write-Host "JSON report written to $ExportJson" -ForegroundColor Green }
    }

    if (-not [string]::IsNullOrWhiteSpace($ExportHtml)) {
        Export-KubeNetHtml -Report $report -Path $ExportHtml
        if (-not $Quiet) { Write-Host "HTML report written to $ExportHtml" -ForegroundColor Green }
    }

    if ($PassThru) { return $report }
    if ($exitCode -ne 0) { $global:LASTEXITCODE = $exitCode }
}
