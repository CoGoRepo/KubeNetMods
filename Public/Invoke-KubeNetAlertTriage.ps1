function Invoke-KubeNetAlertTriage {
    [CmdletBinding(DefaultParameterSetName = 'Path')]
    param(
        [Parameter(Mandatory, ParameterSetName = 'Path')]
        [string]$Path,

        [Parameter(Mandatory, ParameterSetName = 'Json')]
        [string]$Json,

        [Parameter(Mandatory, ValueFromPipeline, ParameterSetName = 'InputObject')]
        [object]$InputObject,

        [ValidateSet('Auto', 'Alertmanager', 'Grafana', 'Datadog', 'NewRelic', 'Generic')]
        [string]$Provider = 'Auto',

        [string]$ExportHtml = '',
        [string]$ExportJson = '',
        [switch]$PreviewOnly,
        [switch]$Force,
        [switch]$PassThru,
        [switch]$Quiet
    )

    process {
        $alerts = @()
        if ($PSCmdlet.ParameterSetName -eq 'Path') {
            $alerts = @(ConvertTo-KubeNetAlert -Path $Path -Provider $Provider)
        } elseif ($PSCmdlet.ParameterSetName -eq 'Json') {
            $alerts = @(ConvertTo-KubeNetAlert -Json $Json -Provider $Provider)
        } else {
            $alerts = @(ConvertTo-KubeNetAlert -InputObject $InputObject -Provider $Provider)
        }

        $outputs = @()
        for ($i = 0; $i -lt $alerts.Count; $i++) {
            $plan = ConvertTo-KubeNetParameterPlan -Alert $alerts[$i]
            if (-not $Quiet) {
                Write-Host "KubeNet alert triage: $($plan.AlertName)" -ForegroundColor White
                Write-Host "Provider:   $($plan.Provider)" -ForegroundColor DarkGray
                Write-Host "Category:   $($plan.Category)" -ForegroundColor DarkGray
                Write-Host "Confidence: $($plan.Confidence)" -ForegroundColor DarkGray
                Write-Host "In scope:   $($plan.InScope)  Can run: $($plan.CanRun)" -ForegroundColor DarkGray
                Write-Host "Reason:     $($plan.Reason)" -ForegroundColor DarkGray
                Write-Host "Command:    $($plan.CommandPreview)" -ForegroundColor DarkGray
            }

            $missingRequired = @($plan.MissingFields).Count -gt 0
            if ($PreviewOnly -or $missingRequired -or (-not $plan.InScope -and -not $Force)) {
                if (-not $Quiet -and $missingRequired) {
                    Write-Host "No diagnostic run started. Missing: $((@($plan.MissingFields) -join ', '))" -ForegroundColor Yellow
                } elseif (-not $Quiet -and -not $plan.InScope) {
                    Write-Host "No diagnostic run started. Alert is outside KubeNet's network-focused scope." -ForegroundColor Yellow
                }
                $outputs += [PSCustomObject]@{
                    Alert  = $alerts[$i]
                    Plan   = $plan
                    Report = $null
                    Ran    = $false
                }
                continue
            }

            $params = @{}
            foreach ($key in $plan.Parameters.Keys) {
                $params[$key] = $plan.Parameters[$key]
            }
            $htmlPath = Resolve-KubeNetIndexedPath -Path $ExportHtml -Index $i -Total $alerts.Count
            $jsonPath = Resolve-KubeNetIndexedPath -Path $ExportJson -Index $i -Total $alerts.Count
            if (-not [string]::IsNullOrWhiteSpace($htmlPath)) { $params.ExportHtml = $htmlPath }
            if (-not [string]::IsNullOrWhiteSpace($jsonPath)) { $params.ExportJson = $jsonPath }
            $params.PassThru = $true
            if ($Quiet) { $params.Quiet = $true }

            $report = switch ($plan.Command) {
                'Test-KubeNetEgress' { Test-KubeNetEgress @params }
                'Test-KubeNetIngress' { Test-KubeNetIngress @params }
                default { Test-KubeNetService @params }
            }
            $outputs += [PSCustomObject]@{
                Alert  = $alerts[$i]
                Plan   = $plan
                Report = $report
                Ran    = $true
            }
        }

        if ($PassThru -or $PreviewOnly) {
            $outputs
        }
    }
}
