function ConvertTo-KubeNetServiceParameters {
    [CmdletBinding(DefaultParameterSetName = 'Alert')]
    param(
        [Parameter(Mandatory, ValueFromPipeline, ParameterSetName = 'Alert')]
        [object]$Alert,

        [Parameter(Mandatory, ParameterSetName = 'Path')]
        [string]$Path,

        [Parameter(Mandatory, ParameterSetName = 'Json')]
        [string]$Json,

        [ValidateSet('Auto', 'Alertmanager', 'Grafana', 'Datadog', 'NewRelic', 'Generic')]
        [string]$Provider = 'Auto'
    )

    process {
        $alerts = @()
        if ($PSCmdlet.ParameterSetName -eq 'Path') {
            $alerts = @(ConvertTo-KubeNetAlert -Path $Path -Provider $Provider)
        } elseif ($PSCmdlet.ParameterSetName -eq 'Json') {
            $alerts = @(ConvertTo-KubeNetAlert -Json $Json -Provider $Provider)
        } else {
            $alerts = @($Alert)
        }

        foreach ($item in $alerts) {
            ConvertTo-KubeNetParameterPlan -Alert $item
        }
    }
}
