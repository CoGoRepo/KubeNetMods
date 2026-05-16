function ConvertTo-KubeNetAlert {
    [CmdletBinding(DefaultParameterSetName = 'Path')]
    param(
        [Parameter(Mandatory, ParameterSetName = 'Path')]
        [string]$Path,

        [Parameter(Mandatory, ParameterSetName = 'Json')]
        [string]$Json,

        [Parameter(Mandatory, ValueFromPipeline, ParameterSetName = 'InputObject')]
        [object]$InputObject,

        [ValidateSet('Auto', 'Alertmanager', 'Grafana', 'Datadog', 'NewRelic', 'Generic')]
        [string]$Provider = 'Auto'
    )

    process {
        $payload = $null
        if ($PSCmdlet.ParameterSetName -eq 'Path') {
            $payload = Get-Content -LiteralPath $Path -Raw | ConvertFrom-Json
        } elseif ($PSCmdlet.ParameterSetName -eq 'Json') {
            $payload = $Json | ConvertFrom-Json
        } else {
            $payload = $InputObject
        }

        ConvertFrom-KubeNetAlertPayload -Payload $payload -Provider $Provider
    }
}
