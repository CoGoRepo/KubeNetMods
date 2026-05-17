function Test-KubeNetIngress {
    [CmdletBinding()]
    param(
        [string]$TargetNamespace = 'default',
        [string]$TargetService = 'nginx',
        [string]$DeploymentName = '',
        [int]$TargetPort = 0,
        [string]$UrlScheme = 'http',
        [string]$UrlPath = '/',
        [string]$TargetPodSelector = '',
        [string]$Context = '',
        [string]$KubeCommand = 'kubectl',
        [string[]]$IngressUrls = @(),
        [string[]]$ExternalUrls = @(),
        [switch]$TestLoadBalancer,
        [switch]$UseDebugPod,
        [string]$DebugImage = 'nicolaka/netshoot:latest',
        [ValidateSet('Always', 'IfNotPresent', 'Never')]
        [string]$DebugImagePullPolicy = 'IfNotPresent',
        [string]$TargetDebugPodName = 'kubenetmods-ingress-debug',
        [int]$TimeoutSec = 5,
        [string]$ExportJson = '',
        [string]$ExportHtml = '',
        [switch]$PassThru,
        [switch]$Quiet
    )

    $baseParams = @{
        TargetNamespace      = $TargetNamespace
        TargetService        = $TargetService
        DeploymentName       = $DeploymentName
        TargetPort           = $TargetPort
        UrlScheme            = $UrlScheme
        UrlPath              = $UrlPath
        TargetPodSelector    = $TargetPodSelector
        Context              = $Context
        KubeCommand          = $KubeCommand
        TargetOnly           = $true
        Quiet                = $true
        PassThru             = $true
        TimeoutSec           = $TimeoutSec
        DebugImage           = $DebugImage
        DebugImagePullPolicy = $DebugImagePullPolicy
        TargetDebugPodName   = $TargetDebugPodName
    }
    if ($UseDebugPod) { $baseParams.UseDebugPod = $true }

    $baseReport = Test-KubeNetService @baseParams
    $state = New-KubeNetState -KubeCommand $KubeCommand -TargetContext $Context -SourceContext $Context -Quiet:$Quiet
    $state.KubeCommand = Resolve-KubeNetCommand -KubeCommand $KubeCommand

    foreach ($result in @($baseReport.RawResults)) {
        $state.Results.Add($result) | Out-Null
    }
    foreach ($diagnosis in @($baseReport.Diagnoses)) {
        Add-KubeNetDiagnosis -State $state -Message $diagnosis
    }

    if (-not $Quiet) {
        Write-Host 'KubeNetMods ingress checker' -ForegroundColor White
        Write-Host "Command:          $($state.KubeCommand)" -ForegroundColor DarkGray
        Write-Host "Context:          $(if ($Context) { $Context } else { '(current)' })" -ForegroundColor DarkGray
        Write-Host "Target namespace: $TargetNamespace" -ForegroundColor DarkGray
        Write-Host "Target service:   $TargetService" -ForegroundColor DarkGray
    }

    Write-KubeNetSection -State $state -Name 'Ingress Reachability Layer' -Description 'Tests explicit ingress URLs from the local host.'
    if ($IngressUrls.Count -eq 0) {
        Add-KubeNetResult -State $state -Layer 'Ingress Reachability Layer' -Check 'ingress urls' -Status 'SKIP' -Message 'No -IngressUrls were supplied.'
    } else {
        foreach ($url in $IngressUrls) {
            $test = Test-KubeNetLocalHttp -Url $url -TimeoutSec $TimeoutSec
            Add-KubeNetResult -State $state -Layer 'Ingress Reachability Layer' -Check $url -Status $(if ($test.Ok) { 'PASS' } else { 'FAIL' }) -Message "$(if ($test.Ok) { "Reachable. HTTP status: $($test.StatusCode)" } else { "Failed: $($test.Error)" })"
            if (-not $test.Ok) {
                Add-KubeNetDiagnosis -State $state -Message "Ingress URL '$url' failed from the local host. Check DNS, load balancer, ingress controller, TLS, host/path rules, and backend service mapping."
            }
        }
    }

    Write-KubeNetSection -State $state -Name 'External Load Balancing Layer' -Description 'Tests explicit external addresses and LoadBalancer status addresses from the local host.'
    $targetsToTest = @($ExternalUrls)
    if ($TestLoadBalancer) {
        try {
            $service = ConvertFrom-KubeNetJson -State $state -Context $Context -Arguments @('get', 'service', $TargetService, '-n', $TargetNamespace)
            if ($service.spec.type -eq 'LoadBalancer') {
                foreach ($address in @($service.status.loadBalancer.ingress | ForEach-Object { if ($_.ip) { $_.ip } elseif ($_.hostname) { $_.hostname } })) {
                    foreach ($port in @($service.spec.ports | ForEach-Object { $_.port })) {
                        $targetsToTest += "$UrlScheme`://$address`:$port$(Get-KubeNetUrlPath -UrlPath $UrlPath)"
                    }
                }
            } else {
                Add-KubeNetResult -State $state -Layer 'External Load Balancing Layer' -Check 'service type' -Status 'SKIP' -Message "Service '$TargetService' is type $($service.spec.type), not LoadBalancer."
            }
        } catch {
            Add-KubeNetResult -State $state -Layer 'External Load Balancing Layer' -Check 'service read' -Status 'WARN' -Message "Could not inspect service '$TargetService' for LoadBalancer addresses: $($_.Exception.Message)"
        }
    }

    if ($targetsToTest.Count -eq 0) {
        Add-KubeNetResult -State $state -Layer 'External Load Balancing Layer' -Check 'external targets' -Status 'SKIP' -Message 'No explicit external URLs or LoadBalancer addresses were available to test.'
    } else {
        foreach ($url in ($targetsToTest | Sort-Object -Unique)) {
            $test = Test-KubeNetLocalHttp -Url $url -TimeoutSec $TimeoutSec
            Add-KubeNetResult -State $state -Layer 'External Load Balancing Layer' -Check $url -Status $(if ($test.Ok) { 'PASS' } else { 'FAIL' }) -Message "$(if ($test.Ok) { "Reachable. HTTP status: $($test.StatusCode)" } else { "Failed: $($test.Error)" })"
            if (-not $test.Ok) {
                Add-KubeNetDiagnosis -State $state -Message "External target '$url' failed from the local host. Check load balancer provisioning, firewall/security groups, DNS, listener ports, and backend health."
            }
        }
    }

    $metadata = [ordered]@{
        Command              = 'Test-KubeNetIngress'
        TargetNamespace      = $TargetNamespace
        TargetService        = $TargetService
        Deployment           = if ([string]::IsNullOrWhiteSpace($DeploymentName)) { $TargetService } else { $DeploymentName }
        TargetPort           = $TargetPort
        UrlScheme            = $UrlScheme
        UrlPath              = $UrlPath
        Context              = $Context
        KubeCommand          = $state.KubeCommand
        IngressUrls          = @($IngressUrls)
        ExternalUrls         = @($ExternalUrls)
        TestLoadBalancer     = [bool]$TestLoadBalancer
        UseDebugPod          = [bool]$UseDebugPod
        DebugImage           = $DebugImage
        DebugImagePullPolicy = $DebugImagePullPolicy
        TargetDebugPodName   = $TargetDebugPodName
    }

    New-KubeNetReport -State $state -Metadata $metadata -Mode Ingress -ExportJson $ExportJson -ExportHtml $ExportHtml -PassThru:$PassThru -Quiet:$Quiet
}
