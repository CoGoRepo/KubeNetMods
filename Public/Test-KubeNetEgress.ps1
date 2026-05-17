function Test-KubeNetEgress {
    [CmdletBinding()]
    param(
        [string]$SourceNamespace = 'default',
        [string]$SourcePodName = '',
        [string]$SourcePodSelector = '',
        [string]$SourceContainer = '',
        [string]$Context = '',
        [string]$KubeCommand = 'kubectl',
        [string[]]$Urls = @(),
        [string]$DebugImage = 'nicolaka/netshoot:latest',
        [ValidateSet('Always', 'IfNotPresent', 'Never')]
        [string]$DebugImagePullPolicy = 'IfNotPresent',
        [string]$SourceDebugPodName = 'kubenetmods-egress-debug',
        [switch]$UseDebugPod,
        [int]$TimeoutSec = 5,
        [string]$ExportJson = '',
        [string]$ExportHtml = '',
        [switch]$PassThru,
        [switch]$Quiet
    )

    $state = New-KubeNetState -KubeCommand $KubeCommand -TargetContext $Context -SourceContext $Context -Quiet:$Quiet
    $sourceExecPodName = ''
    $sourceExecContainer = ''
    $sourcePodObject = $null
    $sourceCanExec = $false

    try {
        $state.KubeCommand = Resolve-KubeNetCommand -KubeCommand $KubeCommand

        if (-not $Quiet) {
            Write-Host 'KubeNetMods egress checker' -ForegroundColor White
            Write-Host "Command:          $($state.KubeCommand)" -ForegroundColor DarkGray
            Write-Host "Context:          $(if ($Context) { $Context } else { '(current)' })" -ForegroundColor DarkGray
            Write-Host "Source namespace: $SourceNamespace" -ForegroundColor DarkGray
        }

        Write-KubeNetSection -State $state -Name 'Source Access' -Description 'Validates the source namespace and selects the pod used for outbound checks.'
        try {
            [void](ConvertFrom-KubeNetJson -State $state -Context $Context -Arguments @('get', 'namespace', $SourceNamespace))
            Add-KubeNetResult -State $state -Layer 'Source Access' -Check 'source namespace' -Status 'PASS' -Message "Source namespace '$SourceNamespace' exists."
        } catch {
            Add-KubeNetResult -State $state -Layer 'Source Access' -Check 'source namespace' -Status 'FAIL' -Message "Source namespace '$SourceNamespace' is not accessible: $($_.Exception.Message)"
            Add-KubeNetDiagnosis -State $state -Message "Cannot access source namespace '$SourceNamespace'. Fix kubeconfig/RBAC/namespace before testing egress."
        }

        if (-not [string]::IsNullOrWhiteSpace($SourcePodName)) {
            $sourceExecPodName = $SourcePodName
            $sourceExecContainer = $SourceContainer
            try {
                $sourcePodObject = ConvertFrom-KubeNetJson -State $state -Context $Context -Arguments @('get', 'pod', $SourcePodName, '-n', $SourceNamespace)
                $sourceCanExec = $true
                Add-KubeNetResult -State $state -Layer 'Source Access' -Check 'source pod selected' -Status 'INFO' -Message "Using supplied source pod '$SourcePodName'."
            } catch {
                Add-KubeNetResult -State $state -Layer 'Source Access' -Check 'source pod selected' -Status 'FAIL' -Message "Could not read supplied source pod '$SourcePodName': $($_.Exception.Message)"
            }
        } elseif (-not [string]::IsNullOrWhiteSpace($SourcePodSelector)) {
            try {
                $sourcePods = ConvertFrom-KubeNetJson -State $state -Context $Context -Arguments @('get', 'pods', '-n', $SourceNamespace, '-l', $SourcePodSelector)
                $readyPods = @($sourcePods.items | Where-Object { $_.status.phase -eq 'Running' -and (Get-KubeNetPodReady -Pod $_) })
                if ($readyPods.Count -gt 0) {
                    $sourcePodObject = $readyPods[0]
                    $sourceExecPodName = $sourcePodObject.metadata.name
                    $sourceExecContainer = $SourceContainer
                    $sourceCanExec = $true
                    Add-KubeNetResult -State $state -Layer 'Source Access' -Check 'source pod selected' -Status 'INFO' -Message "Using source pod '$sourceExecPodName' selected by '$SourcePodSelector'."
                } else {
                    Add-KubeNetResult -State $state -Layer 'Source Access' -Check 'source pod selected' -Status 'FAIL' -Message "No running Ready source pod matched selector '$SourcePodSelector'."
                }
            } catch {
                Add-KubeNetResult -State $state -Layer 'Source Access' -Check 'source pod selected' -Status 'FAIL' -Message "Could not select source pod with selector '$SourcePodSelector': $($_.Exception.Message)"
            }
        } elseif ($UseDebugPod) {
            $sourceExecPodName = $SourceDebugPodName
            $sourceCanExec = Ensure-KubeNetDebugPod -State $state -Context $Context -Namespace $SourceNamespace -Name $SourceDebugPodName -Image $DebugImage -ImagePullPolicy $DebugImagePullPolicy -TimeoutSec $TimeoutSec -Layer 'Source debug pod'
            if ($sourceCanExec) {
                try {
                    $sourcePodObject = ConvertFrom-KubeNetJson -State $state -Context $Context -Arguments @('get', 'pod', $SourceDebugPodName, '-n', $SourceNamespace)
                } catch { }
            }
        } else {
            Add-KubeNetResult -State $state -Layer 'Source Access' -Check 'source path' -Status 'FAIL' -Message 'No source workload pod was provided and debug pod creation is disabled. Provide -SourcePodName, -SourcePodSelector, or -UseDebugPod.'
            Add-KubeNetDiagnosis -State $state -Message 'No executable source path was available for egress testing.'
        }

        if ($sourceCanExec) {
            Write-KubeNetSection -State $state -Name 'Source DNS' -Description 'Reads runtime resolver data before outbound URL tests.'
            $resolv = Invoke-KubeNetInPod -State $state -Context $Context -Namespace $SourceNamespace -PodName $sourceExecPodName -Container $sourceExecContainer -Command 'cat /etc/resolv.conf'
            if ($resolv.ExitCode -eq 0) {
                $summary = Get-KubeNetResolvConfSummary -Text $resolv.Text
                Add-KubeNetResult -State $state -Layer 'Source DNS' -Check 'resolv.conf' -Status 'PASS' -Message "Runtime nameserver(s): $(Format-KubeNetList $summary.Nameservers); search domains: $(Format-KubeNetList $summary.Searches)" -Data $resolv.Text
            } else {
                Add-KubeNetResult -State $state -Layer 'Source DNS' -Check 'resolv.conf' -Status 'WARN' -Message "Could not read /etc/resolv.conf from source pod '$sourceExecPodName'."
            }
        }

        Write-KubeNetSection -State $state -Name 'External Egress' -Description 'Tests DNS and HTTP/TCP reachability from the selected source pod to explicit external URLs.'
        if ($Urls.Count -eq 0) {
            Add-KubeNetResult -State $state -Layer 'External Egress' -Check 'urls' -Status 'FAIL' -Message 'No -Urls were supplied for egress testing.'
            Add-KubeNetDiagnosis -State $state -Message 'No external egress target was supplied. Provide one or more URLs to test outbound connectivity.'
        } elseif ($sourceCanExec) {
            foreach ($url in $Urls) {
                $host = ''
                try { $host = ([System.Uri]$url).Host } catch { }
                if ([string]::IsNullOrWhiteSpace($host)) {
                    Add-KubeNetResult -State $state -Layer 'External Egress' -Check $url -Status 'FAIL' -Message "URL '$url' is not a valid absolute URL."
                    continue
                }

                $dns = Invoke-KubeNetInPod -State $state -Context $Context -Namespace $SourceNamespace -PodName $sourceExecPodName -Container $sourceExecContainer -Command "nslookup $host"
                if ($dns.ExitCode -eq 0) {
                    Add-KubeNetResult -State $state -Layer 'External Egress' -Check "resolve $host" -Status 'PASS' -Message "Source pod '$sourceExecPodName' resolved '$host'."
                } else {
                    Add-KubeNetResult -State $state -Layer 'External Egress' -Check "resolve $host" -Status 'FAIL' -Message "Source pod '$sourceExecPodName' could not resolve '$host'."
                    Add-KubeNetDiagnosis -State $state -Message "External DNS resolution failed for '$host' from source pod '$sourceExecPodName'. Check DNS policy, CoreDNS/NodeLocalDNS, egress DNS policy, proxy, or upstream resolver access."
                }

                $curl = Invoke-KubeNetInPod -State $state -Context $Context -Namespace $SourceNamespace -PodName $sourceExecPodName -Container $sourceExecContainer -Command "curl -k -sS -o /dev/null -w 'HTTP_STATUS=%{http_code}' --connect-timeout $TimeoutSec --max-time $TimeoutSec '$url'"
                if ($curl.ExitCode -eq 0) {
                    Add-KubeNetResult -State $state -Layer 'External Egress' -Check $url -Status 'PASS' -Message "Source pod '$sourceExecPodName' reached '$url'. HTTP status: $(Get-KubeNetHttpStatusFromText $curl.Text)"
                } else {
                    Add-KubeNetResult -State $state -Layer 'External Egress' -Check $url -Status 'FAIL' -Message "Source pod '$sourceExecPodName' could not reach '$url'."
                    Add-KubeNetDiagnosis -State $state -Message "External egress to '$url' failed from source pod '$sourceExecPodName'. Check egress NetworkPolicy/CNI policy, DNS, firewall, NAT gateway, proxy, route tables, or cloud security controls."
                }
            }
        }
    } finally {
        Remove-KubeNetDebugPods -State $state
    }

    $metadata = [ordered]@{
        Command              = 'Test-KubeNetEgress'
        SourceNamespace      = $SourceNamespace
        SourcePodName        = $SourcePodName
        SourcePodSelector    = $SourcePodSelector
        Context              = $Context
        KubeCommand          = $state.KubeCommand
        Urls                 = @($Urls)
        UseDebugPod          = [bool]$UseDebugPod
        DebugImage           = $DebugImage
        DebugImagePullPolicy = $DebugImagePullPolicy
        SourceDebugPodName   = $SourceDebugPodName
    }

    New-KubeNetReport -State $state -Metadata $metadata -Mode Egress -ExportJson $ExportJson -ExportHtml $ExportHtml -PassThru:$PassThru -Quiet:$Quiet
}
