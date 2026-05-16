function Get-KubeNetOptionalJsonList {
    param(
        [object]$State,
        [string]$Context,
        [string[]]$Arguments
    )

    $result = Invoke-KubeNetKubectl -State $State -Context $Context -Arguments $Arguments -AllowFailure
    if ($result.ExitCode -ne 0 -or [string]::IsNullOrWhiteSpace($result.Text)) {
        return @()
    }

    try {
        $json = $result.Text | ConvertFrom-Json
        if ($json.items) { return @($json.items) }
        return @($json)
    } catch {
        return @()
    }
}

function Get-KubeNetPathPorts {
    param([object]$ServicePortObject, [object[]]$ContainerPorts)

    $ports = @(Get-KubeNetConnectionPortCandidates -ServicePortObject $ServicePortObject -ContainerPorts $ContainerPorts)
    @($ports | Where-Object { $_ -gt 0 } | Sort-Object -Unique)
}

function Test-KubeNetCniPortMatch {
    param([object[]]$PortRules, [int[]]$Ports)

    $portsToCheck = @($Ports | Where-Object { $_ -gt 0 } | Sort-Object -Unique)
    if ($null -eq $PortRules -or @($PortRules).Count -eq 0) { return $true }
    if ($portsToCheck.Count -eq 0) { return $true }

    foreach ($rule in @($PortRules | Where-Object { $null -ne $_ })) {
        $portValue = if ($null -ne $rule.port) { [string]$rule.port } elseif ($null -ne $rule.Port) { [string]$rule.Port } else { '' }
        if ([string]::IsNullOrWhiteSpace($portValue)) { return $true }
        $number = 0
        if ([int]::TryParse($portValue, [ref]$number) -and ($portsToCheck -contains $number)) {
            return $true
        }
    }
    $false
}

function Test-KubeNetCniSpecificPolicyPath {
    param(
        [object]$State,
        [string]$Context,
        [string]$CniProviderGuess,
        [object]$SourcePod,
        [object]$SourceNamespace,
        [object[]]$TargetPods,
        [object]$TargetNamespace,
        [object]$Service,
        [object]$ServicePortObject,
        [object[]]$ContainerPorts,
        [object]$SourceResolvSummary = $null,
        [object[]]$CoreDnsPods = @(),
        [object[]]$NodeLocalDnsPods = @(),
        [object]$KubeSystemNamespace = $null,
        [string]$CoreDnsServiceIp = ''
    )

    if ($null -eq $SourcePod -or $null -eq $SourceNamespace -or $null -eq $TargetNamespace -or @($TargetPods).Count -eq 0 -or $null -eq $Service) {
        return [PSCustomObject]@{
            Results = @([PSCustomObject]@{ Check = 'CNI policy path'; Status = 'SKIP'; Message = 'Skipped CNI-specific policy analysis because source pod, target pods, service, or namespace metadata was unavailable.' })
            Diagnoses = @()
        }
    }

    $ports = Get-KubeNetPathPorts -ServicePortObject $ServicePortObject -ContainerPorts $ContainerPorts
    $results = @()
    $diagnoses = @()

    $ciliumPolicies = @()
    $ciliumPolicies += Get-KubeNetOptionalJsonList -State $State -Context $Context -Arguments @('get', 'ciliumnetworkpolicies.cilium.io', '-A', '-o', 'json')
    $ciliumPolicies += Get-KubeNetOptionalJsonList -State $State -Context $Context -Arguments @('get', 'ciliumclusterwidenetworkpolicies.cilium.io', '-o', 'json')
    if ($ciliumPolicies.Count -gt 0 -or $CniProviderGuess -match 'Cilium') {
        $cilium = Test-KubeNetCiliumPolicyPath -Policies $ciliumPolicies -SourcePod $SourcePod -SourceNamespace $SourceNamespace -TargetPods $TargetPods -TargetNamespace $TargetNamespace -Service $Service -Ports $ports
        $results += @($cilium.Results)
        $diagnoses += @($cilium.Diagnoses)
    }

    $calicoPolicies = @()
    $calicoPolicies += Get-KubeNetOptionalJsonList -State $State -Context $Context -Arguments @('get', 'networkpolicies.crd.projectcalico.org', '-A', '-o', 'json')
    $calicoPolicies += Get-KubeNetOptionalJsonList -State $State -Context $Context -Arguments @('get', 'globalnetworkpolicies.crd.projectcalico.org', '-o', 'json')
    $calicoPolicies += Get-KubeNetOptionalJsonList -State $State -Context $Context -Arguments @('get', 'stagednetworkpolicies.crd.projectcalico.org', '-A', '-o', 'json')
    $calicoPolicies += Get-KubeNetOptionalJsonList -State $State -Context $Context -Arguments @('get', 'stagedglobalnetworkpolicies.crd.projectcalico.org', '-o', 'json')
    $calicoNetworkSets = @()
    $calicoNetworkSets += Get-KubeNetOptionalJsonList -State $State -Context $Context -Arguments @('get', 'networksets.crd.projectcalico.org', '-A', '-o', 'json')
    $calicoNetworkSets += Get-KubeNetOptionalJsonList -State $State -Context $Context -Arguments @('get', 'globalnetworksets.crd.projectcalico.org', '-o', 'json')
    $calicoTiers = Get-KubeNetOptionalJsonList -State $State -Context $Context -Arguments @('get', 'tiers.crd.projectcalico.org', '-o', 'json')
    if ($calicoPolicies.Count -gt 0 -or $CniProviderGuess -match 'Calico') {
        $calico = Test-KubeNetCalicoPolicyPath -Policies $calicoPolicies -NetworkSets $calicoNetworkSets -Tiers $calicoTiers -SourcePod $SourcePod -SourceNamespace $SourceNamespace -TargetPods $TargetPods -TargetNamespace $TargetNamespace -Service $Service -ServicePortObject $ServicePortObject -ContainerPorts $ContainerPorts -SourceResolvSummary $SourceResolvSummary -CoreDnsPods $CoreDnsPods -NodeLocalDnsPods $NodeLocalDnsPods -KubeSystemNamespace $KubeSystemNamespace -CoreDnsServiceIp $CoreDnsServiceIp
        $results += @($calico.Results)
        $diagnoses += @($calico.Diagnoses)
    }

    if ($results.Count -eq 0) {
        $results += [PSCustomObject]@{ Check = 'CNI-specific policies'; Status = 'INFO'; Message = 'No Cilium or Calico policy CRDs were detected/readable for CNI-specific deny analysis.' }
    }

    $summary = 'No CNI-specific policy decision was inferred.'
    $fail = @($results | Where-Object { $_.Status -eq 'FAIL' } | Select-Object -First 1)
    $pass = @($results | Where-Object { $_.Status -eq 'PASS' -and $_.Check -match 'first matching|explicit deny|policy path' } | Select-Object -First 1)
    if ($fail.Count -gt 0) {
        $summary = "CNI-specific policy result: blocked or likely blocked. $($fail[0].Message)"
    } elseif ($pass.Count -gt 0) {
        $summary = "CNI-specific policy result: no CNI block inferred. $($pass[0].Message)"
    } elseif ($results.Count -gt 0) {
        $summary = "CNI-specific policy result: informational only. $($results[0].Message)"
    }

    [PSCustomObject]@{ Results = $results; Diagnoses = $diagnoses; Summary = $summary }
}
