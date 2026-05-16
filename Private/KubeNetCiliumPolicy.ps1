function Test-KubeNetCiliumSelectorMatchesPod {
    param([object]$Selector, [object]$Pod, [object]$Namespace)

    if ($null -eq $Selector) { return $true }
    $matchLabels = $Selector.matchLabels
    if ($matchLabels) {
        foreach ($property in $matchLabels.PSObject.Properties) {
            $key = [string]$property.Name
            $expected = [string]$property.Value
            $actual = $null

            if ($key -in @('k8s:io.kubernetes.pod.namespace', 'io.kubernetes.pod.namespace', 'io.cilium.k8s.namespace.labels.kubernetes.io/metadata.name')) {
                $actual = [string]$Pod.metadata.namespace
            } elseif ($key -like 'k8s:*') {
                $actual = [string]$Pod.metadata.labels.$($key.Substring(4))
            } elseif ($key -like 'io.cilium.k8s.namespace.labels.*') {
                $namespaceLabel = $key.Substring('io.cilium.k8s.namespace.labels.'.Length)
                $actual = [string]$Namespace.metadata.labels.$namespaceLabel
            } else {
                $actual = [string]$Pod.metadata.labels.$key
            }

            if ($actual -ne $expected) { return $false }
        }
    }

    if ($Selector.matchExpressions) {
        foreach ($expression in @($Selector.matchExpressions)) {
            $key = [string]$expression.key
            $operator = [string]$expression.operator
            $values = @($expression.values | ForEach-Object { [string]$_ })
            $value = if ($key -like 'k8s:*') { [string]$Pod.metadata.labels.$($key.Substring(4)) } else { [string]$Pod.metadata.labels.$key }
            $hasKey = -not [string]::IsNullOrWhiteSpace($value)
            switch ($operator) {
                'In' { if (-not ($values -contains $value)) { return $false } }
                'NotIn' { if ($values -contains $value) { return $false } }
                'Exists' { if (-not $hasKey) { return $false } }
                'DoesNotExist' { if ($hasKey) { return $false } }
                default { return $false }
            }
        }
    }

    $true
}

function Test-KubeNetCiliumPeerMatchesPath {
    param(
        [object]$Rule,
        [string]$PeerProperty,
        [object]$PeerPod,
        [object]$PeerNamespace,
        [string]$ServiceClusterIp,
        [string[]]$PodIps
    )

    if ($null -eq $Rule) { return $false }

    $peers = @($Rule.$PeerProperty | Where-Object { $null -ne $_ })
    if ($peers.Count -eq 0) {
        $entitiesProperty = if ($PeerProperty -eq 'toEndpoints') { 'toEntities' } else { 'fromEntities' }
        $entities = @($Rule.$entitiesProperty | ForEach-Object { [string]$_ })
        if ($entities.Count -eq 0) { return $true }
        if (@($entities | Where-Object { $_ -in @('all', 'cluster') }).Count -gt 0) { return $true }
    }

    foreach ($peer in $peers) {
        if (Test-KubeNetCiliumSelectorMatchesPod -Selector $peer -Pod $PeerPod -Namespace $PeerNamespace) {
            return $true
        }
    }

    $cidrProperty = if ($PeerProperty -eq 'toEndpoints') { 'toCIDR' } else { 'fromCIDR' }
    foreach ($cidr in @($Rule.$cidrProperty | ForEach-Object { [string]$_ })) {
        if (-not [string]::IsNullOrWhiteSpace($ServiceClusterIp) -and (Test-KubeNetIpv4InCidr -Address $ServiceClusterIp -Cidr $cidr)) { return $true }
        foreach ($ip in @($PodIps)) {
            if (Test-KubeNetIpv4InCidr -Address $ip -Cidr $cidr) { return $true }
        }
    }

    $false
}

function Test-KubeNetCiliumRuleLooksLikeDnsAllow {
    param([object]$Rule)

    if ($null -eq $Rule) { return $false }

    $portRules = @()
    foreach ($toPort in @($Rule.toPorts | Where-Object { $null -ne $_ })) {
        $portRules += @($toPort.ports)
    }
    $allowsDnsPort = Test-KubeNetCniPortMatch -PortRules $portRules -Ports @(53)
    if (-not $allowsDnsPort) { return $false }

    $entities = @($Rule.toEntities | ForEach-Object { [string]$_ })
    if (@($entities | Where-Object { $_ -in @('all', 'cluster', 'host', 'kube-apiserver', 'world') }).Count -gt 0) {
        return $true
    }

    $endpoints = @($Rule.toEndpoints | Where-Object { $null -ne $_ })
    if ($endpoints.Count -eq 0 -and $entities.Count -eq 0) {
        return $true
    }

    foreach ($endpoint in $endpoints) {
        foreach ($property in @($endpoint.matchLabels.PSObject.Properties)) {
            $name = [string]$property.Name
            $value = [string]$property.Value
            if ($name -match 'k8s-app|app|name' -and $value -match 'kube-dns|coredns|node-local-dns|nodelocaldns') {
                return $true
            }
        }

        foreach ($expression in @($endpoint.matchExpressions | Where-Object { $null -ne $_ })) {
            $values = @($expression.values | ForEach-Object { [string]$_ })
            if (@($values | Where-Object { $_ -match 'kube-dns|coredns|node-local-dns|nodelocaldns' }).Count -gt 0) {
                return $true
            }
        }
    }

    $false
}

function Test-KubeNetCiliumPolicyPath {
    param(
        [object[]]$Policies,
        [object]$SourcePod,
        [object]$SourceNamespace,
        [object[]]$TargetPods,
        [object]$TargetNamespace,
        [object]$Service,
        [int[]]$Ports
    )

    $results = @()
    $diagnoses = @()
    if ($Policies.Count -eq 0) {
        return [PSCustomObject]@{ Results = @([PSCustomObject]@{ Check = 'Cilium deny policies'; Status = 'INFO'; Message = 'No CiliumNetworkPolicy/CiliumClusterwideNetworkPolicy objects were found or readable.' }); Diagnoses = @() }
    }

    $serviceClusterIp = if ($Service -and $Service.spec.clusterIP -and $Service.spec.clusterIP -ne 'None') { [string]$Service.spec.clusterIP } else { '' }
    $targetPodIps = @($TargetPods | ForEach-Object { [string]$_.status.podIP } | Where-Object { -not [string]::IsNullOrWhiteSpace($_) })
    $matchedDeny = @()
    $selectedButUnmatched = @()
    $sourceEgressEnforcing = @()
    $sourceEgressAllow = @()
    $sourceDnsAllow = @()
    $targetIngressEnforcing = @()
    $targetIngressAllow = @()

    foreach ($policy in @($Policies | Where-Object { $null -ne $_ })) {
        $policyNamespace = [string]$policy.metadata.namespace
        $isClusterwide = [string]$policy.kind -eq 'CiliumClusterwideNetworkPolicy' -or [string]::IsNullOrWhiteSpace($policyNamespace)
        $selector = $policy.spec.endpointSelector
        $name = if ($isClusterwide) { $policy.metadata.name } else { "$policyNamespace/$($policy.metadata.name)" }

        if ($SourcePod -and ($isClusterwide -or $SourcePod.metadata.namespace -eq $policyNamespace) -and (Test-KubeNetCiliumSelectorMatchesPod -Selector $selector -Pod $SourcePod -Namespace $SourceNamespace)) {
            if (($policy.spec.egress -or $policy.spec.egressDeny) -and $policy.spec.enableDefaultDeny.egress -ne $false) {
                $sourceEgressEnforcing += $name
            }

            foreach ($rule in @($policy.spec.egress | Where-Object { $null -ne $_ })) {
                if (Test-KubeNetCiliumRuleLooksLikeDnsAllow -Rule $rule) {
                    $sourceDnsAllow += "$name egress"
                }

                $portRules = @()
                foreach ($toPort in @($rule.toPorts | Where-Object { $null -ne $_ })) { $portRules += @($toPort.ports) }
                if (-not (Test-KubeNetCniPortMatch -PortRules $portRules -Ports $Ports)) { continue }
                foreach ($targetPod in @($TargetPods)) {
                    if (Test-KubeNetCiliumPeerMatchesPath -Rule $rule -PeerProperty 'toEndpoints' -PeerPod $targetPod -PeerNamespace $TargetNamespace -ServiceClusterIp $serviceClusterIp -PodIps $targetPodIps) {
                        $sourceEgressAllow += "$name egress"
                    }
                }
            }

            foreach ($rule in @($policy.spec.egressDeny | Where-Object { $null -ne $_ })) {
                $portRules = @()
                foreach ($toPort in @($rule.toPorts | Where-Object { $null -ne $_ })) { $portRules += @($toPort.ports) }
                if (-not (Test-KubeNetCniPortMatch -PortRules $portRules -Ports $Ports)) { continue }
                $peerMatches = $false
                foreach ($targetPod in @($TargetPods)) {
                    if (Test-KubeNetCiliumPeerMatchesPath -Rule $rule -PeerProperty 'toEndpoints' -PeerPod $targetPod -PeerNamespace $TargetNamespace -ServiceClusterIp $serviceClusterIp -PodIps $targetPodIps) {
                        $peerMatches = $true
                    }
                }
                if ($peerMatches) { $matchedDeny += "$name egressDeny" } else { $selectedButUnmatched += "$name egressDeny" }
            }
        }

        foreach ($targetPod in @($TargetPods)) {
            if (($isClusterwide -or $targetPod.metadata.namespace -eq $policyNamespace) -and (Test-KubeNetCiliumSelectorMatchesPod -Selector $selector -Pod $targetPod -Namespace $TargetNamespace)) {
                if (($policy.spec.ingress -or $policy.spec.ingressDeny) -and $policy.spec.enableDefaultDeny.ingress -ne $false) {
                    $targetIngressEnforcing += $name
                }

                foreach ($rule in @($policy.spec.ingress | Where-Object { $null -ne $_ })) {
                    $portRules = @()
                    foreach ($toPort in @($rule.toPorts | Where-Object { $null -ne $_ })) { $portRules += @($toPort.ports) }
                    if (-not (Test-KubeNetCniPortMatch -PortRules $portRules -Ports $Ports)) { continue }
                    if (Test-KubeNetCiliumPeerMatchesPath -Rule $rule -PeerProperty 'fromEndpoints' -PeerPod $SourcePod -PeerNamespace $SourceNamespace -ServiceClusterIp '' -PodIps @([string]$SourcePod.status.podIP)) {
                        $targetIngressAllow += "$name ingress"
                    }
                }

                foreach ($rule in @($policy.spec.ingressDeny | Where-Object { $null -ne $_ })) {
                    $portRules = @()
                    foreach ($toPort in @($rule.toPorts | Where-Object { $null -ne $_ })) { $portRules += @($toPort.ports) }
                    if (-not (Test-KubeNetCniPortMatch -PortRules $portRules -Ports $Ports)) { continue }
                    if (Test-KubeNetCiliumPeerMatchesPath -Rule $rule -PeerProperty 'fromEndpoints' -PeerPod $SourcePod -PeerNamespace $SourceNamespace -ServiceClusterIp '' -PodIps @([string]$SourcePod.status.podIP)) {
                        $matchedDeny += "$name ingressDeny"
                    } else {
                        $selectedButUnmatched += "$name ingressDeny"
                    }
                }
            }
        }
    }

    if ($matchedDeny.Count -gt 0) {
        $unique = @($matchedDeny | Sort-Object -Unique)
        $results += [PSCustomObject]@{ Check = 'Cilium explicit deny'; Status = 'FAIL'; Message = "Cilium explicit deny rule(s) appear to match this source-to-target path: $($unique -join ', ')." }
        $diagnoses += "Primary issue: Cilium explicit deny policy appears to block '$($SourcePod.metadata.namespace)/$($SourcePod.metadata.name)' to service '$($TargetNamespace.metadata.name)/$($Service.metadata.name)'. Matching deny rule(s): $($unique -join ', ')."
    } elseif ($sourceEgressEnforcing.Count -gt 0 -and $sourceEgressAllow.Count -eq 0) {
        $policyNames = @($sourceEgressEnforcing | Sort-Object -Unique)
        $results += [PSCustomObject]@{ Check = 'Cilium egress default-deny'; Status = 'FAIL'; Message = "Cilium policy selects source pod '$($SourcePod.metadata.name)' for egress, but no Cilium egress allow rule obviously matches this target/port. Selecting policy/policies: $($policyNames -join ', ')." }
        $diagnoses += "Primary issue: Cilium policy selects source pod '$($SourcePod.metadata.namespace)/$($SourcePod.metadata.name)' for egress default-deny, but no egress allow rule obviously permits service '$($TargetNamespace.metadata.name)/$($Service.metadata.name)'. Policies: $($policyNames -join ', ')."
    } elseif ($sourceEgressEnforcing.Count -gt 0 -and $sourceDnsAllow.Count -eq 0) {
        $policyNames = @($sourceEgressEnforcing | Sort-Object -Unique)
        $results += [PSCustomObject]@{ Check = 'Cilium DNS egress allow'; Status = 'WARN'; Message = "Cilium policy selects source pod '$($SourcePod.metadata.name)' for egress default-deny, and no obvious DNS egress allow rule was found. DNS lookups may fail even if the target service would otherwise be allowed. Selecting policy/policies: $($policyNames -join ', ')." }
        $diagnoses += "Likely issue: Cilium egress default-deny may block DNS from '$($SourcePod.metadata.namespace)/$($SourcePod.metadata.name)'. Add UDP/TCP 53 egress to CoreDNS/NodeLocalDNS or add an appropriate DNS allow policy. Policies: $($policyNames -join ', ')."
    } elseif ($targetIngressEnforcing.Count -gt 0 -and $targetIngressAllow.Count -eq 0) {
        $policyNames = @($targetIngressEnforcing | Sort-Object -Unique)
        $results += [PSCustomObject]@{ Check = 'Cilium ingress default-deny'; Status = 'FAIL'; Message = "Cilium policy selects target pod(s) for ingress, but no Cilium ingress allow rule obviously matches this source/port. Selecting policy/policies: $($policyNames -join ', ')." }
        $diagnoses += "Primary issue: Cilium policy selects target service pods in '$($TargetNamespace.metadata.name)' for ingress default-deny, but no ingress allow rule obviously permits source pod '$($SourcePod.metadata.namespace)/$($SourcePod.metadata.name)'. Policies: $($policyNames -join ', ')."
    } elseif ($selectedButUnmatched.Count -gt 0) {
        $results += [PSCustomObject]@{ Check = 'Cilium explicit deny'; Status = 'INFO'; Message = 'Cilium deny rule(s) exist and select one side of the path, but no deny rule obviously matched the tested peer/port.' }
    } else {
        $results += [PSCustomObject]@{ Check = 'Cilium explicit deny'; Status = 'PASS'; Message = 'No Cilium ingressDeny/egressDeny rule obviously matches this path.' }
    }

    [PSCustomObject]@{ Results = $results; Diagnoses = $diagnoses }
}
