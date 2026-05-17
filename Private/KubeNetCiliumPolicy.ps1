function Get-KubeNetCiliumLabelValue {
    param(
        [object]$Pod,
        [object]$Namespace,
        [string]$Key
    )

    if ([string]::IsNullOrWhiteSpace($Key)) { return '' }

    $normalized = $Key
    if ($normalized.StartsWith('k8s:')) {
        $normalized = $normalized.Substring(4)
    }

    if ($normalized -in @('io.kubernetes.pod.namespace', 'io.cilium.k8s.namespace.labels.kubernetes.io/metadata.name')) {
        return [string]$Pod.metadata.namespace
    }

    if ($normalized -eq 'io.cilium.k8s.policy.serviceaccount') {
        return [string]$Pod.spec.serviceAccountName
    }

    if ($normalized -like 'io.cilium.k8s.namespace.labels.*') {
        $namespaceLabel = $normalized.Substring('io.cilium.k8s.namespace.labels.'.Length)
        return [string]$Namespace.metadata.labels.$namespaceLabel
    }

    return [string]$Pod.metadata.labels.$normalized
}

function Test-KubeNetCiliumSelectorMatchesPod {
    param([object]$Selector, [object]$Pod, [object]$Namespace)

    if ($null -eq $Selector) { return $true }
    if ($null -eq $Pod -or $null -eq $Namespace) { return $false }

    $matchLabels = $Selector.matchLabels
    if ($matchLabels) {
        foreach ($property in $matchLabels.PSObject.Properties) {
            $key = [string]$property.Name
            $expected = [string]$property.Value
            $actual = Get-KubeNetCiliumLabelValue -Pod $Pod -Namespace $Namespace -Key $key
            if ($actual -ne $expected) { return $false }
        }
    }

    if ($Selector.matchExpressions) {
        foreach ($expression in @($Selector.matchExpressions)) {
            $key = [string]$expression.key
            $operator = [string]$expression.operator
            $values = @($expression.values | ForEach-Object { [string]$_ })
            $value = Get-KubeNetCiliumLabelValue -Pod $Pod -Namespace $Namespace -Key $key
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

function Get-KubeNetCiliumPortFacts {
    param(
        [object]$ServicePortObject,
        [object[]]$ContainerPorts,
        [int[]]$Ports
    )

    $names = @()
    $protocol = 'TCP'
    if ($ServicePortObject) {
        if ($ServicePortObject.protocol) { $protocol = [string]$ServicePortObject.protocol }
        if ($ServicePortObject.name) { $names += [string]$ServicePortObject.name }
        $targetPortText = [string]$ServicePortObject.targetPort
        $targetPortNumber = 0
        if (-not [string]::IsNullOrWhiteSpace($targetPortText) -and -not [int]::TryParse($targetPortText, [ref]$targetPortNumber)) {
            $names += $targetPortText
        }
    }

    foreach ($port in @($ContainerPorts | Where-Object { $_.Name })) {
        $names += [string]$port.Name
    }

    [PSCustomObject]@{
        Numbers  = @($Ports | Where-Object { $_ -gt 0 } | Sort-Object -Unique)
        Names    = @($names | Where-Object { -not [string]::IsNullOrWhiteSpace($_) } | Sort-Object -Unique)
        Protocol = $protocol.ToUpperInvariant()
    }
}

function Test-KubeNetCiliumPortMatch {
    param([object[]]$PortRules, [object]$PortFacts)

    if ($null -eq $PortRules -or @($PortRules).Count -eq 0) { return $true }
    if ($null -eq $PortFacts) { return $true }
    if (@($PortFacts.Numbers).Count -eq 0 -and @($PortFacts.Names).Count -eq 0) { return $true }

    foreach ($rule in @($PortRules | Where-Object { $null -ne $_ })) {
        $portValue = if ($null -ne $rule.port) { [string]$rule.port } elseif ($null -ne $rule.Port) { [string]$rule.Port } else { '' }
        $ruleProtocol = if ($rule.protocol) { [string]$rule.protocol } elseif ($rule.Protocol) { [string]$rule.Protocol } else { '' }
        if (-not [string]::IsNullOrWhiteSpace($ruleProtocol) -and $ruleProtocol.ToUpperInvariant() -ne $PortFacts.Protocol) {
            continue
        }

        if ([string]::IsNullOrWhiteSpace($portValue)) { return $true }
        $number = 0
        if ([int]::TryParse($portValue, [ref]$number)) {
            if (@($PortFacts.Numbers) -contains $number) { return $true }
        } elseif (@($PortFacts.Names) -contains $portValue) {
            return $true
        }
    }

    $false
}

function Test-KubeNetCiliumCidrSetMatches {
    param(
        [object[]]$CidrSets,
        [string[]]$Ips
    )

    foreach ($entry in @($CidrSets | Where-Object { $null -ne $_ })) {
        $cidr = if ($entry.cidr) { [string]$entry.cidr } else { [string]$entry }
        if ([string]::IsNullOrWhiteSpace($cidr)) { continue }
        foreach ($ip in @($Ips | Where-Object { -not [string]::IsNullOrWhiteSpace($_) })) {
            if (-not (Test-KubeNetIpv4InCidr -Address $ip -Cidr $cidr)) { continue }
            $exceptMatched = $false
            foreach ($except in @($entry.except | ForEach-Object { [string]$_ })) {
                if (Test-KubeNetIpv4InCidr -Address $ip -Cidr $except) { $exceptMatched = $true }
            }
            if (-not $exceptMatched) { return $true }
        }
    }

    $false
}

function Test-KubeNetCiliumServiceMatch {
    param(
        [object[]]$Services,
        [object]$Service
    )

    if ($null -eq $Service) { return $false }
    $targetName = [string]$Service.metadata.name
    $targetNamespace = [string]$Service.metadata.namespace

    foreach ($serviceRef in @($Services | Where-Object { $null -ne $_ })) {
        if ($serviceRef.k8sService) {
            $name = [string]$serviceRef.k8sService.serviceName
            $namespace = [string]$serviceRef.k8sService.namespace
            if ($name -eq $targetName -and ([string]::IsNullOrWhiteSpace($namespace) -or $namespace -eq $targetNamespace)) {
                return $true
            }
        }

        if ($serviceRef.k8sServiceSelector) {
            $namespace = [string]$serviceRef.k8sServiceSelector.namespace
            if (-not [string]::IsNullOrWhiteSpace($namespace) -and $namespace -ne $targetNamespace) { continue }
            if (Test-KubeNetSelectorMatchesPod -Selector $serviceRef.k8sServiceSelector.selector -Pod $Service) {
                return $true
            }
        }
    }

    $false
}

function ConvertTo-KubeNetCiliumLabelSummary {
    param([object]$Resource)

    $labels = @()
    foreach ($property in @($Resource.metadata.labels.PSObject.Properties | Where-Object { $null -ne $_ })) {
        $labels += "$($property.Name)=$($property.Value)"
    }

    if ($labels.Count -eq 0) { return '(none)' }
    (@($labels | Sort-Object) -join ', ')
}

function ConvertTo-KubeNetCiliumSelectorSummary {
    param([object]$Selector)

    if ($null -eq $Selector) { return '(any)' }

    $parts = @()
    foreach ($property in @($Selector.matchLabels.PSObject.Properties | Where-Object { $null -ne $_ })) {
        $parts += "$($property.Name)=$($property.Value)"
    }

    foreach ($expression in @($Selector.matchExpressions | Where-Object { $null -ne $_ })) {
        $values = @($expression.values | ForEach-Object { [string]$_ })
        $valueText = if ($values.Count -gt 0) { " [$($values -join ', ')]" } else { '' }
        $parts += "$($expression.key) $($expression.operator)$valueText"
    }

    if ($parts.Count -eq 0) { return '(any)' }
    (@($parts | Sort-Object) -join '; ')
}

function ConvertTo-KubeNetCiliumPortSummary {
    param([object]$PortFacts)

    if ($null -eq $PortFacts) { return '(unknown)' }

    $parts = @()
    if (@($PortFacts.Numbers).Count -gt 0) { $parts += "numbers=$((@($PortFacts.Numbers) | Sort-Object -Unique) -join ',')" }
    if (@($PortFacts.Names).Count -gt 0) { $parts += "names=$((@($PortFacts.Names) | Sort-Object -Unique) -join ',')" }
    if (-not [string]::IsNullOrWhiteSpace($PortFacts.Protocol)) { $parts += "protocol=$($PortFacts.Protocol)" }

    if ($parts.Count -eq 0) { return '(none)' }
    ($parts -join '; ')
}

function Get-KubeNetCiliumPathPortSummary {
    param([object]$PortFacts)

    if ($null -eq $PortFacts) { return 'the tested service path' }

    $numbers = @($PortFacts.Numbers | Where-Object { $_ -gt 0 } | Sort-Object -Unique)
    $names = @($PortFacts.Names | Where-Object { -not [string]::IsNullOrWhiteSpace($_) } | Sort-Object -Unique)
    $protocol = if ([string]::IsNullOrWhiteSpace($PortFacts.Protocol)) { 'TCP' } else { [string]$PortFacts.Protocol }

    $serviceNumber = if ($numbers.Count -gt 0) { [string]$numbers[0] } else { '' }
    $containerNumber = if ($numbers.Count -gt 1) { [string]$numbers[-1] } else { '' }
    $serviceName = if ($names.Count -gt 0) { [string]$names[0] } else { '' }
    $containerName = if ($names.Count -gt 1) { [string]$names[-1] } else { '' }

    $left = if ($serviceNumber -and $serviceName) { "$serviceNumber/$serviceName" } elseif ($serviceNumber) { $serviceNumber } elseif ($serviceName) { $serviceName } else { '' }
    $right = if ($containerNumber -and $containerName) { "$containerNumber/$containerName" } elseif ($containerNumber) { $containerNumber } elseif ($containerName) { $containerName } else { '' }

    if ($left -and $right -and $left -ne $right) {
        return "$left -> $right ($protocol)"
    }
    if ($left) { return "$left ($protocol)" }

    $candidateCount = $numbers.Count + $names.Count
    if ($candidateCount -gt 0) { return "$candidateCount candidate port value(s) ($protocol)" }
    'the tested service path'
}

function Get-KubeNetCiliumRulePortMismatchSummary {
    param(
        [object[]]$PortRules,
        [object]$PortFacts,
        [string]$PolicyName,
        [string]$Direction
    )

    $rules = @($PortRules | Where-Object { $null -ne $_ })
    $pathSummary = Get-KubeNetCiliumPathPortSummary -PortFacts $PortFacts

    if ($rules.Count -eq 0) {
        return "$PolicyName $Direction rule has no explicit port restriction, but did not match this path for another reason."
    }

    if ($rules.Count -eq 1) {
        $ruleText = ConvertTo-KubeNetCiliumRulePortSummary -PortRules $rules
        return "no $Direction allow rule matched the tested port path. Policy port: $ruleText. Tested port path: $pathSummary."
    }

    "no $Direction allow rule matched the tested port path. The policy rule has $($rules.Count) port entries, but none match $pathSummary."
}

function New-KubeNetCiliumDiagnosisBlock {
    param([string[]]$Lines)

    (@($Lines | Where-Object { -not [string]::IsNullOrWhiteSpace($_) }) -join "`n")
}

function ConvertTo-KubeNetCiliumRulePortSummary {
    param([object[]]$PortRules)

    $parts = @()
    foreach ($rule in @($PortRules | Where-Object { $null -ne $_ })) {
        $port = if ($null -ne $rule.port) { [string]$rule.port } elseif ($null -ne $rule.Port) { [string]$rule.Port } else { '(any)' }
        $protocol = if ($rule.protocol) { [string]$rule.protocol } elseif ($rule.Protocol) { [string]$rule.Protocol } else { 'any' }
        $parts += "$port/$protocol"
    }

    if ($parts.Count -eq 0) { return '(any)' }
    (@($parts | Sort-Object -Unique) -join ', ')
}

function Get-KubeNetCiliumSelectorMismatchSummary {
    param(
        [object]$Selector,
        [object]$Pod,
        [object]$Namespace,
        [string]$Subject
    )

    foreach ($property in @($Selector.matchLabels.PSObject.Properties | Where-Object { $null -ne $_ })) {
        $key = [string]$property.Name
        $actual = Get-KubeNetCiliumLabelValue -Pod $Pod -Namespace $Namespace -Key $key
        $displayKey = if ($key.StartsWith('k8s:')) { $key.Substring(4) } else { $key }
        $subjectLabel = $Subject
        if ($displayKey -like 'io.cilium.k8s.namespace.labels.*') {
            $displayKey = $displayKey.Substring('io.cilium.k8s.namespace.labels.'.Length)
            $subjectLabel = "$Subject namespace"
        }
        if ([string]::IsNullOrWhiteSpace($actual)) {
            return "$subjectLabel is missing label '$displayKey', which is required by the policy selector."
        }
        if ($actual -ne [string]$property.Value) {
            return "$subjectLabel has $displayKey=$actual, which is not allowed by the policy selector."
        }
    }

    foreach ($expression in @($Selector.matchExpressions | Where-Object { $null -ne $_ })) {
        $key = [string]$expression.key
        $operator = [string]$expression.operator
        $values = @($expression.values | ForEach-Object { [string]$_ })
        $actual = Get-KubeNetCiliumLabelValue -Pod $Pod -Namespace $Namespace -Key $key
        $displayKey = if ($key.StartsWith('k8s:')) { $key.Substring(4) } else { $key }
        $subjectLabel = $Subject
        if ($displayKey -like 'io.cilium.k8s.namespace.labels.*') {
            $displayKey = $displayKey.Substring('io.cilium.k8s.namespace.labels.'.Length)
            $subjectLabel = "$Subject namespace"
        }
        $hasActual = -not [string]::IsNullOrWhiteSpace($actual)

        switch ($operator) {
            'In' {
                if (-not $hasActual) { return "$subjectLabel is missing label '$displayKey', which is required by the policy selector." }
                if (-not ($values -contains $actual)) { return "$subjectLabel has $displayKey=$actual, which is not allowed by the policy selector." }
            }
            'NotIn' {
                if ($hasActual -and ($values -contains $actual)) { return "$subjectLabel has $displayKey=$actual, which is excluded by the policy selector." }
            }
            'Exists' {
                if (-not $hasActual) { return "$subjectLabel is missing label '$displayKey', which is required by the policy selector." }
            }
            'DoesNotExist' {
                if ($hasActual) { return "$subjectLabel has $displayKey=$actual, but the policy selector requires that label to be absent." }
            }
        }
    }

    "$Subject labels do not satisfy the policy selector."
}

function Get-KubeNetCiliumEgressMissHints {
    param(
        [object]$Rule,
        [string]$PolicyName,
        [object]$Service,
        [object[]]$TargetPods,
        [object]$TargetNamespace,
        [object]$PortFacts
    )

    $hints = @()
    $portRules = Get-KubeNetCiliumRulePorts -Rule $Rule
    if (-not (Test-KubeNetCiliumPortMatch -PortRules $portRules -PortFacts $PortFacts)) {
        $hints += Get-KubeNetCiliumRulePortMismatchSummary -PortRules $portRules -PortFacts $PortFacts -PolicyName $PolicyName -Direction 'egress'
    }

    foreach ($serviceRef in @($Rule.toServices | Where-Object { $null -ne $_ })) {
        if ($serviceRef.k8sService) {
            $expectedName = [string]$serviceRef.k8sService.serviceName
            $expectedNamespace = [string]$serviceRef.k8sService.namespace
            if ([string]::IsNullOrWhiteSpace($expectedNamespace)) { $expectedNamespace = [string]$Service.metadata.namespace }
            if ($expectedName -ne [string]$Service.metadata.name -or $expectedNamespace -ne [string]$Service.metadata.namespace) {
                $hints += "egress toServices.k8sService points at '$expectedNamespace/$expectedName', not the tested target Service '$($Service.metadata.namespace)/$($Service.metadata.name)'."
            }
        }

        if ($serviceRef.k8sServiceSelector) {
            $selector = $serviceRef.k8sServiceSelector.selector
            if (-not (Test-KubeNetSelectorMatchesPod -Selector $selector -Pod $Service)) {
                $reason = Get-KubeNetCiliumSelectorMismatchSummary -Selector $selector -Pod $Service -Subject "Target service '$($Service.metadata.namespace)/$($Service.metadata.name)'"
                $hints += "egress toServices.k8sServiceSelector does not match the tested target Service. $reason"
            }
        }
    }

    foreach ($peer in @($Rule.toEndpoints | Where-Object { $null -ne $_ })) {
        $matched = $false
        foreach ($targetPod in @($TargetPods | Where-Object { $null -ne $_ })) {
            if (Test-KubeNetCiliumSelectorMatchesPod -Selector $peer -Pod $targetPod -Namespace $TargetNamespace) { $matched = $true }
        }
        if (-not $matched) {
            $reason = if (@($TargetPods).Count -gt 0) {
                Get-KubeNetCiliumSelectorMismatchSummary -Selector $peer -Pod $TargetPods[0] -Namespace $TargetNamespace -Subject "Target pod '$($TargetPods[0].metadata.namespace)/$($TargetPods[0].metadata.name)'"
            } else {
                "No selected target pod was available to compare."
            }
            $hints += "egress toEndpoints selector does not match the selected target pod. $reason"
        }
    }

    @($hints | Where-Object { -not [string]::IsNullOrWhiteSpace($_) } | Select-Object -Unique)
}

function Get-KubeNetCiliumIngressMissHints {
    param(
        [object]$Rule,
        [string]$PolicyName,
        [object]$SourcePod,
        [object]$SourceNamespace,
        [object]$PortFacts
    )

    $hints = @()
    $portRules = Get-KubeNetCiliumRulePorts -Rule $Rule
    if (-not (Test-KubeNetCiliumPortMatch -PortRules $portRules -PortFacts $PortFacts)) {
        $hints += Get-KubeNetCiliumRulePortMismatchSummary -PortRules $portRules -PortFacts $PortFacts -PolicyName $PolicyName -Direction 'ingress'
    }

    foreach ($peer in @($Rule.fromEndpoints | Where-Object { $null -ne $_ })) {
        if (-not (Test-KubeNetCiliumSelectorMatchesPod -Selector $peer -Pod $SourcePod -Namespace $SourceNamespace)) {
            $reason = Get-KubeNetCiliumSelectorMismatchSummary -Selector $peer -Pod $SourcePod -Namespace $SourceNamespace -Subject "Source pod '$($SourcePod.metadata.namespace)/$($SourcePod.metadata.name)'"
            $hints += "ingress fromEndpoints selector does not match the source pod. $reason"
        }
    }

    @($hints | Where-Object { -not [string]::IsNullOrWhiteSpace($_) } | Select-Object -Unique)
}

function Get-KubeNetCiliumRulePorts {
    param([object]$Rule)

    $portRules = @()
    foreach ($toPort in @($Rule.toPorts | Where-Object { $null -ne $_ })) {
        $portRules += @($toPort.ports)
    }
    $portRules
}

function Test-KubeNetCiliumRuleHasL7 {
    param([object]$Rule)

    foreach ($toPort in @($Rule.toPorts | Where-Object { $null -ne $_ })) {
        if ($toPort.rules -or $toPort.serverNames -or $toPort.listener -or $toPort.originatingTLS -or $toPort.terminatingTLS) {
            return $true
        }
    }
    $false
}

function Test-KubeNetCiliumRequiresMatch {
    param(
        [object]$Rule,
        [string]$RequiresProperty,
        [object]$PeerPod,
        [object]$PeerNamespace
    )

    $requires = @($Rule.$RequiresProperty | Where-Object { $null -ne $_ })
    if ($requires.Count -eq 0) { return $true }

    foreach ($selector in $requires) {
        if (Test-KubeNetCiliumSelectorMatchesPod -Selector $selector -Pod $PeerPod -Namespace $PeerNamespace) {
            return $true
        }
    }

    $false
}

function Test-KubeNetCiliumPeerMatchesPath {
    param(
        [object]$Rule,
        [string]$PeerProperty,
        [object]$PeerPod,
        [object]$PeerNamespace,
        [object]$Service,
        [string[]]$PeerIps,
        [string[]]$ServiceIps = @()
    )

    if ($null -eq $Rule) { return $false }

    $peers = @($Rule.$PeerProperty | Where-Object { $null -ne $_ })
    $entitiesProperty = if ($PeerProperty -eq 'toEndpoints') { 'toEntities' } else { 'fromEntities' }
    $cidrProperty = if ($PeerProperty -eq 'toEndpoints') { 'toCIDR' } else { 'fromCIDR' }
    $cidrSetProperty = if ($PeerProperty -eq 'toEndpoints') { 'toCIDRSet' } else { 'fromCIDRSet' }
    $requiresProperty = if ($PeerProperty -eq 'toEndpoints') { 'toRequires' } else { 'fromRequires' }
    $servicesProperty = if ($PeerProperty -eq 'toEndpoints') { 'toServices' } else { '' }

    if (-not (Test-KubeNetCiliumRequiresMatch -Rule $Rule -RequiresProperty $requiresProperty -PeerPod $PeerPod -PeerNamespace $PeerNamespace)) {
        return $false
    }

    if ($peers.Count -eq 0) {
        $entities = @($Rule.$entitiesProperty | ForEach-Object { [string]$_ })
        $cidrs = @($Rule.$cidrProperty | ForEach-Object { [string]$_ })
        $cidrSets = @($Rule.$cidrSetProperty | Where-Object { $null -ne $_ })
        $services = if ($servicesProperty) { @($Rule.$servicesProperty | Where-Object { $null -ne $_ }) } else { @() }
        $fqdn = if ($PeerProperty -eq 'toEndpoints') { @($Rule.toFQDNs | Where-Object { $null -ne $_ }) } else { @() }

        if ($entities.Count -eq 0 -and $cidrs.Count -eq 0 -and $cidrSets.Count -eq 0 -and $services.Count -eq 0 -and $fqdn.Count -eq 0) {
            return $true
        }

        if (@($entities | Where-Object { $_ -in @('all', 'cluster') }).Count -gt 0) { return $true }
        if ($PeerProperty -eq 'toEndpoints' -and (Test-KubeNetCiliumServiceMatch -Services $services -Service $Service)) { return $true }

        $ipsToCheck = @($PeerIps + $ServiceIps | Where-Object { -not [string]::IsNullOrWhiteSpace($_) } | Sort-Object -Unique)
        foreach ($cidr in $cidrs) {
            foreach ($ip in $ipsToCheck) {
                if (Test-KubeNetIpv4InCidr -Address $ip -Cidr $cidr) { return $true }
            }
        }
        if (Test-KubeNetCiliumCidrSetMatches -CidrSets $cidrSets -Ips $ipsToCheck) { return $true }
    }

    foreach ($peer in $peers) {
        if (Test-KubeNetCiliumSelectorMatchesPod -Selector $peer -Pod $PeerPod -Namespace $PeerNamespace) {
            return $true
        }
    }

    $false
}

function Test-KubeNetCiliumRuleLooksLikeDnsAllow {
    param([object]$Rule)

    if ($null -eq $Rule) { return $false }

    $portRules = Get-KubeNetCiliumRulePorts -Rule $Rule
    $dnsFacts = [PSCustomObject]@{ Numbers = @(53); Names = @('dns', 'domain'); Protocol = 'UDP' }
    $allowsUdpDns = Test-KubeNetCiliumPortMatch -PortRules $portRules -PortFacts $dnsFacts
    $dnsFacts.Protocol = 'TCP'
    $allowsTcpDns = Test-KubeNetCiliumPortMatch -PortRules $portRules -PortFacts $dnsFacts
    if (-not ($allowsUdpDns -or $allowsTcpDns)) { return $false }

    $entities = @($Rule.toEntities | ForEach-Object { [string]$_ })
    if (@($entities | Where-Object { $_ -in @('all', 'cluster', 'host', 'kube-apiserver', 'world') }).Count -gt 0) {
        return $true
    }

    $endpoints = @($Rule.toEndpoints | Where-Object { $null -ne $_ })
    $services = @($Rule.toServices | Where-Object { $null -ne $_ })
    if ($endpoints.Count -eq 0 -and $entities.Count -eq 0 -and $services.Count -eq 0) {
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

    foreach ($serviceRef in $services) {
        if ($serviceRef.k8sService.serviceName -match 'kube-dns|coredns' -or $serviceRef.k8sServiceSelector.selector.matchLabels.'k8s-app' -match 'kube-dns|coredns') {
            return $true
        }
    }

    $false
}

function Get-KubeNetCiliumDnsResolverPeers {
    param(
        [string]$Nameserver,
        [object[]]$CoreDnsPods,
        [object[]]$NodeLocalDnsPods,
        [object]$KubeSystemNamespace,
        [string]$CoreDnsServiceIp
    )

    $kind = Get-KubeNetDnsResolverKind -Nameserver $Nameserver -CoreDnsServiceIp $CoreDnsServiceIp
    $peerPods = @()
    $peerIps = @($Nameserver)

    if ($kind -eq 'CoreDNS service IP') {
        $peerPods = @($CoreDnsPods)
        foreach ($pod in @($CoreDnsPods)) {
            if ($pod.status.podIP) { $peerIps += [string]$pod.status.podIP }
            foreach ($podIp in @($pod.status.podIPs)) {
                if ($podIp.ip) { $peerIps += [string]$podIp.ip }
            }
        }
    } elseif ($kind -eq 'NodeLocalDNS/link-local') {
        $peerPods = @($NodeLocalDnsPods)
    } else {
        foreach ($pod in @($CoreDnsPods + $NodeLocalDnsPods)) {
            if (Test-KubeNetIpMatchesPodAddress -Address $Nameserver -Pod $pod) {
                $peerPods += $pod
            }
        }
    }

    if ($peerPods.Count -eq 0) {
        $peerPods = @([PSCustomObject]@{
            metadata = [PSCustomObject]@{
                name      = "resolver-$Nameserver"
                namespace = if ($KubeSystemNamespace) { [string]$KubeSystemNamespace.metadata.name } else { 'kube-system' }
                labels    = [PSCustomObject]@{}
            }
            spec = [PSCustomObject]@{}
            status = [PSCustomObject]@{ podIP = $Nameserver; podIPs = @([PSCustomObject]@{ ip = $Nameserver }) }
        })
    }

    [PSCustomObject]@{
        Kind          = $kind
        PeerPods      = @($peerPods)
        PeerIps       = @($peerIps | Where-Object { -not [string]::IsNullOrWhiteSpace($_) } | Sort-Object -Unique)
        PeerNamespace = $KubeSystemNamespace
    }
}

function Test-KubeNetCiliumRuleMatchesDnsResolver {
    param(
        [object]$Rule,
        [string]$Nameserver,
        [object[]]$CoreDnsPods,
        [object[]]$NodeLocalDnsPods,
        [object]$KubeSystemNamespace,
        [string]$CoreDnsServiceIp
    )

    $portRules = Get-KubeNetCiliumRulePorts -Rule $Rule
    $udpFacts = [PSCustomObject]@{ Numbers = @(53); Names = @('dns', 'domain'); Protocol = 'UDP' }
    $tcpFacts = [PSCustomObject]@{ Numbers = @(53); Names = @('dns', 'domain'); Protocol = 'TCP' }
    if (-not ((Test-KubeNetCiliumPortMatch -PortRules $portRules -PortFacts $udpFacts) -or (Test-KubeNetCiliumPortMatch -PortRules $portRules -PortFacts $tcpFacts))) {
        return [PSCustomObject]@{ Matches = $false; Reason = 'rule port criteria do not match UDP/TCP DNS port 53' }
    }

    $resolver = Get-KubeNetCiliumDnsResolverPeers -Nameserver $Nameserver -CoreDnsPods $CoreDnsPods -NodeLocalDnsPods $NodeLocalDnsPods -KubeSystemNamespace $KubeSystemNamespace -CoreDnsServiceIp $CoreDnsServiceIp
    $entities = @($Rule.toEntities | ForEach-Object { [string]$_ })
    if (@($entities | Where-Object { $_ -in @('all', 'world') }).Count -gt 0) {
        return [PSCustomObject]@{ Matches = $true; Reason = "$($resolver.Kind) resolver $Nameserver matched broad toEntities allow" }
    }
    if ($resolver.Kind -eq 'NodeLocalDNS/link-local' -and @($entities | Where-Object { $_ -in @('host', 'remote-node') }).Count -gt 0) {
        return [PSCustomObject]@{ Matches = $true; Reason = "$($resolver.Kind) resolver $Nameserver matched host/node toEntities allow" }
    }

    foreach ($cidr in @($Rule.toCIDR | ForEach-Object { [string]$_ })) {
        foreach ($ip in @($resolver.PeerIps)) {
            if (Test-KubeNetIpv4InCidr -Address $ip -Cidr $cidr) {
                return [PSCustomObject]@{ Matches = $true; Reason = "$($resolver.Kind) resolver $Nameserver matched toCIDR $cidr" }
            }
        }
    }
    if (Test-KubeNetCiliumCidrSetMatches -CidrSets @($Rule.toCIDRSet) -Ips @($resolver.PeerIps)) {
        return [PSCustomObject]@{ Matches = $true; Reason = "$($resolver.Kind) resolver $Nameserver matched toCIDRSet" }
    }

    foreach ($serviceRef in @($Rule.toServices | Where-Object { $null -ne $_ })) {
        $serviceName = [string]$serviceRef.k8sService.serviceName
        $serviceNamespace = [string]$serviceRef.k8sService.namespace
        $selector = $serviceRef.k8sServiceSelector.selector
        if ($resolver.Kind -eq 'CoreDNS service IP') {
            if ($serviceName -match 'kube-dns|coredns' -and ([string]::IsNullOrWhiteSpace($serviceNamespace) -or $serviceNamespace -eq 'kube-system')) {
                return [PSCustomObject]@{ Matches = $true; Reason = "CoreDNS service IP resolver $Nameserver matched toServices '$serviceName'" }
            }
            foreach ($pod in @($CoreDnsPods)) {
                if ($selector -and (Test-KubeNetSelectorMatchesPod -Selector $selector -Pod $pod)) {
                    return [PSCustomObject]@{ Matches = $true; Reason = "CoreDNS resolver $Nameserver matched toServices selector" }
                }
            }
        }
    }

    foreach ($peer in @($Rule.toEndpoints | Where-Object { $null -ne $_ })) {
        foreach ($pod in @($resolver.PeerPods)) {
            if (Test-KubeNetCiliumSelectorMatchesPod -Selector $peer -Pod $pod -Namespace $resolver.PeerNamespace) {
                return [PSCustomObject]@{ Matches = $true; Reason = "$($resolver.Kind) resolver $Nameserver matched toEndpoints selector" }
            }
        }
    }

    [PSCustomObject]@{ Matches = $false; Reason = "$($resolver.Kind) resolver $Nameserver did not match DNS destination criteria" }
}

function Test-KubeNetCiliumDnsEgressPolicy {
    param(
        [object[]]$Policies,
        [object]$SourcePod,
        [object]$SourceNamespace,
        [object]$ResolvSummary,
        [object[]]$CoreDnsPods,
        [object[]]$NodeLocalDnsPods,
        [object]$KubeSystemNamespace,
        [string]$CoreDnsServiceIp
    )

    $results = @()
    $diagnoses = @()
    if ($null -eq $SourcePod -or $null -eq $SourceNamespace -or $null -eq $ResolvSummary -or @($ResolvSummary.Nameservers).Count -eq 0) {
        return [PSCustomObject]@{ Results = $results; Diagnoses = $diagnoses; AnyDnsAllow = $false; AnyBlocked = $false }
    }

    $selectedPolicies = @($Policies | Where-Object {
        $null -ne $_ -and
        (([string]$_.kind -eq 'CiliumClusterwideNetworkPolicy') -or [string]::IsNullOrWhiteSpace([string]$_.metadata.namespace) -or [string]$_.metadata.namespace -eq [string]$SourcePod.metadata.namespace) -and
        $_.spec.egress -and
        $_.spec.enableDefaultDeny.egress -ne $false -and
        (Test-KubeNetCiliumSelectorMatchesPod -Selector $_.spec.endpointSelector -Pod $SourcePod -Namespace $SourceNamespace)
    })
    if ($selectedPolicies.Count -eq 0) {
        return [PSCustomObject]@{ Results = $results; Diagnoses = $diagnoses; AnyDnsAllow = $false; AnyBlocked = $false }
    }

    $policyNames = @($selectedPolicies | ForEach-Object {
        $ns = [string]$_.metadata.namespace
        if ([string]::IsNullOrWhiteSpace($ns) -or [string]$_.kind -eq 'CiliumClusterwideNetworkPolicy') { [string]$_.metadata.name } else { "$ns/$($_.metadata.name)" }
    } | Sort-Object -Unique)
    $blockedResolvers = @()
    $resolverMessages = @()
    $anyAllow = $false

    foreach ($nameserver in @($ResolvSummary.Nameservers)) {
        $kind = Get-KubeNetDnsResolverKind -Nameserver $nameserver -CoreDnsServiceIp $CoreDnsServiceIp
        $allowReasons = @()
        foreach ($policy in @($selectedPolicies)) {
            $policyNamespace = [string]$policy.metadata.namespace
            $policyName = if ([string]::IsNullOrWhiteSpace($policyNamespace) -or [string]$policy.kind -eq 'CiliumClusterwideNetworkPolicy') { [string]$policy.metadata.name } else { "$policyNamespace/$($policy.metadata.name)" }
            foreach ($rule in @($policy.spec.egress | Where-Object { $null -ne $_ })) {
                $match = Test-KubeNetCiliumRuleMatchesDnsResolver -Rule $rule -Nameserver $nameserver -CoreDnsPods $CoreDnsPods -NodeLocalDnsPods $NodeLocalDnsPods -KubeSystemNamespace $KubeSystemNamespace -CoreDnsServiceIp $CoreDnsServiceIp
                if ($match.Matches) {
                    $allowReasons += "${policyName}: $($match.Reason)"
                }
            }
        }

        if ($allowReasons.Count -gt 0) {
            $anyAllow = $true
            $resolverMessages += "Resolver $nameserver ($kind) appears allowed by $($allowReasons -join '; ')."
        } else {
            $blockedResolvers += "$nameserver ($kind)"
            $resolverMessages += "Resolver $nameserver ($kind) is not obviously allowed by Cilium egress policy selecting '$($SourcePod.metadata.name)'."
        }
    }

    if ($blockedResolvers.Count -gt 0) {
        $results += [PSCustomObject]@{ Check = 'Cilium DNS egress resolver'; Status = 'FAIL'; Message = "Cilium egress policy selects source pod '$($SourcePod.metadata.name)', but runtime DNS resolver(s) are not allowed. $($resolverMessages -join ' ') Selecting policy/policies: $($policyNames -join ', ')." }
        $resolverLine = $blockedResolvers -join ', '
        $primary = if ($resolverLine -match 'NodeLocalDNS/link-local') {
            'Primary issue: Cilium egress policy does not allow the source pod runtime DNS resolver.'
        } else {
            'Primary issue: Cilium egress policy may block DNS for the source pod.'
        }
        $why = if ($resolverLine -match 'NodeLocalDNS/link-local') {
            'DNS policy appears to allow a different DNS path, but this pod is configured to query a NodeLocalDNS/link-local resolver instead.'
        } else {
            'No Cilium egress allow rule obviously matches the pod runtime resolver on UDP/TCP 53.'
        }
        $diagnoses += New-KubeNetCiliumDiagnosisBlock -Lines @(
            $primary,
            ('Source: `{0}/{1}`' -f $SourcePod.metadata.namespace, $SourcePod.metadata.name),
            ('Runtime resolver(s): `{0}`' -f $resolverLine),
            ('Policy/policies: `{0}`' -f ($policyNames -join ', ')),
            "Why it failed: $why"
        )
        return [PSCustomObject]@{ Results = $results; Diagnoses = $diagnoses; AnyDnsAllow = $anyAllow; AnyBlocked = $true }
    }

    $results += [PSCustomObject]@{ Check = 'Cilium DNS egress resolver'; Status = 'PASS'; Message = "Cilium egress policy appears to allow source pod '$($SourcePod.metadata.name)' to its runtime DNS resolver(s). $($resolverMessages -join ' ')" }
    [PSCustomObject]@{ Results = $results; Diagnoses = $diagnoses; AnyDnsAllow = $true; AnyBlocked = $false }
}

function Test-KubeNetCiliumPolicyPath {
    param(
        [object[]]$Policies,
        [object]$SourcePod,
        [object]$SourceNamespace,
        [object[]]$TargetPods,
        [object]$TargetNamespace,
        [object]$Service,
        [int[]]$Ports,
        [object]$ServicePortObject,
        [object[]]$ContainerPorts,
        [object]$SourceResolvSummary = $null,
        [object[]]$CoreDnsPods = @(),
        [object[]]$NodeLocalDnsPods = @(),
        [object]$KubeSystemNamespace = $null,
        [string]$CoreDnsServiceIp = ''
    )

    $results = @()
    $diagnoses = @()
    if ($Policies.Count -eq 0) {
        return [PSCustomObject]@{ Results = @([PSCustomObject]@{ Check = 'Cilium policies'; Status = 'INFO'; Message = 'No CiliumNetworkPolicy/CiliumClusterwideNetworkPolicy objects were found or readable.' }); Diagnoses = @() }
    }

    $serviceClusterIp = if ($Service -and $Service.spec.clusterIP -and $Service.spec.clusterIP -ne 'None') { [string]$Service.spec.clusterIP } else { '' }
    $targetPodIps = @($TargetPods | ForEach-Object { [string]$_.status.podIP } | Where-Object { -not [string]::IsNullOrWhiteSpace($_) })
    $sourcePodIps = @([string]$SourcePod.status.podIP | Where-Object { -not [string]::IsNullOrWhiteSpace($_) })
    $serviceIps = @($serviceClusterIp | Where-Object { -not [string]::IsNullOrWhiteSpace($_) })
    $portFacts = Get-KubeNetCiliumPortFacts -ServicePortObject $ServicePortObject -ContainerPorts $ContainerPorts -Ports $Ports

    $matchedDeny = @()
    $selectedButUnmatched = @()
    $sourceEgressEnforcing = @()
    $sourceEgressAllow = @()
    $sourceDnsAllow = @()
    $targetIngressEnforcing = @()
    $targetIngressAllow = @()
    $sourceEgressMissHints = @()
    $targetIngressMissHints = @()
    $l7Allows = @()
    $unsupportedHints = @()

    foreach ($policy in @($Policies | Where-Object { $null -ne $_ })) {
        $policyNamespace = [string]$policy.metadata.namespace
        $isClusterwide = [string]$policy.kind -eq 'CiliumClusterwideNetworkPolicy' -or [string]::IsNullOrWhiteSpace($policyNamespace)
        $selector = $policy.spec.endpointSelector
        $name = if ($isClusterwide) { $policy.metadata.name } else { "$policyNamespace/$($policy.metadata.name)" }

        foreach ($sectionName in @('egress', 'egressDeny')) {
            foreach ($rule in @($policy.spec.$sectionName | Where-Object { $null -ne $_ })) {
                if ($rule.toFQDNs) { $unsupportedHints += "$name $sectionName toFQDNs" }
                if ($rule.toGroups) { $unsupportedHints += "$name $sectionName toGroups" }
            }
        }

        if ($SourcePod -and ($isClusterwide -or $SourcePod.metadata.namespace -eq $policyNamespace) -and (Test-KubeNetCiliumSelectorMatchesPod -Selector $selector -Pod $SourcePod -Namespace $SourceNamespace)) {
            if ($policy.spec.egress -and $policy.spec.enableDefaultDeny.egress -ne $false) {
                $sourceEgressEnforcing += $name
            }

            foreach ($rule in @($policy.spec.egress | Where-Object { $null -ne $_ })) {
                $isDnsAllowRule = Test-KubeNetCiliumRuleLooksLikeDnsAllow -Rule $rule
                if ($isDnsAllowRule) {
                    $sourceDnsAllow += "$name egress"
                }

                if ($isDnsAllowRule) { continue }

                if (-not (Test-KubeNetCiliumPortMatch -PortRules (Get-KubeNetCiliumRulePorts -Rule $rule) -PortFacts $portFacts)) {
                    $sourceEgressMissHints += Get-KubeNetCiliumEgressMissHints -Rule $rule -PolicyName $name -Service $Service -TargetPods $TargetPods -TargetNamespace $TargetNamespace -PortFacts $portFacts
                    continue
                }
                $peerMatches = $false
                foreach ($targetPod in @($TargetPods)) {
                    if (Test-KubeNetCiliumPeerMatchesPath -Rule $rule -PeerProperty 'toEndpoints' -PeerPod $targetPod -PeerNamespace $TargetNamespace -Service $Service -PeerIps $targetPodIps -ServiceIps $serviceIps) {
                        $peerMatches = $true
                    }
                }
                if ($peerMatches) {
                    $sourceEgressAllow += "$name egress"
                    if (Test-KubeNetCiliumRuleHasL7 -Rule $rule) { $l7Allows += "$name egress" }
                } else {
                    $sourceEgressMissHints += Get-KubeNetCiliumEgressMissHints -Rule $rule -PolicyName $name -Service $Service -TargetPods $TargetPods -TargetNamespace $TargetNamespace -PortFacts $portFacts
                }
            }

            foreach ($rule in @($policy.spec.egressDeny | Where-Object { $null -ne $_ })) {
                if (-not (Test-KubeNetCiliumPortMatch -PortRules (Get-KubeNetCiliumRulePorts -Rule $rule) -PortFacts $portFacts)) { continue }
                $peerMatches = $false
                foreach ($targetPod in @($TargetPods)) {
                    if (Test-KubeNetCiliumPeerMatchesPath -Rule $rule -PeerProperty 'toEndpoints' -PeerPod $targetPod -PeerNamespace $TargetNamespace -Service $Service -PeerIps $targetPodIps -ServiceIps $serviceIps) {
                        $peerMatches = $true
                    }
                }
                if ($peerMatches) { $matchedDeny += "$name egressDeny" } else { $selectedButUnmatched += "$name egressDeny" }
            }
        }

        foreach ($targetPod in @($TargetPods)) {
            if (($isClusterwide -or $targetPod.metadata.namespace -eq $policyNamespace) -and (Test-KubeNetCiliumSelectorMatchesPod -Selector $selector -Pod $targetPod -Namespace $TargetNamespace)) {
                if ($policy.spec.ingress -and $policy.spec.enableDefaultDeny.ingress -ne $false) {
                    $targetIngressEnforcing += $name
                }

                foreach ($rule in @($policy.spec.ingress | Where-Object { $null -ne $_ })) {
                    if (-not (Test-KubeNetCiliumPortMatch -PortRules (Get-KubeNetCiliumRulePorts -Rule $rule) -PortFacts $portFacts)) {
                        $targetIngressMissHints += Get-KubeNetCiliumIngressMissHints -Rule $rule -PolicyName $name -SourcePod $SourcePod -SourceNamespace $SourceNamespace -PortFacts $portFacts
                        continue
                    }
                    if (Test-KubeNetCiliumPeerMatchesPath -Rule $rule -PeerProperty 'fromEndpoints' -PeerPod $SourcePod -PeerNamespace $SourceNamespace -Service $null -PeerIps $sourcePodIps) {
                        $targetIngressAllow += "$name ingress"
                        if (Test-KubeNetCiliumRuleHasL7 -Rule $rule) { $l7Allows += "$name ingress" }
                    } else {
                        $targetIngressMissHints += Get-KubeNetCiliumIngressMissHints -Rule $rule -PolicyName $name -SourcePod $SourcePod -SourceNamespace $SourceNamespace -PortFacts $portFacts
                    }
                }

                foreach ($rule in @($policy.spec.ingressDeny | Where-Object { $null -ne $_ })) {
                    if (-not (Test-KubeNetCiliumPortMatch -PortRules (Get-KubeNetCiliumRulePorts -Rule $rule) -PortFacts $portFacts)) { continue }
                    if (Test-KubeNetCiliumPeerMatchesPath -Rule $rule -PeerProperty 'fromEndpoints' -PeerPod $SourcePod -PeerNamespace $SourceNamespace -Service $null -PeerIps $sourcePodIps) {
                        $matchedDeny += "$name ingressDeny"
                    } else {
                        $selectedButUnmatched += "$name ingressDeny"
                    }
                }
            }
        }
    }

    $dnsResolverAnalysis = Test-KubeNetCiliumDnsEgressPolicy -Policies $Policies -SourcePod $SourcePod -SourceNamespace $SourceNamespace -ResolvSummary $SourceResolvSummary -CoreDnsPods $CoreDnsPods -NodeLocalDnsPods $NodeLocalDnsPods -KubeSystemNamespace $KubeSystemNamespace -CoreDnsServiceIp $CoreDnsServiceIp
    if (@($dnsResolverAnalysis.Results).Count -gt 0) {
        $results += @($dnsResolverAnalysis.Results)
    }
    if (@($dnsResolverAnalysis.Diagnoses).Count -gt 0) {
        $diagnoses += @($dnsResolverAnalysis.Diagnoses)
    }
    if ($dnsResolverAnalysis.AnyDnsAllow) {
        $sourceDnsAllow += 'Cilium runtime DNS resolver analysis'
    }

    if ($matchedDeny.Count -gt 0) {
        $unique = @($matchedDeny | Sort-Object -Unique)
        $results += [PSCustomObject]@{ Check = 'Cilium explicit deny'; Status = 'FAIL'; Message = "Cilium explicit deny rule(s) appear to match this source-to-target path: $($unique -join ', ')." }
        $lines = @(
            'Primary issue: Cilium explicit deny blocks this path.',
            ('Source: `{0}/{1}`' -f $SourcePod.metadata.namespace, $SourcePod.metadata.name),
            ('Target Service: `{0}/{1}`' -f $TargetNamespace.metadata.name, $Service.metadata.name),
            ('Deny rule(s): `{0}`' -f ($unique -join ', ')),
            'Why it failed: a deny rule matched the tested path.'
        )
        if ($sourceEgressAllow.Count -gt 0 -or $targetIngressAllow.Count -gt 0) {
            $allowMatches = @($sourceEgressAllow + $targetIngressAllow | Sort-Object -Unique)
            $lines += ('Detail: an allow rule also matched (`{0}`), but Cilium deny rules take precedence over allows.' -f ($allowMatches -join ', '))
        }
        $diagnoses += New-KubeNetCiliumDiagnosisBlock -Lines $lines
    } else {
        $results += [PSCustomObject]@{ Check = 'Cilium explicit deny'; Status = 'PASS'; Message = 'No Cilium ingressDeny/egressDeny rule obviously matches this path.' }
    }

    if ($sourceEgressEnforcing.Count -gt 0 -and $sourceEgressAllow.Count -eq 0) {
        $policyNames = @($sourceEgressEnforcing | Sort-Object -Unique)
        $results += [PSCustomObject]@{ Check = 'Cilium egress default-deny'; Status = 'FAIL'; Message = "Cilium policy selects source pod '$($SourcePod.metadata.name)' for egress default-deny, but no Cilium egress allow rule obviously matches this target/port. Selecting policy/policies: $($policyNames -join ', ')." }
        $missHints = @($sourceEgressMissHints | Sort-Object -Unique)
        $why = "no egress allow rule matched the tested target Service path."
        if ($missHints.Count -gt 0) {
            $detail = (@($missHints | Select-Object -First 3) -join ' ')
            $results += [PSCustomObject]@{ Check = 'Cilium egress allow mismatch detail'; Status = 'INFO'; Message = $detail }
            $why = $detail
        } elseif ($sourceDnsAllow.Count -gt 0) {
            $detail = "DNS egress appears allowed, but no egress rule matched the tested target Service path."
            $results += [PSCustomObject]@{ Check = 'Cilium egress allow mismatch detail'; Status = 'INFO'; Message = $detail }
            $why = $detail
        }
        $diagnoses += New-KubeNetCiliumDiagnosisBlock -Lines @(
            'Primary issue: Cilium egress policy does not allow the tested target Service.',
            ('Source: `{0}/{1}`' -f $SourcePod.metadata.namespace, $SourcePod.metadata.name),
            ('Target Service: `{0}/{1}`' -f $TargetNamespace.metadata.name, $Service.metadata.name),
            ('Policy/policies: `{0}`' -f ($policyNames -join ', ')),
            "Why it failed: $why"
        )
    } elseif ($sourceEgressEnforcing.Count -gt 0) {
        $results += [PSCustomObject]@{ Check = 'Cilium egress allow'; Status = 'PASS'; Message = "Cilium egress policy appears to allow this target/port through: $((@($sourceEgressAllow | Sort-Object -Unique)) -join ', ')." }
        if ($sourceDnsAllow.Count -eq 0 -and -not $dnsResolverAnalysis.AnyBlocked) {
            $policyNames = @($sourceEgressEnforcing | Sort-Object -Unique)
            $results += [PSCustomObject]@{ Check = 'Cilium DNS egress allow'; Status = 'WARN'; Message = "Cilium policy selects source pod '$($SourcePod.metadata.name)' for egress default-deny, and no obvious DNS egress allow rule was found. DNS lookups may fail even if the target service path is allowed. Selecting policy/policies: $($policyNames -join ', ')." }
            $diagnoses += New-KubeNetCiliumDiagnosisBlock -Lines @(
                'Likely issue: Cilium egress policy may block DNS.',
                ('Source: `{0}/{1}`' -f $SourcePod.metadata.namespace, $SourcePod.metadata.name),
                ('Policy/policies: `{0}`' -f ($policyNames -join ', ')),
                'Why it may fail: target traffic is allowed, but no obvious DNS egress allow rule was found.'
            )
        }
    } else {
        $results += [PSCustomObject]@{ Check = 'Cilium egress isolation'; Status = 'INFO'; Message = 'No Cilium egress default-deny policy was inferred for the source pod.' }
    }

    if ($targetIngressEnforcing.Count -gt 0 -and $targetIngressAllow.Count -eq 0) {
        $policyNames = @($targetIngressEnforcing | Sort-Object -Unique)
        $results += [PSCustomObject]@{ Check = 'Cilium ingress default-deny'; Status = 'FAIL'; Message = "Cilium policy selects target pod(s) for ingress default-deny, but no Cilium ingress allow rule obviously matches this source/port. Selecting policy/policies: $($policyNames -join ', ')." }
        $missHints = @($targetIngressMissHints | Sort-Object -Unique)
        $why = "no ingress allow rule matched the tested source."
        if ($missHints.Count -gt 0) {
            $detail = (@($missHints | Select-Object -First 3) -join ' ')
            $results += [PSCustomObject]@{ Check = 'Cilium ingress allow mismatch detail'; Status = 'INFO'; Message = $detail }
            $why = $detail
        }
        $diagnoses += New-KubeNetCiliumDiagnosisBlock -Lines @(
            'Primary issue: Cilium ingress policy does not allow this source.',
            ('Source: `{0}/{1}`' -f $SourcePod.metadata.namespace, $SourcePod.metadata.name),
            ('Target Service: `{0}/{1}`' -f $TargetNamespace.metadata.name, $Service.metadata.name),
            ('Policy/policies: `{0}`' -f ($policyNames -join ', ')),
            "Why it failed: $why"
        )
    } elseif ($targetIngressEnforcing.Count -gt 0) {
        $results += [PSCustomObject]@{ Check = 'Cilium ingress allow'; Status = 'PASS'; Message = "Cilium ingress policy appears to allow this source/port through: $((@($targetIngressAllow | Sort-Object -Unique)) -join ', ')." }
    } else {
        $results += [PSCustomObject]@{ Check = 'Cilium ingress isolation'; Status = 'INFO'; Message = 'No Cilium ingress default-deny policy was inferred for the target pod(s).' }
    }

    if ($selectedButUnmatched.Count -gt 0) {
        $results += [PSCustomObject]@{ Check = 'Cilium unmatched deny rules'; Status = 'INFO'; Message = "Cilium deny rule(s) exist and select one side of the path, but no deny rule obviously matched the tested peer/port: $((@($selectedButUnmatched | Sort-Object -Unique)) -join ', ')." }
    }

    if ($l7Allows.Count -gt 0) {
        $results += [PSCustomObject]@{ Check = 'Cilium L7 policy constraints'; Status = 'WARN'; Message = "Cilium L4 path appears allowed, but matching rule(s) include L7/TLS/server-name constraints: $((@($l7Allows | Sort-Object -Unique)) -join ', '). HTTP path, method, host, or TLS details may still be denied." }
        $diagnoses += New-KubeNetCiliumDiagnosisBlock -Lines @(
            'Likely issue: Cilium L4 policy allows this path, but L7 rules may deny the request.',
            ('Policy/rule path: `{0}`' -f ((@($l7Allows | Sort-Object -Unique)) -join ', ')),
            'Why it may fail: HTTP method, path, host, TLS, or SNI constraints may not match the request.'
        )
    }

    if ($unsupportedHints.Count -gt 0) {
        $results += [PSCustomObject]@{ Check = 'Cilium advanced egress selectors'; Status = 'INFO'; Message = "Cilium policy uses advanced egress selectors not fully modeled for in-cluster Service path analysis: $((@($unsupportedHints | Sort-Object -Unique)) -join ', ')." }
    }

    [PSCustomObject]@{ Results = $results; Diagnoses = $diagnoses }
}
