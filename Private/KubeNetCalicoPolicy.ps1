function Get-KubeNetCalicoLabelValue {
    param([object]$Resource, [string]$Key)

    if ($null -eq $Resource -or [string]::IsNullOrWhiteSpace($Key)) { return $null }
    if ($Key -in @('projectcalico.org/name', 'kubernetes.io/metadata.name')) {
        return [string]$Resource.metadata.name
    }
    if ($Key -eq 'projectcalico.org/namespace') {
        return [string]$Resource.metadata.namespace
    }
    $direct = [string]$Resource.metadata.labels.$Key
    if (-not [string]::IsNullOrWhiteSpace($direct)) { return $direct }

    $calicoMetadata = [string]$Resource.metadata.annotations.'projectcalico.org/metadata'
    if (-not [string]::IsNullOrWhiteSpace($calicoMetadata)) {
        try {
            $decoded = $calicoMetadata | ConvertFrom-Json
            $annotated = [string]$decoded.labels.$Key
            if (-not [string]::IsNullOrWhiteSpace($annotated)) { return $annotated }
        } catch {
            return $null
        }
    }

    $null
}

function Split-KubeNetCalicoSelector {
    param([string]$Text, [string]$Operator)

    $items = @()
    $depth = 0
    $quote = ''
    $start = 0
    for ($i = 0; $i -lt $Text.Length; $i++) {
        $char = $Text[$i]
        if ($quote) {
            if ($char -eq $quote) { $quote = '' }
            continue
        }
        if ($char -eq "'" -or $char -eq '"') {
            $quote = $char
            continue
        }
        if ($char -eq '(') { $depth++; continue }
        if ($char -eq ')') { $depth--; continue }
        if ($depth -eq 0 -and $i + $Operator.Length -le $Text.Length -and $Text.Substring($i, $Operator.Length) -eq $Operator) {
            $items += $Text.Substring($start, $i - $start).Trim()
            $start = $i + $Operator.Length
            $i += $Operator.Length - 1
        }
    }
    $items += $Text.Substring($start).Trim()
    @($items | Where-Object { -not [string]::IsNullOrWhiteSpace($_) })
}

function Remove-KubeNetCalicoOuterParens {
    param([string]$Text)

    $clean = $Text.Trim()
    while ($clean.StartsWith('(') -and $clean.EndsWith(')')) {
        $depth = 0
        $balanced = $true
        for ($i = 0; $i -lt $clean.Length; $i++) {
            if ($clean[$i] -eq '(') { $depth++ }
            if ($clean[$i] -eq ')') { $depth-- }
            if ($depth -eq 0 -and $i -lt ($clean.Length - 1)) {
                $balanced = $false
                break
            }
        }
        if (-not $balanced) { break }
        $clean = $clean.Substring(1, $clean.Length - 2).Trim()
    }
    $clean
}

function Test-KubeNetCalicoSelector {
    param([string]$Selector, [object]$Resource)

    if ([string]::IsNullOrWhiteSpace($Selector) -or $Selector.Trim() -eq 'all()') { return $true }
    $clean = Remove-KubeNetCalicoOuterParens -Text $Selector
    if ($clean -eq 'global()') {
        return [string]::IsNullOrWhiteSpace([string]$Resource.metadata.namespace)
    }

    $orParts = Split-KubeNetCalicoSelector -Text $clean -Operator '||'
    if ($orParts.Count -gt 1) {
        foreach ($part in $orParts) {
            if (Test-KubeNetCalicoSelector -Selector $part -Resource $Resource) { return $true }
        }
        return $false
    }

    $andParts = Split-KubeNetCalicoSelector -Text $clean -Operator '&&'
    if ($andParts.Count -gt 1) {
        foreach ($part in $andParts) {
            if (-not (Test-KubeNetCalicoSelector -Selector $part -Resource $Resource)) { return $false }
        }
        return $true
    }

    if ($clean.StartsWith('!')) {
        return -not (Test-KubeNetCalicoSelector -Selector $clean.Substring(1).Trim() -Resource $Resource)
    }

    if ($clean -match '^has\(([A-Za-z0-9_./-]+)\)$') {
        return -not [string]::IsNullOrWhiteSpace((Get-KubeNetCalicoLabelValue -Resource $Resource -Key $Matches[1]))
    }

    if ($clean -match '^([A-Za-z0-9_./-]+)\s*(==|=)\s*["'']?([^"'']+)["'']?$') {
        return (Get-KubeNetCalicoLabelValue -Resource $Resource -Key $Matches[1]) -eq $Matches[3]
    }

    if ($clean -match '^([A-Za-z0-9_./-]+)\s*!=\s*["'']?([^"'']+)["'']?$') {
        return (Get-KubeNetCalicoLabelValue -Resource $Resource -Key $Matches[1]) -ne $Matches[2]
    }

    if ($clean -match '^([A-Za-z0-9_./-]+)\s+in\s+\{(.+)\}$') {
        $actual = Get-KubeNetCalicoLabelValue -Resource $Resource -Key $Matches[1]
        $values = @($Matches[2] -split ',' | ForEach-Object { $_.Trim().Trim("'").Trim('"') })
        return $values -contains $actual
    }

    if ($clean -match '^([A-Za-z0-9_./-]+)\s+not\s+in\s+\{(.+)\}$') {
        $actual = Get-KubeNetCalicoLabelValue -Resource $Resource -Key $Matches[1]
        $values = @($Matches[2] -split ',' | ForEach-Object { $_.Trim().Trim("'").Trim('"') })
        return -not ($values -contains $actual)
    }

    if ($clean -match '^([A-Za-z0-9_./-]+)\s+(contains|starts with|ends with)\s+["'']([^"'']+)["'']$') {
        $actual = [string](Get-KubeNetCalicoLabelValue -Resource $Resource -Key $Matches[1])
        $expected = $Matches[3]
        switch ($Matches[2]) {
            'contains' { return $actual.Contains($expected) }
            'starts with' { return $actual.StartsWith($expected) }
            'ends with' { return $actual.EndsWith($expected) }
        }
    }

    $false
}

function Test-KubeNetCalicoPolicyAppliesToPod {
    param([object]$Policy, [object]$Pod)

    $policyNamespace = [string]$Policy.metadata.namespace
    $isGlobal = [string]$Policy.kind -eq 'GlobalNetworkPolicy' -or [string]::IsNullOrWhiteSpace($policyNamespace)
    if (-not $isGlobal -and [string]$Pod.metadata.namespace -ne $policyNamespace) {
        return $false
    }

    Test-KubeNetCalicoSelector -Selector ([string]$Policy.spec.selector) -Resource $Pod
}

function Get-KubeNetCalicoPolicyTypes {
    param([object]$Policy)

    $types = @($Policy.spec.types | ForEach-Object { [string]$_ })
    if ($types.Count -eq 0) {
        $types += 'Ingress'
        if ($null -ne $Policy.spec.egress) { $types += 'Egress' }
    }
    @($types | Sort-Object -Unique)
}

function Get-KubeNetCalicoPolicyOrder {
    param([object]$Policy)

    $order = 1000000.0
    $parsed = 0.0
    if ([double]::TryParse([string]$Policy.spec.order, [ref]$parsed)) { $order = $parsed }
    $order
}

function Get-KubeNetCalicoPolicyTier {
    param([object]$Policy)
    if ($Policy.spec.tier) { return [string]$Policy.spec.tier }
    'default'
}

function Get-KubeNetCalicoTierOrder {
    param([string]$TierName, [object[]]$Tiers)

    if ([string]::IsNullOrWhiteSpace($TierName)) { $TierName = 'default' }
    foreach ($tier in @($Tiers)) {
        if ([string]$tier.metadata.name -eq $TierName) {
            $parsed = 0.0
            if ([double]::TryParse([string]$tier.spec.order, [ref]$parsed)) { return $parsed }
        }
    }
    if ($TierName -eq 'default') { return 1000000.0 }
    500000.0
}

function Get-KubeNetCalicoTierDefaultAction {
    param([string]$TierName, [object[]]$Tiers)

    foreach ($tier in @($Tiers)) {
        if ([string]$tier.metadata.name -eq $TierName -and $tier.spec.defaultAction) {
            return [string]$tier.spec.defaultAction
        }
    }
    if ($TierName -eq 'default') { return 'Pass' }
    'Deny'
}

function Get-KubeNetCalicoPortFacts {
    param([object]$ServicePortObject, [object[]]$ContainerPorts)

    $ports = Get-KubeNetPathPorts -ServicePortObject $ServicePortObject -ContainerPorts $ContainerPorts
    $protocol = 'TCP'
    if ($ServicePortObject -and $ServicePortObject.protocol) { $protocol = [string]$ServicePortObject.protocol }
    $names = @()
    if ($ServicePortObject -and $ServicePortObject.name) { $names += [string]$ServicePortObject.name }
    if ($ServicePortObject -and $ServicePortObject.targetPort) {
        $targetText = [string]$ServicePortObject.targetPort
        $number = 0
        if (-not [int]::TryParse($targetText, [ref]$number)) { $names += $targetText }
    }
    $names += @($ContainerPorts | Where-Object { $_.ContainerPort -in $ports -and -not [string]::IsNullOrWhiteSpace($_.Name) } | ForEach-Object { [string]$_.Name })

    [PSCustomObject]@{
        Ports    = @($ports | Where-Object { $_ -gt 0 } | Sort-Object -Unique)
        Names    = @($names | Where-Object { -not [string]::IsNullOrWhiteSpace($_) } | Sort-Object -Unique)
        Protocol = $protocol.ToUpperInvariant()
    }
}

function Test-KubeNetCalicoPortTokenMatch {
    param([object]$RulePort, [object]$PortFacts)

    $text = [string]$RulePort
    if ([string]::IsNullOrWhiteSpace($text)) { return $true }

    $number = 0
    if ([int]::TryParse($text, [ref]$number)) {
        return @($PortFacts.Ports) -contains $number
    }

    if ($text -match '^(\d+):(\d+)$') {
        $start = [int]$Matches[1]
        $end = [int]$Matches[2]
        return @($PortFacts.Ports | Where-Object { $_ -ge $start -and $_ -le $end }).Count -gt 0
    }

    @($PortFacts.Names) -contains $text
}

function Test-KubeNetCalicoPortSetMatches {
    param([object[]]$Ports, [object[]]$NotPorts, [object]$PortFacts)

    $positive = @($Ports | Where-Object { $null -ne $_ })
    if ($positive.Count -gt 0) {
        $matchedPositive = $false
        foreach ($port in $positive) {
            if (Test-KubeNetCalicoPortTokenMatch -RulePort $port -PortFacts $PortFacts) {
                $matchedPositive = $true
                break
            }
        }
        if (-not $matchedPositive) { return $false }
    }

    foreach ($port in @($NotPorts | Where-Object { $null -ne $_ })) {
        if (Test-KubeNetCalicoPortTokenMatch -RulePort $port -PortFacts $PortFacts) {
            return $false
        }
    }

    $true
}

function Test-KubeNetCalicoRuleProtocolMatches {
    param([object]$Rule, [object]$PortFacts)

    if ($null -eq $Rule.protocol) { return $true }
    ([string]$Rule.protocol).ToUpperInvariant() -eq [string]$PortFacts.Protocol
}

function Test-KubeNetCalicoServiceAccountMatches {
    param([object]$ServiceAccounts, [object]$Pod)

    if ($null -eq $ServiceAccounts) { return $true }
    $podSa = if ($Pod.spec.serviceAccountName) { [string]$Pod.spec.serviceAccountName } else { 'default' }
    $names = @($ServiceAccounts.names | ForEach-Object { [string]$_ })
    if ($names.Count -gt 0 -and -not ($names -contains $podSa)) { return $false }
    if ($ServiceAccounts.selector) {
        # ServiceAccount label selector support requires reading ServiceAccount objects. Treat as not proven.
        return $false
    }
    $true
}

function Get-KubeNetCalicoResourceIps {
    param([object[]]$Pods, [object]$Service)

    $ips = @()
    if ($Service -and $Service.spec.clusterIP -and $Service.spec.clusterIP -ne 'None') { $ips += [string]$Service.spec.clusterIP }
    foreach ($pod in @($Pods)) {
        if ($pod.status.podIP) { $ips += [string]$pod.status.podIP }
        foreach ($podIp in @($pod.status.podIPs)) {
            if ($podIp.ip) { $ips += [string]$podIp.ip }
        }
    }
    @($ips | Where-Object { -not [string]::IsNullOrWhiteSpace($_) } | Sort-Object -Unique)
}

function Test-KubeNetCalicoIpsInCidrs {
    param([string[]]$Ips, [object[]]$Cidrs)

    $usableCidrs = @($Cidrs | ForEach-Object { [string]$_ } | Where-Object { -not [string]::IsNullOrWhiteSpace($_) })
    if ($usableCidrs.Count -eq 0) { return $true }
    foreach ($cidr in $usableCidrs) {
        foreach ($ip in @($Ips)) {
            if (Test-KubeNetIpv4InCidr -Address $ip -Cidr $cidr) { return $true }
        }
    }
    $false
}

function Test-KubeNetCalicoIpsNotInCidrs {
    param([string[]]$Ips, [object[]]$Cidrs)

    $usableCidrs = @($Cidrs | ForEach-Object { [string]$_ } | Where-Object { -not [string]::IsNullOrWhiteSpace($_) })
    if ($usableCidrs.Count -eq 0) { return $true }
    foreach ($cidr in $usableCidrs) {
        foreach ($ip in @($Ips)) {
            if (Test-KubeNetIpv4InCidr -Address $ip -Cidr $cidr) { return $false }
        }
    }
    $true
}

function Test-KubeNetCalicoNetworkSetMatches {
    param(
        [object]$NetworkSet,
        [string]$Selector,
        [string]$NamespaceSelector,
        [object]$PeerNamespace,
        [string[]]$PeerIps
    )

    if (-not (Test-KubeNetCalicoSelector -Selector $Selector -Resource $NetworkSet)) { return $false }

    $isGlobal = [string]$NetworkSet.kind -eq 'GlobalNetworkSet' -or [string]::IsNullOrWhiteSpace([string]$NetworkSet.metadata.namespace)
    if ($isGlobal) {
        if (-not ([string]::IsNullOrWhiteSpace($NamespaceSelector) -or $NamespaceSelector -match 'global\(\)')) { return $false }
    } else {
        if ([string]::IsNullOrWhiteSpace($NamespaceSelector)) {
            if ([string]$NetworkSet.metadata.namespace -ne [string]$PeerNamespace.metadata.name) { return $false }
        } elseif (-not (Test-KubeNetCalicoSelector -Selector $NamespaceSelector -Resource $PeerNamespace)) {
            return $false
        }
    }

    Test-KubeNetCalicoIpsInCidrs -Ips $PeerIps -Cidrs @($NetworkSet.spec.nets)
}

function Test-KubeNetCalicoEntityMatches {
    param(
        [object]$Entity,
        [object[]]$PeerPods,
        [object]$PeerNamespace,
        [string[]]$PeerIps,
        [object]$Service,
        [object[]]$NetworkSets,
        [object]$PortFacts,
        [string]$PolicyNamespace,
        [bool]$PolicyIsGlobal
    )

    if ($null -eq $Entity) {
        return [PSCustomObject]@{ Matches = $true; Reason = 'no entity criteria, matches all packets' }
    }

    if (-not (Test-KubeNetCalicoPortSetMatches -Ports @($Entity.ports) -NotPorts @($Entity.notPorts) -PortFacts $PortFacts)) {
        return [PSCustomObject]@{ Matches = $false; Reason = 'port/notPort criteria do not match tested path' }
    }

    if (-not (Test-KubeNetCalicoIpsInCidrs -Ips $PeerIps -Cidrs @($Entity.nets))) {
        return [PSCustomObject]@{ Matches = $false; Reason = 'nets do not include tested service/pod IPs' }
    }

    if (-not (Test-KubeNetCalicoIpsNotInCidrs -Ips $PeerIps -Cidrs @($Entity.notNets))) {
        return [PSCustomObject]@{ Matches = $false; Reason = 'notNets exclude tested service/pod IPs' }
    }

    if ($Entity.services) {
        $services = @($Entity.services | Where-Object { $null -ne $_ })
        $matchedService = $false
        foreach ($svc in $services) {
            $svcName = [string]$svc.name
            $svcNamespace = if ($svc.namespace) { [string]$svc.namespace } else { [string]$Service.metadata.namespace }
            if ($svcName -eq [string]$Service.metadata.name -and $svcNamespace -eq [string]$Service.metadata.namespace) {
                $matchedService = $true
                break
            }
        }
        if (-not $matchedService) {
            return [PSCustomObject]@{ Matches = $false; Reason = 'service match does not target this service' }
        }
    }

    if (-not (Test-KubeNetCalicoServiceAccountMatches -ServiceAccounts $Entity.serviceAccounts -Pod $PeerPods[0])) {
        return [PSCustomObject]@{ Matches = $false; Reason = 'serviceAccount criteria do not match or require label lookup' }
    }

    $selector = [string]$Entity.selector
    $notSelector = [string]$Entity.notSelector
    $namespaceSelector = [string]$Entity.namespaceSelector
    if ([string]::IsNullOrWhiteSpace($selector) -and [string]::IsNullOrWhiteSpace($notSelector)) {
        return [PSCustomObject]@{ Matches = $true; Reason = 'IP/service/port criteria match, no selector restriction' }
    }

    $scopeAllowsPods = $true
    if (-not [string]::IsNullOrWhiteSpace($namespaceSelector)) {
        $scopeAllowsPods = Test-KubeNetCalicoSelector -Selector $namespaceSelector -Resource $PeerNamespace
    } elseif (-not $PolicyIsGlobal -and $PeerNamespace.metadata.name -ne $PolicyNamespace) {
        $scopeAllowsPods = $false
    }

    $podMatch = $false
    if ($scopeAllowsPods) {
        foreach ($pod in @($PeerPods)) {
            $positive = if ([string]::IsNullOrWhiteSpace($selector)) { $true } else { Test-KubeNetCalicoSelector -Selector $selector -Resource $pod }
            $negative = if ([string]::IsNullOrWhiteSpace($notSelector)) { $false } else { Test-KubeNetCalicoSelector -Selector $notSelector -Resource $pod }
            if ($positive -and -not $negative) {
                $podMatch = $true
                break
            }
        }
    }

    if ($podMatch) {
        return [PSCustomObject]@{ Matches = $true; Reason = 'selector matches peer pod/namespace' }
    }

    foreach ($networkSet in @($NetworkSets)) {
        $positive = if ([string]::IsNullOrWhiteSpace($selector)) { $true } else { Test-KubeNetCalicoNetworkSetMatches -NetworkSet $networkSet -Selector $selector -NamespaceSelector $namespaceSelector -PeerNamespace $PeerNamespace -PeerIps $PeerIps }
        $negative = if ([string]::IsNullOrWhiteSpace($notSelector)) { $false } else { Test-KubeNetCalicoNetworkSetMatches -NetworkSet $networkSet -Selector $notSelector -NamespaceSelector $namespaceSelector -PeerNamespace $PeerNamespace -PeerIps $PeerIps }
        if ($positive -and -not $negative) {
            return [PSCustomObject]@{ Matches = $true; Reason = "selector matches network set '$($networkSet.metadata.name)'" }
        }
    }

    [PSCustomObject]@{ Matches = $false; Reason = 'selector/namespaceSelector criteria do not match peer pods or network sets' }
}

function Test-KubeNetCalicoRuleLooksLikeDnsAllow {
    param([object]$Rule, [object]$PortFacts)

    if ($null -eq $Rule -or [string]$Rule.action -ne 'Allow') { return $false }
    if (-not (Test-KubeNetCalicoRuleProtocolMatches -Rule $Rule -PortFacts ([PSCustomObject]@{ Protocol = 'UDP'; Ports = @(53); Names = @() }))) {
        if (-not (Test-KubeNetCalicoRuleProtocolMatches -Rule $Rule -PortFacts ([PSCustomObject]@{ Protocol = 'TCP'; Ports = @(53); Names = @() }))) { return $false }
    }
    Test-KubeNetCalicoPortSetMatches -Ports @($Rule.destination.ports) -NotPorts @($Rule.destination.notPorts) -PortFacts ([PSCustomObject]@{ Protocol = 'UDP'; Ports = @(53); Names = @() })
}

function Get-KubeNetCalicoDnsResolverPeers {
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

function Test-KubeNetCalicoRuleMatchesDnsResolver {
    param(
        [object]$Rule,
        [string]$Nameserver,
        [object[]]$CoreDnsPods,
        [object[]]$NodeLocalDnsPods,
        [object]$KubeSystemNamespace,
        [string]$CoreDnsServiceIp,
        [object[]]$NetworkSets,
        [string]$PolicyNamespace,
        [bool]$PolicyIsGlobal
    )

    $udpFacts = [PSCustomObject]@{ Protocol = 'UDP'; Ports = @(53); Names = @() }
    $tcpFacts = [PSCustomObject]@{ Protocol = 'TCP'; Ports = @(53); Names = @() }
    $matchesProtocol = (Test-KubeNetCalicoRuleProtocolMatches -Rule $Rule -PortFacts $udpFacts) -or
        (Test-KubeNetCalicoRuleProtocolMatches -Rule $Rule -PortFacts $tcpFacts)
    if (-not $matchesProtocol) {
        return [PSCustomObject]@{ Matches = $false; Reason = 'rule protocol does not match UDP/TCP DNS' }
    }
    if (-not (Test-KubeNetCalicoPortSetMatches -Ports @($Rule.destination.ports) -NotPorts @($Rule.destination.notPorts) -PortFacts $udpFacts)) {
        return [PSCustomObject]@{ Matches = $false; Reason = 'destination port criteria do not match DNS port 53' }
    }

    $resolver = Get-KubeNetCalicoDnsResolverPeers -Nameserver $Nameserver -CoreDnsPods $CoreDnsPods -NodeLocalDnsPods $NodeLocalDnsPods -KubeSystemNamespace $KubeSystemNamespace -CoreDnsServiceIp $CoreDnsServiceIp
    $entity = Test-KubeNetCalicoEntityMatches -Entity $Rule.destination -PeerPods $resolver.PeerPods -PeerNamespace $resolver.PeerNamespace -PeerIps $resolver.PeerIps -Service $null -NetworkSets $NetworkSets -PortFacts $udpFacts -PolicyNamespace $PolicyNamespace -PolicyIsGlobal $PolicyIsGlobal
    if ($entity.Matches) {
        return [PSCustomObject]@{ Matches = $true; Reason = "$($resolver.Kind) resolver $Nameserver matched destination criteria: $($entity.Reason)" }
    }

    [PSCustomObject]@{ Matches = $false; Reason = "$($resolver.Kind) resolver $Nameserver did not match destination criteria: $($entity.Reason)" }
}

function New-KubeNetCalicoDiagnosisBlock {
    param([string[]]$Lines)

    (@($Lines | Where-Object { -not [string]::IsNullOrWhiteSpace($_) }) -join "`n")
}

function Test-KubeNetCalicoDnsEgressPolicy {
    param(
        [object[]]$Policies,
        [object[]]$NetworkSets,
        [object[]]$Tiers,
        [object]$SourcePod,
        [object]$ResolvSummary,
        [object[]]$CoreDnsPods,
        [object[]]$NodeLocalDnsPods,
        [object]$KubeSystemNamespace,
        [string]$CoreDnsServiceIp
    )

    $results = @()
    $diagnoses = @()
    if ($null -eq $SourcePod -or $null -eq $ResolvSummary -or @($ResolvSummary.Nameservers).Count -eq 0) {
        return [PSCustomObject]@{ Results = $results; Diagnoses = $diagnoses; AnyDnsAllow = $false; AnyBlocked = $false }
    }

    $selectedPolicies = @($Policies | Where-Object {
        $null -ne $_ -and
        [string]$_.kind -notmatch '^Staged' -and
        (Get-KubeNetCalicoPolicyTypes -Policy $_) -contains 'Egress' -and
        (Test-KubeNetCalicoPolicyAppliesToPod -Policy $_ -Pod $SourcePod)
    })
    if ($selectedPolicies.Count -eq 0) {
        return [PSCustomObject]@{ Results = $results; Diagnoses = $diagnoses; AnyDnsAllow = $false; AnyBlocked = $false }
    }

    $policyNames = @($selectedPolicies | ForEach-Object {
        $ns = [string]$_.metadata.namespace
        $tier = Get-KubeNetCalicoPolicyTier -Policy $_
        if ([string]::IsNullOrWhiteSpace($ns)) { "$($_.metadata.name) ($tier)" } else { "$ns/$($_.metadata.name) ($tier)" }
    } | Sort-Object -Unique)
    $resolverMessages = @()
    $blockedResolvers = @()
    $anyAllow = $false

    foreach ($nameserver in @($ResolvSummary.Nameservers)) {
        $dnsMatches = @()
        foreach ($policy in @($selectedPolicies)) {
            $policyNamespace = [string]$policy.metadata.namespace
            $policyName = if ([string]::IsNullOrWhiteSpace($policyNamespace)) { [string]$policy.metadata.name } else { "$policyNamespace/$($policy.metadata.name)" }
            $policyIsGlobal = [string]$policy.kind -eq 'GlobalNetworkPolicy' -or [string]::IsNullOrWhiteSpace($policyNamespace)
            $tier = Get-KubeNetCalicoPolicyTier -Policy $policy
            $tierOrder = Get-KubeNetCalicoTierOrder -TierName $tier -Tiers $Tiers
            $policyOrder = Get-KubeNetCalicoPolicyOrder -Policy $policy
            $ruleIndex = 0
            foreach ($rule in @($policy.spec.egress | Where-Object { $null -ne $_ })) {
                $ruleIndex++
                $action = [string]$rule.action
                if ($action -notin @('Allow', 'Deny', 'Pass', 'Log')) { continue }
                if ($action -eq 'Log') { continue }
                $match = Test-KubeNetCalicoRuleMatchesDnsResolver -Rule $rule -Nameserver $nameserver -CoreDnsPods $CoreDnsPods -NodeLocalDnsPods $NodeLocalDnsPods -KubeSystemNamespace $KubeSystemNamespace -CoreDnsServiceIp $CoreDnsServiceIp -NetworkSets $NetworkSets -PolicyNamespace $policyNamespace -PolicyIsGlobal $policyIsGlobal
                if ($match.Matches) {
                    $dnsMatches += [PSCustomObject]@{ Policy = $policyName; Tier = $tier; TierOrder = $tierOrder; PolicyOrder = $policyOrder; Action = $action; RuleIndex = $ruleIndex; Reason = $match.Reason }
                }
            }
        }

        $orderedDnsMatches = @($dnsMatches | Sort-Object TierOrder, PolicyOrder, RuleIndex, Policy)
        $firstDnsMatch = $orderedDnsMatches | Select-Object -First 1
        if ($firstDnsMatch -and $firstDnsMatch.Action -eq 'Pass') {
            $pass = $firstDnsMatch
            $firstDnsMatch = @($orderedDnsMatches | Where-Object { $_.TierOrder -gt $pass.TierOrder } | Select-Object -First 1)
        }

        $kind = Get-KubeNetDnsResolverKind -Nameserver $nameserver -CoreDnsServiceIp $CoreDnsServiceIp
        if ($firstDnsMatch -and $firstDnsMatch.Action -eq 'Allow') {
            $anyAllow = $true
            $resolverMessages += "Resolver $nameserver ($kind) is allowed by $($firstDnsMatch.Policy) in tier '$($firstDnsMatch.Tier)'."
        } elseif ($firstDnsMatch -and $firstDnsMatch.Action -eq 'Deny') {
            $blockedResolvers += "$nameserver ($kind)"
            $resolverMessages += "Resolver $nameserver ($kind) is explicitly denied by $($firstDnsMatch.Policy) in tier '$($firstDnsMatch.Tier)'."
        } else {
            $blockedResolvers += "$nameserver ($kind)"
            $resolverMessages += "Resolver $nameserver ($kind) has no matching Calico Allow/Pass rule."
        }
    }

    if ($blockedResolvers.Count -gt 0) {
        $results += [PSCustomObject]@{ Check = 'Calico DNS egress resolver'; Status = 'FAIL'; Message = "Calico egress policy selects source pod '$($SourcePod.metadata.name)', but runtime DNS resolver(s) are not allowed. $($resolverMessages -join ' ') Selecting policy/policies: $($policyNames -join ', ')." }
        $resolverLine = $blockedResolvers -join ', '
        if (($blockedResolvers -join ' ') -match 'NodeLocalDNS') {
            $diagnoses += New-KubeNetCalicoDiagnosisBlock -Lines @(
                'Primary issue: Calico egress policy does not allow the source pod runtime DNS resolver.',
                ('Source: `{0}/{1}`' -f $SourcePod.metadata.namespace, $SourcePod.metadata.name),
                ('Runtime resolver(s): `{0}`' -f $resolverLine),
                ('Policy/policies: `{0}`' -f ($policyNames -join ', ')),
                'Why it failed: DNS policy appears to allow a different DNS path, but this pod is configured to query a NodeLocalDNS/link-local resolver instead.'
            )
        } else {
            $diagnoses += New-KubeNetCalicoDiagnosisBlock -Lines @(
                'Primary issue: Calico egress policy may block DNS for the source pod.',
                ('Source: `{0}/{1}`' -f $SourcePod.metadata.namespace, $SourcePod.metadata.name),
                ('Runtime resolver(s): `{0}`' -f $resolverLine),
                ('Policy/policies: `{0}`' -f ($policyNames -join ', ')),
                'Why it failed: No Calico Allow/Pass rule obviously matches the pod runtime resolver on UDP/TCP 53.'
            )
        }
        return [PSCustomObject]@{ Results = $results; Diagnoses = $diagnoses; AnyDnsAllow = $anyAllow; AnyBlocked = $true }
    }

    $results += [PSCustomObject]@{ Check = 'Calico DNS egress resolver'; Status = 'PASS'; Message = "Calico egress policy appears to allow source pod '$($SourcePod.metadata.name)' to its runtime DNS resolver(s). $($resolverMessages -join ' ')" }
    [PSCustomObject]@{ Results = $results; Diagnoses = $diagnoses; AnyDnsAllow = $true; AnyBlocked = $false }
}

function New-KubeNetCalicoUnsupportedResults {
    param([object[]]$Policies)

    $results = @()
    $staged = @($Policies | Where-Object { [string]$_.kind -match '^Staged' })
    if ($staged.Count -gt 0) {
        $results += [PSCustomObject]@{ Check = 'Calico staged policies'; Status = 'INFO'; Message = "Staged Calico policies were detected but are not enforced; they are not used for path decisions. Staged policies: $((@($staged | ForEach-Object { $_.metadata.name }) | Sort-Object -Unique) -join ', ')." }
    }

    foreach ($policy in @($Policies | Where-Object { $null -ne $_ })) {
        foreach ($rule in @($policy.spec.ingress + $policy.spec.egress | Where-Object { $null -ne $_ })) {
            if ($rule.http) {
                $name = if ($policy.metadata.namespace) { "$($policy.metadata.namespace)/$($policy.metadata.name)" } else { [string]$policy.metadata.name }
                $results += [PSCustomObject]@{ Check = 'Calico HTTP policy'; Status = 'WARN'; Message = "Policy '$name' contains HTTP/application-layer criteria. KubeNetMods does not emulate Calico L7 policy matching." }
                break
            }
            if ($rule.icmp) {
                $name = if ($policy.metadata.namespace) { "$($policy.metadata.namespace)/$($policy.metadata.name)" } else { [string]$policy.metadata.name }
                $results += [PSCustomObject]@{ Check = 'Calico ICMP policy'; Status = 'INFO'; Message = "Policy '$name' contains ICMP criteria. The tested service path is treated as TCP/UDP, so ICMP is not used for the path decision." }
                break
            }
        }
    }
    @($results)
}

function Test-KubeNetCalicoPolicyPath {
    param(
        [object[]]$Policies,
        [object[]]$NetworkSets = @(),
        [object[]]$Tiers = @(),
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

    $enforcedPolicies = @($Policies | Where-Object { $null -ne $_ -and [string]$_.kind -notmatch '^Staged' })
    $results = @(New-KubeNetCalicoUnsupportedResults -Policies $Policies)
    $diagnoses = @()
    if ($enforcedPolicies.Count -eq 0) {
        $results += [PSCustomObject]@{ Check = 'Calico policies'; Status = 'INFO'; Message = 'No enforced Calico NetworkPolicy/GlobalNetworkPolicy objects were found or readable.' }
        return [PSCustomObject]@{ Results = $results; Diagnoses = $diagnoses }
    }

    $portFacts = Get-KubeNetCalicoPortFacts -ServicePortObject $ServicePortObject -ContainerPorts $ContainerPorts
    $targetIps = Get-KubeNetCalicoResourceIps -Pods $TargetPods -Service $Service
    $sourceIps = Get-KubeNetCalicoResourceIps -Pods @($SourcePod) -Service $null
    $matchingRules = @()
    $sourceEgressEnforcing = @()
    $sourceDnsAllow = @()
    $targetIngressEnforcing = @()

    foreach ($policy in @($enforcedPolicies)) {
        $policyNamespace = [string]$policy.metadata.namespace
        $policyName = if ([string]::IsNullOrWhiteSpace($policyNamespace)) { [string]$policy.metadata.name } else { "$policyNamespace/$($policy.metadata.name)" }
        $policyIsGlobal = [string]$policy.kind -eq 'GlobalNetworkPolicy' -or [string]::IsNullOrWhiteSpace($policyNamespace)
        $tier = Get-KubeNetCalicoPolicyTier -Policy $policy
        $tierOrder = Get-KubeNetCalicoTierOrder -TierName $tier -Tiers $Tiers
        $policyOrder = Get-KubeNetCalicoPolicyOrder -Policy $policy
        $types = Get-KubeNetCalicoPolicyTypes -Policy $policy

        if ($types -contains 'Egress' -and (Test-KubeNetCalicoPolicyAppliesToPod -Policy $policy -Pod $SourcePod)) {
            $sourceEgressEnforcing += "$policyName ($tier)"
            $ruleIndex = 0
            foreach ($rule in @($policy.spec.egress | Where-Object { $null -ne $_ })) {
                $ruleIndex++
                $action = [string]$rule.action
                if ($action -notin @('Allow', 'Deny', 'Pass', 'Log')) { continue }
                if (Test-KubeNetCalicoRuleLooksLikeDnsAllow -Rule $rule -PortFacts $portFacts) {
                    $sourceDnsAllow += "$policyName egress"
                }
                if ($action -eq 'Log') { continue }
                if (-not (Test-KubeNetCalicoRuleProtocolMatches -Rule $rule -PortFacts $portFacts)) { continue }
                $entity = Test-KubeNetCalicoEntityMatches -Entity $rule.destination -PeerPods $TargetPods -PeerNamespace $TargetNamespace -PeerIps $targetIps -Service $Service -NetworkSets $NetworkSets -PortFacts $portFacts -PolicyNamespace $policyNamespace -PolicyIsGlobal $policyIsGlobal
                if ($entity.Matches) {
                    $matchingRules += [PSCustomObject]@{ Policy = $policyName; Tier = $tier; TierOrder = $tierOrder; PolicyOrder = $policyOrder; Direction = 'egress'; Action = $action; RuleIndex = $ruleIndex; Reason = $entity.Reason }
                }
            }
        }

        if ($types -contains 'Ingress') {
            $appliesToAnyTarget = $false
            foreach ($targetPod in @($TargetPods)) {
                if (Test-KubeNetCalicoPolicyAppliesToPod -Policy $policy -Pod $targetPod) {
                    $appliesToAnyTarget = $true
                    break
                }
            }
            if ($appliesToAnyTarget) {
                $targetIngressEnforcing += "$policyName ($tier)"
                $ruleIndex = 0
                foreach ($rule in @($policy.spec.ingress | Where-Object { $null -ne $_ })) {
                    $ruleIndex++
                    $action = [string]$rule.action
                    if ($action -notin @('Allow', 'Deny', 'Pass', 'Log')) { continue }
                    if ($action -eq 'Log') { continue }
                    if (-not (Test-KubeNetCalicoRuleProtocolMatches -Rule $rule -PortFacts $portFacts)) { continue }
                    $sourceEntity = Test-KubeNetCalicoEntityMatches -Entity $rule.source -PeerPods @($SourcePod) -PeerNamespace $SourceNamespace -PeerIps $sourceIps -Service $Service -NetworkSets $NetworkSets -PortFacts $portFacts -PolicyNamespace $policyNamespace -PolicyIsGlobal $policyIsGlobal
                    $destEntity = Test-KubeNetCalicoEntityMatches -Entity $rule.destination -PeerPods $TargetPods -PeerNamespace $TargetNamespace -PeerIps $targetIps -Service $Service -NetworkSets $NetworkSets -PortFacts $portFacts -PolicyNamespace $policyNamespace -PolicyIsGlobal $policyIsGlobal
                    if ($sourceEntity.Matches -and $destEntity.Matches) {
                        $matchingRules += [PSCustomObject]@{ Policy = $policyName; Tier = $tier; TierOrder = $tierOrder; PolicyOrder = $policyOrder; Direction = 'ingress'; Action = $action; RuleIndex = $ruleIndex; Reason = "source: $($sourceEntity.Reason); destination: $($destEntity.Reason)" }
                    }
                }
            }
        }
    }

    $orderedMatches = @($matchingRules | Sort-Object TierOrder, PolicyOrder, RuleIndex, Policy, Direction)
    $firstMatch = $orderedMatches | Select-Object -First 1
    if ($firstMatch -and $firstMatch.Action -eq 'Pass') {
        $passMatch = $firstMatch
        $nextTierMatch = @($orderedMatches | Where-Object { $_.TierOrder -gt $passMatch.TierOrder } | Select-Object -First 1)
        if ($nextTierMatch) {
            $results += [PSCustomObject]@{ Check = 'Calico target path pass action'; Status = 'INFO'; Message = "For the target service path, Calico Pass matched first in tier '$($passMatch.Tier)' via $($passMatch.Policy); continuing analysis with next matching tier '$($nextTierMatch.Tier)'." }
            $firstMatch = $nextTierMatch
        } else {
            $results += [PSCustomObject]@{ Check = 'Calico target path pass action'; Status = 'WARN'; Message = "For the target service path, first matching Calico action is Pass: $($passMatch.Policy) $($passMatch.Direction) in tier '$($passMatch.Tier)'. No later tier match was found; KubeNetMods does not evaluate workload profiles after Pass." }
            $firstMatch = $null
        }
    }

    if ($firstMatch) {
        if ($firstMatch.Action -eq 'Deny') {
            $results += [PSCustomObject]@{ Check = 'Calico target path first matching action'; Status = 'FAIL'; Message = "For the target service path, first matching Calico action is Deny: $($firstMatch.Policy) $($firstMatch.Direction) in tier '$($firstMatch.Tier)' (reason: $($firstMatch.Reason))." }
            $diagnoses += New-KubeNetCalicoDiagnosisBlock -Lines @(
                'Primary issue: Calico policy denies this source-to-service path.',
                ('Source: `{0}/{1}`' -f $SourcePod.metadata.namespace, $SourcePod.metadata.name),
                ('Target Service: `{0}/{1}`' -f $TargetNamespace.metadata.name, $Service.metadata.name),
                ('First match: `{0} {1} Deny` in tier `{2}`' -f $firstMatch.Policy, $firstMatch.Direction, $firstMatch.Tier),
                ('Why it failed: {0}' -f $firstMatch.Reason)
            )
        } elseif ($firstMatch.Action -eq 'Allow') {
            $results += [PSCustomObject]@{ Check = 'Calico target path first matching action'; Status = 'PASS'; Message = "For the target service path, first matching Calico action is Allow: $($firstMatch.Policy) $($firstMatch.Direction) in tier '$($firstMatch.Tier)' (reason: $($firstMatch.Reason))." }
            $laterDenies = @($orderedMatches | Where-Object { $_.Action -eq 'Deny' -and ($_.TierOrder -gt $firstMatch.TierOrder -or ($_.TierOrder -eq $firstMatch.TierOrder -and ($_.PolicyOrder -gt $firstMatch.PolicyOrder -or ($_.PolicyOrder -eq $firstMatch.PolicyOrder -and $_.RuleIndex -gt $firstMatch.RuleIndex)))) })
            if ($laterDenies.Count -gt 0) {
                $later = $laterDenies | Select-Object -First 1
                $results += [PSCustomObject]@{ Check = 'Calico target path later deny'; Status = 'INFO'; Message = "A later Deny also matches the target service path ($($later.Policy) $($later.Direction) in tier '$($later.Tier)'), but the earlier Allow is the first matching action for this path." }
            }
        }
    }

    if (-not $firstMatch -and $sourceEgressEnforcing.Count -gt 0) {
        $policyNames = @($sourceEgressEnforcing | Sort-Object -Unique)
        $results += [PSCustomObject]@{ Check = 'Calico target path egress default-deny'; Status = 'FAIL'; Message = "Calico policy selects source pod '$($SourcePod.metadata.name)' for egress, but no Calico Allow/Pass rule obviously matches the target service path/port. Selecting policy/policies: $($policyNames -join ', ')." }
        $diagnoses += New-KubeNetCalicoDiagnosisBlock -Lines @(
            'Primary issue: Calico egress policy does not allow the tested target Service.',
            ('Source: `{0}/{1}`' -f $SourcePod.metadata.namespace, $SourcePod.metadata.name),
            ('Target Service: `{0}/{1}`' -f $TargetNamespace.metadata.name, $Service.metadata.name),
            ('Policy/policies: `{0}`' -f ($policyNames -join ', ')),
            'Why it failed: the source pod is egress-isolated by Calico policy, but no Allow/Pass rule obviously matches the tested Service path.'
        )
    } elseif (-not $firstMatch -and $targetIngressEnforcing.Count -gt 0) {
        $policyNames = @($targetIngressEnforcing | Sort-Object -Unique)
        $results += [PSCustomObject]@{ Check = 'Calico target path ingress default-deny'; Status = 'FAIL'; Message = "Calico policy selects target pod(s) for ingress, but no Calico Allow/Pass rule obviously matches this source/target service port. Selecting policy/policies: $($policyNames -join ', ')." }
        $diagnoses += New-KubeNetCalicoDiagnosisBlock -Lines @(
            'Primary issue: Calico ingress policy does not allow this source.',
            ('Source: `{0}/{1}`' -f $SourcePod.metadata.namespace, $SourcePod.metadata.name),
            ('Target Service: `{0}/{1}`' -f $TargetNamespace.metadata.name, $Service.metadata.name),
            ('Policy/policies: `{0}`' -f ($policyNames -join ', ')),
            'Why it failed: the target pods are ingress-isolated by Calico policy, but no Allow/Pass rule obviously matches this source and Service port.'
        )
    }

    $dnsResolverAnalysis = Test-KubeNetCalicoDnsEgressPolicy -Policies $enforcedPolicies -NetworkSets $NetworkSets -Tiers $Tiers -SourcePod $SourcePod -ResolvSummary $SourceResolvSummary -CoreDnsPods $CoreDnsPods -NodeLocalDnsPods $NodeLocalDnsPods -KubeSystemNamespace $KubeSystemNamespace -CoreDnsServiceIp $CoreDnsServiceIp
    $results += @($dnsResolverAnalysis.Results)
    $diagnoses += @($dnsResolverAnalysis.Diagnoses)

    if ($sourceEgressEnforcing.Count -gt 0 -and $sourceDnsAllow.Count -eq 0 -and -not $dnsResolverAnalysis.AnyBlocked -and -not $dnsResolverAnalysis.AnyDnsAllow) {
        $policyNames = @($sourceEgressEnforcing | Sort-Object -Unique)
        $status = if ($firstMatch -and $firstMatch.Action -eq 'Allow') { 'WARN' } else { 'INFO' }
        $results += [PSCustomObject]@{ Check = 'Calico DNS egress allow'; Status = $status; Message = "Calico policy selects source pod '$($SourcePod.metadata.name)' for egress, and no obvious DNS egress allow rule was found. DNS lookups may fail even if the target service is allowed. Selecting policy/policies: $($policyNames -join ', ')." }
        if ($status -eq 'WARN') {
            $diagnoses += New-KubeNetCalicoDiagnosisBlock -Lines @(
                'Likely issue: Calico egress policy may block DNS for the source pod.',
                ('Source: `{0}/{1}`' -f $SourcePod.metadata.namespace, $SourcePod.metadata.name),
                ('Policy/policies: `{0}`' -f ($policyNames -join ', ')),
                'Why it may fail: target traffic appears allowed, but no obvious DNS egress Allow/Pass rule was found.'
            )
        }
    }

    if ($results.Count -eq 0 -or @($results | Where-Object { $_.Check -match 'Calico' }).Count -eq 0) {
        $results += [PSCustomObject]@{ Check = 'Calico target service path'; Status = 'PASS'; Message = 'No enforced Calico policy obviously blocks this source-to-target service path.' }
    }

    [PSCustomObject]@{ Results = $results; Diagnoses = $diagnoses }
}
