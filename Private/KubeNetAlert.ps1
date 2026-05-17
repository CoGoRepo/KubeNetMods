function ConvertTo-KubeNetMap {
    param([object]$InputObject)

    $map = @{}
    if ($null -eq $InputObject) { return $map }

    if ($InputObject -is [System.Collections.IDictionary]) {
        foreach ($key in $InputObject.Keys) {
            if ($null -ne $key) { $map[[string]$key] = $InputObject[$key] }
        }
        return $map
    }

    foreach ($property in @($InputObject.PSObject.Properties)) {
        $map[$property.Name] = $property.Value
    }
    $map
}

function Merge-KubeNetMap {
    param([hashtable[]]$Maps)

    $result = @{}
    foreach ($map in @($Maps)) {
        if ($null -eq $map) { continue }
        foreach ($key in $map.Keys) {
            if ($null -ne $key -and $null -ne $map[$key] -and -not [string]::IsNullOrWhiteSpace([string]$map[$key])) {
                $result[[string]$key] = $map[$key]
            }
        }
    }
    $result
}

function Get-KubeNetMapValue {
    param(
        [hashtable]$Map,
        [string[]]$Names
    )

    if ($null -eq $Map) { return '' }
    $lookup = @{}
    foreach ($key in $Map.Keys) {
        if ($null -ne $key) { $lookup[[string]$key.ToLowerInvariant()] = $key }
    }
    foreach ($name in $Names) {
        $lower = $name.ToLowerInvariant()
        if ($lookup.ContainsKey($lower)) {
            $value = $Map[$lookup[$lower]]
            if ($null -ne $value -and -not [string]::IsNullOrWhiteSpace([string]$value)) {
                return [string]$value
            }
        }
    }
    ''
}

function ConvertTo-KubeNetTagMap {
    param([object]$Tags)

    $map = @{}
    if ($null -eq $Tags) { return $map }

    if ($Tags -is [string]) {
        foreach ($tag in @($Tags -split '[,\s]+' | Where-Object { -not [string]::IsNullOrWhiteSpace($_) })) {
            if ($tag -match '^([^:=]+)[:=](.+)$') {
                $map[$Matches[1]] = $Matches[2]
            } else {
                $map[$tag] = $true
            }
        }
        return $map
    }

    if ($Tags -is [array]) {
        foreach ($tag in $Tags) {
            $child = ConvertTo-KubeNetTagMap -Tags $tag
            foreach ($key in $child.Keys) { $map[$key] = $child[$key] }
        }
        return $map
    }

    ConvertTo-KubeNetMap -InputObject $Tags
}

function Get-KubeNetAlertProvider {
    param([object]$Payload, [string]$Provider)

    if ($Provider -and $Provider -ne 'Auto') { return $Provider }

    $map = ConvertTo-KubeNetMap -InputObject $Payload
    if ($map.ContainsKey('alerts')) {
        if ($map.ContainsKey('orgId') -or $map.ContainsKey('ruleUrl') -or $map.ContainsKey('dashboardURL')) { return 'Grafana' }
        return 'Alertmanager'
    }
    if ($map.ContainsKey('alert_title') -or $map.ContainsKey('alert_type') -or $map.ContainsKey('event_msg')) { return 'Datadog' }
    if ($map.ContainsKey('incident') -or $map.ContainsKey('condition_name') -or $map.ContainsKey('issueUrl')) { return 'NewRelic' }
    'Generic'
}

function Get-KubeNetAlertText {
    param([object]$Alert)

    $parts = @(
        $Alert.AlertName,
        $Alert.Severity,
        $Alert.Summary,
        $Alert.Description,
        $Alert.Status
    )
    foreach ($mapName in @('Labels', 'Annotations', 'Tags')) {
        $map = $Alert.$mapName
        if ($map) {
            foreach ($key in $map.Keys) {
                $parts += [string]$key
                $parts += [string]$map[$key]
            }
        }
    }
    (@($parts | Where-Object { -not [string]::IsNullOrWhiteSpace([string]$_) }) -join ' ').ToLowerInvariant()
}

function Get-KubeNetAlertSymptom {
    param([string]$Text)

    if ($Text -match 'networkpolicy|network policy|egress.*(deny|drop|block)|ingress.*(deny|drop|block)|denied|blocked|dropped') { return 'network-policy' }
    if ($Text -match 'endpoint|endpointslice|no ready endpoint|no endpoints') { return 'endpoints' }
    if ($Text -match 'ingress|ingressclass|route|host rule|tls|backend.*port') { return 'ingress' }
    if ($Text -match 'loadbalancer|load balancer|elb|alb|nlb|external ip|external traffic') { return 'loadbalancer' }
    if ($Text -match 'nodeport|node port|kube-proxy|service routing') { return 'nodeport' }
    if ($Text -match 'egress|nat|proxy|firewall|external.*timeout|internet') { return 'egress' }
    if ($Text -match 'dns|coredns|nxdomain|lookup|resolver|nameserver|udp\s*53|tcp\s*53') { return 'dns' }
    if ($Text -match 'cross.namespace|namespace.*to.*namespace|service\.svc|svc\.cluster\.local') { return 'cross-namespace' }
    if ($Text -match 'connection refused|connection timeout|connect timeout|i/o timeout|no route to host|pod.to.service|pod.to.pod|clusterip|service unavailable') { return 'connectivity' }
    if ($Text -match '401|403|unauthorized|forbidden|login|permission denied') { return 'application-auth' }
    if ($Text -match 'cpu|memory|oom|disk|pvc|volume|imagepull|image pull|crashloop|crash loop|backoff') { return 'workload-health' }
    'unknown'
}

function New-KubeNetNormalizedAlert {
    param(
        [string]$Provider,
        [string]$Status,
        [hashtable]$Labels,
        [hashtable]$Annotations,
        [hashtable]$Tags,
        [object]$Raw,
        [string]$StartsAt = '',
        [string]$EndsAt = ''
    )

    $all = Merge-KubeNetMap -Maps @($Tags, $Labels, $Annotations)
    $alertName = Get-KubeNetMapValue -Map $all -Names @('alertname', 'alert_name', 'alert_title', 'monitor_name', 'condition_name', 'ruleName', 'title', 'name')
    $summary = Get-KubeNetMapValue -Map $all -Names @('summary', 'message', 'event_msg', 'description', 'details')
    $description = Get-KubeNetMapValue -Map $all -Names @('description', 'runbook', 'event_msg', 'body')
    if ([string]::IsNullOrWhiteSpace($alertName)) { $alertName = $summary }

    $namespace = Get-KubeNetMapValue -Map $all -Names @(
        'namespace', 'kubernetes_namespace', 'kube_namespace', 'k8s.namespace.name',
        'kubernetes.namespace_name', 'pod_namespace', 'target_namespace'
    )
    $service = Get-KubeNetMapValue -Map $all -Names @(
        'service', 'service_name', 'k8s.service.name', 'kubernetes_service',
        'kube_service', 'destination_service', 'target_service'
    )
    $deployment = Get-KubeNetMapValue -Map $all -Names @(
        'deployment', 'deployment_name', 'kube_deployment', 'k8s.deployment.name',
        'kubernetes_deployment', 'workload', 'workload_name'
    )
    $pod = Get-KubeNetMapValue -Map $all -Names @(
        'pod', 'pod_name', 'kubernetes_pod_name', 'k8s.pod.name', 'source_pod', 'podname'
    )
    $sourceNamespace = Get-KubeNetMapValue -Map $all -Names @(
        'source_namespace', 'src_namespace', 'client_namespace', 'from_namespace'
    )
    $sourcePod = Get-KubeNetMapValue -Map $all -Names @(
        'source_pod', 'src_pod', 'client_pod', 'from_pod'
    )
    $sourceSelector = Get-KubeNetMapValue -Map $all -Names @(
        'source_pod_selector', 'src_pod_selector', 'client_selector'
    )
    $podSelector = Get-KubeNetMapValue -Map $all -Names @(
        'pod_selector', 'selector', 'target_selector'
    )
    $cluster = Get-KubeNetMapValue -Map $all -Names @(
        'cluster', 'cluster_name', 'k8s.cluster.name', 'kubernetes_cluster', 'kube_cluster'
    )
    $severity = Get-KubeNetMapValue -Map $all -Names @('severity', 'priority', 'level', 'alert_priority')

    if ([string]::IsNullOrWhiteSpace($service) -and -not [string]::IsNullOrWhiteSpace($deployment)) {
        $service = $deployment
    }

    $urls = @()
    foreach ($urlField in @('url', 'link', 'dashboardURL', 'panelURL', 'generatorURL', 'runbook_url', 'external_url')) {
        $url = Get-KubeNetMapValue -Map $all -Names @($urlField)
        if ($url -match '^https?://') { $urls += $url }
    }
    foreach ($value in @($all.Values)) {
        if ($value -is [string] -and $value -match 'https?://[^\s]+' ) {
            $urls += $Matches[0].TrimEnd('.', ',', ')', ']')
        }
    }
    $urls = @($urls | Sort-Object -Unique)

    $alert = [PSCustomObject]@{
        Provider          = $Provider
        AlertName         = if ($alertName) { $alertName } else { '(unnamed alert)' }
        Status            = $Status
        Severity          = $severity
        Cluster           = $cluster
        Namespace         = $namespace
        ServiceName       = $service
        DeploymentName    = $deployment
        PodName           = $pod
        TargetPodSelector = $podSelector
        SourceNamespace   = $sourceNamespace
        SourcePodName     = $sourcePod
        SourcePodSelector = $sourceSelector
        Symptom           = ''
        Summary           = $summary
        Description       = $description
        Urls              = $urls
        StartsAt          = $StartsAt
        EndsAt            = $EndsAt
        Labels            = $Labels
        Annotations       = $Annotations
        Tags              = $Tags
        Raw               = $Raw
    }
    $alert.Symptom = Get-KubeNetAlertSymptom -Text (Get-KubeNetAlertText -Alert $alert)
    $alert
}

function ConvertFrom-KubeNetAlertPayload {
    param([object]$Payload, [string]$Provider = 'Auto')

    $detected = Get-KubeNetAlertProvider -Payload $Payload -Provider $Provider
    $payloadMap = ConvertTo-KubeNetMap -InputObject $Payload

    if ($payloadMap.ContainsKey('alerts') -and $Payload.alerts) {
        $commonLabels = ConvertTo-KubeNetMap -InputObject $Payload.commonLabels
        $commonAnnotations = ConvertTo-KubeNetMap -InputObject $Payload.commonAnnotations
        foreach ($item in @($Payload.alerts)) {
            $labels = Merge-KubeNetMap -Maps @($commonLabels, (ConvertTo-KubeNetMap -InputObject $item.labels))
            $annotations = Merge-KubeNetMap -Maps @($commonAnnotations, (ConvertTo-KubeNetMap -InputObject $item.annotations))
            $tags = ConvertTo-KubeNetTagMap -Tags $item.tags
            New-KubeNetNormalizedAlert -Provider $detected -Status ([string]$item.status) -Labels $labels -Annotations $annotations -Tags $tags -Raw $item -StartsAt ([string]$item.startsAt) -EndsAt ([string]$item.endsAt)
        }
        return
    }

    $labels = ConvertTo-KubeNetMap -InputObject $Payload.labels
    $annotations = ConvertTo-KubeNetMap -InputObject $Payload.annotations
    $tags = ConvertTo-KubeNetTagMap -Tags $Payload.tags
    $top = ConvertTo-KubeNetMap -InputObject $Payload
    $labels = Merge-KubeNetMap -Maps @($top, $labels)
    $status = Get-KubeNetMapValue -Map $top -Names @('status', 'alert_status', 'state', 'current_state')
    New-KubeNetNormalizedAlert -Provider $detected -Status $status -Labels $labels -Annotations $annotations -Tags $tags -Raw $Payload -StartsAt ([string]$Payload.startsAt) -EndsAt ([string]$Payload.endsAt)
}

function Test-KubeNetAlertScope {
    param([object]$Alert)

    $networkCategories = @('dns', 'network-policy', 'endpoints', 'ingress', 'loadbalancer', 'nodeport', 'egress', 'cross-namespace', 'connectivity')
    $limitedCategories = @('application-auth', 'workload-health')
    $missing = @()
    if ([string]::IsNullOrWhiteSpace($Alert.Namespace) -and [string]::IsNullOrWhiteSpace($Alert.SourceNamespace)) { $missing += 'Namespace' }
    if ($Alert.Symptom -ne 'egress' -and [string]::IsNullOrWhiteSpace($Alert.ServiceName)) { $missing += 'ServiceName' }

    $hasKubeContext = -not [string]::IsNullOrWhiteSpace($Alert.Namespace) -or
        -not [string]::IsNullOrWhiteSpace($Alert.PodName) -or
        -not [string]::IsNullOrWhiteSpace($Alert.DeploymentName) -or
        -not [string]::IsNullOrWhiteSpace($Alert.ServiceName)

    $inScope = $networkCategories -contains $Alert.Symptom
    $canRun = $inScope -and $missing.Count -eq 0
    $confidence = 'low'
    if ($inScope -and $canRun) { $confidence = 'high' }
    elseif ($inScope -and $hasKubeContext) { $confidence = 'medium' }
    elseif ($limitedCategories -contains $Alert.Symptom) { $confidence = 'high' }

    $reason = if ($canRun -and $Alert.Symptom -eq 'egress') {
        "Alert looks network-relevant and includes source namespace metadata for egress testing."
    } elseif ($canRun) {
        "Alert looks network-relevant and includes target namespace/service metadata."
    } elseif ($inScope -and $Alert.Symptom -eq 'egress') {
        "Alert looks network-relevant, but KubeNet needs a source namespace before it can run egress testing."
    } elseif ($inScope) {
        "Alert looks network-relevant, but KubeNet needs a target namespace and Service name before it can run."
    } elseif ($Alert.Symptom -eq 'application-auth') {
        "Alert appears to be application authorization/authentication related. KubeNet can test reachability, but not app auth behavior."
    } elseif ($Alert.Symptom -eq 'workload-health') {
        "Alert appears to be workload health/resource/image/crash related. KubeNet is focused on network paths."
    } else {
        "Alert does not contain enough Kubernetes networking signals to map confidently."
    }

    $checks = @()

    [PSCustomObject]@{
        InScope           = [bool]$inScope
        CanRun            = [bool]$canRun
        Confidence        = $confidence
        Category          = $Alert.Symptom
        Reason            = $reason
        MissingFields     = @($missing)
        RecommendedChecks = @($checks | Sort-Object -Unique)
    }
}

function ConvertTo-KubeNetParameterPlan {
    param([object]$Alert)

    $scope = Test-KubeNetAlertScope -Alert $Alert
    $commandName = switch ($Alert.Symptom) {
        'egress' { 'Test-KubeNetEgress' }
        { $_ -in @('ingress', 'loadbalancer') } { 'Test-KubeNetIngress' }
        default { 'Test-KubeNetService' }
    }
    $params = [ordered]@{}

    if ($commandName -eq 'Test-KubeNetEgress') {
        if (-not [string]::IsNullOrWhiteSpace($Alert.SourceNamespace)) { $params.SourceNamespace = $Alert.SourceNamespace }
        elseif (-not [string]::IsNullOrWhiteSpace($Alert.Namespace)) { $params.SourceNamespace = $Alert.Namespace }
        if (-not [string]::IsNullOrWhiteSpace($Alert.SourcePodName)) { $params.SourcePodName = $Alert.SourcePodName }
        if (-not [string]::IsNullOrWhiteSpace($Alert.SourcePodSelector)) { $params.SourcePodSelector = $Alert.SourcePodSelector }
    } else {
        if (-not [string]::IsNullOrWhiteSpace($Alert.Namespace)) { $params.TargetNamespace = $Alert.Namespace }
        if (-not [string]::IsNullOrWhiteSpace($Alert.ServiceName)) { $params.TargetService = $Alert.ServiceName }
        if (-not [string]::IsNullOrWhiteSpace($Alert.DeploymentName)) { $params.DeploymentName = $Alert.DeploymentName }
        if (-not [string]::IsNullOrWhiteSpace($Alert.TargetPodSelector)) { $params.TargetPodSelector = $Alert.TargetPodSelector }
        if ($commandName -eq 'Test-KubeNetService') {
            if (-not [string]::IsNullOrWhiteSpace($Alert.SourceNamespace)) { $params.SourceNamespace = $Alert.SourceNamespace }
            if (-not [string]::IsNullOrWhiteSpace($Alert.SourcePodName)) { $params.SourcePodName = $Alert.SourcePodName }
            if (-not [string]::IsNullOrWhiteSpace($Alert.SourcePodSelector)) { $params.SourcePodSelector = $Alert.SourcePodSelector }
        }
    }

    $reachabilityUrls = Get-KubeNetReachabilityUrls -Urls $Alert.Urls
    if ($Alert.Symptom -eq 'ingress' -and $reachabilityUrls.Count -gt 0) {
        $params.IngressUrls = @($reachabilityUrls)
    } elseif ($Alert.Symptom -eq 'egress' -and $reachabilityUrls.Count -gt 0) {
        $params.Urls = @($reachabilityUrls)
    } elseif ($Alert.Symptom -eq 'loadbalancer' -and $reachabilityUrls.Count -gt 0) {
        $params.TestLoadBalancer = $true
        $params.ExternalUrls = @($reachabilityUrls)
    }

    $previewParts = @($commandName)
    foreach ($key in $params.Keys) {
        $value = $params[$key]
        if ($value -is [bool]) {
            if ($value) { $previewParts += "-$key" }
        } elseif ($value -is [array]) {
            $previewParts += "-$key"
            $previewParts += (@($value) -join ',')
        } else {
            $previewParts += "-$key"
            $previewParts += "'$value'"
        }
    }

    [PSCustomObject]@{
        Provider       = $Alert.Provider
        AlertName      = $Alert.AlertName
        Severity       = $Alert.Severity
        Status         = $Alert.Status
        InScope        = $scope.InScope
        CanRun         = $scope.CanRun
        Confidence     = $scope.Confidence
        Category       = $scope.Category
        Reason         = $scope.Reason
        MissingFields  = $scope.MissingFields
        Parameters     = $params
        Command        = $commandName
        CommandPreview = ($previewParts -join ' ')
        Alert          = $Alert
    }
}

function Get-KubeNetReachabilityUrls {
    param([object[]]$Urls)

    $excluded = 'grafana|dashboard|runbook|pagerduty|opsgenie|datadog|newrelic|splunk|elastic|kibana|prometheus'
    @($Urls | Where-Object {
        $_ -is [string] -and
        $_ -match '^https?://' -and
        $_ -notmatch $excluded
    } | Sort-Object -Unique)
}

function Resolve-KubeNetIndexedPath {
    param([string]$Path, [int]$Index, [int]$Total)

    if ([string]::IsNullOrWhiteSpace($Path)) { return '' }
    if ($Total -le 1) { return $Path }
    $directory = Split-Path -Path $Path -Parent
    $leaf = Split-Path -Path $Path -Leaf
    $extension = [System.IO.Path]::GetExtension($leaf)
    $name = [System.IO.Path]::GetFileNameWithoutExtension($leaf)
    $newLeaf = '{0}-{1}{2}' -f $name, ($Index + 1), $extension
    if ([string]::IsNullOrWhiteSpace($directory)) { return $newLeaf }
    Join-Path $directory $newLeaf
}
