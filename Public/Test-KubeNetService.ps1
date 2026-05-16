function Test-KubeNetService {
    [CmdletBinding()]
    param(
        [string]$Namespace = 'default',
        [string]$ServiceName = 'nginx',
        [string]$DeploymentName = '',
        [int]$ServicePort = 0,
        [string]$UrlScheme = 'http',
        [string]$UrlPath = '/',
        [string]$TargetPodSelector = '',
        [string]$SourceNamespace = '',
        [string]$SourcePodName = '',
        [string]$SourcePodSelector = '',
        [string]$SourceContainer = '',
        [string]$TargetContext = '',
        [string]$SourceContext = '',
        [string]$KubeCommand = 'kubectl',
        [string]$DebugImage = 'nicolaka/netshoot:latest',
        [ValidateSet('Always', 'IfNotPresent', 'Never')]
        [string]$DebugImagePullPolicy = 'IfNotPresent',
        [string]$TargetDebugPodName = 'kubenetmods-debug',
        [string]$SourceDebugPodName = 'kubenetmods-source-debug',
        [int]$TimeoutSec = 5,
        [switch]$SkipDebugPod,
        [switch]$SkipNodePort,
        [switch]$TestPortForward,
        [switch]$TestTargetPodDns,
        [string]$TargetDnsPodName = '',
        [string]$TargetDnsContainer = '',
        [switch]$TestEgress,
        [string[]]$EgressUrls = @(),
        [switch]$TestIngress,
        [string[]]$IngressUrls = @(),
        [switch]$TestLoadBalancer,
        [string[]]$ExternalUrls = @(),
        [switch]$Deep,
        [string]$ExportJson = '',
        [string]$ExportHtml = '',
        [switch]$PassThru,
        [switch]$Quiet
    )

    $state = New-KubeNetState -KubeCommand $KubeCommand -TargetContext $TargetContext -SourceContext $SourceContext -Quiet:$Quiet
    $sourceNamespaceEffective = if ([string]::IsNullOrWhiteSpace($SourceNamespace)) { $Namespace } else { $SourceNamespace }
    $sourceContextEffective = if ([string]::IsNullOrWhiteSpace($SourceContext)) { $TargetContext } else { $SourceContext }
    $targetContextEffective = $TargetContext
    $sourceIsTarget = ($sourceNamespaceEffective -eq $Namespace -and $sourceContextEffective -eq $targetContextEffective)
    if ($Deep) {
        $TestTargetPodDns = $true
        $TestEgress = $true
        $TestIngress = $true
        $TestLoadBalancer = $true
    }

    $service = $null
    $podData = $null
    $selectedPods = @()
    $selectedServicePort = $null
    $containerPorts = @()
    $targetPortMetadataStatus = ''
    $targetPortAnalysis = $null
    $servicePortMissing = $false
    $targetHasReadyEndpoints = $false
    $targetDebugReady = $false
    $sourceDebugReady = $false
    $kubeSystemNamespace = $null
    $coreDnsPods = @()
    $nodeLocalDnsPods = @()
    $coreDnsServiceIp = ''
    $targetNamespaceObject = $null
    $sourceNamespaceObject = $null
    $targetNetworkPolicies = @()
    $sourceNetworkPolicies = @()
    $cniProviderGuess = ''
    $networkPolicyObjectCount = 0

    try {
        $state.KubeCommand = Resolve-KubeNetCommand -KubeCommand $KubeCommand

        if (-not $Quiet) {
            Write-Host 'KubeNetMods network checker' -ForegroundColor White
            Write-Host "Command:          $($state.KubeCommand)" -ForegroundColor DarkGray
            Write-Host "Target context:   $(if ($targetContextEffective) { $targetContextEffective } else { '(current)' })" -ForegroundColor DarkGray
            Write-Host "Target namespace: $Namespace" -ForegroundColor DarkGray
            Write-Host "Target service:   $ServiceName" -ForegroundColor DarkGray
            Write-Host "Source context:   $(if ($sourceContextEffective) { $sourceContextEffective } else { '(current)' })" -ForegroundColor DarkGray
            Write-Host "Source namespace: $sourceNamespaceEffective" -ForegroundColor DarkGray
        }

        Write-KubeNetSection -State $state -Name 'Cluster Access' -Description 'Validates kubectl access to target/source contexts and namespaces.'
        Add-KubeNetResult -State $state -Layer 'Cluster Access' -Check 'kubectl' -Status 'PASS' -Message "$KubeCommand is available."
        try {
            $targetNamespaceObject = ConvertFrom-KubeNetJson -State $state -Context $targetContextEffective -Arguments @('get', 'namespace', $Namespace)
            Add-KubeNetResult -State $state -Layer 'Cluster Access' -Check 'target namespace' -Status 'PASS' -Message "Target namespace '$Namespace' exists."
        } catch {
            Add-KubeNetResult -State $state -Layer 'Cluster Access' -Check 'target namespace' -Status 'FAIL' -Message "Target namespace '$Namespace' is not accessible: $($_.Exception.Message)"
            Add-KubeNetDiagnosis -State $state -Message "Cannot access target namespace '$Namespace'. Fix kubeconfig/RBAC/namespace before debugging networking."
        }
        if (-not $sourceIsTarget) {
            try {
                $sourceNamespaceObject = ConvertFrom-KubeNetJson -State $state -Context $sourceContextEffective -Arguments @('get', 'namespace', $sourceNamespaceEffective)
                Add-KubeNetResult -State $state -Layer 'Cluster Access' -Check 'source namespace' -Status 'PASS' -Message "Source namespace '$sourceNamespaceEffective' exists."
            } catch {
                Add-KubeNetResult -State $state -Layer 'Cluster Access' -Check 'source namespace' -Status 'FAIL' -Message "Source namespace '$sourceNamespaceEffective' is not accessible: $($_.Exception.Message)"
                Add-KubeNetDiagnosis -State $state -Message "Cannot access source namespace '$sourceNamespaceEffective'. Source-to-target checks cannot be trusted until access is fixed."
            }
        } else {
            $sourceNamespaceObject = $targetNamespaceObject
        }

        Write-KubeNetSection -State $state -Name 'Cluster Health' -Description 'Checks node readiness, common node network conditions, and core networking add-ons.'
        try {
            $nodes = ConvertFrom-KubeNetJson -State $state -Context $targetContextEffective -Arguments @('get', 'nodes')
            $nodeItems = @($nodes.items)
            $readyCount = 0
            $problemConditions = @()
            foreach ($node in $nodeItems) {
                $ready = @($node.status.conditions | Where-Object { $_.type -eq 'Ready' } | Select-Object -First 1)
                if ($ready.Count -gt 0 -and $ready[0].status -eq 'True') { $readyCount++ }
                foreach ($condition in @($node.status.conditions | Where-Object { $_.type -in @('NetworkUnavailable', 'MemoryPressure', 'DiskPressure', 'PIDPressure') -and $_.status -eq 'True' })) {
                    $problemConditions += "$($node.metadata.name):$($condition.type)=$($condition.reason)"
                }
            }
            if ($nodeItems.Count -eq 0) {
                Add-KubeNetResult -State $state -Layer 'Cluster Health' -Check 'nodes' -Status 'WARN' -Message 'No nodes were returned. RBAC may block node reads.'
            } elseif ($readyCount -eq $nodeItems.Count) {
                Add-KubeNetResult -State $state -Layer 'Cluster Health' -Check 'node readiness' -Status 'PASS' -Message "$readyCount/$($nodeItems.Count) node(s) are Ready."
            } else {
                Add-KubeNetResult -State $state -Layer 'Cluster Health' -Check 'node readiness' -Status 'FAIL' -Message "$readyCount/$($nodeItems.Count) node(s) are Ready."
                Add-KubeNetDiagnosis -State $state -Message 'Some nodes are not Ready. Fix node health before chasing service-level networking.'
            }
            if ($problemConditions.Count -gt 0) {
                Add-KubeNetResult -State $state -Layer 'Cluster Health' -Check 'node conditions' -Status 'WARN' -Message "Node pressure/network conditions detected: $($problemConditions -join '; ')"
            } else {
                Add-KubeNetResult -State $state -Layer 'Cluster Health' -Check 'node conditions' -Status 'PASS' -Message 'No NetworkUnavailable/pressure node conditions detected.'
            }
        } catch {
            Add-KubeNetResult -State $state -Layer 'Cluster Health' -Check 'nodes' -Status 'WARN' -Message "Could not inspect nodes: $($_.Exception.Message)"
        }

        try {
            $systemPods = ConvertFrom-KubeNetJson -State $state -Context $targetContextEffective -Arguments @('get', 'pods', '-n', 'kube-system')
            $kubeSystemNamespace = ConvertFrom-KubeNetJson -State $state -Context $targetContextEffective -Arguments @('get', 'namespace', 'kube-system')
            $coreDnsSvc = Invoke-KubeNetKubectl -State $state -Context $targetContextEffective -Arguments @('get', 'service', 'kube-dns', '-n', 'kube-system', '-o', 'json') -AllowFailure
            if ($coreDnsSvc.ExitCode -eq 0 -and -not [string]::IsNullOrWhiteSpace($coreDnsSvc.Text)) {
                $coreDnsServiceIp = [string](($coreDnsSvc.Text | ConvertFrom-Json).spec.clusterIP)
                Add-KubeNetResult -State $state -Layer 'Cluster Health' -Check 'CoreDNS service' -Status 'INFO' -Message "kube-dns service ClusterIP is $coreDnsServiceIp."
            }
            $coreDnsConfig = Invoke-KubeNetKubectl -State $state -Context $targetContextEffective -Arguments @('get', 'configmap', 'coredns', '-n', 'kube-system', '-o', 'json') -AllowFailure
            if ($coreDnsConfig.ExitCode -eq 0 -and -not [string]::IsNullOrWhiteSpace($coreDnsConfig.Text)) {
                $corefile = [string](($coreDnsConfig.Text | ConvertFrom-Json).data.Corefile)
                if ($corefile -match '\bkubernetes\s+') {
                    Add-KubeNetResult -State $state -Layer 'Cluster Health' -Check 'CoreDNS Corefile' -Status 'PASS' -Message 'CoreDNS Corefile includes the kubernetes plugin.'
                } else {
                    Add-KubeNetResult -State $state -Layer 'Cluster Health' -Check 'CoreDNS Corefile' -Status 'WARN' -Message 'CoreDNS Corefile was readable but the kubernetes plugin was not obvious.'
                    Add-KubeNetDiagnosis -State $state -Message 'CoreDNS config does not obviously include the kubernetes plugin. Cluster service DNS may not work normally.'
                }
            } else {
                Add-KubeNetResult -State $state -Layer 'Cluster Health' -Check 'CoreDNS Corefile' -Status 'INFO' -Message 'Could not read coredns ConfigMap in kube-system. This may be RBAC or a managed DNS implementation.'
            }

            $cniPods = @($systemPods.items | Where-Object { $_.metadata.name -match 'calico|cilium|flannel|weave|antrea|canal|kube-router|ovn|aws-node|azure-cni|gke|kindnet' })
            $cniNames = (@($cniPods | ForEach-Object { $_.metadata.name }) -join ' ').ToLowerInvariant()
            $cniProviderGuess = if ($cniNames -match 'calico') { 'Calico' }
                elseif ($cniNames -match 'cilium') { 'Cilium' }
                elseif ($cniNames -match 'antrea') { 'Antrea' }
                elseif ($cniNames -match 'weave') { 'Weave Net' }
                elseif ($cniNames -match 'ovn') { 'OVN/OVN-Kubernetes' }
                elseif ($cniNames -match 'kindnet') { 'kindnet' }
                elseif ($cniNames -match 'flannel') { 'Flannel' }
                elseif ($cniNames -match 'aws-node') { 'AWS VPC CNI' }
                elseif ($cniNames -match 'azure') { 'Azure CNI' }
                elseif ($cniNames -match 'gke') { 'GKE dataplane' }
                else { '' }
            $coreDnsPods = @($systemPods.items | Where-Object { $_.metadata.name -match 'coredns|kube-dns' })
            $nodeLocalDnsPods = @($systemPods.items | Where-Object { $_.metadata.name -match 'node-local-dns|nodelocaldns' -or $_.metadata.labels.'k8s-app' -match 'node-local-dns|nodelocaldns' })
            $dnsPods = @($coreDnsPods + $nodeLocalDnsPods)
            $proxyPods = @($systemPods.items | Where-Object { $_.metadata.name -match 'kube-proxy' })
            foreach ($tuple in @(
                [PSCustomObject]@{ Name = 'CNI add-ons'; Items = $cniPods; Hint = 'CNI/overlay dataplane' },
                [PSCustomObject]@{ Name = 'CoreDNS'; Items = $dnsPods; Hint = 'cluster DNS' },
                [PSCustomObject]@{ Name = 'kube-proxy'; Items = $proxyPods; Hint = 'service routing' }
            )) {
                if ($tuple.Items.Count -eq 0) {
                    Add-KubeNetResult -State $state -Layer 'Cluster Health' -Check $tuple.Name -Status 'WARN' -Message "No obvious $($tuple.Name) pod found in kube-system. This may be normal for some managed/CNI-specific clusters."
                } else {
                    $ready = @($tuple.Items | Where-Object { Get-KubeNetPodReady -Pod $_ })
                    if ($ready.Count -eq $tuple.Items.Count) {
                        Add-KubeNetResult -State $state -Layer 'Cluster Health' -Check $tuple.Name -Status 'PASS' -Message "$($ready.Count)/$($tuple.Items.Count) $($tuple.Name) pod(s) are Ready."
                        if ($tuple.Name -eq 'CNI add-ons' -and -not [string]::IsNullOrWhiteSpace($cniProviderGuess)) {
                            Add-KubeNetResult -State $state -Layer 'Cluster Health' -Check 'CNI provider' -Status 'INFO' -Message "CNI/provider guess: $cniProviderGuess."
                        }
                    } else {
                        Add-KubeNetResult -State $state -Layer 'Cluster Health' -Check $tuple.Name -Status 'WARN' -Message "$($ready.Count)/$($tuple.Items.Count) $($tuple.Name) pod(s) are Ready. Check $($tuple.Hint)."
                        Add-KubeNetDiagnosis -State $state -Message "$($tuple.Name) pods are not all Ready. This can affect $($tuple.Hint)."
                    }
                }
            }
        } catch {
            Add-KubeNetResult -State $state -Layer 'Cluster Health' -Check 'kube-system add-ons' -Status 'WARN' -Message "Could not inspect kube-system add-ons: $($_.Exception.Message)"
        }

        Write-KubeNetSection -State $state -Name 'Deployment Layer' -Description 'Checks whether the expected target deployment is available.'
        $effectiveDeploymentName = if ([string]::IsNullOrWhiteSpace($DeploymentName)) { $ServiceName } else { $DeploymentName }
        $deploymentResult = Invoke-KubeNetKubectl -State $state -Context $targetContextEffective -Arguments @('get', 'deployment', $effectiveDeploymentName, '-n', $Namespace, '-o', 'json') -AllowFailure
        if ($deploymentResult.ExitCode -eq 0 -and -not [string]::IsNullOrWhiteSpace($deploymentResult.Text)) {
            $deployment = $deploymentResult.Text | ConvertFrom-Json
            $desired = if ($null -ne $deployment.spec.replicas) { [int]$deployment.spec.replicas } else { 0 }
            $available = if ($null -ne $deployment.status.availableReplicas) { [int]$deployment.status.availableReplicas } else { 0 }
            $ready = if ($null -ne $deployment.status.readyReplicas) { [int]$deployment.status.readyReplicas } else { 0 }
            if ($desired -eq $available -and $desired -eq $ready) {
                Add-KubeNetResult -State $state -Layer 'Deployment Layer' -Check 'replicas' -Status 'PASS' -Message "Deployment '$effectiveDeploymentName' has $available/$desired available replica(s)."
            } else {
                Add-KubeNetResult -State $state -Layer 'Deployment Layer' -Check 'replicas' -Status 'FAIL' -Message "Deployment '$effectiveDeploymentName' has $available/$desired available replica(s) and $ready/$desired ready replica(s)."
                Add-KubeNetDiagnosis -State $state -Message 'Deployment replicas are not available. Fix scheduling, image pulls, crashes, or probes before chasing service networking.'
            }
        } else {
            Add-KubeNetResult -State $state -Layer 'Deployment Layer' -Check 'deployment exists' -Status 'WARN' -Message "Deployment '$effectiveDeploymentName' was not found or is not readable. Continuing with service/pod checks."
        }

        Write-KubeNetSection -State $state -Name 'Service Layer' -Description 'Checks service type, selector, ports, targetPort, and load-balancer metadata.'
        try {
            $service = ConvertFrom-KubeNetJson -State $state -Context $targetContextEffective -Arguments @('get', 'service', $ServiceName, '-n', $Namespace)
            $portsText = (@($service.spec.ports) | ForEach-Object {
                $np = if ($_.nodePort) { " nodePort=$($_.nodePort)" } else { '' }
                "$($_.port)->$($_.targetPort)/$($_.protocol)$np"
            }) -join ', '
            $selectorText = Join-KubeNetSelector -Selector $service.spec.selector
            if ([string]::IsNullOrWhiteSpace($selectorText)) { $selectorText = '(none)' }
            Add-KubeNetResult -State $state -Layer 'Service Layer' -Check 'service exists' -Status 'PASS' -Message "Service '$ServiceName' exists. Type=$($service.spec.type); ClusterIP=$($service.spec.clusterIP); Ports=$portsText; Selector=$selectorText"
            $selectedServicePort = Get-KubeNetServicePortObject -Service $service -ServicePort $ServicePort
            if ($ServicePort -gt 0) {
                $matches = @($service.spec.ports | Where-Object { [int]$_.port -eq $ServicePort })
                if ($matches.Count -gt 0) {
                    Add-KubeNetResult -State $state -Layer 'Service Layer' -Check 'service port' -Status 'PASS' -Message "Service port $ServicePort exists on the service."
                } else {
                    $servicePortMissing = $true
                    Add-KubeNetResult -State $state -Layer 'Service Layer' -Check 'service port' -Status 'FAIL' -Message "Service port $ServicePort was not found on the service."
                    Add-KubeNetDiagnosis -State $state -Message "Primary issue: service '$ServiceName' does not expose service port $ServicePort."
                }
            }
            if ($service.spec.type -eq 'LoadBalancer') {
                $provider = Get-KubeNetLoadBalancerProvider -Service $service
                $ingress = @($service.status.loadBalancer.ingress)
                if ($ingress.Count -eq 0) {
                    Add-KubeNetResult -State $state -Layer 'Cloud LoadBalancer' -Check 'address' -Status 'WARN' -Message "LoadBalancer service has no external ingress address yet. Provider=$provider."
                    Add-KubeNetDiagnosis -State $state -Message "LoadBalancer service has no external address. Check cloud controller manager, service annotations, subnet/security-group settings, and provider quota."
                } else {
                    $addresses = @($ingress | ForEach-Object { if ($_.ip) { $_.ip } elseif ($_.hostname) { $_.hostname } }) -join ', '
                    Add-KubeNetResult -State $state -Layer 'Cloud LoadBalancer' -Check 'address' -Status 'PASS' -Message "LoadBalancer external address(es): $addresses. Provider guess: $provider."
                }
                if ($service.spec.externalTrafficPolicy) {
                    Add-KubeNetResult -State $state -Layer 'Cloud LoadBalancer' -Check 'externalTrafficPolicy' -Status 'INFO' -Message "externalTrafficPolicy=$($service.spec.externalTrafficPolicy); healthCheckNodePort=$($service.spec.healthCheckNodePort)"
                }
            }
        } catch {
            Add-KubeNetResult -State $state -Layer 'Service Layer' -Check 'service exists' -Status 'FAIL' -Message "Service '$ServiceName' does not exist or is not readable in namespace '$Namespace': $($_.Exception.Message)"
            Add-KubeNetDiagnosis -State $state -Message "The target service is missing or unreadable. Create/fix the Service before debugging DNS, endpoints, ingress, or load balancing."
        }

        Write-KubeNetSection -State $state -Name 'Pod Health Layer' -Description 'Finds selected pods and checks phase, readiness, declared ports, and container states.'
        try {
            $podData = Get-KubeNetSelectedPods -State $state -Context $targetContextEffective -Namespace $Namespace -Service $service -DeploymentName $effectiveDeploymentName -ServiceName $ServiceName -TargetPodSelector $TargetPodSelector
            if ([string]::IsNullOrWhiteSpace($podData.Selector)) {
                Add-KubeNetResult -State $state -Layer 'Pod Health Layer' -Check 'pod selector' -Status 'WARN' -Message 'No pod selector could be inferred. Service selector may be missing, or Deployment was not found.'
            } else {
                Add-KubeNetResult -State $state -Layer 'Pod Health Layer' -Check 'pod selector' -Status 'INFO' -Message "Using pod selector: $($podData.Selector)"
                $selectedPods = @($podData.Pods.items)
                if ($selectedPods.Count -eq 0) {
                    Add-KubeNetResult -State $state -Layer 'Pod Health Layer' -Check 'pods exist' -Status 'FAIL' -Message 'No pods found for the selected labels.'
                    Add-KubeNetDiagnosis -State $state -Message 'No pods matched the selector. The service selector/deployment labels may be wrong, or the workload has not created pods.'
                } else {
                    $running = @($selectedPods | Where-Object { $_.status.phase -eq 'Running' })
                    $ready = @($selectedPods | Where-Object { Get-KubeNetPodReady -Pod $_ })
                    Add-KubeNetResult -State $state -Layer 'Pod Health Layer' -Check 'pods exist' -Status 'PASS' -Message "$($selectedPods.Count) pod(s) found."
                    Add-KubeNetResult -State $state -Layer 'Pod Health Layer' -Check 'running' -Status $(if ($running.Count -eq $selectedPods.Count) { 'PASS' } else { 'FAIL' }) -Message "$($running.Count)/$($selectedPods.Count) pod(s) are Running."
                    Add-KubeNetResult -State $state -Layer 'Pod Health Layer' -Check 'ready' -Status $(if ($ready.Count -eq $selectedPods.Count) { 'PASS' } else { 'FAIL' }) -Message "$($ready.Count)/$($selectedPods.Count) pod(s) are Ready."
                    $problems = Get-KubeNetPodProblemStates -Pods $selectedPods
                    if ($problems.Count -gt 0) {
                        Add-KubeNetResult -State $state -Layer 'Pod Health Layer' -Check 'container states' -Status 'FAIL' -Message "Problem states detected: $($problems -join '; ')"
                        if (($problems -join ';') -match 'ImagePull|ErrImagePull') { Add-KubeNetDiagnosis -State $state -Message 'Primary issue: image pull failure detected. Fix image name, registry auth, or image policy before networking.' }
                        elseif (($problems -join ';') -match 'CrashLoopBackOff') { Add-KubeNetDiagnosis -State $state -Message 'Primary issue: container is crashing. Check logs, config, secrets, probes, and startup command before networking.' }
                    } else {
                        Add-KubeNetResult -State $state -Layer 'Pod Health Layer' -Check 'container states' -Status 'PASS' -Message 'No obvious waiting/terminated container states detected.'
                    }
                    $containerPorts = Get-KubeNetContainerPorts -Pods $selectedPods
                    $targetPortAnalysis = Test-KubeNetTargetPortMetadata -ServicePortObject $selectedServicePort -ContainerPorts $containerPorts
                    $targetPortMetadataStatus = $targetPortAnalysis.Status
                    $targetStatus = if ($targetPortAnalysis.Status -eq 'Mismatch' -and $targetPortAnalysis.TargetPortKind -eq 'Named') { 'FAIL' } elseif ($targetPortAnalysis.Status -eq 'Mismatch') { 'WARN' } elseif ($targetPortAnalysis.Status -eq 'NoDeclaredPorts') { 'WARN' } else { 'PASS' }
                    Add-KubeNetResult -State $state -Layer 'Service Layer' -Check 'targetPort metadata' -Status $targetStatus -Message $targetPortAnalysis.Message
                    if ($targetPortAnalysis.Status -eq 'Mismatch' -and $targetPortAnalysis.TargetPortKind -eq 'Named') {
                        Add-KubeNetDiagnosis -State $state -Message "Primary issue: service '$ServiceName' uses named targetPort '$($selectedServicePort.targetPort)', but selected pods do not declare a matching named container port."
                    }
                }
            }
        } catch {
            Add-KubeNetResult -State $state -Layer 'Pod Health Layer' -Check 'pod inspection' -Status 'WARN' -Message "Could not inspect selected pods: $($_.Exception.Message)"
        }

        Write-KubeNetSection -State $state -Name 'EndpointSlice Layer' -Description 'Checks whether the service maps to ready endpoint addresses.'
        if ($service) {
            try {
                $slices = ConvertFrom-KubeNetJson -State $state -Context $targetContextEffective -Arguments @('get', 'endpointslice', '-n', $Namespace, '-l', "kubernetes.io/service-name=$ServiceName")
                $readyAddresses = @()
                $slicePorts = @()
                foreach ($slice in @($slices.items)) {
                    foreach ($slicePort in @($slice.ports)) {
                        $slicePorts += [PSCustomObject]@{
                            Name     = [string]$slicePort.name
                            Port     = if ($slicePort.port) { [int]$slicePort.port } else { 0 }
                            Protocol = if ($slicePort.protocol) { [string]$slicePort.protocol } else { 'TCP' }
                        }
                    }
                    foreach ($endpoint in @($slice.endpoints)) {
                        $readyCondition = if ($null -ne $endpoint.conditions.ready) { [bool]$endpoint.conditions.ready } else { $true }
                        if ($readyCondition) { $readyAddresses += @($endpoint.addresses) }
                    }
                }
                $readyAddresses = @($readyAddresses | Sort-Object -Unique)
                $slicePorts = @($slicePorts | Sort-Object Name, Port, Protocol -Unique)
                if ($readyAddresses.Count -gt 0) {
                    $targetHasReadyEndpoints = $true
                    Add-KubeNetResult -State $state -Layer 'EndpointSlice Layer' -Check 'ready addresses' -Status 'PASS' -Message "Ready endpoint IPs: $($readyAddresses -join ', ')"
                    if ($slicePorts.Count -gt 0) {
                        $slicePortText = (@($slicePorts | ForEach-Object { "$(if ($_.Name) { $_.Name } else { '(unnamed)' })=$($_.Port)/$($_.Protocol)" }) -join ', ')
                        Add-KubeNetResult -State $state -Layer 'EndpointSlice Layer' -Check 'endpoint ports' -Status 'INFO' -Message "EndpointSlice port(s): $slicePortText"
                        if ($selectedServicePort) {
                            $candidatePorts = Get-KubeNetConnectionPortCandidates -ServicePortObject $selectedServicePort -ContainerPorts $containerPorts
                            $endpointPortMatches = @($slicePorts | Where-Object { $candidatePorts -contains $_.Port })
                            if ($candidatePorts.Count -gt 0 -and $endpointPortMatches.Count -eq 0) {
                                $endpointPortStatus = if (@($slicePorts | Where-Object { $_.Port -eq 0 }).Count -gt 0 -or ($targetPortMetadataStatus -eq 'Mismatch' -and $targetPortAnalysis.TargetPortKind -eq 'Named')) { 'FAIL' } else { 'WARN' }
                                Add-KubeNetResult -State $state -Layer 'EndpointSlice Layer' -Check 'endpoint port match' -Status $endpointPortStatus -Message "EndpointSlice ports do not match expected service/target port candidate(s): $($candidatePorts -join ', ')."
                                Add-KubeNetDiagnosis -State $state -Message "EndpointSlice addresses exist, but endpoint ports do not match expected service/target ports. Check service targetPort and pod port naming."
                            } elseif ($candidatePorts.Count -gt 0) {
                                $matchedPorts = (@($endpointPortMatches | ForEach-Object { $_.Port }) | Sort-Object -Unique) -join ', '
                                Add-KubeNetResult -State $state -Layer 'EndpointSlice Layer' -Check 'endpoint port match' -Status 'PASS' -Message "EndpointSlice port(s) $matchedPorts match one of the expected service/target candidate port(s): $($candidatePorts -join ', ')."
                            }
                        }
                    }
                } else {
                    Add-KubeNetResult -State $state -Layer 'EndpointSlice Layer' -Check 'ready addresses' -Status 'FAIL' -Message "No ready EndpointSlice addresses found for service '$ServiceName'."
                    if ($selectedPods.Count -eq 0) {
                        Add-KubeNetDiagnosis -State $state -Message 'The service has no ready endpoints because no pods matched its selector. Fix the Service selector or workload labels.'
                    } elseif (@($selectedPods | Where-Object { Get-KubeNetPodReady -Pod $_ }).Count -eq 0) {
                        Add-KubeNetDiagnosis -State $state -Message 'The service has no ready endpoints because selected pods are not Ready. Fix workload health first.'
                    } else {
                        Add-KubeNetDiagnosis -State $state -Message 'Pods may be healthy but service has no ready endpoints. Check service selector, readiness gates, and EndpointSlice controller.'
                    }
                }
            } catch {
                Add-KubeNetResult -State $state -Layer 'EndpointSlice Layer' -Check 'endpoint slices' -Status 'WARN' -Message "Could not inspect EndpointSlices: $($_.Exception.Message)"
            }
        } else {
            Add-KubeNetResult -State $state -Layer 'EndpointSlice Layer' -Check 'endpoint slices' -Status 'SKIP' -Message 'Skipped because the target service does not exist.'
        }

        Write-KubeNetSection -State $state -Name 'Kubernetes NetworkPolicy Layer' -Description 'Checks native Kubernetes NetworkPolicy objects. Calico/Cilium CRDs are evaluated separately in the CNI Policy Layer.'
        foreach ($policyScope in @(
            [PSCustomObject]@{ Role = 'target'; Namespace = $Namespace; Context = $targetContextEffective; Pods = $selectedPods },
            [PSCustomObject]@{ Role = 'source'; Namespace = $sourceNamespaceEffective; Context = $sourceContextEffective; Pods = @() }
        ) | Where-Object { $_.Namespace -and ($_.Role -eq 'target' -or -not $sourceIsTarget) }) {
            try {
                $policies = ConvertFrom-KubeNetJson -State $state -Context $policyScope.Context -Arguments @('get', 'networkpolicy', '-n', $policyScope.Namespace)
                $items = @($policies.items)
                if ($items.Count -eq 0) {
                    Add-KubeNetResult -State $state -Layer 'Kubernetes NetworkPolicy Layer' -Check "$($policyScope.Role) policies" -Status 'INFO' -Message "No native Kubernetes NetworkPolicy objects found in namespace '$($policyScope.Namespace)'."
                    continue
                }
                Add-KubeNetResult -State $state -Layer 'Kubernetes NetworkPolicy Layer' -Check "$($policyScope.Role) policies" -Status 'INFO' -Message "$($items.Count) native Kubernetes NetworkPolicy object(s) found in namespace '$($policyScope.Namespace)'."
                $networkPolicyObjectCount += $items.Count
                if ($policyScope.Role -eq 'source') {
                    $sourceNetworkPolicies = @($items)
                } elseif ($policyScope.Role -eq 'target') {
                    $targetNetworkPolicies = @($items)
                    if ($sourceIsTarget) {
                        $sourceNetworkPolicies = @($items)
                    }
                }
                if ($policyScope.Role -eq 'target' -and $policyScope.Pods.Count -gt 0) {
                    $selectedPolicies = @()
                    foreach ($policy in $items) {
                        $matchesAny = @($policyScope.Pods | Where-Object { Test-KubeNetSelectorMatchesPod -Selector $policy.spec.podSelector -Pod $_ }).Count -gt 0
                        if ($matchesAny) { $selectedPolicies += $policy }
                    }
                    if ($selectedPolicies.Count -gt 0) {
                        $names = @($selectedPolicies | ForEach-Object { $_.metadata.name }) -join ', '
                        Add-KubeNetResult -State $state -Layer 'Kubernetes NetworkPolicy Layer' -Check 'target pod policies' -Status 'INFO' -Message "Target pod(s) are selected by native Kubernetes NetworkPolicy: $names. Source-to-target allow rules are evaluated in Kubernetes NetworkPolicy Path Analysis when source pod metadata is available."
                    } else {
                        Add-KubeNetResult -State $state -Layer 'Kubernetes NetworkPolicy Layer' -Check 'target pod policies' -Status 'PASS' -Message 'No native Kubernetes NetworkPolicy objects appear to select the target pods.'
                    }
                }
                $defaultDeny = @($items | Where-Object {
                    ($_.spec.podSelector.PSObject.Properties.Count -eq 0) -and ($_.spec.policyTypes -contains 'Ingress' -or $_.spec.policyTypes -contains 'Egress')
                })
                if ($defaultDeny.Count -gt 0) {
                    Add-KubeNetResult -State $state -Layer 'Kubernetes NetworkPolicy Layer' -Check "$($policyScope.Role) default deny" -Status 'WARN' -Message "Namespace '$($policyScope.Namespace)' has broad/default-style native Kubernetes NetworkPolicy: $((@($defaultDeny | ForEach-Object { $_.metadata.name }) -join ', '))."
                }
            } catch {
                Add-KubeNetResult -State $state -Layer 'Kubernetes NetworkPolicy Layer' -Check "$($policyScope.Role) policies" -Status 'WARN' -Message "Could not inspect native Kubernetes NetworkPolicy objects in '$($policyScope.Namespace)': $($_.Exception.Message)"
            }
        }
        if ($networkPolicyObjectCount -gt 0 -and $cniProviderGuess -match 'kindnet|Flannel') {
            Add-KubeNetResult -State $state -Layer 'Kubernetes NetworkPolicy Layer' -Check 'CNI enforcement hint' -Status 'WARN' -Message "Native Kubernetes NetworkPolicy objects exist, but CNI/provider guess is '$cniProviderGuess'. Some CNIs, including kindnet and basic Flannel setups, do not enforce Kubernetes NetworkPolicy by themselves."
            Add-KubeNetDiagnosis -State $state -Message "NetworkPolicies are present, but the detected CNI/provider '$cniProviderGuess' may not enforce them. If traffic succeeds despite restrictive policies, verify the CNI's NetworkPolicy support."
        }

        Write-KubeNetSection -State $state -Name 'Ingress Layer' -Description 'Finds ingress routes pointing at the target service.'
        try {
            $ingresses = ConvertFrom-KubeNetJson -State $state -Context $targetContextEffective -Arguments @('get', 'ingress', '-n', $Namespace)
            $matches = @()
            $ingressClassControllers = @{}
            foreach ($ingress in @($ingresses.items)) {
                $ingressClass = if ($ingress.spec.ingressClassName) { [string]$ingress.spec.ingressClassName } else { '(default)' }
                $address = (@($ingress.status.loadBalancer.ingress | ForEach-Object { if ($_.ip) { $_.ip } elseif ($_.hostname) { $_.hostname } }) -join ', ')
                if ($ingress.spec.defaultBackend.service.name -eq $ServiceName) {
                    $backendPort = if ($ingress.spec.defaultBackend.service.port.number) { [string]$ingress.spec.defaultBackend.service.port.number } elseif ($ingress.spec.defaultBackend.service.port.name) { [string]$ingress.spec.defaultBackend.service.port.name } else { '' }
                    $matches += [PSCustomObject]@{
                        Name        = $ingress.metadata.name
                        Class       = $ingressClass
                        Host        = '(defaultBackend)'
                        Path        = '(all unmatched paths)'
                        BackendPort = $backendPort
                        Address     = $address
                        Object      = $ingress
                    }
                }
                foreach ($rule in @($ingress.spec.rules)) {
                    foreach ($pathItem in @($rule.http.paths)) {
                        if ($pathItem.backend.service.name -eq $ServiceName) {
                            $backendPort = if ($pathItem.backend.service.port.number) { [string]$pathItem.backend.service.port.number } elseif ($pathItem.backend.service.port.name) { [string]$pathItem.backend.service.port.name } else { '' }
                            $matches += [PSCustomObject]@{
                                Name        = $ingress.metadata.name
                                Class       = $ingressClass
                                Host        = if ($rule.host) { $rule.host } else { '*' }
                                Path        = if ($pathItem.path) { $pathItem.path } else { '/' }
                                BackendPort = $backendPort
                                Address     = $address
                                Object      = $ingress
                            }
                        }
                    }
                }
            }
            if ($matches.Count -eq 0) {
                Add-KubeNetResult -State $state -Layer 'Ingress Layer' -Check 'routes' -Status 'INFO' -Message "No Ingress routes in namespace '$Namespace' point at service '$ServiceName'."
            } else {
                foreach ($match in $matches) {
                    $addressText = if ($match.Address) { $match.Address } else { '(no address yet)' }
                    $status = if ($match.Address) { 'PASS' } else { 'WARN' }
                    Add-KubeNetResult -State $state -Layer 'Ingress Layer' -Check $match.Name -Status $status -Message "Ingress $($match.Name) class=$($match.Class) host=$($match.Host) path=$($match.Path) backendPort=$($match.BackendPort) address=$addressText"

                    $backendMatches = @($service.spec.ports | Where-Object { ([string]$_.port -eq $match.BackendPort) -or ([string]$_.name -eq $match.BackendPort) })
                    if ($backendMatches.Count -eq 0) {
                        Add-KubeNetResult -State $state -Layer 'Ingress Layer' -Check "$($match.Name) backend port" -Status 'FAIL' -Message "Ingress backend port '$($match.BackendPort)' does not match any port/name on service '$ServiceName'."
                        Add-KubeNetDiagnosis -State $state -Message "Ingress '$($match.Name)' points at service '$ServiceName' but backend port '$($match.BackendPort)' does not match the service ports."
                    } else {
                        Add-KubeNetResult -State $state -Layer 'Ingress Layer' -Check "$($match.Name) backend port" -Status 'PASS' -Message "Ingress backend port '$($match.BackendPort)' matches service '$ServiceName'."
                    }

                    $annotationNames = @()
                    if ($match.Object.metadata.annotations) {
                        $annotationNames = @($match.Object.metadata.annotations.PSObject.Properties.Name | Sort-Object)
                    }
                    if ($annotationNames.Count -gt 0) {
                        Add-KubeNetResult -State $state -Layer 'Ingress Layer' -Check "$($match.Name) annotations" -Status 'INFO' -Message "Ingress has annotation(s): $($annotationNames -join ', '). KubeNetMods surfaces annotations but does not validate controller-specific annotation semantics."
                    }

                    foreach ($tls in @($match.Object.spec.tls)) {
                        if ([string]::IsNullOrWhiteSpace($tls.secretName)) { continue }
                        $tlsSecret = Invoke-KubeNetKubectl -State $state -Context $targetContextEffective -Arguments @('get', 'secret', $tls.secretName, '-n', $Namespace, '-o', 'json') -AllowFailure
                        if ($tlsSecret.ExitCode -eq 0) {
                            Add-KubeNetResult -State $state -Layer 'Ingress Layer' -Check "$($match.Name) TLS secret" -Status 'PASS' -Message "TLS secret '$($tls.secretName)' exists for ingress '$($match.Name)'."
                        } else {
                            Add-KubeNetResult -State $state -Layer 'Ingress Layer' -Check "$($match.Name) TLS secret" -Status 'FAIL' -Message "TLS secret '$($tls.secretName)' was not found/readable in namespace '$Namespace'."
                            Add-KubeNetDiagnosis -State $state -Message "Ingress '$($match.Name)' references missing/unreadable TLS secret '$($tls.secretName)'."
                        }
                    }
                }

                $classesToCheck = @($matches | ForEach-Object { $_.Class } | Where-Object { $_ -ne '(default)' } | Sort-Object -Unique)
                foreach ($className in $classesToCheck) {
                    $classResult = Invoke-KubeNetKubectl -State $state -Context $targetContextEffective -Arguments @('get', 'ingressclass', $className, '-o', 'json') -AllowFailure
                    if ($classResult.ExitCode -eq 0 -and -not [string]::IsNullOrWhiteSpace($classResult.Text)) {
                        $classObj = $classResult.Text | ConvertFrom-Json
                        Add-KubeNetResult -State $state -Layer 'Ingress Layer' -Check "IngressClass $className" -Status 'PASS' -Message "IngressClass '$className' exists. Controller=$($classObj.spec.controller)."
                        if ($classObj.spec.controller) {
                            $ingressClassControllers[$className] = [string]$classObj.spec.controller
                        }
                    } else {
                        Add-KubeNetResult -State $state -Layer 'Ingress Layer' -Check "IngressClass $className" -Status 'FAIL' -Message "IngressClass '$className' was not found/readable."
                        Add-KubeNetDiagnosis -State $state -Message "Ingress references class '$className', but that IngressClass was not found/readable."
                    }
                }

                $allPods = Invoke-KubeNetKubectl -State $state -Context $targetContextEffective -Arguments @('get', 'pods', '-A', '-o', 'json') -AllowFailure
                if ($allPods.ExitCode -eq 0 -and -not [string]::IsNullOrWhiteSpace($allPods.Text)) {
                    $podObj = $allPods.Text | ConvertFrom-Json
                    $controllerHints = @(
                        'ingress-nginx',
                        'nginx-ingress',
                        'traefik',
                        'contour',
                        'haproxy',
                        'istio-ingressgateway',
                        'aws-load-balancer-controller',
                        'azure-alb',
                        'gateway-api',
                        'envoy'
                    )
                    foreach ($controller in @($ingressClassControllers.Values | Where-Object { -not [string]::IsNullOrWhiteSpace($_) })) {
                        $controllerHints += $controller
                        $controllerHints += ($controller -replace '/', '-')
                        $controllerHints += ($controller -split '[./]' | Where-Object { $_.Length -ge 4 })
                    }
                    $controllerHintPattern = (($controllerHints | Where-Object { -not [string]::IsNullOrWhiteSpace($_) } | Sort-Object -Unique | ForEach-Object { [regex]::Escape($_.ToLowerInvariant()) }) -join '|')
                    if ([string]::IsNullOrWhiteSpace($controllerHintPattern)) { $controllerHintPattern = 'a^' }
                    $controllerPods = @($podObj.items | Where-Object {
                        $n = "$($_.metadata.namespace)/$($_.metadata.name)".ToLowerInvariant()
                        $labels = if ($_.metadata.labels) { ($_.metadata.labels.PSObject.Properties | ForEach-Object { "$($_.Name)=$($_.Value)" }) -join ' ' } else { '' }
                        "$n $labels".ToLowerInvariant() -match $controllerHintPattern
                    })
                    if ($controllerPods.Count -gt 0) {
                        $readyControllers = @($controllerPods | Where-Object { Get-KubeNetPodReady -Pod $_ })
                        $names = (@($controllerPods | Select-Object -First 6 | ForEach-Object { "$($_.metadata.namespace)/$($_.metadata.name)" }) -join ', ')
                        $controllerStatus = if ($readyControllers.Count -eq $controllerPods.Count) { 'PASS' } else { 'WARN' }
                        Add-KubeNetResult -State $state -Layer 'Ingress Layer' -Check 'controller pods' -Status $controllerStatus -Message "$($readyControllers.Count)/$($controllerPods.Count) likely ingress/controller pod(s) are Ready: $names"
                        if ($readyControllers.Count -ne $controllerPods.Count) {
                            Add-KubeNetDiagnosis -State $state -Message 'Likely ingress/controller pods are not all Ready. Check controller deployment, admission/webhook config, and load balancer integration.'
                        }
                    } else {
                        Add-KubeNetResult -State $state -Layer 'Ingress Layer' -Check 'controller pods' -Status 'INFO' -Message 'No obvious ingress controller pods found by visible pod name/label. Static Ingress checks still apply; runtime controller health may require provider/controller-specific access.'
                    }
                } else {
                    Add-KubeNetResult -State $state -Layer 'Ingress Layer' -Check 'controller pods' -Status 'WARN' -Message 'Could not list pods across namespaces to inspect ingress controller readiness.'
                }
            }
        } catch {
            Add-KubeNetResult -State $state -Layer 'Ingress Layer' -Check 'routes' -Status 'WARN' -Message "Could not inspect Ingress objects: $($_.Exception.Message)"
        }

        if (-not $SkipDebugPod) {
            $targetDebugReady = Ensure-KubeNetDebugPod -State $state -Context $targetContextEffective -Namespace $Namespace -Name $TargetDebugPodName -Image $DebugImage -ImagePullPolicy $DebugImagePullPolicy -TimeoutSec $TimeoutSec -Layer 'Target debug pod'
            if (-not $sourceIsTarget) {
                $sourceDebugReady = Ensure-KubeNetDebugPod -State $state -Context $sourceContextEffective -Namespace $sourceNamespaceEffective -Name $SourceDebugPodName -Image $DebugImage -ImagePullPolicy $DebugImagePullPolicy -TimeoutSec $TimeoutSec -Layer 'Source debug pod'
            } else {
                $sourceDebugReady = $targetDebugReady
            }
        } else {
            Add-KubeNetResult -State $state -Layer 'Debug Pod' -Check 'debug pod' -Status 'SKIP' -Message 'Skipped by -SkipDebugPod.'
        }

        Write-KubeNetSection -State $state -Name 'Target debug pod path' -Description 'Uses a debug pod in the target namespace to prove the target service/backend path independent of the source pod.'
        if ($service -and $targetDebugReady) {
            $urls = New-KubeNetServiceUrls -Service $service -ServiceName $ServiceName -Namespace $Namespace -ServicePort $ServicePort -UrlScheme $UrlScheme -UrlPath $UrlPath
            foreach ($name in @($ServiceName, "$ServiceName.$Namespace.svc.cluster.local")) {
                $dns = Invoke-KubeNetInPod -State $state -Context $targetContextEffective -Namespace $Namespace -PodName $TargetDebugPodName -Command "nslookup $name"
                if ($dns.ExitCode -eq 0) {
                    Add-KubeNetResult -State $state -Layer 'Target debug pod path' -Check "target debug pod resolve $name" -Status 'PASS' -Message "Target debug pod '$TargetDebugPodName' resolved '$name'."
                } else {
                    Add-KubeNetResult -State $state -Layer 'Target debug pod path' -Check "target debug pod resolve $name" -Status 'FAIL' -Message "Target debug pod '$TargetDebugPodName' could not resolve '$name'."
                    Add-KubeNetDiagnosis -State $state -Message "Cluster DNS failed for '$name' from namespace '$Namespace'. Check CoreDNS, service name/namespace, and DNS policy."
                }
            }
            foreach ($target in @(
                [PSCustomObject]@{ Name = 'short service URL'; Url = $urls.ShortName },
                [PSCustomObject]@{ Name = 'service FQDN URL'; Url = $urls.Fqdn },
                [PSCustomObject]@{ Name = 'ClusterIP URL'; Url = $urls.ClusterIp }
            ) | Where-Object { -not [string]::IsNullOrWhiteSpace($_.Url) }) {
                if ($servicePortMissing) {
                    Add-KubeNetResult -State $state -Layer 'Target debug pod path' -Check $target.Name -Status 'SKIP' -Message "Skipped because service port $ServicePort is not exposed."
                } else {
                    $curl = Invoke-KubeNetInPod -State $state -Context $targetContextEffective -Namespace $Namespace -PodName $TargetDebugPodName -Command "curl -k -sS -o /dev/null -w 'HTTP_STATUS=%{http_code}' --connect-timeout $TimeoutSec --max-time $TimeoutSec '$($target.Url)'"
                    if ($curl.ExitCode -eq 0) {
                        Add-KubeNetResult -State $state -Layer 'Target debug pod path' -Check $target.Name -Status 'PASS' -Message "$($target.Url) reachable from target debug pod '$TargetDebugPodName'. HTTP status: $(Get-KubeNetHttpStatusFromText $curl.Text)"
                    } else {
                        Add-KubeNetResult -State $state -Layer 'Target debug pod path' -Check $target.Name -Status 'FAIL' -Message "$($target.Url) failed from target debug pod '$TargetDebugPodName'."
                    }
                }
            }
        }

        $sourceExecPodName = if ($sourceIsTarget) { $TargetDebugPodName } else { $SourceDebugPodName }
        $sourceExecContainer = ''
        $usingSuppliedSourcePod = -not [string]::IsNullOrWhiteSpace($SourcePodName)
        $usingSelectedSourcePod = $false
        $sourcePodObject = $null
        if (-not [string]::IsNullOrWhiteSpace($SourcePodName)) {
            $sourceExecPodName = $SourcePodName
            $sourceExecContainer = $SourceContainer
            try {
                $sourcePodObject = ConvertFrom-KubeNetJson -State $state -Context $sourceContextEffective -Arguments @('get', 'pod', $SourcePodName, '-n', $sourceNamespaceEffective)
            } catch {
                Add-KubeNetResult -State $state -Layer 'Source pod path' -Check 'source pod' -Status 'WARN' -Message "Could not read supplied source pod '$SourcePodName': $($_.Exception.Message)"
            }
            Add-KubeNetResult -State $state -Layer 'Source pod path' -Check 'source pod selected' -Status 'INFO' -Message "Using supplied source pod '$SourcePodName' in namespace '$sourceNamespaceEffective' for source-to-target checks."
        } elseif (-not [string]::IsNullOrWhiteSpace($SourcePodSelector)) {
            try {
                $sourcePods = ConvertFrom-KubeNetJson -State $state -Context $sourceContextEffective -Arguments @('get', 'pods', '-n', $sourceNamespaceEffective, '-l', $SourcePodSelector)
                $sourceReadyPods = @($sourcePods.items | Where-Object { $_.status.phase -eq 'Running' -and (Get-KubeNetPodReady -Pod $_) })
                if ($sourceReadyPods.Count -gt 0) {
                    $sourceExecPodName = $sourceReadyPods[0].metadata.name
                    $sourceExecContainer = $SourceContainer
                    $sourcePodObject = $sourceReadyPods[0]
                    $usingSelectedSourcePod = $true
                    Add-KubeNetResult -State $state -Layer 'Source pod path' -Check 'source pod selected' -Status 'INFO' -Message "Using source pod '$sourceExecPodName' selected by '$SourcePodSelector' for source-to-target checks."
                } else {
                    Add-KubeNetResult -State $state -Layer 'Source pod path' -Check 'source pod selected' -Status 'WARN' -Message "No running Ready source pod matched selector '$SourcePodSelector'. Falling back to source debug pod when available."
                }
            } catch {
                Add-KubeNetResult -State $state -Layer 'Source pod path' -Check 'source pod selected' -Status 'WARN' -Message "Could not select source pod with selector '$SourcePodSelector': $($_.Exception.Message)"
            }
        }

        $sourceCanExec = $sourceDebugReady -or $usingSuppliedSourcePod -or $usingSelectedSourcePod
        if ($sourceCanExec -and $null -eq $sourcePodObject) {
            try {
                $sourcePodObject = ConvertFrom-KubeNetJson -State $state -Context $sourceContextEffective -Arguments @('get', 'pod', $sourceExecPodName, '-n', $sourceNamespaceEffective)
            } catch {
                Add-KubeNetResult -State $state -Layer 'Source DNS Policy Layer' -Check 'source pod metadata' -Status 'WARN' -Message "Could not read source pod '$sourceExecPodName': $($_.Exception.Message)"
            }
        }

        if ($targetDebugReady -or $sourceCanExec) {
            Write-KubeNetSection -State $state -Name 'MTU Snapshot Layer' -Description 'Captures pod-side interface MTUs when an exec-capable pod is available.'
            $targetEth0Mtu = $null
            $sourceEth0Mtu = $null
            if ($targetDebugReady) {
                $targetMtuOutput = Invoke-KubeNetInPod -State $state -Context $targetContextEffective -Namespace $Namespace -PodName $TargetDebugPodName -Command 'ip -o link show'
                if ($targetMtuOutput.ExitCode -eq 0) {
                    $targetMtu = Get-KubeNetMtuSummary -Text $targetMtuOutput.Text
                    $targetEth0 = @($targetMtu | Where-Object { $_.Name -eq 'eth0' } | Select-Object -First 1)
                    if ($targetEth0.Count -gt 0) { $targetEth0Mtu = $targetEth0[0].Mtu }
                    Add-KubeNetResult -State $state -Layer 'MTU Snapshot Layer' -Check 'target pod MTU' -Status 'INFO' -Message "Target namespace debug pod MTU(s): $((@($targetMtu | ForEach-Object { '{0}={1}' -f $_.Name, $_.Mtu }) -join ', '))" -Data $targetMtuOutput.Text
                } else {
                    Add-KubeNetResult -State $state -Layer 'MTU Snapshot Layer' -Check 'target pod MTU' -Status 'SKIP' -Message "Could not read target debug pod MTU. The debug image may not include the ip command."
                }
                $targetRoutes = Invoke-KubeNetInPod -State $state -Context $targetContextEffective -Namespace $Namespace -PodName $TargetDebugPodName -Command 'ip route show'
                if ($targetRoutes.ExitCode -eq 0) {
                    Add-KubeNetResult -State $state -Layer 'MTU Snapshot Layer' -Check 'target pod routes' -Status 'INFO' -Message "Target debug pod routes: $(Format-KubeNetRouteSummary -Text $targetRoutes.Text)" -Data $targetRoutes.Text
                }
            }
            if ($sourceCanExec) {
                $sourceMtuOutput = Invoke-KubeNetInPod -State $state -Context $sourceContextEffective -Namespace $sourceNamespaceEffective -PodName $sourceExecPodName -Container $sourceExecContainer -Command 'ip -o link show'
                if ($sourceMtuOutput.ExitCode -eq 0) {
                    $sourceMtu = Get-KubeNetMtuSummary -Text $sourceMtuOutput.Text
                    $sourceEth0 = @($sourceMtu | Where-Object { $_.Name -eq 'eth0' } | Select-Object -First 1)
                    if ($sourceEth0.Count -gt 0) { $sourceEth0Mtu = $sourceEth0[0].Mtu }
                    Add-KubeNetResult -State $state -Layer 'MTU Snapshot Layer' -Check 'source pod MTU' -Status 'INFO' -Message "Source exec pod MTU(s): $((@($sourceMtu | ForEach-Object { '{0}={1}' -f $_.Name, $_.Mtu }) -join ', '))" -Data $sourceMtuOutput.Text
                } else {
                    Add-KubeNetResult -State $state -Layer 'MTU Snapshot Layer' -Check 'source pod MTU' -Status 'SKIP' -Message "Could not read source pod MTU. The container may not include the ip command."
                }
                $sourceRoutes = Invoke-KubeNetInPod -State $state -Context $sourceContextEffective -Namespace $sourceNamespaceEffective -PodName $sourceExecPodName -Container $sourceExecContainer -Command 'ip route show'
                if ($sourceRoutes.ExitCode -eq 0) {
                    Add-KubeNetResult -State $state -Layer 'MTU Snapshot Layer' -Check 'source pod routes' -Status 'INFO' -Message "Source exec pod routes: $(Format-KubeNetRouteSummary -Text $sourceRoutes.Text)" -Data $sourceRoutes.Text
                }
            }
            if ($null -ne $targetEth0Mtu -and $null -ne $sourceEth0Mtu) {
                if ($targetEth0Mtu -eq $sourceEth0Mtu) {
                    Add-KubeNetResult -State $state -Layer 'MTU Snapshot Layer' -Check 'eth0 MTU comparison' -Status 'PASS' -Message "Target/source eth0 MTU values match at $targetEth0Mtu."
                } else {
                    Add-KubeNetResult -State $state -Layer 'MTU Snapshot Layer' -Check 'eth0 MTU comparison' -Status 'WARN' -Message "Target/source eth0 MTU values differ. Target=$targetEth0Mtu Source=$sourceEth0Mtu."
                    Add-KubeNetDiagnosis -State $state -Message "Target and source pod MTUs differ. If large payloads intermittently fail, investigate overlay/CNI MTU settings and path MTU."
                }
            }
        }

        $sourceResolvSummary = $null
        if ($sourceCanExec) {
            Write-KubeNetSection -State $state -Name 'Source DNS Policy Layer' -Description 'Checks the source pod runtime resolver against NetworkPolicies selecting that pod.'
            if (-not $usingSuppliedSourcePod -and -not $usingSelectedSourcePod) {
                Add-KubeNetResult -State $state -Layer 'Source DNS Policy Layer' -Check 'source identity' -Status 'INFO' -Message "Using debug pod '$sourceExecPodName'. This proves namespace-level reachability, but may not match the real workload pod labels or NetworkPolicies."
            }

            $resolv = Invoke-KubeNetInPod -State $state -Context $sourceContextEffective -Namespace $sourceNamespaceEffective -PodName $sourceExecPodName -Container $sourceExecContainer -Command 'cat /etc/resolv.conf'
            if ($resolv.ExitCode -eq 0) {
                $sourceResolvSummary = Get-KubeNetResolvConfSummary -Text $resolv.Text
                Add-KubeNetResult -State $state -Layer 'Source DNS Policy Layer' -Check 'source resolv.conf' -Status 'PASS' -Message "Runtime nameserver(s): $(Format-KubeNetList $sourceResolvSummary.Nameservers); search domains: $(Format-KubeNetList $sourceResolvSummary.Searches)" -Data $resolv.Text
            } else {
                Add-KubeNetResult -State $state -Layer 'Source DNS Policy Layer' -Check 'source resolv.conf' -Status 'WARN' -Message "Could not read /etc/resolv.conf from source pod '$sourceExecPodName'."
            }

            if ($sourcePodObject -and $sourceResolvSummary) {
                $policyAnalysis = Test-KubeNetDnsEgressPolicy -State $state -SourcePod $sourcePodObject -ResolvSummary $sourceResolvSummary -NetworkPolicies $sourceNetworkPolicies -CoreDnsPods $coreDnsPods -NodeLocalDnsPods $nodeLocalDnsPods -KubeSystemNamespace $kubeSystemNamespace -CoreDnsServiceIp $coreDnsServiceIp
                Add-KubeNetResult -State $state -Layer 'Source DNS Policy Layer' -Check 'dns egress policy' -Status $policyAnalysis.Status -Message $policyAnalysis.Message
                foreach ($diagnosis in @($policyAnalysis.Diagnoses)) {
                    Add-KubeNetDiagnosis -State $state -Message $diagnosis
                }
            } else {
                Add-KubeNetResult -State $state -Layer 'Source DNS Policy Layer' -Check 'dns egress policy' -Status 'SKIP' -Message 'Skipped DNS egress policy analysis because source pod metadata or resolver data was unavailable.'
            }
        }

        if ($service -and $sourceCanExec) {
            Write-KubeNetSection -State $state -Name 'Kubernetes NetworkPolicy Path Analysis' -Description 'Compares native Kubernetes NetworkPolicy source egress and target ingress rules against this specific source-to-service path.'
            $pathPolicy = Test-KubeNetNetworkPolicyPath -SourcePod $sourcePodObject -SourceNamespace $sourceNamespaceObject -TargetPods $selectedPods -TargetNamespace $targetNamespaceObject -SourceNetworkPolicies $sourceNetworkPolicies -TargetNetworkPolicies $targetNetworkPolicies -Service $service -ServicePortObject $selectedServicePort -ContainerPorts $containerPorts
            foreach ($pathResult in @($pathPolicy.Results)) {
                Add-KubeNetResult -State $state -Layer 'Kubernetes NetworkPolicy Path Analysis' -Check $pathResult.Check -Status $pathResult.Status -Message $pathResult.Message
            }
            foreach ($diagnosis in @($pathPolicy.Diagnoses)) {
                Add-KubeNetDiagnosis -State $state -Message $diagnosis
            }

            Write-KubeNetSection -State $state -Name 'CNI Policy Layer' -Description 'Checks Calico/Cilium policy CRDs separately from native Kubernetes NetworkPolicy.'
            $cniPolicy = Test-KubeNetCniSpecificPolicyPath -State $state -Context $targetContextEffective -CniProviderGuess $cniProviderGuess -SourcePod $sourcePodObject -SourceNamespace $sourceNamespaceObject -TargetPods $selectedPods -TargetNamespace $targetNamespaceObject -Service $service -ServicePortObject $selectedServicePort -ContainerPorts $containerPorts -SourceResolvSummary $sourceResolvSummary -CoreDnsPods $coreDnsPods -NodeLocalDnsPods $nodeLocalDnsPods -KubeSystemNamespace $kubeSystemNamespace -CoreDnsServiceIp $coreDnsServiceIp
            foreach ($cniResult in @($cniPolicy.Results)) {
                Add-KubeNetResult -State $state -Layer 'CNI Policy Layer' -Check $cniResult.Check -Status $cniResult.Status -Message $cniResult.Message
            }
            foreach ($diagnosis in @($cniPolicy.Diagnoses)) {
                Add-KubeNetDiagnosis -State $state -Message $diagnosis
            }

            $nativePolicyFail = @($pathPolicy.Results | Where-Object { $_.Status -eq 'WARN' -and $_.Message -match 'no rule obviously allows|may block' })
            $nativePolicyPass = @($pathPolicy.Results | Where-Object { $_.Status -eq 'PASS' })
            $cniPolicyFail = @($cniPolicy.Results | Where-Object { $_.Status -eq 'FAIL' })
            $cniPolicyPass = @($cniPolicy.Results | Where-Object { $_.Status -eq 'PASS' })
            $combinedStatus = 'INFO'
            $combinedMessage = "Native Kubernetes NetworkPolicy and CNI-specific policy checks were both evaluated. Native result: unknown. CNI result: $($cniPolicy.Summary)"
            if ($nativePolicyFail.Count -gt 0 -or $cniPolicyFail.Count -gt 0) {
                $combinedStatus = 'FAIL'
                $nativeText = if ($nativePolicyFail.Count -gt 0) { 'native Kubernetes NetworkPolicy may block this path' } elseif ($nativePolicyPass.Count -gt 0) { 'native Kubernetes NetworkPolicy does not appear to block this path' } else { 'native Kubernetes NetworkPolicy result unknown' }
                $cniText = if ($cniPolicyFail.Count -gt 0) { 'CNI-specific policy blocks or likely blocks this path' } elseif ($cniPolicyPass.Count -gt 0) { 'CNI-specific policy does not appear to block this path' } else { 'CNI-specific policy result unknown' }
                $combinedMessage = "Combined policy result: blocked or likely blocked. $nativeText; $cniText."
            } elseif ($nativePolicyPass.Count -gt 0 -or $cniPolicyPass.Count -gt 0) {
                $combinedStatus = 'PASS'
                $combinedMessage = "Combined policy result: no policy block inferred for the tested source-to-target path. Native Kubernetes NetworkPolicy path checks passed or found no isolation; $($cniPolicy.Summary)"
            }
            Add-KubeNetResult -State $state -Layer 'Combined Policy Summary' -Check 'effective policy interpretation' -Status $combinedStatus -Message $combinedMessage
        }

        if ($selectedPods.Count -gt 0 -and ($targetDebugReady -or $sourceCanExec)) {
            Write-KubeNetSection -State $state -Name 'Pod-to-Pod Connectivity Layer' -Description 'Curls selected pod IPs directly to separate pod/app reachability from Service routing.'
            $readyTargetPods = @($selectedPods | Where-Object { $_.status.phase -eq 'Running' -and (Get-KubeNetPodReady -Pod $_) -and -not [string]::IsNullOrWhiteSpace([string]$_.status.podIP) } | Select-Object -First 5)
            $directPortInfo = Get-KubeNetDirectPodPortCandidates -ServicePortObject $selectedServicePort -ContainerPorts $containerPorts
            $directPorts = @($directPortInfo.Ports | Select-Object -First 4)
            if ($readyTargetPods.Count -eq 0) {
                Add-KubeNetResult -State $state -Layer 'Pod-to-Pod Connectivity Layer' -Check 'direct pod curl' -Status 'SKIP' -Message 'Skipped because no running/ready target pod IPs were available.'
            } elseif ($directPorts.Count -eq 0) {
                Add-KubeNetResult -State $state -Layer 'Pod-to-Pod Connectivity Layer' -Check 'direct pod curl' -Status 'SKIP' -Message 'Skipped because no usable pod port candidate was found.'
            } else {
                Add-KubeNetResult -State $state -Layer 'Pod-to-Pod Connectivity Layer' -Check 'port candidates' -Status 'INFO' -Message "Testing direct pod port(s) $($directPorts -join ', ') based on $($directPortInfo.Reason)."
                $directPodReachable = $false
                $directSources = @()
                if ($targetDebugReady) {
                    $directSources += [PSCustomObject]@{
                        Name      = "target debug pod '$TargetDebugPodName'"
                        Context   = $targetContextEffective
                        Namespace = $Namespace
                        PodName   = $TargetDebugPodName
                        Container = ''
                    }
                }
                if ($sourceCanExec -and (-not $targetDebugReady -or $sourceExecPodName -ne $TargetDebugPodName -or $sourceNamespaceEffective -ne $Namespace)) {
                    $directSources += [PSCustomObject]@{
                        Name      = if ($usingSuppliedSourcePod -or $usingSelectedSourcePod) { "source pod '$sourceExecPodName'" } else { "source debug pod '$sourceExecPodName'" }
                        Context   = $sourceContextEffective
                        Namespace = $sourceNamespaceEffective
                        PodName   = $sourceExecPodName
                        Container = $sourceExecContainer
                    }
                }

                foreach ($directSource in $directSources) {
                    foreach ($pod in $readyTargetPods) {
                        foreach ($directPort in $directPorts) {
                            $directUrl = "$UrlScheme`://$($pod.status.podIP)`:$directPort$(Get-KubeNetUrlPath -UrlPath $UrlPath)"
                            $directCurl = Invoke-KubeNetInPod -State $state -Context $directSource.Context -Namespace $directSource.Namespace -PodName $directSource.PodName -Container $directSource.Container -Command "curl -k -sS -o /dev/null -w 'HTTP_STATUS=%{http_code}' --connect-timeout $TimeoutSec --max-time $TimeoutSec '$directUrl'"
                            $checkName = "$($directSource.Name) to $($pod.metadata.name):$directPort"
                            if ($directCurl.ExitCode -eq 0) {
                                $directPodReachable = $true
                                Add-KubeNetResult -State $state -Layer 'Pod-to-Pod Connectivity Layer' -Check $checkName -Status 'PASS' -Message "$directUrl reachable. HTTP status: $(Get-KubeNetHttpStatusFromText $directCurl.Text)"
                            } else {
                                Add-KubeNetResult -State $state -Layer 'Pod-to-Pod Connectivity Layer' -Check $checkName -Status 'FAIL' -Message "$directUrl failed from $($directSource.Name)."
                                Add-KubeNetDiagnosis -State $state -Message "Direct pod IP connectivity failed from $($directSource.Name) to target pod '$($pod.metadata.name)' on port $directPort. Check CNI/overlay routing, NetworkPolicy, sidecars, and whether the app listens on that port."
                            }
                        }
                    }
                }
                if ($directPodReachable -and $targetPortMetadataStatus -eq 'Mismatch') {
                    Add-KubeNetDiagnosis -State $state -Message "Primary issue: target pods are reachable directly, but the Service targetPort does not match declared container ports. Fix the Service targetPort or the pod containerPort/listener."
                }
            }
        } elseif ($selectedPods.Count -gt 0) {
            Add-KubeNetResult -State $state -Layer 'Pod-to-Pod Connectivity Layer' -Check 'direct pod curl' -Status 'SKIP' -Message 'Skipped because no exec-capable debug/source pod was available.'
        }

        if ($service -and $sourceCanExec) {
            $targetFqdn = "$ServiceName.$Namespace.svc.cluster.local"
            $targetPort = Get-KubeNetServicePort -Service $service -ServicePort $ServicePort
            $targetUrl = "$UrlScheme`://$targetFqdn`:$targetPort$(Get-KubeNetUrlPath -UrlPath $UrlPath)"
            $fqdnDns = Invoke-KubeNetInPod -State $state -Context $sourceContextEffective -Namespace $sourceNamespaceEffective -PodName $sourceExecPodName -Container $sourceExecContainer -Command "nslookup $targetFqdn"
            if ($fqdnDns.ExitCode -eq 0) {
                Add-KubeNetResult -State $state -Layer 'Source pod path' -Check 'source pod resolve target FQDN' -Status 'PASS' -Message "Source pod path in namespace '$sourceNamespaceEffective' resolved '$targetFqdn' using pod '$sourceExecPodName'."
            } else {
                Add-KubeNetResult -State $state -Layer 'Source pod path' -Check 'source pod resolve target FQDN' -Status 'FAIL' -Message "Source pod path in namespace '$sourceNamespaceEffective' could not resolve '$targetFqdn' using pod '$sourceExecPodName'."
                Add-KubeNetDiagnosis -State $state -Message "Source namespace '$sourceNamespaceEffective' cannot resolve target service FQDN '$targetFqdn'. Check source pod DNS policy, CoreDNS, and NetworkPolicy allowing DNS egress."
            }
            $sourceCurl = Invoke-KubeNetInPod -State $state -Context $sourceContextEffective -Namespace $sourceNamespaceEffective -PodName $sourceExecPodName -Container $sourceExecContainer -Command "curl -k -sS -o /dev/null -w 'HTTP_STATUS=%{http_code}' --connect-timeout $TimeoutSec --max-time $TimeoutSec '$targetUrl'"
            if ($sourceCurl.ExitCode -eq 0) {
                Add-KubeNetResult -State $state -Layer 'Source pod path' -Check 'source pod curl target FQDN' -Status 'PASS' -Message "$targetUrl reachable from source pod path using pod '$sourceExecPodName'. HTTP status: $(Get-KubeNetHttpStatusFromText $sourceCurl.Text)"
            } else {
                Add-KubeNetResult -State $state -Layer 'Source pod path' -Check 'source pod curl target FQDN' -Status 'FAIL' -Message "$targetUrl failed from source pod path using pod '$sourceExecPodName' in namespace '$sourceNamespaceEffective'."
                if (-not $targetHasReadyEndpoints) {
                    Add-KubeNetDiagnosis -State $state -Message "Source-to-target connection failed, but the target service has no ready endpoints. Fix target workload/readiness before debugging source namespace policy."
                } else {
                    Add-KubeNetDiagnosis -State $state -Message "Source-to-target service connection failed while the target has ready endpoints. Check source egress policy, target ingress policy, service port, and app listener."
                }
            }
        }

        if ($TestTargetPodDns -and $selectedPods.Count -gt 0) {
            Write-KubeNetSection -State $state -Name 'Workload Pod DNS Layer' -Description 'Execs into a selected workload pod and compares runtime DNS with Kubernetes metadata.'
            $podForDns = if ([string]::IsNullOrWhiteSpace($TargetDnsPodName)) {
                @($selectedPods | Where-Object { $_.status.phase -eq 'Running' -and (Get-KubeNetPodReady -Pod $_) } | Select-Object -First 1)
            } else {
                @($selectedPods | Where-Object { $_.metadata.name -eq $TargetDnsPodName } | Select-Object -First 1)
            }
            if ($podForDns.Count -eq 0) {
                Add-KubeNetResult -State $state -Layer 'Workload Pod DNS Layer' -Check 'pod dns exec' -Status 'SKIP' -Message 'No selected running/ready pod was available for DNS exec checks.'
            } else {
                $podName = $podForDns[0].metadata.name
                $dnsPolicy = [string]$podForDns[0].spec.dnsPolicy
                $hostNetwork = [bool]($podForDns[0].spec.hostNetwork)
                Add-KubeNetResult -State $state -Layer 'Workload Pod DNS Layer' -Check 'pod dns metadata' -Status 'INFO' -Message "pod=$podName dnsPolicy=$dnsPolicy hostNetwork=$hostNetwork"
                if ($hostNetwork -and $dnsPolicy -ne 'ClusterFirstWithHostNet') {
                    Add-KubeNetResult -State $state -Layer 'Workload Pod DNS Layer' -Check 'hostNetwork dnsPolicy' -Status 'WARN' -Message "Pod uses hostNetwork but dnsPolicy is '$dnsPolicy'."
                    Add-KubeNetDiagnosis -State $state -Message "Pod '$podName' uses hostNetwork with dnsPolicy '$dnsPolicy'. Use ClusterFirstWithHostNet if it needs Kubernetes service DNS."
                }
                if ($dnsPolicy -eq 'Default') {
                    Add-KubeNetResult -State $state -Layer 'Workload Pod DNS Layer' -Check 'dnsPolicy' -Status 'WARN' -Message 'Pod dnsPolicy is Default, so it inherits node DNS instead of cluster DNS.'
                }
                $resolv = Invoke-KubeNetInPod -State $state -Context $targetContextEffective -Namespace $Namespace -PodName $podName -Container $TargetDnsContainer -Command 'cat /etc/resolv.conf'
                $resolvSummary = $null
                if ($resolv.ExitCode -eq 0) {
                    $resolvSummary = Get-KubeNetResolvConfSummary -Text $resolv.Text
                    Add-KubeNetResult -State $state -Layer 'Workload Pod DNS Layer' -Check 'resolv.conf' -Status 'PASS' -Message "Runtime nameserver(s): $(Format-KubeNetList $resolvSummary.Nameservers); search domains: $(Format-KubeNetList $resolvSummary.Searches)" -Data $resolv.Text
                } else {
                    Add-KubeNetResult -State $state -Layer 'Workload Pod DNS Layer' -Check 'resolv.conf' -Status 'FAIL' -Message "Could not read /etc/resolv.conf from pod '$podName'."
                }
                $fqdn = "$ServiceName.$Namespace.svc.cluster.local"
                foreach ($lookup in @($fqdn, $ServiceName)) {
                    $nslookup = Invoke-KubeNetInPod -State $state -Context $targetContextEffective -Namespace $Namespace -PodName $podName -Container $TargetDnsContainer -Command "if command -v nslookup >/dev/null 2>&1; then nslookup $lookup; else echo KubeNetModsToolMissing:nslookup; exit 127; fi"
                    if ($nslookup.ExitCode -eq 0) {
                        Add-KubeNetResult -State $state -Layer 'Workload Pod DNS Layer' -Check "resolve $lookup" -Status 'PASS' -Message "Pod '$podName' resolved '$lookup'."
                    } elseif ($nslookup.ExitCode -eq 127 -or $nslookup.Text -match 'KubeNetModsToolMissing') {
                        Add-KubeNetResult -State $state -Layer 'Workload Pod DNS Layer' -Check "resolve $lookup" -Status 'SKIP' -Message "Pod '$podName' does not include nslookup."
                    } else {
                        Add-KubeNetResult -State $state -Layer 'Workload Pod DNS Layer' -Check "resolve $lookup" -Status 'WARN' -Message "Pod '$podName' could not resolve '$lookup'."
                        if ($dnsPolicy -eq 'Default' -and $resolvSummary) {
                            Add-KubeNetDiagnosis -State $state -Message "Pod '$podName' uses dnsPolicy Default and runtime nameserver(s) $(Format-KubeNetList $resolvSummary.Nameservers). Remove the override or use ClusterFirst."
                        } elseif ($lookup -eq $ServiceName -and $resolvSummary -and $resolvSummary.Searches.Count -eq 0) {
                            Add-KubeNetDiagnosis -State $state -Message "Pod '$podName' has no DNS search domains. Short service names may fail even when FQDN works."
                        }
                    }
                }
            }
        }

        Write-KubeNetSection -State $state -Name 'NodePort And Host Layer' -Description 'Checks NodePort/LoadBalancer node-level reachability and host reachability where applicable.'
        if ($SkipNodePort) {
            Add-KubeNetResult -State $state -Layer 'NodePort And Host Layer' -Check 'nodeport' -Status 'SKIP' -Message 'Skipped by -SkipNodePort.'
        } elseif (-not $service -or $service.spec.type -notin @('NodePort', 'LoadBalancer')) {
            Add-KubeNetResult -State $state -Layer 'NodePort And Host Layer' -Check 'nodeport' -Status 'SKIP' -Message 'Service type is not NodePort/LoadBalancer.'
        } else {
            try {
                $nodes = ConvertFrom-KubeNetJson -State $state -Context $targetContextEffective -Arguments @('get', 'nodes')
                $nodeIps = @()
                foreach ($node in @($nodes.items)) {
                    $nodeIps += @($node.status.addresses | Where-Object { $_.type -in @('ExternalIP', 'InternalIP') } | ForEach-Object { $_.address })
                }
                $nodePorts = @($service.spec.ports | Where-Object { $_.nodePort } | ForEach-Object { [int]$_.nodePort })
                foreach ($nodePort in $nodePorts) {
                    foreach ($nodeIp in ($nodeIps | Sort-Object -Unique)) {
                        $url = "$UrlScheme`://$nodeIp`:$nodePort$(Get-KubeNetUrlPath -UrlPath $UrlPath)"
                        if ($targetDebugReady) {
                            $inside = Invoke-KubeNetInPod -State $state -Context $targetContextEffective -Namespace $Namespace -PodName $TargetDebugPodName -Command "curl -k -sS -o /dev/null -w 'HTTP_STATUS=%{http_code}' --connect-timeout $TimeoutSec --max-time $TimeoutSec '$url'"
                            Add-KubeNetResult -State $state -Layer 'NodePort And Host Layer' -Check "$nodeIp`:$nodePort inside cluster" -Status $(if ($inside.ExitCode -eq 0) { 'PASS' } else { 'FAIL' }) -Message "$url inside-cluster status: $(Get-KubeNetHttpStatusFromText $inside.Text)"
                        }
                        $local = Test-KubeNetLocalHttp -Url $url -TimeoutSec $TimeoutSec
                        Add-KubeNetResult -State $state -Layer 'NodePort And Host Layer' -Check "$nodeIp`:$nodePort from host" -Status $(if ($local.Ok) { 'PASS' } else { 'FAIL' }) -Message "$url host reachability: $(if ($local.Ok) { "HTTP $($local.StatusCode)" } else { $local.Error })"
                    }
                }
            } catch {
                Add-KubeNetResult -State $state -Layer 'NodePort And Host Layer' -Check 'nodeport' -Status 'WARN' -Message "Could not complete NodePort checks: $($_.Exception.Message)"
            }
        }

        if ($TestEgress -and $sourceCanExec) {
            Write-KubeNetSection -State $state -Name 'Egress Layer' -Description 'Tests optional outbound URLs from the source pod when supplied, otherwise from the source debug pod.'
            if (-not $EgressUrls -or $EgressUrls.Count -eq 0) {
                Add-KubeNetResult -State $state -Layer 'Egress Layer' -Check 'egress targets' -Status 'SKIP' -Message 'No -EgressUrls were supplied.'
            }
            foreach ($target in $EgressUrls) {
                $curl = Invoke-KubeNetInPod -State $state -Context $sourceContextEffective -Namespace $sourceNamespaceEffective -PodName $sourceExecPodName -Container $sourceExecContainer -Command "curl -k -sS -o /dev/null -w 'HTTP_STATUS=%{http_code}' --connect-timeout $TimeoutSec --max-time $TimeoutSec '$target'"
                if ($curl.ExitCode -eq 0) {
                    Add-KubeNetResult -State $state -Layer 'Egress Layer' -Check $target -Status 'PASS' -Message "Source path using pod '$sourceExecPodName' reached '$target'. HTTP status: $(Get-KubeNetHttpStatusFromText $curl.Text)"
                } else {
                    Add-KubeNetResult -State $state -Layer 'Egress Layer' -Check $target -Status 'FAIL' -Message "Source path using pod '$sourceExecPodName' could not reach optional egress target '$target'. This may be unrelated to the target service path."
                    Add-KubeNetDiagnosis -State $state -Message "Optional egress test to '$target' failed from source path using pod '$sourceExecPodName'. This may be unrelated to target service reachability; check egress policy, DNS, firewall, NAT gateway, proxy, or cloud security controls if that outbound target is required."
                }
            }
        }

        if ($TestIngress) {
            Write-KubeNetSection -State $state -Name 'Ingress Reachability Layer' -Description 'Tests explicit ingress URLs from the local host.'
            if ($IngressUrls.Count -eq 0) {
                Add-KubeNetResult -State $state -Layer 'Ingress Reachability Layer' -Check 'ingress urls' -Status 'SKIP' -Message 'No -IngressUrls were supplied.'
            } else {
                foreach ($url in $IngressUrls) {
                    $test = Test-KubeNetLocalHttp -Url $url -TimeoutSec $TimeoutSec
                    Add-KubeNetResult -State $state -Layer 'Ingress Reachability Layer' -Check $url -Status $(if ($test.Ok) { 'PASS' } else { 'FAIL' }) -Message "$(if ($test.Ok) { "Reachable. HTTP status: $($test.StatusCode)" } else { "Failed: $($test.Error)" })"
                }
            }
        }

        if ($TestLoadBalancer -or $ExternalUrls.Count -gt 0) {
            Write-KubeNetSection -State $state -Name 'External Load Balancing Layer' -Description 'Tests explicit external addresses from the local host.'
            $targetsToTest = @($ExternalUrls)
            if ($service -and $service.spec.type -eq 'LoadBalancer') {
                foreach ($address in @($service.status.loadBalancer.ingress | ForEach-Object { if ($_.ip) { $_.ip } elseif ($_.hostname) { $_.hostname } })) {
                    foreach ($port in @($service.spec.ports | ForEach-Object { $_.port })) {
                        $targetsToTest += "$UrlScheme`://$address`:$port$(Get-KubeNetUrlPath -UrlPath $UrlPath)"
                    }
                }
            }
            if ($targetsToTest.Count -eq 0) {
                Add-KubeNetResult -State $state -Layer 'External Load Balancing Layer' -Check 'external targets' -Status 'SKIP' -Message 'No external load-balancer/ingress targets were available to test.'
            } else {
                foreach ($url in ($targetsToTest | Sort-Object -Unique)) {
                    $test = Test-KubeNetLocalHttp -Url $url -TimeoutSec $TimeoutSec
                    Add-KubeNetResult -State $state -Layer 'External Load Balancing Layer' -Check $url -Status $(if ($test.Ok) { 'PASS' } else { 'FAIL' }) -Message "$(if ($test.Ok) { "Reachable. HTTP status: $($test.StatusCode)" } else { "Failed: $($test.Error)" })"
                }
            }
        }

        if ($TestPortForward) {
            Write-KubeNetSection -State $state -Name 'Port-Forward Layer' -Description 'Validates whether kubectl port-forward can reach the target service from the local host.'
            if (-not $service) {
                Add-KubeNetResult -State $state -Layer 'Port-Forward Layer' -Check 'port-forward' -Status 'SKIP' -Message 'Skipped because the service does not exist.'
            } else {
                $pfServicePort = Get-KubeNetServicePort -Service $service -ServicePort $ServicePort
                $localPort = Get-Random -Minimum 20000 -Maximum 45000
                $pfOut = [System.IO.Path]::GetTempFileName()
                $pfErr = [System.IO.Path]::GetTempFileName()
                $process = $null
                try {
                    $args = @()
                    if (-not [string]::IsNullOrWhiteSpace($targetContextEffective)) { $args += @('--context', $targetContextEffective) }
                    $args += @('port-forward', '-n', $Namespace, "svc/$ServiceName", "$localPort`:$pfServicePort")
                    $startParams = @{
                        FilePath               = $state.KubeCommand
                        ArgumentList           = $args
                        RedirectStandardOutput = $pfOut
                        RedirectStandardError  = $pfErr
                        PassThru               = $true
                    }
                    if ($IsWindows -or $PSVersionTable.PSEdition -eq 'Desktop') { $startParams.WindowStyle = 'Hidden' }
                    $process = Start-Process @startParams
                    Start-Sleep -Seconds 2
                    $url = "$UrlScheme`://127.0.0.1`:$localPort$(Get-KubeNetUrlPath -UrlPath $UrlPath)"
                    $pf = Test-KubeNetLocalHttp -Url $url -TimeoutSec $TimeoutSec
                    Add-KubeNetResult -State $state -Layer 'Port-Forward Layer' -Check 'port-forward' -Status $(if ($pf.Ok) { 'PASS' } else { 'FAIL' }) -Message "$(if ($pf.Ok) { "Port-forward worked on localhost:$localPort. HTTP status: $($pf.StatusCode)" } else { "Port-forward started but localhost test failed: $($pf.Error)" })"
                } catch {
                    Add-KubeNetResult -State $state -Layer 'Port-Forward Layer' -Check 'port-forward' -Status 'FAIL' -Message "Port-forward check failed: $($_.Exception.Message)"
                } finally {
                    if ($process -and -not $process.HasExited) { Stop-Process -Id $process.Id -Force -ErrorAction SilentlyContinue }
                    Remove-Item -LiteralPath $pfOut, $pfErr -Force -ErrorAction SilentlyContinue
                }
            }
        }

        if (-not $sourceIsTarget -and -not [string]::IsNullOrWhiteSpace($sourceContextEffective) -and $sourceContextEffective -ne $targetContextEffective) {
            Add-KubeNetResult -State $state -Layer 'Cross-Cluster Layer' -Check 'context boundary' -Status 'INFO' -Message "Source context '$sourceContextEffective' differs from target context '$targetContextEffective'. Kubernetes service DNS and ClusterIP are cluster-local; use Ingress, LoadBalancer, mesh, VPN, peering, or explicit external targets for true cross-cluster validation."
        }

        Write-KubeNetSection -State $state -Name 'Events Layer' -Description 'Surfaces recent warning events in target and source namespaces.'
        foreach ($eventScope in @(
            [PSCustomObject]@{ Role = 'target'; Namespace = $Namespace; Context = $targetContextEffective },
            [PSCustomObject]@{ Role = 'source'; Namespace = $sourceNamespaceEffective; Context = $sourceContextEffective }
        ) | Where-Object { $_.Role -eq 'target' -or -not $sourceIsTarget }) {
            try {
                $events = ConvertFrom-KubeNetJson -State $state -Context $eventScope.Context -Arguments @('get', 'events', '-n', $eventScope.Namespace)
                $warnings = @($events.items | Where-Object { $_.type -eq 'Warning' } | Select-Object -Last 8)
                if ($warnings.Count -eq 0) {
                    Add-KubeNetResult -State $state -Layer 'Events Layer' -Check "$($eventScope.Role) warnings" -Status 'PASS' -Message "No recent Warning events found in namespace '$($eventScope.Namespace)'."
                } else {
                    $summary = (@($warnings | ForEach-Object { "$($_.involvedObject.kind)/$($_.involvedObject.name):$($_.reason)" }) -join '; ')
                    Add-KubeNetResult -State $state -Layer 'Events Layer' -Check "$($eventScope.Role) warnings" -Status 'WARN' -Message "Recent Warning events in '$($eventScope.Namespace)': $summary"
                }
            } catch {
                Add-KubeNetResult -State $state -Layer 'Events Layer' -Check "$($eventScope.Role) warnings" -Status 'WARN' -Message "Could not inspect events in '$($eventScope.Namespace)': $($_.Exception.Message)"
            }
        }
    } finally {
        Remove-KubeNetDebugPods -State $state
    }

    $allResults = @($state.Results)
    $failures = @($allResults | Where-Object { $_.Status -eq 'FAIL' })
    $warnings = @($allResults | Where-Object { $_.Status -eq 'WARN' })
    $summary = @($allResults | Group-Object Status | Sort-Object Name | ForEach-Object { [PSCustomObject]@{ Status = $_.Name; Count = $_.Count } })
    $exitCode = if ($failures.Count -gt 0) { 1 } else { 0 }

    $finalDiagnoses = @(Get-KubeNetFinalDiagnoses -Diagnoses @($state.Diagnoses) -Results $allResults)

    $report = [PSCustomObject]@{
        Target = [PSCustomObject]@{
            Namespace       = $Namespace
            Service         = $ServiceName
            Deployment      = $effectiveDeploymentName
            ServicePort     = $ServicePort
            UrlScheme       = $UrlScheme
            UrlPath         = $UrlPath
            SourceNamespace = $sourceNamespaceEffective
            TargetContext   = $targetContextEffective
            SourceContext   = $sourceContextEffective
            KubeCommand     = $state.KubeCommand
            DebugImage      = $DebugImage
            DebugImagePullPolicy = $DebugImagePullPolicy
            TargetDebugPodName = $TargetDebugPodName
            SourceDebugPodName = $SourceDebugPodName
            Timestamp       = (Get-Date).ToString('o')
        }
        Diagnoses      = $finalDiagnoses
        StatusSummary  = $summary
        Failures       = @($failures | Select-Object Layer, Check, Status, Message, Data)
        Warnings       = @($warnings | Select-Object Layer, Check, Status, Message, Data)
        RawResults     = $allResults
        ExitCode       = $exitCode
    }

    if (-not $Quiet) {
        Write-KubeNetSection -State $state -Name 'Summary'
        foreach ($item in $summary) { Write-Host "$($item.Status): $($item.Count)" }
        Write-KubeNetSection -State $state -Name 'Diagnosis'
        if ($finalDiagnoses.Count -eq 0) {
            Write-Host 'No dominant diagnosis inferred.' -ForegroundColor Green
        } else {
            foreach ($diagnosis in $finalDiagnoses) { Write-Host " - $diagnosis" -ForegroundColor Yellow }
        }
    }

    if (-not [string]::IsNullOrWhiteSpace($ExportJson)) {
        $report | ConvertTo-Json -Depth 30 | Set-Content -LiteralPath $ExportJson -Encoding UTF8
        if (-not $Quiet) { Write-Host "JSON report written to $ExportJson" -ForegroundColor Green }
    }
    if (-not [string]::IsNullOrWhiteSpace($ExportHtml)) {
        Export-KubeNetHtml -Report $report -Path $ExportHtml
        if (-not $Quiet) { Write-Host "HTML report written to $ExportHtml" -ForegroundColor Green }
    }

    if ($PassThru) { return $report }
    if ($exitCode -ne 0) { $global:LASTEXITCODE = $exitCode }
}
