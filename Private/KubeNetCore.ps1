function New-KubeNetState {
    [CmdletBinding()]
    param(
        [string]$KubeCommand = 'kubectl',
        [string]$TargetContext = '',
        [string]$SourceContext = '',
        [switch]$Quiet
    )

    [PSCustomObject]@{
        KubeCommand   = $KubeCommand
        TargetContext = $TargetContext
        SourceContext = if ([string]::IsNullOrWhiteSpace($SourceContext)) { $TargetContext } else { $SourceContext }
        Quiet         = [bool]$Quiet
        Results       = [System.Collections.Generic.List[object]]::new()
        Diagnoses     = [System.Collections.Generic.List[string]]::new()
        DebugPods     = [System.Collections.Generic.List[object]]::new()
    }
}

function Write-KubeNetStatus {
    param(
        [object]$State,
        [string]$Status,
        [string]$Message
    )

    if ($State.Quiet) { return }

    $color = switch ($Status) {
        'PASS' { 'Green' }
        'FAIL' { 'Red' }
        'WARN' { 'Yellow' }
        'SKIP' { 'DarkYellow' }
        default { 'Gray' }
    }

    Write-Host ("[{0}] " -f $Status) -ForegroundColor $color -NoNewline
    Write-Host $Message
}

function Write-KubeNetSection {
    param([object]$State, [string]$Name, [string]$Description = '')
    if ($State.Quiet) { return }
    Write-Host ''
    Write-Host "== $Name ==" -ForegroundColor Cyan
    if (-not [string]::IsNullOrWhiteSpace($Description)) {
        Write-Host "   $Description" -ForegroundColor DarkGray
    }
}

function Add-KubeNetResult {
    param(
        [object]$State,
        [string]$Layer,
        [string]$Check,
        [ValidateSet('PASS', 'FAIL', 'WARN', 'SKIP', 'INFO')]
        [string]$Status,
        [string]$Message,
        [object]$Data = $null
    )

    $State.Results.Add([PSCustomObject]@{
        Layer     = $Layer
        Check     = $Check
        Status    = $Status
        Message   = $Message
        Timestamp = (Get-Date).ToString('o')
        Data      = $Data
    }) | Out-Null

    Write-KubeNetStatus -State $State -Status $Status -Message $Message
}

function Add-KubeNetDiagnosis {
    param([object]$State, [string]$Message)
    if ([string]::IsNullOrWhiteSpace($Message)) { return }
    if (-not $State.Diagnoses.Contains($Message)) {
        $State.Diagnoses.Add($Message) | Out-Null
    }
}

function Get-KubeNetFinalDiagnoses {
    param(
        [string[]]$Diagnoses,
        [object[]]$Results = @(),
        [ValidateSet('Service', 'Egress', 'Ingress')]
        [string]$Mode = 'Service'
    )

    $items = @($Diagnoses | Where-Object { -not [string]::IsNullOrWhiteSpace($_) })
    if ($items.Count -eq 0) { return @() }

    if ($Mode -eq 'Egress') {
        $hasExternalDnsFailure = @($items | Where-Object { $_ -match '^External DNS resolution failed' }).Count -gt 0
        $hasExternalEgressFailure = @($items | Where-Object { $_ -match '^External egress to' }).Count -gt 0
        $filtered = foreach ($item in $items) {
            if ($hasExternalDnsFailure -and $item -match '^External egress to') { continue }
            $item
        }
        return @($filtered | Select-Object -Unique)
    }

    if ($Mode -eq 'Ingress') {
        $hasIngressConfigRoot = @($items | Where-Object { $_ -match '^Ingress .*points at service|^Ingress .*references missing|^Ingress references class' }).Count -gt 0
        $hasIngressRuntimeRoot = @($items | Where-Object { $_ -match '^Ingress URL ' }).Count -gt 0
        $filtered = foreach ($item in $items) {
            if ($hasIngressConfigRoot -and $item -match '^Ingress URL ') { continue }
            if ($hasIngressConfigRoot -and $item -match '^External target ') { continue }
            if ($hasIngressRuntimeRoot -and $item -match '^External target ') { continue }
            $item
        }
        return @($filtered | Select-Object -Unique)
    }

    $runtimeFailures = @($Results | Where-Object {
        $_.Status -eq 'FAIL' -and $_.Layer -in @(
            'Target debug pod path',
            'Pod-to-Pod Connectivity Layer',
            'Source pod path',
            'NodePort And Host Layer',
            'Egress Layer',
            'Ingress Reachability Layer',
            'External Load Balancing Layer',
            'Port-Forward Layer'
        )
    })
    $configFailures = @($Results | Where-Object {
        $_.Status -eq 'FAIL' -and $_.Layer -in @(
            'Cluster Access',
            'Deployment Layer',
            'Service Layer',
            'Pod Health Layer',
            'EndpointSlice Layer',
            'Ingress Layer',
            'Cloud LoadBalancer'
        )
    })
    $hasProvenFailure = ($runtimeFailures.Count -gt 0 -or $configFailures.Count -gt 0)
    $hasDnsPolicyRoot = @($items | Where-Object { $_ -match 'runtime resolver|NodeLocalDNS/link-local' }).Count -gt 0
    $hasTargetPortRoot = @($items | Where-Object { $_ -match 'Service targetPort .*does not match|service targetPort and pod port naming' }).Count -gt 0
    $hasPrimaryTargetPortRoot = @($items | Where-Object { $_ -match '^Primary issue: .*targetPort' }).Count -gt 0
    $hasNamedTargetPortRoot = @($items | Where-Object { $_ -match "uses named targetPort" }).Count -gt 0
    $hasExplicitCniDenyRoot = @($items | Where-Object { $_ -match 'explicit (Deny|deny) policy appears to block|Calico policy denies|Calico first matching action is Deny' }).Count -gt 0
    $hasCniDefaultDenyRoot = @($items | Where-Object { $_ -match 'Cilium .*default-deny|Calico .*default-deny|CNI .*default-deny' }).Count -gt 0
    $hasSpecificPathPolicyRoot = @($items | Where-Object { $_ -match 'source egress NetworkPolicy may block traffic|target ingress NetworkPolicy may block traffic' }).Count -gt 0
    $hasMissingEndpointsRoot = @($items | Where-Object { $_ -match 'no ready endpoints|service has no ready endpoints' }).Count -gt 0
    $hasSelectorRoot = @($items | Where-Object { $_ -match 'No pods matched the selector' }).Count -gt 0
    $hasActionableRoot = @($items | Where-Object {
        $_ -notmatch 'may not enforce them' -and
        $_ -notmatch 'NetworkPolicy selects the target pods'
    }).Count -gt 0

    $filtered = foreach ($item in $items) {
        if (-not $hasProvenFailure -and $item -match 'Likely issue: .*NetworkPolicy may block traffic') { continue }
        if (-not $hasProvenFailure -and $item -match 'Likely issue: .*default-deny') { continue }
        if (-not $hasProvenFailure -and $item -match 'NetworkPolicy selects the target pods') { continue }
        if (-not $hasProvenFailure -and $item -match 'may not enforce them') { continue }
        if ($hasActionableRoot -and $item -match 'may not enforce them') { continue }
        if ($hasSelectorRoot -and $item -match 'service has no ready endpoints|no ready endpoints') { continue }
        if ($hasDnsPolicyRoot -and $item -match 'source egress NetworkPolicy may block traffic') { continue }
        if ($hasDnsPolicyRoot -and $item -match 'cannot resolve target service FQDN') { continue }
        if ($hasDnsPolicyRoot -and $item -match 'Source-to-target service connection failed') { continue }
        if ($hasDnsPolicyRoot -and $item -match 'may not enforce them') { continue }
        if ($hasExplicitCniDenyRoot -and $item -match 'Direct pod IP connectivity failed') { continue }
        if ($hasExplicitCniDenyRoot -and $item -match 'cannot resolve target service FQDN') { continue }
        if ($hasExplicitCniDenyRoot -and $item -match "cannot reach optional egress target") { continue }
        if ($hasExplicitCniDenyRoot -and $item -match 'Source-to-target service connection failed') { continue }
        if ($hasExplicitCniDenyRoot -and $item -match 'Source-to-target connection failed') { continue }
        if ($hasExplicitCniDenyRoot -and $item -match 'Egress test to') { continue }
        if ($hasCniDefaultDenyRoot -and $item -match 'Direct pod IP connectivity failed') { continue }
        if ($hasCniDefaultDenyRoot -and $item -match 'cannot resolve target service FQDN') { continue }
        if ($hasCniDefaultDenyRoot -and $item -match "cannot reach optional egress target") { continue }
        if ($hasCniDefaultDenyRoot -and $item -match 'Source-to-target service connection failed') { continue }
        if ($hasCniDefaultDenyRoot -and $item -match 'Egress test to') { continue }
        if ($hasTargetPortRoot -and $item -match 'NetworkPolicy may block traffic') { continue }
        if ($hasPrimaryTargetPortRoot -and $item -match 'EndpointSlice addresses exist') { continue }
        if ($hasNamedTargetPortRoot -and $item -match 'target pods are reachable directly') { continue }
        if ($hasTargetPortRoot -and $item -match 'Source-to-target service connection failed') { continue }
        if ($hasSpecificPathPolicyRoot -and $item -match 'NetworkPolicy selects the target pods') { continue }
        if ($hasMissingEndpointsRoot -and $item -match 'Source-to-target connection failed') { continue }
        $item
    }

    @($filtered | Select-Object -Unique)
}

function Resolve-KubeNetCommand {
    param([string]$KubeCommand)
    $command = Get-Command $KubeCommand -ErrorAction SilentlyContinue
    if (-not $command) {
        throw "Could not find kubectl command '$KubeCommand'."
    }
    $command.Source
}

function Invoke-KubeNetKubectl {
    param(
        [object]$State,
        [string[]]$Arguments,
        [string]$Context = '',
        [switch]$AllowFailure
    )

    $fullArgs = @()
    if (-not [string]::IsNullOrWhiteSpace($Context)) {
        $fullArgs += @('--context', $Context)
    }
    $fullArgs += $Arguments

    Write-Verbose ("{0} {1}" -f $State.KubeCommand, ($fullArgs -join ' '))

    $stderrFile = [System.IO.Path]::GetTempFileName()
    $previousPreference = $ErrorActionPreference
    try {
        $ErrorActionPreference = 'Continue'
        $output = & $State.KubeCommand @fullArgs 2> $stderrFile
        $exitCode = $LASTEXITCODE
        $ErrorActionPreference = $previousPreference

        $stderr = ''
        if (Test-Path -LiteralPath $stderrFile) {
            $raw = Get-Content -LiteralPath $stderrFile -Raw -ErrorAction SilentlyContinue
            if ($null -ne $raw) { $stderr = $raw.Trim() }
        }
    } finally {
        $ErrorActionPreference = $previousPreference
        Remove-Item -LiteralPath $stderrFile -Force -ErrorAction SilentlyContinue
    }

    $text = (($output | Out-String).Trim())
    if ($exitCode -ne 0 -and -not $AllowFailure) {
        $message = @($text, $stderr) | Where-Object { -not [string]::IsNullOrWhiteSpace($_) }
        throw ($message -join "`n")
    }

    [PSCustomObject]@{
        ExitCode = $exitCode
        Output   = $output
        Text     = (@($text, $stderr) | Where-Object { -not [string]::IsNullOrWhiteSpace($_) }) -join "`n"
        StdErr   = $stderr
        Args     = $fullArgs
    }
}

function ConvertFrom-KubeNetJson {
    param(
        [object]$State,
        [string[]]$Arguments,
        [string]$Context = ''
    )

    $result = Invoke-KubeNetKubectl -State $State -Arguments ($Arguments + @('-o', 'json')) -Context $Context
    if ([string]::IsNullOrWhiteSpace($result.Text)) { return $null }
    $result.Text | ConvertFrom-Json
}

function Join-KubeNetSelector {
    param([object]$Selector)
    if ($null -eq $Selector) { return '' }
    $parts = @()
    foreach ($property in $Selector.PSObject.Properties) {
        if (-not [string]::IsNullOrWhiteSpace([string]$property.Value)) {
            $parts += "$($property.Name)=$($property.Value)"
        }
    }
    $parts -join ','
}

function Test-KubeNetLocalHttp {
    param([string]$Url, [int]$TimeoutSec)
    try {
        $response = Invoke-WebRequest -Uri $Url -UseBasicParsing -TimeoutSec $TimeoutSec -MaximumRedirection 0 -ErrorAction Stop
        [PSCustomObject]@{ Ok = $true; StatusCode = [int]$response.StatusCode; Error = '' }
    } catch {
        $status = $null
        if ($_.Exception.Response -and $_.Exception.Response.StatusCode) {
            $status = [int]$_.Exception.Response.StatusCode
        }
        if ($status -and $status -lt 500) {
            [PSCustomObject]@{ Ok = $true; StatusCode = $status; Error = $_.Exception.Message }
        } else {
            [PSCustomObject]@{ Ok = $false; StatusCode = $status; Error = $_.Exception.Message }
        }
    }
}

function Get-KubeNetHttpStatusFromText {
    param([string]$Text)
    $match = [regex]::Match($Text, 'HTTP_STATUS=(\d{3})')
    if ($match.Success) { return $match.Groups[1].Value }
    'unknown'
}

function Get-KubeNetUrlPath {
    param([string]$UrlPath)
    if ([string]::IsNullOrWhiteSpace($UrlPath)) { return '/' }
    if ($UrlPath.StartsWith('/')) { return $UrlPath }
    "/$UrlPath"
}

function Get-KubeNetServicePort {
    param([object]$Service, [int]$ServicePort)
    if ($ServicePort -gt 0) { return $ServicePort }
    if ($Service -and $Service.spec.ports.Count -gt 0) {
        return [int]$Service.spec.ports[0].port
    }
    80
}

function Get-KubeNetServicePortObject {
    param([object]$Service, [int]$ServicePort)
    if (-not $Service -or $Service.spec.ports.Count -eq 0) { return $null }
    $ports = @($Service.spec.ports)
    if ($ServicePort -gt 0) {
        $match = $ports | Where-Object { [int]$_.port -eq $ServicePort } | Select-Object -First 1
        if ($match) { return $match }
    }
    $ports | Select-Object -First 1
}

function New-KubeNetServiceUrls {
    param(
        [object]$Service,
        [string]$ServiceName,
        [string]$Namespace,
        [int]$ServicePort,
        [string]$UrlScheme,
        [string]$UrlPath
    )

    $port = Get-KubeNetServicePort -Service $Service -ServicePort $ServicePort
    $urlPath = Get-KubeNetUrlPath -UrlPath $UrlPath
    $fqdn = "$ServiceName.$Namespace.svc.cluster.local"
    $clusterIp = $Service.spec.clusterIP

    [PSCustomObject]@{
        Port      = $port
        ShortName = "$UrlScheme`://$ServiceName`:$port$urlPath"
        Fqdn      = "$UrlScheme`://$fqdn`:$port$urlPath"
        ClusterIp = if ($clusterIp -and $clusterIp -ne 'None') { "$UrlScheme`://$clusterIp`:$port$urlPath" } else { '' }
    }
}

function Ensure-KubeNetDebugPod {
    param(
        [object]$State,
        [string]$Namespace,
        [string]$Context,
        [string]$Name,
        [string]$Image,
        [string]$ImagePullPolicy,
        [int]$TimeoutSec,
        [string]$Layer = 'Debug Pod'
    )

    Invoke-KubeNetKubectl -State $State -Context $Context -Arguments @('delete', 'pod', $Name, '-n', $Namespace, '--ignore-not-found=true', '--wait=true') -AllowFailure | Out-Null
    $run = Invoke-KubeNetKubectl -State $State -Context $Context -Arguments @(
        'run', $Name,
        '-n', $Namespace,
        "--image=$Image",
        "--image-pull-policy=$ImagePullPolicy",
        '--restart=Never',
        '--command',
        '--', 'sleep', '3600'
    ) -AllowFailure

    if ($run.ExitCode -ne 0) {
        Add-KubeNetResult -State $State -Layer $Layer -Check 'create debug pod' -Status 'FAIL' -Message "Could not create debug pod '$Name' in namespace '$Namespace'. Check RBAC, image policy, or image pull access." -Data $run.Text
        Add-KubeNetDiagnosis -State $State -Message "Debug pod creation failed in namespace '$Namespace'. Active DNS/curl checks from that namespace cannot run until RBAC or image access is fixed."
        return $false
    }

    $State.DebugPods.Add([PSCustomObject]@{ Namespace = $Namespace; Context = $Context; Name = $Name }) | Out-Null

    $readyTimeoutSec = [Math]::Max($TimeoutSec, 30)
    $wait = Invoke-KubeNetKubectl -State $State -Context $Context -Arguments @(
        'wait', "pod/$Name",
        '-n', $Namespace,
        '--for=condition=Ready',
        "--timeout=$readyTimeoutSec`s"
    ) -AllowFailure

    if ($wait.ExitCode -ne 0) {
        Add-KubeNetResult -State $State -Layer $Layer -Check 'debug pod ready' -Status 'FAIL' -Message "Debug pod '$Name' was created but did not become Ready." -Data $wait.Text
        Add-KubeNetDiagnosis -State $State -Message "Debug pod '$Name' did not become Ready. Check image pull, scheduling, admission policy, or namespace restrictions."
        return $false
    }

    Add-KubeNetResult -State $State -Layer $Layer -Check 'debug pod ready' -Status 'PASS' -Message "Debug pod '$Name' is Ready in namespace '$Namespace'."
    $true
}

function Invoke-KubeNetInPod {
    param(
        [object]$State,
        [string]$Namespace,
        [string]$Context,
        [string]$PodName,
        [string]$Container = '',
        [string]$Command
    )

    $args = @('exec', '-n', $Namespace, $PodName)
    if (-not [string]::IsNullOrWhiteSpace($Container)) { $args += @('-c', $Container) }
    $args += @('--', 'sh', '-c', $Command)
    Invoke-KubeNetKubectl -State $State -Context $Context -Arguments $args -AllowFailure
}

function Remove-KubeNetDebugPods {
    param([object]$State)
    foreach ($pod in @($State.DebugPods)) {
        Invoke-KubeNetKubectl -State $State -Context $pod.Context -Arguments @('delete', 'pod', $pod.Name, '-n', $pod.Namespace, '--ignore-not-found=true', '--wait=false') -AllowFailure | Out-Null
    }
}

function Get-KubeNetSelectedPods {
    param(
        [object]$State,
        [string]$Context,
        [string]$Namespace,
        [object]$Service,
        [string]$DeploymentName,
        [string]$ServiceName,
        [string]$TargetPodSelector
    )

    $selector = $TargetPodSelector
    if ([string]::IsNullOrWhiteSpace($selector) -and $Service -and $Service.spec.selector) {
        $selector = Join-KubeNetSelector -Selector $Service.spec.selector
    }

    if ([string]::IsNullOrWhiteSpace($selector) -and -not [string]::IsNullOrWhiteSpace($DeploymentName)) {
        $deployment = ConvertFrom-KubeNetJson -State $State -Context $Context -Arguments @('get', 'deployment', $DeploymentName, '-n', $Namespace)
        if ($deployment -and $deployment.spec.selector.matchLabels) {
            $selector = Join-KubeNetSelector -Selector $deployment.spec.selector.matchLabels
        }
    }

    if ([string]::IsNullOrWhiteSpace($selector) -and -not [string]::IsNullOrWhiteSpace($ServiceName)) {
        $deployment = Invoke-KubeNetKubectl -State $State -Context $Context -Arguments @('get', 'deployment', $ServiceName, '-n', $Namespace, '-o', 'json') -AllowFailure
        if ($deployment.ExitCode -eq 0 -and -not [string]::IsNullOrWhiteSpace($deployment.Text)) {
            $deploymentObj = $deployment.Text | ConvertFrom-Json
            if ($deploymentObj.spec.selector.matchLabels) {
                $selector = Join-KubeNetSelector -Selector $deploymentObj.spec.selector.matchLabels
            }
        }
    }

    if ([string]::IsNullOrWhiteSpace($selector)) {
        return [PSCustomObject]@{ Selector = ''; Pods = $null }
    }

    $pods = ConvertFrom-KubeNetJson -State $State -Context $Context -Arguments @('get', 'pods', '-n', $Namespace, '-l', $selector)
    [PSCustomObject]@{ Selector = $selector; Pods = $pods }
}

function Get-KubeNetPodReady {
    param([object]$Pod)
    $ready = @($Pod.status.conditions | Where-Object { $_.type -eq 'Ready' } | Select-Object -First 1)
    ($ready.Count -gt 0 -and $ready[0].status -eq 'True')
}

function Get-KubeNetPodProblemStates {
    param([object[]]$Pods)
    $problems = @()
    foreach ($pod in @($Pods)) {
        foreach ($containerStatus in @($pod.status.containerStatuses)) {
            if ($containerStatus.state.waiting) {
                $problems += "$($pod.metadata.name):$($containerStatus.name)=$($containerStatus.state.waiting.reason)"
            }
            if ($containerStatus.state.terminated) {
                $problems += "$($pod.metadata.name):$($containerStatus.name)=$($containerStatus.state.terminated.reason)"
            }
            if ($containerStatus.lastState.terminated) {
                $problems += "$($pod.metadata.name):$($containerStatus.name)=last:$($containerStatus.lastState.terminated.reason)"
            }
        }
    }
    $problems
}

function Get-KubeNetContainerPorts {
    param([object[]]$Pods)
    $ports = @()
    foreach ($pod in @($Pods)) {
        foreach ($container in @($pod.spec.containers)) {
            foreach ($port in @($container.ports)) {
                if ($null -ne $port.containerPort) {
                    $ports += [PSCustomObject]@{
                        Pod           = $pod.metadata.name
                        Container     = $container.name
                        ContainerPort = [int]$port.containerPort
                        Name          = [string]$port.name
                        Protocol      = if ($port.protocol) { [string]$port.protocol } else { 'TCP' }
                    }
                }
            }
        }
    }
    $ports
}

function Test-KubeNetTargetPortMetadata {
    param([object]$ServicePortObject, [object[]]$ContainerPorts)
    if (-not $ServicePortObject) {
        return [PSCustomObject]@{ Status = 'Unknown'; Message = 'No service port selected.' }
    }
    if (-not $ContainerPorts -or @($ContainerPorts).Count -eq 0) {
        return [PSCustomObject]@{ Status = 'NoDeclaredPorts'; Message = 'Selected pods do not declare container ports. Kubernetes allows this, but targetPort metadata cannot be compared.' }
    }

    $target = $ServicePortObject.targetPort
    if ($null -eq $target) { $target = $ServicePortObject.port }
    $targetText = [string]$target
    $number = 0
    if ([int]::TryParse($targetText, [ref]$number)) {
        $matches = @($ContainerPorts | Where-Object { $_.ContainerPort -eq $number })
        if ($matches.Count -gt 0) {
            return [PSCustomObject]@{ Status = 'Match'; TargetPortKind = 'Numeric'; Message = "Service targetPort $number matches declared container port(s): $((@($matches | ForEach-Object { "$($_.Pod)/$($_.Container):$($_.ContainerPort)" }) | Sort-Object -Unique) -join ', ')" }
        }
        return [PSCustomObject]@{ Status = 'Mismatch'; TargetPortKind = 'Numeric'; Message = "Service targetPort $number does not match any declared container port. Declared ports: $((@($ContainerPorts | ForEach-Object { "$($_.Pod)/$($_.Container):$($_.ContainerPort)" }) | Sort-Object -Unique) -join ', ')" }
    }

    $nameMatches = @($ContainerPorts | Where-Object { $_.Name -eq $targetText })
    if ($nameMatches.Count -gt 0) {
        return [PSCustomObject]@{ Status = 'Match'; TargetPortKind = 'Named'; Message = "Service named targetPort '$targetText' resolves to declared container port(s): $((@($nameMatches | ForEach-Object { "$($_.Pod)/$($_.Container):$($_.Name)=$($_.ContainerPort)" }) | Sort-Object -Unique) -join ', ')" }
    }
    [PSCustomObject]@{ Status = 'Mismatch'; TargetPortKind = 'Named'; Message = "Service targetPort '$targetText' does not match any declared named container port." }
}

function Get-KubeNetResolvConfSummary {
    param([string]$Text)
    $nameservers = @()
    $searches = @()
    $options = @()
    foreach ($line in @($Text -split "`r?`n")) {
        $clean = ($line -replace '#.*$', '').Trim()
        if ([string]::IsNullOrWhiteSpace($clean)) { continue }
        if ($clean -match '^nameserver\s+(.+)$') {
            $nameservers += $Matches[1].Trim()
        } elseif ($clean -match '^search\s+(.+)$') {
            $searches += @($Matches[1].Trim() -split '\s+' | Where-Object { -not [string]::IsNullOrWhiteSpace($_) })
        } elseif ($clean -match '^options\s+(.+)$') {
            $options += @($Matches[1].Trim() -split '\s+' | Where-Object { -not [string]::IsNullOrWhiteSpace($_) })
        }
    }
    [PSCustomObject]@{ Nameservers = @($nameservers); Searches = @($searches); Options = @($options) }
}

function Get-KubeNetMtuSummary {
    param([string]$Text)

    $interfaces = @()
    foreach ($line in @($Text -split "`r?`n")) {
        if ($line -match '^\d+:\s+([^:@]+)(?:@[^:]+)?:.*\bmtu\s+(\d+)') {
            $interfaces += [PSCustomObject]@{
                Name = $Matches[1]
                Mtu  = [int]$Matches[2]
            }
        }
    }
    @($interfaces)
}

function Format-KubeNetRouteSummary {
    param([string]$Text)

    $lines = @($Text -split "`r?`n" | Where-Object { -not [string]::IsNullOrWhiteSpace($_) })
    if ($lines.Count -eq 0) { return '(no routes returned)' }
    (@($lines | Select-Object -First 5) -join '; ')
}

function Format-KubeNetList {
    param([object[]]$Items)
    if (-not $Items -or @($Items).Count -eq 0) { return '(none)' }
    (@($Items) -join ', ')
}

function Test-KubeNetSelectorMatchesPod {
    param([object]$Selector, [object]$Pod)
    if ($null -eq $Selector) { return $true }
    $matchLabels = $Selector.matchLabels
    if ($matchLabels) {
        foreach ($property in $matchLabels.PSObject.Properties) {
            $podValue = $Pod.metadata.labels.$($property.Name)
            if ([string]$podValue -ne [string]$property.Value) { return $false }
        }
    }
    if ($Selector.matchExpressions) {
        foreach ($expression in @($Selector.matchExpressions)) {
            $key = [string]$expression.key
            $operator = [string]$expression.operator
            $values = @($expression.values | ForEach-Object { [string]$_ })
            $hasKey = $null -ne $Pod.metadata.labels.$key
            $value = [string]$Pod.metadata.labels.$key
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

function Get-KubeNetPolicyTypes {
    param([object]$Policy)

    $types = @($Policy.spec.policyTypes | ForEach-Object { [string]$_ })
    if ($types.Count -eq 0) {
        $types += 'Ingress'
        if ($null -ne $Policy.spec.egress) { $types += 'Egress' }
    }
    @($types | Sort-Object -Unique)
}

function Get-KubeNetIpv4Number {
    param([string]$Address)

    $parsed = $null
    if (-not [System.Net.IPAddress]::TryParse($Address, [ref]$parsed)) { return $null }
    $bytes = $parsed.GetAddressBytes()
    if ($bytes.Count -ne 4) { return $null }
    [Array]::Reverse($bytes)
    [BitConverter]::ToUInt32($bytes, 0)
}

function Test-KubeNetIpv4InCidr {
    param([string]$Address, [string]$Cidr)

    if ([string]::IsNullOrWhiteSpace($Address) -or [string]::IsNullOrWhiteSpace($Cidr)) { return $false }
    $parts = $Cidr -split '/'
    if ($parts.Count -ne 2) { return $Address -eq $Cidr }

    $ipNumber = Get-KubeNetIpv4Number -Address $Address
    $networkNumber = Get-KubeNetIpv4Number -Address $parts[0]
    if ($null -eq $ipNumber -or $null -eq $networkNumber) { return $false }

    $prefix = 0
    if (-not [int]::TryParse($parts[1], [ref]$prefix)) { return $false }
    if ($prefix -lt 0 -or $prefix -gt 32) { return $false }
    if ($prefix -eq 0) { return $true }

    $mask = [uint32]::MaxValue -shl (32 - $prefix)
    (($ipNumber -band $mask) -eq ($networkNumber -band $mask))
}

function Test-KubeNetNetworkPolicyPortAllowsDns {
    param([object]$Rule)

    if ($null -eq $Rule.ports -or @($Rule.ports).Count -eq 0) {
        return $true
    }

    foreach ($port in @($Rule.ports)) {
        $protocol = if ($port.protocol) { [string]$port.protocol } else { 'TCP' }
        $portValue = [string]$port.port
        if ($portValue -eq '53' -and $protocol -in @('TCP', 'UDP')) {
            return $true
        }
        if ([string]::IsNullOrWhiteSpace($portValue) -and $protocol -in @('TCP', 'UDP')) {
            return $true
        }
    }
    $false
}

function Test-KubeNetNetworkPolicyPortAllowsConnection {
    param([object]$Rule, [int[]]$Ports)

    $portsToCheck = @($Ports | Where-Object { $_ -gt 0 } | Sort-Object -Unique)
    if ($null -eq $Rule.ports -or @($Rule.ports).Count -eq 0) {
        return $true
    }
    if ($portsToCheck.Count -eq 0) {
        return $true
    }

    foreach ($port in @($Rule.ports)) {
        $protocol = if ($port.protocol) { [string]$port.protocol } else { 'TCP' }
        if ($protocol -ne 'TCP') { continue }
        $portValue = [string]$port.port
        $number = 0
        if ([int]::TryParse($portValue, [ref]$number) -and ($portsToCheck -contains $number)) {
            return $true
        }
        if ([string]::IsNullOrWhiteSpace($portValue)) {
            return $true
        }
    }
    $false
}

function Test-KubeNetNetworkPolicyPeerMatchesPod {
    param([object]$Peer, [object]$TargetPod, [object]$TargetNamespace, [string]$PolicyNamespace)

    if ($null -eq $Peer) { return $false }
    if ($Peer.ipBlock) { return $false }

    $namespaceMatches = $true
    if ($Peer.namespaceSelector) {
        $namespaceMatches = Test-KubeNetSelectorMatchesPod -Selector $Peer.namespaceSelector -Pod $TargetNamespace
    } elseif ($TargetNamespace.metadata.name -ne $PolicyNamespace) {
        # A podSelector without namespaceSelector only applies in the policy's own namespace.
        $namespaceMatches = $false
    }

    if (-not $namespaceMatches) { return $false }
    if ($Peer.podSelector) {
        return (Test-KubeNetSelectorMatchesPod -Selector $Peer.podSelector -Pod $TargetPod)
    }

    $true
}

function Test-KubeNetIpMatchesPodAddress {
    param([string]$Address, [object]$Pod)

    if ([string]::IsNullOrWhiteSpace($Address) -or $null -eq $Pod) { return $false }

    $addresses = @()
    if ($Pod.status.podIP) { $addresses += [string]$Pod.status.podIP }
    if ($Pod.status.hostIP) { $addresses += [string]$Pod.status.hostIP }
    foreach ($podIp in @($Pod.status.podIPs)) {
        if ($podIp.ip) { $addresses += [string]$podIp.ip }
    }

    @($addresses | Sort-Object -Unique) -contains $Address
}

function Get-KubeNetConnectionPortCandidates {
    param([object]$ServicePortObject, [object[]]$ContainerPorts)

    $ports = @()
    if ($ServicePortObject) {
        if ($null -ne $ServicePortObject.port) { $ports += [int]$ServicePortObject.port }
        $targetPortText = [string]$ServicePortObject.targetPort
        if ([string]::IsNullOrWhiteSpace($targetPortText)) {
            $targetPortText = [string]$ServicePortObject.port
        }
        $targetPortNumber = 0
        if ([int]::TryParse($targetPortText, [ref]$targetPortNumber)) {
            $ports += $targetPortNumber
        } else {
            $ports += @($ContainerPorts | Where-Object { $_.Name -eq $targetPortText } | ForEach-Object { [int]$_.ContainerPort })
        }
    }

    @($ports | Where-Object { $_ -gt 0 } | Sort-Object -Unique)
}

function Get-KubeNetDirectPodPortCandidates {
    param([object]$ServicePortObject, [object[]]$ContainerPorts)

    $ports = @()
    $reason = ''
    $declaredTcpPorts = @($ContainerPorts | Where-Object { $_.Protocol -eq 'TCP' -and $_.ContainerPort -gt 0 })

    if ($ServicePortObject) {
        $targetPortText = [string]$ServicePortObject.targetPort
        if ([string]::IsNullOrWhiteSpace($targetPortText)) {
            $targetPortText = [string]$ServicePortObject.port
        }

        $targetPortNumber = 0
        if ([int]::TryParse($targetPortText, [ref]$targetPortNumber)) {
            $matchingDeclared = @($declaredTcpPorts | Where-Object { $_.ContainerPort -eq $targetPortNumber })
            if ($matchingDeclared.Count -gt 0) {
                $ports += $targetPortNumber
                $reason = "service targetPort $targetPortNumber matches declared container port"
            }
        } elseif (-not [string]::IsNullOrWhiteSpace($targetPortText)) {
            $namedMatches = @($declaredTcpPorts | Where-Object { $_.Name -eq $targetPortText })
            if ($namedMatches.Count -gt 0) {
                $ports += @($namedMatches | ForEach-Object { [int]$_.ContainerPort })
                $reason = "service named targetPort '$targetPortText' resolves to declared container port"
            }
        }
    }

    if ($ports.Count -eq 0 -and $declaredTcpPorts.Count -gt 0) {
        $ports += @($declaredTcpPorts | ForEach-Object { [int]$_.ContainerPort })
        $reason = 'declared TCP container port(s)'
    }

    if ($ports.Count -eq 0 -and $ServicePortObject) {
        $targetPortText = [string]$ServicePortObject.targetPort
        if ([string]::IsNullOrWhiteSpace($targetPortText)) {
            $targetPortText = [string]$ServicePortObject.port
        }
        $targetPortNumber = 0
        if ([int]::TryParse($targetPortText, [ref]$targetPortNumber)) {
            $ports += $targetPortNumber
            $reason = "numeric service targetPort $targetPortNumber"
        }
        if ($null -ne $ServicePortObject.port) {
            $ports += [int]$ServicePortObject.port
            if ([string]::IsNullOrWhiteSpace($reason)) { $reason = "service port $($ServicePortObject.port)" }
        }
    }

    [PSCustomObject]@{
        Ports  = @($ports | Where-Object { $_ -gt 0 } | Sort-Object -Unique)
        Reason = if ([string]::IsNullOrWhiteSpace($reason)) { 'no usable pod port candidate found' } else { $reason }
    }
}

function Test-KubeNetNetworkPolicyEgressAllowsTarget {
    param(
        [object]$Rule,
        [object[]]$TargetPods,
        [object]$TargetNamespace,
        [string]$PolicyNamespace,
        [string]$ServiceClusterIp,
        [int[]]$Ports
    )

    if (-not (Test-KubeNetNetworkPolicyPortAllowsConnection -Rule $Rule -Ports $Ports)) {
        return [PSCustomObject]@{ Allows = $false; Reason = "rule does not allow TCP port(s) $($Ports -join ', ')" }
    }

    if ($null -eq $Rule.to -or @($Rule.to).Count -eq 0) {
        return [PSCustomObject]@{ Allows = $true; Reason = 'egress rule allows selected port(s) to all destinations' }
    }

    foreach ($peer in @($Rule.to)) {
        if ($peer.ipBlock) {
            $cidr = [string]$peer.ipBlock.cidr
            if (-not [string]::IsNullOrWhiteSpace($ServiceClusterIp) -and (Test-KubeNetIpv4InCidr -Address $ServiceClusterIp -Cidr $cidr)) {
                return [PSCustomObject]@{ Allows = $true; Reason = "ipBlock $cidr includes service ClusterIP $ServiceClusterIp" }
            }
            foreach ($pod in @($TargetPods)) {
                if (Test-KubeNetIpMatchesPodAddress -Address ([string]$pod.status.podIP) -Pod $pod) {
                    if (Test-KubeNetIpv4InCidr -Address ([string]$pod.status.podIP) -Cidr $cidr) {
                        return [PSCustomObject]@{ Allows = $true; Reason = "ipBlock $cidr includes target pod IP $($pod.status.podIP)" }
                    }
                }
            }
        }

        foreach ($pod in @($TargetPods)) {
            if (Test-KubeNetNetworkPolicyPeerMatchesPod -Peer $peer -TargetPod $pod -TargetNamespace $TargetNamespace -PolicyNamespace $PolicyNamespace) {
                return [PSCustomObject]@{ Allows = $true; Reason = "peer selector matches target pod '$($pod.metadata.name)'" }
            }
        }
    }

    [PSCustomObject]@{ Allows = $false; Reason = 'no egress peer obviously matches the target service/pods' }
}

function Test-KubeNetNetworkPolicyIngressAllowsSource {
    param(
        [object]$Rule,
        [object]$SourcePod,
        [object]$SourceNamespace,
        [string]$PolicyNamespace,
        [int[]]$Ports
    )

    if (-not (Test-KubeNetNetworkPolicyPortAllowsConnection -Rule $Rule -Ports $Ports)) {
        return [PSCustomObject]@{ Allows = $false; Reason = "rule does not allow TCP port(s) $($Ports -join ', ')" }
    }

    if ($null -eq $Rule.from -or @($Rule.from).Count -eq 0) {
        return [PSCustomObject]@{ Allows = $true; Reason = 'ingress rule allows selected port(s) from all sources' }
    }

    foreach ($peer in @($Rule.from)) {
        if ($peer.ipBlock) {
            $cidr = [string]$peer.ipBlock.cidr
            if (Test-KubeNetIpv4InCidr -Address ([string]$SourcePod.status.podIP) -Cidr $cidr) {
                return [PSCustomObject]@{ Allows = $true; Reason = "ipBlock $cidr includes source pod IP $($SourcePod.status.podIP)" }
            }
        }

        if (Test-KubeNetNetworkPolicyPeerMatchesPod -Peer $peer -TargetPod $SourcePod -TargetNamespace $SourceNamespace -PolicyNamespace $PolicyNamespace) {
            return [PSCustomObject]@{ Allows = $true; Reason = "peer selector matches source pod '$($SourcePod.metadata.name)'" }
        }
    }

    [PSCustomObject]@{ Allows = $false; Reason = 'no ingress peer obviously matches the source pod' }
}

function Test-KubeNetNetworkPolicyPath {
    param(
        [object]$SourcePod,
        [object]$SourceNamespace,
        [object[]]$TargetPods,
        [object]$TargetNamespace,
        [object[]]$SourceNetworkPolicies,
        [object[]]$TargetNetworkPolicies,
        [object]$Service,
        [object]$ServicePortObject,
        [object[]]$ContainerPorts
    )

    if ($null -eq $SourcePod -or $null -eq $TargetNamespace -or $null -eq $SourceNamespace -or @($TargetPods).Count -eq 0) {
        return [PSCustomObject]@{
            Results = @([PSCustomObject]@{ Check = 'policy path'; Status = 'SKIP'; Message = 'Skipped policy path analysis because source pod, target pods, or namespace metadata was unavailable.' })
            Diagnoses = @()
        }
    }

    $ports = Get-KubeNetConnectionPortCandidates -ServicePortObject $ServicePortObject -ContainerPorts $ContainerPorts
    $serviceClusterIp = if ($Service -and $Service.spec.clusterIP -and $Service.spec.clusterIP -ne 'None') { [string]$Service.spec.clusterIP } else { '' }
    $results = @()
    $diagnoses = @()

    $sourceEgressPolicies = @($SourceNetworkPolicies | Where-Object {
        (Test-KubeNetSelectorMatchesPod -Selector $_.spec.podSelector -Pod $SourcePod) -and ((Get-KubeNetPolicyTypes -Policy $_) -contains 'Egress')
    })
    if ($sourceEgressPolicies.Count -eq 0) {
        $results += [PSCustomObject]@{ Check = 'source egress to target'; Status = 'PASS'; Message = "No egress NetworkPolicies select source pod '$($SourcePod.metadata.name)'." }
    } else {
        $allowedReasons = @()
        foreach ($policy in $sourceEgressPolicies) {
            foreach ($rule in @($policy.spec.egress)) {
                $allow = Test-KubeNetNetworkPolicyEgressAllowsTarget -Rule $rule -TargetPods $TargetPods -TargetNamespace $TargetNamespace -PolicyNamespace $SourcePod.metadata.namespace -ServiceClusterIp $serviceClusterIp -Ports $ports
                if ($allow.Allows) {
                    $allowedReasons += "$($policy.metadata.name): $($allow.Reason)"
                }
            }
        }
        $policyNames = (@($sourceEgressPolicies | ForEach-Object { $_.metadata.name }) -join ', ')
        if ($allowedReasons.Count -gt 0) {
            $results += [PSCustomObject]@{ Check = 'source egress to target'; Status = 'PASS'; Message = "Source egress policies selecting '$($SourcePod.metadata.name)' appear to allow the target path. $($allowedReasons -join '; ')" }
        } else {
            $results += [PSCustomObject]@{ Check = 'source egress to target'; Status = 'WARN'; Message = "Source pod '$($SourcePod.metadata.name)' is egress-isolated by NetworkPolicy ($policyNames), and no rule obviously allows target namespace '$($TargetNamespace.metadata.name)' on TCP port(s) $($ports -join ', ')." }
            $diagnoses += "Likely issue: source egress NetworkPolicy may block traffic from '$($SourcePod.metadata.namespace)/$($SourcePod.metadata.name)' to service '$($TargetNamespace.metadata.name)/$($Service.metadata.name)'. Policies: $policyNames."
        }
    }

    $targetIngressPolicies = @()
    foreach ($policy in @($TargetNetworkPolicies)) {
        $matchesAnyTargetPod = @($TargetPods | Where-Object { Test-KubeNetSelectorMatchesPod -Selector $policy.spec.podSelector -Pod $_ }).Count -gt 0
        if ($matchesAnyTargetPod -and ((Get-KubeNetPolicyTypes -Policy $policy) -contains 'Ingress')) {
            $targetIngressPolicies += $policy
        }
    }
    if ($targetIngressPolicies.Count -eq 0) {
        $results += [PSCustomObject]@{ Check = 'target ingress from source'; Status = 'PASS'; Message = 'No ingress NetworkPolicies select the target pods.' }
    } else {
        $allowedReasons = @()
        foreach ($policy in $targetIngressPolicies) {
            foreach ($rule in @($policy.spec.ingress)) {
                $allow = Test-KubeNetNetworkPolicyIngressAllowsSource -Rule $rule -SourcePod $SourcePod -SourceNamespace $SourceNamespace -PolicyNamespace $policy.metadata.namespace -Ports $ports
                if ($allow.Allows) {
                    $allowedReasons += "$($policy.metadata.name): $($allow.Reason)"
                }
            }
        }
        $policyNames = (@($targetIngressPolicies | ForEach-Object { $_.metadata.name }) -join ', ')
        if ($allowedReasons.Count -gt 0) {
            $results += [PSCustomObject]@{ Check = 'target ingress from source'; Status = 'PASS'; Message = "Target ingress policies appear to allow source pod '$($SourcePod.metadata.name)'. $($allowedReasons -join '; ')" }
        } else {
            $results += [PSCustomObject]@{ Check = 'target ingress from source'; Status = 'WARN'; Message = "Target pods are ingress-isolated by NetworkPolicy ($policyNames), and no rule obviously allows source namespace '$($SourceNamespace.metadata.name)' on TCP port(s) $($ports -join ', ')." }
            $diagnoses += "Likely issue: target ingress NetworkPolicy may block traffic from '$($SourcePod.metadata.namespace)/$($SourcePod.metadata.name)' to service '$($TargetNamespace.metadata.name)/$($Service.metadata.name)'. Policies: $policyNames."
        }
    }

    [PSCustomObject]@{ Results = $results; Diagnoses = $diagnoses }
}

function Test-KubeNetNetworkPolicyRuleAllowsDnsDestination {
    param(
        [object]$Rule,
        [string]$Nameserver,
        [object[]]$CoreDnsPods,
        [object[]]$NodeLocalDnsPods,
        [object]$KubeSystemNamespace,
        [string]$PolicyNamespace,
        [string]$CoreDnsServiceIp
    )

    if (-not (Test-KubeNetNetworkPolicyPortAllowsDns -Rule $Rule)) {
        return [PSCustomObject]@{ Allows = $false; Reason = 'rule does not allow UDP/TCP port 53' }
    }

    if ($null -eq $Rule.to -or @($Rule.to).Count -eq 0) {
        return [PSCustomObject]@{ Allows = $true; Reason = 'egress rule allows DNS port to all destinations' }
    }

    foreach ($peer in @($Rule.to)) {
        if ($peer.ipBlock) {
            $cidr = [string]$peer.ipBlock.cidr
            if (Test-KubeNetIpv4InCidr -Address $Nameserver -Cidr $cidr) {
                return [PSCustomObject]@{ Allows = $true; Reason = "ipBlock $cidr includes resolver $Nameserver" }
            }
        }

        $resolverIsCoreDns = (-not [string]::IsNullOrWhiteSpace($CoreDnsServiceIp) -and $Nameserver -eq $CoreDnsServiceIp) -or
            (@($CoreDnsPods | Where-Object { Test-KubeNetIpMatchesPodAddress -Address $Nameserver -Pod $_ }).Count -gt 0)
        $resolverIsNodeLocal = ($Nameserver -match '^169\.254\.') -or
            (@($NodeLocalDnsPods | Where-Object { Test-KubeNetIpMatchesPodAddress -Address $Nameserver -Pod $_ }).Count -gt 0)

        if ($resolverIsCoreDns) {
            foreach ($pod in @($CoreDnsPods)) {
                if (Test-KubeNetNetworkPolicyPeerMatchesPod -Peer $peer -TargetPod $pod -TargetNamespace $KubeSystemNamespace -PolicyNamespace $PolicyNamespace) {
                    return [PSCustomObject]@{ Allows = $true; Reason = "peer selector matches CoreDNS pod '$($pod.metadata.name)' for resolver $Nameserver" }
                }
            }
        }

        if ($resolverIsNodeLocal) {
            foreach ($pod in @($NodeLocalDnsPods)) {
                if (Test-KubeNetNetworkPolicyPeerMatchesPod -Peer $peer -TargetPod $pod -TargetNamespace $KubeSystemNamespace -PolicyNamespace $PolicyNamespace) {
                    return [PSCustomObject]@{ Allows = $true; Reason = "peer selector matches NodeLocalDNS pod '$($pod.metadata.name)' for resolver $Nameserver" }
                }
            }
        }
    }

    [PSCustomObject]@{ Allows = $false; Reason = 'no egress peer appears to match the runtime DNS resolver' }
}

function Get-KubeNetDnsResolverKind {
    param([string]$Nameserver, [string]$CoreDnsServiceIp)

    if ([string]::IsNullOrWhiteSpace($Nameserver)) { return 'Unknown' }
    if ($Nameserver -eq $CoreDnsServiceIp) { return 'CoreDNS service IP' }
    if ($Nameserver -match '^169\.254\.') { return 'NodeLocalDNS/link-local' }
    if ($Nameserver -match '^127\.') { return 'Localhost DNS' }
    'Custom/Node DNS'
}

function Test-KubeNetDnsEgressPolicy {
    param(
        [object]$State,
        [object]$SourcePod,
        [object]$ResolvSummary,
        [object[]]$NetworkPolicies,
        [object[]]$CoreDnsPods,
        [object[]]$NodeLocalDnsPods,
        [object]$KubeSystemNamespace,
        [string]$CoreDnsServiceIp
    )

    if ($null -eq $SourcePod -or $null -eq $ResolvSummary) {
        return [PSCustomObject]@{
            Status = 'SKIP'
            Message = 'Source pod or runtime DNS data was not available for DNS egress policy analysis.'
            Diagnoses = @()
        }
    }

    $sourcePodName = [string]$SourcePod.metadata.name
    $selectedPolicies = @($NetworkPolicies | Where-Object {
        (Test-KubeNetSelectorMatchesPod -Selector $_.spec.podSelector -Pod $SourcePod) -and ((Get-KubeNetPolicyTypes -Policy $_) -contains 'Egress')
    })

    if ($selectedPolicies.Count -eq 0) {
        return [PSCustomObject]@{
            Status = 'PASS'
            Message = "No egress NetworkPolicies select source pod '$sourcePodName'. DNS egress is not isolated by Kubernetes NetworkPolicy."
            Diagnoses = @()
        }
    }

    $messages = @()
    $diagnoses = @()
    $blockedResolvers = @()
    foreach ($nameserver in @($ResolvSummary.Nameservers)) {
        $kind = Get-KubeNetDnsResolverKind -Nameserver $nameserver -CoreDnsServiceIp $CoreDnsServiceIp
        $allowed = $false
        $allowReasons = @()

        foreach ($policy in $selectedPolicies) {
            foreach ($rule in @($policy.spec.egress)) {
                $ruleResult = Test-KubeNetNetworkPolicyRuleAllowsDnsDestination -Rule $rule -Nameserver $nameserver -CoreDnsPods $CoreDnsPods -NodeLocalDnsPods $NodeLocalDnsPods -KubeSystemNamespace $KubeSystemNamespace -PolicyNamespace $SourcePod.metadata.namespace -CoreDnsServiceIp $CoreDnsServiceIp
                if ($ruleResult.Allows) {
                    $allowed = $true
                    $allowReasons += "$($policy.metadata.name): $($ruleResult.Reason)"
                }
            }
        }

        if ($allowed) {
            $messages += "Resolver $nameserver ($kind) appears allowed by $($allowReasons -join '; ')."
        } else {
            $blockedResolvers += "$nameserver ($kind)"
            $messages += "Resolver $nameserver ($kind) does not appear allowed by egress NetworkPolicies selecting '$sourcePodName'."
        }
    }

    $policyNames = (@($selectedPolicies | ForEach-Object { $_.metadata.name }) -join ', ')
    if ($blockedResolvers.Count -gt 0) {
        if (($blockedResolvers -join ' ') -match 'NodeLocalDNS') {
            $diagnoses += "Likely issue: source pod '$sourcePodName' uses NodeLocalDNS/link-local resolver(s) $($blockedResolvers -join ', '), but egress NetworkPolicy ($policyNames) does not appear to allow DNS to that runtime resolver. Add UDP/TCP 53 egress to the NodeLocalDNS/link-local resolver IP or adjust the pod DNS policy."
        } else {
            $diagnoses += "Likely issue: egress NetworkPolicy selecting source pod '$sourcePodName' may block DNS to runtime resolver(s) $($blockedResolvers -join ', '). Policies: $policyNames."
        }
        return [PSCustomObject]@{
            Status = 'WARN'
            Message = "Source pod '$sourcePodName' is egress-isolated by NetworkPolicy ($policyNames). $($messages -join ' ')"
            Diagnoses = $diagnoses
        }
    }

    [PSCustomObject]@{
        Status = 'PASS'
        Message = "Source pod '$sourcePodName' is selected by egress NetworkPolicy ($policyNames), and DNS resolver(s) appear allowed. $($messages -join ' ')"
        Diagnoses = @()
    }
}

function Get-KubeNetLoadBalancerProvider {
    param([object]$Service)
    $annotations = $Service.metadata.annotations
    $keys = @()
    if ($annotations) { $keys = @($annotations.PSObject.Properties.Name) }
    $joined = ($keys -join ' ').ToLowerInvariant()
    if ($joined -match 'service\.beta\.kubernetes\.io/aws|aws-load-balancer') { return 'AWS' }
    if ($joined -match 'service\.beta\.kubernetes\.io/azure|azure-load-balancer') { return 'Azure' }
    if ($joined -match 'cloud\.google\.com|networking\.gke\.io') { return 'GCP/GKE' }
    if ($joined -match 'metallb') { return 'MetalLB' }
    if ($joined -match 'oci\.oraclecloud\.com') { return 'OCI' }
    'Unknown'
}
