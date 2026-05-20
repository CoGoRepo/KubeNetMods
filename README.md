# KubeNetMods Go CLI

`knm` is the Go CLI version of KubeNetMods. It is a Kubernetes network and network-adjacent troubleshooting tool focused on answering:

```text
Why can't this source workload reach this target Service?
Why can't this workload reach the internet?
Why can't users reach this app through Ingress or LoadBalancer?
```

It does not install an agent, controller, webhook, CRD, or anything persistent in the cluster. It uses your kubeconfig access, reads Kubernetes objects directly, and only creates debug pods when you explicitly ask it to with `--use-debug-pod`.

## What KubeNetMods Is

KubeNetMods is a local diagnostic CLI for Kubernetes network paths. It is not a monitoring platform, packet capture tool, service mesh, CNI replacement, admission controller, or SaaS agent.

The main idea is to collect the evidence an engineer normally gathers by hand and then explain which layer most likely owns the failure.

It focuses on these paths:

| Path | Main command | Example question |
|---|---|---|
| Workload to Kubernetes Service | `knm check service` | Can `checkout-api` reach `postgres.database.svc`? |
| Workload to external URL | `knm check egress` | Can this pod reach `https://login.microsoftonline.com`? |
| External/user/node-facing traffic to app | `knm check ingress` | Can outside users reach this app through Ingress, NodePort, or LoadBalancer? |
| Policy-only preflight/blocker review | `knm show blockers` | Would policy block this pod/label/port path before I deploy it? |

It is strongest at Kubernetes object, Service path, DNS, workload readiness, EndpointSlice, runtime pod-path, and policy reasoning. It can identify when a failure appears to fall below Kubernetes into CNI/node/cloud networking, but it does not yet deeply inspect cloud route tables, security groups, AWS source/destination checks, CNI dataplane state, or kernel packet drops.

## Capability Map

| Area | Current capability |
|---|---|
| Cluster access | Verifies kubeconfig context, namespace access, and core API readability. |
| Node health | Checks node readiness and common pressure/network conditions. |
| CNI/CoreDNS health | Checks CNI daemon-style pods and CoreDNS pod readiness where visible. |
| Deployment/workload health | Checks Deployment availability, pod phase, readiness, and common waiting/terminated states such as image pulls and crashes. |
| Service shape | Checks Service existence, type, ClusterIP, selector, ports, NodePort, and `targetPort`. |
| Backend mapping | Checks EndpointSlice readiness and whether selected pod IPs appear as ready endpoints. |
| Runtime DNS | Reads source pod `/etc/resolv.conf`, reports nameservers/search domains, and tests source-to-target FQDN resolution. |
| Runtime reachability | Tests source pod to Service DNS name, Service ClusterIP, and direct target pod IP/port when a source pod/debug pod is available. |
| Cross-namespace service paths | Tests FQDN-style paths such as `service.namespace.svc.cluster.local` and avoids overclaiming short-name behavior. |
| Native NetworkPolicy | Models source egress and target ingress for the tested pod-to-Service path. |
| Calico policy | Models a broad subset of Calico policy behavior, including tiers, order, selector logic, explicit Deny, Allow, Pass, default-deny, workload profile fallback, service accounts, named ports, port ranges, NetworkSets, GlobalNetworkSets, and host/pre-DNAT/forwarded policy awareness. |
| Cilium policy | Models Cilium policy behavior at a useful but currently less complete depth than Calico. |
| Ingress objects | Finds Ingress routes pointing at the Service, including `spec.defaultBackend`; validates backend ports, TLS secret readability, IngressClass readability, and lists annotations. |
| LoadBalancer/NodePort surface | Checks Service exposure shape and local reachability where applicable. |
| Calico HostEndpoint surface | For ingress/node-facing paths, inspects HostEndpoint-oriented GlobalNetworkPolicy behavior such as `preDNAT`, `doNotTrack`, and `applyOnForward`. |
| Reports | Emits terminal output and optional HTML/JSON reports. |
| CI/preflight usage | `knm show blockers` supports label-based preflight checks before a pod exists. Exit codes support automation. |

## What It Does Not Currently Do

- It does not install a daemonset, controller, CRD, webhook, or kernel probe.
- It does not continuously monitor clusters.
- It does not capture packets.
- It does not directly query AWS/Azure/GCP APIs.
- It does not inspect cloud route tables, NACLs, security groups, source/destination check, or load balancer control-plane logs.
- It does not fully validate Gateway API resources yet.
- It does not fully emulate every CNI dataplane detail.
- It does not replace Hubble, Inspektor Gadget, packet captures, cloud provider diagnostics, or CNI-native debugging tools.
- It does not claim a definite cloud/dataplane root cause when Kubernetes evidence only proves "below Kubernetes."

## Design Principles

- **Local first:** runs from the operator machine.
- **Read-heavy:** reads Kubernetes objects and CRDs; normal checks do not mutate the cluster.
- **No persistent footprint:** no agent, controller, webhook, CRD, or telemetry.
- **Explicit active checks:** source pod exec and debug pod creation happen only when the user provides the relevant inputs/options.
- **Layered diagnosis:** tries to say which layer owns the problem rather than dumping raw Kubernetes objects.
- **Provider-aware when possible:** reads Calico/Cilium CRDs when present instead of treating all policy as generic Kubernetes NetworkPolicy.

## Build

From the repo root:

```powershell
go build -o .\bin\knm.exe .\cmd\knm
```

On Linux/macOS:

```bash
go build -o ./bin/knm ./cmd/knm
```

Check that it runs:

```powershell
.\bin\knm.exe --help
```

## Install From A Release

The easiest way to try `knm` is to download a binary from the GitHub Releases page:

```text
https://github.com/CoGoRepo/KubeNetMods/releases
```

Pick the binary for your platform:

| Platform | Release artifact |
|---|---|
| Windows x64 | `knm-windows-amd64.exe` |
| Linux x64 | `knm-linux-amd64` |
| Linux ARM64 | `knm-linux-arm64` |
| macOS Intel | `knm-darwin-amd64` |
| macOS Apple Silicon | `knm-darwin-arm64` |

Optional checksum verification is available in `checksums.txt` for each release.

Windows example:

```powershell
.\knm-windows-amd64.exe --help
```

Linux/macOS example:

```bash
chmod +x ./knm-linux-amd64
./knm-linux-amd64 --help
```

## Command Shape

```text
knm check service [options]
knm check egress  [options]
knm check ingress [options]
knm show blockers [options]
```

There are also short aliases:

```text
knm service [options]
knm egress  [options]
knm ingress [options]
```

## Command Scope

| Command | Scope | What it can conclude | What it will not prove |
|---|---|---|---|
| `knm check service` | Source pod/workload to target Kubernetes Service. | Service, EndpointSlice, pod readiness, DNS, targetPort, runtime reachability, native policy, Calico/Cilium policy, and NodePort/LB host-policy context when relevant. | Exact cloud/dataplane root cause such as AWS source/destination check, route table, security group, or missing CNI tunnel route. |
| `knm check egress` | Source workload to one or more external URLs. | Whether a selected source pod/debug pod can resolve and reach external URLs, plus source selection/debug pod issues. | Cloud NAT, proxy, firewall, or provider-specific root cause unless visible from Kubernetes/runtime symptoms. |
| `knm check ingress` | External/user/node-facing path around a Service. | Ingress object mapping, backend port mismatch, TLS secret/IngressClass issues, explicit URL reachability, LoadBalancer/NodePort surface, Calico HostEndpoint/pre-DNAT/doNotTrack/applyOnForward policy posture. | Exact external client geography, CDN/edge router failures, cloud load balancer control-plane causes, or specific node dataplane drops without additional provider/dataplane integration. |
| `knm show blockers` | Policy-only blocker/preflight analysis for pod labels or a deployed pod. | Explicit Calico Deny, default-deny risk, native NetworkPolicy blockers, path-specific policy mismatch, and pre-deploy label/service-account posture. | Full runtime reachability, DNS behavior, Service/EndpointSlice health, or host/node policy blockers. |

## Show Blockers

Use `show blockers` when you want policy-focused answers without running the full Service diagnostic stack.

It is useful for:

- preflight checks before a workload exists
- finding explicit Calico `Deny` rules
- spotting native Kubernetes NetworkPolicy default-deny behavior
- checking whether a pod is selected by policy for a direction/port
- checking a source pod against a specific target Service path

Path-specific check:

```powershell
.\bin\knm.exe show blockers `
  --namespace apps `
  --selector app=api `
  --direction egress `
  --port 5432 `
  --to-namespace database `
  --to-service postgres
```

Specific deployed pod:

```powershell
.\bin\knm.exe show blockers `
  --namespace apps `
  --pod api-1234 `
  --direction egress `
  --port 5432 `
  --to-namespace database `
  --to-service postgres
```

Preflight mode when the pod is not deployed yet:

```powershell
.\bin\knm.exe show blockers `
  --namespace apps `
  --labels app=api `
  --labels env=prod `
  --service-account api-sa `
  --direction egress `
  --port 5432 `
  --to-namespace database `
  --to-service postgres
```

Port posture mode without a destination:

```powershell
.\bin\knm.exe show blockers `
  --namespace apps `
  --labels app=api `
  --direction egress `
  --port 5432
```

Port posture mode can identify explicit Deny rules and default-deny risk for the subject and port, but destination selectors cannot be fully proven without `--to-service` or target information.

Example explicit Calico deny output:

```text
Calico Blockers explicit deny FAIL
knm-edge17-src/edge17-final-deny rule 2 explicitly Denies TCP/80 in tier "edge-chain-final".
Reason: IP/service/selector criteria match.
```

Example default-deny output:

```text
Calico Blockers default deny FAIL
Calico egress policy selects this pod, but no matching Allow rule was found for TCP/80.
Closest allow-rule miss: allow-db rule 1: service match does not target this Service.
```

### Show Blockers Flags

| Flag | Default | Purpose |
|---|---|---|
| `--context` | current context | Kubeconfig context. |
| `--namespace` | `default` | Subject pod namespace. |
| `--pod` | empty | Subject pod name. |
| `--selector` | empty | Label selector used to find a deployed subject pod. |
| `--labels` | empty | Preflight subject labels as `key=value`. Repeatable. |
| `--service-account` | `default` | Preflight subject service account. |
| `--direction` | `egress` | Policy direction: `egress` or `ingress`. |
| `--protocol` | `tcp` | Protocol to evaluate. Only TCP is currently supported. |
| `--port` | required | TCP port to evaluate. Accepts a number (`5432`), named Calico port (`http`), or numeric range (`23:53`). |
| `--to-namespace` | subject namespace | Target namespace for path-specific evaluation. |
| `--to-service` | empty | Target Service for path-specific evaluation. |
| `--to-selector` | Service selector | Target pod selector override. |
| `--timeout` | `10` | Timeout in seconds. |
| `--html` | empty | Write an HTML report. |
| `--json` | empty | Write a JSON report. |
| `--quiet` | `false` | Suppress terminal report output. |

## Policy Analysis Depth

KubeNetMods does more than list policies. It attempts to model the policy decision for the tested path.

### Native Kubernetes NetworkPolicy

For native Kubernetes NetworkPolicy, `knm` checks:

- whether target pods are selected by ingress policy
- whether source pods are selected by egress policy
- namespace selectors
- pod selectors
- port/protocol matching for the tested TCP path
- default-deny behavior when policy selects a pod but no matching allow rule exists

Native Kubernetes NetworkPolicy is pod-focused. It does not model node-to-node host traffic, pre-DNAT traffic, or Calico/Cilium-specific extensions.

### Calico

Calico support is currently the deepest provider-specific analysis in the tool.

For normal workload policy, `knm` models:

- namespaced Calico `NetworkPolicy`
- Calico `GlobalNetworkPolicy`
- staged policy detection as non-enforced context
- tiers and tier ordering
- policy `order`
- first-match rule behavior
- `Allow`
- `Deny`
- `Pass` through later tiers
- fallback to inferred Kubernetes workload profiles such as `kns.<namespace>` and `ksa.<namespace>.<serviceAccount>`
- default-deny when policy selects a side of the path and no matching allow is found
- source and destination selectors
- namespace selectors, including Calico-style namespace labels
- `all()`, `global()`, `has()`, `in`, `not in`, equality, inequality, and boolean selector combinations supported by the embedded selector parser
- `notSelector`
- `nets` and `notNets`
- Calico `services` matches
- service account names and service account selectors
- numeric ports
- named ports where target pod/service metadata can resolve them
- port ranges
- `NetworkSet`
- `GlobalNetworkSet`
- DNS-runtime resolver policy checks, including cases where the pod uses a runtime resolver such as NodeLocalDNS/link-local DNS but policy only allows CoreDNS pods
- limited awareness of HTTP/L7 and ICMP criteria as warnings/context

For node-facing and external ingress paths, `knm` also models Calico host-policy posture:

- `HostEndpoint` selector matching
- `GlobalNetworkPolicy` with `preDNAT`
- `GlobalNetworkPolicy` with `doNotTrack`
- `GlobalNetworkPolicy` with `applyOnForward`
- explicit host-policy Deny on the tested Service/NodePort/LB port
- first matching Allow before later Deny
- Deny before later Allow
- default-deny risk when a matching host/forwarded policy applies but no allow matches
- invalid host policy combinations such as `preDNAT` without `applyOnForward`
- invalid `preDNAT` and `doNotTrack` together
- named host-port ambiguity when HostEndpoint metadata cannot resolve the named port

Calico caveats:

- Workload profile attachment is inferred from Kubernetes-style profile names when WorkloadEndpoint data is not exposed.
- Host/pre-DNAT analysis requires readable HostEndpoint objects to prove selector attachment.
- Host/pre-DNAT analysis is strongest for Service/NodePort/LoadBalancer posture; it is not a packet capture or kernel dataplane trace.
- Calico Enterprise-only features are not assumed.

### Cilium

Cilium support exists, but it is not yet as complete as Calico.

Current Cilium analysis can identify useful policy blockers and risky policy posture, including common source/target selector and service-path mismatches. It is still being brought up to parity with Calico.

Current Cilium limitations:

- L7 policy awareness is limited.
- Deep dataplane confirmation through Hubble or eBPF state is not integrated yet.
- Some Cilium-specific entities and advanced policy forms may be reported as limited/ambiguous instead of fully simulated.

## Cross-Node, Node, And Cloud Boundaries

`knm check service` can be situationally useful for cross-node pod traffic because it can show:

- source pod and target pod are on different nodes
- pods are healthy
- Service and EndpointSlices are correct
- DNS resolves or fails
- direct pod IP reachability succeeds or fails
- native/Calico/Cilium policy does or does not explain the block

If pod-to-pod or pod-to-Service traffic fails across nodes while Kubernetes objects and policy look healthy, `knm` can narrow the likely failure domain to CNI/node/cloud networking.

It does not yet deeply inspect:

- node route tables
- node interfaces
- CNI tunnel state
- BGP sessions
- VXLAN/IPIP/WireGuard dataplane health
- cloud route tables
- cloud security groups/NACLs
- AWS source/destination check
- provider load balancer internals

Those are candidates for future `knm check node` or cloud-provider integrations.

## Exit Codes

`knm` is designed to work in terminals and automation.

| Exit code | Meaning |
|---|---|
| `0` | Command ran and no `FAIL` results were found. |
| `1` | Command ran but at least one `FAIL` result was found, or the check could not complete. |
| `2` | Bad command or invalid flags. |

## Reports

By default, `knm` prints a terminal report.

Reports are organized as layered evidence. Each row has:

- layer
- check name
- status
- message

Reports also include a `Diagnosis` section when the tool can infer a likely failure owner. The diagnosis is intentionally based on gathered evidence, not on a generic checklist.

You can also export HTML and JSON:

```powershell
.\bin\knm.exe check service `
  --namespace database `
  --service postgres `
  --source-namespace apps `
  --source-selector app=api `
  --port 5432 `
  --html .\reports\postgres.html `
  --json .\reports\postgres.json
```

Use `--quiet` when you only want report files:

```powershell
.\bin\knm.exe check service `
  --namespace database `
  --service postgres `
  --source-namespace apps `
  --source-selector app=api `
  --port 5432 `
  --quiet `
  --html .\reports\postgres.html
```

The JSON report is intended for automation and later alert/CI integration. The HTML report is intended for human review and sharing.

## Service Checks

Use `check service` when you have a source workload trying to reach a Kubernetes Service.

This is the main command.

```powershell
.\bin\knm.exe check service `
  --namespace database `
  --service postgres `
  --source-namespace apps `
  --source-selector app=api `
  --port 5432
```

This checks the path around the target Service:

- Kubernetes API and namespace access
- node readiness and common network/pressure conditions
- Service existence, type, selector, ports, and `targetPort`
- target Deployment availability when provided or inferred
- target pod phase, readiness, and common container failure states
- EndpointSlice population
- source pod selection
- source pod runtime DNS resolver and search domains
- source-to-target DNS resolution
- source-to-Service HTTP/TCP reachability
- source-to-target-pod direct reachability
- native Kubernetes NetworkPolicy
- Calico policy and Kubernetes workload profile fallback when Calico CRDs are present/readable
- Cilium policy when Cilium CRDs are present/readable
- Calico host/pre-DNAT policy context for NodePort and LoadBalancer Services
- NodePort/host path unless skipped
- recent Warning events

### Same Namespace

```powershell
.\bin\knm.exe check service `
  --namespace default `
  --service nginx `
  --source-selector app=client `
  --port 80
```

If `--source-namespace` is omitted, it defaults to the target namespace.

### Cross Namespace

```powershell
.\bin\knm.exe check service `
  --namespace database `
  --service postgres `
  --source-namespace apps `
  --source-selector app=api `
  --port 5432
```

For cross-namespace checks, the tool tests the FQDN-style Service path, not just the short Service name.

### Specific Source Pod

```powershell
.\bin\knm.exe check service `
  --namespace database `
  --service postgres `
  --source-namespace apps `
  --source-pod api-7f7c6dbb9d-j2m8x `
  --port 5432
```

Use `--source-container` if the pod has multiple containers:

```powershell
.\bin\knm.exe check service `
  --namespace database `
  --service postgres `
  --source-namespace apps `
  --source-pod api-7f7c6dbb9d-j2m8x `
  --source-container api `
  --port 5432
```

### Target Selector Override

Normally, `knm` uses the Service selector to find target backend pods.

Use `--target-selector` when you need to override that:

```powershell
.\bin\knm.exe check service `
  --namespace apps `
  --service api `
  --target-selector "app=api,version=v2" `
  --source-selector app=frontend `
  --port 80
```

### Different Contexts

Target cluster context:

```powershell
.\bin\knm.exe check service `
  --context prod `
  --namespace apps `
  --service api
```

Source checks can use a different context:

```powershell
.\bin\knm.exe check service `
  --context target-cluster `
  --namespace database `
  --service postgres `
  --source-context source-cluster `
  --source-namespace apps `
  --source-selector app=api `
  --port 5432
```

Cross-context behavior is still a deeper/advanced path. For normal in-cluster troubleshooting, source and target usually use the same context.

### Debug Pod Mode

By default, `knm check service` does not create a debug pod.

If you do not have a real source pod, you can opt in:

```powershell
.\bin\knm.exe check service `
  --namespace database `
  --service postgres `
  --port 5432 `
  --use-debug-pod
```

Custom debug image:

```powershell
.\bin\knm.exe check service `
  --namespace database `
  --service postgres `
  --port 5432 `
  --use-debug-pod `
  --debug-image registry.example.com/tools/netshoot:latest
```

## Service Flags

| Flag | Default | Purpose |
|---|---|---|
| `--context` | current context | Target kubeconfig context. |
| `--namespace` | `default` | Target Service namespace. |
| `--service` | `nginx` | Target Service name. |
| `--deployment` | Service name | Target Deployment name. |
| `--port` | first Service port | Target Service port to test. |
| `--source-context` | target context | Source kubeconfig context. |
| `--source-namespace` | target namespace | Source workload namespace. |
| `--source-pod` | empty | Specific source workload pod. |
| `--source-selector` | empty | Label selector used to find a source pod. |
| `--source-container` | empty | Container name for source pod exec. |
| `--target-selector` | Service selector | Override target backend pod selector. |
| `--scheme` | `http` | Scheme used for HTTP checks. |
| `--path` | `/` | URL path used for HTTP checks. |
| `--use-debug-pod` | `false` | Create a temporary source debug pod when no source pod is supplied. |
| `--debug-image` | `nicolaka/netshoot:latest` | Debug pod image. |
| `--debug-pull-policy` | `IfNotPresent` | Debug pod image pull policy. |
| `--source-debug-pod` | `kubenetmods-source-debug` | Source debug pod name. |
| `--skip-nodeport` | `false` | Skip NodePort/host reachability checks. |
| `--timeout` | `10` | Per-check timeout in seconds. |
| `--html` | empty | Write an HTML report. |
| `--json` | empty | Write a JSON report. |
| `--quiet` | `false` | Suppress terminal report output. |

## Egress Checks

Use `check egress` when a workload cannot reach an external URL.

```powershell
.\bin\knm.exe check egress `
  --source-namespace apps `
  --source-selector app=api `
  --url https://example.com `
  --html .\reports\egress.html
```

Repeat `--url` to test multiple destinations:

```powershell
.\bin\knm.exe check egress `
  --source-namespace apps `
  --source-selector app=api `
  --url https://example.com `
  --url https://login.microsoftonline.com `
  --url https://github.com
```

Use a debug pod if you do not want to exec into a real workload:

```powershell
.\bin\knm.exe check egress `
  --source-namespace apps `
  --use-debug-pod `
  --url https://example.com
```

### Egress Flags

| Flag | Default | Purpose |
|---|---|---|
| `--context` | current context | Kubeconfig context. |
| `--source-namespace` | `default` | Source namespace. |
| `--source-pod` | empty | Specific source workload pod. |
| `--source-selector` | empty | Label selector used to find a source pod. |
| `--source-container` | empty | Container name for source pod exec. |
| `--url` | empty | External URL to test. Repeatable. |
| `--use-debug-pod` | `false` | Create a temporary source debug pod when no source pod is supplied. |
| `--debug-image` | `nicolaka/netshoot:latest` | Debug pod image. |
| `--debug-pull-policy` | `IfNotPresent` | Debug pod image pull policy. |
| `--source-debug-pod` | `kubenetmods-egress-debug` | Source debug pod name. |
| `--timeout` | `10` | Per-check timeout in seconds. |
| `--html` | empty | Write an HTML report. |
| `--json` | empty | Write a JSON report. |
| `--quiet` | `false` | Suppress terminal report output. |

## Ingress Checks

Use `check ingress` when users or external callers cannot reach an app through Ingress, LoadBalancer, or an explicit external URL.

When Calico CRDs are readable, `check ingress` also inspects HostEndpoint-oriented GlobalNetworkPolicy behavior such as `preDNAT`, `doNotTrack`, and `applyOnForward`. This is the path that can block NodePort, LoadBalancer, ingress-controller, or other externally-originated traffic before normal workload policy is reached.

```powershell
.\bin\knm.exe check ingress `
  --namespace apps `
  --service api
```

Test explicit Ingress URLs:

```powershell
.\bin\knm.exe check ingress `
  --namespace apps `
  --service api `
  --ingress-url https://api.example.com
```

Inspect/test LoadBalancer paths:

```powershell
.\bin\knm.exe check ingress `
  --namespace apps `
  --service api `
  --test-load-balancer
```

Test external URLs:

```powershell
.\bin\knm.exe check ingress `
  --namespace apps `
  --service api `
  --external-url https://api.example.com
```

### Ingress Flags

| Flag | Default | Purpose |
|---|---|---|
| `--context` | current context | Kubeconfig context. |
| `--namespace` | `default` | Target Service namespace. |
| `--service` | `nginx` | Target Service name. |
| `--ingress-url` | empty | Explicit Ingress URL to test. Repeatable. |
| `--external-url` | empty | Explicit external URL to test. Repeatable. |
| `--test-load-balancer` | `false` | Inspect/test LoadBalancer external paths. |
| `--timeout` | `10` | Per-check timeout in seconds. |
| `--html` | empty | Write an HTML report. |
| `--json` | empty | Write a JSON report. |
| `--quiet` | `false` | Suppress terminal report output. |

### What `check ingress` Actually Checks

`check ingress` is intentionally broader than Kubernetes `Ingress` objects. It is the command for the external or node-facing side of a Service.

It checks:

- target Service readability
- Service type and exposed ports
- Kubernetes Ingress routes pointing at the Service
- `spec.defaultBackend` pointing at the Service
- Ingress backend port/name matching
- Ingress TLS secret readability
- IngressClass readability
- annotation presence and keys
- explicit URL reachability from the machine running `knm`
- LoadBalancer external targets when `--test-load-balancer` is used
- Calico HostEndpoint/pre-DNAT/doNotTrack/applyOnForward policy posture when Calico CRDs are readable

It does not yet check Gateway API resources such as `Gateway`, `HTTPRoute`, `TLSRoute`, or `GRPCRoute`.

## How To Pick A Command

| Situation | Command |
|---|---|
| App pod cannot reach database Service | `knm check service` |
| App pod cannot reach another namespace Service | `knm check service` |
| Service has no endpoints or wrong targetPort | `knm check service` |
| Source pod cannot resolve the target Service | `knm check service` |
| Source pod cannot reach the internet | `knm check egress` |
| External users cannot reach an app | `knm check ingress` |
| You only have a URL and no source pod | `knm check egress --use-debug-pod` |

## Practical Examples

### App Cannot Reach Postgres

```powershell
.\bin\knm.exe check service `
  --namespace database `
  --service postgres `
  --source-namespace apps `
  --source-selector app=api `
  --port 5432 `
  --html .\reports\api-to-postgres.html
```

### Frontend Cannot Reach API

```powershell
.\bin\knm.exe check service `
  --namespace apps `
  --service api `
  --source-namespace web `
  --source-selector app=frontend `
  --port 80
```

### Calico Policy Suspected

```powershell
.\bin\knm.exe check service `
  --namespace payments `
  --service ledger `
  --source-namespace checkout `
  --source-selector app=checkout-api `
  --port 8080 `
  --html .\reports\checkout-to-ledger.html
```

If Calico CRDs are present and readable, `knm` includes Calico path analysis automatically. When a Calico policy `Pass` falls through with no later tier match, `knm` also evaluates the inferred Kubernetes workload profiles such as `kns.<namespace>` and `ksa.<namespace>.<serviceAccount>`.

### Cilium Policy Suspected

```powershell
.\bin\knm.exe check service `
  --namespace backend `
  --service api `
  --source-namespace frontend `
  --source-selector app=web `
  --port 80 `
  --html .\reports\web-to-api.html
```

If Cilium CRDs are present and readable, `knm` includes Cilium path analysis automatically.

### NodePort Is Noisy In A Local Cluster

```powershell
.\bin\knm.exe check service `
  --namespace default `
  --service nginx `
  --source-selector app=client `
  --port 80 `
  --skip-nodeport
```

### Generate Only HTML And JSON

```powershell
.\bin\knm.exe check service `
  --namespace default `
  --service nginx `
  --source-selector app=client `
  --port 80 `
  --quiet `
  --html .\reports\nginx.html `
  --json .\reports\nginx.json
```

## Reading The Report

The report is organized by layers.

Important statuses:

| Status | Meaning |
|---|---|
| `PASS` | The check found no problem. |
| `FAIL` | The check found a likely problem. The command exits `1`. |
| `WARN` | Something may matter, but it is not necessarily broken. |
| `INFO` | Context that helps explain the path. |
| `SKIP` | The check was intentionally skipped or not applicable. |

Start with the `Diagnosis` section, then review the failed layer rows.

For example:

```text
Calico policy denies the egress path between source pod "api-..." and Service "database/postgres".
```

That means the source side is selected by Calico egress policy and the modeled policy decision blocks the target Service path.

## Safety Notes

Safe by default:

- no agent
- no controller
- no webhook
- no CRD
- no telemetry
- no cluster mutation for normal reads/checks
- no debug pod unless `--use-debug-pod` is set
- no external service dependency
- no data is sent to a vendor or SaaS endpoint by the tool itself

Possible active operations:

- `pods/exec` into the source workload when you provide `--source-pod` or `--source-selector`
- temporary debug pod creation only when `--use-debug-pod` is set
- HTTP/DNS/curl-style checks from the chosen source pod/debug pod

The tool may make outbound HTTP requests only for URLs you explicitly ask it to test, such as `--url`, `--ingress-url`, or `--external-url`.

## RBAC Notes

Useful permissions depend on the checks you run.

Common read permissions:

- namespaces
- nodes
- services
- deployments
- pods
- EndpointSlices
- events
- NetworkPolicies
- Ingresses and IngressClasses
- Calico/Cilium CRDs if you want provider policy analysis

Exec/debug permissions:

- `pods/exec` for source workload checks
- `pods/create`, `pods/delete`, and `pods/get` if using `--use-debug-pod`

## Current Limitations

`knm` narrows the failure domain. It does not claim to replace every CNI-native dataplane tool.

Current practical limits:

- Calico and Cilium policy analysis is best-effort static modeling.
- Calico profile fallback is inferred from Kubernetes namespace/service-account profile names when WorkloadEndpoint data is not exposed by the cluster.
- Calico host/pre-DNAT analysis requires readable HostEndpoint objects. If a cluster hides HostEndpoints, `knm` can warn that host policy exists but cannot prove node attachment.
- Runtime checks still matter. If policy modeling and runtime disagree, trust the report as a prompt to inspect that edge.
- L7 policy awareness is limited.
- Cloud load balancer diagnosis is shallow compared to cloud-provider logs.
- It does not install a kernel/dataplane probe.

## Quick Help

```powershell
.\bin\knm.exe --help
.\bin\knm.exe check service --help
.\bin\knm.exe check egress --help
.\bin\knm.exe check ingress --help
```

