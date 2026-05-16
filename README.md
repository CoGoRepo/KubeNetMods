# KubeNetMods

KubeNetMods is an experimental PowerShell module for Kubernetes network and network-adjacent troubleshooting.

It starts with a target Kubernetes Service and checks the network path around it: cluster and namespace access, node/core add-on health, Service and EndpointSlice mapping, target pod health, DNS, native Kubernetes NetworkPolicy, Calico/Cilium policy hints, Ingress, NodePort, LoadBalancer/external reachability, source-to-target tests, pod-side MTU/route snapshots, recent events, and optional alert-driven triage.

The goal is simple:

```text
Is this actually a Kubernetes networking problem, and where should I look first?
```

## Demo

https://github.com/CoGoRepo/KubeNetMods/blob/main/examples/videos/KNM-DEMO.mp4

The demo shows a Calico/NodeLocalDNS-style failure where the target service path is allowed, direct pod connectivity works, but the source pod's runtime DNS resolver is blocked by policy.

## Commands

| Command | Purpose |
|---|---|
| `Test-KubeNetService` | Main diagnostic command for a Kubernetes Service/network path. |
| `ConvertTo-KubeNetAlert` | Normalize alert JSON into a provider-neutral KubeNet alert object. |
| `ConvertTo-KubeNetServiceParameters` | Convert a normalized alert into a visible `Test-KubeNetService` parameter plan. |
| `Invoke-KubeNetAlertTriage` | Normalize, classify, plan, and optionally run KubeNet diagnostics from an alert payload. |

## Current Status

This is a prototype module. It is usable for real troubleshooting, but some checks are intentionally heuristic.

Report statuses:

| Status | Meaning |
|---|---|
| `FAIL` | A deterministic config problem or runtime test failure. |
| `WARN` | Suspicious configuration that may matter, but is not proven broken. |
| `PASS` | The check succeeded. |
| `SKIP` | The check did not apply or was disabled. |
| `INFO` | Context collected for the report. |

The `Diagnosis` section is filtered so downstream symptoms do not drown out the clearest likely cause.

## What It Checks

| Area | What KubeNetMods Checks |
|---|---|
| Cluster access | `kubectl` access, target/source namespace access, node readiness, and common node pressure/network conditions. |
| Core networking | CNI add-on pod health, CoreDNS pod health, kube-dns Service IP, CoreDNS Corefile basics, kube-proxy pod health. |
| Target Service | Service existence, type, ClusterIP, port, `targetPort`, selector, selected backend pods, pod readiness, and EndpointSlice readiness/ports. |
| Target baseline | DNS and HTTP from a target debug pod to the target Service, ClusterIP, and target pod IPs. This answers: "does the target side work from its own namespace?" |
| Source path | DNS and HTTP from a source pod, selected source pod, or source debug pod to the target Service FQDN and target pod IPs. This answers: "can this client side reach the target?" |
| DNS | Source pod resolver data, target workload DNS checks when requested, `/etc/resolv.conf`, `dnsPolicy`, `hostNetwork`, search domains, CoreDNS/NodeLocalDNS policy hints. |
| Native Kubernetes NetworkPolicy | Source egress isolation, target ingress isolation, DNS egress hints, and likely source-to-target allow/block interpretation for standard Kubernetes `NetworkPolicy`. |
| CNI-specific policy | Extra Calico/Cilium policy analysis when those provider CRDs are present and readable. Depth varies by provider. |
| Ingress | Ingress objects pointing to the target Service, backend service port/name, TLS secret existence, IngressClass existence, controller pod hints, optional external URL checks. |
| NodePort/LoadBalancer | NodePort inside-cluster and host reachability, LoadBalancer status addresses, optional explicit external URL checks. |
| Snapshots | Pod-side MTU and route snapshots from exec-capable pods, plus source/target `eth0` MTU comparison when available. These are snapshots, not full packet-size path-MTU tests. |
| Events | Recent Warning events in target/source namespaces. |
| Alerts | Best-effort alert normalization, network-scope classification, parameter planning, and optional triage run. |

## CNI-Specific Policy Analysis

KubeNetMods includes a `CNI Policy Layer` for common Calico and Cilium policy behavior.

This layer does not replace native CNI tools. It is meant to answer:

```text
Does a common Cilium or Calico policy pattern obviously explain this failing path?
```

### Calico Coverage

Calico currently has the deeper provider-specific analyzer.

It can inspect:

- Calico `NetworkPolicy` and `GlobalNetworkPolicy`
- staged policy visibility for `StagedNetworkPolicy` and `StagedGlobalNetworkPolicy`
- tier order and ordered first-match behavior
- `Allow`, `Deny`, `Pass`, and `Log` actions
- source egress default-deny and target ingress default-deny
- missing DNS egress allow hints
- namespace selectors, pod selectors, and common selector operators
- numeric ports, named ports, port ranges, and protocol matching
- `notSelector`, `notPorts`, `nets`, `notNets`
- destination `services` matches
- `NetworkSet` and `GlobalNetworkSet`
- cases where a later Deny matches but an earlier Allow wins

Calico analysis is still heuristic. It does not fully emulate workload profiles after `Pass`, every tier/default-action edge case, service account selectors, pre-DNAT policy, host endpoint policy, every selector expression, or live dataplane state.

### Cilium Coverage

Cilium analysis is currently shallower than Calico.

It can inspect:

- `CiliumNetworkPolicy` and `CiliumClusterwideNetworkPolicy`
- `endpointSelector`
- `toEndpoints` and `fromEndpoints`
- basic namespace-label matching
- `egressDeny` and `ingressDeny`
- source egress default-deny and target ingress default-deny
- target port matching through `toPorts`
- common DNS egress allow hints
- simple `toEntities` / `fromEntities` cases such as `all` and `cluster`
- basic `toCIDR` / `fromCIDR` matches against target/source IPs

Cilium analysis does not fully emulate Cilium identity resolution, FQDN policies, service-aware policy behavior, L7 HTTP/Kafka/DNS policy, `toServices`, `toGroups`, advanced entities, every selector form, eBPF dataplane state, or Hubble flow history.

## What It Cannot Do Yet

- It does not inspect Gateway API resources.
- It does not deeply understand service mesh config such as Istio, Linkerd, or Consul.
- It does not run provider-specific dataplane commands such as `cilium monitor`, `cilium policy trace`, `calicoctl`, or Felix/BPF inspection.
- It does not deeply inspect kube-proxy iptables, IPVS, or eBPF state.
- It does not perform path-MTU discovery, packet-size probing, or DF-bit testing.
- It does not inspect node route tables or cloud route tables.
- It does not call AWS, Azure, or GCP APIs.
- It does not prove country/region edge-provider outages unless they appear through explicit external URL tests.
- It does not validate application auth or business logic. HTTP checks focus on reachability.
- NetworkPolicy analysis is heuristic. Generated policies, admission-mutated policies, service mesh policies, and provider-specific dataplane state may still need human review.
- Alert normalization is best-effort because alert platforms and teams use different label/tag names.

## Safety

The module is mostly read-only, but some checks create temporary debug pods or run `kubectl exec`.

Temporary debug pods are cleaned up automatically. If a run is interrupted:

```powershell
kubectl delete pod kubenetmods-debug -n <namespace> --ignore-not-found
kubectl delete pod kubenetmods-source-debug -n <namespace> --ignore-not-found
```

Use `-SkipDebugPod` for read-mostly inspection.

## Parameters

### Source And Target Terms

`target` means the Service/backend you are troubleshooting.
`source` means where the client connection starts.

If you do not provide a source namespace or pod, KubeNetMods starts from the target namespace and uses debug pods for baseline checks. If you provide `-SourcePodName` or `-SourcePodSelector`, source-side DNS, policy, and curl checks run from that source pod instead.

### Target

| Parameter | Default | Purpose |
|---|---:|---|
| `-Namespace` | `default` | Target Service namespace. |
| `-ServiceName` | `nginx` | Target Service name. |
| `-DeploymentName` | empty | Target Deployment name. Defaults to Service name when omitted. |
| `-ServicePort` | `0` | Service port to test. Uses the first Service port when omitted. |
| `-UrlScheme` | `http` | URL scheme for curl/HTTP checks. |
| `-UrlPath` | `/` | HTTP path used for curl checks. |
| `-TargetPodSelector` | empty | Override which backend pods belong to the target Service. |
| `-TargetContext` | current | kubectl context for the target cluster. |

### Source

| Parameter | Default | Purpose |
|---|---:|---|
| `-SourceNamespace` | target namespace | Namespace to test from. |
| `-SourceContext` | target context | kubectl context for source checks. |
| `-SourcePodName` | empty | Source workload pod to exec into for source-side checks. |
| `-SourcePodSelector` | empty | Select a source workload pod by labels. |
| `-SourceContainer` | empty | Container name when execing into a source workload pod. |

### Debug Pods

| Parameter | Default | Purpose |
|---|---:|---|
| `-DebugImage` | `nicolaka/netshoot:latest` | Debug pod image. |
| `-DebugImagePullPolicy` | `IfNotPresent` | Pull policy for temporary debug pods. |
| `-TargetDebugPodName` | `kubenetmods-debug` | Name for the debug pod created in the target namespace. |
| `-SourceDebugPodName` | `kubenetmods-source-debug` | Name for the debug pod created in the source namespace. |
| `-SkipDebugPod` | false | Skip checks that create or exec into debug pods. Provide a source pod if you still want source-side exec checks. |

### Optional Checks

| Parameter | Default | Purpose |
|---|---:|---|
| `-TestTargetPodDns` | false | Exec into a target workload pod for target-side DNS checks. Source-side DNS is checked separately when a source pod/debug pod can be used. |
| `-TargetDnsPodName` | empty | Specific target workload pod for `-TestTargetPodDns`. Defaults to a selected ready target pod. |
| `-TargetDnsContainer` | empty | Container name when execing into the target workload pod for DNS checks. |
| `-TestEgress` | false | Test egress from source namespace/pod. |
| `-EgressUrls` | empty | URLs for egress checks. No outbound URL curl is run unless at least one URL is supplied. |
| `-TestIngress` | false | Test explicit Ingress URLs when supplied. Static Ingress discovery runs when Ingresses exist. |
| `-IngressUrls` | empty | Explicit Ingress URLs to test from local host. |
| `-TestLoadBalancer` | false | Inspect/test LoadBalancer service external paths. |
| `-ExternalUrls` | empty | Explicit external URLs to test from local host. |
| `-TestPortForward` | false | Run `kubectl port-forward` validation. |
| `-SkipNodePort` | false | Skip NodePort/host reachability checks. |
| `-Deep` | false | Enables deeper DNS, egress, ingress, and load-balancer checks. Egress URL tests still require `-EgressUrls`. |

### Output

| Parameter | Default | Purpose |
|---|---:|---|
| `-ExportJson` | empty | Save JSON report. |
| `-ExportHtml` | empty | Save HTML report. |
| `-PassThru` | false | Return report object. |
| `-Quiet` | false | Suppress console output. |
| `-Verbose` | false | Show underlying `kubectl` commands. |

## Quick Start

Import the module from the module directory:

```powershell
Import-Module .\KubeNetMods.psd1 -Force
```

Check a Service:

```powershell
Test-KubeNetService `
  -Namespace default `
  -ServiceName nginx
```

Save HTML and JSON reports:

```powershell
Test-KubeNetService `
  -Namespace apps `
  -ServiceName api `
  -ExportHtml .\api-net.html `
  -ExportJson .\api-net.json
```

Run deeper optional checks. Egress URL curls only run when `-EgressUrls` is supplied.

```powershell
Test-KubeNetService `
  -Namespace apps `
  -ServiceName api `
  -Deep `
  -ExportHtml .\api-deep.html
```

## Alert Payload Triage

Alert handling is intentionally separate from the main diagnostic command:

```text
raw alert JSON -> normalized alert -> scope classification -> parameter plan -> optional run
```

Normalize an alert:

```powershell
ConvertTo-KubeNetAlert `
  -Provider Grafana `
  -Path .\examples\alerts\grafana-ingress-backend.json
```

Preview the inferred parameters:

```powershell
ConvertTo-KubeNetServiceParameters `
  -Provider Alertmanager `
  -Path .\examples\alerts\alertmanager-dns-timeout.json
```

Run triage only when the alert is in scope and has enough metadata:

```powershell
Invoke-KubeNetAlertTriage `
  -Provider Alertmanager `
  -Path .\examples\alerts\alertmanager-dns-timeout.json `
  -ExportHtml .\alert-triage.html
```

Preview an out-of-scope alert:

```powershell
Invoke-KubeNetAlertTriage `
  -Provider Datadog `
  -Path .\examples\alerts\datadog-http-401.json `
  -PreviewOnly
```

The triage wrapper will not run by default when an alert is out of scope or missing the target `Namespace`/`ServiceName`. Use `-Force` only when you intentionally want to run with the inferred parameters anyway.

## Common Examples

### Cross-Namespace Service Path

```powershell
Test-KubeNetService `
  -SourceNamespace apps `
  -Namespace database `
  -ServiceName postgres `
  -ServicePort 5432
```

This tests the target Service and source-side DNS/reachability against:

```text
postgres.database.svc.cluster.local
```

### Test From A Source Pod

Use a source pod when labels, DNS policy, sidecars, service accounts, or NetworkPolicies may differ from a generic debug pod.

```powershell
Test-KubeNetService `
  -SourceNamespace apps `
  -SourcePodSelector "app=api" `
  -Namespace database `
  -ServiceName postgres `
  -ServicePort 5432
```

Specific pod/container:

```powershell
Test-KubeNetService `
  -SourceNamespace apps `
  -SourcePodName api-7f8d9c4d5b-x2p6q `
  -SourceContainer api `
  -Namespace database `
  -ServiceName postgres `
  -ServicePort 5432
```

### Target Workload DNS

```powershell
Test-KubeNetService `
  -Namespace apps `
  -ServiceName api `
  -TestTargetPodDns `
  -TargetDnsPodName api-7f8d9c4d5b-x2p6q `
  -TargetDnsContainer api
```

### Ingress URL

```powershell
Test-KubeNetService `
  -Namespace apps `
  -ServiceName api `
  -TestIngress `
  -IngressUrls https://api.example.com/health
```

### Egress

```powershell
Test-KubeNetService `
  -SourceNamespace apps `
  -Namespace apps `
  -ServiceName api `
  -TestEgress `
  -EgressUrls https://kubernetes.default.svc,https://example.com
```

### LoadBalancer Or External URL

```powershell
Test-KubeNetService `
  -Namespace apps `
  -ServiceName public-api `
  -TestLoadBalancer
```

```powershell
Test-KubeNetService `
  -Namespace apps `
  -ServiceName api `
  -ExternalUrls https://api.example.com/health
```

### Port-Forward

```powershell
Test-KubeNetService `
  -Namespace apps `
  -ServiceName api `
  -TestPortForward
```

If port-forward works but NodePort, Ingress, or LoadBalancer fails, the problem is more likely outside the pod path.

### Cross-Cluster Note

Kubernetes `ClusterIP` and `service.namespace.svc.cluster.local` DNS are cluster-local. For true cross-cluster validation, provide explicit external routes.

```powershell
Test-KubeNetService `
  -SourceContext dev-cluster `
  -SourceNamespace apps `
  -TargetContext prod-cluster `
  -Namespace database `
  -ServiceName postgres `
  -ExternalUrls https://postgres.example.internal
```

## Reading The Report

Read the HTML report from the top down:

1. Start with `Diagnosis`.
2. Review `Failures`.
3. Review `Warnings`.
4. Use the detailed layer table when you need evidence.

Warnings do not always mean something is broken. They mean the configuration is worth reviewing.

NetworkPolicy findings are additive for native Kubernetes policies, but some CNIs add their own behavior. Calico and Cilium support policy forms that can explicitly deny traffic or place a selected endpoint into default-deny mode. When KubeNetMods can see a clear provider-specific cause, it reports that in the `CNI Policy Layer` and filters the follow-on DNS/curl failures down to the likely root.

## Samples

Sample HTML and JSON reports are in [`examples/reports`](./examples/reports).

| Report | Scenario |
|---|---|
| [`healthy-cross-namespace.html`](./examples/reports/healthy-cross-namespace.html) | Clean cross-namespace source-to-target path with no inferred failures. |
| [`wrong-targetport.html`](./examples/reports/wrong-targetport.html) | Service routes to the wrong `targetPort` while direct pod IP connectivity still works. |
| [`selector-mismatch.html`](./examples/reports/selector-mismatch.html) | Service selector does not match the intended backend pods, leaving no ready endpoints. |
| [`crashloop-workload.html`](./examples/reports/crashloop-workload.html) | Workload health failure where the selected backend pod is crashing instead of serving traffic. |
| [`bad-image-pull.html`](./examples/reports/bad-image-pull.html) | Image pull failure that prevents backend readiness and endpoint population. |
| [`ingress-misconfig.html`](./examples/reports/ingress-misconfig.html) | Ingress points at a bad backend port, missing TLS secret, and missing IngressClass. |
| [`native-networkpolicy-block.html`](./examples/reports/native-networkpolicy-block.html) | Native Kubernetes `NetworkPolicy` likely blocks source-to-target ingress. |
| [`nodeport-kind-host-path.html`](./examples/reports/nodeport-kind-host-path.html) | NodePort path in a local kind-style environment where host reachability can differ from cluster reachability. |
| [`calico-dns-nodelocal-block.html`](./examples/reports/calico-dns-nodelocal-block.html) | Calico egress policy allows the target service path but blocks the source pod's NodeLocalDNS/link-local runtime resolver. |
| [`calico-dns-nodelocal-block-wide.html`](./examples/reports/calico-dns-nodelocal-block-wide.html) | Same Calico/NodeLocalDNS failure generated during the broader `-SkipDebugPod` test pass. |
| [`calico-tier-pass-to-deny.html`](./examples/reports/calico-tier-pass-to-deny.html) | Calico tier ordering where a `Pass` in one tier continues to a later tier that denies the path. |
| [`calico-tier-pass-to-deny-wide.html`](./examples/reports/calico-tier-pass-to-deny-wide.html) | Calico tier `Pass` followed by a later tier `Deny` from the broader test pass. |

Sample alert payloads are in [`examples/alerts`](./examples/alerts).

| Alert | Scenario |
|---|---|
| [`alertmanager-dns-timeout.json`](./examples/alerts/alertmanager-dns-timeout.json) | Network-relevant DNS timeout with enough metadata to run. |
| [`grafana-ingress-backend.json`](./examples/alerts/grafana-ingress-backend.json) | Network-relevant Ingress/backend alert. |
| [`generic-egress-timeout.json`](./examples/alerts/generic-egress-timeout.json) | Network-relevant egress timeout with an external URL to test. |
| [`datadog-http-401.json`](./examples/alerts/datadog-http-401.json) | Out-of-scope application-auth alert. |
| [`generic-missing-service.json`](./examples/alerts/generic-missing-service.json) | Network-looking alert missing target Service metadata. |

## Layout

```text
KubeNetMods/
  KubeNetMods.psd1
  KubeNetMods.psm1
  Public/
  Private/
  Reports/
  examples/
    alerts/
    reports/
```

The `.psm1` is the module loader. Public commands live in `Public`, helper functions live in `Private`, report exporters live in `Reports`, and example payloads/reports live in `examples`.
