# KubeNetMods

KubeNetMods is a PowerShell module for Kubernetes network and network-adjacent troubleshooting.

It helps answer practical questions:

```text
Why can't this workload reach that Service?
Can this pod reach an external endpoint?
Can users reach this app through Ingress or a LoadBalancer?
```

No agent. No controller. No CRD. No webhook. No telemetry. It uses your existing Kubernetes CLI access, reads Kubernetes objects, optionally execs into workload pods, and only creates temporary debug pods when you explicitly ask it to.

## Demo

https://github.com/CoGoRepo/KubeNetMods/blob/main/examples/videos/KNM-DEMO.mp4

The demo shows a Calico/NodeLocalDNS-style failure where direct pod connectivity works, but the source pod's runtime DNS resolver is blocked by policy.

## Quick Start

```powershell
git clone https://github.com/CoGoRepo/KubeNetMods.git
cd KubeNetMods
Import-Module .\KubeNetMods.psd1 -Force
```

Source workload to target Service:

```powershell
Test-KubeNetService `
  -SourceNamespace apps `
  -SourcePodSelector app=api `
  -TargetNamespace database `
  -TargetService postgres `
  -TargetPort 5432
```

Target-side inspection only:

```powershell
Test-KubeNetService `
  -TargetNamespace database `
  -TargetService postgres `
  -TargetOnly
```

Export a report:

```powershell
Test-KubeNetService `
  -SourceNamespace apps `
  -SourcePodSelector app=api `
  -TargetNamespace database `
  -TargetService postgres `
  -TargetPort 5432 `
  -ExportHtml .\reports\postgres-path.html `
  -ExportJson .\reports\postgres-path.json
```

## Command Picker

| Problem | Command |
|---|---|
| Source app cannot reach a Kubernetes Service | [`Test-KubeNetService`](./docs/Test-KubeNetService.md) |
| Service has no endpoints, wrong selector, or wrong `targetPort` | [`Test-KubeNetService -TargetOnly`](./docs/Test-KubeNetService.md) |
| Pod cannot reach an external URL | [`Test-KubeNetEgress`](./docs/Test-KubeNetEgress.md) |
| Users cannot reach an app through Ingress or LoadBalancer | [`Test-KubeNetIngress`](./docs/Test-KubeNetIngress.md) |
| Alert payload has Kubernetes labels/tags | [`Invoke-KubeNetAlertTriage`](./docs/AlertTriage.md) |

## What It Checks

KubeNetMods can inspect:

- cluster and namespace access
- node readiness and common node network/pressure conditions
- Service selectors, ports, `targetPort`, EndpointSlices, and backend pod readiness
- source pod DNS resolver data and source-to-service DNS
- source pod to target Service and target pod IP reachability
- native Kubernetes NetworkPolicy source egress and target ingress
- Calico/Cilium policy hints when CRDs are present and readable
- Ingress objects, `defaultBackend`, backend ports, TLS secrets, IngressClass, annotations, and controller hints
- NodePort and LoadBalancer shape/reachability
- pod-side MTU/route snapshots when exec is available
- recent Warning events
- alert payload normalization and command planning

## Safety

KubeNetMods is designed for safe troubleshooting.

- It does not install anything into the cluster.
- It does not send data to an external service.
- `Test-KubeNetService` does not create debug pods by default.
- Debug pods are opt-in with `-UseDebugPod`.
- Workload `exec` only happens when you provide a source pod/selector or explicitly enable debug pods.

If a run is interrupted, cleanup is simple:

```powershell
kubectl delete pod kubenetmods-debug -n <namespace> --ignore-not-found
kubectl delete pod kubenetmods-source-debug -n <namespace> --ignore-not-found
kubectl delete pod kubenetmods-egress-debug -n <namespace> --ignore-not-found
kubectl delete pod kubenetmods-ingress-debug -n <namespace> --ignore-not-found
```

## Documentation

| Doc | Contents |
|---|---|
| [Test-KubeNetService](./docs/Test-KubeNetService.md) | Source-to-Service troubleshooting, parameters, examples, policy behavior. |
| [Test-KubeNetEgress](./docs/Test-KubeNetEgress.md) | Workload-to-external URL checks. |
| [Test-KubeNetIngress](./docs/Test-KubeNetIngress.md) | External-to-app checks through Ingress, LoadBalancer, or explicit URLs. |
| [Policy Analysis](./docs/PolicyAnalysis.md) | Native NetworkPolicy, Calico, and Cilium coverage. |
| [Reports](./docs/Reports.md) | HTML, JSON, `-PassThru`, `-Verbose`, and report shape. |
| [Alert Triage](./docs/AlertTriage.md) | Alert payload normalization and command planning. |
| [Limitations](./docs/Limitations.md) | What KubeNetMods does not claim to diagnose. |

## Requirements

- PowerShell 5.1+ or PowerShell 7+
- `kubectl` or another kubectl-compatible command
- Kubernetes RBAC permissions for the objects you want to inspect
- `pods/exec` permission only for checks that exec into workload/debug pods

## License

KubeNetMods is licensed under the [GNU Affero General Public License v3.0](./LICENSE).

## Examples

Example reports live in [`examples/reports`](./examples/reports).

Alert payload examples live in [`examples/alerts`](./examples/alerts).

## Current Status

KubeNetMods is usable for real troubleshooting, but some checks are intentionally heuristic. The goal is to narrow the failure domain quickly, not replace CNI-native dataplane tools, cloud-provider logs, or human review.
