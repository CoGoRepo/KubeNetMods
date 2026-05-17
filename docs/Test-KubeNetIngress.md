# Test-KubeNetIngress

`Test-KubeNetIngress` checks external-to-app paths through Kubernetes Ingress, LoadBalancer Services, or explicit external URLs.

Use it when the question is:

```text
Why can't users reach this app?
```

## What It Checks

`Test-KubeNetIngress` reuses target-side Service inspection from `Test-KubeNetService -TargetOnly`, then adds external reachability checks.

It can inspect:

- target Service and backend health
- Ingress rule backends and `spec.defaultBackend`
- backend service port/name matches
- TLS secret existence
- IngressClass existence
- annotation visibility
- likely controller pod hints
- explicit ingress URLs from the local host
- explicit external URLs from the local host
- LoadBalancer status addresses when requested

## Examples

Test an Ingress URL:

```powershell
Test-KubeNetIngress `
  -TargetNamespace apps `
  -TargetService api `
  -IngressUrls https://api.example.com/health
```

Inspect LoadBalancer status addresses:

```powershell
Test-KubeNetIngress `
  -TargetNamespace apps `
  -TargetService api `
  -TestLoadBalancer
```

Test explicit external URLs:

```powershell
Test-KubeNetIngress `
  -TargetNamespace apps `
  -TargetService api `
  -ExternalUrls https://api.example.com/health,https://api-alt.example.com/health
```

Use a debug pod for target-side synthetic checks:

```powershell
Test-KubeNetIngress `
  -TargetNamespace apps `
  -TargetService api `
  -UseDebugPod `
  -IngressUrls https://api.example.com/health
```

## Parameters

| Parameter | Default | Purpose |
|---|---:|---|
| `-TargetNamespace` | `default` | Target Service namespace. |
| `-TargetService` | `nginx` | Target Service name. |
| `-DeploymentName` | target Service | Target Deployment name when it differs from the Service. |
| `-TargetPort` | `0` | Service port to inspect. |
| `-UrlScheme` | `http` | Scheme for generated LoadBalancer URLs. |
| `-UrlPath` | `/` | Path for generated LoadBalancer URLs. |
| `-TargetPodSelector` | empty | Override backend pod selection. |
| `-Context` | current | kubectl context. |
| `-IngressUrls` | empty | External ingress URLs to test from the local host. |
| `-ExternalUrls` | empty | Other external URLs to test from the local host. |
| `-TestLoadBalancer` | false | Test LoadBalancer status addresses for the Service. |
| `-UseDebugPod` | false | Create a target debug pod for synthetic target-side checks. |
| `-KubeCommand` | `kubectl` | kubectl-compatible command to use. |
| `-TimeoutSec` | `5` | Per-check timeout. |
| `-ExportJson` | empty | Save JSON report. |
| `-ExportHtml` | empty | Save HTML report. |
| `-PassThru` | false | Return report object. |
| `-Quiet` | false | Suppress console output. |
| `-Verbose` | false | Show underlying Kubernetes commands. |

Advanced debug pod knobs:

| Parameter | Default |
|---|---:|
| `-DebugImage` | `nicolaka/netshoot:latest` |
| `-DebugImagePullPolicy` | `IfNotPresent` |
| `-TargetDebugPodName` | `kubenetmods-ingress-debug` |

## Notes

KubeNetMods currently inspects Kubernetes `Ingress` resources only. It does not inspect Gateway API resources such as `Gateway`, `HTTPRoute`, `TLSRoute`, or `GRPCRoute`.

Ingress annotation checks are visibility-only. KubeNetMods surfaces annotation names but does not validate controller-specific annotation semantics.
