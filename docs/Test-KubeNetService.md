# Test-KubeNetService

`Test-KubeNetService` diagnoses the path from a source workload to a target Kubernetes Service.

Use it when the question is:

```text
Why can't this pod/app reach that Service?
```

## What It Checks

- target namespace and Service access
- deployment availability when the deployment exists
- backend pod selection and readiness
- Service selector, port, `targetPort`, and container port metadata
- EndpointSlice readiness and endpoint-to-pod mapping
- basic static Ingress references to the target Service, including `spec.defaultBackend`
- source pod DNS resolver data when a source pod can be used
- source pod to target Service FQDN
- source pod to target pod IP
- native Kubernetes NetworkPolicy source egress and target ingress
- Calico/Cilium policy hints when provider CRDs are present and readable
- NodePort/host reachability for NodePort/LoadBalancer Services unless skipped
- recent Warning events in target/source namespaces

## Common Usage

Source workload to target Service:

```powershell
Test-KubeNetService `
  -SourceNamespace apps `
  -SourcePodSelector app=api `
  -TargetNamespace database `
  -TargetService postgres `
  -TargetPort 5432
```

Use a specific source pod:

```powershell
Test-KubeNetService `
  -SourceNamespace apps `
  -SourcePodName api-7f8d9c4d5b-x2p6q `
  -TargetNamespace database `
  -TargetService postgres `
  -TargetPort 5432
```

Only inspect the target side:

```powershell
Test-KubeNetService `
  -TargetNamespace database `
  -TargetService postgres `
  -TargetOnly
```

Use temporary debug pods:

```powershell
Test-KubeNetService `
  -TargetNamespace default `
  -TargetService nginx `
  -UseDebugPod
```

Save reports:

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

## Parameters

| Parameter | Default | Purpose |
|---|---:|---|
| `-TargetNamespace` | `default` | Target Service namespace. |
| `-TargetService` | `nginx` | Target Service name. |
| `-DeploymentName` | target Service | Target Deployment name when it differs from the Service. |
| `-TargetPort` | `0` | Service port to test. Uses first Service port when omitted. |
| `-UrlScheme` | `http` | Scheme for HTTP checks. |
| `-UrlPath` | `/` | Path for HTTP checks. |
| `-TargetPodSelector` | empty | Override backend pod selection. |
| `-Context` | current | kubectl context for the target cluster. |
| `-SourceNamespace` | target namespace | Source/client namespace. |
| `-SourceContext` | target context | kubectl context for source checks. |
| `-SourcePodName` | empty | Source workload pod to exec into. |
| `-SourcePodSelector` | empty | Select source workload pod by labels. |
| `-SourceContainer` | empty | Container name for source pod exec. |
| `-UseDebugPod` | false | Create temporary debug pods for synthetic path checks. |
| `-TargetOnly` | false | Inspect target side only and skip source-to-target exec checks. |
| `-SkipNodePort` | false | Skip NodePort/host reachability checks. |
| `-TestPortForward` | false | Run `kubectl port-forward` validation. |
| `-KubeCommand` | `kubectl` | kubectl-compatible command to use. |
| `-TimeoutSec` | `5` | Per-check timeout for curl/HTTP operations. |
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
| `-TargetDebugPodName` | `kubenetmods-debug` |
| `-SourceDebugPodName` | `kubenetmods-source-debug` |

## Notes

`Test-KubeNetService` keeps DNS and policy checks that are part of the source-to-Service path. It does not test arbitrary external egress URLs or external user-facing ingress URLs. Use `Test-KubeNetEgress` or `Test-KubeNetIngress` for those paths.
