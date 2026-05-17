# Test-KubeNetEgress

`Test-KubeNetEgress` checks whether a workload can reach external URLs.

Use it when the question is:

```text
Why can't this pod reach the internet or an external dependency?
```

## What It Checks

- source namespace access
- source pod selection
- source `/etc/resolv.conf`
- DNS resolution for each URL host
- HTTP/HTTPS reachability for each URL

## Examples

Use a real source workload:

```powershell
Test-KubeNetEgress `
  -SourceNamespace apps `
  -SourcePodSelector app=api `
  -Urls https://example.com,https://api.vendor.com
```

Use a specific pod and container:

```powershell
Test-KubeNetEgress `
  -SourceNamespace apps `
  -SourcePodName api-7f8d9c4d5b-x2p6q `
  -SourceContainer api `
  -Urls https://example.com
```

Use a temporary debug pod:

```powershell
Test-KubeNetEgress `
  -SourceNamespace apps `
  -UseDebugPod `
  -Urls https://example.com
```

Save reports:

```powershell
Test-KubeNetEgress `
  -SourceNamespace apps `
  -SourcePodSelector app=api `
  -Urls https://example.com `
  -ExportHtml .\reports\egress.html `
  -ExportJson .\reports\egress.json
```

## Parameters

| Parameter | Default | Purpose |
|---|---:|---|
| `-SourceNamespace` | `default` | Namespace to test egress from. |
| `-SourcePodName` | empty | Source workload pod to exec into. |
| `-SourcePodSelector` | empty | Select source workload pod by labels. |
| `-SourceContainer` | empty | Container name for exec. |
| `-Context` | current | kubectl context. |
| `-Urls` | empty | External URLs to test. |
| `-UseDebugPod` | false | Create a temporary debug pod if no source workload pod is supplied. |
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
| `-SourceDebugPodName` | `kubenetmods-egress-debug` |

## Notes

This command is intentionally external-target focused. It does not inspect an internal Kubernetes Service path. Use `Test-KubeNetService` when the target is another Service inside the cluster.
