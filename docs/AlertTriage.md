# Alert Triage

KubeNetMods can normalize alert payloads and turn them into command plans.

This is useful when alerts already include Kubernetes labels/tags such as namespace, service, pod, deployment, or URL.

## Preview A Plan

```powershell
ConvertTo-KubeNetServiceParameters `
  -Path .\examples\alerts\alertmanager-dns-timeout.json
```

The output includes:

- detected provider
- alert category
- confidence
- missing fields
- command name
- command preview
- parameter map

## Run Triage

```powershell
Invoke-KubeNetAlertTriage `
  -Path .\examples\alerts\alertmanager-dns-timeout.json `
  -ExportHtml .\reports\alert-triage.html `
  -ExportJson .\reports\alert-triage.json
```

Use `-PreviewOnly` to avoid running diagnostics:

```powershell
Invoke-KubeNetAlertTriage `
  -Path .\examples\alerts\alertmanager-dns-timeout.json `
  -PreviewOnly
```

## Provider Support

Supported provider modes:

- `Auto`
- `Alertmanager`
- `Grafana`
- `Datadog`
- `NewRelic`
- `Generic`

Alert normalization is best-effort because teams use different label and tag names.

## Command Routing

KubeNetMods chooses the command based on the detected symptom:

| Symptom | Command |
|---|---|
| `dns` | `Test-KubeNetService` |
| `network-policy` | `Test-KubeNetService` |
| `endpoints` | `Test-KubeNetService` |
| `cross-namespace` | `Test-KubeNetService` |
| `connectivity` | `Test-KubeNetService` |
| `egress` | `Test-KubeNetEgress` |
| `ingress` | `Test-KubeNetIngress` |
| `loadbalancer` | `Test-KubeNetIngress` |

## Examples

Example alert payloads live in [`../examples/alerts`](../examples/alerts).
