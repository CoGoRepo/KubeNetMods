# KubeNetMods

KubeNetMods (`knm`) is a Kubernetes network troubleshooting CLI for operators, platform engineers, and application teams.

Use it when something should connect, but does not:

- a pod cannot reach a Kubernetes Service
- a workload cannot reach an external URL
- users cannot reach an app through Ingress, NodePort, or LoadBalancer
- a policy change may block traffic before a deployment goes live

`knm` runs locally from your machine. It uses your kubeconfig permissions and reads Kubernetes objects directly. It does not install an agent, controller, webhook, CRD, daemonset, or telemetry.

## What It Helps Diagnose

`knm` checks the layers that commonly break Kubernetes connectivity:

- cluster and namespace access
- node readiness
- CNI and CoreDNS pod health
- Deployment and pod readiness
- image pull and crash states
- Service selectors, ports, `targetPort`, NodePort, ClusterIP, ExternalName, and headless Services
- EndpointSlice readiness
- source pod DNS configuration
- source-to-Service DNS resolution
- source-to-Service runtime reachability
- direct source-to-pod reachability
- native Kubernetes NetworkPolicy
- Calico policy
- Cilium policy
- Ingress backend mapping
- TLS secret and IngressClass readability
- LoadBalancer and external URL reachability

## What It Does Not Do

`knm` does not:

- continuously monitor clusters
- capture packets
- install probes or agents
- query AWS, Azure, or GCP APIs
- inspect cloud route tables, security groups, NACLs, source/destination checks, or load balancer logs
- fully validate Gateway API resources yet
- replace Hubble, calicoctl, the Cilium CLI, packet captures, or cloud-provider diagnostics

When the evidence points below Kubernetes, `knm` reports that boundary instead of guessing at a cloud or dataplane root cause.

## Commands

| Command | Purpose |
|---|---|
| `knm check service` | Troubleshoot a source workload reaching a Kubernetes Service. |
| `knm check egress` | Troubleshoot a workload reaching an external URL. |
| `knm check ingress` | Troubleshoot external or node-facing access to an app. |
| `knm show blockers` | Review policy blockers and preflight policy risk. |

Short aliases:

```text
knm service
knm egress
knm ingress
```

## Install

Download a release binary:

```text
https://github.com/CoGoRepo/KubeNetMods/releases
```

Common release artifacts:

| Platform | Artifact |
|---|---|
| Windows x64 | `knm-windows-amd64.exe` |
| Linux x64 | `knm-linux-amd64` |
| Linux ARM64 | `knm-linux-arm64` |
| macOS Intel | `knm-darwin-amd64` |
| macOS Apple Silicon | `knm-darwin-arm64` |

Windows:

```powershell
.\knm-windows-amd64.exe --help
```

Linux/macOS:

```bash
chmod +x ./knm-linux-amd64
./knm-linux-amd64 --help
```

## Build

```bash
go build -o ./bin/knm ./cmd/knm
```

Windows:

```powershell
go build -o .\bin\knm.exe .\cmd\knm
```

## Usage

### Check A Service Path

Use this when one workload should reach another workload through a Kubernetes Service.

```powershell
knm check service `
  --context prod `
  --source-namespace apps `
  --source-selector app=api `
  --namespace database `
  --service postgres `
  --port 5432 `
  --html .\reports\service.html `
  --json .\reports\service.json
```

This checks the target Service, selected backend pods, EndpointSlices, DNS, runtime reachability, direct pod reachability, and relevant policy.

### Check External Egress

Use this when a pod cannot reach an external URL.

```powershell
knm check egress `
  --context prod `
  --source-namespace apps `
  --source-selector app=api `
  --url https://example.com `
  --html .\reports\egress.html
```

Repeat `--url` to test more than one destination.

```powershell
knm check egress `
  --source-namespace apps `
  --source-selector app=api `
  --url https://example.com `
  --url https://login.microsoftonline.com
```

This checks source pod DNS, URL resolution, HTTP reachability, native NetworkPolicy egress posture, Calico external egress posture, and Cilium external egress/DNS posture when available.

### Check Ingress Or LoadBalancer Access

Use this when users or external systems cannot reach an app.

```powershell
knm check ingress `
  --context prod `
  --namespace apps `
  --service api `
  --port 443 `
  --ingress-url https://api.example.com `
  --test-load-balancer `
  --html .\reports\ingress.html
```

This checks the Service, selected port, Ingress backend mapping, default backends, TLS secrets, IngressClass, annotations, explicit URL reachability, LoadBalancer address state, and Calico host-policy posture when available.

### Show Policy Blockers

Use this when you want policy-only analysis without runtime checks.

`show blockers` evaluates native Kubernetes NetworkPolicy, Calico policy, and Cilium policy when the related CRDs are installed and readable. It can also run in preflight mode with labels before a pod exists.

```powershell
knm show blockers `
  --context prod `
  --namespace apps `
  --selector app=api `
  --direction egress `
  --port 5432 `
  --to-namespace database `
  --to-service postgres
```

Preflight labels before a pod exists:

```powershell
knm show blockers `
  --namespace apps `
  --labels app=api `
  --labels env=prod `
  --service-account api-sa `
  --direction egress `
  --port 5432 `
  --to-namespace database `
  --to-service postgres
```

Use `--wide` for more detail:

```powershell
knm show blockers `
  --namespace apps `
  --labels app=api `
  --direction egress `
  --port 443 `
  --wide
```

## Reports

Most commands support:

```text
--html path
--json path
--quiet
```

HTML reports are for humans. JSON reports are for automation, CI, issue attachments, and downstream tooling.

## Debug Pods

Debug pods are disabled by default.

Use `--use-debug-pod` when there is no real source workload to exec into:

```powershell
knm check service `
  --namespace database `
  --service postgres `
  --source-namespace apps `
  --use-debug-pod
```

Useful debug pod flags:

```text
--debug-image
--debug-pull-policy
--source-debug-pod
```

## Permissions

`knm` needs read access to the resources it inspects. Depending on the command, that can include:

- Namespaces
- Nodes
- Deployments
- Pods
- Services
- EndpointSlices
- Events
- Ingresses and IngressClasses
- TLS Secrets referenced by Ingress
- NetworkPolicies
- Calico CRDs
- Cilium CRDs

Runtime checks require permission to exec into the selected source pod. Debug-pod checks require permission to create and delete the debug pod.

## License

AGPL-3.0. See [LICENSE](./LICENSE).
