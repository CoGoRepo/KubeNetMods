# KubeNetMods

KubeNetMods (`knm`) is a Kubernetes network troubleshooting CLI for operators, platform engineers, SREs, and application teams.

Use it when something should connect, but does not:

- a workload cannot reach a Kubernetes Service
- a pod cannot reach an external URL
- users cannot reach an app through Ingress, NodePort, or LoadBalancer
- a policy change may block traffic before a deployment goes live
- an alert gives you a source, target, URL, timeout, or app name and you need to find the failing layer fast

`knm` runs locally from your machine. It uses your kubeconfig permissions and reads Kubernetes objects directly. It does not install an agent, controller, webhook, CRD, daemonset, or telemetry.

## Current Capabilities

`knm` can inspect and reason across:

- kubeconfig context / cluster access
- namespace access
- node readiness and warning conditions
- CNI and CoreDNS pod health
- Deployment availability
- pod phase, readiness, image pull failures, crashes, and container states
- Service type, selectors, ports, `targetPort`, NodePort, ClusterIP, ExternalName, and headless Service behavior
- EndpointSlice readiness and backend mapping
- source workload resolution by pod, Deployment, StatefulSet, DaemonSet, ReplicaSet, Service, or common app label
- source pod DNS configuration and `/etc/resolv.conf`
- DNS resolution from the source side
- source-to-Service runtime reachability
- source-to-target-pod direct reachability
- native Kubernetes NetworkPolicy
- Calico NetworkPolicy and GlobalNetworkPolicy
- Calico tiers, order, allow, deny, pass, default-deny, selectors, namespace selectors, service accounts, named ports, port ranges, NetworkSets, GlobalNetworkSets, HostEndpoint/pre-DNAT/doNotTrack/applyOnForward awareness
- Cilium NetworkPolicy and CiliumClusterwideNetworkPolicy
- Cilium endpoint selectors, namespace selectors, services, entities, CIDRs, FQDN/DNS policy, deny rules, and default-deny behavior
- Istio sidecar-aware service-path diagnostics when Istio CRDs are installed and readable
- Istio AuthorizationPolicy DENY matches, ALLOW default-deny behavior, dry-run policy filtering, CUSTOM/external authz visibility, RequestAuthentication/JWT hints, Sidecar egress scope, PeerAuthentication mTLS posture, VirtualService routing, DestinationRule subsets, weighted routes, direct responses, redirects, fault injection, and client TLS mismatches
- Istio mesh visibility guardrails for `VirtualService.spec.gateways`, `VirtualService.exportTo`, and `DestinationRule.exportTo` so `check service` focuses on config visible to the tested source-to-Service path
- Ingress route mapping, `spec.defaultBackend`, backend ports, TLS secret readability, IngressClass readability, and annotations
- Gateway API v1 static scans for GatewayClass, Gateway, listener status, HTTPRoute attachment, ReferenceGrant, TLS Secret refs, backend Service refs, Service ports, and ready EndpointSlices
- NodePort and LoadBalancer exposure checks
- external egress URL checks
- policy blocker and preflight checks before a pod exists

## Boundaries

`knm` does not:

- continuously monitor clusters
- capture packets
- install probes or agents
- query AWS, Azure, or GCP APIs
- inspect cloud route tables, security groups, NACLs, source/destination checks, or cloud load balancer logs
- fully emulate Gateway API controller/provider behavior or every conformance rule
- fully emulate Envoy, Istio Pilot, or every Istio analyzer rule
- replace Hubble, calicoctl, the Cilium CLI, packet captures, or cloud-provider diagnostics

When the evidence points below Kubernetes, `knm` reports that boundary instead of pretending to know a cloud or dataplane root cause it cannot prove.

## Commands

| Command | Purpose |
|---|---|
| `knm discover` | Find Kubernetes objects by name, label, selector, service account, node, namespace, kind, or cluster/context. |
| `knm check service` | Troubleshoot a source workload reaching a Kubernetes Service. |
| `knm check egress` | Troubleshoot a workload reaching an external URL. |
| `knm check ingress` | Troubleshoot external or node-facing access to an app. |
| `knm check gateway` | Scan Gateway API resources for obvious route, listener, reference, and backend problems. |
| `knm show blockers` | Review policy blockers and preflight policy risk. |

Short aliases:

```text
knm service
knm egress
knm ingress
knm gateway
```

`--cluster` is a friendly alias for Kubernetes `--context`. Both work. Internally, KNM uses kubeconfig contexts.

Common shorthand flags:

| Short | Long | Where |
|---|---|---|
| `-c` | `--context` | most commands |
| `-n` | `--namespace` | `discover`, `service`, `ingress`, `gateway`, `show blockers` |
| `-p` | `--port` | `service`, `ingress`, `show blockers` |
| `-t` | `--target` / target Service | `service`, `ingress` |
| `-s` | `--source` | `service` |
| `-d` | `--deployment` | `service` |

## Install

Download a release binary from the releases page:

[https://github.com/CoGoRepo/KubeNetMods/releases](https://github.com/CoGoRepo/KubeNetMods/releases)

Common release artifacts:

| Platform | Artifact |
|---|---|
| Windows x64 | `knm-vX.Y.Z-windows-amd64.zip` |
| Linux x64 | `knm-vX.Y.Z-linux-amd64.tar.gz` |
| Linux ARM64 | `knm-vX.Y.Z-linux-arm64.tar.gz` |
| macOS Intel | `knm-vX.Y.Z-darwin-amd64.tar.gz` |
| macOS Apple Silicon | `knm-vX.Y.Z-darwin-arm64.tar.gz` |

Windows:

```powershell
Expand-Archive .\knm-vX.Y.Z-windows-amd64.zip
.\knm-windows-amd64.exe --help
```

Linux/macOS:

```bash
tar -xzf ./knm-vX.Y.Z-linux-amd64.tar.gz
chmod +x ./knm-linux-amd64
./knm-linux-amd64 --help
```

## Build From Source

```bash
go build -o ./bin/knm ./cmd/knm
```

Windows:

```powershell
go build -o .\bin\knm.exe .\cmd\knm
```

## Discover Objects

Use `discover` when an alert gives you an app/workload-ish name and you need to figure out what to pass to `knm`.

```powershell
knm discover checkout-client `
  --cluster prod `
  --namespace apps
```

Use `*` to list everything in scope when you do not know what to search for yet:

```powershell
knm discover * `
  --cluster prod `
  --namespace apps
```

Useful filters:

```text
--cluster cluster-context-name
--context kube-context-name
--namespace namespace-name
--kind pod|service|deployment|statefulset|daemonset|replicaset|ingress|networkpolicy
--name exact-object-name
--label key=value
--label-selector 'app=api,tier=backend'
--service-account account-name
--node node-name
--wide
```

Example:

```powershell
knm discover checkout-client --cluster calico-dev --namespace gnarly-src
```

Typical output:

```text
NAMESPACE    NAME             KINDS          HINT
gnarly-src   checkout-client  deploy,pod,rs  source=checkout-client selector=app=checkout,role=client
```

Discovery output is grouped by default. Use `--wide` to show every matched object as a separate row.

If nothing is found, `discover` prints the searched cluster/context and namespace so wrong-cluster mistakes are easier to spot.

## Check A Service Path

Use this when one workload should reach another workload through a Kubernetes Service.

```powershell
knm check service `
  --cluster prod `
  --source api `
  --source-namespace apps `
  --namespace database `
  --target postgres `
  --port 5432 `
  --html .\reports\service.html `
  --json .\reports\service.json
```

This checks the target Service, backend pods, EndpointSlices, DNS, runtime reachability, direct pod reachability, and relevant policy.

If Istio is installed, readable, and involved in the path, `check service` also inspects mesh config that can explain Envoy responses such as `403 RBAC: access denied`, missing-JWT style `401` responses, `503 no healthy upstream`, intentional direct responses/redirects/faults, and mTLS/DestinationRule TLS mismatches. It filters gateway-only VirtualServices, honors `exportTo` visibility for VirtualServices and DestinationRules, and ignores dry-run AuthorizationPolicies as live blockers. The goal is still the same: keep the command source-to-target focused and report the most specific path reason KNM can prove.

Friendly resolver flags:

```text
--source             Resolve a source pod/workload/service name automatically.
--source-deployment  Resolve a source Deployment directly.
--source-pod         Use an exact source pod.
--source-selector    Use an explicit source label selector.
--target             Shortcut for the target Service name.
--deployment         Target Deployment name. Defaults to the target Service name.
```

HTTP probe shaping:

```text
--scheme http|https  Runtime probe scheme. Defaults to http.
--path path          Runtime probe path. Defaults to /.
--header Name=Value  Runtime probe header. Repeatable.
```

Examples:

```powershell
knm check service `
  --cluster calico-dev `
  --namespace gnarly-tgt `
  --target ledger-api `
  --source-namespace gnarly-src `
  --source checkout-client `
  --port 8443
```

```powershell
knm check service `
  --source-namespace apps `
  --source-deployment api `
  --namespace database `
  --target postgres `
  --port 5432
```

Istio examples:

```powershell
knm service `
  -n app `
  -t echo-denied `
  --source-namespace src `
  -s curl `
  -p 80
```

```powershell
knm service `
  -n app `
  -t echo-bad-subset `
  --source-namespace src `
  -s curl `
  -p 80 `
  --path /api/items `
  --header x-canary=true
```

Use `--use-debug-pod` when there is no real source workload to exec into.

## Check Outbound Egress

Use this when a pod cannot reach an outbound URL, whether that target is internet-facing, private, or cluster-local.

```powershell
knm check egress `
  --cluster prod `
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

This checks source pod DNS, URL resolution, HTTP reachability, native NetworkPolicy egress posture, Calico outbound posture, and Cilium outbound/DNS posture when available.

## Check Ingress Or LoadBalancer Access

Use this when users or external systems cannot reach an app.

```powershell
knm check ingress `
  --cluster prod `
  --namespace apps `
  --service api `
  --port 443 `
  --ingress-url https://api.example.com `
  --test-load-balancer `
  --html .\reports\ingress.html
```

This checks the Service, selected port, Ingress backend mapping, default backends, TLS secrets, IngressClass, annotations, explicit URL reachability, LoadBalancer address state, and Calico host-policy posture when available.

## Check Gateway API

Use this when Gateway API objects are involved in external access to an app.

```powershell
knm check gateway
```

The no-parameter run is a static/status scan. It checks Gateway API v1 objects across the current cluster and reports obvious problems without running external probes or expanding every healthy backend.

Useful filters:

```powershell
knm check gateway -n apps
```

```powershell
knm check gateway --gateway infra/public
```

```powershell
knm check gateway --route apps/api-route --wide
```

The initial scan checks GatewayClass acceptance, Gateway acceptance/programming/address state, listener status, TLS Secret references, HTTPRoute attachment/status, cross-namespace ReferenceGrant requirements, backend Service existence, Service port matches, and ready EndpointSlices.

## Show Policy Blockers

Use this when you want policy-only analysis without runtime checks.

`show blockers` evaluates native Kubernetes NetworkPolicy, Calico policy, and Cilium policy when the related CRDs are installed and readable. It can also run in preflight mode with labels before a pod exists.

```powershell
knm show blockers `
  --cluster prod `
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

Most diagnostic commands support:

```text
--html path
--json path
--quiet
--no-terminal
```

HTML reports are for humans. JSON reports are for automation, CI, issue attachments, and downstream tooling.

Terminal output modes:

- default: print the full terminal report
- `--quiet`: print only the inferred diagnosis
- `--no-terminal` / `--no-term`: print no successful stdout output, useful when writing JSON/HTML for automation

## Examples

The `examples/` directory contains sample alerts, HTML reports, JSON reports, and demo media. The Istio examples under `examples/reports/istio/` show real `check service` diagnoses for AuthorizationPolicy, RequestAuthentication, VirtualService, DestinationRule, Sidecar, and mTLS failure cases.

## Permissions

`knm` needs read access to the resources it inspects. Depending on the command, that can include:

- Namespaces
- Nodes
- Deployments, StatefulSets, DaemonSets, ReplicaSets
- Pods
- Services
- EndpointSlices
- Events
- Ingresses and IngressClasses
- TLS Secrets referenced by Ingress
- NetworkPolicies
- Calico CRDs
- Cilium CRDs
- Istio CRDs: AuthorizationPolicies, RequestAuthentications, PeerAuthentications, Sidecars, VirtualServices, and DestinationRules

Runtime checks require permission to exec into the selected source pod. Debug-pod checks require permission to create and delete the debug pod.

## License

AGPL-3.0. See [LICENSE](./LICENSE).
