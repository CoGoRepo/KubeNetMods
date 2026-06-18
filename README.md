# KubeNetMods

KubeNetMods (`knm`) is a Kubernetes network troubleshooting CLI for operators, platform engineers, SREs, and application teams.

It is built around one question:

> This traffic should work. What part of the path is broken?

`knm` runs from your machine or CI runner, uses your kubeconfig permissions, and reads Kubernetes objects directly. It does not install an agent, controller, webhook, CRD, daemonset, or telemetry.

Use it for:

- first-response troubleshooting when a service path, Gateway route, or outbound URL is failing
- CI validation after deploying Gateway API, Service, policy, or mesh changes
- preflight policy checks before a workload exists
- turning vague alert context into concrete Kubernetes objects and follow-up commands
- generating JSON or HTML evidence for incidents, pull requests, and handoffs

## What KNM Checks

KNM combines Kubernetes API inspection, policy analysis, and runtime probes when a source pod or debug pod is available.

Core Kubernetes path checks:

- kubeconfig context and namespace access
- node readiness and warning conditions
- CNI and CoreDNS pod health
- recent warning Events in the target and source namespaces
- Deployment availability
- pod phase, readiness, image pull failures, crashes, and container states
- Service type, selector, ports, protocol, `targetPort`, NodePort, ClusterIP, ExternalName, selectorless Service, and headless Service behavior
- Service port and container port comparisons, including targetPort mismatches
- EndpointSlice readiness, ready-address checks, and selected-pod-to-endpoint mapping
- source workload resolution by pod, Deployment, StatefulSet, DaemonSet, ReplicaSet, Service, or common app label
- source pod DNS configuration, `/etc/resolv.conf`, and runtime DNS resolution
- source-to-Service and source-to-pod runtime reachability
- NodePort and local-host reachability checks for NodePort and LoadBalancer Services
- MTU route snapshots from the source path when exec tooling allows it

Policy and CNI checks:

- native Kubernetes NetworkPolicy ingress and egress path analysis
- Calico NetworkPolicy and GlobalNetworkPolicy
- Calico tiers, order, allow, deny, pass, default-deny, selectors, namespace selectors, service accounts, named ports, port ranges, NetworkSets, GlobalNetworkSets, HostEndpoint, pre-DNAT, doNotTrack, and applyOnForward awareness
- Cilium NetworkPolicy and CiliumClusterwideNetworkPolicy
- Cilium endpoint state, endpoint selectors, namespace selectors, services, entities, CIDRs, CIDRGroup refs, FQDN/DNS policy, L7 constraints, deny rules, and default-deny behavior
- policy-only blocker checks for pods that exist and preflight labels before a pod exists

Istio service-path checks:

- AuthorizationPolicy DENY matches, matching rule numbers, ALLOW default-deny behavior, dry-run filtering, CUSTOM/external auth visibility, root-namespace policies, and HTTP-only DENY rule risk
- RequestAuthentication/JWT hints
- Sidecar egress scope
- PeerAuthentication mTLS posture, including STRICT mTLS with an unmeshed source
- VirtualService routing, bad subsets, missing subsets, source-namespace route config, weighted routes, direct responses, redirects, fault aborts, fault delays, and HTTP match fields
- DestinationRule subsets, subset traffic policy overrides, port-level traffic policy overrides, and client TLS mismatches
- mesh visibility guardrails for `VirtualService.spec.gateways`, `VirtualService.exportTo`, and `DestinationRule.exportTo`

Gateway API checks:

- GatewayClass, Gateway, HTTPRoute, GRPCRoute, TLSRoute, TCPRoute, UDPRoute, ListenerSet, ReferenceGrant, BackendTLSPolicy, listener status, TLS Secret refs, backend Service refs, Service ports, and ready EndpointSlices
- Gateway implementation Service checks, including listener port exposure and ready dataplane endpoints
- generic Gateway policy attachment checks for experimental XBackendTrafficPolicy
- Envoy Gateway checks for Backend, BackendTrafficPolicy, ClientTrafficPolicy, SecurityPolicy, EnvoyExtensionPolicy, EnvoyPatchPolicy, EnvoyProxy, and HTTPRouteFilter resources when those CRDs are installed
- Envoy Gateway BackendTrafficPolicy semantics for targetRefs, targetSelectors, merge behavior, rate limits, circuit breakers, fault injection, response overrides, request buffering, health checks, timeouts, load balancing, bandwidth limits, admission control, HTTP/2, TCP keepalive, and compression settings
- traffic-intent checks for HTTPRoute host/path/method/header/query matching, GRPCRoute service/method/header matching, TLSRoute SNI/hostname matching, listener and route hostname misses, backendRef failures, unsupported backend kinds, inactive `weight: 0` backendRefs, mixed weighted backend paths, redirects, URL rewrites, request mirrors, and expected backend Services
- live HTTP/HTTPS probes that compare the advertised Gateway address with the in-cluster Gateway implementation Service path
- follow-up `knm check service` command hints when Gateway runtime probes identify a single backend Service worth drilling into

When evidence points outside the Kubernetes objects KNM can inspect, KNM reports that boundary instead of pretending to know a lower-level cloud, firewall, or packet root cause.

## Quick Start

```powershell
# Scan Gateway API objects for obvious broken references, status, and backend issues.
knm check gateway

# Trace a specific Gateway request intent.
knm check gateway --url https://payments.example.com/api --expect-service apps/payments-api

# Check a source workload reaching a Service.
knm check service -n database -t postgres --source-namespace apps -s api -p 5432

# Check outbound egress from a workload.
knm check egress -n apps --source-selector app=api --url https://example.com

# Find Kubernetes objects from vague alert text.
knm discover checkout-client -n apps

# Preflight policy risk before or after a pod exists.
knm show blockers -n apps --labels app=api --direction egress -p 5432 --to-namespace database --to-service postgres
```

Short aliases:

```text
knm gateway
knm service
knm egress
```

`--cluster` is a friendly alias for Kubernetes `--context`. Both work. Internally, KNM uses kubeconfig contexts.

Common shorthand flags:

| Short | Long | Where |
|---|---|---|
| `-c` | `--context`, `--cluster` | most commands |
| `-n` | `--namespace` or `--source-namespace` | `discover`, `service`, `egress`, `gateway`, `show blockers` |
| `-p` | `--port` | `service`, `show blockers` |
| `-t` | `--target` | `service` |
| `-s` | `--source` | `service` |
| `-d` | `--deployment` | `service` |

## CI Usage

KNM can be used as a validation step after manifests are applied or as a policy preflight before a rollout.

Typical CI patterns:

- run `knm check gateway --quiet --fail-on-warn` after applying Gateway API resources
- run `knm check gateway --url ... --expect-service ... --quiet` for critical externally exposed paths
- run `knm check service ... --quiet` after deploying an app to prove the Service path works from a real source
- run `knm show blockers ...` before deployment to catch policy that would block a planned path
- write `--json` and/or `--html` artifacts for the CI job summary

Example:

```powershell
knm check gateway `
  --url https://payments.example.com/api `
  --expect-service apps/payments-api `
  --quiet `
  --fail-on-warn `
  --ignore-warn runtime-unavailable `
  --json .\artifacts\gateway-payments.json `
  --html .\artifacts\gateway-payments.html
```

Exit behavior:

- `FAIL` results exit non-zero.
- `WARN` results exit zero by default.
- `--fail-on-warn` makes unignored `WARN` results exit non-zero.
- `--ignore-warn` only affects exit-code behavior when `--fail-on-warn` is used.

Warning categories:

| Alias | Category |
|---|---|
| `1` | `runtime-unavailable` |
| `2` | `api-inspection` |
| `3` | `policy-ambiguous` |
| `4` | `conditional-routing` |
| `5` | `unsupported-ref` |
| `6` | `output-limited` |
| `7` | `uncategorized` |

## Check Gateway API

Use this when Gateway API objects are involved in external or north-south access to an app.

```powershell
knm check gateway
```

The no-parameter run is a static/status scan. It checks standard Gateway API resources plus supported experimental/provider policy CRDs across the current cluster and reports obvious problems without running live probes or inferring a specific request path.

The broad scan checks:

- GatewayClass acceptance
- Gateway acceptance, programming, listener status, address state, and TLS Secret references
- HTTPRoute, GRPCRoute, TLSRoute, TCPRoute, and UDPRoute attachment and parent status
- ListenerSet status and TLS refs
- BackendTLSPolicy targets and CA refs
- supported generic Gateway policy target refs/status
- Envoy Gateway Backend, policy, patch, proxy, and HTTPRouteFilter reference/status checks
- Envoy Gateway BackendTrafficPolicy target resolution, accepted status, merge conflicts, selector attachment, and traffic-impacting policy settings
- cross-namespace ReferenceGrant requirements
- backend Service existence, Service port matches, and ready EndpointSlices

Scope filters narrow the scan:

```powershell
knm check gateway -n apps
knm check gateway --gateway infra/public
knm check gateway --route apps/api-route --wide
```

Use traffic intent when you have a specific request host or URL:

```powershell
knm check gateway --host payments.example.com --path /api
knm check gateway --url https://payments.example.com/api --method POST --header x-canary=true
knm check gateway --url https://payments.example.com/api --expect-service apps/payments-api
```

Traffic-intent mode traces the request through matching Gateway listeners, selected route parent status, route rules, backendRefs, Services, and EndpointSlices. It can explain request-specific misses that a broad scan cannot see, such as:

- no listener matching host, scheme, or port
- a listener with no attached routes
- attached routes that do not allow the request hostname
- path, method, header, or query matches that do not select a rule
- hostname typo near-misses
- multiple matching rules and the Gateway API precedence-selected rule
- backendRefs pointing at a missing Service, wrong Service port, missing ReferenceGrant, or no ready endpoints
- backendRefs using a non-Service backend kind
- weighted backend splits where only part of the traffic is broken
- redirects, URL rewrites, request mirrors, and expected Service mismatches

`--url` owns scheme, host, port, path, and query. `--method`, `--header`, and `--expect-service` can be combined with `--url`. If you do not use `--url`, provide `--host`; `--path` defaults to `/` and `--method` defaults to `GET`.

Gateway protocol inference supports HTTP/HTTPS, GRPCRoute, and TLSRoute traffic intent. Use `--grpc-service`, `--grpc-method`, or `--protocol grpc` for GRPCRoute paths. Use `--protocol tls` or a TLS-style `--host ... --port 443` for TLSRoute/SNI paths.

If a Gateway HTTP/HTTPS probe reaches Envoy but returns a backend failure, KNM can include a follow-up `knm check service ...` command for the selected backend Service when the path is unambiguous.

When Envoy Gateway CRDs are installed, `check gateway` also inspects Envoy-specific configuration around policy targets, referenced Secrets/ConfigMaps, external auth and ext-proc backend Services, Backend TLS validation refs, HTTPRouteFilter credential injection, EnvoyPatchPolicy targets, and EnvoyProxy status.

For Envoy Gateway BackendTrafficPolicy, KNM checks accepted controller status plus static policy semantics that can affect a routed path:

- unsupported or missing target references
- `targetSelectors` using `matchLabels` or `matchExpressions`
- unresolved namespace-label selectors without claiming the policy applies to a route
- `mergeType` on Gateway-targeted policies
- rateLimit type/rule mismatches, including Envoy's header/sourceCIDR selector requirement
- fault aborts/delays and response overrides that intentionally return errors
- circuit breaker and retry-budget settings that can reject or disable retries
- request buffering on HTTPRoute/GRPCRoute targets
- active health checks that only treat error responses as healthy
- TCP timeouts on HTTPRoute/GRPCRoute targets
- load-balancer, bandwidth, HTTP/2, TCP keepalive, and compression settings that are risky or ambiguous

Use `--probe` when you want runtime proof for an HTTP/HTTPS Gateway path:

```powershell
knm check gateway `
  --url https://payments.example.com/api `
  --probe `
  --quiet
```

With `--probe`, KNM tests the advertised Gateway address from the workstation/client side and, when it can create or reuse a debug pod, the in-cluster Gateway implementation Service. That separates "Gateway proxy works inside the cluster" from "the client cannot reach the advertised Gateway address."

Local labs sometimes advertise a Gateway address that is valid inside Docker or kind but not routable from the workstation. Use `--probe-address host[:port]` to keep tracing the original Gateway URL while dialing a local proxy address for the workstation-side probe:

```powershell
knm check gateway `
  --url https://microservices.local/users `
  --probe `
  --probe-address 127.0.0.1:61128
```

## Check Service

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

This checks the target Service, backend pods, EndpointSlices, DNS, runtime reachability, direct pod reachability, NodePort/host exposure when applicable, MTU route snapshots, recent warning Events, and relevant policy.

If Istio is installed, readable, and involved in the path, `check service` also inspects mesh config that can explain Envoy responses such as `403 RBAC: access denied`, missing-JWT style `401` responses, `503 no healthy upstream`, intentional direct responses/redirects/faults, and mTLS/DestinationRule TLS mismatches.

Friendly resolver flags:

```text
--source             Resolve a source pod/workload/service name automatically.
--source-context     Use a different kubeconfig context for the source side.
--source-deployment  Resolve a source Deployment directly.
--source-pod         Use an exact source pod.
--source-selector    Use an explicit source label selector.
--target-selector    Override the target backend pod selector.
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

## Check Egress

Use this when a pod cannot reach an outbound URL, whether that target is internet-facing, private, or cluster-local.

```powershell
knm check egress `
  --cluster prod `
  --source-namespace apps `
  --source-selector app=api `
  --url https://example.com `
  --html .\reports\egress.html
```

Repeat `--url` to test more than one destination:

```powershell
knm check egress `
  --source-namespace apps `
  --source-selector app=api `
  --url https://example.com `
  --url https://login.microsoftonline.com
```

This checks source pod DNS, URL resolution, HTTP reachability, whether the URL is local, cluster-local, or external, native NetworkPolicy egress posture, Calico outbound posture, and Cilium outbound/DNS posture when available.

## Discover

Use `discover` when an alert gives you an app/workload-ish name and you need to figure out what to pass to `knm`.

```powershell
knm discover checkout-client --cluster prod --namespace apps
```

Use `*` to list everything in scope when you do not know what to search for yet:

```powershell
knm discover * --cluster prod --namespace apps
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

Typical output:

```text
NAMESPACE    NAME             KINDS          HINT
gnarly-src   checkout-client  deploy,pod,rs  source=checkout-client selector=app=checkout,role=client
```

Discovery output is grouped by default. Use `--wide` to show every matched object as a separate row.

## Show Blockers

Use this when you want policy-only analysis without runtime checks.

`show blockers` evaluates native Kubernetes NetworkPolicy, Calico policy, and Cilium policy when the related CRDs are installed and readable. It can also run in preflight mode with labels and a service account before a pod exists.

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

Use `--wide` for more detail.

Path-specific target flags:

```text
--to-namespace  Target namespace for path-specific policy evaluation.
--to-service    Target Service for path-specific policy evaluation.
--to-selector   Target pod selector override.
```

## Reports And Automation

Most diagnostic commands support:

```text
--html path
--json path
--quiet
--no-terminal
--fail-on-warn
--ignore-warn category[,category]
```

HTML reports are for humans. JSON reports are for automation, CI, issue attachments, and downstream tooling.

Terminal output modes:

- default: print the full terminal report
- `--quiet`: print only the inferred diagnosis
- `--no-terminal` / `--no-term`: print no successful stdout output, useful when writing JSON/HTML for automation

## Permissions

`knm` needs read access to the resources it inspects. Depending on the command, that can include:

- Namespaces
- Nodes
- Deployments, StatefulSets, DaemonSets, ReplicaSets
- Pods
- Services
- EndpointSlices
- Events
- Ingresses for discovery results
- NetworkPolicies
- Gateway API resources
- Envoy Gateway CRDs and experimental Gateway policy CRDs when installed
- Calico CRDs
- Cilium CRDs
- Istio CRDs: AuthorizationPolicies, RequestAuthentications, PeerAuthentications, Sidecars, VirtualServices, and DestinationRules

Runtime checks require permission to exec into the selected source pod. Debug-pod checks require permission to create and delete the debug pod.

## Security Scanning

KubeNetMods release hardening uses several checks before publishing:

- `go test ./...` for regression coverage
- `go test -race ./...` for data race detection
- `go vet ./...` for Go correctness checks
- `govulncheck ./...` for reachable Go dependency vulnerabilities
- `gosec ./...` for security-oriented static analysis

Release artifacts also include SHA256 checksums and GitHub build provenance attestations. Windows Authenticode publisher signing is not configured yet.

## Examples

The `examples/` directory contains sample alerts, HTML reports, JSON reports, and demo media. The Istio examples under `examples/reports/istio/` show real `check service` diagnoses for AuthorizationPolicy, RequestAuthentication, VirtualService, DestinationRule, Sidecar, and mTLS failure cases.

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

## License

AGPL-3.0. See [LICENSE](./LICENSE).
