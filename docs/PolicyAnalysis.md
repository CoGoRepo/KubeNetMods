# Policy Analysis

KubeNetMods includes policy analysis for the source-to-target path tested by `Test-KubeNetService`.

It is meant to answer:

```text
Does a policy obviously explain this failed path?
```

## Native Kubernetes NetworkPolicy

KubeNetMods can inspect:

- source egress isolation
- target ingress isolation
- DNS egress hints
- namespace selectors
- pod selectors
- common port/protocol matching
- likely source-to-target allow/block interpretation

Native Kubernetes NetworkPolicy is additive allow-list behavior. There is no explicit deny action in the base Kubernetes API.

## Calico

KubeNetMods can inspect:

- Calico `NetworkPolicy`
- Calico `GlobalNetworkPolicy`
- staged policy visibility for `StagedNetworkPolicy` and `StagedGlobalNetworkPolicy`
- tier order and ordered first-match behavior
- `Allow`, `Deny`, `Pass`, and `Log` actions
- source egress default-deny and target ingress default-deny
- missing DNS egress allow hints
- runtime DNS resolver checks, including CoreDNS service IP and NodeLocalDNS/link-local resolver paths
- namespace selectors, pod selectors, and common selector operators
- numeric ports, named ports, port ranges, and protocol matching
- `notSelector`, `notPorts`, `nets`, `notNets`
- destination `services` matches
- `NetworkSet` and `GlobalNetworkSet`
- cases where a later Deny matches but an earlier Allow wins

Calico analysis is heuristic. It does not fully emulate workload profiles after `Pass`, every tier/default-action edge case, service account selectors, pre-DNAT policy, host endpoint policy, every selector expression, or live dataplane state.

## Cilium

KubeNetMods can inspect:

- `CiliumNetworkPolicy`
- `CiliumClusterwideNetworkPolicy`
- `endpointSelector`
- `toEndpoints` and `fromEndpoints`
- namespace labels, pod labels, service-account labels, and common `matchExpressions`
- `egressDeny` and `ingressDeny`
- explicit deny priority over allow rules
- source egress default-deny and target ingress default-deny
- numeric ports, named ports, and protocol matching through `toPorts`
- common DNS egress allow hints
- runtime DNS resolver checks, including CoreDNS service IP and NodeLocalDNS/link-local resolver paths
- simple `toEntities` / `fromEntities` cases such as `all` and `cluster`
- `toCIDR`, `fromCIDR`, `toCIDRSet`, and `fromCIDRSet` matches against target/source IPs, including common `except` handling
- `toServices` with `k8sService` and `k8sServiceSelector`
- `toRequires` / `fromRequires` as additional peer constraints
- L7/TLS/server-name constraint detection when an L4 path appears allowed but application traffic still fails
- advanced selector visibility for items such as `toFQDNs` and `toGroups`

Cilium analysis is heuristic. It does not fully emulate Cilium identity resolution, dynamic FQDN policy resolution, every entity, every selector form, service-aware implementation detail, exact L7 HTTP/Kafka/DNS policy behavior, eBPF dataplane state, or Hubble flow history.

## Important Boundary

Policy analysis is not a replacement for CNI-native tools, packet captures, flow logs, or dataplane inspection.

It is a fast path-narrowing tool. If KubeNetMods says a policy likely blocks the path, it gives you a strong place to start. If it does not find a policy block, provider dataplane state can still matter.
