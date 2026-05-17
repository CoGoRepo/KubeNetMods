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

Calico currently has the deeper provider-specific analyzer.

KubeNetMods can inspect:

- Calico `NetworkPolicy`
- Calico `GlobalNetworkPolicy`
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

Calico analysis is heuristic. It does not fully emulate workload profiles after `Pass`, every tier/default-action edge case, service account selectors, pre-DNAT policy, host endpoint policy, every selector expression, or live dataplane state.

## Cilium

Cilium analysis is currently shallower than Calico.

KubeNetMods can inspect:

- `CiliumNetworkPolicy`
- `CiliumClusterwideNetworkPolicy`
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

## Important Boundary

Policy analysis is not a replacement for CNI-native tools, packet captures, flow logs, or dataplane inspection.

It is a fast path-narrowing tool. If KubeNetMods says a policy likely blocks the path, it gives you a strong place to start. If it does not find a policy block, provider dataplane state can still matter.
