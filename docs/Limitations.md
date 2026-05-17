# Limitations

KubeNetMods is a troubleshooting assistant, not a full Kubernetes dataplane simulator.

## Not Covered

- Gateway API resources such as `Gateway`, `HTTPRoute`, `TLSRoute`, or `GRPCRoute`
- deep service mesh config such as Istio, Linkerd, or Consul
- provider-specific dataplane commands such as `cilium monitor`, `cilium policy trace`, `calicoctl`, Felix inspection, or BPF inspection
- deep kube-proxy iptables, IPVS, or eBPF map inspection
- node route table inspection
- cloud route table, load balancer, firewall, WAF, or security group API calls
- path-MTU discovery, packet-size probing, or DF-bit testing
- application authentication, authorization, or business logic
- country/region edge-provider outages unless they appear through explicit external URL tests

## Heuristic Areas

These areas are intentionally heuristic:

- native Kubernetes NetworkPolicy interpretation
- Calico/Cilium policy interpretation
- Ingress controller detection
- Ingress annotation visibility
- CNI/provider detection
- alert payload normalization

## Good Use

KubeNetMods is best used to narrow the failure domain quickly:

```text
Service selector?
EndpointSlice?
Pod readiness?
DNS?
NetworkPolicy?
CNI-specific policy?
Ingress mapping?
LoadBalancer reachability?
External egress?
```

When KubeNetMods identifies a likely root cause, use the native platform tools to confirm and fix.
