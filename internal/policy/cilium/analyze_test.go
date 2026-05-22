package cilium

import (
	"strings"
	"testing"

	ciliumapi "github.com/cilium/cilium/pkg/policy/api"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"
	"k8s.io/apimachinery/pkg/util/intstr"
)

func TestCiliumEgressServiceSelectorMismatchIsAmbiguousWhenPortMatches(t *testing.T) {
	sourceNS := namespace("apps", map[string]string{"role": "dev"})
	targetNS := namespace("data", nil)
	source := pod("apps", "api", map[string]string{"app": "api"}, "default", "")
	target := pod("data", "db-1", map[string]string{"app": "db"}, "default", "10.2.0.9")
	svc := service("data", "postgres", map[string]string{"app": "postgres"}, 5432, intstr.FromInt(5432))
	rules := []namedRule{{
		Name: "apps/allow-wrong-service-label",
		Rule: &ciliumapi.Rule{
			EndpointSelector: es(map[string]string{"app": "api"}),
			Egress: []ciliumapi.EgressRule{{
				EgressCommonRule: ciliumapi.EgressCommonRule{
					ToServices: []ciliumapi.Service{{
						K8sServiceSelector: &ciliumapi.K8sServiceSelectorNamespace{
							Selector:  ciliumapi.ServiceSelector(es(map[string]string{"app": "mysql"})),
							Namespace: "data",
						},
					}},
				},
				ToPorts: ciliumapi.PortRules{{Ports: []ciliumapi.PortProtocol{{Port: "5432", Protocol: ciliumapi.ProtoTCP}}}},
			}},
		},
	}}

	got := ciliumEgressDecision(rules, targetNS, []corev1.Pod{target}, sourceNS, source, &svc, ciliumPathPortCandidates([]int32{5432}, &svc, []corev1.Pod{target}), "default", nil)
	if got.Status != "WARN" {
		t.Fatalf("status = %s, want WARN; message=%s", got.Status, got.Message)
	}
	if !strings.Contains(got.Message, "toServices selector does not match target Service labels") {
		t.Fatalf("message should explain service label miss, got: %s", got.Message)
	}
}

func TestCiliumEgressDefaultDenyWhenNoAllowPortMatches(t *testing.T) {
	sourceNS := namespace("apps", nil)
	targetNS := namespace("data", nil)
	source := pod("apps", "api", map[string]string{"app": "api"}, "default", "")
	target := pod("data", "db-1", map[string]string{"app": "db"}, "default", "10.2.0.9")
	svc := service("data", "postgres", map[string]string{"app": "postgres"}, 5432, intstr.FromInt(5432))
	rules := []namedRule{{
		Name: "apps/dns-only",
		Rule: &ciliumapi.Rule{
			EndpointSelector: es(map[string]string{"app": "api"}),
			Egress: []ciliumapi.EgressRule{{
				EgressCommonRule: ciliumapi.EgressCommonRule{ToEndpoints: []ciliumapi.EndpointSelector{es(map[string]string{"k8s-app": "kube-dns"})}},
				ToPorts:          ciliumapi.PortRules{{Ports: []ciliumapi.PortProtocol{{Port: "53", Protocol: ciliumapi.ProtoUDP}}}},
			}},
		},
	}}

	got := ciliumEgressDecision(rules, targetNS, []corev1.Pod{target}, sourceNS, source, &svc, ciliumPathPortCandidates([]int32{5432}, &svc, []corev1.Pod{target}), "default", nil)
	if got.Status != "FAIL" {
		t.Fatalf("status = %s, want FAIL; message=%s", got.Status, got.Message)
	}
	if !strings.Contains(got.Message, "no egress allow rule permits") {
		t.Fatalf("message should explain default deny, got: %s", got.Message)
	}
}

func TestCiliumShowBlockersEgressDenyPortPosture(t *testing.T) {
	sourceNS := namespace("apps", nil)
	source := pod("apps", "api", map[string]string{"app": "api"}, "default", "")
	rules := []namedRule{{
		Name: "apps/deny-db",
		Rule: &ciliumapi.Rule{
			EndpointSelector: es(map[string]string{"app": "api"}),
			EgressDeny: []ciliumapi.EgressDenyRule{{
				ToPorts: ciliumapi.PortDenyRules{{Ports: []ciliumapi.PortProtocol{{Port: "5432", Protocol: ciliumapi.ProtoTCP}}}},
			}},
		},
	}}

	got := ciliumEgressPortPosture(rules, sourceNS, source, []ciliumPortCandidate{{Number: 5432, Protocol: "TCP"}}, "5432", "default")
	if got.Status != "FAIL" {
		t.Fatalf("status = %s, want FAIL; message=%s", got.Status, got.Message)
	}
	if !strings.Contains(got.Message, "explicitly Denies TCP/5432") {
		t.Fatalf("message should explain explicit deny, got: %s", got.Message)
	}
}

func TestCiliumShowBlockersEgressDefaultDenyPortPosture(t *testing.T) {
	sourceNS := namespace("apps", nil)
	source := pod("apps", "api", map[string]string{"app": "api"}, "default", "")
	rules := []namedRule{{
		Name: "apps/dns-only",
		Rule: &ciliumapi.Rule{
			EndpointSelector: es(map[string]string{"app": "api"}),
			Egress: []ciliumapi.EgressRule{{
				ToPorts: ciliumapi.PortRules{{Ports: []ciliumapi.PortProtocol{{Port: "53", Protocol: ciliumapi.ProtoUDP}}}},
			}},
		},
	}}

	got := ciliumEgressPortPosture(rules, sourceNS, source, []ciliumPortCandidate{{Number: 5432, Protocol: "TCP"}}, "5432", "default")
	if got.Status != "FAIL" {
		t.Fatalf("status = %s, want FAIL; message=%s", got.Status, got.Message)
	}
	if !strings.Contains(got.Message, "no egress allow rule mentions TCP/5432") {
		t.Fatalf("message should explain default deny, got: %s", got.Message)
	}
}

func TestCiliumExternalEgressAllowFQDN(t *testing.T) {
	sourceNS := namespace("apps", nil)
	source := pod("apps", "api", map[string]string{"app": "api"}, "default", "")
	rules := []namedRule{{
		Name: "apps/allow-example",
		Rule: &ciliumapi.Rule{
			EndpointSelector: es(map[string]string{"app": "api"}),
			Egress: []ciliumapi.EgressRule{{
				ToFQDNs: ciliumapi.FQDNSelectorSlice{{MatchName: "example.com"}},
				ToPorts: ciliumapi.PortRules{{Ports: []ciliumapi.PortProtocol{{Port: "443", Protocol: ciliumapi.ProtoTCP}}}},
			}},
		},
	}}

	got := ciliumExternalEgressDecision(rules, sourceNS, source, "example.com", 443, "default")
	if got.Status != "PASS" {
		t.Fatalf("status = %s, want PASS; message=%s", got.Status, got.Message)
	}
	if !strings.Contains(got.Message, "toFQDNs matches example.com") {
		t.Fatalf("message should explain FQDN match, got: %s", got.Message)
	}
}

func TestCiliumExternalEgressDenyWorld(t *testing.T) {
	sourceNS := namespace("apps", nil)
	source := pod("apps", "api", map[string]string{"app": "api"}, "default", "")
	rules := []namedRule{{
		Name: "apps/deny-world",
		Rule: &ciliumapi.Rule{
			EndpointSelector: es(map[string]string{"app": "api"}),
			EgressDeny: []ciliumapi.EgressDenyRule{{
				EgressCommonRule: ciliumapi.EgressCommonRule{ToEntities: ciliumapi.EntitySlice{ciliumapi.EntityWorld}},
				ToPorts:          ciliumapi.PortDenyRules{{Ports: []ciliumapi.PortProtocol{{Port: "443", Protocol: ciliumapi.ProtoTCP}}}},
			}},
		},
	}}

	got := ciliumExternalEgressDecision(rules, sourceNS, source, "example.com", 443, "default")
	if got.Status != "FAIL" {
		t.Fatalf("status = %s, want FAIL; message=%s", got.Status, got.Message)
	}
	if !strings.Contains(got.Message, "egressDeny blocks") {
		t.Fatalf("message should explain egressDeny, got: %s", got.Message)
	}
}

func TestCiliumExternalEgressDefaultDenyWhenFQDNMisses(t *testing.T) {
	sourceNS := namespace("apps", nil)
	source := pod("apps", "api", map[string]string{"app": "api"}, "default", "")
	rules := []namedRule{{
		Name: "apps/allow-other-host",
		Rule: &ciliumapi.Rule{
			EndpointSelector: es(map[string]string{"app": "api"}),
			Egress: []ciliumapi.EgressRule{{
				ToFQDNs: ciliumapi.FQDNSelectorSlice{{MatchName: "allowed.example.com"}},
				ToPorts: ciliumapi.PortRules{{Ports: []ciliumapi.PortProtocol{{Port: "443", Protocol: ciliumapi.ProtoTCP}}}},
			}},
		},
	}}

	got := ciliumExternalEgressDecision(rules, sourceNS, source, "example.com", 443, "default")
	if got.Status != "FAIL" {
		t.Fatalf("status = %s, want FAIL; message=%s", got.Status, got.Message)
	}
	if !strings.Contains(got.Message, "no egress allow rule permits outbound target") {
		t.Fatalf("message should explain outbound default-deny, got: %s", got.Message)
	}
}

func TestCiliumNamedTargetPortAllow(t *testing.T) {
	sourceNS := namespace("apps", nil)
	targetNS := namespace("data", nil)
	source := pod("apps", "api", map[string]string{"app": "api"}, "default", "")
	target := pod("data", "web-1", map[string]string{"app": "web"}, "default", "10.2.0.10")
	target.Spec.Containers = []corev1.Container{{
		Name:  "web",
		Ports: []corev1.ContainerPort{{Name: "web", ContainerPort: 8080, Protocol: corev1.ProtocolTCP}},
	}}
	svc := service("data", "web", map[string]string{"app": "web"}, 80, intstr.FromString("web"))
	rules := []namedRule{{
		Name: "apps/allow-web-name",
		Rule: &ciliumapi.Rule{
			EndpointSelector: es(map[string]string{"app": "api"}),
			Egress: []ciliumapi.EgressRule{{
				EgressCommonRule: ciliumapi.EgressCommonRule{ToEndpoints: []ciliumapi.EndpointSelector{es(map[string]string{"app": "web"})}},
				ToPorts:          ciliumapi.PortRules{{Ports: []ciliumapi.PortProtocol{{Port: "web", Protocol: ciliumapi.ProtoTCP}}}},
			}},
		},
	}}

	got := ciliumEgressDecision(rules, targetNS, []corev1.Pod{target}, sourceNS, source, &svc, ciliumPathPortCandidates([]int32{80}, &svc, []corev1.Pod{target}), "default", nil)
	if got.Status != "WARN" {
		t.Fatalf("status = %s, want WARN; message=%s", got.Status, got.Message)
	}
	if !strings.Contains(got.Message, "named port") {
		t.Fatalf("message should explain named-port ambiguity, got: %s", got.Message)
	}
}

func TestCiliumEndpointDenyUsesBackendPortNotServicePort(t *testing.T) {
	sourceNS := namespace("apps", nil)
	targetNS := namespace("data", nil)
	source := pod("apps", "api", map[string]string{"app": "api"}, "default", "")
	target := pod("data", "web-1", map[string]string{"app": "web"}, "default", "10.2.0.10")
	target.Spec.Containers = []corev1.Container{{
		Name:  "web",
		Ports: []corev1.ContainerPort{{Name: "web", ContainerPort: 8080, Protocol: corev1.ProtocolTCP}},
	}}
	svc := service("data", "web", map[string]string{"app": "web"}, 80, intstr.FromString("web"))
	rules := []namedRule{{
		Name: "apps/deny-service-frontend-port",
		Rule: &ciliumapi.Rule{
			EndpointSelector: es(map[string]string{"app": "api"}),
			EgressDeny: []ciliumapi.EgressDenyRule{{
				EgressCommonRule: ciliumapi.EgressCommonRule{ToEndpoints: []ciliumapi.EndpointSelector{es(map[string]string{"app": "web"})}},
				ToPorts:          ciliumapi.PortDenyRules{{Ports: []ciliumapi.PortProtocol{{Port: "80", Protocol: ciliumapi.ProtoTCP}}}},
			}},
			Egress: []ciliumapi.EgressRule{{
				EgressCommonRule: ciliumapi.EgressCommonRule{ToEndpoints: []ciliumapi.EndpointSelector{es(map[string]string{"app": "web"})}},
				ToPorts:          ciliumapi.PortRules{{Ports: []ciliumapi.PortProtocol{{Port: "web", Protocol: ciliumapi.ProtoTCP}}}},
			}},
		},
	}}

	got := ciliumEgressDecision(rules, targetNS, []corev1.Pod{target}, sourceNS, source, &svc, ciliumPathPortCandidates([]int32{80}, &svc, []corev1.Pod{target}), "default", nil)
	if got.Status != "WARN" {
		t.Fatalf("status = %s, want WARN because deny on service port 80 should not match backend 8080/web but named-port allow needs runtime verification; message=%s", got.Status, got.Message)
	}
}

func TestCiliumEgressDenyOnlyStillEnforcesDefaultDeny(t *testing.T) {
	sourceNS := namespace("apps", nil)
	targetNS := namespace("data", nil)
	source := pod("apps", "api", map[string]string{"app": "api"}, "default", "")
	target := pod("data", "web-1", map[string]string{"app": "web"}, "default", "10.2.0.10")
	target.Spec.Containers = []corev1.Container{{
		Name:  "web",
		Ports: []corev1.ContainerPort{{Name: "web", ContainerPort: 8080, Protocol: corev1.ProtocolTCP}},
	}}
	svc := service("data", "web", map[string]string{"app": "web"}, 80, intstr.FromString("web"))
	rules := []namedRule{{
		Name: "apps/deny-unrelated-port",
		Rule: &ciliumapi.Rule{
			EndpointSelector: es(map[string]string{"app": "api"}),
			EgressDeny: []ciliumapi.EgressDenyRule{{
				EgressCommonRule: ciliumapi.EgressCommonRule{ToEndpoints: []ciliumapi.EndpointSelector{es(map[string]string{"app": "web"})}},
				ToPorts:          ciliumapi.PortDenyRules{{Ports: []ciliumapi.PortProtocol{{Port: "9999", Protocol: ciliumapi.ProtoTCP}}}},
			}},
		},
	}}

	got := ciliumEgressDecision(rules, targetNS, []corev1.Pod{target}, sourceNS, source, &svc, ciliumPathPortCandidates([]int32{80}, &svc, []corev1.Pod{target}), "default", nil)
	if got.Status != "FAIL" {
		t.Fatalf("status = %s, want FAIL because deny-only policy still selects/enforces egress; message=%s", got.Status, got.Message)
	}
	if !strings.Contains(got.Message, "no egress allow rule permits") {
		t.Fatalf("message should explain default deny from selected deny-only policy, got: %s", got.Message)
	}
}

func TestCiliumIngressDenyOnlyStillEnforcesDefaultDeny(t *testing.T) {
	sourceNS := namespace("apps", nil)
	targetNS := namespace("data", nil)
	source := pod("apps", "api", map[string]string{"app": "api"}, "default", "")
	target := pod("data", "web-1", map[string]string{"app": "web"}, "default", "10.2.0.10")
	target.Spec.Containers = []corev1.Container{{
		Name:  "web",
		Ports: []corev1.ContainerPort{{Name: "web", ContainerPort: 8080, Protocol: corev1.ProtocolTCP}},
	}}
	svc := service("data", "web", map[string]string{"app": "web"}, 80, intstr.FromString("web"))
	rules := []namedRule{{
		Name: "data/deny-unrelated-port",
		Rule: &ciliumapi.Rule{
			EndpointSelector: es(map[string]string{"app": "web"}),
			IngressDeny: []ciliumapi.IngressDenyRule{{
				IngressCommonRule: ciliumapi.IngressCommonRule{FromEndpoints: []ciliumapi.EndpointSelector{es(map[string]string{"app": "api"})}},
				ToPorts:           ciliumapi.PortDenyRules{{Ports: []ciliumapi.PortProtocol{{Port: "9999", Protocol: ciliumapi.ProtoTCP}}}},
			}},
		},
	}}

	got := ciliumIngressDecision(rules, targetNS, []corev1.Pod{target}, sourceNS, source, &svc, ciliumPathPortCandidates([]int32{80}, &svc, []corev1.Pod{target}), "default")
	if got.Status != "FAIL" {
		t.Fatalf("status = %s, want FAIL because deny-only policy still selects/enforces ingress; message=%s", got.Status, got.Message)
	}
	if !strings.Contains(got.Message, "no ingress allow rule permits") {
		t.Fatalf("message should explain default deny from selected deny-only policy, got: %s", got.Message)
	}
}

func TestCiliumL7AllowIsWarnNotCleanPass(t *testing.T) {
	sourceNS := namespace("apps", nil)
	targetNS := namespace("data", nil)
	source := pod("apps", "api", map[string]string{"app": "api"}, "default", "")
	target := pod("data", "web-1", map[string]string{"app": "web"}, "default", "10.2.0.10")
	target.Spec.Containers = []corev1.Container{{
		Name:  "web",
		Ports: []corev1.ContainerPort{{Name: "web", ContainerPort: 8080, Protocol: corev1.ProtocolTCP}},
	}}
	svc := service("data", "web", map[string]string{"app": "web"}, 80, intstr.FromString("web"))
	rules := []namedRule{{
		Name: "apps/allow-web-get-only",
		Rule: &ciliumapi.Rule{
			EndpointSelector: es(map[string]string{"app": "api"}),
			Egress: []ciliumapi.EgressRule{{
				EgressCommonRule: ciliumapi.EgressCommonRule{ToEndpoints: []ciliumapi.EndpointSelector{es(map[string]string{"app": "web"})}},
				ToPorts: ciliumapi.PortRules{{
					Ports: []ciliumapi.PortProtocol{{Port: "web", Protocol: ciliumapi.ProtoTCP}},
					Rules: &ciliumapi.L7Rules{HTTP: []ciliumapi.PortRuleHTTP{{Method: "GET", Path: "/healthz"}}},
				}},
			}},
		},
	}}

	got := ciliumEgressDecision(rules, targetNS, []corev1.Pod{target}, sourceNS, source, &svc, ciliumPathPortCandidates([]int32{80}, &svc, []corev1.Pod{target}), "default", nil)
	if got.Status != "WARN" {
		t.Fatalf("status = %s, want WARN for L7-constrained allow; message=%s", got.Status, got.Message)
	}
	if !strings.Contains(got.Message, "L7 constraints") && !strings.Contains(got.Message, "HTTP") {
		t.Fatalf("message should mention L7/HTTP constraints, got: %s", got.Message)
	}
}

func TestCiliumCIDRDenyAgainstInClusterEndpointIsAmbiguous(t *testing.T) {
	sourceNS := namespace("apps", nil)
	targetNS := namespace("data", nil)
	source := pod("apps", "api", map[string]string{"app": "api"}, "default", "")
	target := pod("data", "web-1", map[string]string{"app": "web"}, "default", "10.2.0.10")
	target.Spec.Containers = []corev1.Container{{
		Name:  "web",
		Ports: []corev1.ContainerPort{{Name: "web", ContainerPort: 8080, Protocol: corev1.ProtocolTCP}},
	}}
	svc := service("data", "web", map[string]string{"app": "web"}, 80, intstr.FromString("web"))
	rules := []namedRule{{
		Name: "apps/deny-pod-cidr",
		Rule: &ciliumapi.Rule{
			EndpointSelector: es(map[string]string{"app": "api"}),
			EgressDeny: []ciliumapi.EgressDenyRule{{
				EgressCommonRule: ciliumapi.EgressCommonRule{ToCIDR: ciliumapi.CIDRSlice{"10.2.0.10/32"}},
				ToPorts:          ciliumapi.PortDenyRules{{Ports: []ciliumapi.PortProtocol{{Port: "web", Protocol: ciliumapi.ProtoTCP}}}},
			}},
			Egress: []ciliumapi.EgressRule{{
				EgressCommonRule: ciliumapi.EgressCommonRule{ToEntities: ciliumapi.EntitySlice{ciliumapi.EntityCluster}},
				ToPorts:          ciliumapi.PortRules{{Ports: []ciliumapi.PortProtocol{{Port: "web", Protocol: ciliumapi.ProtoTCP}}}},
			}},
		},
	}}

	got := ciliumEgressDecision(rules, targetNS, []corev1.Pod{target}, sourceNS, source, &svc, ciliumPathPortCandidates([]int32{80}, &svc, []corev1.Pod{target}), "default", nil)
	if got.Status != "WARN" {
		t.Fatalf("status = %s, want WARN for in-cluster CIDR deny ambiguity; message=%s", got.Status, got.Message)
	}
	if !strings.Contains(got.Message, "CIDR") {
		t.Fatalf("message should mention CIDR ambiguity, got: %s", got.Message)
	}
}

func TestCiliumDNSNodeLocalResolverBlocked(t *testing.T) {
	sourceNS := namespace("apps", nil)
	source := pod("apps", "api", map[string]string{"app": "api"}, "default", "")
	coredns := pod("kube-system", "coredns", map[string]string{"k8s-app": "kube-dns"}, "default", "10.244.0.10")
	nodeLocal := pod("kube-system", "node-local-dns", map[string]string{"k8s-app": "node-local-dns"}, "default", "169.254.20.10")
	rules := []namedRule{{
		Name: "apps/allow-coredns-only",
		Rule: &ciliumapi.Rule{
			EndpointSelector: es(map[string]string{"app": "api"}),
			Egress: []ciliumapi.EgressRule{{
				EgressCommonRule: ciliumapi.EgressCommonRule{ToEndpoints: []ciliumapi.EndpointSelector{es(map[string]string{"k8s-app": "kube-dns"})}},
				ToPorts:          ciliumapi.PortRules{{Ports: []ciliumapi.PortProtocol{{Port: "53", Protocol: ciliumapi.ProtoUDP}}}},
			}},
		},
	}}

	got := analyzeCiliumDNS(rules, sourceNS, source, DNSContext{
		Nameservers:      []string{"169.254.20.10"},
		CoreDNSServiceIP: "10.96.0.10",
		CoreDNSPods:      []corev1.Pod{coredns},
		NodeLocalDNSPods: []corev1.Pod{nodeLocal},
	}, "default", nil)
	if len(got) != 1 || got[0].Status != "FAIL" {
		t.Fatalf("result = %#v, want one FAIL", got)
	}
	if !strings.Contains(got[0].Message, "169.254.20.10") {
		t.Fatalf("message should include runtime resolver, got: %s", got[0].Message)
	}
}

func TestCiliumDNSDenyOnlyPolicyStillEnforcesEgress(t *testing.T) {
	sourceNS := namespace("apps", nil)
	source := pod("apps", "api", map[string]string{"app": "api"}, "default", "")
	rules := []namedRule{{
		Name: "apps/deny-unrelated-web-port",
		Rule: &ciliumapi.Rule{
			EndpointSelector: es(map[string]string{"app": "api"}),
			EgressDeny: []ciliumapi.EgressDenyRule{{
				EgressCommonRule: ciliumapi.EgressCommonRule{ToEndpoints: []ciliumapi.EndpointSelector{es(map[string]string{"app": "web"})}},
				ToPorts:          ciliumapi.PortDenyRules{{Ports: []ciliumapi.PortProtocol{{Port: "9999", Protocol: ciliumapi.ProtoTCP}}}},
			}},
		},
	}}

	got := analyzeCiliumDNS(rules, sourceNS, source, DNSContext{
		Nameservers:      []string{"10.96.0.10"},
		CoreDNSServiceIP: "10.96.0.10",
	}, "default", nil)
	if len(got) != 1 || got[0].Status != "FAIL" {
		t.Fatalf("result = %#v, want one FAIL", got)
	}
	if !strings.Contains(got[0].Message, "no egress allow rule permits DNS") {
		t.Fatalf("message should explain DNS default deny, got: %s", got[0].Message)
	}
}

func TestCiliumDNSAllowsRuntimeResolverViaCIDRGroupRef(t *testing.T) {
	sourceNS := namespace("apps", nil)
	source := pod("apps", "api", map[string]string{"app": "api"}, "default", "")
	rules := []namedRule{{
		Name: "apps/allow-dns-cidrgroup",
		Rule: &ciliumapi.Rule{
			EndpointSelector: es(map[string]string{"app": "api"}),
			Egress: []ciliumapi.EgressRule{{
				EgressCommonRule: ciliumapi.EgressCommonRule{ToCIDRSet: ciliumapi.CIDRRuleSlice{{CIDRGroupRef: "cluster-dns"}}},
				ToPorts:          ciliumapi.PortRules{{Ports: []ciliumapi.PortProtocol{{Port: "53", Protocol: ciliumapi.ProtoUDP}}}},
			}},
		},
	}}

	got := analyzeCiliumDNS(rules, sourceNS, source, DNSContext{
		Nameservers: []string{"169.254.20.10"},
	}, "default", []ciliumCIDRGroup{{Name: "cluster-dns", CIDRs: []string{"169.254.20.10/32"}}})
	if len(got) != 1 || got[0].Status != "PASS" {
		t.Fatalf("result = %#v, want one PASS", got)
	}
}

func TestCiliumDNSServiceIPCIDRGroupDoesNotProveCoreDNSServicePath(t *testing.T) {
	sourceNS := namespace("apps", nil)
	source := pod("apps", "api", map[string]string{"app": "api"}, "default", "")
	coredns := pod("kube-system", "coredns", map[string]string{"k8s-app": "kube-dns"}, "default", "10.244.0.10")
	rules := []namedRule{{
		Name: "apps/allow-dns-service-cidrgroup",
		Rule: &ciliumapi.Rule{
			EndpointSelector: es(map[string]string{"app": "api"}),
			Egress: []ciliumapi.EgressRule{{
				EgressCommonRule: ciliumapi.EgressCommonRule{ToCIDRSet: ciliumapi.CIDRRuleSlice{{CIDRGroupRef: "cluster-dns-service"}}},
				ToPorts:          ciliumapi.PortRules{{Ports: []ciliumapi.PortProtocol{{Port: "53", Protocol: ciliumapi.ProtoUDP}}}},
			}},
		},
	}}

	got := analyzeCiliumDNS(rules, sourceNS, source, DNSContext{
		Nameservers:      []string{"10.96.0.10"},
		CoreDNSServiceIP: "10.96.0.10",
		CoreDNSPods:      []corev1.Pod{coredns},
	}, "default", []ciliumCIDRGroup{{Name: "cluster-dns-service", CIDRs: []string{"10.96.0.10/32"}}})
	if len(got) != 1 || got[0].Status != "FAIL" {
		t.Fatalf("result = %#v, want one FAIL because CoreDNS service-IP CIDR does not prove backend endpoint DNS path", got)
	}
}

func TestCiliumServiceAccountLabelParticipatesInSourceSelector(t *testing.T) {
	ns := namespace("apps", nil)
	p := pod("apps", "api", map[string]string{"app": "api"}, "jackryan", "")
	selector := es(map[string]string{"io.cilium.k8s.policy.serviceaccount": "jackryan"})
	if !ciliumEndpointSelectorMatches(selector, ciliumPodLabels(p, ns)) {
		t.Fatal("Cilium service account selector should match pod identity labels")
	}
}

func TestParsedCiliumPolicyEndpointSelectorMatchesSourcePod(t *testing.T) {
	ns := namespace("knm-cil-source", nil)
	source := pod("knm-cil-source", "client", map[string]string{"app": "client"}, "default", "")
	item := unstructured.Unstructured{Object: map[string]interface{}{
		"apiVersion": "cilium.io/v2",
		"kind":       "CiliumNetworkPolicy",
		"metadata": map[string]interface{}{
			"name":      "source-service-selector-mismatch",
			"namespace": "knm-cil-source",
		},
		"spec": map[string]interface{}{
			"endpointSelector": map[string]interface{}{"matchLabels": map[string]interface{}{"app": "client"}},
			"egress": []interface{}{
				map[string]interface{}{
					"toServices": []interface{}{
						map[string]interface{}{"k8sServiceSelector": map[string]interface{}{
							"namespace": "knm-cil-target",
							"selector":  map[string]interface{}{"matchLabels": map[string]interface{}{"app": "postgres"}},
						}},
					},
				},
			},
		},
	}}
	rules, _, err := ciliumPolicyRulesAndTargetMatch(item, ns, []corev1.Pod{source}, "default")
	if err != nil {
		t.Fatalf("parse error = %v", err)
	}
	if len(rules) != 1 {
		t.Fatalf("rules len = %d, want 1", len(rules))
	}
	if !ciliumEndpointSelectorMatches(rules[0].EndpointSelector, ciliumPodLabels(source, ns)) {
		t.Fatalf("parsed endpointSelector %q should match source labels %#v", rules[0].EndpointSelector.String(), ciliumPodLabels(source, ns))
	}
}

func es(labels map[string]string) ciliumapi.EndpointSelector {
	return ciliumapi.NewESFromMatchRequirements(labels, nil)
}

func namespace(name string, labels map[string]string) corev1.Namespace {
	return corev1.Namespace{ObjectMeta: metav1.ObjectMeta{Name: name, Labels: labels}}
}

func pod(namespace, name string, labels map[string]string, serviceAccount, ip string) corev1.Pod {
	return corev1.Pod{
		ObjectMeta: metav1.ObjectMeta{Name: name, Namespace: namespace, Labels: labels},
		Spec:       corev1.PodSpec{ServiceAccountName: serviceAccount},
		Status:     corev1.PodStatus{PodIP: ip},
	}
}

func service(namespace, name string, labels map[string]string, port int32, targetPort intstr.IntOrString) corev1.Service {
	return corev1.Service{
		ObjectMeta: metav1.ObjectMeta{Name: name, Namespace: namespace, Labels: labels},
		Spec: corev1.ServiceSpec{
			ClusterIP: "10.96.10.10",
			Ports: []corev1.ServicePort{{
				Name:       "http",
				Protocol:   corev1.ProtocolTCP,
				Port:       port,
				TargetPort: targetPort,
			}},
		},
	}
}
