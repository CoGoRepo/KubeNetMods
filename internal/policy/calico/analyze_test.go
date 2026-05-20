package calico

import (
	"strings"
	"testing"

	"github.com/CoGoRepo/KubeNetMods/internal/policy"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"
	"k8s.io/apimachinery/pkg/util/intstr"
)

func TestCalicoFirstMatchAllowBeforeLaterDeny(t *testing.T) {
	sourceNS, targetNS, sourcePod, targetPod, service := calicoTestPath()
	policies := []unstructured.Unstructured{
		calicoPolicy("allow-web", "knm-source", "default", 100, `app == "client"`, "Egress", "Allow", map[string]interface{}{
			"selector":          `app == "web"`,
			"namespaceSelector": `projectcalico.org/name == "knm-target"`,
			"ports":             []interface{}{float64(80)},
		}),
		calicoPolicy("deny-web-later", "knm-source", "default", 200, `app == "client"`, "Egress", "Deny", map[string]interface{}{
			"selector":          `app == "web"`,
			"namespaceSelector": `projectcalico.org/name == "knm-target"`,
			"ports":             []interface{}{float64(80)},
		}),
	}

	insight := calicoDirectionDecision(policies, "egress", nil, nil, nil, nil, sourceNS, sourcePod, targetNS, []corev1.Pod{targetPod}, &service, []int32{80, 8080})
	if insight.Status != "PASS" {
		t.Fatalf("status = %s, want PASS. message=%s", insight.Status, insight.Message)
	}
}

func TestCalicoFirstMatchDenyBeforeAllow(t *testing.T) {
	sourceNS, targetNS, sourcePod, targetPod, service := calicoTestPath()
	policies := []unstructured.Unstructured{
		calicoPolicy("deny-web", "knm-source", "default", 100, `app == "client"`, "Egress", "Deny", map[string]interface{}{
			"selector":          `app == "web"`,
			"namespaceSelector": `projectcalico.org/name == "knm-target"`,
			"ports":             []interface{}{float64(80)},
		}),
		calicoPolicy("allow-web-later", "knm-source", "default", 200, `app == "client"`, "Egress", "Allow", map[string]interface{}{
			"selector":          `app == "web"`,
			"namespaceSelector": `projectcalico.org/name == "knm-target"`,
			"ports":             []interface{}{float64(80)},
		}),
	}

	insight := calicoDirectionDecision(policies, "egress", nil, nil, nil, nil, sourceNS, sourcePod, targetNS, []corev1.Pod{targetPod}, &service, []int32{80, 8080})
	if insight.Status != "FAIL" {
		t.Fatalf("status = %s, want FAIL. message=%s", insight.Status, insight.Message)
	}
	if insight.Diagnosis == "" {
		t.Fatal("expected diagnosis for deny")
	}
}

func TestCalicoMultiplePassTiersReachAllow(t *testing.T) {
	sourceNS, targetNS, sourcePod, targetPod, service := calicoTestPath()
	policies := []unstructured.Unstructured{
		calicoPolicy("pass-a", "knm-source", "edge-a", 10, `app == "client"`, "Egress", "Pass", map[string]interface{}{
			"selector":          `app == "web"`,
			"namespaceSelector": `projectcalico.org/name == "knm-target"`,
			"ports":             []interface{}{float64(80)},
		}),
		calicoPolicy("pass-b", "knm-source", "edge-b", 10, `app == "client"`, "Egress", "Pass", map[string]interface{}{
			"selector":          `app == "web"`,
			"namespaceSelector": `projectcalico.org/name == "knm-target"`,
			"ports":             []interface{}{float64(80)},
		}),
		calicoPolicy("pass-c", "knm-source", "edge-c", 10, `app == "client"`, "Egress", "Pass", map[string]interface{}{
			"selector":          `app == "web"`,
			"namespaceSelector": `projectcalico.org/name == "knm-target"`,
			"ports":             []interface{}{float64(80)},
		}),
		calicoPolicy("allow-final", "knm-source", "edge-final", 10, `app == "client"`, "Egress", "Allow", map[string]interface{}{
			"selector":          `app == "web"`,
			"namespaceSelector": `projectcalico.org/name == "knm-target"`,
			"ports":             []interface{}{float64(80)},
		}),
	}
	tiers := []unstructured.Unstructured{
		calicoTier("edge-a", 100),
		calicoTier("edge-b", 200),
		calicoTier("edge-c", 300),
		calicoTier("edge-final", 400),
	}

	insight := calicoDirectionDecision(policies, "egress", tiers, nil, nil, nil, sourceNS, sourcePod, targetNS, []corev1.Pod{targetPod}, &service, []int32{80})
	if insight.Status != "PASS" {
		t.Fatalf("status = %s, want PASS after pass chain. message=%s", insight.Status, insight.Message)
	}
}

func TestCalicoMultiplePassTiersReachDeny(t *testing.T) {
	sourceNS, targetNS, sourcePod, targetPod, service := calicoTestPath()
	policies := []unstructured.Unstructured{
		calicoPolicy("pass-a", "knm-source", "edge-a", 10, `app == "client"`, "Egress", "Pass", map[string]interface{}{
			"selector":          `app == "web"`,
			"namespaceSelector": `projectcalico.org/name == "knm-target"`,
			"ports":             []interface{}{float64(80)},
		}),
		calicoPolicy("pass-b", "knm-source", "edge-b", 10, `app == "client"`, "Egress", "Pass", map[string]interface{}{
			"selector":          `app == "web"`,
			"namespaceSelector": `projectcalico.org/name == "knm-target"`,
			"ports":             []interface{}{float64(80)},
		}),
		calicoPolicy("deny-final", "knm-source", "edge-final", 10, `app == "client"`, "Egress", "Deny", map[string]interface{}{
			"selector":          `app == "web"`,
			"namespaceSelector": `projectcalico.org/name == "knm-target"`,
			"ports":             []interface{}{float64(80)},
		}),
	}
	tiers := []unstructured.Unstructured{
		calicoTier("edge-a", 100),
		calicoTier("edge-b", 200),
		calicoTier("edge-final", 300),
	}

	insight := calicoDirectionDecision(policies, "egress", tiers, nil, nil, nil, sourceNS, sourcePod, targetNS, []corev1.Pod{targetPod}, &service, []int32{80})
	if insight.Status != "FAIL" {
		t.Fatalf("status = %s, want FAIL after pass chain reaches deny. message=%s", insight.Status, insight.Message)
	}
}

func TestCalicoNetworkSetCanSatisfySelector(t *testing.T) {
	sourceNS, targetNS, sourcePod, targetPod, service := calicoTestPath()
	targetPod.Status.PodIP = "10.244.1.20"
	networkSet := unstructured.Unstructured{Object: map[string]interface{}{
		"kind": "NetworkSet",
		"metadata": map[string]interface{}{
			"name":      "target-cidr",
			"namespace": "knm-target",
			"labels": map[string]interface{}{
				"role": "target-network",
			},
		},
		"spec": map[string]interface{}{
			"nets": []interface{}{"10.244.1.0/24"},
		},
	}}
	policies := []unstructured.Unstructured{
		calicoPolicy("allow-networkset", "knm-source", "default", 100, `app == "client"`, "Egress", "Allow", map[string]interface{}{
			"selector":          `role == "target-network"`,
			"namespaceSelector": `projectcalico.org/name == "knm-target"`,
			"ports":             []interface{}{float64(80)},
		}),
	}

	insight := calicoDirectionDecision(policies, "egress", nil, []unstructured.Unstructured{networkSet}, nil, nil, sourceNS, sourcePod, targetNS, []corev1.Pod{targetPod}, &service, []int32{80})
	if insight.Status != "PASS" {
		t.Fatalf("status = %s, want PASS. message=%s", insight.Status, insight.Message)
	}
}

func TestCalicoGlobalNetworkSetWithGlobalNamespaceSelector(t *testing.T) {
	sourceNS, targetNS, sourcePod, targetPod, service := calicoTestPath()
	targetPod.Status.PodIP = "10.244.9.20"
	globalNetworkSet := unstructured.Unstructured{Object: map[string]interface{}{
		"kind": "GlobalNetworkSet",
		"metadata": map[string]interface{}{
			"name": "global-target-cidr",
			"labels": map[string]interface{}{
				"global-role": "target-network",
			},
		},
		"spec": map[string]interface{}{
			"nets": []interface{}{"10.244.9.20/32"},
		},
	}}
	policies := []unstructured.Unstructured{
		calicoPolicy("allow-global-networkset", "knm-source", "default", 100, `app == "client"`, "Egress", "Allow", map[string]interface{}{
			"selector":          `global-role == "target-network"`,
			"namespaceSelector": `global()`,
			"ports":             []interface{}{float64(80)},
		}),
	}

	insight := calicoDirectionDecision(policies, "egress", nil, []unstructured.Unstructured{globalNetworkSet}, nil, nil, sourceNS, sourcePod, targetNS, []corev1.Pod{targetPod}, &service, []int32{80})
	if insight.Status != "PASS" {
		t.Fatalf("status = %s, want PASS. message=%s", insight.Status, insight.Message)
	}
}

func TestCalicoNamedPortMatchesTargetPath(t *testing.T) {
	sourceNS, targetNS, sourcePod, targetPod, service := calicoTestPath()
	targetPod.Spec.Containers = []corev1.Container{{
		Name:  "echo",
		Ports: []corev1.ContainerPort{{Name: "web", ContainerPort: 8080}},
	}}
	service.Spec.Ports = []corev1.ServicePort{{
		Name:       "http",
		Port:       80,
		TargetPort: intstr.FromString("web"),
		Protocol:   corev1.ProtocolTCP,
	}}
	policies := []unstructured.Unstructured{
		calicoPolicy("allow-named-port", "knm-source", "default", 100, `app == "client"`, "Egress", "Allow", map[string]interface{}{
			"selector":          `app == "web"`,
			"namespaceSelector": `projectcalico.org/name == "knm-target"`,
			"ports":             []interface{}{"web"},
		}),
	}

	insight := calicoDirectionDecision(policies, "egress", nil, nil, nil, nil, sourceNS, sourcePod, targetNS, []corev1.Pod{targetPod}, &service, []int32{80, 8080})
	if insight.Status != "PASS" {
		t.Fatalf("status = %s, want PASS. message=%s", insight.Status, insight.Message)
	}
}

func TestCalicoEgressRuleSourceSelectorMustMatchSourcePod(t *testing.T) {
	sourceNS, targetNS, sourcePod, targetPod, service := calicoTestPath()
	policies := []unstructured.Unstructured{
		calicoPolicyWithRule("allow-jk-only", "knm-source", "default", 100, `all()`, "Egress", map[string]interface{}{
			"action":   "Allow",
			"protocol": "TCP",
			"source": map[string]interface{}{
				"selector": `app == "jk"`,
			},
			"destination": map[string]interface{}{
				"selector":          `app == "web"`,
				"namespaceSelector": `projectcalico.org/name == "knm-target"`,
				"ports":             []interface{}{float64(80)},
			},
		}),
	}

	insight := calicoDirectionDecision(policies, "egress", nil, nil, nil, nil, sourceNS, sourcePod, targetNS, []corev1.Pod{targetPod}, &service, []int32{80})
	if insight.Status != "FAIL" {
		t.Fatalf("status = %s, want FAIL because source selector should not match source pod. message=%s", insight.Status, insight.Message)
	}
}

func TestCalicoNotSelectorExcludesPath(t *testing.T) {
	sourceNS, targetNS, sourcePod, targetPod, service := calicoTestPath()
	policies := []unstructured.Unstructured{
		calicoPolicy("allow-but-not-web", "knm-source", "default", 100, `app == "client"`, "Egress", "Allow", map[string]interface{}{
			"selector":          `app == "web"`,
			"notSelector":       `app == "web"`,
			"namespaceSelector": `projectcalico.org/name == "knm-target"`,
			"ports":             []interface{}{float64(80)},
		}),
	}

	insight := calicoDirectionDecision(policies, "egress", nil, nil, nil, nil, sourceNS, sourcePod, targetNS, []corev1.Pod{targetPod}, &service, []int32{80})
	if insight.Status != "FAIL" {
		t.Fatalf("status = %s, want FAIL because notSelector excludes the only allow. message=%s", insight.Status, insight.Message)
	}
}

func TestCalicoServiceAccountSelectorMatch(t *testing.T) {
	sourceNS, targetNS, sourcePod, targetPod, service := calicoTestPath()
	targetPod.Spec.ServiceAccountName = "web-sa"
	policies := []unstructured.Unstructured{
		calicoPolicy("allow-web-sa", "knm-source", "default", 100, `app == "client"`, "Egress", "Allow", map[string]interface{}{
			"namespaceSelector": `projectcalico.org/name == "knm-target"`,
			"serviceAccounts": map[string]interface{}{
				"selector": `team == "platform"`,
			},
			"ports": []interface{}{float64(80)},
		}),
	}
	serviceAccounts := serviceAccountLabels{
		serviceAccountKey("knm-target", "web-sa"): map[string]string{"team": "platform"},
	}

	insight := calicoDirectionDecision(policies, "egress", nil, nil, nil, serviceAccounts, sourceNS, sourcePod, targetNS, []corev1.Pod{targetPod}, &service, []int32{80})
	if insight.Status != "PASS" {
		t.Fatalf("status = %s, want PASS. message=%s", insight.Status, insight.Message)
	}
}

func TestCalicoDenseAllowBeforeLaterDeny(t *testing.T) {
	sourceNS, targetNS, sourcePod, targetPod, service := calicoTestPath()
	targetPod.Labels["env"] = "prod"
	targetPod.Labels["version"] = "v1"
	targetPod.Labels["role"] = "allowed"
	policies := []unstructured.Unstructured{
		calicoPolicy("deny-wrong-port-first", "knm-source", "default", 10, `app == "client"`, "Egress", "Deny", map[string]interface{}{
			"selector":          `app == "web"`,
			"namespaceSelector": `projectcalico.org/name == "knm-target"`,
			"ports":             []interface{}{float64(8443)},
		}),
		calicoPolicy("dense-allow", "knm-source", "default", 20, `app == "client"`, "Egress", "Allow", map[string]interface{}{
			"selector":          `app in {"web", "api"} && env not in {"dev", "qa"} && has(version)`,
			"namespaceSelector": `projectcalico.org/name == "knm-target"`,
			"ports":             []interface{}{float64(80), float64(8080)},
		}),
		calicoPolicy("deny-later", "knm-source", "default", 200, `app == "client"`, "Egress", "Deny", map[string]interface{}{
			"selector":          `app == "web"`,
			"namespaceSelector": `projectcalico.org/name == "knm-target"`,
			"ports":             []interface{}{float64(80), float64(8080)},
		}),
	}

	insight := calicoDirectionDecision(policies, "egress", nil, nil, nil, nil, sourceNS, sourcePod, targetNS, []corev1.Pod{targetPod}, &service, []int32{80, 8080})
	if insight.Status != "PASS" {
		t.Fatalf("status = %s, want PASS. message=%s", insight.Status, insight.Message)
	}
}

func TestCalicoServiceMatchDoesNotMatchOtherService(t *testing.T) {
	entity := map[string]interface{}{
		"services": map[string]interface{}{
			"name":      "web",
			"namespace": "knm-target",
		},
	}
	kubeDNS := corev1.Service{ObjectMeta: metav1.ObjectMeta{Name: "kube-dns", Namespace: "kube-system"}}
	if calicoServicesMatch(entity, &kubeDNS) {
		t.Fatal("service match should not match a different service")
	}
}

func TestCalicoNodeLocalDNSMissingAllow(t *testing.T) {
	sourceNS, _, sourcePod, _, _ := calicoTestPath()
	kubeSystem := corev1.Namespace{ObjectMeta: metav1.ObjectMeta{Name: "kube-system", Labels: map[string]string{"projectcalico.org/name": "kube-system"}}}
	coredns := corev1.Pod{
		ObjectMeta: metav1.ObjectMeta{Name: "coredns", Namespace: "kube-system", Labels: map[string]string{"k8s-app": "kube-dns"}},
		Status:     corev1.PodStatus{PodIP: "10.244.9.10"},
	}
	policies := []unstructured.Unstructured{
		calicoPolicy("allow-coredns-only", "knm-source", "default", 100, `app == "client"`, "Egress", "Allow", map[string]interface{}{
			"selector":          `k8s-app == "kube-dns"`,
			"namespaceSelector": `projectcalico.org/name == "kube-system"`,
			"ports":             []interface{}{float64(53)},
		}),
	}

	insights := analyzeDNSEgress(policies, nil, nil, nil, nil, nil, sourceNS, sourcePod, DNSContext{
		Nameservers:      []string{"169.254.20.10"},
		CoreDNSServiceIP: "10.96.0.10",
		CoreDNSPods:      []corev1.Pod{coredns},
		KubeSystemNS:     &kubeSystem,
	})
	if len(insights) != 1 || insights[0].Status != "FAIL" {
		t.Fatalf("status = %#v, want one FAIL insight", insights)
	}
	if !strings.Contains(insights[0].Diagnosis, "runtime DNS resolver") {
		t.Fatalf("diagnosis should mention runtime DNS resolver: %s", insights[0].Diagnosis)
	}
}

func TestCalicoPassFallsThroughToProfileAllow(t *testing.T) {
	sourceNS, targetNS, sourcePod, targetPod, service := calicoTestPath()
	policies := []unstructured.Unstructured{
		calicoPolicy("pass-to-profile", "knm-source", "edge", 10, `app == "client"`, "Egress", "Pass", map[string]interface{}{
			"selector":          `app == "web"`,
			"namespaceSelector": `projectcalico.org/name == "knm-target"`,
			"ports":             []interface{}{float64(80)},
		}),
	}
	profiles := []unstructured.Unstructured{
		calicoProfile("kns.knm-source", "Egress", "Allow", map[string]interface{}{
			"selector":          `app == "web"`,
			"namespaceSelector": `projectcalico.org/name == "knm-target"`,
			"ports":             []interface{}{float64(80)},
		}),
	}

	insight := calicoDirectionDecision(policies, "egress", nil, nil, profiles, nil, sourceNS, sourcePod, targetNS, []corev1.Pod{targetPod}, &service, []int32{80})
	if insight.Status != "PASS" {
		t.Fatalf("status = %s, want PASS from profile fallback. message=%s", insight.Status, insight.Message)
	}
	if !strings.Contains(insight.Message, "workload profile fallback allows") {
		t.Fatalf("message should mention profile fallback: %s", insight.Message)
	}
}

func TestCalicoPassFallsThroughToProfileDeny(t *testing.T) {
	sourceNS, targetNS, sourcePod, targetPod, service := calicoTestPath()
	policies := []unstructured.Unstructured{
		calicoPolicy("pass-to-profile", "knm-source", "edge", 10, `app == "client"`, "Egress", "Pass", map[string]interface{}{
			"selector":          `app == "web"`,
			"namespaceSelector": `projectcalico.org/name == "knm-target"`,
			"ports":             []interface{}{float64(80)},
		}),
	}
	profiles := []unstructured.Unstructured{
		calicoProfile("kns.knm-source", "Egress", "Deny", map[string]interface{}{
			"selector":          `app == "web"`,
			"namespaceSelector": `projectcalico.org/name == "knm-target"`,
			"ports":             []interface{}{float64(80)},
		}),
	}

	insight := calicoDirectionDecision(policies, "egress", nil, nil, profiles, nil, sourceNS, sourcePod, targetNS, []corev1.Pod{targetPod}, &service, []int32{80})
	if insight.Status != "FAIL" {
		t.Fatalf("status = %s, want FAIL from profile fallback. message=%s", insight.Status, insight.Message)
	}
	if !strings.Contains(insight.Diagnosis, "profile") {
		t.Fatalf("diagnosis should mention profile fallback: %s", insight.Diagnosis)
	}
}

func TestCalicoNoPolicyProfileDefaultDeny(t *testing.T) {
	sourceNS, targetNS, sourcePod, targetPod, service := calicoTestPath()
	profiles := []unstructured.Unstructured{
		calicoProfile("kns.knm-source", "Egress", "Allow", map[string]interface{}{
			"selector":          `app == "other"`,
			"namespaceSelector": `projectcalico.org/name == "knm-target"`,
			"ports":             []interface{}{float64(80)},
		}),
	}

	insight := calicoDirectionDecision(nil, "egress", nil, nil, profiles, nil, sourceNS, sourcePod, targetNS, []corev1.Pod{targetPod}, &service, []int32{80})
	if insight.Status != "FAIL" {
		t.Fatalf("status = %s, want FAIL from profile default deny. message=%s", insight.Status, insight.Message)
	}
	if !strings.Contains(insight.Message, "No Calico egress policies select") {
		t.Fatalf("message should retain no-policy context: %s", insight.Message)
	}
}

func TestCalicoIngressSurfaceExplicitDeny(t *testing.T) {
	_, _, _, _, service := calicoTestPath()
	service.Spec.Type = corev1.ServiceTypeNodePort
	service.Spec.Ports = []corev1.ServicePort{{Port: 80, NodePort: 30080, Protocol: corev1.ProtocolTCP}}
	policies := []unstructured.Unstructured{
		calicoGlobalHostPolicy("deny-nodeport", 10, `role == "edge-node"`, "Deny", map[string]interface{}{
			"ports": []interface{}{float64(30080)},
		}),
	}
	hostEndpoints := []unstructured.Unstructured{calicoHostEndpoint("worker-a", map[string]string{"role": "edge-node"})}

	insights := analyzeIngressSurface(policies, hostEndpoints, nil, calicoIngressPorts(&service))
	if !hasInsightStatus(insights, "Calico Host Policy Path", "FAIL") {
		t.Fatalf("expected host policy deny insight, got %#v", insights)
	}
}

func TestCalicoIngressSurfaceDefaultDeny(t *testing.T) {
	_, _, _, _, service := calicoTestPath()
	service.Spec.Type = corev1.ServiceTypeNodePort
	service.Spec.Ports = []corev1.ServicePort{{Port: 80, NodePort: 30080, Protocol: corev1.ProtocolTCP}}
	policies := []unstructured.Unstructured{
		calicoGlobalHostPolicy("allow-other-port", 10, `role == "edge-node"`, "Allow", map[string]interface{}{
			"ports": []interface{}{float64(30443)},
		}),
	}
	hostEndpoints := []unstructured.Unstructured{calicoHostEndpoint("worker-a", map[string]string{"role": "edge-node"})}

	insights := analyzeIngressSurface(policies, hostEndpoints, nil, calicoIngressPorts(&service))
	if !hasInsightStatus(insights, "Calico Host Policy Path", "FAIL") {
		t.Fatalf("expected host policy default-deny insight, got %#v", insights)
	}
}

func TestCalicoIngressSurfaceAllowBeforeLaterDeny(t *testing.T) {
	_, _, _, _, service := calicoTestPath()
	service.Spec.Type = corev1.ServiceTypeNodePort
	service.Spec.Ports = []corev1.ServicePort{{Port: 80, NodePort: 30080, Protocol: corev1.ProtocolTCP}}
	policies := []unstructured.Unstructured{
		calicoGlobalHostPolicyWithRules("allow-then-deny", 10, `role == "edge-node"`, true, false, true, []interface{}{
			hostRule("Allow", map[string]interface{}{"ports": []interface{}{float64(30080)}}),
			hostRule("Deny", map[string]interface{}{"ports": []interface{}{float64(30080)}}),
		}),
	}
	hostEndpoints := []unstructured.Unstructured{calicoHostEndpoint("worker-a", map[string]string{"role": "edge-node"})}

	insights := analyzeIngressSurface(policies, hostEndpoints, nil, calicoIngressPorts(&service))
	insight := firstInsight(insights, "Calico Host Policy Path", "external ingress to node")
	if insight == nil || insight.Status != "PASS" || !strings.Contains(insight.Message, "rule 1") {
		t.Fatalf("expected first Allow rule to win, got %#v", insights)
	}
}

func TestCalicoIngressSurfaceDenyBeforeLaterAllow(t *testing.T) {
	_, _, _, _, service := calicoTestPath()
	service.Spec.Type = corev1.ServiceTypeNodePort
	service.Spec.Ports = []corev1.ServicePort{{Port: 80, NodePort: 30080, Protocol: corev1.ProtocolTCP}}
	policies := []unstructured.Unstructured{
		calicoGlobalHostPolicyWithRules("deny-then-allow", 10, `role == "edge-node"`, true, false, true, []interface{}{
			hostRule("Deny", map[string]interface{}{"ports": []interface{}{float64(30080)}}),
			hostRule("Allow", map[string]interface{}{"ports": []interface{}{float64(30080)}}),
		}),
	}
	hostEndpoints := []unstructured.Unstructured{calicoHostEndpoint("worker-a", map[string]string{"role": "edge-node"})}

	insights := analyzeIngressSurface(policies, hostEndpoints, nil, calicoIngressPorts(&service))
	insight := firstInsight(insights, "Calico Host Policy Path", "external ingress to node")
	if insight == nil || insight.Status != "FAIL" || !strings.Contains(insight.Message, "rule 1") {
		t.Fatalf("expected first Deny rule to win, got %#v", insights)
	}
}

func TestCalicoIngressSurfaceHostEndpointSelectorMiss(t *testing.T) {
	_, _, _, _, service := calicoTestPath()
	service.Spec.Type = corev1.ServiceTypeNodePort
	service.Spec.Ports = []corev1.ServicePort{{Port: 80, NodePort: 30080, Protocol: corev1.ProtocolTCP}}
	policies := []unstructured.Unstructured{
		calicoGlobalHostPolicy("deny-gateway", 10, `role == "gateway"`, "Deny", map[string]interface{}{
			"ports": []interface{}{float64(30080)},
		}),
	}
	hostEndpoints := []unstructured.Unstructured{calicoHostEndpoint("worker-a", map[string]string{"role": "worker"})}

	insights := analyzeIngressSurface(policies, hostEndpoints, nil, calicoIngressPorts(&service))
	if hasInsightStatus(insights, "Calico Host Policy Path", "FAIL") {
		t.Fatalf("selector miss should not claim host policy block, got %#v", insights)
	}
	if !hasInsightStatus(insights, "Calico Host Policy Path", "PASS") {
		t.Fatalf("expected visible host policy non-match to be treated as not blocking forwarded path, got %#v", insights)
	}
}

func TestCalicoIngressSurfaceNoHostEndpointsLimitedEvidence(t *testing.T) {
	_, _, _, _, service := calicoTestPath()
	service.Spec.Type = corev1.ServiceTypeNodePort
	service.Spec.Ports = []corev1.ServicePort{{Port: 80, NodePort: 30080, Protocol: corev1.ProtocolTCP}}
	policies := []unstructured.Unstructured{
		calicoGlobalHostPolicy("deny-nodeport", 10, `role == "edge-node"`, "Deny", map[string]interface{}{
			"ports": []interface{}{float64(30080)},
		}),
	}

	insights := analyzeIngressSurface(policies, nil, nil, calicoIngressPorts(&service))
	insight := firstInsight(insights, "Calico Host Policy Layer", "host endpoints")
	if insight == nil || insight.Status != "WARN" || !strings.Contains(insight.Message, "no HostEndpoint") {
		t.Fatalf("expected limited evidence warning for missing HostEndpoints, got %#v", insights)
	}
}

func TestCalicoIngressSurfaceInvalidPreDNATWithoutApplyOnForward(t *testing.T) {
	_, _, _, _, service := calicoTestPath()
	service.Spec.Type = corev1.ServiceTypeNodePort
	service.Spec.Ports = []corev1.ServicePort{{Port: 80, NodePort: 30080, Protocol: corev1.ProtocolTCP}}
	policies := []unstructured.Unstructured{
		calicoGlobalHostPolicyWithRules("invalid-prednat", 10, `role == "edge-node"`, true, false, false, []interface{}{
			hostRule("Deny", map[string]interface{}{"ports": []interface{}{float64(30080)}}),
		}),
	}
	hostEndpoints := []unstructured.Unstructured{calicoHostEndpoint("worker-a", map[string]string{"role": "edge-node"})}

	insights := analyzeIngressSurface(policies, hostEndpoints, nil, calicoIngressPorts(&service))
	insight := firstInsight(insights, "Calico Host Policy Layer", "global/invalid-prednat invalid host policy")
	if insight == nil || insight.Status != "WARN" || !strings.Contains(insight.Message, "applyOnForward") {
		t.Fatalf("expected invalid preDNAT/applyOnForward warning, got %#v", insights)
	}
	if hasInsightStatus(insights, "Calico Host Policy Path", "FAIL") {
		t.Fatalf("invalid host policy should not be reasoned as a normal blocker, got %#v", insights)
	}
}

func TestCalicoIngressSurfaceInvalidDoNotTrackAndPreDNAT(t *testing.T) {
	_, _, _, _, service := calicoTestPath()
	service.Spec.Type = corev1.ServiceTypeNodePort
	service.Spec.Ports = []corev1.ServicePort{{Port: 80, NodePort: 30080, Protocol: corev1.ProtocolTCP}}
	policies := []unstructured.Unstructured{
		calicoGlobalHostPolicyWithRules("invalid-both-modes", 10, `role == "edge-node"`, true, true, true, []interface{}{
			hostRule("Deny", map[string]interface{}{"ports": []interface{}{float64(30080)}}),
		}),
	}
	hostEndpoints := []unstructured.Unstructured{calicoHostEndpoint("worker-a", map[string]string{"role": "edge-node"})}

	insights := analyzeIngressSurface(policies, hostEndpoints, nil, calicoIngressPorts(&service))
	insight := firstInsight(insights, "Calico Host Policy Layer", "global/invalid-both-modes invalid host policy")
	if insight == nil || insight.Status != "WARN" || !strings.Contains(insight.Message, "both preDNAT and doNotTrack") {
		t.Fatalf("expected invalid preDNAT/doNotTrack warning, got %#v", insights)
	}
}

func TestCalicoIngressSurfaceDoNotTrackExplicitDeny(t *testing.T) {
	_, _, _, _, service := calicoTestPath()
	service.Spec.Type = corev1.ServiceTypeNodePort
	service.Spec.Ports = []corev1.ServicePort{{Port: 80, NodePort: 30080, Protocol: corev1.ProtocolTCP}}
	policies := []unstructured.Unstructured{
		calicoGlobalHostPolicyWithRules("untracked-deny", 10, `role == "edge-node"`, false, true, true, []interface{}{
			hostRule("Deny", map[string]interface{}{"ports": []interface{}{float64(30080)}}),
		}),
	}
	hostEndpoints := []unstructured.Unstructured{calicoHostEndpoint("worker-a", map[string]string{"role": "edge-node"})}

	insights := analyzeIngressSurface(policies, hostEndpoints, nil, calicoIngressPorts(&service))
	if !hasInsightStatus(insights, "Calico Host Policy Path", "FAIL") {
		t.Fatalf("expected doNotTrack explicit deny, got %#v", insights)
	}
	if !hasInsightStatus(insights, "Calico Host Policy Layer", "WARN") {
		t.Fatalf("expected doNotTrack warning context, got %#v", insights)
	}
}

func TestCalicoIngressSurfaceApplyOnForwardWithoutPreDNAT(t *testing.T) {
	_, _, _, _, service := calicoTestPath()
	service.Spec.Type = corev1.ServiceTypeNodePort
	service.Spec.Ports = []corev1.ServicePort{{Port: 80, NodePort: 30080, Protocol: corev1.ProtocolTCP}}
	policies := []unstructured.Unstructured{
		calicoGlobalHostPolicyWithRules("forwarded-deny", 10, `role == "edge-node"`, false, false, true, []interface{}{
			hostRule("Deny", map[string]interface{}{"ports": []interface{}{float64(30080)}}),
		}),
	}
	hostEndpoints := []unstructured.Unstructured{calicoHostEndpoint("worker-a", map[string]string{"role": "edge-node"})}

	insights := analyzeIngressSurface(policies, hostEndpoints, nil, calicoIngressPorts(&service))
	if !hasInsightStatus(insights, "Calico Host Policy Path", "FAIL") {
		t.Fatalf("expected applyOnForward explicit deny, got %#v", insights)
	}
	insight := firstInsight(insights, "Calico Host Policy Layer", "global/forwarded-deny applyOnForward")
	if insight == nil || !strings.Contains(insight.Message, "after DNAT") {
		t.Fatalf("expected applyOnForward without preDNAT context, got %#v", insights)
	}
}

func TestCalicoIngressSurfaceNamedHostPortAmbiguous(t *testing.T) {
	_, _, _, _, service := calicoTestPath()
	service.Spec.Type = corev1.ServiceTypeNodePort
	service.Spec.Ports = []corev1.ServicePort{{Port: 80, NodePort: 30080, Protocol: corev1.ProtocolTCP}}
	policies := []unstructured.Unstructured{
		calicoGlobalHostPolicy("allow-named-host-port", 10, `role == "edge-node"`, "Allow", map[string]interface{}{
			"ports": []interface{}{"web"},
		}),
	}
	hostEndpoints := []unstructured.Unstructured{calicoHostEndpoint("worker-a", map[string]string{"role": "edge-node"})}

	insights := analyzeIngressSurface(policies, hostEndpoints, nil, calicoIngressPorts(&service))
	insight := firstInsight(insights, "Calico Host Policy Path", "named host ports")
	if insight == nil || insight.Status != "WARN" {
		t.Fatalf("expected named host port ambiguity warning, got %#v", insights)
	}
}

func TestCalicoIngressPortsIncludeLoadBalancerServicePort(t *testing.T) {
	_, _, _, _, service := calicoTestPath()
	service.Spec.Type = corev1.ServiceTypeLoadBalancer
	service.Spec.Ports = []corev1.ServicePort{{Port: 443, TargetPort: intstr.FromInt32(8443), Protocol: corev1.ProtocolTCP}}
	policies := []unstructured.Unstructured{
		calicoGlobalHostPolicy("deny-lb-port", 10, `role == "edge-node"`, "Deny", map[string]interface{}{
			"ports": []interface{}{float64(443)},
		}),
	}
	hostEndpoints := []unstructured.Unstructured{calicoHostEndpoint("worker-a", map[string]string{"role": "edge-node"})}

	insights := analyzeIngressSurface(policies, hostEndpoints, nil, calicoIngressPorts(&service))
	if !hasInsightStatus(insights, "Calico Host Policy Path", "FAIL") {
		t.Fatalf("expected LoadBalancer service port deny insight, got %#v", insights)
	}
}

func calicoTestPath() (corev1.Namespace, corev1.Namespace, corev1.Pod, corev1.Pod, corev1.Service) {
	sourceNS := corev1.Namespace{ObjectMeta: metav1.ObjectMeta{Name: "knm-source", Labels: map[string]string{"projectcalico.org/name": "knm-source"}}}
	targetNS := corev1.Namespace{ObjectMeta: metav1.ObjectMeta{Name: "knm-target", Labels: map[string]string{"projectcalico.org/name": "knm-target"}}}
	sourcePod := corev1.Pod{
		ObjectMeta: metav1.ObjectMeta{Name: "client", Namespace: "knm-source", Labels: map[string]string{"app": "client"}},
		Spec:       corev1.PodSpec{ServiceAccountName: "default"},
		Status:     corev1.PodStatus{PodIP: "10.244.0.10"},
	}
	targetPod := corev1.Pod{
		ObjectMeta: metav1.ObjectMeta{Name: "web", Namespace: "knm-target", Labels: map[string]string{"app": "web"}},
		Spec:       corev1.PodSpec{ServiceAccountName: "default"},
		Status:     corev1.PodStatus{PodIP: "10.244.1.10"},
	}
	service := corev1.Service{
		ObjectMeta: metav1.ObjectMeta{Name: "web", Namespace: "knm-target"},
		Spec:       corev1.ServiceSpec{ClusterIP: "10.96.0.50"},
	}
	return sourceNS, targetNS, sourcePod, targetPod, service
}

func calicoGlobalHostPolicy(name string, order float64, selector string, action string, destination map[string]interface{}) unstructured.Unstructured {
	return calicoGlobalHostPolicyWithRules(name, order, selector, true, false, true, []interface{}{hostRule(action, destination)})
}

func calicoGlobalHostPolicyWithRules(name string, order float64, selector string, preDNAT bool, doNotTrack bool, applyOnForward bool, rules []interface{}) unstructured.Unstructured {
	return unstructured.Unstructured{Object: map[string]interface{}{
		"kind": "GlobalNetworkPolicy",
		"metadata": map[string]interface{}{
			"name": name,
		},
		"spec": map[string]interface{}{
			"order":          order,
			"selector":       selector,
			"preDNAT":        preDNAT,
			"doNotTrack":     doNotTrack,
			"applyOnForward": applyOnForward,
			"types":          []interface{}{"Ingress"},
			"ingress":        rules,
		},
	}}
}

func hostRule(action string, destination map[string]interface{}) map[string]interface{} {
	return map[string]interface{}{
		"action":      action,
		"protocol":    "TCP",
		"destination": destination,
	}
}

func calicoHostEndpoint(name string, labels map[string]string) unstructured.Unstructured {
	item := unstructured.Unstructured{Object: map[string]interface{}{
		"kind": "HostEndpoint",
		"metadata": map[string]interface{}{
			"name": name,
		},
	}}
	item.SetLabels(labels)
	return item
}

func hasInsightStatus(insights []policy.Insight, layer string, status string) bool {
	for _, insight := range insights {
		if insight.Layer == layer && insight.Status == status {
			return true
		}
	}
	return false
}

func firstInsight(insights []policy.Insight, layer string, check string) *policy.Insight {
	for i := range insights {
		if insights[i].Layer == layer && insights[i].Check == check {
			return &insights[i]
		}
	}
	return nil
}

func calicoPolicy(name, namespace, tier string, order float64, selector string, direction string, action string, entity map[string]interface{}) unstructured.Unstructured {
	rule := map[string]interface{}{
		"action":   action,
		"protocol": "TCP",
	}
	if direction == "Egress" {
		rule["destination"] = entity
	} else {
		rule["source"] = entity
	}
	return unstructured.Unstructured{Object: map[string]interface{}{
		"kind": "NetworkPolicy",
		"metadata": map[string]interface{}{
			"name":      name,
			"namespace": namespace,
		},
		"spec": map[string]interface{}{
			"tier":                     tier,
			"order":                    order,
			"selector":                 selector,
			"types":                    []interface{}{direction},
			strings.ToLower(direction): []interface{}{rule},
		},
	}}
}

func calicoPolicyWithRule(name, namespace, tier string, order float64, selector string, direction string, rule map[string]interface{}) unstructured.Unstructured {
	return unstructured.Unstructured{Object: map[string]interface{}{
		"kind": "NetworkPolicy",
		"metadata": map[string]interface{}{
			"name":      name,
			"namespace": namespace,
		},
		"spec": map[string]interface{}{
			"tier":                     tier,
			"order":                    order,
			"selector":                 selector,
			"types":                    []interface{}{direction},
			strings.ToLower(direction): []interface{}{rule},
		},
	}}
}

func calicoProfile(name string, direction string, action string, entity map[string]interface{}) unstructured.Unstructured {
	rule := map[string]interface{}{
		"action":   action,
		"protocol": "TCP",
	}
	if direction == "Egress" {
		rule["destination"] = entity
	} else {
		rule["source"] = entity
	}
	return unstructured.Unstructured{Object: map[string]interface{}{
		"kind": "Profile",
		"metadata": map[string]interface{}{
			"name": name,
		},
		"spec": map[string]interface{}{
			strings.ToLower(direction): []interface{}{rule},
		},
	}}
}

func calicoTier(name string, order float64) unstructured.Unstructured {
	return unstructured.Unstructured{Object: map[string]interface{}{
		"kind": "Tier",
		"metadata": map[string]interface{}{
			"name": name,
		},
		"spec": map[string]interface{}{
			"order": order,
		},
	}}
}
