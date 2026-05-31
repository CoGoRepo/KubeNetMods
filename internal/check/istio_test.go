package check

import (
	"context"
	"strings"
	"testing"

	"github.com/CoGoRepo/KubeNetMods/internal/kube"
	"github.com/CoGoRepo/KubeNetMods/internal/model"
	networkingapi "istio.io/api/networking/v1alpha3"
	securityapi "istio.io/api/security/v1beta1"
	istiotype "istio.io/api/type/v1beta1"
	networkingv1 "istio.io/client-go/pkg/apis/networking/v1"
	securityv1 "istio.io/client-go/pkg/apis/security/v1"
	istiofake "istio.io/client-go/pkg/clientset/versioned/fake"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/util/intstr"
)

func TestClassifyIstioRuntimeRequiresIstioEvidence(t *testing.T) {
	result := RuntimeHTTPResult{
		OK:         true,
		StatusCode: "403",
		Output:     "HTTP/1.1 403 Forbidden\r\nserver: app\r\n\r\nforbidden",
	}

	if got := classifyIstioRuntime(result, nil, nil); got != istioSignalNone {
		t.Fatalf("expected non-Istio 403 to stay generic, got %q", got)
	}

	result.Output = "HTTP/1.1 403 Forbidden\r\nserver: envoy\r\n\r\nRBAC: access denied"
	if got := classifyIstioRuntime(result, nil, nil); got != istioSignalRBACDenied {
		t.Fatalf("expected Envoy RBAC denial, got %q", got)
	}

	result = RuntimeHTTPResult{
		OK:         true,
		StatusCode: "503",
		Output:     "HTTP/1.1 503 Service Unavailable\r\nserver: envoy\r\n\r\nupstream connect error or disconnect/reset before headers. reset reason: connection termination",
	}
	if got := classifyIstioRuntime(result, nil, nil); got != istioSignalUpstreamReset {
		t.Fatalf("expected Envoy upstream reset, got %q", got)
	}
}

func TestInspectIstioAuthorizationPolicyReportsMatchingDeny(t *testing.T) {
	service := testService("app", "echo-denied")
	targetPods := []corev1.Pod{
		testPod("app", "echo-denied-abc", map[string]string{"app": "echo-denied"}, true, true),
	}
	source := &ExecTarget{
		Kind: "source pod",
		Pod:  testPod("src", "curl-abc", map[string]string{"app": "curl"}, true, true),
	}
	policy := &securityv1.AuthorizationPolicy{
		ObjectMeta: metav1.ObjectMeta{Name: "deny-echo-denied", Namespace: "app"},
		Spec: securityapi.AuthorizationPolicy{
			Selector: &istiotype.WorkloadSelector{MatchLabels: map[string]string{"app": "echo-denied"}},
			Action:   securityapi.AuthorizationPolicy_DENY,
			Rules:    []*securityapi.Rule{{}},
		},
	}
	report := model.NewReport("check service", model.Target{Namespace: "app", Service: "echo-denied"})
	client := &kube.Client{Istio: istiofake.NewSimpleClientset(policy)}

	inspectIstioAuthorizationPolicy(context.Background(), client, report, ServiceOptions{Namespace: "app"}, service, targetPods, source, "http://echo-denied.app.svc.cluster.local/")

	assertResult(t, report, "Istio Authorization Layer", "app/deny-echo-denied", model.StatusFail)
	assertDiagnosisContains(t, report, "AuthorizationPolicy \"app/deny-echo-denied\" denies requests")
	assertDiagnosisContains(t, report, "via rule 1")
}

func TestInspectIstioAuthorizationPolicyIgnoresDenyWithNoRules(t *testing.T) {
	service := testService("app", "echo-denied")
	targetPods := []corev1.Pod{
		testPod("app", "echo-denied-abc", map[string]string{"app": "echo-denied"}, true, true),
	}
	source := &ExecTarget{
		Kind: "source pod",
		Pod:  testPod("src", "curl-abc", map[string]string{"app": "curl"}, true, true),
	}
	policy := &securityv1.AuthorizationPolicy{
		ObjectMeta: metav1.ObjectMeta{Name: "deny-empty", Namespace: "app"},
		Spec: securityapi.AuthorizationPolicy{
			Selector: &istiotype.WorkloadSelector{MatchLabels: map[string]string{"app": "echo-denied"}},
			Action:   securityapi.AuthorizationPolicy_DENY,
		},
	}
	report := model.NewReport("check service", model.Target{Namespace: "app", Service: "echo-denied"})
	client := &kube.Client{Istio: istiofake.NewSimpleClientset(policy)}

	inspectIstioAuthorizationPolicy(context.Background(), client, report, ServiceOptions{Namespace: "app"}, service, targetPods, source, "http://echo-denied.app.svc.cluster.local/")

	assertResult(t, report, "Istio Authorization Layer", "authorization policies", model.StatusWarn)
	assertDiagnosisContains(t, report, "could not identify the exact AuthorizationPolicy")
}

func TestInspectIstioAuthorizationPolicyReportsRiskyHTTPDenyWithoutPort(t *testing.T) {
	service := testService("app", "echo-denied")
	targetPods := []corev1.Pod{
		testPod("app", "echo-denied-abc", map[string]string{"app": "echo-denied"}, true, true),
	}
	source := &ExecTarget{
		Kind: "source pod",
		Pod:  testPod("src", "curl-abc", map[string]string{"app": "curl"}, true, true),
	}
	policy := &securityv1.AuthorizationPolicy{
		ObjectMeta: metav1.ObjectMeta{Name: "deny-http-footgun", Namespace: "app"},
		Spec: securityapi.AuthorizationPolicy{
			Selector: &istiotype.WorkloadSelector{MatchLabels: map[string]string{"app": "echo-denied"}},
			Action:   securityapi.AuthorizationPolicy_DENY,
			Rules: []*securityapi.Rule{
				{To: []*securityapi.Rule_To{{Operation: &securityapi.Operation{Methods: []string{"POST"}}}}},
				{To: []*securityapi.Rule_To{{Operation: &securityapi.Operation{Paths: []string{"/admin*"}}}}},
			},
		},
	}
	report := model.NewReport("check service", model.Target{Namespace: "app", Service: "echo-denied"})
	client := &kube.Client{Istio: istiofake.NewSimpleClientset(policy)}

	inspectIstioAuthorizationPolicy(context.Background(), client, report, ServiceOptions{Namespace: "app", SourceNamespace: "src", URLPath: "/"}, service, targetPods, source, "http://echo-denied.app.svc.cluster.local/")

	assertResult(t, report, "Istio Authorization Layer", "authorization policies", model.StatusFail)
	assertDiagnosisContains(t, report, "HTTP-only match fields without an explicit port constraint")
	assertDiagnosisContains(t, report, "app/deny-http-footgun rule 1")
	assertDiagnosisContains(t, report, "app/deny-http-footgun rule 2")
}

func TestInspectIstioAuthorizationPolicyDoesNotWarnForHTTPDenyBoundToPort(t *testing.T) {
	service := testService("app", "echo-denied")
	targetPods := []corev1.Pod{
		testPod("app", "echo-denied-abc", map[string]string{"app": "echo-denied"}, true, true),
	}
	source := &ExecTarget{
		Kind: "source pod",
		Pod:  testPod("src", "curl-abc", map[string]string{"app": "curl"}, true, true),
	}
	policy := &securityv1.AuthorizationPolicy{
		ObjectMeta: metav1.ObjectMeta{Name: "deny-post-only", Namespace: "app"},
		Spec: securityapi.AuthorizationPolicy{
			Selector: &istiotype.WorkloadSelector{MatchLabels: map[string]string{"app": "echo-denied"}},
			Action:   securityapi.AuthorizationPolicy_DENY,
			Rules: []*securityapi.Rule{
				{To: []*securityapi.Rule_To{{Operation: &securityapi.Operation{
					Ports:   []string{"80"},
					Methods: []string{"POST"},
				}}}},
			},
		},
	}
	report := model.NewReport("check service", model.Target{Namespace: "app", Service: "echo-denied"})
	client := &kube.Client{Istio: istiofake.NewSimpleClientset(policy)}

	inspectIstioAuthorizationPolicy(context.Background(), client, report, ServiceOptions{Namespace: "app", SourceNamespace: "src", URLPath: "/"}, service, targetPods, source, "http://echo-denied.app.svc.cluster.local/")

	assertResult(t, report, "Istio Authorization Layer", "authorization policies", model.StatusWarn)
	assertDiagnosisContains(t, report, "could not identify the exact AuthorizationPolicy")
	assertDiagnosisNotContains(t, report, "HTTP-only match fields without an explicit port constraint")
}

func TestInspectIstioAuthorizationPolicyReportsMatchingSpecificRule(t *testing.T) {
	service := testService("app", "echo-denied")
	targetPods := []corev1.Pod{
		testPod("app", "echo-denied-abc", map[string]string{"app": "echo-denied"}, true, true),
	}
	sourcePod := testPod("src", "curl-abc", map[string]string{"app": "curl"}, true, true)
	sourcePod.Spec.ServiceAccountName = "curl"
	source := &ExecTarget{Kind: "source pod", Pod: sourcePod}
	policy := &securityv1.AuthorizationPolicy{
		ObjectMeta: metav1.ObjectMeta{Name: "deny-echo-denied", Namespace: "app"},
		Spec: securityapi.AuthorizationPolicy{
			Selector: &istiotype.WorkloadSelector{MatchLabels: map[string]string{"app": "echo-denied"}},
			Action:   securityapi.AuthorizationPolicy_DENY,
			Rules: []*securityapi.Rule{
				{To: []*securityapi.Rule_To{{Operation: &securityapi.Operation{Ports: []string{"9991"}}}}},
				{To: []*securityapi.Rule_To{{Operation: &securityapi.Operation{Methods: []string{"POST"}}}}},
				{From: []*securityapi.Rule_From{{Source: &securityapi.Source{Namespaces: []string{"other"}}}}},
				{To: []*securityapi.Rule_To{{Operation: &securityapi.Operation{Paths: []string{"/admin*"}}}}},
				{
					To: []*securityapi.Rule_To{{Operation: &securityapi.Operation{
						Hosts:   []string{"echo-denied.app.svc.cluster.local"},
						Ports:   []string{"8080"},
						Methods: []string{"GET"},
						Paths:   []string{"/api/items"},
					}}},
					When: []*securityapi.Condition{
						{Key: "destination.port", Values: []string{"8080"}},
					},
				},
			},
		},
	}
	report := model.NewReport("check service", model.Target{Namespace: "app", Service: "echo-denied"})
	client := &kube.Client{Istio: istiofake.NewSimpleClientset(policy)}

	inspectIstioAuthorizationPolicy(context.Background(), client, report, ServiceOptions{Namespace: "app", SourceNamespace: "src", URLPath: "/api/items"}, service, targetPods, source, "http://echo-denied.app.svc.cluster.local/api/items")

	assertResult(t, report, "Istio Authorization Layer", "app/deny-echo-denied", model.StatusFail)
	assertDiagnosisContains(t, report, "via rule 5")
	assertDiagnosisNotContains(t, report, "via rule 1")
}

func TestInspectIstioAuthorizationPolicyReportsAllowDefaultDeny(t *testing.T) {
	service := testService("app", "echo-denied")
	targetPods := []corev1.Pod{
		testPod("app", "echo-denied-abc", map[string]string{"app": "echo-denied"}, true, true),
	}
	source := &ExecTarget{
		Kind: "source pod",
		Pod:  testPod("src", "curl-abc", map[string]string{"app": "curl"}, true, true),
	}
	policy := &securityv1.AuthorizationPolicy{
		ObjectMeta: metav1.ObjectMeta{Name: "allow-other", Namespace: "app"},
		Spec: securityapi.AuthorizationPolicy{
			Selector: &istiotype.WorkloadSelector{MatchLabels: map[string]string{"app": "echo-denied"}},
			Action:   securityapi.AuthorizationPolicy_ALLOW,
			Rules: []*securityapi.Rule{
				{From: []*securityapi.Rule_From{{Source: &securityapi.Source{Namespaces: []string{"other"}}}}},
			},
		},
	}
	report := model.NewReport("check service", model.Target{Namespace: "app", Service: "echo-denied"})
	client := &kube.Client{Istio: istiofake.NewSimpleClientset(policy)}

	inspectIstioAuthorizationPolicy(context.Background(), client, report, ServiceOptions{Namespace: "app", SourceNamespace: "src"}, service, targetPods, source, "http://echo-denied.app.svc.cluster.local/")

	assertResult(t, report, "Istio Authorization Layer", "allow policies", model.StatusFail)
	assertDiagnosisContains(t, report, "selected by Istio ALLOW AuthorizationPolicy")
	assertDiagnosisContains(t, report, "app/allow-other")
}

func TestInspectIstioAuthorizationPolicyDoesNotReportAllowWhenRuleMatches(t *testing.T) {
	service := testService("app", "echo-denied")
	targetPods := []corev1.Pod{
		testPod("app", "echo-denied-abc", map[string]string{"app": "echo-denied"}, true, true),
	}
	source := &ExecTarget{
		Kind: "source pod",
		Pod:  testPod("src", "curl-abc", map[string]string{"app": "curl"}, true, true),
	}
	policy := &securityv1.AuthorizationPolicy{
		ObjectMeta: metav1.ObjectMeta{Name: "allow-src", Namespace: "app"},
		Spec: securityapi.AuthorizationPolicy{
			Selector: &istiotype.WorkloadSelector{MatchLabels: map[string]string{"app": "echo-denied"}},
			Action:   securityapi.AuthorizationPolicy_ALLOW,
			Rules: []*securityapi.Rule{
				{From: []*securityapi.Rule_From{{Source: &securityapi.Source{Namespaces: []string{"src"}}}}},
			},
		},
	}
	report := model.NewReport("check service", model.Target{Namespace: "app", Service: "echo-denied"})
	client := &kube.Client{Istio: istiofake.NewSimpleClientset(policy)}

	inspectIstioAuthorizationPolicy(context.Background(), client, report, ServiceOptions{Namespace: "app", SourceNamespace: "src"}, service, targetPods, source, "http://echo-denied.app.svc.cluster.local/")

	assertResult(t, report, "Istio Authorization Layer", "authorization policies", model.StatusWarn)
	assertDiagnosisContains(t, report, "could not identify the exact AuthorizationPolicy")
	assertDiagnosisNotContains(t, report, "ALLOW")
}

func TestInspectIstioAuthorizationPolicyAllowsWhenAnyAllowPolicyMatches(t *testing.T) {
	service := testService("app", "echo-denied")
	targetPods := []corev1.Pod{
		testPod("app", "echo-denied-abc", map[string]string{"app": "echo-denied"}, true, true),
	}
	source := &ExecTarget{
		Kind: "source pod",
		Pod:  testPod("src", "curl-abc", map[string]string{"app": "curl"}, true, true),
	}
	allowOther := &securityv1.AuthorizationPolicy{
		ObjectMeta: metav1.ObjectMeta{Name: "allow-other", Namespace: "app"},
		Spec: securityapi.AuthorizationPolicy{
			Selector: &istiotype.WorkloadSelector{MatchLabels: map[string]string{"app": "echo-denied"}},
			Action:   securityapi.AuthorizationPolicy_ALLOW,
			Rules: []*securityapi.Rule{
				{From: []*securityapi.Rule_From{{Source: &securityapi.Source{Namespaces: []string{"other"}}}}},
			},
		},
	}
	allowSrc := &securityv1.AuthorizationPolicy{
		ObjectMeta: metav1.ObjectMeta{Name: "allow-src", Namespace: "app"},
		Spec: securityapi.AuthorizationPolicy{
			Selector: &istiotype.WorkloadSelector{MatchLabels: map[string]string{"app": "echo-denied"}},
			Action:   securityapi.AuthorizationPolicy_ALLOW,
			Rules: []*securityapi.Rule{
				{From: []*securityapi.Rule_From{{Source: &securityapi.Source{Namespaces: []string{"src"}}}}},
			},
		},
	}
	report := model.NewReport("check service", model.Target{Namespace: "app", Service: "echo-denied"})
	client := &kube.Client{Istio: istiofake.NewSimpleClientset(allowOther, allowSrc)}

	inspectIstioAuthorizationPolicy(context.Background(), client, report, ServiceOptions{Namespace: "app", SourceNamespace: "src"}, service, targetPods, source, "http://echo-denied.app.svc.cluster.local/")

	assertResult(t, report, "Istio Authorization Layer", "authorization policies", model.StatusWarn)
	assertDiagnosisContains(t, report, "could not identify the exact AuthorizationPolicy")
	assertDiagnosisNotContains(t, report, "ALLOW AuthorizationPolicy")
	assertDiagnosisNotContains(t, report, "allow-other")
}

func TestInspectIstioAuthorizationPolicyIgnoresNearMissDenyWhenAllowMatches(t *testing.T) {
	service := testService("app", "echo-denied")
	targetPods := []corev1.Pod{
		testPod("app", "echo-denied-abc", map[string]string{"app": "echo-denied"}, true, true),
	}
	source := &ExecTarget{
		Kind: "source pod",
		Pod:  testPod("src", "curl-abc", map[string]string{"app": "curl"}, true, true),
	}
	denyNearMisses := &securityv1.AuthorizationPolicy{
		ObjectMeta: metav1.ObjectMeta{Name: "deny-near-misses", Namespace: "app"},
		Spec: securityapi.AuthorizationPolicy{
			Selector: &istiotype.WorkloadSelector{MatchLabels: map[string]string{"app": "echo-denied"}},
			Action:   securityapi.AuthorizationPolicy_DENY,
			Rules: []*securityapi.Rule{
				{To: []*securityapi.Rule_To{{Operation: &securityapi.Operation{Ports: []string{"9991"}}}}},
				{To: []*securityapi.Rule_To{{Operation: &securityapi.Operation{Ports: []string{"80"}, Methods: []string{"POST"}}}}},
				{From: []*securityapi.Rule_From{{Source: &securityapi.Source{Namespaces: []string{"other"}}}}},
				{To: []*securityapi.Rule_To{{Operation: &securityapi.Operation{Ports: []string{"80"}, Paths: []string{"/admin*"}}}}},
			},
		},
	}
	allowOther := &securityv1.AuthorizationPolicy{
		ObjectMeta: metav1.ObjectMeta{Name: "allow-other", Namespace: "app"},
		Spec: securityapi.AuthorizationPolicy{
			Selector: &istiotype.WorkloadSelector{MatchLabels: map[string]string{"app": "echo-denied"}},
			Action:   securityapi.AuthorizationPolicy_ALLOW,
			Rules: []*securityapi.Rule{
				{From: []*securityapi.Rule_From{{Source: &securityapi.Source{Namespaces: []string{"other"}}}}},
			},
		},
	}
	allowSrc := &securityv1.AuthorizationPolicy{
		ObjectMeta: metav1.ObjectMeta{Name: "allow-src", Namespace: "app"},
		Spec: securityapi.AuthorizationPolicy{
			Selector: &istiotype.WorkloadSelector{MatchLabels: map[string]string{"app": "echo-denied"}},
			Action:   securityapi.AuthorizationPolicy_ALLOW,
			Rules: []*securityapi.Rule{
				{From: []*securityapi.Rule_From{{Source: &securityapi.Source{Namespaces: []string{"src"}}}}},
			},
		},
	}
	report := model.NewReport("check service", model.Target{Namespace: "app", Service: "echo-denied"})
	client := &kube.Client{Istio: istiofake.NewSimpleClientset(denyNearMisses, allowOther, allowSrc)}

	inspectIstioAuthorizationPolicy(context.Background(), client, report, ServiceOptions{Namespace: "app", SourceNamespace: "src", URLPath: "/"}, service, targetPods, source, "http://echo-denied.app.svc.cluster.local/")

	assertResult(t, report, "Istio Authorization Layer", "authorization policies", model.StatusWarn)
	assertDiagnosisContains(t, report, "could not identify the exact AuthorizationPolicy")
	assertDiagnosisNotContains(t, report, "deny-near-misses")
	assertDiagnosisNotContains(t, report, "ALLOW AuthorizationPolicy")
}

func TestInspectIstioAuthorizationPolicyReportsCustomOnlyAsFallback(t *testing.T) {
	service := testService("app", "echo-denied")
	targetPods := []corev1.Pod{
		testPod("app", "echo-denied-abc", map[string]string{"app": "echo-denied"}, true, true),
	}
	source := &ExecTarget{
		Kind: "source pod",
		Pod:  testPod("src", "curl-abc", map[string]string{"app": "curl"}, true, true),
	}
	policy := &securityv1.AuthorizationPolicy{
		ObjectMeta: metav1.ObjectMeta{Name: "external-authz", Namespace: "app"},
		Spec: securityapi.AuthorizationPolicy{
			Selector: &istiotype.WorkloadSelector{MatchLabels: map[string]string{"app": "echo-denied"}},
			Action:   securityapi.AuthorizationPolicy_CUSTOM,
			ActionDetail: &securityapi.AuthorizationPolicy_Provider{
				Provider: &securityapi.AuthorizationPolicy_ExtensionProvider{Name: "corp-authz"},
			},
			Rules: []*securityapi.Rule{
				{To: []*securityapi.Rule_To{{Operation: &securityapi.Operation{Paths: []string{"/admin*"}}}}},
			},
		},
	}
	report := model.NewReport("check service", model.Target{Namespace: "app", Service: "echo-denied"})
	client := &kube.Client{Istio: istiofake.NewSimpleClientset(policy)}

	inspectIstioAuthorizationPolicy(context.Background(), client, report, ServiceOptions{Namespace: "app", SourceNamespace: "src", URLPath: "/admin/panel"}, service, targetPods, source, "http://echo-denied.app.svc.cluster.local/admin/panel")

	assertResult(t, report, "Istio Authorization Layer", "custom authorization", model.StatusWarn)
	assertDiagnosisContains(t, report, "CUSTOM AuthorizationPolicy")
	assertDiagnosisContains(t, report, "provider \"corp-authz\"")
	assertDiagnosisContains(t, report, "does not evaluate external auth providers")
}

func TestInspectIstioAuthorizationPolicyReportsRequestAuthenticationPointer(t *testing.T) {
	service := testService("app", "echo-denied")
	targetPods := []corev1.Pod{
		testPod("app", "echo-denied-abc", map[string]string{"app": "echo-denied"}, true, true),
	}
	source := &ExecTarget{
		Kind: "source pod",
		Pod:  testPod("src", "curl-abc", map[string]string{"app": "curl"}, true, true),
	}
	requestAuth := &securityv1.RequestAuthentication{
		ObjectMeta: metav1.ObjectMeta{Name: "jwt", Namespace: "app"},
		Spec: securityapi.RequestAuthentication{
			Selector: &istiotype.WorkloadSelector{MatchLabels: map[string]string{"app": "echo-denied"}},
			JwtRules: []*securityapi.JWTRule{
				{Issuer: "https://issuer.example"},
			},
		},
	}
	allowJWT := &securityv1.AuthorizationPolicy{
		ObjectMeta: metav1.ObjectMeta{Name: "allow-jwt", Namespace: "app"},
		Spec: securityapi.AuthorizationPolicy{
			Selector: &istiotype.WorkloadSelector{MatchLabels: map[string]string{"app": "echo-denied"}},
			Action:   securityapi.AuthorizationPolicy_ALLOW,
			Rules: []*securityapi.Rule{
				{From: []*securityapi.Rule_From{{Source: &securityapi.Source{RequestPrincipals: []string{"https://issuer.example/*"}}}}},
			},
		},
	}
	report := model.NewReport("check service", model.Target{Namespace: "app", Service: "echo-denied"})
	client := &kube.Client{Istio: istiofake.NewSimpleClientset(requestAuth, allowJWT)}

	inspectIstioAuthorizationPolicy(context.Background(), client, report, ServiceOptions{Namespace: "app", SourceNamespace: "src"}, service, targetPods, source, "http://echo-denied.app.svc.cluster.local/")

	assertResult(t, report, "Istio JWT Layer", "request authentication", model.StatusWarn)
	assertDiagnosisContains(t, report, "RequestAuthentication")
	assertDiagnosisContains(t, report, "https://issuer.example")
	assertDiagnosisContains(t, report, "does not validate JWT tokens")
	assertDiagnosisNotContains(t, report, "ALLOW AuthorizationPolicy")
}

func TestInspectIstioRequestAuthenticationReportsJWT401(t *testing.T) {
	service := testService("app", "echo-denied")
	targetPods := []corev1.Pod{
		testPod("app", "echo-denied-abc", map[string]string{"app": "echo-denied"}, true, true),
	}
	requestAuth := &securityv1.RequestAuthentication{
		ObjectMeta: metav1.ObjectMeta{Name: "jwt", Namespace: "app"},
		Spec: securityapi.RequestAuthentication{
			Selector: &istiotype.WorkloadSelector{MatchLabels: map[string]string{"app": "echo-denied"}},
			JwtRules: []*securityapi.JWTRule{
				{Issuer: "https://issuer.example"},
			},
		},
	}
	report := model.NewReport("check service", model.Target{Namespace: "app", Service: "echo-denied"})
	client := &kube.Client{Istio: istiofake.NewSimpleClientset(requestAuth)}

	ok := inspectIstioRequestAuthentication(context.Background(), client, report, service, targetPods, model.StatusFail)

	if !ok {
		t.Fatal("expected RequestAuthentication pointer")
	}
	assertResult(t, report, "Istio JWT Layer", "request authentication", model.StatusFail)
	assertDiagnosisContains(t, report, "Check JWT issuer/audience/token")
}

func TestInspectIstioSidecarEgressScopeReportsMissingTargetHost(t *testing.T) {
	service := testService("app", "echo-open")
	source := &ExecTarget{
		Kind: "source pod",
		Pod:  testPod("src", "curl-abc", map[string]string{"app": "curl"}, true, true),
	}
	sidecar := &networkingv1.Sidecar{
		ObjectMeta: metav1.ObjectMeta{Name: "curl-scope", Namespace: "src"},
		Spec: networkingapi.Sidecar{
			WorkloadSelector: &networkingapi.WorkloadSelector{Labels: map[string]string{"app": "curl"}},
			Egress: []*networkingapi.IstioEgressListener{
				{Hosts: []string{"./*"}},
			},
		},
	}
	report := model.NewReport("check service", model.Target{Namespace: "app", Service: "echo-open"})
	client := &kube.Client{Istio: istiofake.NewSimpleClientset(sidecar)}

	ok := inspectIstioSidecarEgressScope(context.Background(), client, report, service, source)

	if !ok {
		t.Fatal("expected Sidecar egress scope diagnosis")
	}
	assertResult(t, report, "Istio Sidecar Scope Layer", "src/curl-scope", model.StatusWarn)
	assertDiagnosisContains(t, report, "Sidecar \"src/curl-scope\"")
	assertDiagnosisContains(t, report, "do not include Service \"app/echo-open\"")
}

func TestInspectIstioSidecarEgressScopeAllowsTargetHost(t *testing.T) {
	service := testService("app", "echo-open")
	source := &ExecTarget{
		Kind: "source pod",
		Pod:  testPod("src", "curl-abc", map[string]string{"app": "curl"}, true, true),
	}
	sidecar := &networkingv1.Sidecar{
		ObjectMeta: metav1.ObjectMeta{Name: "curl-scope", Namespace: "src"},
		Spec: networkingapi.Sidecar{
			WorkloadSelector: &networkingapi.WorkloadSelector{Labels: map[string]string{"app": "curl"}},
			Egress: []*networkingapi.IstioEgressListener{
				{Hosts: []string{"./*", "app/echo-open.app.svc.cluster.local"}},
			},
		},
	}
	report := model.NewReport("check service", model.Target{Namespace: "app", Service: "echo-open"})
	client := &kube.Client{Istio: istiofake.NewSimpleClientset(sidecar)}

	if inspectIstioSidecarEgressScope(context.Background(), client, report, service, source) {
		t.Fatal("did not expect Sidecar egress scope diagnosis")
	}
}

func TestInspectIstioAuthorizationPolicyPrefersDenyOverCustom(t *testing.T) {
	service := testService("app", "echo-denied")
	targetPods := []corev1.Pod{
		testPod("app", "echo-denied-abc", map[string]string{"app": "echo-denied"}, true, true),
	}
	source := &ExecTarget{
		Kind: "source pod",
		Pod:  testPod("src", "curl-abc", map[string]string{"app": "curl"}, true, true),
	}
	custom := &securityv1.AuthorizationPolicy{
		ObjectMeta: metav1.ObjectMeta{Name: "external-authz", Namespace: "app"},
		Spec: securityapi.AuthorizationPolicy{
			Selector: &istiotype.WorkloadSelector{MatchLabels: map[string]string{"app": "echo-denied"}},
			Action:   securityapi.AuthorizationPolicy_CUSTOM,
			ActionDetail: &securityapi.AuthorizationPolicy_Provider{
				Provider: &securityapi.AuthorizationPolicy_ExtensionProvider{Name: "corp-authz"},
			},
			Rules: []*securityapi.Rule{{}},
		},
	}
	deny := &securityv1.AuthorizationPolicy{
		ObjectMeta: metav1.ObjectMeta{Name: "deny-src", Namespace: "app"},
		Spec: securityapi.AuthorizationPolicy{
			Selector: &istiotype.WorkloadSelector{MatchLabels: map[string]string{"app": "echo-denied"}},
			Action:   securityapi.AuthorizationPolicy_DENY,
			Rules:    []*securityapi.Rule{{}},
		},
	}
	report := model.NewReport("check service", model.Target{Namespace: "app", Service: "echo-denied"})
	client := &kube.Client{Istio: istiofake.NewSimpleClientset(custom, deny)}

	inspectIstioAuthorizationPolicy(context.Background(), client, report, ServiceOptions{Namespace: "app", SourceNamespace: "src"}, service, targetPods, source, "http://echo-denied.app.svc.cluster.local/")

	assertResult(t, report, "Istio Authorization Layer", "app/deny-src", model.StatusFail)
	assertDiagnosisContains(t, report, "AuthorizationPolicy \"app/deny-src\" denies requests")
	assertDiagnosisNotContains(t, report, "CUSTOM")
}

func TestInspectIstioTrafficRoutingReportsBadSubset(t *testing.T) {
	service := testService("app", "echo-bad-subset")
	targetPods := []corev1.Pod{
		testPod("app", "echo-bad-subset-abc", map[string]string{"app": "echo-bad-subset", "version": "v1"}, true, true),
	}
	virtualService := &networkingv1.VirtualService{
		ObjectMeta: metav1.ObjectMeta{Name: "echo-bad-subset", Namespace: "app"},
		Spec: networkingapi.VirtualService{
			Hosts: []string{"echo-bad-subset.app.svc.cluster.local"},
			Http: []*networkingapi.HTTPRoute{
				{
					Route: []*networkingapi.HTTPRouteDestination{
						{Destination: &networkingapi.Destination{Host: "echo-bad-subset.app.svc.cluster.local", Subset: "v2"}},
					},
				},
			},
		},
	}
	destinationRule := &networkingv1.DestinationRule{
		ObjectMeta: metav1.ObjectMeta{Name: "echo-bad-subset", Namespace: "app"},
		Spec: networkingapi.DestinationRule{
			Host: "echo-bad-subset.app.svc.cluster.local",
			Subsets: []*networkingapi.Subset{
				{Name: "v2", Labels: map[string]string{"version": "v2"}},
			},
		},
	}
	report := model.NewReport("check service", model.Target{Namespace: "app", Service: "echo-bad-subset"})
	client := &kube.Client{Istio: istiofake.NewSimpleClientset(virtualService, destinationRule)}

	inspectIstioTrafficRouting(context.Background(), client, report, ServiceOptions{Namespace: "app"}, service, targetPods, nil, "http://echo-bad-subset.app.svc.cluster.local/")

	assertResult(t, report, "Istio Traffic Routing Layer", "app/echo-bad-subset", model.StatusFail)
	assertDiagnosisContains(t, report, "VirtualService \"app/echo-bad-subset\" HTTP route 1")
	assertDiagnosisContains(t, report, "DestinationRule \"app/echo-bad-subset\" subset \"v2\"")
	assertDiagnosisContains(t, report, "no ready backend pods match labels version=v2")
	assertDiagnosisContains(t, report, "Ready backend pod label values for those keys: version=v1")
	assertDiagnosisNotContains(t, report, "direct pod")
}

func TestInspectIstioTrafficRoutingReportsMatchingRouteNumber(t *testing.T) {
	service := testService("app", "echo-bad-subset")
	targetPods := []corev1.Pod{
		testPod("app", "echo-bad-subset-abc", map[string]string{"app": "echo-bad-subset", "version": "v1"}, true, true),
	}
	virtualService := &networkingv1.VirtualService{
		ObjectMeta: metav1.ObjectMeta{Name: "echo-bad-subset", Namespace: "app"},
		Spec: networkingapi.VirtualService{
			Hosts: []string{"echo-bad-subset.app.svc.cluster.local"},
			Http: []*networkingapi.HTTPRoute{
				testHTTPRoute("/one", "v2"),
				testHTTPRoute("/two", "v2"),
				testHTTPRoute("/three", "v2"),
				{Route: []*networkingapi.HTTPRouteDestination{
					{Destination: &networkingapi.Destination{Host: "echo-bad-subset.app.svc.cluster.local", Subset: "v2"}},
				}},
			},
		},
	}
	destinationRule := &networkingv1.DestinationRule{
		ObjectMeta: metav1.ObjectMeta{Name: "echo-bad-subset", Namespace: "app"},
		Spec: networkingapi.DestinationRule{
			Host: "echo-bad-subset.app.svc.cluster.local",
			Subsets: []*networkingapi.Subset{
				{Name: "v2", Labels: map[string]string{"version": "v2"}},
			},
		},
	}
	report := model.NewReport("check service", model.Target{Namespace: "app", Service: "echo-bad-subset"})
	client := &kube.Client{Istio: istiofake.NewSimpleClientset(virtualService, destinationRule)}

	inspectIstioTrafficRouting(context.Background(), client, report, ServiceOptions{Namespace: "app", URLPath: "/"}, service, targetPods, nil, "http://echo-bad-subset.app.svc.cluster.local/")

	assertDiagnosisContains(t, report, "HTTP route 4")
	assertDiagnosisNotContains(t, report, "HTTP route 1")
}

func TestInspectIstioTrafficRoutingReportsMissingSubset(t *testing.T) {
	service := testService("app", "echo-bad-subset")
	targetPods := []corev1.Pod{
		testPod("app", "echo-bad-subset-abc", map[string]string{"app": "echo-bad-subset", "version": "v1"}, true, true),
	}
	virtualService := &networkingv1.VirtualService{
		ObjectMeta: metav1.ObjectMeta{Name: "echo-bad-subset", Namespace: "app"},
		Spec: networkingapi.VirtualService{
			Hosts: []string{"echo-bad-subset.app.svc.cluster.local"},
			Http: []*networkingapi.HTTPRoute{
				{Route: []*networkingapi.HTTPRouteDestination{
					{Destination: &networkingapi.Destination{Host: "echo-bad-subset.app.svc.cluster.local", Subset: "missing"}},
				}},
			},
		},
	}
	destinationRule := &networkingv1.DestinationRule{
		ObjectMeta: metav1.ObjectMeta{Name: "echo-bad-subset", Namespace: "app"},
		Spec: networkingapi.DestinationRule{
			Host:    "echo-bad-subset.app.svc.cluster.local",
			Subsets: []*networkingapi.Subset{{Name: "v1", Labels: map[string]string{"version": "v1"}}},
		},
	}
	report := model.NewReport("check service", model.Target{Namespace: "app", Service: "echo-bad-subset"})
	client := &kube.Client{Istio: istiofake.NewSimpleClientset(virtualService, destinationRule)}

	inspectIstioTrafficRouting(context.Background(), client, report, ServiceOptions{Namespace: "app"}, service, targetPods, nil, "http://echo-bad-subset.app.svc.cluster.local/")

	assertDiagnosisContains(t, report, "subset is missing")
	assertDiagnosisContains(t, report, "subset \"missing\"")
}

func TestInspectIstioTrafficRoutingReportsWeightedBadDestination(t *testing.T) {
	service := testService("app", "echo-bad-subset")
	targetPods := []corev1.Pod{
		testPod("app", "echo-bad-subset-abc", map[string]string{"app": "echo-bad-subset", "version": "v1"}, true, true),
	}
	virtualService := &networkingv1.VirtualService{
		ObjectMeta: metav1.ObjectMeta{Name: "echo-bad-subset", Namespace: "app"},
		Spec: networkingapi.VirtualService{
			Hosts: []string{"echo-bad-subset.app.svc.cluster.local"},
			Http: []*networkingapi.HTTPRoute{
				{Route: []*networkingapi.HTTPRouteDestination{
					{Destination: &networkingapi.Destination{Host: "echo-bad-subset.app.svc.cluster.local", Subset: "v1"}, Weight: 90},
					{Destination: &networkingapi.Destination{Host: "echo-bad-subset.app.svc.cluster.local", Subset: "v2"}, Weight: 10},
				}},
			},
		},
	}
	destinationRule := &networkingv1.DestinationRule{
		ObjectMeta: metav1.ObjectMeta{Name: "echo-bad-subset", Namespace: "app"},
		Spec: networkingapi.DestinationRule{
			Host: "echo-bad-subset.app.svc.cluster.local",
			Subsets: []*networkingapi.Subset{
				{Name: "v1", Labels: map[string]string{"version": "v1"}},
				{Name: "v2", Labels: map[string]string{"version": "v2"}},
			},
		},
	}
	report := model.NewReport("check service", model.Target{Namespace: "app", Service: "echo-bad-subset"})
	client := &kube.Client{Istio: istiofake.NewSimpleClientset(virtualService, destinationRule)}

	inspectIstioTrafficRouting(context.Background(), client, report, ServiceOptions{Namespace: "app"}, service, targetPods, nil, "http://echo-bad-subset.app.svc.cluster.local/")

	assertDiagnosisContains(t, report, "subset \"v2\" with weight 10")
	assertDiagnosisNotContains(t, report, "subset \"v1\"")
}

func TestInspectIstioWeightedRouteRisksReportsPartialBadDestination(t *testing.T) {
	service := testService("app", "echo-bad-subset")
	targetPods := []corev1.Pod{
		testPod("app", "echo-bad-subset-abc", map[string]string{"app": "echo-bad-subset", "version": "v1"}, true, true),
	}
	virtualService := &networkingv1.VirtualService{
		ObjectMeta: metav1.ObjectMeta{Name: "echo-bad-subset", Namespace: "app"},
		Spec: networkingapi.VirtualService{
			Hosts: []string{"echo-bad-subset.app.svc.cluster.local"},
			Http: []*networkingapi.HTTPRoute{
				{Route: []*networkingapi.HTTPRouteDestination{
					{Destination: &networkingapi.Destination{Host: "echo-bad-subset.app.svc.cluster.local", Subset: "v1"}, Weight: 90},
					{Destination: &networkingapi.Destination{Host: "echo-bad-subset.app.svc.cluster.local", Subset: "v2"}, Weight: 10},
				}},
			},
		},
	}
	destinationRule := &networkingv1.DestinationRule{
		ObjectMeta: metav1.ObjectMeta{Name: "echo-bad-subset", Namespace: "app"},
		Spec: networkingapi.DestinationRule{
			Host: "echo-bad-subset.app.svc.cluster.local",
			Subsets: []*networkingapi.Subset{
				{Name: "v1", Labels: map[string]string{"version": "v1"}},
				{Name: "v2", Labels: map[string]string{"version": "v2"}},
			},
		},
	}
	report := model.NewReport("check service", model.Target{Namespace: "app", Service: "echo-bad-subset"})
	client := &kube.Client{Istio: istiofake.NewSimpleClientset(virtualService, destinationRule)}

	ok := inspectIstioWeightedRouteRisks(context.Background(), client, report, ServiceOptions{Namespace: "app", URLPath: "/"}, service, targetPods, nil, "http://echo-bad-subset.app.svc.cluster.local/")

	if !ok {
		t.Fatalf("expected weighted route risk")
	}
	assertResult(t, report, "Istio Traffic Routing Layer", "app/echo-bad-subset weighted destinations", model.StatusWarn)
	assertDiagnosisContains(t, report, "splits traffic across weighted destinations")
	assertDiagnosisContains(t, report, "subset \"v2\" with weight 10 has no ready pods matching version=v2")
	assertDiagnosisContains(t, report, "subset \"v1\" with weight 90 matches ready pods with version=v1")
}

func TestInspectIstioWeightedRouteRisksReportsSubsetTLSMismatch(t *testing.T) {
	service := testService("app", "echo-open")
	targetPods := []corev1.Pod{
		testPod("app", "echo-open-v1", map[string]string{"app": "echo-open", "version": "v1"}, true, true),
		testPod("app", "echo-open-v2", map[string]string{"app": "echo-open", "version": "v2"}, true, true),
	}
	source := &ExecTarget{
		Kind: "source pod",
		Pod:  testPod("src", "curl-abc", map[string]string{"app": "curl"}, true, true),
	}
	peerAuth := &securityv1.PeerAuthentication{
		ObjectMeta: metav1.ObjectMeta{Name: "strict-target", Namespace: "app"},
		Spec: securityapi.PeerAuthentication{
			Selector: &istiotype.WorkloadSelector{MatchLabels: map[string]string{"app": "echo-open"}},
			Mtls:     &securityapi.PeerAuthentication_MutualTLS{Mode: securityapi.PeerAuthentication_MutualTLS_STRICT},
		},
	}
	virtualService := &networkingv1.VirtualService{
		ObjectMeta: metav1.ObjectMeta{Name: "echo-open", Namespace: "app"},
		Spec: networkingapi.VirtualService{
			Hosts: []string{"echo-open.app.svc.cluster.local"},
			Http: []*networkingapi.HTTPRoute{
				{Route: []*networkingapi.HTTPRouteDestination{
					{Destination: &networkingapi.Destination{Host: "echo-open.app.svc.cluster.local", Subset: "v1"}, Weight: 50},
					{Destination: &networkingapi.Destination{Host: "echo-open.app.svc.cluster.local", Subset: "v2"}, Weight: 50},
				}},
			},
		},
	}
	destinationRule := &networkingv1.DestinationRule{
		ObjectMeta: metav1.ObjectMeta{Name: "echo-open", Namespace: "src"},
		Spec: networkingapi.DestinationRule{
			Host: "echo-open.app.svc.cluster.local",
			Subsets: []*networkingapi.Subset{
				{Name: "v1", Labels: map[string]string{"version": "v1"}},
				{
					Name:   "v2",
					Labels: map[string]string{"version": "v2"},
					TrafficPolicy: &networkingapi.TrafficPolicy{
						Tls: &networkingapi.ClientTLSSettings{Mode: networkingapi.ClientTLSSettings_DISABLE},
					},
				},
			},
		},
	}
	report := model.NewReport("check service", model.Target{Namespace: "app", Service: "echo-open", ServicePort: 80})
	client := &kube.Client{Istio: istiofake.NewSimpleClientset(peerAuth, virtualService, destinationRule)}

	ok := inspectIstioWeightedRouteRisks(context.Background(), client, report, ServiceOptions{Namespace: "app", SourceNamespace: "src"}, service, targetPods, source, "http://echo-open.app.svc.cluster.local/")

	if !ok {
		t.Fatal("expected weighted TLS risk")
	}
	assertResult(t, report, "Istio Traffic Routing Layer", "app/echo-open weighted destinations", model.StatusWarn)
	assertDiagnosisContains(t, report, "subset \"v2\" with weight 50 sets DestinationRule \"src/echo-open\" TLS mode DISABLE")
	assertDiagnosisContains(t, report, "subset \"v1\" with weight 50 matches ready pods with version=v1")
}

func TestInspectIstioTrafficRoutingHonorsHTTPMatchFields(t *testing.T) {
	service := testService("app", "echo-bad-subset")
	targetPods := []corev1.Pod{
		testPod("app", "echo-bad-subset-abc", map[string]string{"app": "echo-bad-subset", "version": "v1"}, true, true),
	}
	source := testPod("src", "curl-abc", map[string]string{"app": "curl"}, true, true)
	virtualService := &networkingv1.VirtualService{
		ObjectMeta: metav1.ObjectMeta{Name: "echo-bad-subset", Namespace: "app"},
		Spec: networkingapi.VirtualService{
			Hosts: []string{"echo-bad-subset"},
			Http: []*networkingapi.HTTPRoute{
				{
					Match: []*networkingapi.HTTPMatchRequest{
						{Method: &networkingapi.StringMatch{MatchType: &networkingapi.StringMatch_Exact{Exact: "POST"}}},
					},
					Route: []*networkingapi.HTTPRouteDestination{
						{Destination: &networkingapi.Destination{Host: "echo-bad-subset", Subset: "v2"}},
					},
				},
				{
					Match: []*networkingapi.HTTPMatchRequest{
						{SourceNamespace: "other"},
					},
					Route: []*networkingapi.HTTPRouteDestination{
						{Destination: &networkingapi.Destination{Host: "echo-bad-subset", Subset: "v2"}},
					},
				},
				{
					Match: []*networkingapi.HTTPMatchRequest{
						{QueryParams: map[string]*networkingapi.StringMatch{
							"version": {MatchType: &networkingapi.StringMatch_Exact{Exact: "canary"}},
						}},
					},
					Route: []*networkingapi.HTTPRouteDestination{
						{Destination: &networkingapi.Destination{Host: "echo-bad-subset", Subset: "v2"}},
					},
				},
				{
					Match: []*networkingapi.HTTPMatchRequest{
						{
							Uri:             &networkingapi.StringMatch{MatchType: &networkingapi.StringMatch_Prefix{Prefix: "/api"}},
							Method:          &networkingapi.StringMatch{MatchType: &networkingapi.StringMatch_Exact{Exact: "GET"}},
							Scheme:          &networkingapi.StringMatch{MatchType: &networkingapi.StringMatch_Exact{Exact: "http"}},
							SourceNamespace: "src",
							SourceLabels:    map[string]string{"app": "curl"},
							QueryParams: map[string]*networkingapi.StringMatch{
								"version": {MatchType: &networkingapi.StringMatch_Exact{Exact: "v1"}},
							},
						},
					},
					Route: []*networkingapi.HTTPRouteDestination{
						{Destination: &networkingapi.Destination{Host: "echo-bad-subset", Subset: "v2"}},
					},
				},
			},
		},
	}
	destinationRule := &networkingv1.DestinationRule{
		ObjectMeta: metav1.ObjectMeta{Name: "echo-bad-subset", Namespace: "app"},
		Spec: networkingapi.DestinationRule{
			Host: "echo-bad-subset",
			Subsets: []*networkingapi.Subset{
				{Name: "v2", Labels: map[string]string{"version": "v2"}},
			},
		},
	}
	report := model.NewReport("check service", model.Target{Namespace: "app", Service: "echo-bad-subset"})
	client := &kube.Client{Istio: istiofake.NewSimpleClientset(virtualService, destinationRule)}

	inspectIstioTrafficRouting(context.Background(), client, report, ServiceOptions{Namespace: "app", SourceNamespace: "src", URLScheme: "http", URLPath: "/api/items?version=v1"}, service, targetPods, &ExecTarget{Pod: source}, "http://echo-bad-subset.app.svc.cluster.local/api/items?version=v1")

	assertDiagnosisContains(t, report, "HTTP route 4")
	assertDiagnosisNotContains(t, report, "HTTP route 1")
	assertDiagnosisNotContains(t, report, "HTTP route 2")
	assertDiagnosisNotContains(t, report, "HTTP route 3")
}

func TestInspectIstioTrafficRoutingHonorsHeadersAndPort(t *testing.T) {
	service := testService("app", "echo-bad-subset")
	targetPods := []corev1.Pod{
		testPod("app", "echo-bad-subset-abc", map[string]string{"app": "echo-bad-subset", "version": "v1"}, true, true),
	}
	virtualService := &networkingv1.VirtualService{
		ObjectMeta: metav1.ObjectMeta{Name: "echo-bad-subset", Namespace: "app"},
		Spec: networkingapi.VirtualService{
			Hosts: []string{"echo-bad-subset.app.svc.cluster.local"},
			Http: []*networkingapi.HTTPRoute{
				{
					Match: []*networkingapi.HTTPMatchRequest{{
						Port: 9999,
						Headers: map[string]*networkingapi.StringMatch{
							"x-env": {MatchType: &networkingapi.StringMatch_Exact{Exact: "prod"}},
						},
					}},
					Route: []*networkingapi.HTTPRouteDestination{
						{Destination: &networkingapi.Destination{Host: "echo-bad-subset.app.svc.cluster.local", Subset: "v2"}},
					},
				},
				{
					Match: []*networkingapi.HTTPMatchRequest{{
						Port: 80,
						Headers: map[string]*networkingapi.StringMatch{
							"x-env": {MatchType: &networkingapi.StringMatch_Exact{Exact: "prod"}},
						},
					}},
					Route: []*networkingapi.HTTPRouteDestination{
						{Destination: &networkingapi.Destination{Host: "echo-bad-subset.app.svc.cluster.local", Subset: "v2"}},
					},
				},
			},
		},
	}
	destinationRule := &networkingv1.DestinationRule{
		ObjectMeta: metav1.ObjectMeta{Name: "echo-bad-subset", Namespace: "app"},
		Spec: networkingapi.DestinationRule{
			Host:    "echo-bad-subset.app.svc.cluster.local",
			Subsets: []*networkingapi.Subset{{Name: "v2", Labels: map[string]string{"version": "v2"}}},
		},
	}
	report := model.NewReport("check service", model.Target{Namespace: "app", Service: "echo-bad-subset"})
	client := &kube.Client{Istio: istiofake.NewSimpleClientset(virtualService, destinationRule)}

	inspectIstioTrafficRouting(context.Background(), client, report, ServiceOptions{Namespace: "app", ServicePort: 80, HTTPHeaders: map[string]string{"X-Env": "prod"}}, service, targetPods, nil, "http://echo-bad-subset.app.svc.cluster.local/")

	assertDiagnosisContains(t, report, "HTTP route 2")
	assertDiagnosisNotContains(t, report, "HTTP route 1")
}

func TestInspectIstioTrafficRoutingUsesSourceNamespaceConfig(t *testing.T) {
	service := testService("app", "echo-bad-subset")
	targetPods := []corev1.Pod{
		testPod("app", "echo-bad-subset-abc", map[string]string{"app": "echo-bad-subset", "version": "v1"}, true, true),
	}
	source := testPod("src", "curl-abc", map[string]string{"app": "curl"}, true, true)
	virtualService := &networkingv1.VirtualService{
		ObjectMeta: metav1.ObjectMeta{Name: "echo-bad-subset-src", Namespace: "src"},
		Spec: networkingapi.VirtualService{
			Hosts: []string{"echo-bad-subset.app.svc.cluster.local"},
			Http: []*networkingapi.HTTPRoute{
				{Route: []*networkingapi.HTTPRouteDestination{
					{Destination: &networkingapi.Destination{Host: "echo-bad-subset.app.svc.cluster.local", Subset: "v2"}},
				}},
			},
		},
	}
	destinationRule := &networkingv1.DestinationRule{
		ObjectMeta: metav1.ObjectMeta{Name: "echo-bad-subset-src", Namespace: "src"},
		Spec: networkingapi.DestinationRule{
			Host:    "echo-bad-subset.app.svc.cluster.local",
			Subsets: []*networkingapi.Subset{{Name: "v2", Labels: map[string]string{"version": "v2"}}},
		},
	}
	report := model.NewReport("check service", model.Target{Namespace: "app", Service: "echo-bad-subset"})
	client := &kube.Client{Istio: istiofake.NewSimpleClientset(virtualService, destinationRule)}

	inspectIstioTrafficRouting(context.Background(), client, report, ServiceOptions{Namespace: "app", SourceNamespace: "src"}, service, targetPods, &ExecTarget{Pod: source}, "http://echo-bad-subset.app.svc.cluster.local/")

	assertDiagnosisContains(t, report, "VirtualService \"src/echo-bad-subset-src\"")
	assertDiagnosisContains(t, report, "DestinationRule \"src/echo-bad-subset-src\"")
}

func TestInspectIstioMTLSResetReportsUnmeshedSourceToStrictTarget(t *testing.T) {
	service := testService("app", "echo-bad-subset")
	targetPods := []corev1.Pod{
		testPod("app", "echo-bad-subset-abc", map[string]string{"app": "echo-bad-subset"}, true, true),
	}
	source := &ExecTarget{
		Kind: "source pod",
		Pod:  testPod("plain-src", "curl-abc", map[string]string{"app": "curl"}, true, false),
	}
	peerAuth := &securityv1.PeerAuthentication{
		ObjectMeta: metav1.ObjectMeta{Name: "strict-target", Namespace: "app"},
		Spec: securityapi.PeerAuthentication{
			Selector: &istiotype.WorkloadSelector{MatchLabels: map[string]string{"app": "echo-bad-subset"}},
			Mtls:     &securityapi.PeerAuthentication_MutualTLS{Mode: securityapi.PeerAuthentication_MutualTLS_STRICT},
		},
	}
	report := model.NewReport("check service", model.Target{Namespace: "app", Service: "echo-bad-subset"})
	client := &kube.Client{Istio: istiofake.NewSimpleClientset(peerAuth)}

	ok := inspectIstioMTLSReset(context.Background(), client, report, service, 80, targetPods, source, RuntimeHTTPResult{Error: "curl: (56) Recv failure: Connection reset by peer"})

	if !ok {
		t.Fatal("expected mTLS reset diagnosis")
	}
	assertResult(t, report, "Istio mTLS Layer", "app/strict-target", model.StatusFail)
	assertDiagnosisContains(t, report, "Target workload is under Istio STRICT mTLS")
	assertDiagnosisContains(t, report, "source pod \"plain-src/curl-abc\" is not in the mesh")
}

func TestInspectIstioMTLSResetIgnoresMeshedSource(t *testing.T) {
	service := testService("app", "echo-bad-subset")
	targetPods := []corev1.Pod{
		testPod("app", "echo-bad-subset-abc", map[string]string{"app": "echo-bad-subset"}, true, true),
	}
	source := &ExecTarget{
		Kind: "source pod",
		Pod:  testPod("src", "curl-abc", map[string]string{"app": "curl"}, true, true),
	}
	peerAuth := &securityv1.PeerAuthentication{
		ObjectMeta: metav1.ObjectMeta{Name: "strict-target", Namespace: "app"},
		Spec: securityapi.PeerAuthentication{
			Selector: &istiotype.WorkloadSelector{MatchLabels: map[string]string{"app": "echo-bad-subset"}},
			Mtls:     &securityapi.PeerAuthentication_MutualTLS{Mode: securityapi.PeerAuthentication_MutualTLS_STRICT},
		},
	}
	report := model.NewReport("check service", model.Target{Namespace: "app", Service: "echo-bad-subset"})
	client := &kube.Client{Istio: istiofake.NewSimpleClientset(peerAuth)}

	if inspectIstioMTLSReset(context.Background(), client, report, service, 80, targetPods, source, RuntimeHTTPResult{Error: "curl: (56) Recv failure: Connection reset by peer"}) {
		t.Fatal("did not expect mTLS reset diagnosis for meshed source")
	}
}

func TestInspectIstioDestinationRuleMTLSMismatchReportsPlaintextToStrictTarget(t *testing.T) {
	service := testService("app", "echo-open")
	targetPods := []corev1.Pod{
		testPod("app", "echo-open-abc", map[string]string{"app": "echo-open"}, true, true),
	}
	source := &ExecTarget{
		Kind: "source pod",
		Pod:  testPod("src", "curl-abc", map[string]string{"app": "curl"}, true, true),
	}
	peerAuth := &securityv1.PeerAuthentication{
		ObjectMeta: metav1.ObjectMeta{Name: "strict-target", Namespace: "app"},
		Spec: securityapi.PeerAuthentication{
			Selector: &istiotype.WorkloadSelector{MatchLabels: map[string]string{"app": "echo-open"}},
			Mtls:     &securityapi.PeerAuthentication_MutualTLS{Mode: securityapi.PeerAuthentication_MutualTLS_STRICT},
		},
	}
	destinationRule := &networkingv1.DestinationRule{
		ObjectMeta: metav1.ObjectMeta{Name: "echo-open-plaintext", Namespace: "src"},
		Spec: networkingapi.DestinationRule{
			Host: "echo-open.app.svc.cluster.local",
			TrafficPolicy: &networkingapi.TrafficPolicy{
				Tls: &networkingapi.ClientTLSSettings{Mode: networkingapi.ClientTLSSettings_DISABLE},
			},
		},
	}
	report := model.NewReport("check service", model.Target{Namespace: "app", Service: "echo-open", ServicePort: 80})
	client := &kube.Client{Istio: istiofake.NewSimpleClientset(peerAuth, destinationRule)}

	ok := inspectIstioDestinationRuleMTLSMismatch(context.Background(), client, report, ServiceOptions{Namespace: "app", SourceNamespace: "src"}, service, targetPods, source, "http://echo-open.app.svc.cluster.local/", RuntimeHTTPResult{Error: "curl: (56) Recv failure: Connection reset by peer"})

	if !ok {
		t.Fatal("expected DestinationRule mTLS mismatch diagnosis")
	}
	assertResult(t, report, "Istio mTLS Layer", "src/echo-open-plaintext", model.StatusFail)
	assertDiagnosisContains(t, report, "DestinationRule \"src/echo-open-plaintext\" sets client TLS mode DISABLE")
	assertDiagnosisContains(t, report, "STRICT mTLS")
}

func TestInspectIstioDestinationRuleMTLSMismatchIgnoresIstioMutual(t *testing.T) {
	service := testService("app", "echo-open")
	targetPods := []corev1.Pod{
		testPod("app", "echo-open-abc", map[string]string{"app": "echo-open"}, true, true),
	}
	source := &ExecTarget{
		Kind: "source pod",
		Pod:  testPod("src", "curl-abc", map[string]string{"app": "curl"}, true, true),
	}
	peerAuth := &securityv1.PeerAuthentication{
		ObjectMeta: metav1.ObjectMeta{Name: "strict-target", Namespace: "app"},
		Spec: securityapi.PeerAuthentication{
			Selector: &istiotype.WorkloadSelector{MatchLabels: map[string]string{"app": "echo-open"}},
			Mtls:     &securityapi.PeerAuthentication_MutualTLS{Mode: securityapi.PeerAuthentication_MutualTLS_STRICT},
		},
	}
	destinationRule := &networkingv1.DestinationRule{
		ObjectMeta: metav1.ObjectMeta{Name: "echo-open-mtls", Namespace: "src"},
		Spec: networkingapi.DestinationRule{
			Host: "echo-open.app.svc.cluster.local",
			TrafficPolicy: &networkingapi.TrafficPolicy{
				Tls: &networkingapi.ClientTLSSettings{Mode: networkingapi.ClientTLSSettings_ISTIO_MUTUAL},
			},
		},
	}
	report := model.NewReport("check service", model.Target{Namespace: "app", Service: "echo-open", ServicePort: 80})
	client := &kube.Client{Istio: istiofake.NewSimpleClientset(peerAuth, destinationRule)}

	if inspectIstioDestinationRuleMTLSMismatch(context.Background(), client, report, ServiceOptions{Namespace: "app", SourceNamespace: "src"}, service, targetPods, source, "http://echo-open.app.svc.cluster.local/", RuntimeHTTPResult{Error: "curl: (56) Recv failure: Connection reset by peer"}) {
		t.Fatal("did not expect DestinationRule mTLS mismatch diagnosis")
	}
}

func TestInspectIstioDestinationRuleMTLSMismatchReportsSubsetOverride(t *testing.T) {
	service := testService("app", "echo-open")
	targetPods := []corev1.Pod{
		testPod("app", "echo-open-abc", map[string]string{"app": "echo-open", "version": "v1"}, true, true),
	}
	source := &ExecTarget{
		Kind: "source pod",
		Pod:  testPod("src", "curl-abc", map[string]string{"app": "curl"}, true, true),
	}
	peerAuth := &securityv1.PeerAuthentication{
		ObjectMeta: metav1.ObjectMeta{Name: "strict-target", Namespace: "app"},
		Spec: securityapi.PeerAuthentication{
			Selector: &istiotype.WorkloadSelector{MatchLabels: map[string]string{"app": "echo-open"}},
			Mtls:     &securityapi.PeerAuthentication_MutualTLS{Mode: securityapi.PeerAuthentication_MutualTLS_STRICT},
		},
	}
	virtualService := &networkingv1.VirtualService{
		ObjectMeta: metav1.ObjectMeta{Name: "echo-open", Namespace: "app"},
		Spec: networkingapi.VirtualService{
			Hosts: []string{"echo-open.app.svc.cluster.local"},
			Http: []*networkingapi.HTTPRoute{
				{Route: []*networkingapi.HTTPRouteDestination{
					{Destination: &networkingapi.Destination{Host: "echo-open.app.svc.cluster.local", Subset: "v1"}},
				}},
			},
		},
	}
	destinationRule := &networkingv1.DestinationRule{
		ObjectMeta: metav1.ObjectMeta{Name: "echo-open-subset-plaintext", Namespace: "src"},
		Spec: networkingapi.DestinationRule{
			Host: "echo-open.app.svc.cluster.local",
			TrafficPolicy: &networkingapi.TrafficPolicy{
				Tls: &networkingapi.ClientTLSSettings{Mode: networkingapi.ClientTLSSettings_ISTIO_MUTUAL},
			},
			Subsets: []*networkingapi.Subset{
				{
					Name:   "v1",
					Labels: map[string]string{"version": "v1"},
					TrafficPolicy: &networkingapi.TrafficPolicy{
						Tls: &networkingapi.ClientTLSSettings{Mode: networkingapi.ClientTLSSettings_DISABLE},
					},
				},
			},
		},
	}
	report := model.NewReport("check service", model.Target{Namespace: "app", Service: "echo-open", ServicePort: 80})
	client := &kube.Client{Istio: istiofake.NewSimpleClientset(peerAuth, virtualService, destinationRule)}

	ok := inspectIstioDestinationRuleMTLSMismatch(context.Background(), client, report, ServiceOptions{Namespace: "app", SourceNamespace: "src"}, service, targetPods, source, "http://echo-open.app.svc.cluster.local/", RuntimeHTTPResult{Error: "curl: (56) Recv failure: Connection reset by peer"})

	if !ok {
		t.Fatal("expected subset DestinationRule mTLS mismatch diagnosis")
	}
	assertResult(t, report, "Istio mTLS Layer", "src/echo-open-subset-plaintext", model.StatusFail)
	assertDiagnosisContains(t, report, "subset \"v1\"")
	assertDiagnosisContains(t, report, "TLS mode DISABLE")
}

func TestInspectIstioDestinationRuleMTLSMismatchReportsSubsetPortOverride(t *testing.T) {
	service := testService("app", "echo-open")
	targetPods := []corev1.Pod{
		testPod("app", "echo-open-abc", map[string]string{"app": "echo-open", "version": "v1"}, true, true),
	}
	source := &ExecTarget{
		Kind: "source pod",
		Pod:  testPod("src", "curl-abc", map[string]string{"app": "curl"}, true, true),
	}
	peerAuth := &securityv1.PeerAuthentication{
		ObjectMeta: metav1.ObjectMeta{Name: "strict-target", Namespace: "app"},
		Spec: securityapi.PeerAuthentication{
			Selector: &istiotype.WorkloadSelector{MatchLabels: map[string]string{"app": "echo-open"}},
			Mtls:     &securityapi.PeerAuthentication_MutualTLS{Mode: securityapi.PeerAuthentication_MutualTLS_STRICT},
		},
	}
	virtualService := &networkingv1.VirtualService{
		ObjectMeta: metav1.ObjectMeta{Name: "echo-open", Namespace: "app"},
		Spec: networkingapi.VirtualService{
			Hosts: []string{"echo-open.app.svc.cluster.local"},
			Http: []*networkingapi.HTTPRoute{
				{Route: []*networkingapi.HTTPRouteDestination{
					{Destination: &networkingapi.Destination{Host: "echo-open.app.svc.cluster.local", Subset: "v1"}},
				}},
			},
		},
	}
	destinationRule := &networkingv1.DestinationRule{
		ObjectMeta: metav1.ObjectMeta{Name: "echo-open-subset-port-plaintext", Namespace: "src"},
		Spec: networkingapi.DestinationRule{
			Host: "echo-open.app.svc.cluster.local",
			Subsets: []*networkingapi.Subset{
				{
					Name:   "v1",
					Labels: map[string]string{"version": "v1"},
					TrafficPolicy: &networkingapi.TrafficPolicy{
						Tls: &networkingapi.ClientTLSSettings{Mode: networkingapi.ClientTLSSettings_ISTIO_MUTUAL},
						PortLevelSettings: []*networkingapi.TrafficPolicy_PortTrafficPolicy{
							{
								Port: &networkingapi.PortSelector{Number: 80},
								Tls:  &networkingapi.ClientTLSSettings{Mode: networkingapi.ClientTLSSettings_DISABLE},
							},
						},
					},
				},
			},
		},
	}
	report := model.NewReport("check service", model.Target{Namespace: "app", Service: "echo-open", ServicePort: 80})
	client := &kube.Client{Istio: istiofake.NewSimpleClientset(peerAuth, virtualService, destinationRule)}

	ok := inspectIstioDestinationRuleMTLSMismatch(context.Background(), client, report, ServiceOptions{Namespace: "app", SourceNamespace: "src"}, service, targetPods, source, "http://echo-open.app.svc.cluster.local/", RuntimeHTTPResult{Error: "curl: (56) Recv failure: Connection reset by peer"})

	if !ok {
		t.Fatal("expected subset port DestinationRule mTLS mismatch diagnosis")
	}
	assertResult(t, report, "Istio mTLS Layer", "src/echo-open-subset-port-plaintext", model.StatusFail)
	assertDiagnosisContains(t, report, "subset \"v1\"")
	assertDiagnosisContains(t, report, "service port 80")
	assertDiagnosisContains(t, report, "TLS mode DISABLE")
}

func TestEffectivePeerAuthenticationUsesNamespaceDefault(t *testing.T) {
	service := testService("app", "echo-open")
	targetPods := []corev1.Pod{
		testPod("app", "echo-open-abc", map[string]string{"app": "echo-open"}, true, true),
	}
	peerAuth := &securityv1.PeerAuthentication{
		ObjectMeta: metav1.ObjectMeta{Name: "default", Namespace: "app"},
		Spec: securityapi.PeerAuthentication{
			Mtls: &securityapi.PeerAuthentication_MutualTLS{Mode: securityapi.PeerAuthentication_MutualTLS_STRICT},
		},
	}
	client := &kube.Client{Istio: istiofake.NewSimpleClientset(peerAuth)}

	effective := effectivePeerAuthenticationForPods(context.Background(), client, service, 80, targetPods)

	if effective.Mode != securityapi.PeerAuthentication_MutualTLS_STRICT {
		t.Fatalf("expected STRICT, got %s", effective.Mode.String())
	}
	if effective.Name != "app/default" {
		t.Fatalf("expected app/default, got %s", effective.Name)
	}
	if effective.Port != 8080 {
		t.Fatalf("expected workload port 8080, got %d", effective.Port)
	}
}

func TestEffectivePeerAuthenticationUsesRootNamespaceDefault(t *testing.T) {
	service := testService("app", "echo-open")
	targetPods := []corev1.Pod{
		testPod("app", "echo-open-abc", map[string]string{"app": "echo-open"}, true, true),
	}
	peerAuth := &securityv1.PeerAuthentication{
		ObjectMeta: metav1.ObjectMeta{Name: "default", Namespace: "istio-system"},
		Spec: securityapi.PeerAuthentication{
			Mtls: &securityapi.PeerAuthentication_MutualTLS{Mode: securityapi.PeerAuthentication_MutualTLS_STRICT},
		},
	}
	client := &kube.Client{Istio: istiofake.NewSimpleClientset(peerAuth)}

	effective := effectivePeerAuthenticationForPods(context.Background(), client, service, 80, targetPods)

	if effective.Mode != securityapi.PeerAuthentication_MutualTLS_STRICT {
		t.Fatalf("expected STRICT, got %s", effective.Mode.String())
	}
	if effective.Name != "istio-system/default" {
		t.Fatalf("expected istio-system/default, got %s", effective.Name)
	}
}

func TestEffectivePeerAuthenticationWorkloadOverridesRootNamespaceDefault(t *testing.T) {
	service := testService("app", "echo-open")
	targetPods := []corev1.Pod{
		testPod("app", "echo-open-abc", map[string]string{"app": "echo-open"}, true, true),
	}
	meshStrict := &securityv1.PeerAuthentication{
		ObjectMeta: metav1.ObjectMeta{Name: "default", Namespace: "istio-system"},
		Spec: securityapi.PeerAuthentication{
			Mtls: &securityapi.PeerAuthentication_MutualTLS{Mode: securityapi.PeerAuthentication_MutualTLS_STRICT},
		},
	}
	workloadPermissive := &securityv1.PeerAuthentication{
		ObjectMeta: metav1.ObjectMeta{Name: "echo-open-permissive", Namespace: "app"},
		Spec: securityapi.PeerAuthentication{
			Selector: &istiotype.WorkloadSelector{MatchLabels: map[string]string{"app": "echo-open"}},
			Mtls:     &securityapi.PeerAuthentication_MutualTLS{Mode: securityapi.PeerAuthentication_MutualTLS_PERMISSIVE},
		},
	}
	client := &kube.Client{Istio: istiofake.NewSimpleClientset(meshStrict, workloadPermissive)}

	effective := effectivePeerAuthenticationForPods(context.Background(), client, service, 80, targetPods)

	if effective.Mode != securityapi.PeerAuthentication_MutualTLS_PERMISSIVE {
		t.Fatalf("expected PERMISSIVE, got %s", effective.Mode.String())
	}
	if effective.Name != "app/echo-open-permissive" {
		t.Fatalf("expected app/echo-open-permissive, got %s", effective.Name)
	}
}

func TestEffectivePeerAuthenticationHonorsPortLevelOverride(t *testing.T) {
	service := testService("app", "echo-open")
	targetPods := []corev1.Pod{
		testPod("app", "echo-open-abc", map[string]string{"app": "echo-open"}, true, true),
	}
	peerAuth := &securityv1.PeerAuthentication{
		ObjectMeta: metav1.ObjectMeta{Name: "strict-except-8080", Namespace: "app"},
		Spec: securityapi.PeerAuthentication{
			Selector: &istiotype.WorkloadSelector{MatchLabels: map[string]string{"app": "echo-open"}},
			Mtls:     &securityapi.PeerAuthentication_MutualTLS{Mode: securityapi.PeerAuthentication_MutualTLS_STRICT},
			PortLevelMtls: map[uint32]*securityapi.PeerAuthentication_MutualTLS{
				8080: {Mode: securityapi.PeerAuthentication_MutualTLS_PERMISSIVE},
			},
		},
	}
	client := &kube.Client{Istio: istiofake.NewSimpleClientset(peerAuth)}

	effective := effectivePeerAuthenticationForPods(context.Background(), client, service, 80, targetPods)

	if effective.Mode != securityapi.PeerAuthentication_MutualTLS_PERMISSIVE {
		t.Fatalf("expected PERMISSIVE, got %s", effective.Mode.String())
	}
}

func TestInspectIstioTrafficRoutingUsesActualRuntimeAuthority(t *testing.T) {
	service := testService("app", "echo-bad-subset")
	targetPods := []corev1.Pod{
		testPod("app", "echo-bad-subset-abc", map[string]string{"app": "echo-bad-subset", "version": "v1"}, true, true),
	}
	virtualService := &networkingv1.VirtualService{
		ObjectMeta: metav1.ObjectMeta{Name: "echo-bad-subset", Namespace: "app"},
		Spec: networkingapi.VirtualService{
			Hosts: []string{"echo-bad-subset.app.svc.cluster.local"},
			Http: []*networkingapi.HTTPRoute{
				{
					Match: []*networkingapi.HTTPMatchRequest{
						{Authority: &networkingapi.StringMatch{MatchType: &networkingapi.StringMatch_Exact{Exact: "echo-bad-subset"}}},
					},
					Route: []*networkingapi.HTTPRouteDestination{
						{Destination: &networkingapi.Destination{Host: "echo-bad-subset.app.svc.cluster.local", Subset: "v2"}},
					},
				},
				{
					Route: []*networkingapi.HTTPRouteDestination{
						{Destination: &networkingapi.Destination{Host: "echo-bad-subset.app.svc.cluster.local", Subset: "v2"}},
					},
				},
			},
		},
	}
	destinationRule := &networkingv1.DestinationRule{
		ObjectMeta: metav1.ObjectMeta{Name: "echo-bad-subset", Namespace: "app"},
		Spec: networkingapi.DestinationRule{
			Host: "echo-bad-subset.app.svc.cluster.local",
			Subsets: []*networkingapi.Subset{
				{Name: "v2", Labels: map[string]string{"version": "v2"}},
			},
		},
	}
	report := model.NewReport("check service", model.Target{Namespace: "app", Service: "echo-bad-subset"})
	client := &kube.Client{Istio: istiofake.NewSimpleClientset(virtualService, destinationRule)}

	inspectIstioTrafficRouting(context.Background(), client, report, ServiceOptions{Namespace: "app", URLPath: "/"}, service, targetPods, nil, "http://echo-bad-subset.app.svc.cluster.local/")

	assertDiagnosisContains(t, report, "HTTP route 2")
	assertDiagnosisNotContains(t, report, "HTTP route 1")
}

func TestIstioShortHostDoesNotMatchDifferentNamespace(t *testing.T) {
	service := testService("app", "echo")

	if istioHostMatchesService("echo", "other", service) {
		t.Fatal("short host in another namespace should not match app/echo")
	}
	if !istioHostMatchesService("echo", "app", service) {
		t.Fatal("short host in service namespace should match app/echo")
	}
	if !istioHostMatchesService("echo.app.svc.cluster.local", "other", service) {
		t.Fatal("fqdn host should match app/echo regardless of config namespace")
	}
}

func testService(namespace, name string) *corev1.Service {
	return &corev1.Service{
		ObjectMeta: metav1.ObjectMeta{Name: name, Namespace: namespace},
		Spec: corev1.ServiceSpec{
			Ports: []corev1.ServicePort{{Name: "http", Port: 80, TargetPort: intstr.FromInt32(8080)}},
		},
	}
}

func testPod(namespace, name string, podLabels map[string]string, ready bool, meshed bool) corev1.Pod {
	pod := corev1.Pod{
		ObjectMeta: metav1.ObjectMeta{Name: name, Namespace: namespace, Labels: podLabels},
		Status: corev1.PodStatus{
			Phase: corev1.PodRunning,
			Conditions: []corev1.PodCondition{
				{Type: corev1.PodReady, Status: corev1.ConditionFalse},
			},
		},
	}
	if ready {
		pod.Status.Conditions[0].Status = corev1.ConditionTrue
	}
	if meshed {
		pod.Spec.Containers = append(pod.Spec.Containers, corev1.Container{Name: "istio-proxy"})
	}
	return pod
}

func testHTTPRoute(path string, subset string) *networkingapi.HTTPRoute {
	return &networkingapi.HTTPRoute{
		Match: []*networkingapi.HTTPMatchRequest{
			{Uri: &networkingapi.StringMatch{MatchType: &networkingapi.StringMatch_Exact{Exact: path}}},
		},
		Route: []*networkingapi.HTTPRouteDestination{
			{Destination: &networkingapi.Destination{Host: "echo-bad-subset.app.svc.cluster.local", Subset: subset}},
		},
	}
}

func assertResult(t *testing.T, report *model.Report, layer, check string, status model.Status) {
	t.Helper()
	for _, result := range report.Results {
		if result.Layer == layer && result.Check == check && result.Status == status {
			return
		}
	}
	t.Fatalf("missing result %s/%s=%s in %#v", layer, check, status, report.Results)
}

func assertDiagnosisContains(t *testing.T, report *model.Report, want string) {
	t.Helper()
	for _, diagnosis := range report.Diagnoses {
		if strings.Contains(diagnosis.Message, want) {
			return
		}
	}
	t.Fatalf("missing diagnosis containing %q in %#v", want, report.Diagnoses)
}

func assertDiagnosisNotContains(t *testing.T, report *model.Report, unwanted string) {
	t.Helper()
	for _, diagnosis := range report.Diagnoses {
		if strings.Contains(strings.ToLower(diagnosis.Message), strings.ToLower(unwanted)) {
			t.Fatalf("diagnosis should not contain %q: %q", unwanted, diagnosis.Message)
		}
	}
}
