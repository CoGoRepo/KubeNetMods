package check

import (
	"context"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/CoGoRepo/KubeNetMods/internal/kube"
	"github.com/CoGoRepo/KubeNetMods/internal/model"
	networkingapi "istio.io/api/networking/v1alpha3"
	networkingv1 "istio.io/client-go/pkg/apis/networking/v1"
	istiofake "istio.io/client-go/pkg/clientset/versioned/fake"
	corev1 "k8s.io/api/core/v1"
	discoveryv1 "k8s.io/api/discovery/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"
	kruntime "k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/runtime/schema"
	"k8s.io/apimachinery/pkg/util/intstr"
	dynamicfake "k8s.io/client-go/dynamic/fake"
	k8sfake "k8s.io/client-go/kubernetes/fake"
)

func TestGatewayScanHealthyNoParam(t *testing.T) {
	client := fakeGatewayClient(t,
		[]unstructured.Unstructured{
			testGatewayClass("istio", "True", "Accepted"),
			testGateway("infra", "public", "istio", true, "True", "True", testGatewayListener("https", nil)),
			testGatewayHTTPRoute("app", "api-route", "infra", "public", []map[string]interface{}{
				testBackendRef("api", "", int64(80)),
			}, "True", "True"),
		},
		[]kruntime.Object{
			testGatewayService("app", "api", 80),
			testGatewayEndpointSlice("app", "api", true, "10.0.0.10"),
		},
	)
	report := model.NewReport("check gateway", model.Target{})

	runGatewayStaticScan(context.Background(), client, report, GatewayOptions{})

	if report.CountByStatus(model.StatusFail) != 0 {
		t.Fatalf("expected no failures, got %#v", report.Results)
	}
	assertResultContains(t, report, model.StatusPass, "No obvious Gateway API")
	if len(report.Diagnoses) != 0 {
		t.Fatalf("expected no diagnoses, got %#v", report.Diagnoses)
	}
}

func TestGatewayScanDiagnosesMissingBackendService(t *testing.T) {
	client := fakeGatewayClient(t,
		[]unstructured.Unstructured{
			testGatewayClass("istio", "True", "Accepted"),
			testGateway("infra", "public", "istio", true, "True", "True", testGatewayListener("http", nil)),
			testGatewayHTTPRoute("app", "api-route", "infra", "public", []map[string]interface{}{
				testBackendRef("missing-api", "", int64(80)),
			}, "True", "False"),
		},
		nil,
	)
	report := model.NewReport("check gateway", model.Target{})

	runGatewayStaticScan(context.Background(), client, report, GatewayOptions{})

	assertResultContains(t, report, model.StatusFail, "missing/unreadable Service app/missing-api")
	assertGatewayDiagnosisContains(t, report, "routes to Service app/missing-api")
	assertGatewayDiagnosisNotContains(t, report, "has unresolved references")
}

func TestGatewayScanDiagnosesCrossNamespaceBackendWithoutReferenceGrant(t *testing.T) {
	client := fakeGatewayClient(t,
		[]unstructured.Unstructured{
			testGatewayClass("istio", "True", "Accepted"),
			testGateway("infra", "public", "istio", true, "True", "True", testGatewayListener("http", nil)),
			testGatewayHTTPRoute("web", "api-route", "infra", "public", []map[string]interface{}{
				testBackendRef("api", "app", int64(80)),
			}, "True", "False"),
		},
		[]kruntime.Object{
			testGatewayService("app", "api", 80),
			testGatewayEndpointSlice("app", "api", true, "10.0.0.10"),
		},
	)
	report := model.NewReport("check gateway", model.Target{})

	runGatewayStaticScan(context.Background(), client, report, GatewayOptions{})

	assertResultContains(t, report, model.StatusFail, "without a matching ReferenceGrant")
	assertGatewayDiagnosisContains(t, report, "does not grant that reference")
	assertGatewayDiagnosisNotContains(t, report, "has unresolved references")
}

func TestGatewayScanAllowsCrossNamespaceBackendWithReferenceGrant(t *testing.T) {
	client := fakeGatewayClient(t,
		[]unstructured.Unstructured{
			testGatewayClass("istio", "True", "Accepted"),
			testGateway("infra", "public", "istio", true, "True", "True", testGatewayListener("http", nil)),
			testGatewayHTTPRoute("web", "api-route", "infra", "public", []map[string]interface{}{
				testBackendRef("api", "app", int64(80)),
			}, "True", "True"),
			testReferenceGrant("app", "web", "HTTPRoute", "", "Service", "api"),
		},
		[]kruntime.Object{
			testGatewayService("app", "api", 80),
			testGatewayEndpointSlice("app", "api", true, "10.0.0.10"),
		},
	)
	report := model.NewReport("check gateway", model.Target{})

	runGatewayStaticScan(context.Background(), client, report, GatewayOptions{})

	assertGatewayDiagnosisNotContains(t, report, "does not grant that reference")
	if report.CountByStatus(model.StatusFail) != 0 {
		t.Fatalf("expected no failures, got %#v", report.Results)
	}
}

func TestGatewayScanDiagnosesMissingTLSSecret(t *testing.T) {
	client := fakeGatewayClient(t,
		[]unstructured.Unstructured{
			testGatewayClass("istio", "True", "Accepted"),
			testGateway("infra", "public", "istio", true, "True", "True", testGatewayListener("https", []map[string]interface{}{
				{"name": "missing-cert"},
			})),
		},
		nil,
	)
	report := model.NewReport("check gateway", model.Target{})

	runGatewayStaticScan(context.Background(), client, report, GatewayOptions{})

	assertResultContains(t, report, model.StatusFail, "references TLS Secret infra/missing-cert")
	assertGatewayDiagnosisContains(t, report, "missing or unreadable TLS Secret infra/missing-cert")
	assertGatewayDiagnosisNotContains(t, report, "is not Programmed")
	assertGatewayDiagnosisNotContains(t, report, "is not ResolvedRefs")
}

func TestGatewayTrafficIntentDiagnosesMatchedHTTPSListenerMissingTLSSecret(t *testing.T) {
	listener := testGatewayListener("https", []map[string]interface{}{
		{"name": "partner-cert"},
	})
	listener["hostname"] = "partner.knm.local"
	client := fakeGatewayClient(t,
		[]unstructured.Unstructured{
			testGatewayClass("istio", "True", "Accepted"),
			testGateway("edge", "partner", "istio", true, "True", "True", listener),
		},
		nil,
	)
	report := model.NewReport("check gateway", model.Target{})

	runGatewayIntentScan(context.Background(), client, report, GatewayOptions{}, gatewayTrafficIntent{
		Scheme: "https",
		Host:   "partner.knm.local",
		Port:   443,
		Path:   "/",
	})

	t.Logf("diagnosis output:\n%s", gatewayDiagnosisLog(report))
	assertResultContains(t, report, model.StatusFail, "HTTPS request matched Gateway listener edge/partner/https, but TLS Secret edge/partner-cert is missing or unreadable.")
	assertGatewayDiagnosisContains(t, report, "HTTPS request matched Gateway listener edge/partner/https, but TLS Secret edge/partner-cert is missing or unreadable.")
	assertGatewayDiagnosisNotContains(t, report, "listener is not Programmed")
	assertGatewayDiagnosisNotContains(t, report, "references are not resolved")
}

func TestGatewayTrafficIntentReportsReadableHTTPSListenerSecret(t *testing.T) {
	listener := testGatewayListener("https", []map[string]interface{}{
		{"name": "partner-cert"},
	})
	listener["hostname"] = "partner.knm.local"
	client := fakeGatewayClient(t,
		[]unstructured.Unstructured{
			testGatewayClass("istio", "True", "Accepted"),
			testGateway("edge", "partner", "istio", true, "True", "True", listener),
		},
		[]kruntime.Object{
			&corev1.Secret{ObjectMeta: metav1.ObjectMeta{Namespace: "edge", Name: "partner-cert"}},
		},
	)
	report := model.NewReport("check gateway", model.Target{})

	runGatewayIntentScan(context.Background(), client, report, GatewayOptions{}, gatewayTrafficIntent{
		Scheme: "https",
		Host:   "partner.knm.local",
		Port:   443,
		Path:   "/",
	})

	assertResultContains(t, report, model.StatusPass, "Matched HTTPS listener edge/partner/https references readable TLS Secret edge/partner-cert.")
	assertGatewayDiagnosisNotContains(t, report, "TLS Secret edge/partner-cert is missing")
}

func TestGatewayScanKeepsRouteStatusDiagnosisWhenNoConcreteBackendCauseExists(t *testing.T) {
	client := fakeGatewayClient(t,
		[]unstructured.Unstructured{
			testGatewayClass("istio", "True", "Accepted"),
			testGateway("infra", "public", "istio", true, "True", "True", testGatewayListener("http", nil)),
			testGatewayHTTPRoute("app", "catalog", "infra", "public", []map[string]interface{}{
				testBackendRef("catalog-api", "", int64(80)),
			}, "True", "False"),
		},
		[]kruntime.Object{
			testGatewayService("app", "catalog-api", 80),
			testGatewayEndpointSlice("app", "catalog-api", true, "10.0.0.10"),
		},
	)
	report := model.NewReport("check gateway", model.Target{})

	runGatewayStaticScan(context.Background(), client, report, GatewayOptions{})

	assertGatewayDiagnosisContains(t, report, "HTTPRoute app/catalog has unresolved references")
}

func TestGatewayScanSuppressesRouteStatusWhenUnsupportedBackendKindIsConcrete(t *testing.T) {
	client := fakeGatewayClient(t,
		[]unstructured.Unstructured{
			testGatewayClass("istio", "True", "Accepted"),
			testGateway("edge", "secure", "istio", true, "True", "True", testGatewayListener("tls", nil)),
			testGatewayRouteKind("TLSRoute", "app", "bucket", "edge", "secure", []map[string]interface{}{
				{"group": "storage.example.io", "kind": "Bucket", "name": "profile-archive"},
			}, "True", "False"),
		},
		nil,
	)
	report := model.NewReport("check gateway", model.Target{})

	runGatewayStaticScan(context.Background(), client, report, GatewayOptions{})

	t.Logf("diagnosis output:\n%s", gatewayDiagnosisLog(report))
	assertGatewayDiagnosisContains(t, report, "TLSRoute app/bucket rule 1 routes to backend kind storage.example.io/Bucket app/profile-archive")
	assertGatewayDiagnosisNotContains(t, report, "TLSRoute app/bucket has unresolved references")
}

func TestGatewayScanKeepsListenerStatusDiagnosisWhenNoConcreteTLSCauseExists(t *testing.T) {
	client := fakeGatewayClient(t,
		[]unstructured.Unstructured{
			testGatewayClass("istio", "True", "Accepted"),
			testGatewayWithListenerStatus("infra", "public", "istio", true, "True", "True", testGatewayListener("https", []map[string]interface{}{
				{"name": "public-cert"},
			}), "False", "False"),
		},
		[]kruntime.Object{
			&corev1.Secret{ObjectMeta: metav1.ObjectMeta{Namespace: "infra", Name: "public-cert"}},
		},
	)
	report := model.NewReport("check gateway", model.Target{})

	runGatewayStaticScan(context.Background(), client, report, GatewayOptions{})

	assertGatewayDiagnosisContains(t, report, "Gateway listener infra/public/https is not Programmed")
	assertGatewayDiagnosisContains(t, report, "Gateway listener infra/public/https is not ResolvedRefs")
	assertGatewayDiagnosisNotContains(t, report, "missing or unreadable TLS Secret")
}

func TestGatewayScanDiagnosesGRPCRouteBackendProblems(t *testing.T) {
	client := fakeGatewayClient(t,
		[]unstructured.Unstructured{
			testGatewayClass("istio", "True", "Accepted"),
			testGateway("edge", "grpc", "istio", true, "True", "True", testGatewayListener("grpc", nil)),
			testGatewayRouteKind("GRPCRoute", "app", "payments", "edge", "grpc", []map[string]interface{}{
				testBackendRef("payments-api", "", int64(50051)),
				testBackendRef("orders-api", "", int64(50051)),
			}, "True", "True"),
		},
		[]kruntime.Object{
			testGatewayService("app", "orders-api", 80),
		},
	)
	report := model.NewReport("check gateway", model.Target{})

	runGatewayStaticScan(context.Background(), client, report, GatewayOptions{})

	t.Logf("diagnosis output:\n%s", gatewayDiagnosisLog(report))
	assertGatewayDiagnosisContains(t, report, "GRPCRoute app/payments rule 1 routes to Service app/payments-api, but that Service is missing or unreadable")
	assertGatewayDiagnosisContains(t, report, "GRPCRoute app/payments rule 1 routes to Service app/orders-api port 50051, but the Service exposes 80->80/ name=http")
}

func TestGatewayScanDiagnosesTLSRouteBackendProblems(t *testing.T) {
	client := fakeGatewayClient(t,
		[]unstructured.Unstructured{
			testGatewayClass("istio", "True", "Accepted"),
			testGateway("edge", "tls", "istio", true, "True", "True", testGatewayListener("tls", nil)),
			testGatewayRouteKind("TLSRoute", "app", "payments", "edge", "tls", []map[string]interface{}{
				testBackendRef("payments-api", "", int64(443)),
			}, "True", "True"),
		},
		[]kruntime.Object{
			testGatewayService("app", "payments-api", 443),
		},
	)
	report := model.NewReport("check gateway", model.Target{})

	runGatewayStaticScan(context.Background(), client, report, GatewayOptions{})

	t.Logf("diagnosis output:\n%s", gatewayDiagnosisLog(report))
	assertGatewayDiagnosisContains(t, report, "TLSRoute app/payments rule 1 routes to Service app/payments-api port 443, but that Service has no ready endpoints")
}

func TestGatewayScanDiagnosesTCPRouteBackendProblems(t *testing.T) {
	client := fakeGatewayClient(t,
		[]unstructured.Unstructured{
			testGatewayClass("istio", "True", "Accepted"),
			testGateway("edge", "tcp", "istio", true, "True", "True", testGatewayListener("tcp", nil)),
			testGatewayRouteKind("TCPRoute", "app", "database", "edge", "tcp", []map[string]interface{}{
				testBackendRef("postgres-api", "", int64(5432)),
				testBackendRef("redis-api", "", int64(6379)),
			}, "True", "True"),
		},
		[]kruntime.Object{
			testGatewayService("app", "postgres-api", 5432),
			testGatewayEndpointSlice("app", "postgres-api", false, "10.0.0.30"),
		},
	)
	report := model.NewReport("check gateway", model.Target{})

	runGatewayStaticScan(context.Background(), client, report, GatewayOptions{})

	t.Logf("diagnosis output:\n%s", gatewayDiagnosisLog(report))
	assertGatewayDiagnosisContains(t, report, "TCPRoute app/database rule 1 routes to Service app/postgres-api port 5432, but that Service has no ready endpoints")
	assertGatewayDiagnosisContains(t, report, "TCPRoute app/database rule 1 routes to Service app/redis-api, but that Service is missing or unreadable")
}

func TestGatewayScanDiagnosesUDPRouteBackendProblems(t *testing.T) {
	client := fakeGatewayClient(t,
		[]unstructured.Unstructured{
			testGatewayClass("istio", "True", "Accepted"),
			testGateway("edge", "udp", "istio", true, "True", "True", testGatewayListener("udp", nil)),
			testGatewayRouteKind("UDPRoute", "app", "dns", "edge", "udp", []map[string]interface{}{
				testBackendRef("dns-api", "", int64(5353)),
			}, "True", "True"),
		},
		[]kruntime.Object{
			testGatewayService("app", "dns-api", 53),
		},
	)
	report := model.NewReport("check gateway", model.Target{})

	runGatewayStaticScan(context.Background(), client, report, GatewayOptions{})

	t.Logf("diagnosis output:\n%s", gatewayDiagnosisLog(report))
	assertGatewayDiagnosisContains(t, report, "UDPRoute app/dns rule 1 routes to Service app/dns-api port 5353, but the Service exposes 53->53/ name=http")
}

func TestGatewayScanSuppressesRouteBackendProblemsWhenRouteRejected(t *testing.T) {
	client := fakeGatewayClient(t,
		[]unstructured.Unstructured{
			testGatewayClass("istio", "True", "Accepted"),
			testGateway("edge", "public", "istio", true, "True", "True", testGatewayListener("http", nil)),
			testGatewayRouteKind("TLSRoute", "app", "payments", "edge", "public", []map[string]interface{}{
				testBackendRef("payments-api", "", int64(443)),
			}, "False", "True"),
		},
		nil,
	)
	report := model.NewReport("check gateway", model.Target{})

	runGatewayStaticScan(context.Background(), client, report, GatewayOptions{})

	t.Logf("diagnosis output:\n%s", gatewayDiagnosisLog(report))
	assertGatewayDiagnosisContains(t, report, "TLSRoute app/payments is not accepted by Gateway edge/public")
	assertGatewayDiagnosisNotContains(t, report, "TLSRoute app/payments rule 1 routes to Service app/payments-api")
}

func TestGatewayScanDiagnosesListenerSetProblems(t *testing.T) {
	listener := testGatewayListener("https", []map[string]interface{}{{"name": "edge-cert"}})
	client := fakeGatewayClient(t,
		[]unstructured.Unstructured{
			testGatewayClass("istio", "True", "Accepted"),
			testListenerSet("edge", "partner", "public", listener, "False", "Invalid"),
		},
		nil,
	)
	report := model.NewReport("check gateway", model.Target{})

	runGatewayStaticScan(context.Background(), client, report, GatewayOptions{})

	t.Logf("diagnosis output:\n%s", gatewayDiagnosisLog(report))
	assertGatewayDiagnosisContains(t, report, "ListenerSet edge/partner references Gateway edge/public, but that Gateway was not found")
	assertGatewayDiagnosisContains(t, report, "ListenerSet edge/partner is not Accepted: Invalid")
	assertGatewayDiagnosisNotContains(t, report, "ListenerSet edge/partner references missing or unreadable TLS Secret edge/edge-cert")
}

func TestGatewayScanDiagnosesBackendTLSPolicyProblems(t *testing.T) {
	client := fakeGatewayClient(t,
		[]unstructured.Unstructured{
			testBackendTLSPolicy("app", "payments-tls", "payments-api", "https", "payments-ca", "True", "False", "InvalidCACertificateRef"),
		},
		[]kruntime.Object{
			testGatewayService("app", "payments-api", 80),
			&corev1.ConfigMap{ObjectMeta: metav1.ObjectMeta{Namespace: "app", Name: "payments-ca"}, Data: map[string]string{}},
		},
	)
	report := model.NewReport("check gateway", model.Target{})

	runGatewayStaticScan(context.Background(), client, report, GatewayOptions{})

	t.Logf("diagnosis output:\n%s", gatewayDiagnosisLog(report))
	assertGatewayDiagnosisContains(t, report, "BackendTLSPolicy app/payments-tls targets Service app/payments-api sectionName \"https\", but that Service port name does not exist")
	assertGatewayDiagnosisContains(t, report, "BackendTLSPolicy app/payments-tls CA ConfigMap app/payments-ca is missing key ca.crt")
	assertGatewayDiagnosisNotContains(t, report, "BackendTLSPolicy app/payments-tls is not ResolvedRefs: InvalidCACertificateRef")
}

func TestGatewayPolicyTargetRefsAcceptsSingularAndPluralTargets(t *testing.T) {
	policy := gatewayUnstructured("BackendTrafficPolicy", "app", "payments", map[string]interface{}{
		"spec": map[string]interface{}{
			"targetRef": map[string]interface{}{
				"group":       "",
				"kind":        "Service",
				"name":        "payments-api",
				"sectionName": "http",
			},
			"targetRefs": []interface{}{
				map[string]interface{}{
					"group": "",
					"kind":  "Service",
					"name":  "orders-api",
				},
			},
		},
	})

	targetRefs := gatewayPolicyTargetRefs(policy)

	if len(targetRefs) != 2 {
		t.Fatalf("expected 2 target refs, got %d", len(targetRefs))
	}
	if got := stringField(targetRefs[0].ref, "name"); got != "payments-api" {
		t.Fatalf("expected singular targetRef first, got %q", got)
	}
	if got := gatewayPolicyTargetRefText(targetRefs[1]); got != "targetRef 1" {
		t.Fatalf("expected plural target ref label, got %q", got)
	}
}

func TestGatewayScanDiagnosesEnvoyPolicyTargetProblems(t *testing.T) {
	client := fakeGatewayClient(t,
		[]unstructured.Unstructured{
			testGateway("edge", "public", "istio", true, "True", "True", testGatewayListener("http", nil)),
			testEnvoyPolicy("BackendTrafficPolicy", "edge", "edge-traffic", []interface{}{
				map[string]interface{}{"group": "gateway.networking.k8s.io", "kind": "Gateway", "name": "public", "sectionName": "missing"},
			}, "True", "False", "Invalid"),
			testEnvoyPolicy("ClientTrafficPolicy", "app", "client", []interface{}{
				map[string]interface{}{"group": "gateway.networking.k8s.io", "kind": "HTTPRoute", "name": "orders"},
			}, "False", "True", "InvalidTarget"),
			testEnvoyPolicy("SecurityPolicy", "app", "security", []interface{}{
				map[string]interface{}{"group": "", "kind": "Secret", "name": "creds"},
			}, "True", "True", "Accepted"),
		},
		nil,
	)
	report := model.NewReport("check gateway", model.Target{})

	runGatewayStaticScan(context.Background(), client, report, GatewayOptions{})

	t.Logf("diagnosis output:\n%s", gatewayDiagnosisLog(report))
	assertGatewayDiagnosisContains(t, report, "Envoy BackendTrafficPolicy edge/edge-traffic targets Gateway edge/public sectionName \"missing\", but that listener does not exist")
	assertGatewayDiagnosisContains(t, report, "Envoy ClientTrafficPolicy app/client targets HTTPRoute app/orders, but that route was not found")
	assertGatewayDiagnosisContains(t, report, "Envoy ClientTrafficPolicy app/client is not Accepted: InvalidTarget")
	assertGatewayDiagnosisContains(t, report, "Envoy SecurityPolicy app/security targets kind Secret app/creds; KNM does not evaluate that target type")
}

func TestGatewayScanDiagnosesEnvoyBackendTrafficPolicyServiceTargetsUnsupported(t *testing.T) {
	client := fakeGatewayClient(t,
		[]unstructured.Unstructured{
			testEnvoyPolicy("BackendTrafficPolicy", "app", "traffic", []interface{}{
				map[string]interface{}{"group": "", "kind": "Service", "name": "orders-api", "sectionName": "grpc"},
				map[string]interface{}{"group": "", "kind": "Service", "name": "payments-api"},
			}, "True", "True", "Accepted"),
		},
		[]kruntime.Object{
			testGatewayService("app", "orders-api", 80),
		},
	)
	report := model.NewReport("check gateway", model.Target{})

	runGatewayStaticScan(context.Background(), client, report, GatewayOptions{})

	t.Logf("diagnosis output:\n%s", gatewayDiagnosisLog(report))
	assertGatewayDiagnosisContains(t, report, "Envoy BackendTrafficPolicy app/traffic targets kind Service app/orders-api; KNM does not evaluate that target type")
	assertGatewayDiagnosisContains(t, report, "Envoy BackendTrafficPolicy app/traffic targets kind Service app/payments-api; KNM does not evaluate that target type")
}

func TestGatewayScanDiagnosesEnvoyBackendTrafficPolicySemantics(t *testing.T) {
	client := fakeGatewayClient(t,
		[]unstructured.Unstructured{
			testGatewayClass("istio", "True", "Accepted"),
			testGateway("edge", "public", "istio", true, "True", "True", testGatewayListener("grpc", nil)),
			testGatewayRouteKind("GRPCRoute", "app", "ledger", "edge", "public", []map[string]interface{}{
				{"name": "ledger-api", "port": int64(50051)},
			}, "True", "True"),
			testEnvoyPolicyWithSpec("BackendTrafficPolicy", "edge", "traffic", []interface{}{
				map[string]interface{}{"group": "gateway.networking.k8s.io", "kind": "Gateway", "name": "public"},
				map[string]interface{}{"group": "gateway.networking.k8s.io", "kind": "GRPCRoute", "namespace": "app", "name": "ledger"},
			}, map[string]interface{}{
				"mergeType":     "StrategicMerge",
				"requestBuffer": map[string]interface{}{"limit": "1Mi"},
			}, "True", "True", "Accepted"),
		},
		[]kruntime.Object{
			testGatewayService("app", "ledger-api", 50051),
			testGatewayEndpointSlice("app", "ledger-api", true, "10.0.0.10"),
		},
	)
	report := model.NewReport("check gateway", model.Target{})

	runGatewayStaticScan(context.Background(), client, report, GatewayOptions{})

	t.Logf("diagnosis output:\n%s", gatewayDiagnosisLog(report))
	assertGatewayDiagnosisContains(t, report, "Envoy BackendTrafficPolicy edge/traffic targets Gateway edge/public and sets mergeType, but mergeType cannot be used when targeting a Gateway")
	assertResultContains(t, report, model.StatusWarn, "Envoy BackendTrafficPolicy edge/traffic enables requestBuffer for GRPCRoute app/ledger. This is usually only safe for unary gRPC; streaming gRPC can hang or fail")
	assertGatewayDiagnosisNotContains(t, report, "requestBuffer for GRPCRoute app/ledger")
}

func TestGatewayScanDiagnosesDenseEnvoyBackendTrafficPolicySemantics(t *testing.T) {
	client := fakeGatewayClient(t,
		[]unstructured.Unstructured{
			testGatewayClass("eg", "True", "Accepted"),
			testGateway("edge", "public", "eg", true, "True", "True", testGatewayListener("http", nil)),
			testGatewayHTTPRoute("app", "catalog", "edge", "public", []map[string]interface{}{
				{"name": "catalog-api", "port": int64(80)},
			}, "True", "True"),
			testEnvoyPolicyWithSpec("BackendTrafficPolicy", "app", "catalog-traffic", []interface{}{
				map[string]interface{}{"group": "gateway.networking.k8s.io", "kind": "HTTPRoute", "name": "catalog"},
			}, map[string]interface{}{
				"requestBuffer": map[string]interface{}{"limit": "1Mi"},
				"faultInjection": map[string]interface{}{
					"abort": map[string]interface{}{"httpStatus": int64(503), "percentage": float64(100)},
					"delay": map[string]interface{}{"fixedDelay": "30s", "percentage": float64(25)},
				},
				"responseOverride": []interface{}{
					map[string]interface{}{
						"match": map[string]interface{}{
							"statusCodes": []interface{}{
								map[string]interface{}{"type": "Range", "range": map[string]interface{}{"start": int64(599), "end": int64(500)}},
							},
						},
						"response": map[string]interface{}{"statusCode": int64(502)},
					},
				},
				"circuitBreaker": map[string]interface{}{
					"maxConnections":     int64(0),
					"maxParallelRetries": int64(0),
					"perEndpoint":        map[string]interface{}{"maxConnections": int64(0)},
					"retryBudget":        map[string]interface{}{"percent": map[string]interface{}{"numerator": int64(0)}},
				},
				"rateLimit": map[string]interface{}{
					"local": map[string]interface{}{
						"rules": []interface{}{
							map[string]interface{}{
								"clientSelectors": []interface{}{
									map[string]interface{}{
										"methods": []interface{}{
											map[string]interface{}{"value": "GET"},
										},
									},
								},
								"limit": map[string]interface{}{"requests": int64(0), "unit": "Second"},
							},
						},
					},
				},
				"retry": map[string]interface{}{
					"numRetries": int64(0),
					"retryOn":    map[string]interface{}{"httpStatusCodes": []interface{}{int64(503)}},
					"perRetry": map[string]interface{}{
						"timeout": "0s",
						"backOff": map[string]interface{}{"baseInterval": "5s", "maxInterval": "1s"},
					},
				},
				"healthCheck": map[string]interface{}{
					"active": map[string]interface{}{
						"type": "HTTP",
						"http": map[string]interface{}{"path": "/healthz", "expectedStatuses": []interface{}{int64(500)}},
						"grpc": map[string]interface{}{"service": "catalog.Catalog"},
						"tcp": map[string]interface{}{
							"send": map[string]interface{}{"type": "Text", "text": "ping"},
						},
					},
				},
				"admissionControl": map[string]interface{}{
					"maxRejectionPercent": int64(100),
					"minSuccessRate":      int64(100),
					"successCriteria": map[string]interface{}{
						"http": map[string]interface{}{"statusCodes": []interface{}{int64(500)}},
						"grpc": map[string]interface{}{"statusCodes": []interface{}{"Unavailable"}},
					},
				},
				"bandwidthLimit": map[string]interface{}{
					"request":  map[string]interface{}{"limit": map[string]interface{}{"value": "0", "unit": "Second"}},
					"response": map[string]interface{}{"limit": map[string]interface{}{"value": "1", "unit": "Second"}},
				},
				"connection": map[string]interface{}{
					"bufferLimit":       "0",
					"socketBufferLimit": "0",
					"preconnect": map[string]interface{}{
						"predictivePercent":  int64(50),
						"perEndpointPercent": int64(0),
					},
				},
				"loadBalancer": map[string]interface{}{
					"type":           "ConsistentHash",
					"consistentHash": map[string]interface{}{"tableSize": int64(0)},
					"zoneAware": map[string]interface{}{
						"weightedZones": []interface{}{
							map[string]interface{}{"zone": "us-a", "weight": int64(0)},
						},
					},
				},
				"timeout": map[string]interface{}{
					"http": map[string]interface{}{
						"requestTimeout": "1s",
					},
					"tcp": map[string]interface{}{"connectTimeout": "0s"},
				},
				"http2": map[string]interface{}{
					"maxConcurrentStreams":        int64(0),
					"initialConnectionWindowSize": "0",
					"connectionKeepalive":         map[string]interface{}{"interval": "0s"},
				},
				"tcpKeepalive": map[string]interface{}{"probes": int64(0), "interval": "0s"},
				"routingType":  "Magic",
				"compressor": []interface{}{
					map[string]interface{}{"type": "Gzip", "minContentLength": int64(1), "gzip": map[string]interface{}{}, "brotli": map[string]interface{}{}},
					map[string]interface{}{"type": "Gzip"},
				},
				"compression": []interface{}{
					map[string]interface{}{"type": "Gzip"},
				},
			}, "True", "True", "Accepted"),
		},
		[]kruntime.Object{
			testGatewayService("app", "catalog-api", 80),
			testGatewayEndpointSlice("app", "catalog-api", true, "10.0.0.10"),
		},
	)
	report := model.NewReport("check gateway", model.Target{})

	runGatewayStaticScan(context.Background(), client, report, GatewayOptions{})

	t.Logf("diagnosis output:\n%s", gatewayDiagnosisLog(report))
	assertGatewayDiagnosisContains(t, report, "Envoy BackendTrafficPolicy app/catalog-traffic aborts 100% of matching traffic with HTTP status 503")
	assertGatewayDiagnosisContains(t, report, "Envoy BackendTrafficPolicy app/catalog-traffic responseOverride 1 can replace matching responses with HTTP 502")
	assertGatewayDiagnosisContains(t, report, "Envoy BackendTrafficPolicy app/catalog-traffic responseOverride 1 has an invalid status code range")
	assertGatewayDiagnosisContains(t, report, "Envoy BackendTrafficPolicy app/catalog-traffic circuitBreaker.maxConnections is 0")
	assertGatewayDiagnosisContains(t, report, "Envoy BackendTrafficPolicy app/catalog-traffic circuitBreaker.maxParallelRetries is 0")
	assertGatewayDiagnosisContains(t, report, "Envoy BackendTrafficPolicy app/catalog-traffic circuitBreaker.perEndpoint.maxConnections is 0")
	assertGatewayDiagnosisContains(t, report, "Envoy BackendTrafficPolicy app/catalog-traffic circuitBreaker.retryBudget.percent.numerator is 0")
	assertGatewayDiagnosisContains(t, report, "Envoy BackendTrafficPolicy app/catalog-traffic configures rateLimit, but rateLimit.type is missing")
	assertGatewayDiagnosisContains(t, report, "Envoy BackendTrafficPolicy app/catalog-traffic local rateLimit rule 1 allows 0 requests per Second")
	assertGatewayDiagnosisContains(t, report, "Envoy BackendTrafficPolicy app/catalog-traffic local rateLimit rule 1 cannot be translated by Envoy Gateway without at least one header or sourceCIDR selector")
	assertGatewayDiagnosisContains(t, report, "Envoy BackendTrafficPolicy app/catalog-traffic active HTTP healthCheck only treats 5xx status codes as healthy")
	assertGatewayDiagnosisContains(t, report, "Envoy BackendTrafficPolicy app/catalog-traffic admissionControl can reject up to 100% of matching traffic")
	assertGatewayDiagnosisContains(t, report, "Envoy BackendTrafficPolicy app/catalog-traffic bandwidthLimit.request.limit.value is 0")
	assertGatewayDiagnosisContains(t, report, "Envoy BackendTrafficPolicy app/catalog-traffic connection.preconnect.predictivePercent only works with Random or RoundRobin load balancers")
	assertGatewayDiagnosisContains(t, report, "Envoy BackendTrafficPolicy app/catalog-traffic uses ConsistentHash load balancing without a hash source")
	assertGatewayDiagnosisContains(t, report, "Envoy BackendTrafficPolicy app/catalog-traffic zoneAware weighted zone 1 has weight 0")
	assertGatewayDiagnosisContains(t, report, "Envoy BackendTrafficPolicy app/catalog-traffic http2.maxConcurrentStreams is 0")
	assertGatewayDiagnosisContains(t, report, "Envoy BackendTrafficPolicy app/catalog-traffic http2.initialConnectionWindowSize is 0")
	assertGatewayDiagnosisContains(t, report, "Envoy BackendTrafficPolicy app/catalog-traffic sets both compression and compressor")
	assertGatewayDiagnosisContains(t, report, "Envoy BackendTrafficPolicy app/catalog-traffic uses unsupported routingType \"Magic\"")
	assertResultContains(t, report, model.StatusWarn, "Envoy BackendTrafficPolicy app/catalog-traffic enables requestBuffer for HTTPRoute app/catalog; streaming requests and protocol upgrades can hang or fail")
	assertResultContains(t, report, model.StatusWarn, "Envoy BackendTrafficPolicy app/catalog-traffic enables requestBuffer without explicit httpUpgrade settings")
	assertResultContains(t, report, model.StatusWarn, "Envoy BackendTrafficPolicy app/catalog-traffic delays 25% of matching traffic by 30s")
	assertResultContains(t, report, model.StatusWarn, "Envoy BackendTrafficPolicy app/catalog-traffic defines retryOn conditions but numRetries is 0")
	assertResultContains(t, report, model.StatusWarn, "Envoy BackendTrafficPolicy app/catalog-traffic sets retry.perRetry.timeout to 0s")
	assertResultContains(t, report, model.StatusWarn, "Envoy BackendTrafficPolicy app/catalog-traffic retry backOff baseInterval 5s is greater than maxInterval 1s")
	assertResultContains(t, report, model.StatusWarn, "Envoy BackendTrafficPolicy app/catalog-traffic admissionControl requires a 100% success rate")
	assertResultContains(t, report, model.StatusWarn, "Envoy BackendTrafficPolicy app/catalog-traffic admissionControl treats HTTP 500 as successful")
	assertResultContains(t, report, model.StatusWarn, "Envoy BackendTrafficPolicy app/catalog-traffic admissionControl treats gRPC status Unavailable as successful")
	assertResultContains(t, report, model.StatusWarn, "Envoy BackendTrafficPolicy app/catalog-traffic connection.bufferLimit is 0")
	assertResultContains(t, report, model.StatusWarn, "Envoy BackendTrafficPolicy app/catalog-traffic timeout.tcp.connectTimeout is 0s")
	assertResultContains(t, report, model.StatusWarn, "Envoy BackendTrafficPolicy app/catalog-traffic configures TCP connectTimeout while targeting HTTPRoute")
	assertResultContains(t, report, model.StatusWarn, "Envoy BackendTrafficPolicy app/catalog-traffic http2.connectionKeepalive.interval is 0s")
	assertResultContains(t, report, model.StatusWarn, "Envoy BackendTrafficPolicy app/catalog-traffic tcpKeepalive.probes is 0")
	assertResultContains(t, report, model.StatusWarn, "Envoy BackendTrafficPolicy app/catalog-traffic compressor 1 minContentLength is below Envoy's 30 byte minimum")
	assertResultContains(t, report, model.StatusWarn, "Envoy BackendTrafficPolicy app/catalog-traffic active healthCheck defines multiple protocol configs")
	assertResultContains(t, report, model.StatusWarn, "Envoy BackendTrafficPolicy app/catalog-traffic uses deprecated compression")
}

func TestGatewayScanDiagnosesEnvoyBackendTrafficPolicyRateLimitTypeMismatch(t *testing.T) {
	client := fakeGatewayClient(t,
		[]unstructured.Unstructured{
			testEnvoyPolicyWithSpec("BackendTrafficPolicy", "app", "traffic", []interface{}{
				map[string]interface{}{"group": "gateway.networking.k8s.io", "kind": "HTTPRoute", "name": "catalog"},
			}, map[string]interface{}{
				"rateLimit": map[string]interface{}{
					"type": "Global",
					"local": map[string]interface{}{
						"rules": []interface{}{
							map[string]interface{}{
								"limit": map[string]interface{}{"requests": int64(1), "unit": "Hour"},
							},
						},
					},
				},
			}, "True", "True", "Accepted"),
		},
		nil,
	)
	report := model.NewReport("check gateway", model.Target{})

	runGatewayStaticScan(context.Background(), client, report, GatewayOptions{})

	t.Logf("diagnosis output:\n%s", gatewayDiagnosisLog(report))
	assertGatewayDiagnosisContains(t, report, "Envoy BackendTrafficPolicy app/traffic sets rateLimit.type=Global, but no global rate limit rules are configured")
	assertGatewayDiagnosisContains(t, report, "Envoy BackendTrafficPolicy app/traffic sets rateLimit.type=Global, but the configured rules are under local")
}

func TestGatewayScanWarnsEnvoyBackendTrafficPolicyTargetSelectors(t *testing.T) {
	client := fakeGatewayClient(t,
		[]unstructured.Unstructured{
			testGatewayClass("eg", "True", "Accepted"),
			testGateway("edge", "public", "eg", true, "True", "True", testGatewayListener("http", nil)),
			withLabels(testGatewayHTTPRoute("app", "catalog", "edge", "public", []map[string]interface{}{
				{"name": "catalog-api", "port": int64(80)},
			}, "True", "True"), map[string]string{"app": "catalog"}),
			testEnvoyObject("BackendTrafficPolicy", "app", "selected-traffic", map[string]interface{}{
				"spec": map[string]interface{}{
					"targetSelectors": []interface{}{
						map[string]interface{}{
							"group": "gateway.networking.k8s.io",
							"kind":  "HTTPRoute",
							"matchLabels": map[string]interface{}{
								"app": "catalog",
							},
						},
					},
					"faultInjection": map[string]interface{}{
						"abort": map[string]interface{}{"httpStatus": int64(500), "percentage": float64(100)},
					},
					"requestBuffer": map[string]interface{}{"limit": "1Mi"},
				},
			}),
		},
		[]kruntime.Object{
			testGatewayService("app", "catalog-api", 80),
			testGatewayEndpointSlice("app", "catalog-api", true, "10.0.0.10"),
		},
	)
	report := model.NewReport("check gateway", model.Target{})

	runGatewayStaticScan(context.Background(), client, report, GatewayOptions{})

	t.Logf("diagnosis output:\n%s", gatewayDiagnosisLog(report))
	assertResultContains(t, report, model.StatusWarn, "Envoy BackendTrafficPolicy app/selected-traffic enables requestBuffer for HTTPRoute app/catalog")
	assertGatewayDiagnosisContains(t, report, "Envoy BackendTrafficPolicy app/selected-traffic aborts 100% of matching traffic with HTTP status 500")
}

func TestGatewayScanDiagnosesEnvoyClientTrafficPolicyTLSRefs(t *testing.T) {
	client := fakeGatewayClient(t,
		[]unstructured.Unstructured{
			testGatewayClass("istio", "True", "Accepted"),
			testGateway("edge", "public", "istio", true, "True", "True", testGatewayListener("https", nil)),
			testEnvoyPolicyWithSpec("ClientTrafficPolicy", "edge", "client", []interface{}{
				map[string]interface{}{"group": "gateway.networking.k8s.io", "kind": "Gateway", "name": "public"},
			}, map[string]interface{}{
				"enableProxyProtocol": true,
				"proxyProtocol":       map[string]interface{}{},
				"tls": map[string]interface{}{
					"clientValidation": map[string]interface{}{
						"caCertificateRefs": []interface{}{
							map[string]interface{}{"group": "", "kind": "ConfigMap", "name": "client-ca"},
							map[string]interface{}{"group": "", "kind": "Secret", "name": "client-secret-ca"},
						},
						"crl": map[string]interface{}{
							"refs": []interface{}{
								map[string]interface{}{"group": "", "kind": "ConfigMap", "name": "client-crl"},
							},
						},
					},
				},
			}, "True", "True", "Accepted"),
		},
		[]kruntime.Object{
			&corev1.ConfigMap{ObjectMeta: metav1.ObjectMeta{Namespace: "edge", Name: "client-ca"}, Data: map[string]string{"note": "missing ca"}},
			&corev1.ConfigMap{ObjectMeta: metav1.ObjectMeta{Namespace: "edge", Name: "client-crl"}, Data: map[string]string{"note": "missing crl"}},
			&corev1.Secret{ObjectMeta: metav1.ObjectMeta{Namespace: "edge", Name: "client-secret-ca"}, Data: map[string][]byte{"note": []byte("missing ca")}},
		},
	)
	report := model.NewReport("check gateway", model.Target{})

	runGatewayStaticScan(context.Background(), client, report, GatewayOptions{})

	t.Logf("diagnosis output:\n%s", gatewayDiagnosisLog(report))
	assertResultContains(t, report, model.StatusWarn, "Envoy ClientTrafficPolicy edge/client sets both enableProxyProtocol and proxyProtocol; proxyProtocol takes precedence")
	assertGatewayDiagnosisNotContains(t, report, "enableProxyProtocol and proxyProtocol")
	assertGatewayDiagnosisContains(t, report, "Envoy ClientTrafficPolicy edge/client clientValidation caCertificateRef 1 ConfigMap edge/client-ca is missing key ca.crt")
	assertGatewayDiagnosisContains(t, report, "Envoy ClientTrafficPolicy edge/client clientValidation caCertificateRef 2 Secret edge/client-secret-ca is missing key ca.crt")
	assertGatewayDiagnosisContains(t, report, "Envoy ClientTrafficPolicy edge/client clientValidation crl 1 ConfigMap edge/client-crl is missing key ca.crl")
}

func TestGatewayScanDiagnosesEnvoyClientTrafficPolicyRiskySemantics(t *testing.T) {
	client := fakeGatewayClient(t,
		[]unstructured.Unstructured{
			testGatewayClass("eg", "True", "Accepted"),
			testGateway("edge", "public", "eg", true, "True", "True", testGatewayListener("https", nil)),
			testEnvoyPolicyWithSpec("ClientTrafficPolicy", "edge", "client", []interface{}{
				map[string]interface{}{"group": "gateway.networking.k8s.io", "kind": "Gateway", "name": "public"},
			}, map[string]interface{}{
				"clientIPDetection": map[string]interface{}{
					"customHeader":  map[string]interface{}{"name": "x-real-ip"},
					"xForwardedFor": map[string]interface{}{"numTrustedHops": int64(1)},
				},
				"connection": map[string]interface{}{
					"connectionLimit": map[string]interface{}{"value": int64(0)},
					"bufferLimit":     "0",
				},
				"headers": map[string]interface{}{
					"withUnderscoresAction": "RejectRequest",
				},
				"path": map[string]interface{}{
					"escapedSlashesAction": "RejectRequest",
				},
				"http2": map[string]interface{}{
					"maxConcurrentStreams": int64(0),
				},
				"timeout": map[string]interface{}{
					"http": map[string]interface{}{"requestReceivedTimeout": "0s"},
				},
				"tls": map[string]interface{}{
					"minVersion": "1.3",
					"maxVersion": "1.2",
					"clientValidation": map[string]interface{}{
						"mode": "RequireAndVerify",
					},
				},
			}, "True", "True", "Accepted"),
		},
		nil,
	)
	report := model.NewReport("check gateway", model.Target{})

	runGatewayStaticScan(context.Background(), client, report, GatewayOptions{})

	t.Logf("diagnosis output:\n%s", gatewayDiagnosisLog(report))
	assertResultContains(t, report, model.StatusWarn, "Envoy ClientTrafficPolicy edge/client configures both customHeader and xForwardedFor client IP detection")
	assertGatewayDiagnosisContains(t, report, "Envoy ClientTrafficPolicy edge/client connection.connectionLimit.value is 0; the listener can reject new downstream connections")
	assertGatewayDiagnosisContains(t, report, "Envoy ClientTrafficPolicy edge/client rejects requests containing headers with underscores")
	assertGatewayDiagnosisContains(t, report, "Envoy ClientTrafficPolicy edge/client rejects requests containing escaped slashes in the path")
	assertGatewayDiagnosisContains(t, report, "Envoy ClientTrafficPolicy edge/client http2.maxConcurrentStreams is 0; downstream HTTP/2 streams can be blocked")
	assertGatewayDiagnosisContains(t, report, "Envoy ClientTrafficPolicy edge/client requires client certificate verification but has no trust source")
	assertGatewayDiagnosisContains(t, report, "Envoy ClientTrafficPolicy edge/client has impossible TLS version bounds")
}

func TestGatewayScanDiagnosesEnvoyExtensionPolicyExtProcBackendProblems(t *testing.T) {
	client := fakeGatewayClient(t,
		[]unstructured.Unstructured{
			testGatewayClass("istio", "True", "Accepted"),
			testGateway("edge", "public", "istio", true, "True", "True", testGatewayListener("http", nil)),
			testGatewayHTTPRoute("app", "orders", "edge", "public", []map[string]interface{}{
				{"name": "orders-api", "port": int64(80)},
			}, "True", "True"),
			testEnvoyPolicyWithSpec("EnvoyExtensionPolicy", "app", "extensions", []interface{}{
				map[string]interface{}{"group": "gateway.networking.k8s.io", "kind": "HTTPRoute", "name": "orders"},
			}, map[string]interface{}{
				"extProc": []interface{}{
					map[string]interface{}{
						"backendRefs": []interface{}{
							map[string]interface{}{"name": "processor", "port": int64(9443)},
							map[string]interface{}{"name": "missing-processor", "port": int64(9000)},
						},
						"processingMode": map[string]interface{}{
							"request": map[string]interface{}{"body": "Buffered"},
						},
					},
				},
				"lua": []interface{}{
					map[string]interface{}{
						"type":     "ValueRef",
						"valueRef": map[string]interface{}{"group": "", "kind": "ConfigMap", "name": "lua-code"},
					},
				},
				"wasm": []interface{}{
					map[string]interface{}{
						"code": map[string]interface{}{
							"type": "Image",
							"image": map[string]interface{}{
								"url":           "oci://example.com/filter:v1",
								"pullSecretRef": map[string]interface{}{"group": "", "kind": "Secret", "name": "pull-secret"},
								"tls": map[string]interface{}{
									"caCertificateRef": map[string]interface{}{"group": "", "kind": "ConfigMap", "name": "wasm-ca"},
								},
							},
						},
					},
				},
				"dynamicModule": []interface{}{
					map[string]interface{}{"name": "mod", "filterName": "filter"},
					map[string]interface{}{"name": "mod", "filterName": "filter"},
				},
			}, "True", "True", "Accepted"),
		},
		[]kruntime.Object{
			testGatewayService("app", "orders-api", 80),
			testGatewayEndpointSlice("app", "orders-api", true, "10.0.0.10"),
			testGatewayService("app", "processor", 9000),
			&corev1.ConfigMap{ObjectMeta: metav1.ObjectMeta{Namespace: "app", Name: "lua-code"}, Data: map[string]string{}},
			&corev1.ConfigMap{ObjectMeta: metav1.ObjectMeta{Namespace: "app", Name: "wasm-ca"}, Data: map[string]string{"note": "missing ca"}},
			&corev1.Secret{ObjectMeta: metav1.ObjectMeta{Namespace: "app", Name: "pull-secret"}, Data: map[string][]byte{}},
		},
	)
	report := model.NewReport("check gateway", model.Target{})

	runGatewayStaticScan(context.Background(), client, report, GatewayOptions{})

	t.Logf("diagnosis output:\n%s", gatewayDiagnosisLog(report))
	assertResultContains(t, report, model.StatusWarn, "Envoy EnvoyExtensionPolicy app/extensions extProc 1 buffers request or response bodies")
	assertResultContains(t, report, model.StatusWarn, "Envoy EnvoyExtensionPolicy app/extensions defines dynamicModule name \"mod\" more than once")
	assertGatewayDiagnosisContains(t, report, "Envoy EnvoyExtensionPolicy app/extensions external processor backend Service app/processor does not expose port 9443")
	assertGatewayDiagnosisContains(t, report, "Envoy EnvoyExtensionPolicy app/extensions external processor backend Service app/missing-processor is missing or unreadable")
	assertGatewayDiagnosisContains(t, report, "Envoy EnvoyExtensionPolicy app/extensions lua 1 valueRef ConfigMap app/lua-code is missing key lua")
	assertGatewayDiagnosisContains(t, report, "Envoy EnvoyExtensionPolicy app/extensions wasm 1 image tls caCertificateRef ConfigMap app/wasm-ca is missing key ca.crt")
	assertGatewayDiagnosisContains(t, report, "Envoy EnvoyExtensionPolicy app/extensions wasm 1 image pullSecretRef Secret app/pull-secret is missing key .dockerconfigjson")
}

func TestGatewayScanDiagnosesEnvoyBackendProblems(t *testing.T) {
	client := fakeGatewayClient(t,
		[]unstructured.Unstructured{
			testEnvoyObject("Backend", "app", "inventory", map[string]interface{}{
				"spec": map[string]interface{}{
					"type": "Endpoints",
					"endpoints": []interface{}{
						map[string]interface{}{"fqdn": map[string]interface{}{"port": int64(443)}},
						map[string]interface{}{"ip": map[string]interface{}{"address": "not-an-ip", "port": int64(9443)}},
						map[string]interface{}{"unix": map[string]interface{}{"path": strings.Repeat("a", 109)}},
						map[string]interface{}{"fqdn": map[string]interface{}{"hostname": "inventory.internal", "port": int64(443)}, "ip": map[string]interface{}{"address": "10.0.0.10", "port": int64(443)}},
					},
					"tls": map[string]interface{}{
						"caCertificateRefs": []interface{}{
							map[string]interface{}{"group": "", "kind": "ConfigMap", "name": "inventory-ca"},
						},
						"wellKnownCACertificates": "System",
						"clientCertificateRef":    map[string]interface{}{"group": "", "kind": "Secret", "name": "inventory-client"},
					},
				},
			}),
		},
		[]kruntime.Object{
			&corev1.ConfigMap{ObjectMeta: metav1.ObjectMeta{Namespace: "app", Name: "inventory-ca"}, Data: map[string]string{"note": "missing ca"}},
			&corev1.Secret{ObjectMeta: metav1.ObjectMeta{Namespace: "app", Name: "inventory-client"}, Data: map[string][]byte{"note": []byte("missing cert")}},
		},
	)
	report := model.NewReport("check gateway", model.Target{})

	runGatewayStaticScan(context.Background(), client, report, GatewayOptions{})

	t.Logf("diagnosis output:\n%s", gatewayDiagnosisLog(report))
	assertGatewayDiagnosisContains(t, report, "Envoy Backend app/inventory endpoint 1 has an FQDN endpoint with no hostname")
	assertGatewayDiagnosisContains(t, report, "Envoy Backend app/inventory endpoint 2 has an invalid IP address")
	assertGatewayDiagnosisContains(t, report, "Envoy Backend app/inventory endpoint 3 has a Unix socket path longer than 108 characters")
	assertGatewayDiagnosisContains(t, report, "Envoy Backend app/inventory endpoint 4 sets multiple address types")
	assertGatewayDiagnosisContains(t, report, "Envoy Backend app/inventory TLS specifies both caCertificateRefs and wellKnownCACertificates")
	assertGatewayDiagnosisContains(t, report, "Envoy Backend app/inventory tls caCertificateRef 1 ConfigMap app/inventory-ca is missing key ca.crt")
	assertGatewayDiagnosisContains(t, report, "Envoy Backend app/inventory tls clientCertificateRef tls.crt Secret app/inventory-client is missing key tls.crt")
	assertGatewayDiagnosisContains(t, report, "Envoy Backend app/inventory tls clientCertificateRef tls.key Secret app/inventory-client is missing key tls.key")
}

func TestGatewayScanDiagnosesEnvoyHTTPRouteFilterProblems(t *testing.T) {
	client := fakeGatewayClient(t,
		[]unstructured.Unstructured{
			testEnvoyObject("HTTPRouteFilter", "app", "catalog-filter", map[string]interface{}{
				"spec": map[string]interface{}{
					"directResponse": map[string]interface{}{
						"statusCode": int64(700),
						"body": map[string]interface{}{
							"type":     "ValueRef",
							"valueRef": map[string]interface{}{"group": "", "kind": "ConfigMap", "name": "response-body"},
						},
					},
					"credentialInjection": map[string]interface{}{
						"credential": map[string]interface{}{
							"valueRef": map[string]interface{}{"group": "", "kind": "Secret", "name": "catalog-credential"},
						},
					},
					"matches": []interface{}{
						map[string]interface{}{
							"cookies": []interface{}{
								map[string]interface{}{"name": "session", "type": "RegularExpression", "value": "["},
							},
						},
					},
					"urlRewrite": map[string]interface{}{
						"path": map[string]interface{}{
							"type": "ReplaceRegexMatch",
							"replaceRegexMatch": map[string]interface{}{
								"pattern": "[",
							},
						},
					},
				},
			}),
		},
		[]kruntime.Object{
			&corev1.Secret{ObjectMeta: metav1.ObjectMeta{Namespace: "app", Name: "catalog-credential"}, Data: map[string][]byte{"note": []byte("missing credential")}},
			&corev1.ConfigMap{ObjectMeta: metav1.ObjectMeta{Namespace: "app", Name: "response-body"}, Data: map[string]string{}},
		},
	)
	report := model.NewReport("check gateway", model.Target{})

	runGatewayStaticScan(context.Background(), client, report, GatewayOptions{})

	t.Logf("diagnosis output:\n%s", gatewayDiagnosisLog(report))
	assertGatewayDiagnosisContains(t, report, "Envoy HTTPRouteFilter app/catalog-filter directResponse has invalid HTTP status code 700")
	assertGatewayDiagnosisContains(t, report, "Envoy HTTPRouteFilter app/catalog-filter directResponse body valueRef ConfigMap app/response-body has no data")
	assertGatewayDiagnosisContains(t, report, "Envoy HTTPRouteFilter app/catalog-filter credentialInjection valueRef Secret app/catalog-credential is missing key credential")
	assertGatewayDiagnosisContains(t, report, "Envoy HTTPRouteFilter app/catalog-filter URL rewrite has an invalid regex pattern")
	assertGatewayDiagnosisContains(t, report, "Envoy HTTPRouteFilter app/catalog-filter has an invalid cookie regex match")
}

func TestGatewayRouteFilterScopesEnvoyHTTPRouteFilters(t *testing.T) {
	catalogRoute := testGatewayHTTPRouteWithRules("app", "catalog", []map[string]interface{}{
		{"name": "public", "namespace": "edge"},
	}, []map[string]interface{}{
		{
			"backendRefs": []interface{}{testBackendRef("catalog-api", "", int64(80))},
			"filters": []interface{}{
				map[string]interface{}{
					"type": "ExtensionRef",
					"extensionRef": map[string]interface{}{
						"group": "gateway.envoyproxy.io",
						"kind":  "HTTPRouteFilter",
						"name":  "catalog-filter",
					},
				},
			},
		},
	})
	client := fakeGatewayClient(t,
		[]unstructured.Unstructured{
			testGatewayClass("istio", "True", "Accepted"),
			testGateway("edge", "public", "istio", true, "True", "True", testGatewayListener("http", nil)),
			catalogRoute,
			testGatewayHTTPRoute("app", "orders", "edge", "public", []map[string]interface{}{
				{"name": "orders-api", "port": int64(80)},
			}, "True", "True"),
			testEnvoyObject("HTTPRouteFilter", "app", "catalog-filter", map[string]interface{}{
				"spec": map[string]interface{}{"directResponse": map[string]interface{}{"statusCode": int64(700)}},
			}),
			testEnvoyObject("HTTPRouteFilter", "app", "orders-filter", map[string]interface{}{
				"spec": map[string]interface{}{"directResponse": map[string]interface{}{"statusCode": int64(701)}},
			}),
			testEnvoyObject("Backend", "app", "inventory", map[string]interface{}{
				"spec": map[string]interface{}{
					"type": "Endpoints",
					"tls": map[string]interface{}{
						"caCertificateRefs": []interface{}{
							map[string]interface{}{"group": "", "kind": "ConfigMap", "name": "inventory-ca"},
						},
					},
				},
			}),
		},
		[]kruntime.Object{
			testGatewayService("app", "catalog-api", 80),
			testGatewayEndpointSlice("app", "catalog-api", true, "10.0.0.10"),
			testGatewayService("app", "orders-api", 80),
			testGatewayEndpointSlice("app", "orders-api", true, "10.0.0.11"),
		},
	)
	report := model.NewReport("check gateway", model.Target{})

	runGatewayStaticScan(context.Background(), client, report, GatewayOptions{RouteRef: "app/catalog"})

	t.Logf("diagnosis output:\n%s", gatewayDiagnosisLog(report))
	assertGatewayDiagnosisContains(t, report, "Envoy HTTPRouteFilter app/catalog-filter directResponse has invalid HTTP status code 700")
	assertGatewayDiagnosisNotContains(t, report, "orders-filter")
	assertGatewayDiagnosisNotContains(t, report, "inventory")
}

func TestGatewayScanDiagnosesEnvoyPatchPolicyProblems(t *testing.T) {
	client := fakeGatewayClient(t,
		[]unstructured.Unstructured{
			testGatewayClass("istio", "True", "Accepted"),
			testGateway("edge", "public", "istio", true, "True", "True", testGatewayListener("http", nil)),
			testEnvoyObject("EnvoyPatchPolicy", "edge", "gateway-patch", map[string]interface{}{
				"spec": map[string]interface{}{
					"targetRef": map[string]interface{}{"group": "gateway.networking.k8s.io", "kind": "Gateway", "name": "missing"},
					"type":      "JSONPatch",
					"jsonPatches": []interface{}{
						map[string]interface{}{"name": "listener_0", "type": "type.googleapis.com/envoy.config.listener.v3.Listener"},
						map[string]interface{}{
							"name": "listener_1",
							"type": "type.googleapis.com/envoy.config.listener.v3.Listener",
							"operation": map[string]interface{}{
								"op": "add",
							},
						},
						map[string]interface{}{
							"name": "listener_2",
							"type": "type.googleapis.com/envoy.config.listener.v3.Listener",
							"operation": map[string]interface{}{
								"op":   "move",
								"path": "/filterChains/0",
							},
						},
					},
				},
			}),
			testEnvoyObject("EnvoyPatchPolicy", "edge", "class-patch", map[string]interface{}{
				"spec": map[string]interface{}{
					"targetRef":   map[string]interface{}{"group": "gateway.networking.k8s.io", "kind": "GatewayClass", "name": "missing-class"},
					"type":        "Bogus",
					"jsonPatches": []interface{}{},
				},
			}),
		},
		nil,
	)
	report := model.NewReport("check gateway", model.Target{})

	runGatewayStaticScan(context.Background(), client, report, GatewayOptions{})

	t.Logf("diagnosis output:\n%s", gatewayDiagnosisLog(report))
	assertGatewayDiagnosisContains(t, report, "Envoy EnvoyPatchPolicy edge/gateway-patch targets Gateway edge/missing, but that Gateway was not found")
	assertGatewayDiagnosisContains(t, report, "Envoy EnvoyPatchPolicy edge/gateway-patch jsonPatch 1 has no JSON patch operation")
	assertGatewayDiagnosisContains(t, report, "Envoy EnvoyPatchPolicy edge/gateway-patch jsonPatch 2 operation has no path or jsonPath")
	assertGatewayDiagnosisContains(t, report, "Envoy EnvoyPatchPolicy edge/gateway-patch jsonPatch 2 operation add has no value")
	assertGatewayDiagnosisContains(t, report, "Envoy EnvoyPatchPolicy edge/gateway-patch jsonPatch 3 operation move has no from path")
	assertGatewayDiagnosisContains(t, report, "Envoy EnvoyPatchPolicy edge/class-patch targets GatewayClass missing-class, but that GatewayClass was not found")
	assertGatewayDiagnosisContains(t, report, "Envoy EnvoyPatchPolicy edge/class-patch uses unsupported type \"Bogus\"")
	assertGatewayDiagnosisContains(t, report, "Envoy EnvoyPatchPolicy edge/class-patch has no jsonPatches")
}

func TestGatewayScanDiagnosesEnvoyProxyProblems(t *testing.T) {
	client := fakeGatewayClient(t,
		[]unstructured.Unstructured{
			testEnvoyObject("EnvoyProxy", "edge", "proxy", map[string]interface{}{
				"spec": map[string]interface{}{
					"provider":    map[string]interface{}{"type": "Other"},
					"concurrency": int64(-1),
					"backendTLS": map[string]interface{}{
						"clientCertificateRef": map[string]interface{}{"group": "", "kind": "Secret", "name": "proxy-client"},
					},
					"dynamicModules": []interface{}{
						map[string]interface{}{"name": "mod"},
						map[string]interface{}{"name": "mod"},
					},
				},
				"status": map[string]interface{}{
					"ancestors": []interface{}{
						map[string]interface{}{
							"conditions": []interface{}{
								testGatewayCondition("Accepted", "False", "Invalid", "bad provider"),
							},
						},
					},
				},
			}),
		},
		[]kruntime.Object{
			&corev1.Secret{ObjectMeta: metav1.ObjectMeta{Namespace: "edge", Name: "proxy-client"}, Data: map[string][]byte{"tls.crt": []byte("cert")}},
		},
	)
	report := model.NewReport("check gateway", model.Target{})

	runGatewayStaticScan(context.Background(), client, report, GatewayOptions{})

	t.Logf("diagnosis output:\n%s", gatewayDiagnosisLog(report))
	assertGatewayDiagnosisContains(t, report, "EnvoyProxy edge/proxy uses unsupported provider.type \"Other\"")
	assertGatewayDiagnosisContains(t, report, "EnvoyProxy edge/proxy has invalid negative concurrency")
	assertGatewayDiagnosisContains(t, report, "EnvoyProxy edge/proxy backendTLS clientCertificateRef tls.key Secret edge/proxy-client is missing key tls.key")
	assertResultContains(t, report, model.StatusWarn, "EnvoyProxy edge/proxy defines dynamicModule name \"mod\" more than once")
	assertGatewayDiagnosisContains(t, report, "EnvoyProxy edge/proxy is not Accepted: Invalid: bad provider")
}

func TestGatewayRouteFilterScopesEnvoyPolicies(t *testing.T) {
	client := fakeGatewayClient(t,
		[]unstructured.Unstructured{
			testGatewayClass("istio", "True", "Accepted"),
			testGateway("edge", "public", "istio", true, "True", "True", testGatewayListener("http", nil)),
			testGatewayHTTPRoute("app", "catalog", "edge", "public", []map[string]interface{}{
				{"name": "catalog-api", "port": int64(80)},
			}, "True", "True"),
			testGatewayRouteKind("GRPCRoute", "app", "ledger", "edge", "public", []map[string]interface{}{
				{"name": "ledger-api", "port": int64(50051)},
			}, "True", "True"),
			testEnvoyPolicyWithSpec("BackendTrafficPolicy", "edge", "edge-traffic", []interface{}{
				map[string]interface{}{"group": "gateway.networking.k8s.io", "kind": "Gateway", "name": "public"},
			}, map[string]interface{}{
				"mergeType": "StrategicMerge",
			}, "True", "True", "Accepted"),
			testEnvoyPolicyWithSpec("BackendTrafficPolicy", "app", "ledger-buffer", []interface{}{
				map[string]interface{}{"group": "gateway.networking.k8s.io", "kind": "GRPCRoute", "name": "ledger"},
			}, map[string]interface{}{
				"requestBuffer": map[string]interface{}{"limit": "1Mi"},
			}, "True", "True", "Accepted"),
			testEnvoyPolicyWithSpec("EnvoyExtensionPolicy", "app", "catalog-processing", []interface{}{
				map[string]interface{}{"group": "gateway.networking.k8s.io", "kind": "HTTPRoute", "name": "catalog"},
			}, map[string]interface{}{
				"extProc": []interface{}{
					map[string]interface{}{
						"backendRefs": []interface{}{
							map[string]interface{}{"name": "processor", "port": int64(9443)},
						},
					},
				},
			}, "True", "True", "Accepted"),
		},
		[]kruntime.Object{
			testGatewayService("app", "catalog-api", 80),
			testGatewayEndpointSlice("app", "catalog-api", true, "10.0.0.10"),
			testGatewayService("app", "ledger-api", 50051),
			testGatewayEndpointSlice("app", "ledger-api", true, "10.0.0.11"),
			testGatewayService("app", "processor", 9000),
		},
	)
	report := model.NewReport("check gateway", model.Target{})

	runGatewayStaticScan(context.Background(), client, report, GatewayOptions{RouteRef: "app/catalog"})

	t.Logf("diagnosis output:\n%s", gatewayDiagnosisLog(report))
	assertGatewayDiagnosisContains(t, report, "Envoy BackendTrafficPolicy edge/edge-traffic targets Gateway edge/public and sets mergeType, but mergeType cannot be used when targeting a Gateway")
	assertGatewayDiagnosisContains(t, report, "Envoy EnvoyExtensionPolicy app/catalog-processing external processor backend Service app/processor does not expose port 9443")
	assertGatewayDiagnosisNotContains(t, report, "Envoy BackendTrafficPolicy app/ledger-buffer enables requestBuffer")
	assertGatewayDiagnosisNotContains(t, report, "Gateway API Route \"app/catalog\" was not found")
}

func TestGatewayRouteFilterMatchesGRPCRoute(t *testing.T) {
	client := fakeGatewayClient(t,
		[]unstructured.Unstructured{
			testGatewayClass("istio", "True", "Accepted"),
			testGateway("edge", "public", "istio", true, "True", "True", testGatewayListener("grpc", nil)),
			testGatewayRouteKind("GRPCRoute", "app", "ledger", "edge", "public", []map[string]interface{}{
				{"name": "ledger-api", "port": int64(50051)},
			}, "True", "True"),
			testEnvoyPolicyWithSpec("BackendTrafficPolicy", "app", "ledger-buffer", []interface{}{
				map[string]interface{}{"group": "gateway.networking.k8s.io", "kind": "GRPCRoute", "name": "ledger"},
			}, map[string]interface{}{
				"requestBuffer": map[string]interface{}{"limit": "1Mi"},
			}, "True", "True", "Accepted"),
		},
		[]kruntime.Object{
			testGatewayService("app", "ledger-api", 50051),
			testGatewayEndpointSlice("app", "ledger-api", true, "10.0.0.11"),
		},
	)
	report := model.NewReport("check gateway", model.Target{})

	runGatewayStaticScan(context.Background(), client, report, GatewayOptions{RouteRef: "app/ledger"})

	t.Logf("diagnosis output:\n%s", gatewayDiagnosisLog(report))
	assertResultContains(t, report, model.StatusWarn, "Envoy BackendTrafficPolicy app/ledger-buffer enables requestBuffer for GRPCRoute app/ledger. This is usually only safe for unary gRPC; streaming gRPC can hang or fail")
	assertGatewayDiagnosisNotContains(t, report, "requestBuffer for GRPCRoute app/ledger")
	assertGatewayDiagnosisNotContains(t, report, "Gateway API Route \"app/ledger\" was not found")
}

func TestGatewayScanDiagnosesEnvoySecurityPolicySecretProblems(t *testing.T) {
	client := fakeGatewayClient(t,
		[]unstructured.Unstructured{
			testGatewayClass("istio", "True", "Accepted"),
			testGateway("edge", "public", "istio", true, "True", "True", testGatewayListener("http", nil)),
			testEnvoySecurityPolicy("app", "security", []interface{}{
				map[string]interface{}{"group": "gateway.networking.k8s.io", "kind": "HTTPRoute", "name": "orders"},
			}, map[string]interface{}{
				"basicAuth": map[string]interface{}{
					"users": map[string]interface{}{"name": "basic-users"},
				},
				"apiKeyAuth": map[string]interface{}{
					"credentialRefs": []interface{}{
						map[string]interface{}{"name": "api-keys"},
						map[string]interface{}{"name": "empty-api-keys"},
					},
				},
				"oidc": map[string]interface{}{
					"clientIDRef":  map[string]interface{}{"name": "oidc-client-id"},
					"clientSecret": map[string]interface{}{"name": "oidc-client-secret"},
				},
			}, "True", "True", "Accepted"),
			testGatewayHTTPRoute("app", "orders", "edge", "public", []map[string]interface{}{
				{"name": "orders-api", "port": int64(80)},
			}, "True", "True"),
		},
		[]kruntime.Object{
			testGatewayService("app", "orders-api", 80),
			testGatewayEndpointSlice("app", "orders-api", true, "10.0.0.10"),
			&corev1.Secret{ObjectMeta: metav1.ObjectMeta{Namespace: "app", Name: "basic-users"}, Data: map[string][]byte{}},
			&corev1.Secret{ObjectMeta: metav1.ObjectMeta{Namespace: "app", Name: "api-keys"}, Data: map[string][]byte{"client-a": []byte("key")}},
			&corev1.Secret{ObjectMeta: metav1.ObjectMeta{Namespace: "app", Name: "empty-api-keys"}, Data: map[string][]byte{}},
			&corev1.Secret{ObjectMeta: metav1.ObjectMeta{Namespace: "app", Name: "oidc-client-id"}, Data: map[string][]byte{"wrong": []byte("id")}},
			&corev1.Secret{ObjectMeta: metav1.ObjectMeta{Namespace: "app", Name: "oidc-client-secret"}, Data: map[string][]byte{"wrong": []byte("secret")}},
		},
	)
	report := model.NewReport("check gateway", model.Target{})

	runGatewayStaticScan(context.Background(), client, report, GatewayOptions{})

	t.Logf("diagnosis output:\n%s", gatewayDiagnosisLog(report))
	assertGatewayDiagnosisContains(t, report, "Envoy SecurityPolicy app/security basicAuth users Secret app/basic-users is missing key .htpasswd")
	assertGatewayDiagnosisContains(t, report, "Envoy SecurityPolicy app/security apiKeyAuth credentialRef 2 Secret app/empty-api-keys has no credential data")
	assertGatewayDiagnosisContains(t, report, "Envoy SecurityPolicy app/security oidc clientIDRef Secret app/oidc-client-id is missing key client-id")
	assertGatewayDiagnosisContains(t, report, "Envoy SecurityPolicy app/security oidc clientSecret Secret app/oidc-client-secret is missing key client-secret")
}

func TestGatewayScanDiagnosesEnvoySecurityPolicyExtAuthBackendProblems(t *testing.T) {
	client := fakeGatewayClient(t,
		[]unstructured.Unstructured{
			testGatewayClass("istio", "True", "Accepted"),
			testGateway("edge", "public", "istio", true, "True", "True", testGatewayListener("http", nil)),
			testEnvoySecurityPolicy("app", "security", []interface{}{
				map[string]interface{}{"group": "gateway.networking.k8s.io", "kind": "HTTPRoute", "name": "orders"},
			}, map[string]interface{}{
				"extAuth": map[string]interface{}{
					"http": map[string]interface{}{
						"backendRefs": []interface{}{
							map[string]interface{}{"name": "auth-api", "port": int64(8443)},
							map[string]interface{}{"name": "missing-auth", "port": int64(8080)},
						},
					},
					"contextExtensions": []interface{}{
						map[string]interface{}{
							"name": "tenant",
							"type": "ValueRef",
							"valueRef": map[string]interface{}{
								"kind": "Secret",
								"name": "auth-context",
								"key":  "tenant-id",
							},
						},
					},
				},
			}, "True", "True", "Accepted"),
			testGatewayHTTPRoute("app", "orders", "edge", "public", []map[string]interface{}{
				{"name": "orders-api", "port": int64(80)},
			}, "True", "True"),
		},
		[]kruntime.Object{
			testGatewayService("app", "orders-api", 80),
			testGatewayEndpointSlice("app", "orders-api", true, "10.0.0.10"),
			testGatewayService("app", "auth-api", 8080),
			&corev1.Secret{ObjectMeta: metav1.ObjectMeta{Namespace: "app", Name: "auth-context"}, Data: map[string][]byte{"wrong": []byte("tenant")}},
		},
	)
	report := model.NewReport("check gateway", model.Target{})

	runGatewayStaticScan(context.Background(), client, report, GatewayOptions{})

	t.Logf("diagnosis output:\n%s", gatewayDiagnosisLog(report))
	assertGatewayDiagnosisContains(t, report, "Envoy SecurityPolicy app/security external authorization backend Service app/auth-api does not expose port 8443")
	assertGatewayDiagnosisContains(t, report, "Envoy SecurityPolicy app/security external authorization backend Service app/missing-auth is missing or unreadable")
	assertGatewayDiagnosisContains(t, report, "Envoy SecurityPolicy app/security extAuth contextExtension 1 Secret app/auth-context is missing key tenant-id")
}

func TestGatewayScanWarnsEnvoySecurityPolicyHTTPAuthOnTCPRoute(t *testing.T) {
	client := fakeGatewayClient(t,
		[]unstructured.Unstructured{
			testGatewayClass("istio", "True", "Accepted"),
			testGateway("edge", "public", "istio", true, "True", "True", testGatewayListener("tcp", nil)),
			testEnvoySecurityPolicy("app", "security", []interface{}{
				map[string]interface{}{"group": "gateway.networking.k8s.io", "kind": "TCPRoute", "name": "tcp-orders"},
			}, map[string]interface{}{
				"jwt": map[string]interface{}{
					"providers": []interface{}{map[string]interface{}{"name": "issuer"}},
				},
				"authorization": map[string]interface{}{
					"rules": []interface{}{map[string]interface{}{"name": "allow-admins"}},
				},
			}, "True", "True", "Accepted"),
			testGatewayRouteKind("TCPRoute", "app", "tcp-orders", "edge", "public", []map[string]interface{}{
				{"name": "orders-api", "port": int64(80)},
			}, "True", "True"),
		},
		[]kruntime.Object{
			testGatewayService("app", "orders-api", 80),
			testGatewayEndpointSlice("app", "orders-api", true, "10.0.0.10"),
		},
	)
	report := model.NewReport("check gateway", model.Target{})

	runGatewayStaticScan(context.Background(), client, report, GatewayOptions{})

	t.Logf("diagnosis output:\n%s", gatewayDiagnosisLog(report))
	assertResultContains(t, report, model.StatusWarn, "Envoy SecurityPolicy app/security targets TCPRoute app/tcp-orders with HTTP authentication settings; those settings do not apply to raw TCP traffic")
	assertResultContains(t, report, model.StatusWarn, "Envoy SecurityPolicy app/security targets TCPRoute app/tcp-orders with HTTP authorization rules; only client-IP based authorization applies to TCPRoute targets")
	assertGatewayDiagnosisNotContains(t, report, "HTTP authentication settings; those settings do not apply to raw TCP traffic")
	assertGatewayDiagnosisNotContains(t, report, "HTTP authorization rules; only client-IP based authorization applies to TCPRoute targets")
}

func TestGatewayScanDiagnosesEnvoySecurityPolicyAPIKeyAndJWTProblems(t *testing.T) {
	client := fakeGatewayClient(t,
		[]unstructured.Unstructured{
			testGatewayClass("eg", "True", "Accepted"),
			testGateway("edge", "public", "eg", true, "True", "True", testGatewayListener("http", nil)),
			testEnvoySecurityPolicy("app", "security", []interface{}{
				map[string]interface{}{"group": "gateway.networking.k8s.io", "kind": "HTTPRoute", "name": "orders"},
			}, map[string]interface{}{
				"apiKeyAuth": map[string]interface{}{
					"extractFrom": []interface{}{
						map[string]interface{}{},
					},
					"credentialRefs": []interface{}{
						map[string]interface{}{"name": "api-keys"},
					},
				},
				"jwt": map[string]interface{}{
					"providers": []interface{}{
						map[string]interface{}{
							"name": "corp",
							"remoteJWKS": map[string]interface{}{
								"uri": "https://issuer.example/.well-known/jwks.json",
								"backendRefs": []interface{}{
									map[string]interface{}{"name": "jwks-api", "port": int64(8443)},
								},
							},
						},
					},
				},
				"authorization": map[string]interface{}{
					"rules": []interface{}{
						map[string]interface{}{
							"action": "Allow",
							"principal": map[string]interface{}{
								"jwt": map[string]interface{}{
									"provider": "missing-provider",
									"claims": []interface{}{
										map[string]interface{}{"name": "role", "values": []interface{}{"admin"}},
									},
								},
							},
						},
					},
				},
			}, "True", "True", "Accepted"),
			testEnvoySecurityPolicy("app", "jwks-local", []interface{}{
				map[string]interface{}{"group": "gateway.networking.k8s.io", "kind": "HTTPRoute", "name": "orders"},
			}, map[string]interface{}{
				"jwt": map[string]interface{}{
					"providers": []interface{}{
						map[string]interface{}{
							"name":   "corp",
							"issuer": "https://issuer.example",
							"localJWKS": map[string]interface{}{
								"type": "ValueRef",
								"valueRef": map[string]interface{}{
									"kind": "ConfigMap",
									"name": "missing-jwks",
								},
							},
						},
					},
				},
			}, "True", "True", "Accepted"),
			testGatewayHTTPRoute("app", "orders", "edge", "public", []map[string]interface{}{
				{"name": "orders-api", "port": int64(80)},
			}, "True", "True"),
		},
		[]kruntime.Object{
			testGatewayService("app", "orders-api", 80),
			testGatewayEndpointSlice("app", "orders-api", true, "10.0.0.10"),
			&corev1.Secret{ObjectMeta: metav1.ObjectMeta{Namespace: "app", Name: "api-keys"}, Data: map[string][]byte{"client-a": []byte("key")}},
			testGatewayService("app", "jwks-api", 8080),
		},
	)
	report := model.NewReport("check gateway", model.Target{})

	runGatewayStaticScan(context.Background(), client, report, GatewayOptions{})

	t.Logf("diagnosis output:\n%s", gatewayDiagnosisLog(report))
	assertGatewayDiagnosisContains(t, report, "Envoy SecurityPolicy app/security apiKeyAuth extractFrom 1 does not read keys from any header, cookie, or query param")
	assertGatewayDiagnosisContains(t, report, "Envoy SecurityPolicy app/security JWT remote JWKS backend Service app/jwks-api does not expose port 8443")
	assertGatewayDiagnosisContains(t, report, "Envoy SecurityPolicy app/security authorization rule 1 references missing JWT provider \"missing-provider\"")
	assertGatewayDiagnosisContains(t, report, "Envoy SecurityPolicy app/jwks-local references ConfigMap app/missing-jwks, but that object is missing or unreadable")
}

func TestGatewayScanWarnsEnvoySecurityPolicyCORSCredentialWildcard(t *testing.T) {
	client := fakeGatewayClient(t,
		[]unstructured.Unstructured{
			testGatewayClass("eg", "True", "Accepted"),
			testGateway("edge", "public", "eg", true, "True", "True", testGatewayListener("http", nil)),
			testEnvoySecurityPolicy("app", "security", []interface{}{
				map[string]interface{}{"group": "gateway.networking.k8s.io", "kind": "HTTPRoute", "name": "orders"},
			}, map[string]interface{}{
				"cors": map[string]interface{}{
					"allowCredentials": true,
					"allowOrigins":     []interface{}{"*"},
				},
			}, "True", "True", "Accepted"),
			testGatewayHTTPRoute("app", "orders", "edge", "public", []map[string]interface{}{
				{"name": "orders-api", "port": int64(80)},
			}, "True", "True"),
		},
		[]kruntime.Object{
			testGatewayService("app", "orders-api", 80),
			testGatewayEndpointSlice("app", "orders-api", true, "10.0.0.10"),
		},
	)
	report := model.NewReport("check gateway", model.Target{})

	runGatewayStaticScan(context.Background(), client, report, GatewayOptions{})

	t.Logf("diagnosis output:\n%s", gatewayDiagnosisLog(report))
	assertResultContains(t, report, model.StatusWarn, "Envoy SecurityPolicy app/security CORS allows credentials with wildcard origin \"*\"")
	assertGatewayDiagnosisNotContains(t, report, "CORS allows credentials with wildcard origin")
}

func TestGatewayScanResolvesEnvoySecurityPolicyTargetSelectors(t *testing.T) {
	policy := testEnvoySecurityPolicy("app", "security", nil, map[string]interface{}{
		"basicAuth": map[string]interface{}{
			"users": map[string]interface{}{"name": "basic-users"},
		},
	}, "True", "True", "Accepted")
	policy.Object["spec"].(map[string]interface{})["targetSelectors"] = []interface{}{
		map[string]interface{}{
			"group": "gateway.networking.k8s.io",
			"kind":  "HTTPRoute",
			"matchLabels": map[string]interface{}{
				"app": "orders",
			},
		},
	}
	route := testGatewayHTTPRoute("app", "orders", "edge", "public", []map[string]interface{}{
		{"name": "orders-api", "port": int64(80)},
	}, "True", "True")
	route.SetLabels(map[string]string{"app": "orders"})
	client := fakeGatewayClient(t,
		[]unstructured.Unstructured{
			testGatewayClass("eg", "True", "Accepted"),
			testGateway("edge", "public", "eg", true, "True", "True", testGatewayListener("http", nil)),
			policy,
			route,
		},
		[]kruntime.Object{
			testGatewayService("app", "orders-api", 80),
			testGatewayEndpointSlice("app", "orders-api", true, "10.0.0.10"),
			&corev1.Secret{ObjectMeta: metav1.ObjectMeta{Namespace: "app", Name: "basic-users"}, Data: map[string][]byte{}},
		},
	)
	report := model.NewReport("check gateway", model.Target{})

	runGatewayStaticScan(context.Background(), client, report, GatewayOptions{RouteRef: "app/orders"})

	t.Logf("diagnosis output:\n%s", gatewayDiagnosisLog(report))
	assertGatewayDiagnosisContains(t, report, "Envoy SecurityPolicy app/security basicAuth users Secret app/basic-users is missing key .htpasswd")
	assertResultNotContains(t, report, model.StatusInfo, "uses targetSelectors; KNM does not resolve selector-based policy targets yet")
}

func TestGatewayScanDiagnosesXBackendTrafficPolicyTargetProblems(t *testing.T) {
	client := fakeGatewayClient(t,
		[]unstructured.Unstructured{
			testXBackendTrafficPolicy("app", "traffic", []interface{}{
				map[string]interface{}{"group": "", "kind": "Service", "name": "payments-api"},
			}, "True", "False", "BackendNotFound"),
		},
		nil,
	)
	report := model.NewReport("check gateway", model.Target{})

	runGatewayStaticScan(context.Background(), client, report, GatewayOptions{})

	t.Logf("diagnosis output:\n%s", gatewayDiagnosisLog(report))
	assertGatewayDiagnosisContains(t, report, "XBackendTrafficPolicy app/traffic targets Service app/payments-api, but that Service is missing or unreadable")
	assertGatewayDiagnosisContains(t, report, "XBackendTrafficPolicy app/traffic is not ResolvedRefs: BackendNotFound")
}

func TestGatewayScanDiagnosesImplementationServicePortMismatch(t *testing.T) {
	client := fakeGatewayClient(t,
		[]unstructured.Unstructured{
			testGatewayClass("istio", "True", "Accepted"),
			testGateway("edge", "public", "istio", true, "True", "True", testGatewayListener("http", nil)),
		},
		[]kruntime.Object{
			testGatewayImplementationService("edge", "public-istio", "public", 8080),
			testGatewayEndpointSlice("edge", "public-istio", true, "10.0.0.20"),
		},
	)
	report := model.NewReport("check gateway", model.Target{})

	runGatewayStaticScan(context.Background(), client, report, GatewayOptions{})

	t.Logf("diagnosis output:\n%s", gatewayDiagnosisLog(report))
	assertGatewayDiagnosisContains(t, report, "Gateway edge/public listener http uses port 80, but implementation Service edge/public-istio exposes 8080->8080/ name=http")
}

func TestGatewayScanDiagnosesImplementationServiceNoReadyEndpoints(t *testing.T) {
	client := fakeGatewayClient(t,
		[]unstructured.Unstructured{
			testGatewayClass("istio", "True", "Accepted"),
			testGateway("edge", "public", "istio", true, "True", "True", testGatewayListener("http", nil)),
		},
		[]kruntime.Object{
			testGatewayImplementationService("edge", "public-istio", "public", 80),
			testGatewayEndpointSlice("edge", "public-istio", false, "10.0.0.20"),
		},
	)
	report := model.NewReport("check gateway", model.Target{})

	runGatewayStaticScan(context.Background(), client, report, GatewayOptions{})

	t.Logf("diagnosis output:\n%s", gatewayDiagnosisLog(report))
	assertGatewayDiagnosisContains(t, report, "Gateway implementation Service edge/public-istio has no ready endpoints")
}

func TestGatewayBroadScanDiagnosisMatrix(t *testing.T) {
	tests := []struct {
		name           string
		gatewayObjects []unstructured.Unstructured
		coreObjects    []kruntime.Object
		want           []string
		doNotWant      []string
	}{
		{
			name: "gatewayclass no controller",
			gatewayObjects: []unstructured.Unstructured{
				gatewayUnstructured("GatewayClass", "", "istio", map[string]interface{}{
					"spec":   map[string]interface{}{},
					"status": map[string]interface{}{"conditions": []interface{}{testGatewayCondition("Accepted", "True", "Accepted", "")}},
				}),
			},
			want: []string{"GatewayClass \"istio\" has no controllerName"},
		},
		{
			name: "gatewayclass rejected",
			gatewayObjects: []unstructured.Unstructured{
				testGatewayClass("istio", "False", "InvalidParameters"),
			},
			want: []string{"GatewayClass istio is not Accepted: InvalidParameters"},
		},
		{
			name: "gateway missing class name",
			gatewayObjects: []unstructured.Unstructured{
				testGatewayWithoutClassName("edge", "public", testGatewayListener("http", nil)),
			},
			want: []string{"Gateway edge/public has no gatewayClassName"},
		},
		{
			name: "gateway missing gatewayclass",
			gatewayObjects: []unstructured.Unstructured{
				testGateway("edge", "public", "istio", true, "True", "True", testGatewayListener("http", nil)),
			},
			want: []string{"Gateway edge/public references GatewayClass \"istio\""},
		},
		{
			name: "gateway not programmed",
			gatewayObjects: []unstructured.Unstructured{
				testGatewayClass("istio", "True", "Accepted"),
				testGateway("edge", "public", "istio", true, "True", "False", testGatewayListener("http", nil)),
			},
			want: []string{"Gateway edge/public is not Programmed: False"},
		},
		{
			name: "gateway no address",
			gatewayObjects: []unstructured.Unstructured{
				testGatewayClass("istio", "True", "Accepted"),
				testGateway("edge", "public", "istio", false, "True", "True", testGatewayListener("http", nil)),
			},
			want: []string{"Gateway edge/public has no assigned address"},
		},
		{
			name: "gateway no listeners",
			gatewayObjects: []unstructured.Unstructured{
				testGatewayClass("istio", "True", "Accepted"),
				gatewayUnstructured("Gateway", "edge", "public", map[string]interface{}{
					"spec": map[string]interface{}{"gatewayClassName": "istio"},
					"status": map[string]interface{}{
						"conditions": []interface{}{
							testGatewayCondition("Accepted", "True", "Accepted", ""),
							testGatewayCondition("Programmed", "True", "Programmed", ""),
						},
						"addresses": []interface{}{map[string]interface{}{"value": "10.0.0.20"}},
					},
				}),
			},
			want: []string{"Gateway edge/public has no listeners"},
		},
		{
			name: "listener conflict",
			gatewayObjects: []unstructured.Unstructured{
				testGatewayClass("istio", "True", "Accepted"),
				testGatewayWithListenerExtraCondition("edge", "public", "istio", testGatewayListener("http", nil), testGatewayCondition("Conflicted", "True", "HostnameConflict", "hostname overlaps")),
			},
			want: []string{"Gateway listener edge/public/http has a listener conflict: HostnameConflict: hostname overlaps"},
		},
		{
			name: "tls cross namespace no grant",
			gatewayObjects: []unstructured.Unstructured{
				testGatewayClass("istio", "True", "Accepted"),
				testGateway("edge", "partner", "istio", true, "True", "True", testGatewayListener("https", []map[string]interface{}{
					{"name": "partner-cert", "namespace": "certs"},
				})),
			},
			want: []string{"Gateway edge/partner references TLS Secret certs/partner-cert across namespaces"},
		},
		{
			name: "tls missing secret deduped",
			gatewayObjects: []unstructured.Unstructured{
				testGatewayClass("istio", "True", "Accepted"),
				testGatewayWithListenerStatus("edge", "partner", "istio", true, "True", "True", testGatewayListener("https", []map[string]interface{}{
					{"name": "partner-cert"},
				}), "False", "False"),
			},
			want:      []string{"Gateway edge/partner references missing or unreadable TLS Secret edge/partner-cert"},
			doNotWant: []string{"Gateway listener edge/partner/https is not Programmed", "Gateway listener edge/partner/https is not ResolvedRefs"},
		},
		{
			name: "route no parent refs",
			gatewayObjects: []unstructured.Unstructured{
				testGatewayClass("istio", "True", "Accepted"),
				testGatewayHTTPRouteWithRules("app", "payments", nil, []map[string]interface{}{
					{"backendRefs": []interface{}{testBackendRef("payments-api", "", int64(80))}},
				}),
			},
			coreObjects: []kruntime.Object{
				testGatewayService("app", "payments-api", 80),
				testGatewayEndpointSlice("app", "payments-api", true, "10.0.0.10"),
			},
			want: []string{"HTTPRoute app/payments is not attached to any Gateway"},
		},
		{
			name: "route missing parent gateway",
			gatewayObjects: []unstructured.Unstructured{
				testGatewayClass("istio", "True", "Accepted"),
				testGatewayHTTPRoute("app", "payments", "edge", "public", []map[string]interface{}{
					testBackendRef("payments-api", "", int64(80)),
				}, "True", "True"),
			},
			coreObjects: []kruntime.Object{
				testGatewayService("app", "payments-api", 80),
				testGatewayEndpointSlice("app", "payments-api", true, "10.0.0.10"),
			},
			want: []string{"HTTPRoute app/payments references Gateway edge/public"},
		},
		{
			name: "route no parent status",
			gatewayObjects: []unstructured.Unstructured{
				testGatewayClass("istio", "True", "Accepted"),
				testGateway("edge", "public", "istio", true, "True", "True", testGatewayListener("http", nil)),
				testGatewayHTTPRouteNoStatus("app", "payments", "edge", "public", []map[string]interface{}{
					testBackendRef("payments-api", "", int64(80)),
				}),
			},
			coreObjects: []kruntime.Object{
				testGatewayService("app", "payments-api", 80),
				testGatewayEndpointSlice("app", "payments-api", true, "10.0.0.10"),
			},
			want: []string{"HTTPRoute app/payments has no parent status"},
		},
		{
			name: "route rejected",
			gatewayObjects: []unstructured.Unstructured{
				testGatewayClass("istio", "True", "Accepted"),
				testGateway("edge", "public", "istio", true, "True", "True", testGatewayListener("http", nil)),
				testGatewayHTTPRoute("app", "payments", "edge", "public", []map[string]interface{}{
					testBackendRef("payments-api", "", int64(80)),
				}, "False", "True"),
			},
			coreObjects: []kruntime.Object{
				testGatewayService("app", "payments-api", 80),
				testGatewayEndpointSlice("app", "payments-api", true, "10.0.0.10"),
			},
			want: []string{"HTTPRoute app/payments is not accepted by Gateway edge/public"},
		},
		{
			name: "route unresolved refs kept without concrete cause",
			gatewayObjects: []unstructured.Unstructured{
				testGatewayClass("istio", "True", "Accepted"),
				testGateway("edge", "public", "istio", true, "True", "True", testGatewayListener("http", nil)),
				testGatewayHTTPRoute("app", "payments", "edge", "public", []map[string]interface{}{
					testBackendRef("payments-api", "", int64(80)),
				}, "True", "False"),
			},
			coreObjects: []kruntime.Object{
				testGatewayService("app", "payments-api", 80),
				testGatewayEndpointSlice("app", "payments-api", true, "10.0.0.10"),
			},
			want: []string{"HTTPRoute app/payments has unresolved references"},
		},
		{
			name: "route partially invalid",
			gatewayObjects: []unstructured.Unstructured{
				testGatewayClass("istio", "True", "Accepted"),
				testGateway("edge", "public", "istio", true, "True", "True", testGatewayListener("http", nil)),
				testGatewayHTTPRouteWithParentCondition("app", "payments", "edge", "public", []map[string]interface{}{
					testBackendRef("payments-api", "", int64(80)),
				}, testGatewayCondition("PartiallyInvalid", "True", "UnsupportedValue", "some rules are invalid")),
			},
			coreObjects: []kruntime.Object{
				testGatewayService("app", "payments-api", 80),
				testGatewayEndpointSlice("app", "payments-api", true, "10.0.0.10"),
			},
			want: []string{"HTTPRoute app/payments is partially invalid"},
		},
		{
			name: "rule no backend refs",
			gatewayObjects: []unstructured.Unstructured{
				testGatewayClass("istio", "True", "Accepted"),
				testGateway("edge", "public", "istio", true, "True", "True", testGatewayListener("http", nil)),
				testGatewayHTTPRouteWithRules("app", "payments", []map[string]interface{}{{"name": "public", "namespace": "edge"}}, []map[string]interface{}{{}}),
			},
			want: []string{"HTTPRoute app/payments rule 1 has no backendRefs"},
		},
		{
			name: "backend ref no name",
			gatewayObjects: []unstructured.Unstructured{
				testGatewayClass("istio", "True", "Accepted"),
				testGateway("edge", "public", "istio", true, "True", "True", testGatewayListener("http", nil)),
				testGatewayHTTPRoute("app", "payments", "edge", "public", []map[string]interface{}{
					{"port": int64(80)},
				}, "True", "True"),
			},
			want: []string{"HTTPRoute app/payments rule 1 has a backendRef with no name"},
		},
		{
			name: "backend ref no numeric port",
			gatewayObjects: []unstructured.Unstructured{
				testGatewayClass("istio", "True", "Accepted"),
				testGateway("edge", "public", "istio", true, "True", "True", testGatewayListener("http", nil)),
				testGatewayHTTPRoute("app", "payments", "edge", "public", []map[string]interface{}{
					{"name": "payments-api"},
				}, "True", "True"),
			},
			want: []string{"HTTPRoute app/payments backendRef app/payments-api does not specify a Service port"},
		},
		{
			name: "backend missing service deduped",
			gatewayObjects: []unstructured.Unstructured{
				testGatewayClass("istio", "True", "Accepted"),
				testGateway("edge", "public", "istio", true, "True", "True", testGatewayListener("http", nil)),
				testGatewayHTTPRoute("app", "payments", "edge", "public", []map[string]interface{}{
					testBackendRef("payments-api", "", int64(80)),
				}, "True", "False"),
			},
			want:      []string{"HTTPRoute app/payments rule 1 routes to Service app/payments-api, but that Service is missing or unreadable"},
			doNotWant: []string{"HTTPRoute app/payments has unresolved references"},
		},
		{
			name: "backend wrong service port",
			gatewayObjects: []unstructured.Unstructured{
				testGatewayClass("istio", "True", "Accepted"),
				testGateway("edge", "public", "istio", true, "True", "True", testGatewayListener("http", nil)),
				testGatewayHTTPRoute("app", "orders", "edge", "public", []map[string]interface{}{
					testBackendRef("orders-api", "", int64(9999)),
				}, "True", "True"),
			},
			coreObjects: []kruntime.Object{testGatewayService("app", "orders-api", 80)},
			want:        []string{"HTTPRoute app/orders rule 1 routes to Service app/orders-api port 9999, but the Service exposes"},
		},
		{
			name: "backend no ready endpoints",
			gatewayObjects: []unstructured.Unstructured{
				testGatewayClass("istio", "True", "Accepted"),
				testGateway("edge", "public", "istio", true, "True", "True", testGatewayListener("http", nil)),
				testGatewayHTTPRoute("app", "payments", "edge", "public", []map[string]interface{}{
					testBackendRef("payments-api", "", int64(80)),
				}, "True", "True"),
			},
			coreObjects: []kruntime.Object{
				testGatewayService("app", "payments-api", 80),
				testGatewayEndpointSlice("app", "payments-api", false, "10.0.0.10"),
			},
			want: []string{"HTTPRoute app/payments rule 1 routes to Service app/payments-api port 80, but that Service has no ready endpoints"},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			client := fakeGatewayClient(t, tt.gatewayObjects, tt.coreObjects)
			report := model.NewReport("check gateway", model.Target{})

			runGatewayStaticScan(context.Background(), client, report, GatewayOptions{})

			t.Logf("diagnosis output:\n%s", gatewayDiagnosisLog(report))
			for _, want := range tt.want {
				assertGatewayDiagnosisContains(t, report, want)
			}
			for _, unwanted := range tt.doNotWant {
				assertGatewayDiagnosisNotContains(t, report, unwanted)
			}
		})
	}
}

func TestGatewayRouteFilterSkipsUnrelatedGatewayProblems(t *testing.T) {
	client := fakeGatewayClient(t,
		[]unstructured.Unstructured{
			testGatewayClass("istio", "True", "Accepted"),
			testGateway("infra", "public", "istio", true, "True", "True", testGatewayListener("http", nil)),
			testGateway("infra", "broken-tls", "istio", true, "True", "True", testGatewayListener("https", []map[string]interface{}{
				{"name": "missing-cert"},
			})),
			testGatewayHTTPRoute("app", "api-route", "infra", "public", []map[string]interface{}{
				testBackendRef("api", "", int64(9999)),
			}, "True", "True"),
		},
		[]kruntime.Object{
			testGatewayService("app", "api", 80),
			testGatewayEndpointSlice("app", "api", true, "10.0.0.10"),
		},
	)
	report := model.NewReport("check gateway", model.Target{})

	runGatewayStaticScan(context.Background(), client, report, GatewayOptions{RouteRef: "app/api-route"})

	assertGatewayDiagnosisContains(t, report, "Service app/api port 9999")
	assertGatewayDiagnosisNotContains(t, report, "broken-tls")
	assertGatewayDiagnosisNotContains(t, report, "missing-cert")
}

func TestGatewayNamespaceScanResolvesCrossNamespaceRouteParents(t *testing.T) {
	client := fakeGatewayClient(t,
		[]unstructured.Unstructured{
			testGatewayClass("istio", "True", "Accepted"),
			testGateway("edge", "public", "istio", true, "True", "True", testGatewayListener("http", nil)),
			testGateway("edge", "partner", "istio", true, "True", "True", testGatewayListener("https", []map[string]interface{}{
				{"name": "partner-cert"},
			})),
			testGatewayHTTPRoute("app", "catalog", "edge", "public", []map[string]interface{}{
				testBackendRef("catalog-api", "", int64(80)),
			}, "True", "True"),
		},
		[]kruntime.Object{
			testGatewayService("app", "catalog-api", 80),
			testGatewayEndpointSlice("app", "catalog-api", true, "10.0.0.10"),
		},
	)
	report := model.NewReport("check gateway", model.Target{})

	runGatewayStaticScan(context.Background(), client, report, GatewayOptions{Namespace: "app"})

	assertGatewayDiagnosisNotContains(t, report, "Gateway edge/public was not found")
	assertGatewayDiagnosisNotContains(t, report, "partner-cert")
	if report.CountByStatus(model.StatusFail) != 0 {
		t.Fatalf("expected namespace scan to avoid cross-namespace parent false positives, got %#v", report.Results)
	}
}

func TestGatewayTrafficIntentFromURL(t *testing.T) {
	intent, intentMode, err := gatewayTrafficIntentFromOptions(GatewayOptions{
		URL:         "https://payments.knm.local:8443/api/items?version=v1",
		Method:      "post",
		HTTPHeaders: map[string]string{"x-canary": "true"},
	})
	if err != nil {
		t.Fatalf("gatewayTrafficIntentFromOptions returned error: %v", err)
	}
	if !intentMode {
		t.Fatal("expected intent mode")
	}
	if intent.Scheme != "https" || intent.Host != "payments.knm.local" || intent.Port != 8443 || intent.Path != "/api/items" || intent.Method != "POST" {
		t.Fatalf("unexpected intent: %#v", intent)
	}
	if intent.Protocol != "https" || strings.Join(intent.RouteFamilies, ",") != "HTTPRoute" {
		t.Fatalf("unexpected protocol inference: %#v", intent)
	}
	if got := intent.Query["version"]; len(got) != 1 || got[0] != "v1" {
		t.Fatalf("query version = %#v, want v1", got)
	}
}

func TestGatewayTrafficIntentDefaultsMethodToGET(t *testing.T) {
	intent, intentMode, err := gatewayTrafficIntentFromOptions(GatewayOptions{
		Host: "payments.knm.local",
		Path: "/api",
	})
	if err != nil {
		t.Fatalf("gatewayTrafficIntentFromOptions returned error: %v", err)
	}
	if !intentMode {
		t.Fatal("expected intent mode")
	}
	if intent.Method != "GET" {
		t.Fatalf("method = %q, want GET", intent.Method)
	}
	if intent.Protocol != "http" || strings.Join(intent.RouteFamilies, ",") != "HTTPRoute" {
		t.Fatalf("unexpected protocol inference: %#v", intent)
	}
}

func TestGatewayTrafficIntentInfersGRPCRoute(t *testing.T) {
	intent, intentMode, err := gatewayTrafficIntentFromOptions(GatewayOptions{
		Host:        "payments.knm.local",
		GRPCService: "checkout.Payment",
		GRPCMethod:  "Create",
	})
	if err != nil {
		t.Fatalf("gatewayTrafficIntentFromOptions returned error: %v", err)
	}
	if !intentMode {
		t.Fatal("expected intent mode")
	}
	if intent.Protocol != "grpc" || strings.Join(intent.RouteFamilies, ",") != "GRPCRoute" {
		t.Fatalf("unexpected protocol inference: %#v", intent)
	}
	if intent.Path != "" || intent.Method != "" {
		t.Fatalf("gRPC intent should not synthesize HTTP path/method: %#v", intent)
	}
}

func TestGatewayTrafficIntentInfersTLSRouteFromHostPort(t *testing.T) {
	intent, intentMode, err := gatewayTrafficIntentFromOptions(GatewayOptions{
		Host: "invoices.knm.local",
		Port: 443,
	})
	if err != nil {
		t.Fatalf("gatewayTrafficIntentFromOptions returned error: %v", err)
	}
	if !intentMode {
		t.Fatal("expected intent mode")
	}
	if intent.Protocol != "tls" || strings.Join(intent.RouteFamilies, ",") != "TLSRoute" {
		t.Fatalf("unexpected protocol inference: %#v", intent)
	}
	if intent.Path != "" || intent.Method != "" {
		t.Fatalf("TLS intent should not synthesize HTTP path/method: %#v", intent)
	}
}

func TestGatewayTrafficIntentTracesGRPCRouteBackendProblems(t *testing.T) {
	listener := testGatewayListener("grpc", nil)
	listener["hostname"] = "*.knm.local"
	listener["protocol"] = "HTTP2"
	listener["port"] = int64(50051)
	route := testGatewayRouteKind("GRPCRoute", "app", "payments", "edge", "grpc", []map[string]interface{}{
		testBackendRef("ledger-api", "", int64(50051)),
	}, "True", "True")
	route.Object["spec"].(map[string]interface{})["hostnames"] = []interface{}{"payments.knm.local"}
	rules := route.Object["spec"].(map[string]interface{})["rules"].([]interface{})
	rules[0].(map[string]interface{})["matches"] = []interface{}{map[string]interface{}{
		"method": map[string]interface{}{"service": "checkout.Payment", "method": "Create"},
		"headers": []interface{}{map[string]interface{}{
			"name":  "x-region",
			"value": "us",
		}},
	}}
	client := fakeGatewayClient(t,
		[]unstructured.Unstructured{
			testGatewayClass("istio", "True", "Accepted"),
			testGateway("edge", "grpc", "istio", true, "True", "True", listener),
			route,
		},
		nil,
	)
	report := model.NewReport("check gateway", model.Target{})

	runGatewayIntentScan(context.Background(), client, report, GatewayOptions{}, gatewayTrafficIntent{
		Protocol:      "grpc",
		RouteFamilies: []string{"GRPCRoute"},
		Host:          "payments.knm.local",
		Port:          50051,
		GRPCService:   "checkout.Payment",
		GRPCMethod:    "Create",
		Headers:       map[string]string{"x-region": "us"},
	})

	t.Logf("diagnosis output:\n%s", gatewayDiagnosisLog(report))
	assertGatewayDiagnosisContains(t, report, "GRPCRoute app/payments rule 1 routes to Service app/ledger-api, but that Service is missing or unreadable")
}

func TestGatewayTrafficIntentExplainsGRPCRouteMethodMiss(t *testing.T) {
	listener := testGatewayListener("grpc", nil)
	listener["hostname"] = "*.knm.local"
	listener["protocol"] = "HTTP2"
	listener["port"] = int64(50051)
	route := testGatewayRouteKind("GRPCRoute", "app", "payments", "edge", "grpc", []map[string]interface{}{
		testBackendRef("ledger-api", "", int64(50051)),
	}, "True", "True")
	route.Object["spec"].(map[string]interface{})["hostnames"] = []interface{}{"payments.knm.local"}
	rules := route.Object["spec"].(map[string]interface{})["rules"].([]interface{})
	rules[0].(map[string]interface{})["matches"] = []interface{}{map[string]interface{}{
		"method": map[string]interface{}{"service": "checkout.Payment", "method": "Create"},
	}}
	client := fakeGatewayClient(t,
		[]unstructured.Unstructured{
			testGatewayClass("istio", "True", "Accepted"),
			testGateway("edge", "grpc", "istio", true, "True", "True", listener),
			route,
		},
		nil,
	)
	report := model.NewReport("check gateway", model.Target{})

	runGatewayIntentScan(context.Background(), client, report, GatewayOptions{}, gatewayTrafficIntent{
		Protocol:      "grpc",
		RouteFamilies: []string{"GRPCRoute"},
		Host:          "payments.knm.local",
		Port:          50051,
		GRPCService:   "checkout.Payment",
		GRPCMethod:    "Refund",
	})

	t.Logf("diagnosis output:\n%s", gatewayDiagnosisLog(report))
	assertGatewayDiagnosisContains(t, report, "GRPCRoute service matched for host=payments.knm.local port=50051 grpcService=checkout.Payment grpcMethod=Refund, but no rule matched gRPC method \"Refund\"")
}

func TestGatewayTrafficIntentExplainsGRPCRouteHeaderMiss(t *testing.T) {
	listener := testGatewayListener("grpc", nil)
	listener["hostname"] = "*.knm.local"
	listener["protocol"] = "HTTP2"
	listener["port"] = int64(50051)
	route := testGatewayRouteKind("GRPCRoute", "app", "payments", "edge", "grpc", []map[string]interface{}{
		testBackendRef("ledger-api", "", int64(50051)),
	}, "True", "True")
	route.Object["spec"].(map[string]interface{})["hostnames"] = []interface{}{"payments.knm.local"}
	rules := route.Object["spec"].(map[string]interface{})["rules"].([]interface{})
	rules[0].(map[string]interface{})["matches"] = []interface{}{
		map[string]interface{}{
			"method": map[string]interface{}{"service": "checkout.Payment", "method": "Create"},
			"headers": []interface{}{map[string]interface{}{
				"name":  "x-region",
				"value": "us",
			}},
		},
		map[string]interface{}{
			"method": map[string]interface{}{"service": "catalog.Inventory", "method": "List"},
		},
	}
	client := fakeGatewayClient(t,
		[]unstructured.Unstructured{
			testGatewayClass("istio", "True", "Accepted"),
			testGateway("edge", "grpc", "istio", true, "True", "True", listener),
			route,
		},
		nil,
	)
	report := model.NewReport("check gateway", model.Target{})

	runGatewayIntentScan(context.Background(), client, report, GatewayOptions{}, gatewayTrafficIntent{
		Protocol:      "grpc",
		RouteFamilies: []string{"GRPCRoute"},
		Host:          "payments.knm.local",
		Port:          50051,
		GRPCService:   "checkout.Payment",
		GRPCMethod:    "Create",
		Headers:       map[string]string{"x-region": "eu"},
	})

	t.Logf("diagnosis output:\n%s", gatewayDiagnosisLog(report))
	assertGatewayDiagnosisContains(t, report, "GRPCRoute service/method matched for host=payments.knm.local port=50051 grpcService=checkout.Payment grpcMethod=Create 1 header(s), but request headers did not satisfy any matching rule")
}

func TestGatewayTrafficIntentTracesTLSRouteBackendProblems(t *testing.T) {
	listener := testGatewayListener("tls", nil)
	listener["hostname"] = "*.knm.local"
	listener["protocol"] = "TLS"
	listener["port"] = int64(443)
	route := testGatewayRouteKind("TLSRoute", "app", "invoices", "edge", "tls", []map[string]interface{}{
		testBackendRef("invoices-api", "", int64(443)),
	}, "True", "True")
	route.Object["spec"].(map[string]interface{})["hostnames"] = []interface{}{"invoices.knm.local"}
	client := fakeGatewayClient(t,
		[]unstructured.Unstructured{
			testGatewayClass("istio", "True", "Accepted"),
			testGateway("edge", "tls", "istio", true, "True", "True", listener),
			route,
		},
		[]kruntime.Object{
			testGatewayService("app", "invoices-api", 443),
		},
	)
	report := model.NewReport("check gateway", model.Target{})

	runGatewayIntentScan(context.Background(), client, report, GatewayOptions{}, gatewayTrafficIntent{
		Protocol:      "tls",
		RouteFamilies: []string{"TLSRoute"},
		Host:          "invoices.knm.local",
		Port:          443,
	})

	t.Logf("diagnosis output:\n%s", gatewayDiagnosisLog(report))
	assertGatewayDiagnosisContains(t, report, "TLSRoute app/invoices rule 1 routes to Service app/invoices-api port 443, but that Service has no ready endpoints")
}

func TestGatewayLocalHTTPProbePreservesHostHeader(t *testing.T) {
	seenHost := ""
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		seenHost = r.Host
		w.WriteHeader(http.StatusNoContent)
	}))
	defer server.Close()
	parsed, err := url.Parse(server.URL)
	if err != nil {
		t.Fatalf("parse test server URL: %v", err)
	}
	host := parsed.Hostname()
	port, err := strconv.Atoi(parsed.Port())
	if err != nil {
		t.Fatalf("parse test server port: %v", err)
	}

	result := testGatewayLocalHTTP("http://payments.knm.local/", host, int32(port), "payments.knm.local", "GET", time.Second, map[string]string{"x-test": "true"})

	if !result.OK || result.Status != "204" {
		t.Fatalf("unexpected probe result: %#v", result)
	}
	if seenHost != "payments.knm.local" {
		t.Fatalf("host header = %q, want payments.knm.local", seenHost)
	}
}

func TestGatewayProbeDialTargetOverride(t *testing.T) {
	host, port, text, err := gatewayProbeDialTarget("172.18.0.11", 443, "127.0.0.1:61128")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if host != "127.0.0.1" || port != 61128 {
		t.Fatalf("dial target = %s:%d, want 127.0.0.1:61128", host, port)
	}
	if !strings.Contains(text, "172.18.0.11:443") || !strings.Contains(text, "127.0.0.1:61128") {
		t.Fatalf("dial text = %q, want advertised and override addresses", text)
	}
}

func TestGatewayTrafficIntentRejectsURLPartOverrides(t *testing.T) {
	_, _, err := gatewayTrafficIntentFromOptions(GatewayOptions{
		URL:  "https://payments.knm.local/api",
		Path: "/other",
	})
	if err == nil {
		t.Fatal("expected --url plus --path to be rejected")
	}
}

func TestGatewayTrafficIntentRequiresHostOrURL(t *testing.T) {
	_, _, err := gatewayTrafficIntentFromOptions(GatewayOptions{
		Path: "/api",
	})
	if err == nil {
		t.Fatal("expected path-only intent to be rejected")
	}
	_, _, err = gatewayTrafficIntentFromOptions(GatewayOptions{
		ExpectService: "app/payments-api",
	})
	if err == nil {
		t.Fatal("expected expected-service-only intent to be rejected")
	}
}

func TestGatewayTrafficIntentScanMatchesBackendPath(t *testing.T) {
	client := fakeGatewayClient(t,
		[]unstructured.Unstructured{
			testGatewayClass("istio", "True", "Accepted"),
			testGatewayForHostname("edge", "public", "istio", "web", "*.knm.local"),
			testGatewayHTTPRouteForHostname("app", "payments", "edge", "public", "payments.knm.local", []map[string]interface{}{
				{
					"matches": []interface{}{map[string]interface{}{
						"path": map[string]interface{}{"type": "PathPrefix", "value": "/api"},
					}},
					"backendRefs": []interface{}{testBackendRef("payments-api", "", int64(80))},
				},
			}),
		},
		[]kruntime.Object{
			testGatewayService("app", "payments-api", 80),
			testGatewayEndpointSlice("app", "payments-api", true, "10.0.0.10"),
		},
	)
	report := model.NewReport("check gateway", model.Target{})

	runGatewayIntentScan(context.Background(), client, report, GatewayOptions{}, gatewayTrafficIntent{
		Scheme: "http",
		Host:   "payments.knm.local",
		Port:   80,
		Path:   "/api/items",
	})

	assertResultContains(t, report, model.StatusInfo, "matches listener edge/public/web")
	assertResultContains(t, report, model.StatusPass, "matching backend path")
	if report.CountByStatus(model.StatusFail) != 0 {
		t.Fatalf("expected no failures, got %#v", report.Results)
	}
}

func TestGatewayTrafficIntentReportsRejectedMatchedRoute(t *testing.T) {
	route := testGatewayHTTPRouteForHostname("app", "payments", "edge", "public", "payments.knm.local", []map[string]interface{}{
		{"backendRefs": []interface{}{testBackendRef("payments-api", "", int64(80))}},
	})
	parents := sliceField(route.Object, "status", "parents")
	if len(parents) == 0 {
		t.Fatal("test route has no parent status")
	}
	parent := parents[0].(map[string]interface{})
	parent["conditions"] = []interface{}{
		testGatewayCondition("Accepted", "False", "UnsupportedValue", "invalid extension filter"),
		testGatewayCondition("ResolvedRefs", "True", "ResolvedRefs", ""),
	}
	if err := unstructured.SetNestedSlice(route.Object, parents, "status", "parents"); err != nil {
		t.Fatalf("set route parent status: %v", err)
	}
	client := fakeGatewayClient(t,
		[]unstructured.Unstructured{
			testGatewayClass("istio", "True", "Accepted"),
			testGatewayForHostname("edge", "public", "istio", "web", "*.knm.local"),
			route,
		},
		[]kruntime.Object{
			testGatewayService("app", "payments-api", 80),
			testGatewayEndpointSlice("app", "payments-api", true, "10.0.0.10"),
		},
	)
	report := model.NewReport("check gateway", model.Target{})

	runGatewayIntentScan(context.Background(), client, report, GatewayOptions{}, gatewayTrafficIntent{
		Scheme: "http",
		Host:   "payments.knm.local",
		Port:   80,
		Path:   "/",
	})

	assertGatewayDiagnosisContains(t, report, "HTTPRoute app/payments is not accepted by Gateway edge/public: UnsupportedValue: invalid extension filter")
	assertResultContains(t, report, model.StatusFail, "HTTPRoute app/payments is not accepted by Gateway edge/public")
}

func TestGatewayTrafficIntentExpectedServicePasses(t *testing.T) {
	client := fakeGatewayClient(t,
		[]unstructured.Unstructured{
			testGatewayClass("istio", "True", "Accepted"),
			testGatewayForHostname("edge", "public", "istio", "web", "*.knm.local"),
			testGatewayHTTPRouteForHostname("app", "payments", "edge", "public", "payments.knm.local", []map[string]interface{}{
				{"backendRefs": []interface{}{testBackendRef("payments-api", "", int64(80))}},
			}),
		},
		[]kruntime.Object{
			testGatewayService("app", "payments-api", 80),
			testGatewayEndpointSlice("app", "payments-api", true, "10.0.0.10"),
		},
	)
	report := model.NewReport("check gateway", model.Target{})

	runGatewayIntentScan(context.Background(), client, report, GatewayOptions{ExpectService: "app/payments-api"}, gatewayTrafficIntent{
		Scheme: "http",
		Host:   "payments.knm.local",
		Port:   80,
		Path:   "/",
	})

	assertResultContains(t, report, model.StatusPass, "selected expected Service app/payments-api")
	assertGatewayDiagnosisNotContains(t, report, "expected Service")
}

func TestGatewayTrafficIntentExpectedServiceMismatch(t *testing.T) {
	client := fakeGatewayClient(t,
		[]unstructured.Unstructured{
			testGatewayClass("istio", "True", "Accepted"),
			testGatewayForHostname("edge", "public", "istio", "web", "*.knm.local"),
			testGatewayHTTPRouteForHostname("app", "payments", "edge", "public", "payments.knm.local", []map[string]interface{}{
				{
					"matches":     []interface{}{map[string]interface{}{"path": map[string]interface{}{"type": "PathPrefix", "value": "/admin"}}},
					"backendRefs": []interface{}{testBackendRef("admin-api", "", int64(80))},
				},
				{
					"matches": []interface{}{map[string]interface{}{
						"path":   map[string]interface{}{"type": "PathPrefix", "value": "/api"},
						"method": "POST",
					}},
					"backendRefs": []interface{}{testBackendRef("payments-api", "", int64(80))},
				},
				{
					"matches": []interface{}{map[string]interface{}{
						"path": map[string]interface{}{"type": "PathPrefix", "value": "/api"},
						"headers": []interface{}{map[string]interface{}{
							"name":  "x-canary",
							"value": "true",
						}},
					}},
					"backendRefs": []interface{}{testBackendRef("catalog-api", "", int64(80))},
				},
				{
					"matches": []interface{}{map[string]interface{}{"path": map[string]interface{}{"type": "PathPrefix", "value": "/api"}}},
					"backendRefs": []interface{}{
						map[string]interface{}{"name": "orders-api", "port": int64(80), "weight": int64(0)},
					},
				},
			}),
		},
		[]kruntime.Object{
			testGatewayService("app", "catalog-api", 80),
			testGatewayEndpointSlice("app", "catalog-api", true, "10.0.0.10"),
		},
	)
	report := model.NewReport("check gateway", model.Target{})

	runGatewayIntentScan(context.Background(), client, report, GatewayOptions{ExpectService: "app/payments-api"}, gatewayTrafficIntent{
		Scheme: "http",
		Host:   "payments.knm.local",
		Port:   80,
		Path:   "/api/items",
		Method: "GET",
		Headers: map[string]string{
			"x-canary": "true",
		},
	})

	t.Logf("diagnosis output:\n%s", gatewayDiagnosisLog(report))
	assertGatewayDiagnosisContains(t, report, "This Gateway request routes to Service app/catalog-api, not expected Service app/payments-api. Selected route: app/payments rule 3.")
}

func TestGatewayTrafficIntentExpectedServiceMatchesWeightedBackend(t *testing.T) {
	client := fakeGatewayClient(t,
		[]unstructured.Unstructured{
			testGatewayClass("istio", "True", "Accepted"),
			testGatewayForHostname("edge", "public", "istio", "web", "*.knm.local"),
			testGatewayHTTPRouteForHostname("app", "payments", "edge", "public", "payments.knm.local", []map[string]interface{}{
				{
					"backendRefs": []interface{}{
						map[string]interface{}{"name": "catalog-api", "port": int64(80), "weight": int64(50)},
						map[string]interface{}{"name": "payments-api", "port": int64(80), "weight": int64(50)},
					},
				},
			}),
		},
		[]kruntime.Object{
			testGatewayService("app", "catalog-api", 80),
			testGatewayEndpointSlice("app", "catalog-api", true, "10.0.0.10"),
			testGatewayService("app", "payments-api", 80),
			testGatewayEndpointSlice("app", "payments-api", true, "10.0.0.11"),
		},
	)
	report := model.NewReport("check gateway", model.Target{})

	runGatewayIntentScan(context.Background(), client, report, GatewayOptions{ExpectService: "app/payments-api"}, gatewayTrafficIntent{
		Scheme: "http",
		Host:   "payments.knm.local",
		Port:   80,
		Path:   "/",
	})

	assertResultContains(t, report, model.StatusPass, "selected expected Service app/payments-api")
	assertGatewayDiagnosisNotContains(t, report, "but expected Service")
}

func TestGatewayTrafficIntentScanReportsMatchedBackendProblem(t *testing.T) {
	client := fakeGatewayClient(t,
		[]unstructured.Unstructured{
			testGatewayClass("istio", "True", "Accepted"),
			testGatewayForHostname("edge", "public", "istio", "web", "*.knm.local"),
			testGatewayHTTPRouteForHostname("app", "payments", "edge", "public", "payments.knm.local", []map[string]interface{}{
				{
					"matches":     []interface{}{map[string]interface{}{"path": map[string]interface{}{"type": "PathPrefix", "value": "/admin"}}},
					"backendRefs": []interface{}{testBackendRef("admin-api", "", int64(80))},
				},
				{
					"matches": []interface{}{map[string]interface{}{
						"path":   map[string]interface{}{"type": "PathPrefix", "value": "/api"},
						"method": "POST",
					}},
					"backendRefs": []interface{}{testBackendRef("orders-api", "", int64(80))},
				},
				{
					"matches": []interface{}{map[string]interface{}{
						"path": map[string]interface{}{"type": "PathPrefix", "value": "/api"},
						"headers": []interface{}{map[string]interface{}{
							"name":  "x-tenant",
							"value": "gold",
						}},
					}},
					"backendRefs": []interface{}{testBackendRef("payments-api", "", int64(80))},
				},
				{
					"matches": []interface{}{map[string]interface{}{"path": map[string]interface{}{"type": "PathPrefix", "value": "/api"}}},
					"backendRefs": []interface{}{
						map[string]interface{}{"name": "catalog-api", "port": int64(80), "weight": int64(0)},
					},
				},
			}),
		},
		nil,
	)
	report := model.NewReport("check gateway", model.Target{})

	runGatewayIntentScan(context.Background(), client, report, GatewayOptions{}, gatewayTrafficIntent{
		Scheme: "http",
		Host:   "payments.knm.local",
		Port:   80,
		Path:   "/api/items",
		Method: "GET",
		Headers: map[string]string{
			"x-tenant": "gold",
		},
	})

	t.Logf("diagnosis output:\n%s", gatewayDiagnosisLog(report))
	assertGatewayDiagnosisContains(t, report, "HTTPRoute app/payments rule 3 routes to Service app/payments-api, but that Service is missing or unreadable")
	assertGatewayDiagnosisNotContains(t, report, "rule 1 routes to Service app/payments-api")
}

func TestGatewayTrafficIntentScanReportsMixedWeightedBackends(t *testing.T) {
	client := fakeGatewayClient(t,
		[]unstructured.Unstructured{
			testGatewayClass("istio", "True", "Accepted"),
			testGatewayForHostname("edge", "public", "istio", "web", "*.knm.local"),
			testGatewayHTTPRouteForHostname("app", "payments", "edge", "public", "payments.knm.local", []map[string]interface{}{
				{
					"matches":     []interface{}{map[string]interface{}{"path": map[string]interface{}{"type": "PathPrefix", "value": "/admin"}}},
					"backendRefs": []interface{}{testBackendRef("admin-api", "", int64(80))},
				},
				{
					"matches": []interface{}{map[string]interface{}{
						"path":   map[string]interface{}{"type": "PathPrefix", "value": "/checkout"},
						"method": "POST",
					}},
					"backendRefs": []interface{}{testBackendRef("orders-api", "", int64(80))},
				},
				{
					"matches": []interface{}{map[string]interface{}{
						"path": map[string]interface{}{"type": "PathPrefix", "value": "/checkout"},
						"headers": []interface{}{map[string]interface{}{
							"name":  "x-split",
							"value": "dense",
						}},
					}},
					"backendRefs": []interface{}{
						map[string]interface{}{"name": "catalog-api", "port": int64(80), "weight": int64(2)},
						map[string]interface{}{"name": "payments-api", "port": int64(80), "weight": int64(1)},
						map[string]interface{}{"name": "orders-api", "port": int64(9999), "weight": int64(1)},
						map[string]interface{}{"name": "archive-api", "port": int64(80), "weight": int64(0)},
					},
				},
				{
					"matches": []interface{}{map[string]interface{}{
						"path":   map[string]interface{}{"type": "PathPrefix", "value": "/checkout"},
						"method": "POST",
					}},
					"backendRefs": []interface{}{testBackendRef("fallback-api", "", int64(80))},
				},
			}),
		},
		[]kruntime.Object{
			testGatewayService("app", "catalog-api", 80),
			testGatewayEndpointSlice("app", "catalog-api", true, "10.0.0.10"),
			testGatewayService("app", "orders-api", 80),
		},
	)
	report := model.NewReport("check gateway", model.Target{})

	runGatewayIntentScan(context.Background(), client, report, GatewayOptions{}, gatewayTrafficIntent{
		Scheme: "http",
		Host:   "payments.knm.local",
		Port:   80,
		Path:   "/checkout/pay",
		Method: "GET",
		Headers: map[string]string{
			"x-split": "dense",
		},
	})

	assertResultContains(t, report, model.StatusWarn, "splits this request across weighted backendRefs")
	t.Logf("diagnosis output:\n%s", gatewayDiagnosisLog(report))
	assertGatewayDiagnosisContains(t, report, "HTTPRoute app/payments rule 3 splits this request across weighted backendRefs; broken backends: app/payments-api:80 weight 1 (25%) (missing Service); app/orders-api:9999 weight 1 (25%) (Service exposes 80->80/ name=http).")
	assertGatewayDiagnosisNotContains(t, report, "but that Service is missing or unreadable")
	assertGatewayDiagnosisNotContains(t, report, "archive-api")
}

func TestGatewayTrafficIntentReportsRedirectRule(t *testing.T) {
	client := fakeGatewayClient(t,
		[]unstructured.Unstructured{
			testGatewayClass("istio", "True", "Accepted"),
			testGatewayForHostname("edge", "public", "istio", "web", "*.knm.local"),
			testGatewayHTTPRouteForHostname("app", "payments", "edge", "public", "payments.knm.local", []map[string]interface{}{
				{
					"matches":     []interface{}{map[string]interface{}{"path": map[string]interface{}{"type": "PathPrefix", "value": "/admin"}}},
					"backendRefs": []interface{}{testBackendRef("admin-api", "", int64(80))},
				},
				{
					"matches": []interface{}{map[string]interface{}{
						"path":   map[string]interface{}{"type": "PathPrefix", "value": "/old"},
						"method": "POST",
					}},
					"backendRefs": []interface{}{testBackendRef("payments-api", "", int64(80))},
				},
				{
					"matches": []interface{}{map[string]interface{}{
						"path": map[string]interface{}{"type": "PathPrefix", "value": "/old"},
						"headers": []interface{}{map[string]interface{}{
							"name":  "x-legacy",
							"value": "true",
						}},
					}},
					"filters": []interface{}{map[string]interface{}{
						"type":            "RequestRedirect",
						"requestRedirect": map[string]interface{}{"path": map[string]interface{}{"type": "ReplaceFullPath", "replaceFullPath": "/new"}},
					}},
				},
				{
					"matches": []interface{}{map[string]interface{}{"path": map[string]interface{}{"type": "PathPrefix", "value": "/old"}}},
					"backendRefs": []interface{}{
						map[string]interface{}{"name": "catalog-api", "port": int64(80), "weight": int64(0)},
					},
				},
				{
					"matches":     []interface{}{map[string]interface{}{"path": map[string]interface{}{"type": "PathPrefix", "value": "/archive"}}},
					"backendRefs": []interface{}{testBackendRef("archive-api", "", int64(80))},
				},
			}),
		},
		nil,
	)
	report := model.NewReport("check gateway", model.Target{})

	runGatewayIntentScan(context.Background(), client, report, GatewayOptions{}, gatewayTrafficIntent{
		Scheme: "http",
		Host:   "payments.knm.local",
		Port:   80,
		Path:   "/old",
		Method: "GET",
		Headers: map[string]string{
			"x-legacy": "true",
		},
	})

	t.Logf("diagnosis output:\n%s", gatewayDiagnosisLog(report))
	assertResultContains(t, report, model.StatusInfo, "app/payments rule 3 applies filter(s): RequestRedirect")
	assertGatewayDiagnosisContains(t, report, "HTTPRoute app/payments rule 3 redirects this request instead of routing to backendRefs.")
	assertGatewayDiagnosisNotContains(t, report, "rule 1 redirects")
}

func TestGatewayTrafficIntentReportsMultipleMatchingRulesAndFilters(t *testing.T) {
	client := fakeGatewayClient(t,
		[]unstructured.Unstructured{
			testGatewayClass("istio", "True", "Accepted"),
			testGatewayForHostname("edge", "public", "istio", "web", "*.knm.local"),
			testGatewayHTTPRouteForHostname("app", "payments", "edge", "public", "payments.knm.local", []map[string]interface{}{
				{
					"backendRefs": []interface{}{testBackendRef("payments-api", "", int64(80))},
					"filters":     []interface{}{map[string]interface{}{"type": "URLRewrite"}},
				},
			}),
			testGatewayHTTPRouteForHostname("app", "catalog", "edge", "public", "payments.knm.local", []map[string]interface{}{
				{"backendRefs": []interface{}{testBackendRef("catalog-api", "", int64(80))}},
			}),
		},
		[]kruntime.Object{
			testGatewayService("app", "payments-api", 80),
			testGatewayEndpointSlice("app", "payments-api", true, "10.0.0.10"),
			testGatewayService("app", "catalog-api", 80),
			testGatewayEndpointSlice("app", "catalog-api", true, "10.0.0.11"),
		},
	)
	report := model.NewReport("check gateway", model.Target{})

	runGatewayIntentScan(context.Background(), client, report, GatewayOptions{}, gatewayTrafficIntent{
		Scheme: "http",
		Host:   "payments.knm.local",
		Port:   80,
		Path:   "/",
	})

	assertResultContains(t, report, model.StatusInfo, "Request matches multiple HTTPRoute rules: app/catalog rule 1, app/payments rule 1.")
	assertResultContains(t, report, model.StatusInfo, "HTTPRoute app/payments rule 1 applies filter(s): URLRewrite.")
}

func TestGatewayTrafficIntentReportsSelectedURLRewriteRule(t *testing.T) {
	client := fakeGatewayClient(t,
		[]unstructured.Unstructured{
			testGatewayClass("istio", "True", "Accepted"),
			testGatewayForHostname("edge", "public", "istio", "web", "*.knm.local"),
			testGatewayHTTPRouteForHostname("app", "payments", "edge", "public", "payments.knm.local", []map[string]interface{}{
				{
					"matches":     []interface{}{map[string]interface{}{"path": map[string]interface{}{"type": "PathPrefix", "value": "/api"}}},
					"backendRefs": []interface{}{testBackendRef("legacy-api", "", int64(80))},
				},
				{
					"matches":     []interface{}{map[string]interface{}{"path": map[string]interface{}{"type": "Exact", "value": "/api/items"}, "method": "POST"}},
					"backendRefs": []interface{}{testBackendRef("archive-api", "", int64(80))},
				},
				{
					"matches": []interface{}{map[string]interface{}{"path": map[string]interface{}{"type": "Exact", "value": "/api/items"}}},
					"filters": []interface{}{map[string]interface{}{
						"type": "URLRewrite",
						"urlRewrite": map[string]interface{}{
							"path": map[string]interface{}{"type": "ReplaceFullPath", "replaceFullPath": "/v2/items"},
						},
					}},
					"backendRefs": []interface{}{testBackendRef("payments-api", "", int64(80))},
				},
			}),
		},
		[]kruntime.Object{
			testGatewayService("app", "payments-api", 80),
			testGatewayEndpointSlice("app", "payments-api", true, "10.0.0.10"),
		},
	)
	report := model.NewReport("check gateway", model.Target{})

	runGatewayIntentScan(context.Background(), client, report, GatewayOptions{ExpectService: "app/payments-api"}, gatewayTrafficIntent{
		Scheme: "http",
		Host:   "payments.knm.local",
		Port:   80,
		Path:   "/api/items",
		Method: "GET",
	})

	t.Logf("diagnosis output:\n%s", gatewayDiagnosisLog(report))
	assertResultContains(t, report, model.StatusInfo, `HTTPRoute app/payments rule 3 rewrites path from "/api/items" to "/v2/items".`)
	assertResultContains(t, report, model.StatusPass, "selected expected Service app/payments-api")
	assertGatewayDiagnosisNotContains(t, report, "legacy-api")
}

func TestGatewayTrafficIntentReportsBrokenRequestMirrorSeparately(t *testing.T) {
	client := fakeGatewayClient(t,
		[]unstructured.Unstructured{
			testGatewayClass("istio", "True", "Accepted"),
			testGatewayForHostname("edge", "public", "istio", "web", "*.knm.local"),
			testGatewayHTTPRouteForHostname("app", "payments", "edge", "public", "payments.knm.local", []map[string]interface{}{
				{
					"matches":     []interface{}{map[string]interface{}{"path": map[string]interface{}{"type": "PathPrefix", "value": "/api"}}},
					"backendRefs": []interface{}{testBackendRef("legacy-api", "", int64(80))},
				},
				{
					"matches":     []interface{}{map[string]interface{}{"path": map[string]interface{}{"type": "Exact", "value": "/api/items"}, "headers": []interface{}{map[string]interface{}{"name": "x-test", "value": "other"}}}},
					"backendRefs": []interface{}{testBackendRef("archive-api", "", int64(80))},
				},
				{
					"matches": []interface{}{map[string]interface{}{"path": map[string]interface{}{"type": "Exact", "value": "/api/items"}}},
					"filters": []interface{}{map[string]interface{}{
						"type": "RequestMirror",
						"requestMirror": map[string]interface{}{
							"backendRef": map[string]interface{}{"name": "shadow-api", "port": int64(80)},
						},
					}},
					"backendRefs": []interface{}{testBackendRef("payments-api", "", int64(80))},
				},
			}),
		},
		[]kruntime.Object{
			testGatewayService("app", "payments-api", 80),
			testGatewayEndpointSlice("app", "payments-api", true, "10.0.0.10"),
		},
	)
	report := model.NewReport("check gateway", model.Target{})

	runGatewayIntentScan(context.Background(), client, report, GatewayOptions{ExpectService: "app/payments-api"}, gatewayTrafficIntent{
		Scheme: "http",
		Host:   "payments.knm.local",
		Port:   80,
		Path:   "/api/items",
		Method: "GET",
	})

	t.Logf("diagnosis output:\n%s", gatewayDiagnosisLog(report))
	assertResultContains(t, report, model.StatusWarn, "mirrors this request to app/shadow-api:80, but the mirror backend is broken: missing Service")
	assertGatewayDiagnosisContains(t, report, "HTTPRoute app/payments rule 3 mirrors this request to app/shadow-api:80, but the mirror backend is broken: missing Service.")
	assertResultContains(t, report, model.StatusPass, "selected expected Service app/payments-api")
	assertGatewayDiagnosisNotContains(t, report, "legacy-api")
}

func TestGatewayTrafficIntentReportsUnsupportedBackendKind(t *testing.T) {
	client := fakeGatewayClient(t,
		[]unstructured.Unstructured{
			testGatewayClass("istio", "True", "Accepted"),
			testGatewayForHostname("edge", "public", "istio", "web", "*.knm.local"),
			testGatewayHTTPRouteForHostname("app", "payments", "edge", "public", "payments.knm.local", []map[string]interface{}{
				{
					"matches":     []interface{}{map[string]interface{}{"path": map[string]interface{}{"type": "PathPrefix", "value": "/api"}}},
					"backendRefs": []interface{}{testBackendRef("legacy-api", "", int64(80))},
				},
				{
					"matches": []interface{}{map[string]interface{}{"path": map[string]interface{}{"type": "Exact", "value": "/api/items"}}},
					"backendRefs": []interface{}{map[string]interface{}{
						"group": "storage.example.io",
						"kind":  "Bucket",
						"name":  "payments-shadow",
						"port":  int64(80),
					}},
				},
				{
					"matches":     []interface{}{map[string]interface{}{"path": map[string]interface{}{"type": "PathPrefix", "value": "/"}}},
					"backendRefs": []interface{}{testBackendRef("payments-api", "", int64(80))},
				},
			}),
		},
		[]kruntime.Object{
			testGatewayService("app", "payments-api", 80),
			testGatewayEndpointSlice("app", "payments-api", true, "10.0.0.10"),
		},
	)
	report := model.NewReport("check gateway", model.Target{})

	runGatewayIntentScan(context.Background(), client, report, GatewayOptions{}, gatewayTrafficIntent{
		Scheme: "http",
		Host:   "payments.knm.local",
		Port:   80,
		Path:   "/api/items",
	})

	t.Logf("diagnosis output:\n%s", gatewayDiagnosisLog(report))
	assertResultContains(t, report, model.StatusWarn, "HTTPRoute app/payments rule 2 routes to backend kind storage.example.io/Bucket app/payments-shadow; KNM does not evaluate that backend type.")
	assertGatewayDiagnosisContains(t, report, "HTTPRoute app/payments rule 2 routes to backend kind storage.example.io/Bucket app/payments-shadow; KNM does not evaluate that backend type.")
	assertResultContains(t, report, model.StatusInfo, "app/payments rule 2 (exact path match)")
	assertGatewayDiagnosisNotContains(t, report, "legacy-api")
	assertResultNotContains(t, report, model.StatusPass, "no obvious backend reference or endpoint problems")
}

func TestGatewayTrafficIntentPrecedenceExactPathShadowsPrefixProblem(t *testing.T) {
	client := fakeGatewayClient(t,
		[]unstructured.Unstructured{
			testGatewayClass("istio", "True", "Accepted"),
			testGatewayForHostname("edge", "public", "istio", "web", "*.knm.local"),
			testGatewayHTTPRouteForHostname("app", "payments", "edge", "public", "payments.knm.local", []map[string]interface{}{
				{
					"matches":     []interface{}{map[string]interface{}{"path": map[string]interface{}{"type": "PathPrefix", "value": "/api"}}},
					"backendRefs": []interface{}{testBackendRef("payments-api", "", int64(80))},
				},
				{
					"matches":     []interface{}{map[string]interface{}{"path": map[string]interface{}{"type": "Exact", "value": "/api/items"}}},
					"backendRefs": []interface{}{testBackendRef("catalog-api", "", int64(80))},
				},
			}),
		},
		[]kruntime.Object{
			testGatewayService("app", "catalog-api", 80),
			testGatewayEndpointSlice("app", "catalog-api", true, "10.0.0.10"),
		},
	)
	report := model.NewReport("check gateway", model.Target{})

	runGatewayIntentScan(context.Background(), client, report, GatewayOptions{ExpectService: "app/catalog-api"}, gatewayTrafficIntent{
		Scheme: "http",
		Host:   "payments.knm.local",
		Port:   80,
		Path:   "/api/items",
	})

	assertResultContains(t, report, model.StatusInfo, "app/payments rule 2 (exact path match)")
	assertResultContains(t, report, model.StatusPass, "selected expected Service app/catalog-api")
	assertGatewayDiagnosisNotContains(t, report, "payments-api")
}

func TestGatewayTrafficIntentPrecedenceExactHostnameShadowsWildcardProblem(t *testing.T) {
	wildcard := testGatewayHTTPRouteForHostname("app", "wildcard", "edge", "public", "*.knm.local", []map[string]interface{}{
		{
			"matches":     []interface{}{map[string]interface{}{"path": map[string]interface{}{"type": "Exact", "value": "/api/items"}}},
			"backendRefs": []interface{}{testBackendRef("payments-api", "", int64(80))},
		},
	})
	exact := testGatewayHTTPRouteForHostname("app", "payments", "edge", "public", "payments.knm.local", []map[string]interface{}{
		{
			"matches":     []interface{}{map[string]interface{}{"path": map[string]interface{}{"type": "PathPrefix", "value": "/"}}},
			"backendRefs": []interface{}{testBackendRef("catalog-api", "", int64(80))},
		},
	})
	client := fakeGatewayClient(t,
		[]unstructured.Unstructured{
			testGatewayClass("istio", "True", "Accepted"),
			testGatewayForHostname("edge", "public", "istio", "web", "*.knm.local"),
			wildcard,
			exact,
		},
		[]kruntime.Object{
			testGatewayService("app", "catalog-api", 80),
			testGatewayEndpointSlice("app", "catalog-api", true, "10.0.0.10"),
		},
	)
	report := model.NewReport("check gateway", model.Target{})

	runGatewayIntentScan(context.Background(), client, report, GatewayOptions{ExpectService: "app/catalog-api"}, gatewayTrafficIntent{
		Scheme: "http",
		Host:   "payments.knm.local",
		Port:   80,
		Path:   "/api/items",
	})

	assertResultContains(t, report, model.StatusInfo, "app/payments rule 1 (more specific hostname)")
	assertResultContains(t, report, model.StatusPass, "selected expected Service app/catalog-api")
	assertGatewayDiagnosisNotContains(t, report, "payments-api")
}

func TestGatewayTrafficIntentPrecedenceOldestRouteWinsTie(t *testing.T) {
	newer := testGatewayHTTPRouteForHostname("app", "a-new", "edge", "public", "payments.knm.local", []map[string]interface{}{
		{"backendRefs": []interface{}{testBackendRef("payments-api", "", int64(80))}},
	})
	newer.SetCreationTimestamp(metav1.Time{Time: time.Date(2026, 6, 8, 2, 0, 0, 0, time.UTC)})
	older := testGatewayHTTPRouteForHostname("app", "z-old", "edge", "public", "payments.knm.local", []map[string]interface{}{
		{"backendRefs": []interface{}{testBackendRef("catalog-api", "", int64(80))}},
	})
	older.SetCreationTimestamp(metav1.Time{Time: time.Date(2026, 6, 8, 1, 0, 0, 0, time.UTC)})
	client := fakeGatewayClient(t,
		[]unstructured.Unstructured{
			testGatewayClass("istio", "True", "Accepted"),
			testGatewayForHostname("edge", "public", "istio", "web", "*.knm.local"),
			newer,
			older,
		},
		[]kruntime.Object{
			testGatewayService("app", "catalog-api", 80),
			testGatewayEndpointSlice("app", "catalog-api", true, "10.0.0.10"),
		},
	)
	report := model.NewReport("check gateway", model.Target{})

	runGatewayIntentScan(context.Background(), client, report, GatewayOptions{ExpectService: "app/catalog-api"}, gatewayTrafficIntent{
		Scheme: "http",
		Host:   "payments.knm.local",
		Port:   80,
		Path:   "/",
	})

	assertResultContains(t, report, model.StatusInfo, "app/z-old rule 1 (older HTTPRoute creation timestamp)")
	assertResultContains(t, report, model.StatusPass, "selected expected Service app/catalog-api")
	assertGatewayDiagnosisNotContains(t, report, "payments-api")
}

func TestGatewayTrafficIntentPrecedenceFirstRuleWinsSameRouteTie(t *testing.T) {
	client := fakeGatewayClient(t,
		[]unstructured.Unstructured{
			testGatewayClass("istio", "True", "Accepted"),
			testGatewayForHostname("edge", "public", "istio", "web", "*.knm.local"),
			testGatewayHTTPRouteForHostname("app", "payments", "edge", "public", "payments.knm.local", []map[string]interface{}{
				{"backendRefs": []interface{}{testBackendRef("catalog-api", "", int64(80))}},
				{"backendRefs": []interface{}{testBackendRef("payments-api", "", int64(80))}},
			}),
		},
		[]kruntime.Object{
			testGatewayService("app", "catalog-api", 80),
			testGatewayEndpointSlice("app", "catalog-api", true, "10.0.0.10"),
		},
	)
	report := model.NewReport("check gateway", model.Target{})

	runGatewayIntentScan(context.Background(), client, report, GatewayOptions{ExpectService: "app/catalog-api"}, gatewayTrafficIntent{
		Scheme: "http",
		Host:   "payments.knm.local",
		Port:   80,
		Path:   "/",
	})

	assertResultContains(t, report, model.StatusInfo, "app/payments rule 1 (first matching rule in the HTTPRoute)")
	assertResultContains(t, report, model.StatusPass, "selected expected Service app/catalog-api")
	assertGatewayDiagnosisNotContains(t, report, "payments-api")
}

func TestGatewayTrafficIntentIgnoresZeroWeightBrokenBackend(t *testing.T) {
	client := fakeGatewayClient(t,
		[]unstructured.Unstructured{
			testGatewayClass("istio", "True", "Accepted"),
			testGatewayForHostname("edge", "public", "istio", "web", "*.knm.local"),
			testGatewayHTTPRouteForHostname("app", "payments", "edge", "public", "payments.knm.local", []map[string]interface{}{
				{
					"backendRefs": []interface{}{
						map[string]interface{}{"name": "catalog-api", "port": int64(80), "weight": int64(100)},
						map[string]interface{}{"name": "payments-api", "port": int64(80), "weight": int64(0)},
					},
				},
			}),
		},
		[]kruntime.Object{
			testGatewayService("app", "catalog-api", 80),
			testGatewayEndpointSlice("app", "catalog-api", true, "10.0.0.10"),
		},
	)
	report := model.NewReport("check gateway", model.Target{})

	runGatewayIntentScan(context.Background(), client, report, GatewayOptions{}, gatewayTrafficIntent{
		Scheme: "http",
		Host:   "payments.knm.local",
		Port:   80,
		Path:   "/",
	})

	assertResultContains(t, report, model.StatusPass, "1 matching backend path")
	assertGatewayDiagnosisNotContains(t, report, "payments-api")
	if report.CountByStatus(model.StatusFail) != 0 {
		t.Fatalf("expected no failures for inactive backendRef, got %#v", report.Results)
	}
}

func TestGatewayBackendWeightTextNormalizesNonHundredTotals(t *testing.T) {
	tests := []struct {
		name   string
		weight int64
		total  int64
		want   string
	}{
		{name: "hundred total stays literal", weight: 25, total: 100, want: "weight 25"},
		{name: "quarter from four", weight: 1, total: 4, want: "weight 1 (25%)"},
		{name: "third rounds to one decimal", weight: 1, total: 3, want: "weight 1 (33.3%)"},
		{name: "zero total stays literal", weight: 1, total: 0, want: "weight 1"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := gatewayBackendWeightText(tt.weight, tt.total); got != tt.want {
				t.Fatalf("gatewayBackendWeightText(%d, %d) = %q, want %q", tt.weight, tt.total, got, tt.want)
			}
		})
	}
}

func TestGatewayCheckServiceFollowupCommand(t *testing.T) {
	command, ok := gatewayCheckServiceFollowupCommand([]gatewayPathMatch{{
		RouteKind:        "HTTPRoute",
		BackendNamespace: "microservices",
		BackendName:      "gateway-service",
		BackendPort:      3000,
	}}, &corev1.Service{ObjectMeta: metav1.ObjectMeta{Namespace: "istio-ingress", Name: "microservices-gateway-istio"}}, gatewayTrafficIntent{Path: "/users"})

	if !ok {
		t.Fatalf("expected follow-up command")
	}
	want := "knm check service -n microservices -t gateway-service --source-namespace istio-ingress -s microservices-gateway-istio --port 3000 --path /users"
	if command != want {
		t.Fatalf("unexpected command:\nwant: %s\n got: %s", want, command)
	}
}

func TestGatewayCheckServiceFollowupCommandSuppressesAmbiguousBackends(t *testing.T) {
	_, ok := gatewayCheckServiceFollowupCommand([]gatewayPathMatch{
		{RouteKind: "HTTPRoute", BackendNamespace: "app", BackendName: "catalog-api", BackendPort: 80},
		{RouteKind: "HTTPRoute", BackendNamespace: "app", BackendName: "orders-api", BackendPort: 80},
	}, &corev1.Service{ObjectMeta: metav1.ObjectMeta{Namespace: "edge", Name: "public-istio"}}, gatewayTrafficIntent{Path: "/"})

	if ok {
		t.Fatalf("expected ambiguous backends to suppress follow-up command")
	}
}

func TestGatewayCheckServiceFollowupCommandSuppressesNonHTTPRoute(t *testing.T) {
	_, ok := gatewayCheckServiceFollowupCommand([]gatewayPathMatch{{
		RouteKind:        "TLSRoute",
		BackendNamespace: "app",
		BackendName:      "secure-api",
		BackendPort:      443,
	}}, &corev1.Service{ObjectMeta: metav1.ObjectMeta{Namespace: "edge", Name: "secure-istio"}}, gatewayTrafficIntent{})

	if ok {
		t.Fatalf("expected non-HTTP routes to suppress follow-up command")
	}
}

func TestGatewayFindDestinationRuleMatchesWildcardHost(t *testing.T) {
	service := &corev1.Service{ObjectMeta: metav1.ObjectMeta{Namespace: "microservices", Name: "gateway-service"}}
	dr := &networkingv1.DestinationRule{
		ObjectMeta: metav1.ObjectMeta{Namespace: "istio-system", Name: "default"},
		Spec: networkingapi.DestinationRule{
			Host: "*.local",
			TrafficPolicy: &networkingapi.TrafficPolicy{
				Tls: &networkingapi.ClientTLSSettings{Mode: networkingapi.ClientTLSSettings_ISTIO_MUTUAL},
			},
		},
	}

	got, ok := gatewayFindDestinationRule([]*networkingv1.DestinationRule{dr}, service)

	if !ok {
		t.Fatalf("expected wildcard DestinationRule to match service FQDN")
	}
	if got.Namespace != "istio-system" || got.Name != "default" {
		t.Fatalf("unexpected DestinationRule: %s/%s", got.Namespace, got.Name)
	}
}

func TestInspectGatewayIstioBackendTLSMismatchReportsUnmeshedBackend(t *testing.T) {
	service := testGatewayService("microservices", "gateway-service", 3000)
	service.(*corev1.Service).Spec.Selector = map[string]string{"app": "gateway"}
	pod := &corev1.Pod{
		ObjectMeta: metav1.ObjectMeta{Namespace: "microservices", Name: "gateway-abc", Labels: map[string]string{"app": "gateway"}},
		Spec:       corev1.PodSpec{Containers: []corev1.Container{{Name: "app"}}},
		Status: corev1.PodStatus{
			Phase: corev1.PodRunning,
			Conditions: []corev1.PodCondition{{
				Type:   corev1.PodReady,
				Status: corev1.ConditionTrue,
			}},
		},
	}
	meshConfig := &corev1.ConfigMap{
		ObjectMeta: metav1.ObjectMeta{Namespace: "istio-system", Name: "istio"},
		Data:       map[string]string{"mesh": "rootNamespace: istio-system\n"},
	}
	dr := &networkingv1.DestinationRule{
		ObjectMeta: metav1.ObjectMeta{Namespace: "istio-system", Name: "default"},
		Spec: networkingapi.DestinationRule{
			Host: "*.local",
			TrafficPolicy: &networkingapi.TrafficPolicy{
				Tls: &networkingapi.ClientTLSSettings{Mode: networkingapi.ClientTLSSettings_ISTIO_MUTUAL},
			},
		},
	}
	client := &kube.Client{
		Core:  k8sfake.NewSimpleClientset(service, pod, meshConfig),
		Istio: istiofake.NewSimpleClientset(dr),
	}
	report := model.NewReport("check gateway", model.Target{})

	ok := inspectGatewayIstioBackendTLSMismatch(context.Background(), client, report, []gatewayPathMatch{{
		RouteKind:        "HTTPRoute",
		BackendNamespace: "microservices",
		BackendName:      "gateway-service",
		BackendPort:      3000,
	}}, &corev1.Service{ObjectMeta: metav1.ObjectMeta{Namespace: "istio-ingress", Name: "microservices-gateway-istio"}}, "503")

	if !ok {
		t.Fatal("expected Istio Gateway backend TLS mismatch")
	}
	assertGatewayDiagnosisContains(t, report, "Istio DestinationRule \"istio-system/default\" configures ISTIO_MUTUAL TLS for Gateway backend Service \"microservices/gateway-service\"")
	assertResult(t, report, "Gateway Istio Layer", "istio-system/default", model.StatusFail)
}

func TestGatewayBroadScanIgnoresZeroWeightBrokenBackend(t *testing.T) {
	client := fakeGatewayClient(t,
		[]unstructured.Unstructured{
			testGatewayClass("istio", "True", "Accepted"),
			testGateway("edge", "public", "istio", true, "True", "True", testGatewayListener("http", nil)),
			testGatewayHTTPRoute("app", "payments", "edge", "public", []map[string]interface{}{
				{"name": "payments-api", "port": int64(80), "weight": int64(0)},
			}, "True", "True"),
		},
		nil,
	)
	report := model.NewReport("check gateway", model.Target{})

	runGatewayStaticScan(context.Background(), client, report, GatewayOptions{})

	assertGatewayDiagnosisNotContains(t, report, "payments-api")
	if report.CountByStatus(model.StatusFail) != 0 {
		t.Fatalf("expected no failures for inactive backendRef, got %#v", report.Results)
	}
}

func TestGatewayTrafficIntentScanReportsNoMatch(t *testing.T) {
	client := fakeGatewayClient(t,
		[]unstructured.Unstructured{
			testGatewayClass("istio", "True", "Accepted"),
			testGatewayForHostname("edge", "public", "istio", "web", "*.knm.local"),
			testGatewayHTTPRouteForHostname("app", "payments", "edge", "public", "payments.knm.local", []map[string]interface{}{
				{"backendRefs": []interface{}{testBackendRef("payments-api", "", int64(80))}},
			}),
		},
		[]kruntime.Object{
			testGatewayService("app", "payments-api", 80),
			testGatewayEndpointSlice("app", "payments-api", true, "10.0.0.10"),
		},
	)
	report := model.NewReport("check gateway", model.Target{})

	runGatewayIntentScan(context.Background(), client, report, GatewayOptions{}, gatewayTrafficIntent{
		Scheme: "http",
		Host:   "orders.knm.local",
		Port:   80,
		Path:   "/",
	})

	assertGatewayDiagnosisContains(t, report, "no attached HTTPRoute has a hostname matching \"orders.knm.local\"")
}

func TestGatewayTrafficIntentNoMatchExplainsDeepestMiss(t *testing.T) {
	tests := []struct {
		name    string
		intent  gatewayTrafficIntent
		rules   []map[string]interface{}
		want    string
		routeOK bool
	}{
		{
			name:   "listener host",
			intent: gatewayTrafficIntent{Scheme: "http", Host: "orders.other.local", Port: 80, Path: "/"},
			rules:  []map[string]interface{}{{"backendRefs": []interface{}{testBackendRef("payments-api", "", int64(80))}}},
			want:   "No Gateway listener matched",
		},
		{
			name:   "route hostname",
			intent: gatewayTrafficIntent{Scheme: "http", Host: "orders.knm.local", Port: 80, Path: "/"},
			rules:  []map[string]interface{}{{"backendRefs": []interface{}{testBackendRef("payments-api", "", int64(80))}}},
			want:   "no attached HTTPRoute has a hostname matching \"orders.knm.local\"",
		},
		{
			name:   "path",
			intent: gatewayTrafficIntent{Scheme: "http", Host: "payments.knm.local", Port: 80, Path: "/admin"},
			rules: []map[string]interface{}{{
				"matches":     []interface{}{map[string]interface{}{"path": map[string]interface{}{"type": "PathPrefix", "value": "/api"}}},
				"backendRefs": []interface{}{testBackendRef("payments-api", "", int64(80))},
			}},
			want: "no rule matched path \"/admin\"",
		},
		{
			name:   "method",
			intent: gatewayTrafficIntent{Scheme: "http", Host: "payments.knm.local", Port: 80, Path: "/api", Method: "POST"},
			rules: []map[string]interface{}{{
				"matches":     []interface{}{map[string]interface{}{"path": map[string]interface{}{"type": "PathPrefix", "value": "/api"}, "method": "GET"}},
				"backendRefs": []interface{}{testBackendRef("payments-api", "", int64(80))},
			}},
			want: "no rule matched method \"POST\"",
		},
		{
			name:   "header",
			intent: gatewayTrafficIntent{Scheme: "http", Host: "payments.knm.local", Port: 80, Path: "/api", Method: "GET", Headers: map[string]string{"x-canary": "false"}},
			rules: []map[string]interface{}{{
				"matches": []interface{}{map[string]interface{}{
					"path":    map[string]interface{}{"type": "PathPrefix", "value": "/api"},
					"method":  "GET",
					"headers": []interface{}{map[string]interface{}{"name": "x-canary", "value": "true"}},
				}},
				"backendRefs": []interface{}{testBackendRef("payments-api", "", int64(80))},
			}},
			want: "request headers did not satisfy any matching rule",
		},
		{
			name:   "query",
			intent: gatewayTrafficIntent{Scheme: "http", Host: "payments.knm.local", Port: 80, Path: "/api", Method: "GET", Headers: map[string]string{"x-canary": "true"}, Query: map[string][]string{"version": {"v2"}}},
			rules: []map[string]interface{}{{
				"matches": []interface{}{map[string]interface{}{
					"path":        map[string]interface{}{"type": "PathPrefix", "value": "/api"},
					"method":      "GET",
					"headers":     []interface{}{map[string]interface{}{"name": "x-canary", "value": "true"}},
					"queryParams": []interface{}{map[string]interface{}{"name": "version", "value": "v1"}},
				}},
				"backendRefs": []interface{}{testBackendRef("payments-api", "", int64(80))},
			}},
			want: "query parameters did not satisfy any matching rule",
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			client := fakeGatewayClient(t,
				[]unstructured.Unstructured{
					testGatewayClass("istio", "True", "Accepted"),
					testGatewayForHostname("edge", "public", "istio", "web", "*.knm.local"),
					testGatewayHTTPRouteForHostname("app", "payments", "edge", "public", "payments.knm.local", tt.rules),
				},
				[]kruntime.Object{
					testGatewayService("app", "payments-api", 80),
					testGatewayEndpointSlice("app", "payments-api", true, "10.0.0.10"),
				},
			)
			report := model.NewReport("check gateway", model.Target{})

			runGatewayIntentScan(context.Background(), client, report, GatewayOptions{}, tt.intent)

			t.Logf("diagnosis output:\n%s", gatewayDiagnosisLog(report))
			assertGatewayDiagnosisContains(t, report, tt.want)
		})
	}
}

func TestGatewayTrafficIntentNoMatchExplainsNoAttachedRoutes(t *testing.T) {
	client := fakeGatewayClient(t,
		[]unstructured.Unstructured{
			testGatewayClass("istio", "True", "Accepted"),
			testGatewayForHostname("edge", "public", "istio", "web", "*.knm.local"),
			testGatewayHTTPRouteForHostname("app", "payments", "edge", "private", "payments.knm.local", []map[string]interface{}{
				{"backendRefs": []interface{}{testBackendRef("payments-api", "", int64(80))}},
			}),
		},
		nil,
	)
	report := model.NewReport("check gateway", model.Target{})

	runGatewayIntentScan(context.Background(), client, report, GatewayOptions{}, gatewayTrafficIntent{
		Scheme: "http",
		Host:   "payments.knm.local",
		Port:   80,
		Path:   "/",
	})

	t.Logf("diagnosis output:\n%s", gatewayDiagnosisLog(report))
	assertGatewayDiagnosisContains(t, report, "no HTTPRoute attaches to them")
}

func TestGatewayTrafficIntentSuggestsNearMissListenerHostname(t *testing.T) {
	client := fakeGatewayClient(t,
		[]unstructured.Unstructured{
			testGatewayClass("istio", "True", "Accepted"),
			testGatewayForHostname("edge", "public", "istio", "web", "*.knm.local"),
		},
		nil,
	)
	report := model.NewReport("check gateway", model.Target{})

	runGatewayIntentScan(context.Background(), client, report, GatewayOptions{}, gatewayTrafficIntent{
		Scheme: "http",
		Host:   "payments.knm.loca",
		Port:   80,
		Path:   "/",
	})

	t.Logf("diagnosis output:\n%s", gatewayDiagnosisLog(report))
	assertGatewayDiagnosisContains(t, report, "Closest listener hostname: *.knm.local")
}

func TestGatewayTrafficIntentSuggestsNearMissRouteHostname(t *testing.T) {
	client := fakeGatewayClient(t,
		[]unstructured.Unstructured{
			testGatewayClass("istio", "True", "Accepted"),
			testGatewayForHostname("edge", "public", "istio", "web", "*.knm.local"),
			testGatewayHTTPRouteForHostname("app", "payments", "edge", "public", "payments.knm.local", []map[string]interface{}{
				{"backendRefs": []interface{}{testBackendRef("payments-api", "", int64(80))}},
			}),
		},
		nil,
	)
	report := model.NewReport("check gateway", model.Target{})

	runGatewayIntentScan(context.Background(), client, report, GatewayOptions{}, gatewayTrafficIntent{
		Scheme: "http",
		Host:   "paymets.knm.local",
		Port:   80,
		Path:   "/",
	})

	t.Logf("diagnosis output:\n%s", gatewayDiagnosisLog(report))
	assertGatewayDiagnosisContains(t, report, "Closest route hostname: payments.knm.local")
}

func TestGatewayClosestHostnameAvoidsWeakSuggestions(t *testing.T) {
	_, ok := gatewayClosestHostname("orders.knm.local", []string{"payments.knm.local", "catalog.knm.local"})
	if ok {
		t.Fatal("expected no weak hostname suggestion")
	}
}

func TestGatewayHostnameMatches(t *testing.T) {
	tests := []struct {
		name    string
		pattern string
		host    string
		want    bool
	}{
		{name: "exact", pattern: "payments.knm.local", host: "payments.knm.local", want: true},
		{name: "case insensitive", pattern: "Payments.KNM.Local", host: "payments.knm.local.", want: true},
		{name: "single label wildcard", pattern: "*.knm.local", host: "payments.knm.local", want: true},
		{name: "wildcard does not match zone root", pattern: "*.knm.local", host: "knm.local", want: false},
		{name: "wildcard does not match multiple labels", pattern: "*.knm.local", host: "deep.payments.knm.local", want: false},
		{name: "empty pattern matches unknown host", pattern: "", host: "payments.knm.local", want: true},
		{name: "empty host keeps static scans broad", pattern: "payments.knm.local", host: "", want: true},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := gatewayHostnameMatches(tt.pattern, tt.host); got != tt.want {
				t.Fatalf("gatewayHostnameMatches(%q, %q) = %v, want %v", tt.pattern, tt.host, got, tt.want)
			}
		})
	}
}

func TestGatewayHTTPRouteRuleMatchesPathMethodHeadersAndQuery(t *testing.T) {
	rule := map[string]interface{}{
		"matches": []interface{}{map[string]interface{}{
			"path": map[string]interface{}{
				"type":  "PathPrefix",
				"value": "/api",
			},
			"method": "GET",
			"headers": []interface{}{map[string]interface{}{
				"name":  "x-canary",
				"value": "true",
			}},
			"queryParams": []interface{}{map[string]interface{}{
				"name":  "version",
				"value": "v1",
			}},
		}},
	}

	intent := gatewayTrafficIntent{
		Path:    "/api/items",
		Method:  "get",
		Headers: map[string]string{"X-Canary": "true"},
		Query:   map[string][]string{"version": {"v1"}},
	}
	if !gatewayHTTPRouteRuleMatches(rule, intent) {
		t.Fatal("expected route rule to match full request intent")
	}
	intent.Path = "/apiv2"
	if gatewayHTTPRouteRuleMatches(rule, intent) {
		t.Fatal("PathPrefix /api should not match /apiv2")
	}
}

func TestGatewayHTTPRouteRuleMatchesExactAndRegex(t *testing.T) {
	exact := map[string]interface{}{"matches": []interface{}{map[string]interface{}{
		"path": map[string]interface{}{"type": "Exact", "value": "/api"},
	}}}
	if !gatewayHTTPRouteRuleMatches(exact, gatewayTrafficIntent{Path: "/api"}) {
		t.Fatal("expected exact path to match")
	}
	if gatewayHTTPRouteRuleMatches(exact, gatewayTrafficIntent{Path: "/api/items"}) {
		t.Fatal("exact path should not match child path")
	}

	regex := map[string]interface{}{"matches": []interface{}{map[string]interface{}{
		"path": map[string]interface{}{"type": "RegularExpression", "value": "^/v[0-9]+/items$"},
	}}}
	if !gatewayHTTPRouteRuleMatches(regex, gatewayTrafficIntent{Path: "/v2/items"}) {
		t.Fatal("expected regex path to match")
	}
	if gatewayHTTPRouteRuleMatches(regex, gatewayTrafficIntent{Path: "/v2/orders"}) {
		t.Fatal("regex path should not match different path")
	}
}

func TestGatewayFindCandidatePaths(t *testing.T) {
	gateway := testGateway("edge", "public", "istio", true, "True", "True", testGatewayListener("web", nil))
	gateway.Object["spec"].(map[string]interface{})["listeners"].([]interface{})[0].(map[string]interface{})["hostname"] = "*.knm.local"
	route := testGatewayHTTPRouteWithRules("app", "payments", []map[string]interface{}{
		{"name": "public", "namespace": "edge", "sectionName": "web"},
	}, []map[string]interface{}{
		{
			"matches": []interface{}{map[string]interface{}{
				"path": map[string]interface{}{"type": "PathPrefix", "value": "/api"},
			}},
			"backendRefs": []interface{}{
				testBackendRef("payments-api", "", int64(80)),
				map[string]interface{}{"name": "orders-api", "port": int64(80), "weight": int64(20)},
			},
		},
	})
	route.Object["spec"].(map[string]interface{})["hostnames"] = []interface{}{"payments.knm.local"}

	matches := gatewayFindCandidatePaths(
		[]unstructured.Unstructured{gateway},
		[]unstructured.Unstructured{route},
		gatewayTrafficIntent{Scheme: "http", Host: "payments.knm.local", Port: 80, Path: "/api/items"},
	)

	if len(matches) != 2 {
		t.Fatalf("expected 2 candidate backend paths, got %#v", matches)
	}
	first := matches[0]
	if first.GatewayNamespace != "edge" || first.GatewayName != "public" || first.ListenerName != "web" {
		t.Fatalf("unexpected gateway match: %#v", first)
	}
	if first.RouteNamespace != "app" || first.RouteName != "payments" || first.RuleNumber != 1 || first.BackendNumber != 1 {
		t.Fatalf("unexpected route/backend match: %#v", first)
	}
	if first.BackendNamespace != "app" || first.BackendName != "payments-api" || first.BackendPort != 80 || first.BackendWeight != 1 {
		t.Fatalf("unexpected backend details: %#v", first)
	}
}

func TestGatewayFindCandidatePathsHonorsListenerAndRouteHostnames(t *testing.T) {
	gateway := testGateway("edge", "public", "istio", true, "True", "True", testGatewayListener("web", nil))
	gateway.Object["spec"].(map[string]interface{})["listeners"].([]interface{})[0].(map[string]interface{})["hostname"] = "*.knm.local"
	route := testGatewayHTTPRouteWithRules("app", "payments", []map[string]interface{}{
		{"name": "public", "namespace": "edge", "sectionName": "web"},
	}, []map[string]interface{}{
		{"backendRefs": []interface{}{testBackendRef("payments-api", "", int64(80))}},
	})
	route.Object["spec"].(map[string]interface{})["hostnames"] = []interface{}{"payments.knm.local"}

	matches := gatewayFindCandidatePaths(
		[]unstructured.Unstructured{gateway},
		[]unstructured.Unstructured{route},
		gatewayTrafficIntent{Scheme: "http", Host: "orders.knm.local", Port: 80, Path: "/"},
	)
	if len(matches) != 0 {
		t.Fatalf("expected host mismatch to remove candidates, got %#v", matches)
	}
}

func fakeGatewayClient(t *testing.T, gatewayObjects []unstructured.Unstructured, coreObjects []kruntime.Object) *kube.Client {
	t.Helper()
	listKinds := map[schema.GroupVersionResource]string{
		backendTLSPolicyGVR:          "BackendTLSPolicyList",
		gatewayClassGVR:              "GatewayClassList",
		gatewayGVR:                   "GatewayList",
		grpcRouteGVR:                 "GRPCRouteList",
		httpRouteGVR:                 "HTTPRouteList",
		listenerSetGVR:               "ListenerSetList",
		referenceGVR:                 "ReferenceGrantList",
		tlsRouteGVR:                  "TLSRouteList",
		tcpRouteGVR:                  "TCPRouteList",
		udpRouteGVR:                  "UDPRouteList",
		xBackendTrafficPolicyGVR:     "XBackendTrafficPolicyList",
		envoyBackendGVR:              "BackendList",
		envoyBackendTrafficPolicyGVR: "BackendTrafficPolicyList",
		envoyClientTrafficPolicyGVR:  "ClientTrafficPolicyList",
		envoySecurityPolicyGVR:       "SecurityPolicyList",
		envoyEnvoyExtensionPolicyGVR: "EnvoyExtensionPolicyList",
		envoyEnvoyPatchPolicyGVR:     "EnvoyPatchPolicyList",
		envoyEnvoyProxyGVR:           "EnvoyProxyList",
		envoyHTTPRouteFilterGVR:      "HTTPRouteFilterList",
	}
	dyn := dynamicfake.NewSimpleDynamicClientWithCustomListKinds(kruntime.NewScheme(), listKinds)
	for i := range gatewayObjects {
		obj := gatewayObjects[i]
		gvr := gatewayTestGVRForObject(obj)
		var err error
		if gvr == gatewayClassGVR {
			_, err = dyn.Resource(gvr).Create(context.Background(), &obj, metav1.CreateOptions{})
		} else {
			_, err = dyn.Resource(gvr).Namespace(obj.GetNamespace()).Create(context.Background(), &obj, metav1.CreateOptions{})
		}
		if err != nil {
			t.Fatalf("create fake Gateway API object %s/%s: %v", obj.GetKind(), obj.GetName(), err)
		}
	}
	return &kube.Client{
		Dynamic: dyn,
		Core:    k8sfake.NewSimpleClientset(coreObjects...),
	}
}

func runGatewayStaticScan(ctx context.Context, client *kube.Client, report *model.Report, opts GatewayOptions) {
	runGatewayScan(ctx, client, report, opts, gatewayTrafficIntent{}, false)
}

func runGatewayIntentScan(ctx context.Context, client *kube.Client, report *model.Report, opts GatewayOptions, intent gatewayTrafficIntent) {
	runGatewayScan(ctx, client, report, opts, intent, true)
}

func gatewayTestGVRForObject(object unstructured.Unstructured) schema.GroupVersionResource {
	if strings.HasPrefix(object.GetAPIVersion(), "gateway.envoyproxy.io/") {
		switch object.GetKind() {
		case "Backend":
			return envoyBackendGVR
		case "BackendTrafficPolicy":
			return envoyBackendTrafficPolicyGVR
		case "ClientTrafficPolicy":
			return envoyClientTrafficPolicyGVR
		case "SecurityPolicy":
			return envoySecurityPolicyGVR
		case "EnvoyExtensionPolicy":
			return envoyEnvoyExtensionPolicyGVR
		case "EnvoyPatchPolicy":
			return envoyEnvoyPatchPolicyGVR
		case "EnvoyProxy":
			return envoyEnvoyProxyGVR
		case "HTTPRouteFilter":
			return envoyHTTPRouteFilterGVR
		}
	}
	if strings.HasPrefix(object.GetAPIVersion(), "gateway.networking.x-k8s.io/") && object.GetKind() == "XBackendTrafficPolicy" {
		return xBackendTrafficPolicyGVR
	}
	switch object.GetKind() {
	case "GatewayClass":
		return gatewayClassGVR
	case "Gateway":
		return gatewayGVR
	case "HTTPRoute":
		return httpRouteGVR
	case "GRPCRoute":
		return grpcRouteGVR
	case "TLSRoute":
		return tlsRouteGVR
	case "TCPRoute":
		return tcpRouteGVR
	case "UDPRoute":
		return udpRouteGVR
	case "ListenerSet":
		return listenerSetGVR
	case "BackendTLSPolicy":
		return backendTLSPolicyGVR
	case "ReferenceGrant":
		return referenceGVR
	default:
		return schema.GroupVersionResource{Group: "gateway.networking.k8s.io", Version: "v1", Resource: strings.ToLower(object.GetKind()) + "s"}
	}
}

func testGatewayClass(name, acceptedStatus, reason string) unstructured.Unstructured {
	return gatewayUnstructured("GatewayClass", "", name, map[string]interface{}{
		"spec": map[string]interface{}{"controllerName": "example.io/gateway-controller"},
		"status": map[string]interface{}{
			"conditions": []interface{}{testGatewayCondition("Accepted", acceptedStatus, reason, "")},
		},
	})
}

func testGateway(namespace, name, class string, hasAddress bool, acceptedStatus, programmedStatus string, listener map[string]interface{}) unstructured.Unstructured {
	return testGatewayWithListenerStatus(namespace, name, class, hasAddress, acceptedStatus, programmedStatus, listener, "True", "True")
}

func testGatewayWithListenerStatus(namespace, name, class string, hasAddress bool, acceptedStatus, programmedStatus string, listener map[string]interface{}, listenerProgrammedStatus, listenerResolvedRefsStatus string) unstructured.Unstructured {
	listenerName, _ := listener["name"].(string)
	status := map[string]interface{}{
		"conditions": []interface{}{
			testGatewayCondition("Accepted", acceptedStatus, acceptedStatus, ""),
			testGatewayCondition("Programmed", programmedStatus, programmedStatus, ""),
		},
		"listeners": []interface{}{
			map[string]interface{}{
				"name": listenerName,
				"conditions": []interface{}{
					testGatewayCondition("Accepted", "True", "Accepted", ""),
					testGatewayCondition("Programmed", listenerProgrammedStatus, "Programmed", ""),
					testGatewayCondition("ResolvedRefs", listenerResolvedRefsStatus, "ResolvedRefs", ""),
				},
			},
		},
	}
	if hasAddress {
		status["addresses"] = []interface{}{map[string]interface{}{"type": "IPAddress", "value": "10.0.0.20"}}
	}
	return gatewayUnstructured("Gateway", namespace, name, map[string]interface{}{
		"spec": map[string]interface{}{
			"gatewayClassName": class,
			"listeners":        []interface{}{listener},
		},
		"status": status,
	})
}

func testGatewayWithListenerExtraCondition(namespace, name, class string, listener map[string]interface{}, extraCondition map[string]interface{}) unstructured.Unstructured {
	gateway := testGateway(namespace, name, class, true, "True", "True", listener)
	statusListeners := gateway.Object["status"].(map[string]interface{})["listeners"].([]interface{})
	conditions := statusListeners[0].(map[string]interface{})["conditions"].([]interface{})
	statusListeners[0].(map[string]interface{})["conditions"] = append(conditions, extraCondition)
	return gateway
}

func testGatewayWithoutClassName(namespace, name string, listener map[string]interface{}) unstructured.Unstructured {
	gateway := testGateway(namespace, name, "istio", true, "True", "True", listener)
	delete(gateway.Object["spec"].(map[string]interface{}), "gatewayClassName")
	return gateway
}

func testGatewayForHostname(namespace, name, class, listenerName, hostname string) unstructured.Unstructured {
	listener := testGatewayListener(listenerName, nil)
	listener["hostname"] = hostname
	return testGateway(namespace, name, class, true, "True", "True", listener)
}

func testGatewayListener(name string, certRefs []map[string]interface{}) map[string]interface{} {
	listener := map[string]interface{}{
		"name":     "http",
		"hostname": "*.example.com",
		"port":     int64(80),
		"protocol": "HTTP",
	}
	if name != "" {
		listener["name"] = name
	}
	if len(certRefs) > 0 {
		var refs []interface{}
		for _, ref := range certRefs {
			refs = append(refs, ref)
		}
		listener["tls"] = map[string]interface{}{"certificateRefs": refs}
		listener["protocol"] = "HTTPS"
		listener["port"] = int64(443)
	}
	return listener
}

func testGatewayHTTPRoute(namespace, name, gatewayNamespace, gatewayName string, backendRefs []map[string]interface{}, acceptedStatus, resolvedStatus string) unstructured.Unstructured {
	return testGatewayRouteKind("HTTPRoute", namespace, name, gatewayNamespace, gatewayName, backendRefs, acceptedStatus, resolvedStatus)
}

func testGatewayRouteKind(kind, namespace, name, gatewayNamespace, gatewayName string, backendRefs []map[string]interface{}, acceptedStatus, resolvedStatus string) unstructured.Unstructured {
	var refs []interface{}
	for _, ref := range backendRefs {
		refs = append(refs, ref)
	}
	return gatewayUnstructured(kind, namespace, name, map[string]interface{}{
		"spec": map[string]interface{}{
			"parentRefs": []interface{}{map[string]interface{}{"name": gatewayName, "namespace": gatewayNamespace}},
			"rules":      []interface{}{map[string]interface{}{"backendRefs": refs}},
		},
		"status": map[string]interface{}{
			"parents": []interface{}{map[string]interface{}{
				"parentRef": map[string]interface{}{"name": gatewayName, "namespace": gatewayNamespace},
				"conditions": []interface{}{
					testGatewayCondition("Accepted", acceptedStatus, acceptedStatus, ""),
					testGatewayCondition("ResolvedRefs", resolvedStatus, resolvedStatus, ""),
				},
			}},
		},
	})
}

func testGatewayHTTPRouteNoStatus(namespace, name, gatewayNamespace, gatewayName string, backendRefs []map[string]interface{}) unstructured.Unstructured {
	route := testGatewayHTTPRoute(namespace, name, gatewayNamespace, gatewayName, backendRefs, "True", "True")
	delete(route.Object, "status")
	return route
}

func testGatewayHTTPRouteWithParentCondition(namespace, name, gatewayNamespace, gatewayName string, backendRefs []map[string]interface{}, extraCondition map[string]interface{}) unstructured.Unstructured {
	route := testGatewayHTTPRoute(namespace, name, gatewayNamespace, gatewayName, backendRefs, "True", "True")
	parents := route.Object["status"].(map[string]interface{})["parents"].([]interface{})
	conditions := parents[0].(map[string]interface{})["conditions"].([]interface{})
	parents[0].(map[string]interface{})["conditions"] = append(conditions, extraCondition)
	return route
}

func testGatewayHTTPRouteForHostname(namespace, name, gatewayNamespace, gatewayName, hostname string, rules []map[string]interface{}) unstructured.Unstructured {
	route := testGatewayHTTPRouteWithRules(namespace, name, []map[string]interface{}{{"name": gatewayName, "namespace": gatewayNamespace, "sectionName": "web"}}, rules)
	route.Object["spec"].(map[string]interface{})["hostnames"] = []interface{}{hostname}
	return route
}

func testGatewayHTTPRouteWithRules(namespace, name string, parentRefs []map[string]interface{}, rules []map[string]interface{}) unstructured.Unstructured {
	var parents []interface{}
	for _, ref := range parentRefs {
		parents = append(parents, ref)
	}
	var routeRules []interface{}
	for _, rule := range rules {
		routeRules = append(routeRules, rule)
	}
	fields := map[string]interface{}{
		"spec": map[string]interface{}{
			"parentRefs": parents,
			"rules":      routeRules,
		},
	}
	if len(parentRefs) > 0 {
		parentRef := parentRefs[0]
		parentName := stringField(parentRef, "name")
		parentNamespace := defaultString(stringField(parentRef, "namespace"), namespace)
		fields["status"] = map[string]interface{}{
			"parents": []interface{}{map[string]interface{}{
				"parentRef": map[string]interface{}{"name": parentName, "namespace": parentNamespace},
				"conditions": []interface{}{
					testGatewayCondition("Accepted", "True", "Accepted", ""),
					testGatewayCondition("ResolvedRefs", "True", "ResolvedRefs", ""),
				},
			}},
		}
	}
	return gatewayUnstructured("HTTPRoute", namespace, name, fields)
}

func testBackendRef(name, namespace string, port int64) map[string]interface{} {
	ref := map[string]interface{}{
		"name": name,
		"port": port,
	}
	if namespace != "" {
		ref["namespace"] = namespace
	}
	return ref
}

func testReferenceGrant(namespace, fromNamespace, fromKind, toGroup, toKind, toName string) unstructured.Unstructured {
	return gatewayUnstructured("ReferenceGrant", namespace, "allow-"+fromNamespace, map[string]interface{}{
		"spec": map[string]interface{}{
			"from": []interface{}{map[string]interface{}{
				"group":     "gateway.networking.k8s.io",
				"kind":      fromKind,
				"namespace": fromNamespace,
			}},
			"to": []interface{}{map[string]interface{}{
				"group": toGroup,
				"kind":  toKind,
				"name":  toName,
			}},
		},
	})
}

func testListenerSet(namespace, name, parentGateway string, listener map[string]interface{}, acceptedStatus, acceptedReason string) unstructured.Unstructured {
	listenerName := stringField(listener, "name")
	return gatewayUnstructured("ListenerSet", namespace, name, map[string]interface{}{
		"spec": map[string]interface{}{
			"parentRef": map[string]interface{}{"name": parentGateway},
			"listeners": []interface{}{listener},
		},
		"status": map[string]interface{}{
			"conditions": []interface{}{
				testGatewayCondition("Accepted", acceptedStatus, acceptedReason, ""),
				testGatewayCondition("Programmed", "True", "Programmed", ""),
			},
			"listeners": []interface{}{
				map[string]interface{}{
					"name": listenerName,
					"conditions": []interface{}{
						testGatewayCondition("Accepted", "True", "Accepted", ""),
						testGatewayCondition("Programmed", "True", "Programmed", ""),
						testGatewayCondition("ResolvedRefs", "True", "ResolvedRefs", ""),
					},
				},
			},
		},
	})
}

func testBackendTLSPolicy(namespace, name, targetService, sectionName, caConfigMap, acceptedStatus, resolvedStatus, resolvedReason string) unstructured.Unstructured {
	target := map[string]interface{}{
		"group": "",
		"kind":  "Service",
		"name":  targetService,
	}
	if sectionName != "" {
		target["sectionName"] = sectionName
	}
	return gatewayUnstructured("BackendTLSPolicy", namespace, name, map[string]interface{}{
		"spec": map[string]interface{}{
			"targetRefs": []interface{}{target},
			"validation": map[string]interface{}{
				"caCertificateRefs": []interface{}{map[string]interface{}{
					"group": "",
					"kind":  "ConfigMap",
					"name":  caConfigMap,
				}},
			},
		},
		"status": map[string]interface{}{
			"ancestors": []interface{}{
				map[string]interface{}{
					"conditions": []interface{}{
						testGatewayCondition("Accepted", acceptedStatus, acceptedStatus, ""),
						testGatewayCondition("ResolvedRefs", resolvedStatus, resolvedReason, ""),
					},
				},
			},
		},
	})
}

func testEnvoyPolicy(kind, namespace, name string, targetRefs []interface{}, acceptedStatus, resolvedStatus, reason string) unstructured.Unstructured {
	obj := gatewayUnstructured(kind, namespace, name, gatewayPolicyFields(targetRefs, acceptedStatus, resolvedStatus, reason))
	obj.SetAPIVersion("gateway.envoyproxy.io/v1alpha1")
	return obj
}

func testEnvoyPolicyWithSpec(kind, namespace, name string, targetRefs []interface{}, spec map[string]interface{}, acceptedStatus, resolvedStatus, reason string) unstructured.Unstructured {
	fields := gatewayPolicyFields(targetRefs, acceptedStatus, resolvedStatus, reason)
	policySpec := mapField(fields, "spec")
	for key, value := range spec {
		policySpec[key] = value
	}
	fields["spec"] = policySpec
	obj := gatewayUnstructured(kind, namespace, name, fields)
	obj.SetAPIVersion("gateway.envoyproxy.io/v1alpha1")
	return obj
}

func testEnvoyObject(kind, namespace, name string, fields map[string]interface{}) unstructured.Unstructured {
	obj := gatewayUnstructured(kind, namespace, name, fields)
	obj.SetAPIVersion("gateway.envoyproxy.io/v1alpha1")
	return obj
}

func testEnvoySecurityPolicy(namespace, name string, targetRefs []interface{}, spec map[string]interface{}, acceptedStatus, resolvedStatus, reason string) unstructured.Unstructured {
	fields := gatewayPolicyFields(targetRefs, acceptedStatus, resolvedStatus, reason)
	policySpec := mapField(fields, "spec")
	for key, value := range spec {
		policySpec[key] = value
	}
	fields["spec"] = policySpec
	obj := gatewayUnstructured("SecurityPolicy", namespace, name, fields)
	obj.SetAPIVersion("gateway.envoyproxy.io/v1alpha1")
	return obj
}

func testXBackendTrafficPolicy(namespace, name string, targetRefs []interface{}, acceptedStatus, resolvedStatus, reason string) unstructured.Unstructured {
	obj := gatewayUnstructured("XBackendTrafficPolicy", namespace, name, gatewayPolicyFields(targetRefs, acceptedStatus, resolvedStatus, reason))
	obj.SetAPIVersion("gateway.networking.x-k8s.io/v1alpha1")
	return obj
}

func gatewayPolicyFields(targetRefs []interface{}, acceptedStatus, resolvedStatus, reason string) map[string]interface{} {
	return map[string]interface{}{
		"spec": map[string]interface{}{
			"targetRefs": targetRefs,
		},
		"status": map[string]interface{}{
			"ancestors": []interface{}{
				map[string]interface{}{
					"conditions": []interface{}{
						testGatewayCondition("Accepted", acceptedStatus, reason, ""),
						testGatewayCondition("ResolvedRefs", resolvedStatus, reason, ""),
					},
				},
			},
		},
	}
}

func gatewayUnstructured(kind, namespace, name string, fields map[string]interface{}) unstructured.Unstructured {
	obj := unstructured.Unstructured{Object: map[string]interface{}{}}
	for key, value := range fields {
		obj.Object[key] = value
	}
	obj.SetAPIVersion("gateway.networking.k8s.io/v1")
	obj.SetKind(kind)
	obj.SetNamespace(namespace)
	obj.SetName(name)
	return obj
}

func withLabels(obj unstructured.Unstructured, labels map[string]string) unstructured.Unstructured {
	obj.SetLabels(labels)
	return obj
}

func testGatewayCondition(conditionType, status, reason, message string) map[string]interface{} {
	return map[string]interface{}{
		"type":    conditionType,
		"status":  status,
		"reason":  reason,
		"message": message,
	}
}

func testGatewayService(namespace, name string, port int32) kruntime.Object {
	return &corev1.Service{
		ObjectMeta: metav1.ObjectMeta{Namespace: namespace, Name: name},
		Spec: corev1.ServiceSpec{
			Ports: []corev1.ServicePort{{Name: "http", Port: port, TargetPort: intstr.FromInt32(port)}},
		},
	}
}

func testGatewayImplementationService(namespace, name, gatewayName string, port int32) kruntime.Object {
	return &corev1.Service{
		ObjectMeta: metav1.ObjectMeta{
			Namespace: namespace,
			Name:      name,
			Labels:    map[string]string{"gateway.networking.k8s.io/gateway-name": gatewayName},
		},
		Spec: corev1.ServiceSpec{
			Type:  corev1.ServiceTypeLoadBalancer,
			Ports: []corev1.ServicePort{{Name: "http", Port: port, TargetPort: intstr.FromInt32(port)}},
		},
		Status: corev1.ServiceStatus{
			LoadBalancer: corev1.LoadBalancerStatus{
				Ingress: []corev1.LoadBalancerIngress{{IP: "10.0.0.20"}},
			},
		},
	}
}

func testGatewayEndpointSlice(namespace, service string, ready bool, addresses ...string) kruntime.Object {
	return &discoveryv1.EndpointSlice{
		ObjectMeta: metav1.ObjectMeta{
			Namespace: namespace,
			Name:      service + "-slice",
			Labels:    map[string]string{discoveryv1.LabelServiceName: service},
		},
		AddressType: discoveryv1.AddressTypeIPv4,
		Ports:       []discoveryv1.EndpointPort{},
		Endpoints: []discoveryv1.Endpoint{{
			Addresses:  addresses,
			Conditions: discoveryv1.EndpointConditions{Ready: &ready},
		}},
	}
}

func assertResultContains(t *testing.T, report *model.Report, status model.Status, want string) {
	t.Helper()
	for _, result := range report.Results {
		if result.Status == status && strings.Contains(result.Message, want) {
			return
		}
	}
	t.Fatalf("missing %s result containing %q in %#v", status, want, report.Results)
}

func assertResultNotContains(t *testing.T, report *model.Report, status model.Status, unwanted string) {
	t.Helper()
	for _, result := range report.Results {
		if result.Status == status && strings.Contains(result.Message, unwanted) {
			t.Fatalf("%s result should not contain %q: %q", status, unwanted, result.Message)
		}
	}
}

func assertGatewayDiagnosisContains(t *testing.T, report *model.Report, want string) {
	t.Helper()
	for _, diagnosis := range report.Diagnoses {
		if strings.Contains(diagnosis.Message, want) {
			return
		}
	}
	t.Fatalf("missing diagnosis containing %q in %#v", want, report.Diagnoses)
}

func assertGatewayDiagnosisNotContains(t *testing.T, report *model.Report, unwanted string) {
	t.Helper()
	for _, diagnosis := range report.Diagnoses {
		if strings.Contains(diagnosis.Message, unwanted) {
			t.Fatalf("diagnosis should not contain %q: %q", unwanted, diagnosis.Message)
		}
	}
}

func gatewayDiagnosisLog(report *model.Report) string {
	if len(report.Diagnoses) == 0 {
		return "(none)"
	}
	var lines []string
	for _, diagnosis := range report.Diagnoses {
		lines = append(lines, "- "+diagnosis.Message)
	}
	return strings.Join(lines, "\n")
}
