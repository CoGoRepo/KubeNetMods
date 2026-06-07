package check

import (
	"context"
	"strings"
	"testing"

	"github.com/CoGoRepo/KubeNetMods/internal/kube"
	"github.com/CoGoRepo/KubeNetMods/internal/model"
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

func TestGatewayTrafficIntentScanReportsMatchedBackendProblem(t *testing.T) {
	client := fakeGatewayClient(t,
		[]unstructured.Unstructured{
			testGatewayClass("istio", "True", "Accepted"),
			testGatewayForHostname("edge", "public", "istio", "web", "*.knm.local"),
			testGatewayHTTPRouteForHostname("app", "payments", "edge", "public", "payments.knm.local", []map[string]interface{}{
				{
					"matches":     []interface{}{map[string]interface{}{"path": map[string]interface{}{"type": "PathPrefix", "value": "/api"}}},
					"backendRefs": []interface{}{testBackendRef("payments-api", "", int64(80))},
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
	})

	assertGatewayDiagnosisContains(t, report, "HTTPRoute app/payments rule 1 routes to Service app/payments-api, but that Service is missing or unreadable")
}

func TestGatewayTrafficIntentScanReportsMixedWeightedBackends(t *testing.T) {
	client := fakeGatewayClient(t,
		[]unstructured.Unstructured{
			testGatewayClass("istio", "True", "Accepted"),
			testGatewayForHostname("edge", "public", "istio", "web", "*.knm.local"),
			testGatewayHTTPRouteForHostname("app", "payments", "edge", "public", "payments.knm.local", []map[string]interface{}{
				{
					"backendRefs": []interface{}{
						map[string]interface{}{"name": "catalog-api", "port": int64(80), "weight": int64(75)},
						map[string]interface{}{"name": "payments-api", "port": int64(80), "weight": int64(25)},
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

	assertResultContains(t, report, model.StatusWarn, "splits this request across weighted backendRefs")
	assertGatewayDiagnosisContains(t, report, "HTTPRoute app/payments rule 1 splits this request across weighted backendRefs; broken backend: app/payments-api:80 weight 25 (missing Service).")
	assertGatewayDiagnosisNotContains(t, report, "but that Service is missing or unreadable")
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
		gatewayClassGVR: "GatewayClassList",
		gatewayGVR:      "GatewayList",
		httpRouteGVR:    "HTTPRouteList",
		referenceGVR:    "ReferenceGrantList",
	}
	dyn := dynamicfake.NewSimpleDynamicClientWithCustomListKinds(kruntime.NewScheme(), listKinds)
	for i := range gatewayObjects {
		obj := gatewayObjects[i]
		gvr := gatewayTestGVRForKind(obj.GetKind())
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

func gatewayTestGVRForKind(kind string) schema.GroupVersionResource {
	switch kind {
	case "GatewayClass":
		return gatewayClassGVR
	case "Gateway":
		return gatewayGVR
	case "HTTPRoute":
		return httpRouteGVR
	case "ReferenceGrant":
		return referenceGVR
	default:
		return schema.GroupVersionResource{Group: "gateway.networking.k8s.io", Version: "v1", Resource: strings.ToLower(kind) + "s"}
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
	var refs []interface{}
	for _, ref := range backendRefs {
		refs = append(refs, ref)
	}
	return gatewayUnstructured("HTTPRoute", namespace, name, map[string]interface{}{
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
