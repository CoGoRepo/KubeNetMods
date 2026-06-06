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

	runGatewayScan(context.Background(), client, report, GatewayOptions{})

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

	runGatewayScan(context.Background(), client, report, GatewayOptions{})

	assertResultContains(t, report, model.StatusFail, "missing/unreadable Service app/missing-api")
	assertGatewayDiagnosisContains(t, report, "routes to Service app/missing-api")
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

	runGatewayScan(context.Background(), client, report, GatewayOptions{})

	assertResultContains(t, report, model.StatusFail, "without a matching ReferenceGrant")
	assertGatewayDiagnosisContains(t, report, "does not grant that reference")
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

	runGatewayScan(context.Background(), client, report, GatewayOptions{})

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

	runGatewayScan(context.Background(), client, report, GatewayOptions{})

	assertResultContains(t, report, model.StatusFail, "references TLS Secret infra/missing-cert")
	assertGatewayDiagnosisContains(t, report, "missing or unreadable TLS Secret infra/missing-cert")
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

	runGatewayScan(context.Background(), client, report, GatewayOptions{RouteRef: "app/api-route"})

	assertGatewayDiagnosisContains(t, report, "Service app/api port 9999")
	assertGatewayDiagnosisNotContains(t, report, "broken-tls")
	assertGatewayDiagnosisNotContains(t, report, "missing-cert")
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
					testGatewayCondition("Programmed", "True", "Programmed", ""),
					testGatewayCondition("ResolvedRefs", "True", "ResolvedRefs", ""),
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
			Ports: []corev1.ServicePort{{Name: "http", Port: port}},
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
