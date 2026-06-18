package check

import (
	"context"
	"crypto/tls"
	"fmt"
	"net"
	"net/http"
	"net/url"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/CoGoRepo/KubeNetMods/internal/kube"
	"github.com/CoGoRepo/KubeNetMods/internal/model"
	networkingapi "istio.io/api/networking/v1alpha3"
	networkingv1 "istio.io/client-go/pkg/apis/networking/v1"
	corev1 "k8s.io/api/core/v1"
	discoveryv1 "k8s.io/api/discovery/v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	"k8s.io/apimachinery/pkg/api/resource"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"
	"k8s.io/apimachinery/pkg/labels"
	"k8s.io/apimachinery/pkg/runtime/schema"
	"k8s.io/apimachinery/pkg/selection"
	gatewayv1 "sigs.k8s.io/gateway-api/apis/v1"
)

var (
	backendTLSPolicyGVR = schema.GroupVersionResource{Group: gatewayv1.GroupName, Version: "v1", Resource: "backendtlspolicies"}
	gatewayClassGVR     = schema.GroupVersionResource{Group: gatewayv1.GroupName, Version: "v1", Resource: "gatewayclasses"}
	gatewayGVR          = schema.GroupVersionResource{Group: gatewayv1.GroupName, Version: "v1", Resource: "gateways"}
	grpcRouteGVR        = schema.GroupVersionResource{Group: gatewayv1.GroupName, Version: "v1", Resource: "grpcroutes"}
	httpRouteGVR        = schema.GroupVersionResource{Group: gatewayv1.GroupName, Version: "v1", Resource: "httproutes"}
	listenerSetGVR      = schema.GroupVersionResource{Group: gatewayv1.GroupName, Version: "v1", Resource: "listenersets"}
	referenceGVR        = schema.GroupVersionResource{Group: gatewayv1.GroupName, Version: "v1", Resource: "referencegrants"}
	tlsRouteGVR         = schema.GroupVersionResource{Group: gatewayv1.GroupName, Version: "v1", Resource: "tlsroutes"}
	tcpRouteGVR         = schema.GroupVersionResource{Group: gatewayv1.GroupName, Version: "v1alpha2", Resource: "tcproutes"}
	udpRouteGVR         = schema.GroupVersionResource{Group: gatewayv1.GroupName, Version: "v1alpha2", Resource: "udproutes"}

	xBackendTrafficPolicyGVR             = schema.GroupVersionResource{Group: "gateway.networking.x-k8s.io", Version: "v1alpha1", Resource: "xbackendtrafficpolicies"}
	envoyBackendGVR                      = schema.GroupVersionResource{Group: "gateway.envoyproxy.io", Version: "v1alpha1", Resource: "backends"}
	envoyBackendTrafficPolicyGVR         = schema.GroupVersionResource{Group: "gateway.envoyproxy.io", Version: "v1alpha1", Resource: "backendtrafficpolicies"}
	envoyClientTrafficPolicyGVR          = schema.GroupVersionResource{Group: "gateway.envoyproxy.io", Version: "v1alpha1", Resource: "clienttrafficpolicies"}
	envoySecurityPolicyGVR               = schema.GroupVersionResource{Group: "gateway.envoyproxy.io", Version: "v1alpha1", Resource: "securitypolicies"}
	envoyEnvoyExtensionPolicyGVR         = schema.GroupVersionResource{Group: "gateway.envoyproxy.io", Version: "v1alpha1", Resource: "envoyextensionpolicies"}
	envoyEnvoyPatchPolicyGVR             = schema.GroupVersionResource{Group: "gateway.envoyproxy.io", Version: "v1alpha1", Resource: "envoypatchpolicies"}
	envoyEnvoyProxyGVR                   = schema.GroupVersionResource{Group: "gateway.envoyproxy.io", Version: "v1alpha1", Resource: "envoyproxies"}
	envoyHTTPRouteFilterGVR              = schema.GroupVersionResource{Group: "gateway.envoyproxy.io", Version: "v1alpha1", Resource: "httproutefilters"}
	envoyBackendTrafficPolicyTargetKinds = map[string]bool{"Gateway": true, "HTTPRoute": true, "GRPCRoute": true, "TLSRoute": true, "TCPRoute": true, "UDPRoute": true}
	envoyClientTrafficPolicyTargetKinds  = map[string]bool{"Gateway": true, "HTTPRoute": true, "GRPCRoute": true}
	envoySecurityPolicyTargetKinds       = map[string]bool{"Gateway": true, "HTTPRoute": true, "GRPCRoute": true, "TCPRoute": true}
	envoyExtensionPolicyTargetKinds      = map[string]bool{"Gateway": true, "HTTPRoute": true, "GRPCRoute": true}
)

type GatewayOptions struct {
	Context         string
	Namespace       string
	GatewayRef      string
	RouteRef        string
	GatewayClass    string
	URL             string
	Host            string
	Scheme          string
	Port            int32
	Protocol        string
	Path            string
	Method          string
	HTTPHeaders     map[string]string
	GRPCService     string
	GRPCMethod      string
	ExpectService   string
	Probe           bool
	ProbeAddress    string
	DebugImage      string
	DebugPullPolicy string
	DebugPodName    string
	Limit           int
	Wide            bool
	Timeout         time.Duration
}

func RunGateway(ctx context.Context, opts GatewayOptions) (*model.Report, error) {
	if opts.Limit <= 0 {
		opts.Limit = 50
	}
	if opts.DebugImage == "" {
		opts.DebugImage = "nicolaka/netshoot:latest"
	}
	if opts.DebugPullPolicy == "" {
		opts.DebugPullPolicy = "IfNotPresent"
	}
	if opts.DebugPodName == "" {
		opts.DebugPodName = "kubenetmods-gateway-debug"
	}
	target := model.Target{
		Context:      opts.Context,
		Namespace:    opts.Namespace,
		GatewayClass: opts.GatewayClass,
		URL:          opts.URL,
		Host:         opts.Host,
		Path:         opts.Path,
		Method:       opts.Method,
	}
	if ref := parseGatewayObjectRef(opts.GatewayRef, opts.Namespace); ref.Name != "" {
		target.GatewayNamespace = ref.Namespace
		target.Gateway = ref.Name
	}
	if ref := parseGatewayObjectRef(opts.RouteRef, opts.Namespace); ref.Name != "" {
		target.RouteNamespace = ref.Namespace
		target.Route = ref.Name
	}
	report := model.NewReport("check gateway", target)

	intent, intentMode, intentErr := gatewayTrafficIntentFromOptions(opts)
	if intentErr != nil {
		report.Add("Gateway Traffic Intent", "options", model.StatusFail, intentErr.Error())
		report.Diagnose(intentErr.Error())
		return report, nil
	}
	if intentMode {
		report.Target.Host = intent.Host
		report.Target.Path = intent.Path
		report.Target.Method = intent.Method
	}
	if strings.TrimSpace(opts.ExpectService) != "" {
		if _, err := parseGatewayServiceRef(opts.ExpectService); err != nil {
			report.Add("Gateway Traffic Intent", "options", model.StatusFail, err.Error())
			report.Diagnose(err.Error())
			return report, nil
		}
	}

	client, err := kube.New(opts.Context)
	if err != nil {
		report.Add("Gateway API Access", "context", model.StatusFail, err.Error())
		report.Diagnose("Cannot build Kubernetes client. Check kubeconfig, context, and credentials.")
		return report, nil
	}
	if report.Target.Context == "" {
		report.Target.Context = client.Context
	}
	if opts.Namespace != "" {
		if _, err := client.Core.CoreV1().Namespaces().Get(ctx, opts.Namespace, metav1.GetOptions{}); err != nil {
			report.Add("Gateway API Access", "namespace", model.StatusFail, fmt.Sprintf("Namespace %q is not accessible: %v", opts.Namespace, err))
			report.Diagnose(fmt.Sprintf("Cannot access namespace %q. Fix the namespace, kubeconfig, or RBAC before scanning scoped Gateway API resources.", opts.Namespace))
			return report, nil
		}
		report.Add("Gateway API Access", "namespace", model.StatusPass, fmt.Sprintf("Namespace %q exists.", opts.Namespace))
	}

	runGatewayScan(ctx, client, report, opts, intent, intentMode)
	if len(report.Diagnoses) == 0 && report.CountByStatus(model.StatusFail) > 0 {
		report.Diagnose("Gateway API scan found failures, but no single dominant diagnosis was inferred yet. Review the failed Gateway, Route, and backend details.")
	}
	report.Limitations = append(report.Limitations,
		"Gateway checks inspect Kubernetes/Gateway API resources and can run HTTP/HTTPS probes with --probe; they do not inspect provider xDS/dataplane state yet.",
	)
	return report, nil
}

func runGatewayScan(ctx context.Context, client *kube.Client, report *model.Report, opts GatewayOptions, intent gatewayTrafficIntent, intentMode bool) {
	scanner := gatewayScanner{report: report, opts: opts, limit: opts.Limit, trafficIntent: intentMode}
	namespace := metav1.NamespaceAll
	if opts.Namespace != "" {
		namespace = opts.Namespace
	}

	classes, classErr := gatewayList(ctx, client, gatewayClassGVR, "")
	gateways, gatewayErr := gatewayList(ctx, client, gatewayGVR, namespace)
	parentGateways := gateways
	parentGatewayErr := gatewayErr
	if opts.Namespace != "" {
		parentGateways, parentGatewayErr = gatewayList(ctx, client, gatewayGVR, metav1.NamespaceAll)
	}
	routes, routeErr := gatewayList(ctx, client, httpRouteGVR, namespace)
	grpcRoutes, grpcRouteErr := gatewayList(ctx, client, grpcRouteGVR, namespace)
	tlsRoutes, tlsRouteErr := gatewayList(ctx, client, tlsRouteGVR, namespace)
	tcpRoutes, tcpRouteErr := gatewayList(ctx, client, tcpRouteGVR, namespace)
	udpRoutes, udpRouteErr := gatewayList(ctx, client, udpRouteGVR, namespace)
	listenerSets, listenerSetErr := gatewayList(ctx, client, listenerSetGVR, namespace)
	backendTLSPolicies, backendTLSPolicyErr := gatewayList(ctx, client, backendTLSPolicyGVR, namespace)
	xBackendTrafficPolicies, xBackendTrafficPolicyErr := gatewayList(ctx, client, xBackendTrafficPolicyGVR, namespace)
	envoyBackends, envoyBackendErr := gatewayList(ctx, client, envoyBackendGVR, namespace)
	envoyBackendTrafficPolicies, envoyBackendTrafficPolicyErr := gatewayList(ctx, client, envoyBackendTrafficPolicyGVR, namespace)
	envoyClientTrafficPolicies, envoyClientTrafficPolicyErr := gatewayList(ctx, client, envoyClientTrafficPolicyGVR, namespace)
	envoySecurityPolicies, envoySecurityPolicyErr := gatewayList(ctx, client, envoySecurityPolicyGVR, namespace)
	envoyExtensionPolicies, envoyExtensionPolicyErr := gatewayList(ctx, client, envoyEnvoyExtensionPolicyGVR, namespace)
	envoyPatchPolicies, envoyPatchPolicyErr := gatewayList(ctx, client, envoyEnvoyPatchPolicyGVR, namespace)
	envoyProxies, envoyProxyErr := gatewayList(ctx, client, envoyEnvoyProxyGVR, namespace)
	envoyHTTPRouteFilters, envoyHTTPRouteFilterErr := gatewayList(ctx, client, envoyHTTPRouteFilterGVR, namespace)
	refGrants, refGrantErr := gatewayList(ctx, client, referenceGVR, metav1.NamespaceAll)

	if gatewayAPIMissing(classErr) && gatewayAPIMissing(gatewayErr) && gatewayAPIMissing(routeErr) && gatewayAPIMissing(parentGatewayErr) &&
		gatewayAPIMissing(grpcRouteErr) && gatewayAPIMissing(tlsRouteErr) && gatewayAPIMissing(tcpRouteErr) && gatewayAPIMissing(udpRouteErr) &&
		gatewayAPIMissing(listenerSetErr) && gatewayAPIMissing(backendTLSPolicyErr) &&
		gatewayAPIMissing(xBackendTrafficPolicyErr) && gatewayAPIMissing(envoyBackendErr) && gatewayAPIMissing(envoyBackendTrafficPolicyErr) && gatewayAPIMissing(envoyClientTrafficPolicyErr) &&
		gatewayAPIMissing(envoySecurityPolicyErr) && gatewayAPIMissing(envoyExtensionPolicyErr) && gatewayAPIMissing(envoyPatchPolicyErr) && gatewayAPIMissing(envoyProxyErr) && gatewayAPIMissing(envoyHTTPRouteFilterErr) {
		report.Add("Gateway API Access", "v1 resources", model.StatusInfo, "Gateway API v1 resources were not found in this cluster.")
		return
	}
	if classErr != nil && !gatewayAPIMissing(classErr) {
		scanner.addProblemCategorized("Gateway API Access", "GatewayClass list", model.StatusWarn, "api-inspection", fmt.Sprintf("Could not list GatewayClass objects: %v", classErr), "")
	}
	if gatewayErr != nil && !gatewayAPIMissing(gatewayErr) {
		scanner.addProblemCategorized("Gateway API Access", "Gateway list", model.StatusWarn, "api-inspection", fmt.Sprintf("Could not list Gateway objects: %v", gatewayErr), "")
	}
	if parentGatewayErr != nil && parentGatewayErr != gatewayErr && !gatewayAPIMissing(parentGatewayErr) {
		scanner.addProblemCategorized("Gateway API Access", "Gateway parent lookup", model.StatusWarn, "api-inspection", fmt.Sprintf("Could not list Gateway objects cluster-wide for HTTPRoute parent resolution: %v", parentGatewayErr), "")
	}
	if routeErr != nil && !gatewayAPIMissing(routeErr) {
		scanner.addProblemCategorized("Gateway API Access", "HTTPRoute list", model.StatusWarn, "api-inspection", fmt.Sprintf("Could not list HTTPRoute objects: %v", routeErr), "")
	}
	if grpcRouteErr != nil && !gatewayAPIMissing(grpcRouteErr) {
		scanner.addProblemCategorized("Gateway API Access", "GRPCRoute list", model.StatusWarn, "api-inspection", fmt.Sprintf("Could not list GRPCRoute objects: %v", grpcRouteErr), "")
	}
	if tlsRouteErr != nil && !gatewayAPIMissing(tlsRouteErr) {
		scanner.addProblemCategorized("Gateway API Access", "TLSRoute list", model.StatusWarn, "api-inspection", fmt.Sprintf("Could not list TLSRoute objects: %v", tlsRouteErr), "")
	}
	if tcpRouteErr != nil && !gatewayAPIMissing(tcpRouteErr) {
		scanner.addProblemCategorized("Gateway API Access", "TCPRoute list", model.StatusWarn, "api-inspection", fmt.Sprintf("Could not list TCPRoute objects: %v", tcpRouteErr), "")
	}
	if udpRouteErr != nil && !gatewayAPIMissing(udpRouteErr) {
		scanner.addProblemCategorized("Gateway API Access", "UDPRoute list", model.StatusWarn, "api-inspection", fmt.Sprintf("Could not list UDPRoute objects: %v", udpRouteErr), "")
	}
	if listenerSetErr != nil && !gatewayAPIMissing(listenerSetErr) {
		scanner.addProblemCategorized("Gateway API Access", "ListenerSet list", model.StatusWarn, "api-inspection", fmt.Sprintf("Could not list ListenerSet objects: %v", listenerSetErr), "")
	}
	if backendTLSPolicyErr != nil && !gatewayAPIMissing(backendTLSPolicyErr) {
		scanner.addProblemCategorized("Gateway API Access", "BackendTLSPolicy list", model.StatusWarn, "api-inspection", fmt.Sprintf("Could not list BackendTLSPolicy objects: %v", backendTLSPolicyErr), "")
	}
	if xBackendTrafficPolicyErr != nil && !gatewayAPIMissing(xBackendTrafficPolicyErr) {
		scanner.addProblemCategorized("Gateway API Access", "XBackendTrafficPolicy list", model.StatusWarn, "api-inspection", fmt.Sprintf("Could not list XBackendTrafficPolicy objects: %v", xBackendTrafficPolicyErr), "")
	}
	if envoyBackendErr != nil && !gatewayAPIMissing(envoyBackendErr) {
		scanner.addProblemCategorized("Gateway API Access", "Envoy Backend list", model.StatusWarn, "api-inspection", fmt.Sprintf("Could not list Envoy Backend objects: %v", envoyBackendErr), "")
	}
	if envoyBackendTrafficPolicyErr != nil && !gatewayAPIMissing(envoyBackendTrafficPolicyErr) {
		scanner.addProblemCategorized("Gateway API Access", "Envoy BackendTrafficPolicy list", model.StatusWarn, "api-inspection", fmt.Sprintf("Could not list Envoy BackendTrafficPolicy objects: %v", envoyBackendTrafficPolicyErr), "")
	}
	if envoyClientTrafficPolicyErr != nil && !gatewayAPIMissing(envoyClientTrafficPolicyErr) {
		scanner.addProblemCategorized("Gateway API Access", "Envoy ClientTrafficPolicy list", model.StatusWarn, "api-inspection", fmt.Sprintf("Could not list Envoy ClientTrafficPolicy objects: %v", envoyClientTrafficPolicyErr), "")
	}
	if envoySecurityPolicyErr != nil && !gatewayAPIMissing(envoySecurityPolicyErr) {
		scanner.addProblemCategorized("Gateway API Access", "Envoy SecurityPolicy list", model.StatusWarn, "api-inspection", fmt.Sprintf("Could not list Envoy SecurityPolicy objects: %v", envoySecurityPolicyErr), "")
	}
	if envoyExtensionPolicyErr != nil && !gatewayAPIMissing(envoyExtensionPolicyErr) {
		scanner.addProblemCategorized("Gateway API Access", "Envoy EnvoyExtensionPolicy list", model.StatusWarn, "api-inspection", fmt.Sprintf("Could not list Envoy EnvoyExtensionPolicy objects: %v", envoyExtensionPolicyErr), "")
	}
	if envoyPatchPolicyErr != nil && !gatewayAPIMissing(envoyPatchPolicyErr) {
		scanner.addProblemCategorized("Gateway API Access", "Envoy EnvoyPatchPolicy list", model.StatusWarn, "api-inspection", fmt.Sprintf("Could not list Envoy EnvoyPatchPolicy objects: %v", envoyPatchPolicyErr), "")
	}
	if envoyProxyErr != nil && !gatewayAPIMissing(envoyProxyErr) {
		scanner.addProblemCategorized("Gateway API Access", "Envoy EnvoyProxy list", model.StatusWarn, "api-inspection", fmt.Sprintf("Could not list Envoy EnvoyProxy objects: %v", envoyProxyErr), "")
	}
	if envoyHTTPRouteFilterErr != nil && !gatewayAPIMissing(envoyHTTPRouteFilterErr) {
		scanner.addProblemCategorized("Gateway API Access", "Envoy HTTPRouteFilter list", model.StatusWarn, "api-inspection", fmt.Sprintf("Could not list Envoy HTTPRouteFilter objects: %v", envoyHTTPRouteFilterErr), "")
	}
	if refGrantErr != nil && !gatewayAPIMissing(refGrantErr) {
		scanner.addProblemCategorized("Gateway API Access", "ReferenceGrant list", model.StatusWarn, "api-inspection", fmt.Sprintf("Could not list ReferenceGrant objects: %v", refGrantErr), "")
	}
	gatewaySortObjects(classes)
	gatewaySortObjects(gateways)
	gatewaySortObjects(parentGateways)
	gatewaySortObjects(routes)
	gatewaySortObjects(grpcRoutes)
	gatewaySortObjects(tlsRoutes)
	gatewaySortObjects(tcpRoutes)
	gatewaySortObjects(udpRoutes)
	gatewaySortObjects(listenerSets)
	gatewaySortObjects(backendTLSPolicies)
	gatewaySortObjects(xBackendTrafficPolicies)
	gatewaySortObjects(envoyBackends)
	gatewaySortObjects(envoyBackendTrafficPolicies)
	gatewaySortObjects(envoyClientTrafficPolicies)
	gatewaySortObjects(envoySecurityPolicies)
	gatewaySortObjects(envoyExtensionPolicies)
	gatewaySortObjects(envoyPatchPolicies)
	gatewaySortObjects(envoyProxies)
	gatewaySortObjects(envoyHTTPRouteFilters)
	gatewaySortObjects(refGrants)

	var classIndex map[string]unstructured.Unstructured
	if classErr == nil {
		classIndex = gatewayClassIndex(classes)
	}
	serviceCache := map[string]*corev1.Service{}
	serviceErrCache := map[string]error{}
	endpointReadyCache := map[string]int{}
	endpointErrCache := map[string]error{}
	routeScope := gatewayRouteScopeForRouteFilter(routes, grpcRoutes, tlsRoutes, tcpRoutes, udpRoutes, opts)

	if intentMode {
		intentRoutes := routes
		switch gatewayPrimaryRouteFamily(intent) {
		case "GRPCRoute":
			intentRoutes = grpcRoutes
		case "TLSRoute":
			intentRoutes = tlsRoutes
		}
		scanner.scanGatewayTrafficIntent(ctx, client, gateways, parentGateways, intentRoutes, refGrants, serviceCache, serviceErrCache, endpointReadyCache, endpointErrCache, intent)
		scanner.finish(len(classes), len(gateways), len(routes))
		dedupeGatewayDiagnoses(report)
		return
	}

	scanner.scanGatewayClasses(classes)
	scanner.scanGateways(ctx, client, gateways, classIndex, refGrants, routeScope, endpointReadyCache, endpointErrCache)
	scanner.scanHTTPRoutes(ctx, client, routes, parentGateways, refGrants, serviceCache, serviceErrCache, endpointReadyCache, endpointErrCache)
	scanner.scanGenericRoutes(ctx, client, "GRPCRoute", grpcRoutes, parentGateways, refGrants, serviceCache, serviceErrCache, endpointReadyCache, endpointErrCache)
	scanner.scanGenericRoutes(ctx, client, "TLSRoute", tlsRoutes, parentGateways, refGrants, serviceCache, serviceErrCache, endpointReadyCache, endpointErrCache)
	scanner.scanGenericRoutes(ctx, client, "TCPRoute", tcpRoutes, parentGateways, refGrants, serviceCache, serviceErrCache, endpointReadyCache, endpointErrCache)
	scanner.scanGenericRoutes(ctx, client, "UDPRoute", udpRoutes, parentGateways, refGrants, serviceCache, serviceErrCache, endpointReadyCache, endpointErrCache)
	scanner.scanListenerSets(ctx, client, listenerSets, parentGateways, refGrants)
	scanner.scanBackendTLSPolicies(ctx, client, backendTLSPolicies, serviceCache, serviceErrCache)
	scanner.scanEnvoyBackends(ctx, client, envoyBackends, routeScope, refGrants)
	scanner.scanEnvoyHTTPRouteFilters(ctx, client, envoyHTTPRouteFilters, routeScope, refGrants)
	scanner.scanEnvoyProxies(envoyProxies)
	gatewayTargets := gatewayPolicyTargetIndexes{
		GatewayClasses: gatewayClassIndex(classes),
		Gateways:       gatewayIndex(parentGateways),
		HTTPRoutes:     gatewayIndex(routes),
		GRPCRoutes:     gatewayIndex(grpcRoutes),
		TLSRoutes:      gatewayIndex(tlsRoutes),
		TCPRoutes:      gatewayIndex(tcpRoutes),
		UDPRoutes:      gatewayIndex(udpRoutes),
	}
	scanner.scanEnvoyPatchPolicies(envoyPatchPolicies, "Envoy Gateway Policy Layer", gatewayTargets, routeScope)
	scanner.scanGatewayPolicyAttachments(ctx, client, xBackendTrafficPolicies, "XBackendTrafficPolicy", "Gateway Policy Layer", nil, gatewayTargets, routeScope, refGrants, serviceCache, serviceErrCache)
	scanner.scanGatewayPolicyAttachments(ctx, client, envoyBackendTrafficPolicies, "Envoy BackendTrafficPolicy", "Envoy Gateway Policy Layer", envoyBackendTrafficPolicyTargetKinds, gatewayTargets, routeScope, refGrants, serviceCache, serviceErrCache)
	scanner.scanGatewayPolicyAttachments(ctx, client, envoyClientTrafficPolicies, "Envoy ClientTrafficPolicy", "Envoy Gateway Policy Layer", envoyClientTrafficPolicyTargetKinds, gatewayTargets, routeScope, refGrants, serviceCache, serviceErrCache)
	scanner.scanGatewayPolicyAttachments(ctx, client, envoySecurityPolicies, "Envoy SecurityPolicy", "Envoy Gateway Policy Layer", envoySecurityPolicyTargetKinds, gatewayTargets, routeScope, refGrants, serviceCache, serviceErrCache)
	scanner.scanGatewayPolicyAttachments(ctx, client, envoyExtensionPolicies, "Envoy EnvoyExtensionPolicy", "Envoy Gateway Policy Layer", envoyExtensionPolicyTargetKinds, gatewayTargets, routeScope, refGrants, serviceCache, serviceErrCache)

	scanner.finish(len(classes), len(gateways), len(routes), len(grpcRoutes), len(tlsRoutes), len(tcpRoutes), len(udpRoutes), len(listenerSets), len(backendTLSPolicies), len(xBackendTrafficPolicies), len(envoyBackends), len(envoyBackendTrafficPolicies), len(envoyClientTrafficPolicies), len(envoySecurityPolicies), len(envoyExtensionPolicies), len(envoyPatchPolicies), len(envoyProxies), len(envoyHTTPRouteFilters))
	dedupeGatewayDiagnoses(report)
}

type gatewayScanner struct {
	report           *model.Report
	opts             GatewayOptions
	limit            int
	problemCount     int
	truncated        bool
	scannedClass     int
	scannedGate      int
	scannedRoutes    int
	scannedOther     int
	trafficIntent    bool
	trafficRouteKind string
}

func (s *gatewayScanner) addProblem(layer, check string, status model.Status, message string, diagnosis string) {
	s.addProblemCategorized(layer, check, status, "", message, diagnosis)
}

func (s *gatewayScanner) addProblemCategorized(layer, check string, status model.Status, category string, message string, diagnosis string) {
	if s.limit <= 0 {
		s.limit = 50
	}
	s.problemCount++
	if s.problemCount <= s.limit {
		s.report.AddCategorized(layer, check, status, category, message)
		if diagnosis != "" {
			s.report.Diagnose(diagnosis)
		}
		return
	}
	s.truncated = true
}

func (s *gatewayScanner) addWide(layer, check string, status model.Status, message string) {
	if s.opts.Wide {
		s.report.Add(layer, check, status, message)
	}
}

func (s *gatewayScanner) finish(classCount, gatewayCount, routeCount int, extraCounts ...int) {
	s.addFilterMissProblems()
	filterText := s.filterText()
	if filterText != "" {
		filterText = " " + filterText
	}
	if s.trafficIntent {
		routeKind := defaultString(s.trafficRouteKind, "HTTPRoute")
		s.report.Add("Gateway API Access", "traffic scope", model.StatusInfo, fmt.Sprintf("Evaluated %d Gateway and %d %s object(s) for the requested traffic intent%s.", s.scannedGate, s.scannedRoutes, routeKind, filterText))
	} else {
		s.report.Add("Gateway API Access", "scan summary", model.StatusInfo, fmt.Sprintf("Scanned %d GatewayClass, %d Gateway, %d HTTPRoute, and %d other Gateway API object(s)%s.", s.scannedClass, s.scannedGate, s.scannedRoutes, s.scannedOther, filterText))
	}
	if s.problemCount == 0 && !s.trafficIntent {
		s.report.Add("Gateway API Scan", "obvious problems", model.StatusPass, "No obvious Gateway API status, attachment, reference, or backend endpoint problems found.")
	}
	if s.truncated {
		s.report.AddCategorized("Gateway API Scan", "limit", model.StatusWarn, "output-limited", fmt.Sprintf("Scan found more than %d problem detail(s). Re-run with --limit %d or narrower filters for the full list.", s.limit, s.limit*2))
	}
	totalExtra := 0
	for _, count := range extraCounts {
		totalExtra += count
	}
	if classCount == 0 && gatewayCount == 0 && routeCount == 0 && totalExtra == 0 {
		s.report.Add("Gateway API Scan", "objects", model.StatusInfo, "Gateway API v1 is available, but no Gateway API objects matched the scan scope.")
	}
}

func gatewayTrafficIntentFromOptions(opts GatewayOptions) (gatewayTrafficIntent, bool, error) {
	hasURL := strings.TrimSpace(opts.URL) != ""
	hasPartialIntent := strings.TrimSpace(opts.Host) != "" ||
		strings.TrimSpace(opts.Scheme) != "" ||
		opts.Port != 0 ||
		strings.TrimSpace(opts.Protocol) != "" ||
		strings.TrimSpace(opts.Path) != "" ||
		strings.TrimSpace(opts.Method) != "" ||
		len(opts.HTTPHeaders) > 0 ||
		strings.TrimSpace(opts.GRPCService) != "" ||
		strings.TrimSpace(opts.GRPCMethod) != "" ||
		strings.TrimSpace(opts.ExpectService) != ""
	if !hasURL && !hasPartialIntent {
		return gatewayTrafficIntent{}, false, nil
	}
	protocol, err := gatewayNormalizeProtocol(opts.Protocol)
	if err != nil {
		return gatewayTrafficIntent{}, true, err
	}
	intent := gatewayTrafficIntent{
		Scheme:      strings.ToLower(strings.TrimSpace(opts.Scheme)),
		Host:        gatewayNormalizeHostname(opts.Host),
		Port:        opts.Port,
		Protocol:    protocol,
		Path:        strings.TrimSpace(opts.Path),
		Method:      strings.ToUpper(strings.TrimSpace(opts.Method)),
		Headers:     opts.HTTPHeaders,
		GRPCService: strings.TrimSpace(opts.GRPCService),
		GRPCMethod:  strings.TrimSpace(opts.GRPCMethod),
	}
	if intent.Path != "" && !strings.HasPrefix(intent.Path, "/") {
		return gatewayTrafficIntent{}, true, fmt.Errorf("Gateway traffic intent path %q is invalid; paths must start with /.", intent.Path)
	}
	if hasURL {
		if opts.Host != "" || opts.Scheme != "" || opts.Port != 0 || opts.Path != "" {
			return gatewayTrafficIntent{}, true, fmt.Errorf("--url owns scheme, host, port, path, and query; do not combine it with --host, --scheme, --port, or --path.")
		}
		parsed, err := url.Parse(strings.TrimSpace(opts.URL))
		if err != nil || parsed.Scheme == "" || parsed.Host == "" {
			return gatewayTrafficIntent{}, true, fmt.Errorf("Invalid Gateway traffic URL %q. Provide an absolute URL such as https://payments.example.com/api.", opts.URL)
		}
		intent.Scheme = strings.ToLower(parsed.Scheme)
		host := parsed.Hostname()
		intent.Host = gatewayNormalizeHostname(host)
		if port := parsed.Port(); port != "" {
			parsedPort, err := strconv.Atoi(port)
			if err != nil || parsedPort <= 0 || parsedPort > 65535 {
				return gatewayTrafficIntent{}, true, fmt.Errorf("Invalid Gateway traffic URL port %q.", port)
			}
			intentPort, _ := int32PortFromInt(parsedPort)
			intent.Port = intentPort
		} else {
			intent.Port = gatewayDefaultPortForScheme(intent.Scheme)
		}
		intent.Path = parsed.EscapedPath()
		if intent.Path == "" {
			intent.Path = "/"
		}
		intent.Query = parsed.Query()
	}
	if intent.Host == "" {
		return gatewayTrafficIntent{}, true, fmt.Errorf("Gateway traffic intent needs --host or --url; --path, --method, and --header only narrow a request after the host is known.")
	}
	if intent.Protocol == "auto" {
		intent.Protocol = gatewayInferApplicationProtocol(intent)
	}
	return gatewayFinalizeTrafficIntent(intent), true, nil
}

func gatewayNormalizeProtocol(raw string) (string, error) {
	value := strings.ToLower(strings.TrimSpace(raw))
	if value == "" {
		return "auto", nil
	}
	switch value {
	case "auto", "http", "https", "grpc", "tls":
		return value, nil
	default:
		return "", fmt.Errorf("Invalid Gateway traffic protocol %q. Use auto, http, https, grpc, or tls.", raw)
	}
}

func gatewayInferApplicationProtocol(intent gatewayTrafficIntent) string {
	if intent.GRPCService != "" || intent.GRPCMethod != "" {
		return "grpc"
	}
	if intent.Scheme == "http" || intent.Scheme == "https" {
		return intent.Scheme
	}
	if intent.Path != "" || intent.Method != "" || len(intent.Headers) > 0 || len(intent.Query) > 0 {
		return "http"
	}
	if intent.Port == 443 {
		return "tls"
	}
	return "http"
}

func gatewayFinalizeTrafficIntent(intent gatewayTrafficIntent) gatewayTrafficIntent {
	if intent.Protocol == "" || intent.Protocol == "auto" {
		intent.Protocol = gatewayInferApplicationProtocol(intent)
	}
	if len(intent.RouteFamilies) == 0 {
		intent.RouteFamilies = gatewayRouteFamiliesForProtocol(intent.Protocol, intent)
	}
	if gatewayTrafficIntentUsesHTTP(intent) && intent.Path == "" {
		intent.Path = "/"
	}
	if gatewayTrafficIntentUsesHTTP(intent) && intent.Method == "" {
		intent.Method = "GET"
	}
	if intent.Port == 0 {
		intent.Port = gatewayDefaultPortForIntent(intent)
	}
	if intent.Scheme == "" {
		intent.Scheme = gatewayDefaultSchemeForProtocol(intent.Protocol)
	}
	return intent
}

func gatewayRouteFamiliesForProtocol(protocol string, intent gatewayTrafficIntent) []string {
	switch protocol {
	case "grpc":
		return []string{"GRPCRoute"}
	case "tls":
		return []string{"TLSRoute"}
	case "http", "https":
		return []string{"HTTPRoute"}
	default:
		if intent.GRPCService != "" || intent.GRPCMethod != "" {
			return []string{"GRPCRoute"}
		}
		return []string{"HTTPRoute"}
	}
}

func gatewayTrafficIntentUsesHTTP(intent gatewayTrafficIntent) bool {
	for _, family := range intent.RouteFamilies {
		if family == "HTTPRoute" {
			return true
		}
	}
	return false
}

func gatewayPrimaryRouteFamily(intent gatewayTrafficIntent) string {
	intent = gatewayFinalizeTrafficIntent(intent)
	if len(intent.RouteFamilies) == 0 {
		return "HTTPRoute"
	}
	return intent.RouteFamilies[0]
}

func gatewayDefaultPortForIntent(intent gatewayTrafficIntent) int32 {
	if port := gatewayDefaultPortForScheme(intent.Scheme); port != 0 {
		return port
	}
	switch intent.Protocol {
	case "https", "tls":
		return 443
	case "grpc":
		return 0
	default:
		return 80
	}
}

func gatewayDefaultSchemeForProtocol(protocol string) string {
	switch protocol {
	case "https":
		return "https"
	case "http":
		return "http"
	default:
		return ""
	}
}

func gatewayDefaultPortForScheme(scheme string) int32 {
	switch strings.ToLower(strings.TrimSpace(scheme)) {
	case "http":
		return 80
	case "https":
		return 443
	default:
		return 0
	}
}

func dedupeGatewayDiagnoses(report *model.Report) {
	if len(report.Diagnoses) < 2 {
		return
	}
	routeConcrete := map[string]bool{}
	routeNoParents := map[string]bool{}
	routeRejected := map[string]bool{}
	gatewayConcrete := map[string]bool{}
	listenerSetRejected := map[string]bool{}
	backendTLSPolicyConcrete := map[string]bool{}
	trafficTLSConcrete := false
	for _, diagnosis := range report.Diagnoses {
		message := diagnosis.Message
		if route := gatewayDiagnosisHTTPRoute(message); route != "" && gatewayDiagnosisIsConcreteRouteBackend(message) {
			routeConcrete[route] = true
		}
		if route := gatewayDiagnosisHTTPRoute(message); route != "" && gatewayDiagnosisIsRouteUnattached(message) {
			routeNoParents[route] = true
		}
		if route := gatewayDiagnosisHTTPRoute(message); route != "" && gatewayDiagnosisIsRouteRejected(message) {
			routeRejected[route] = true
		}
		if gateway := gatewayDiagnosisGateway(message); gateway != "" && gatewayDiagnosisIsConcreteGatewayTLS(message) {
			gatewayConcrete[gateway] = true
		}
		if listenerSet := gatewayDiagnosisListenerSet(message); listenerSet != "" && gatewayDiagnosisIsListenerSetRejected(message) {
			listenerSetRejected[listenerSet] = true
		}
		if policy := gatewayDiagnosisBackendTLSPolicy(message); policy != "" && gatewayDiagnosisIsConcreteBackendTLSPolicy(message) {
			backendTLSPolicyConcrete[policy] = true
		}
		if gatewayDiagnosisIsConcreteTrafficTLS(message) {
			trafficTLSConcrete = true
		}
	}
	var kept []model.Diagnosis
	for _, diagnosis := range report.Diagnoses {
		message := diagnosis.Message
		if route := gatewayDiagnosisHTTPRoute(message); route != "" && routeConcrete[route] && gatewayDiagnosisIsRouteStatusReference(message) {
			continue
		}
		if route := gatewayDiagnosisHTTPRoute(message); route != "" && routeNoParents[route] && gatewayDiagnosisIsRouteNoParentStatus(message) {
			continue
		}
		if route := gatewayDiagnosisHTTPRoute(message); route != "" && routeRejected[route] && gatewayDiagnosisIsRouteNoAcceptedParent(message) {
			continue
		}
		if route := gatewayDiagnosisHTTPRoute(message); route != "" && routeRejected[route] && gatewayDiagnosisIsConcreteRouteBackend(message) {
			continue
		}
		if gateway := gatewayDiagnosisListenerGateway(message); gateway != "" && gatewayConcrete[gateway] && gatewayDiagnosisIsListenerStatus(message) {
			continue
		}
		if listenerSet := gatewayDiagnosisListenerSet(message); listenerSet != "" && listenerSetRejected[listenerSet] && gatewayDiagnosisIsListenerSetProgrammedStatus(message) {
			continue
		}
		if listenerSet := gatewayDiagnosisListenerSet(message); listenerSet != "" && listenerSetRejected[listenerSet] && gatewayDiagnosisIsListenerSetTLSReference(message) {
			continue
		}
		if policy := gatewayDiagnosisBackendTLSPolicy(message); policy != "" && backendTLSPolicyConcrete[policy] && gatewayDiagnosisIsBackendTLSPolicyStatus(message) {
			continue
		}
		if trafficTLSConcrete && gatewayDiagnosisIsTrafficTLSStatus(message) {
			continue
		}
		if trafficTLSConcrete && strings.HasPrefix(message, "Gateway listener(s) matched ") && strings.Contains(message, "but no HTTPRoute attaches to them") {
			continue
		}
		kept = append(kept, diagnosis)
	}
	report.Diagnoses = kept
}

func gatewayDiagnosisHTTPRoute(message string) string {
	if !strings.HasPrefix(message, "HTTPRoute ") &&
		!strings.HasPrefix(message, "GRPCRoute ") &&
		!strings.HasPrefix(message, "TLSRoute ") {
		return ""
	}
	fields := strings.Fields(message)
	if len(fields) < 2 {
		return ""
	}
	return fields[1]
}

func gatewayDiagnosisListenerSet(message string) string {
	if !strings.HasPrefix(message, "ListenerSet ") {
		return ""
	}
	fields := strings.Fields(message)
	if len(fields) < 2 {
		return ""
	}
	return fields[1]
}

func gatewayDiagnosisBackendTLSPolicy(message string) string {
	if !strings.HasPrefix(message, "BackendTLSPolicy ") {
		return ""
	}
	fields := strings.Fields(message)
	if len(fields) < 2 {
		return ""
	}
	return fields[1]
}

func gatewayDiagnosisGateway(message string) string {
	if !strings.HasPrefix(message, "Gateway ") {
		return ""
	}
	fields := strings.Fields(message)
	if len(fields) < 2 {
		return ""
	}
	return fields[1]
}

func gatewayDiagnosisListenerGateway(message string) string {
	if !strings.HasPrefix(message, "Gateway listener ") {
		return ""
	}
	fields := strings.Fields(message)
	if len(fields) < 3 {
		return ""
	}
	listener := fields[2]
	index := strings.LastIndex(listener, "/")
	if index <= 0 {
		return ""
	}
	return listener[:index]
}

func gatewayDiagnosisIsConcreteRouteBackend(message string) bool {
	return strings.Contains(message, " routes to Service ") ||
		strings.Contains(message, " routes to backend kind ") ||
		strings.Contains(message, " backendRef ") ||
		strings.Contains(message, " backendRef with no name") ||
		strings.Contains(message, " has no backendRefs")
}

func gatewayDiagnosisIsRouteStatusReference(message string) bool {
	return strings.Contains(message, " has unresolved references for Gateway ")
}

func gatewayDiagnosisIsRouteUnattached(message string) bool {
	return strings.Contains(message, " is not attached to any Gateway")
}

func gatewayDiagnosisIsRouteNoParentStatus(message string) bool {
	return strings.Contains(message, " has no parent status")
}

func gatewayDiagnosisIsRouteRejected(message string) bool {
	return strings.Contains(message, " is not accepted by Gateway ")
}

func gatewayDiagnosisIsRouteNoAcceptedParent(message string) bool {
	return strings.Contains(message, " is not currently accepted by any Gateway parent")
}

func gatewayDiagnosisIsConcreteGatewayTLS(message string) bool {
	return strings.Contains(message, " references missing or unreadable TLS Secret ") ||
		strings.Contains(message, " references TLS Secret ") && strings.Contains(message, "does not grant that reference")
}

func gatewayDiagnosisIsListenerStatus(message string) bool {
	return strings.HasPrefix(message, "Gateway listener ") &&
		(strings.Contains(message, " is not Programmed:") ||
			strings.Contains(message, " is not ResolvedRefs:"))
}

func gatewayDiagnosisIsConcreteTrafficTLS(message string) bool {
	return strings.HasPrefix(message, "HTTPS request matched Gateway listener ") &&
		strings.Contains(message, "TLS Secret ") &&
		(strings.Contains(message, "missing or unreadable") ||
			strings.Contains(message, "without a matching ReferenceGrant"))
}

func gatewayDiagnosisIsTrafficTLSStatus(message string) bool {
	return strings.HasPrefix(message, "HTTPS request matched Gateway listener ") &&
		(strings.Contains(message, "listener is not Programmed:") ||
			strings.Contains(message, "references are not resolved:"))
}

func gatewayDiagnosisIsListenerSetRejected(message string) bool {
	return strings.HasPrefix(message, "ListenerSet ") && strings.Contains(message, " is not Accepted:")
}

func gatewayDiagnosisIsListenerSetProgrammedStatus(message string) bool {
	return strings.HasPrefix(message, "ListenerSet ") && strings.Contains(message, " is not Programmed:")
}

func gatewayDiagnosisIsListenerSetTLSReference(message string) bool {
	return strings.HasPrefix(message, "ListenerSet ") &&
		(strings.Contains(message, " references missing or unreadable TLS Secret ") ||
			strings.Contains(message, " references TLS Secret ") && strings.Contains(message, "does not grant that reference"))
}

func gatewayDiagnosisIsConcreteBackendTLSPolicy(message string) bool {
	return strings.HasPrefix(message, "BackendTLSPolicy ") &&
		(strings.Contains(message, " targets Service ") ||
			strings.Contains(message, " CA ConfigMap ") ||
			strings.Contains(message, " does not specify caCertificateRefs") ||
			strings.Contains(message, " specifies both caCertificateRefs") ||
			strings.Contains(message, " uses unrecognized wellKnownCACertificates"))
}

func gatewayDiagnosisIsBackendTLSPolicyStatus(message string) bool {
	return strings.HasPrefix(message, "BackendTLSPolicy ") &&
		(strings.Contains(message, " is not Accepted:") ||
			strings.Contains(message, " is not ResolvedRefs:"))
}

func (s *gatewayScanner) addFilterMissProblems() {
	if s.opts.GatewayClass != "" && s.scannedClass == 0 {
		s.addProblem("Gateway API Scan", "gateway-class filter", model.StatusFail, fmt.Sprintf("No GatewayClass matched %q.", s.opts.GatewayClass), fmt.Sprintf("GatewayClass %q was not found in the cluster.", s.opts.GatewayClass))
	}
	if s.opts.GatewayRef != "" && s.scannedGate == 0 {
		s.addProblem("Gateway API Scan", "gateway filter", model.StatusFail, fmt.Sprintf("No Gateway matched %q.", s.opts.GatewayRef), fmt.Sprintf("Gateway %q was not found in the scan scope.", s.opts.GatewayRef))
	}
	if s.opts.RouteRef != "" && s.scannedRoutes == 0 {
		s.addProblem("Gateway API Scan", "route filter", model.StatusFail, fmt.Sprintf("No Gateway API Route matched %q.", s.opts.RouteRef), fmt.Sprintf("Gateway API Route %q was not found in the scan scope.", s.opts.RouteRef))
	}
}

func (s *gatewayScanner) filterText() string {
	var filters []string
	if s.opts.Namespace != "" {
		filters = append(filters, "namespace="+s.opts.Namespace)
	}
	if s.opts.GatewayClass != "" {
		filters = append(filters, "gatewayClass="+s.opts.GatewayClass)
	}
	if s.opts.GatewayRef != "" {
		filters = append(filters, "gateway="+s.opts.GatewayRef)
	}
	if s.opts.RouteRef != "" {
		filters = append(filters, "route="+s.opts.RouteRef)
	}
	if len(filters) == 0 {
		return ""
	}
	return "with filters: " + strings.Join(filters, ", ")
}

func (s *gatewayScanner) scanGatewayClasses(classes []unstructured.Unstructured) {
	for _, class := range classes {
		if s.opts.GatewayClass != "" && class.GetName() != s.opts.GatewayClass {
			continue
		}
		s.scannedClass++
		if controller := stringField(class.Object, "spec", "controllerName"); controller == "" {
			s.addProblem("GatewayClass Layer", class.GetName(), model.StatusFail, fmt.Sprintf("GatewayClass %q has no spec.controllerName.", class.GetName()), fmt.Sprintf("GatewayClass %q has no controllerName, so no Gateway controller can claim it.", class.GetName()))
		}
		s.addConditionProblems("GatewayClass Layer", "GatewayClass", class.GetName(), class.Object, []gatewayConditionRule{
			{Type: string(gatewayv1.GatewayClassConditionStatusAccepted), FalseStatus: model.StatusFail, MissingStatus: model.StatusWarn},
		})
		s.addWide("GatewayClass Layer", class.GetName(), model.StatusPass, fmt.Sprintf("GatewayClass %q scanned.", class.GetName()))
	}
}

func (s *gatewayScanner) scanGateways(ctx context.Context, client *kube.Client, gateways []unstructured.Unstructured, classes map[string]unstructured.Unstructured, refGrants []unstructured.Unstructured, routeScope gatewayRouteScope, endpointReadyCache map[string]int, endpointErrCache map[string]error) {
	filter := parseGatewayObjectRef(s.opts.GatewayRef, s.opts.Namespace)
	for _, gateway := range gateways {
		if !gatewayObjectRefMatches(gateway, filter) {
			continue
		}
		gwName := objectRefText(gateway)
		if routeScope.Active && !routeScope.Gateways[gwName] {
			continue
		}
		className := stringField(gateway.Object, "spec", "gatewayClassName")
		if s.opts.GatewayClass != "" && className != s.opts.GatewayClass {
			continue
		}
		s.scannedGate++
		if className == "" {
			s.addProblem("Gateway Layer", gwName, model.StatusFail, fmt.Sprintf("Gateway %s has no spec.gatewayClassName.", gwName), fmt.Sprintf("Gateway %s has no gatewayClassName, so no GatewayClass/controller can program it.", gwName))
		} else if classes != nil {
			if _, ok := classes[className]; ok {
				// Class exists and will be checked in the GatewayClass layer.
			} else {
				s.addProblem("Gateway Layer", gwName+" class", model.StatusFail, fmt.Sprintf("Gateway %s references missing GatewayClass %q.", gwName, className), fmt.Sprintf("Gateway %s references GatewayClass %q, but that GatewayClass was not found.", gwName, className))
			}
		}

		s.addConditionProblems("Gateway Layer", "Gateway", gwName, gateway.Object, []gatewayConditionRule{
			{Type: string(gatewayv1.GatewayConditionAccepted), FalseStatus: model.StatusFail, MissingStatus: model.StatusWarn},
			{Type: string(gatewayv1.GatewayConditionProgrammed), FalseStatus: model.StatusFail, MissingStatus: model.StatusWarn},
		})
		if addresses := sliceField(gateway.Object, "status", "addresses"); len(addresses) == 0 {
			s.addProblem("Gateway Layer", gwName+" address", model.StatusWarn, fmt.Sprintf("Gateway %s has no status.addresses entries.", gwName), fmt.Sprintf("Gateway %s has no assigned address, so external clients may have no usable entry point yet.", gwName))
		}
		s.scanGatewayListeners(ctx, client, gateway, refGrants, routeScope.listenerFilter(gwName))
		s.scanGatewayDataplane(ctx, client, gateway, endpointReadyCache, endpointErrCache)
		s.addWide("Gateway Layer", gwName, model.StatusPass, fmt.Sprintf("Gateway %s scanned.", gwName))
	}
}

func (s *gatewayScanner) scanGatewayDataplane(ctx context.Context, client *kube.Client, gateway unstructured.Unstructured, endpointReadyCache map[string]int, endpointErrCache map[string]error) {
	services, err := gatewayImplementationServices(ctx, client, gateway)
	gwName := objectRefText(gateway)
	if err != nil {
		s.addProblemCategorized("Gateway Dataplane Layer", gwName+" services", model.StatusWarn, "api-inspection", fmt.Sprintf("Could not list implementation Services for Gateway %s: %v", gwName, err), "")
		return
	}
	if len(services) == 0 {
		s.addWide("Gateway Dataplane Layer", gwName+" services", model.StatusInfo, fmt.Sprintf("No implementation Service with label gateway.networking.k8s.io/gateway-name=%s was found for Gateway %s.", gateway.GetName(), gwName))
		return
	}
	listeners := sliceField(gateway.Object, "spec", "listeners")
	for _, service := range services {
		serviceName := service.Namespace + "/" + service.Name
		for _, raw := range listeners {
			listener, ok := raw.(map[string]interface{})
			if !ok {
				continue
			}
			listenerName := stringField(listener, "name")
			listenerPort := int32FieldDefault(listener, "port", 0)
			if listenerPort == 0 {
				continue
			}
			if !serviceHasGatewayPort(&service, listenerPort) {
				s.addProblem("Gateway Dataplane Layer", gwName+"/"+listenerName+" service port", model.StatusFail, fmt.Sprintf("Gateway %s listener %s port %d is not exposed by implementation Service %s. Service ports: %s", gwName, listenerName, listenerPort, serviceName, servicePorts(&service)), fmt.Sprintf("Gateway %s listener %s uses port %d, but implementation Service %s exposes %s.", gwName, listenerName, listenerPort, serviceName, servicePorts(&service)))
			}
		}
		if service.Spec.Type == corev1.ServiceTypeLoadBalancer && len(service.Status.LoadBalancer.Ingress) == 0 {
			s.addProblem("Gateway Dataplane Layer", serviceName+" load balancer", model.StatusWarn, fmt.Sprintf("Gateway implementation Service %s is LoadBalancer but has no external ingress address yet.", serviceName), fmt.Sprintf("Gateway implementation Service %s has no LoadBalancer ingress address yet.", serviceName))
		}
		ready, err := cachedReadyEndpointCount(ctx, client, service.Namespace, service.Name, endpointReadyCache, endpointErrCache)
		if err != nil {
			s.addProblemCategorized("Gateway Dataplane Layer", serviceName+" endpoints", model.StatusWarn, "api-inspection", fmt.Sprintf("Could not read EndpointSlices for Gateway implementation Service %s: %v", serviceName, err), "")
			continue
		}
		if ready == 0 {
			s.addProblem("Gateway Dataplane Layer", serviceName+" endpoints", model.StatusFail, fmt.Sprintf("Gateway implementation Service %s has no ready EndpointSlice addresses.", serviceName), fmt.Sprintf("Gateway implementation Service %s has no ready endpoints, so Gateway traffic has no ready dataplane pod.", serviceName))
			continue
		}
		s.addWide("Gateway Dataplane Layer", serviceName+" endpoints", model.StatusPass, fmt.Sprintf("Gateway implementation Service %s has %d ready endpoint address(es).", serviceName, ready))
	}
}

func (s *gatewayScanner) scanGatewayListeners(ctx context.Context, client *kube.Client, gateway unstructured.Unstructured, refGrants []unstructured.Unstructured, listenerFilter map[string]bool) {
	listeners := sliceField(gateway.Object, "spec", "listeners")
	statusListeners := gatewayStatusListeners(gateway.Object)
	gwName := objectRefText(gateway)
	if len(listeners) == 0 {
		s.addProblem("Listener Layer", gwName, model.StatusFail, fmt.Sprintf("Gateway %s has no spec.listeners entries.", gwName), fmt.Sprintf("Gateway %s has no listeners, so it cannot accept external traffic.", gwName))
		return
	}
	for _, raw := range listeners {
		listener, ok := raw.(map[string]interface{})
		if !ok {
			continue
		}
		name := stringField(listener, "name")
		if listenerFilter != nil && !listenerFilter[name] {
			continue
		}
		check := gwName + "/" + name
		status := statusListeners[name]
		s.addListenerConditionProblems(check, status)
		s.scanListenerTLSRefs(ctx, client, gateway, listener, refGrants)
	}
}

func (s *gatewayScanner) addListenerConditionProblems(check string, status map[string]interface{}) {
	if len(status) == 0 {
		s.addProblem("Listener Layer", check, model.StatusWarn, fmt.Sprintf("Listener %s has no status entry.", check), "")
		return
	}
	for _, rule := range []gatewayConditionRule{
		{Type: string(gatewayv1.ListenerConditionAccepted), FalseStatus: model.StatusFail, MissingStatus: model.StatusWarn},
		{Type: string(gatewayv1.ListenerConditionProgrammed), FalseStatus: model.StatusFail, MissingStatus: model.StatusWarn},
		{Type: string(gatewayv1.ListenerConditionResolvedRefs), FalseStatus: model.StatusFail, MissingStatus: model.StatusWarn},
	} {
		cond, ok := conditionByType(status, rule.Type)
		if !ok {
			if rule.MissingStatus != "" {
				s.addProblem("Listener Layer", check+" "+rule.Type, rule.MissingStatus, fmt.Sprintf("Listener %s has no %s condition.", check, rule.Type), "")
			}
			continue
		}
		if strings.EqualFold(cond.Status, "False") {
			s.addProblem("Listener Layer", check+" "+rule.Type, rule.FalseStatus, fmt.Sprintf("Listener %s condition %s=False: %s%s", check, rule.Type, cond.Reason, conditionMessageSuffix(cond.Message)), fmt.Sprintf("Gateway listener %s is not %s: %s%s", check, rule.Type, cond.Reason, conditionMessageSuffix(cond.Message)))
		}
	}
	if cond, ok := conditionByType(status, string(gatewayv1.ListenerConditionConflicted)); ok && strings.EqualFold(cond.Status, "True") {
		s.addProblem("Listener Layer", check+" Conflicted", model.StatusFail, fmt.Sprintf("Listener %s condition Conflicted=True: %s%s", check, cond.Reason, conditionMessageSuffix(cond.Message)), fmt.Sprintf("Gateway listener %s has a listener conflict: %s%s", check, cond.Reason, conditionMessageSuffix(cond.Message)))
	}
}

func (s *gatewayScanner) scanListenerTLSRefs(ctx context.Context, client *kube.Client, gateway unstructured.Unstructured, listener map[string]interface{}, refGrants []unstructured.Unstructured) {
	certRefs := sliceField(listener, "tls", "certificateRefs")
	if len(certRefs) == 0 {
		return
	}
	gwName := objectRefText(gateway)
	for _, raw := range certRefs {
		ref, ok := raw.(map[string]interface{})
		if !ok {
			continue
		}
		name := stringField(ref, "name")
		if name == "" {
			continue
		}
		group := stringField(ref, "group")
		kind := defaultString(stringField(ref, "kind"), "Secret")
		namespace := defaultString(stringField(ref, "namespace"), gateway.GetNamespace())
		check := fmt.Sprintf("%s cert %s/%s", gwName, namespace, name)
		if group != "" || kind != "Secret" {
			s.addProblemCategorized("TLS Reference Layer", check, model.StatusWarn, "unsupported-ref", fmt.Sprintf("Gateway %s listener certificateRef %s/%s is %s/%s; KNM only validates core Secret refs right now.", gwName, namespace, name, group, kind), "")
			continue
		}
		if namespace != gateway.GetNamespace() && !referenceGrantAllows(refGrants, gatewayv1.GroupName, "Gateway", gateway.GetNamespace(), "", "Secret", name, namespace) {
			s.addProblem("TLS Reference Layer", check, model.StatusFail, fmt.Sprintf("Gateway %s references cross-namespace TLS Secret %s/%s without a matching ReferenceGrant.", gwName, namespace, name), fmt.Sprintf("Gateway %s references TLS Secret %s/%s across namespaces, but the Secret namespace does not grant that reference.", gwName, namespace, name))
			continue
		}
		if _, err := client.Core.CoreV1().Secrets(namespace).Get(ctx, name, metav1.GetOptions{}); err != nil {
			s.addProblem("TLS Reference Layer", check, model.StatusFail, fmt.Sprintf("Gateway %s references TLS Secret %s/%s, but it was not found or is unreadable: %v", gwName, namespace, name, err), fmt.Sprintf("Gateway %s references missing or unreadable TLS Secret %s/%s.", gwName, namespace, name))
		}
	}
}

func (s *gatewayScanner) scanHTTPRoutes(ctx context.Context, client *kube.Client, routes []unstructured.Unstructured, gateways []unstructured.Unstructured, refGrants []unstructured.Unstructured, serviceCache map[string]*corev1.Service, serviceErrCache map[string]error, endpointReadyCache map[string]int, endpointErrCache map[string]error) {
	filter := parseGatewayObjectRef(s.opts.RouteRef, s.opts.Namespace)
	gatewayFilter := parseGatewayObjectRef(s.opts.GatewayRef, s.opts.Namespace)
	gatewayIndex := gatewayIndex(gateways)
	for _, route := range routes {
		if !gatewayObjectRefMatches(route, filter) {
			continue
		}
		if !routeMatchesGatewayFilter(route, gatewayFilter) {
			continue
		}
		s.scannedRoutes++
		routeName := objectRefText(route)
		if s.scanRouteParents("HTTPRoute", route, gatewayIndex) {
			s.scanRouteBackendRefs(ctx, client, "HTTPRoute", route, refGrants, serviceCache, serviceErrCache, endpointReadyCache, endpointErrCache)
		}
		s.addWide("HTTPRoute Layer", routeName, model.StatusPass, fmt.Sprintf("HTTPRoute %s scanned.", routeName))
	}
}

func (s *gatewayScanner) scanGenericRoutes(ctx context.Context, client *kube.Client, kind string, routes []unstructured.Unstructured, gateways []unstructured.Unstructured, refGrants []unstructured.Unstructured, serviceCache map[string]*corev1.Service, serviceErrCache map[string]error, endpointReadyCache map[string]int, endpointErrCache map[string]error) {
	filter := parseGatewayObjectRef(s.opts.RouteRef, s.opts.Namespace)
	gatewayFilter := parseGatewayObjectRef(s.opts.GatewayRef, s.opts.Namespace)
	gatewayIndex := gatewayIndex(gateways)
	for _, route := range routes {
		if !gatewayObjectRefMatches(route, filter) {
			continue
		}
		if !routeMatchesGatewayFilter(route, gatewayFilter) {
			continue
		}
		if s.opts.RouteRef != "" {
			s.scannedRoutes++
		} else {
			s.scannedOther++
		}
		routeName := objectRefText(route)
		if s.scanRouteParents(kind, route, gatewayIndex) {
			s.scanRouteBackendRefs(ctx, client, kind, route, refGrants, serviceCache, serviceErrCache, endpointReadyCache, endpointErrCache)
		}
		s.addWide(kind+" Layer", routeName, model.StatusPass, fmt.Sprintf("%s %s scanned.", kind, routeName))
	}
}

func (s *gatewayScanner) scanListenerSets(ctx context.Context, client *kube.Client, listenerSets []unstructured.Unstructured, gateways []unstructured.Unstructured, refGrants []unstructured.Unstructured) {
	filter := parseGatewayObjectRef(s.opts.GatewayRef, s.opts.Namespace)
	gatewayIndex := gatewayIndex(gateways)
	for _, listenerSet := range listenerSets {
		parent := mapField(listenerSet.Object, "spec", "parentRef")
		parentName := stringField(parent, "name")
		parentNS := defaultString(stringField(parent, "namespace"), listenerSet.GetNamespace())
		if filter.Name != "" && (parentName != filter.Name || filter.Namespace != "" && parentNS != filter.Namespace) {
			continue
		}
		s.scannedOther++
		name := objectRefText(listenerSet)
		if parentName == "" {
			s.addProblem("ListenerSet Layer", name+" parent", model.StatusFail, fmt.Sprintf("ListenerSet %s has no spec.parentRef.name.", name), fmt.Sprintf("ListenerSet %s has no parent Gateway reference, so its listeners cannot be attached.", name))
		} else if _, ok := gatewayIndex[parentNS+"/"+parentName]; !ok {
			s.addProblem("ListenerSet Layer", name+" parent", model.StatusFail, fmt.Sprintf("ListenerSet %s references missing parent Gateway %s/%s.", name, parentNS, parentName), fmt.Sprintf("ListenerSet %s references Gateway %s/%s, but that Gateway was not found.", name, parentNS, parentName))
		}
		s.addConditionProblems("ListenerSet Layer", "ListenerSet", name, listenerSet.Object, []gatewayConditionRule{
			{Type: "Accepted", FalseStatus: model.StatusFail, MissingStatus: model.StatusWarn},
			{Type: "Programmed", FalseStatus: model.StatusFail, MissingStatus: model.StatusWarn},
		})
		listeners := sliceField(listenerSet.Object, "spec", "listeners")
		if len(listeners) == 0 {
			s.addProblem("ListenerSet Layer", name+" listeners", model.StatusFail, fmt.Sprintf("ListenerSet %s has no spec.listeners entries.", name), fmt.Sprintf("ListenerSet %s has no listeners, so it does not add any usable Gateway entry points.", name))
		}
		statusListeners := gatewayStatusListeners(listenerSet.Object)
		for _, raw := range listeners {
			listener, ok := raw.(map[string]interface{})
			if !ok {
				continue
			}
			listenerName := stringField(listener, "name")
			check := name + "/" + listenerName
			s.addListenerConditionProblems(check, statusListeners[listenerName])
			s.scanListenerSetTLSRefs(ctx, client, listenerSet, listener, refGrants)
		}
		s.addWide("ListenerSet Layer", name, model.StatusPass, fmt.Sprintf("ListenerSet %s scanned.", name))
	}
}

func (s *gatewayScanner) scanListenerSetTLSRefs(ctx context.Context, client *kube.Client, listenerSet unstructured.Unstructured, listener map[string]interface{}, refGrants []unstructured.Unstructured) {
	certRefs := sliceField(listener, "tls", "certificateRefs")
	if len(certRefs) == 0 {
		return
	}
	name := objectRefText(listenerSet)
	for _, raw := range certRefs {
		ref, ok := raw.(map[string]interface{})
		if !ok {
			continue
		}
		certName := stringField(ref, "name")
		if certName == "" {
			continue
		}
		group := stringField(ref, "group")
		kind := defaultString(stringField(ref, "kind"), "Secret")
		namespace := defaultString(stringField(ref, "namespace"), listenerSet.GetNamespace())
		check := fmt.Sprintf("%s cert %s/%s", name, namespace, certName)
		if group != "" || kind != "Secret" {
			s.addProblemCategorized("TLS Reference Layer", check, model.StatusWarn, "unsupported-ref", fmt.Sprintf("ListenerSet %s listener certificateRef %s/%s is %s/%s; KNM only validates core Secret refs right now.", name, namespace, certName, group, kind), "")
			continue
		}
		if namespace != listenerSet.GetNamespace() && !referenceGrantAllows(refGrants, gatewayv1.GroupName, "ListenerSet", listenerSet.GetNamespace(), "", "Secret", certName, namespace) {
			s.addProblem("TLS Reference Layer", check, model.StatusFail, fmt.Sprintf("ListenerSet %s references cross-namespace TLS Secret %s/%s without a matching ReferenceGrant.", name, namespace, certName), fmt.Sprintf("ListenerSet %s references TLS Secret %s/%s across namespaces, but the Secret namespace does not grant that reference.", name, namespace, certName))
			continue
		}
		if _, err := client.Core.CoreV1().Secrets(namespace).Get(ctx, certName, metav1.GetOptions{}); err != nil {
			s.addProblem("TLS Reference Layer", check, model.StatusFail, fmt.Sprintf("ListenerSet %s references TLS Secret %s/%s, but it was not found or is unreadable: %v", name, namespace, certName, err), fmt.Sprintf("ListenerSet %s references missing or unreadable TLS Secret %s/%s.", name, namespace, certName))
		}
	}
}

func (s *gatewayScanner) scanBackendTLSPolicies(ctx context.Context, client *kube.Client, policies []unstructured.Unstructured, serviceCache map[string]*corev1.Service, serviceErrCache map[string]error) {
	for _, policy := range policies {
		s.scannedOther++
		name := objectRefText(policy)
		s.scanGatewayPolicyServiceTargets(ctx, client, policy, "BackendTLSPolicy", "BackendTLSPolicy Layer", serviceCache, serviceErrCache)
		s.scanBackendTLSPolicyValidation(ctx, client, policy)
		s.scanGatewayPolicyAncestorStatus(policy, "BackendTLSPolicy", "BackendTLSPolicy Layer")
		s.addWide("BackendTLSPolicy Layer", name, model.StatusPass, fmt.Sprintf("BackendTLSPolicy %s scanned.", name))
	}
}

type gatewayPolicyTargetRef struct {
	ref      map[string]interface{}
	field    string
	position int
}

func gatewayPolicyTargetRefs(policy unstructured.Unstructured) []gatewayPolicyTargetRef {
	var refs []gatewayPolicyTargetRef
	if targetRef := mapField(policy.Object, "spec", "targetRef"); len(targetRef) > 0 {
		refs = append(refs, gatewayPolicyTargetRef{ref: targetRef, field: "targetRef"})
	}
	for index, raw := range sliceField(policy.Object, "spec", "targetRefs") {
		targetRef, ok := raw.(map[string]interface{})
		if !ok {
			continue
		}
		refs = append(refs, gatewayPolicyTargetRef{ref: targetRef, field: "targetRef", position: index + 1})
	}
	return refs
}

func gatewayPolicyTargetRefText(target gatewayPolicyTargetRef) string {
	if target.position > 0 {
		return fmt.Sprintf("%s %d", target.field, target.position)
	}
	return target.field
}

func (s *gatewayScanner) gatewayPolicyTargetSelectorRefs(policy unstructured.Unstructured, policyKind, layer string, targets gatewayPolicyTargetIndexes) ([]gatewayPolicyTargetRef, []string) {
	name := objectRefText(policy)
	var refs []gatewayPolicyTargetRef
	var warnings []string
	for index, raw := range sliceField(policy.Object, "spec", "targetSelectors") {
		selector, ok := raw.(map[string]interface{})
		if !ok {
			continue
		}
		group := defaultString(stringField(selector, "group"), gatewayv1.GroupName)
		kind := stringField(selector, "kind")
		canonical := gatewayPolicyCanonicalTargetKind(group, kind)
		objects := gatewayObjectsForPolicySelectorKind(canonical, targets)
		if canonical == "" || len(objects) == 0 {
			warnings = append(warnings, fmt.Sprintf("%s %s targetSelector %d targets kind %s; KNM does not evaluate that selector target type.", policyKind, name, index+1, gatewayBackendKindText(group, kind)))
			continue
		}
		namespaceMode := stringField(selector, "namespaces", "from")
		if namespaceMode == "" {
			namespaceMode = "Same"
		}
		if namespaceMode == "Selector" {
			warnings = append(warnings, fmt.Sprintf("%s %s targetSelector %d uses namespaces.from=Selector; KNM does not resolve namespace-label selectors yet.", policyKind, name, index+1))
			continue
		}
		labelSelector, err := gatewayLabelSelector(selector)
		if err != nil {
			warnings = append(warnings, fmt.Sprintf("%s %s targetSelector %d has an invalid label selector: %v.", policyKind, name, index+1, err))
			continue
		}
		for _, object := range objects {
			if namespaceMode == "Same" && object.GetNamespace() != policy.GetNamespace() {
				continue
			}
			if namespaceMode != "Same" && namespaceMode != "All" {
				warnings = append(warnings, fmt.Sprintf("%s %s targetSelector %d uses unsupported namespaces.from=%q.", policyKind, name, index+1, namespaceMode))
				break
			}
			if !labelSelector.Matches(labels.Set(object.GetLabels())) {
				continue
			}
			refs = append(refs, gatewayPolicyTargetRef{
				ref: map[string]interface{}{
					"group":     gatewayv1.GroupName,
					"kind":      canonical,
					"name":      object.GetName(),
					"namespace": object.GetNamespace(),
				},
				field:    "targetSelector",
				position: index + 1,
			})
		}
	}
	sort.Slice(refs, func(i, j int) bool {
		left := fmt.Sprintf("%s/%s/%s", stringField(refs[i].ref, "kind"), stringField(refs[i].ref, "namespace"), stringField(refs[i].ref, "name"))
		right := fmt.Sprintf("%s/%s/%s", stringField(refs[j].ref, "kind"), stringField(refs[j].ref, "namespace"), stringField(refs[j].ref, "name"))
		return left < right
	})
	return refs, warnings
}

func gatewayObjectsForPolicySelectorKind(kind string, targets gatewayPolicyTargetIndexes) []unstructured.Unstructured {
	switch kind {
	case "Gateway":
		return gatewayIndexValues(targets.Gateways)
	case "HTTPRoute":
		return gatewayIndexValues(targets.HTTPRoutes)
	case "GRPCRoute":
		return gatewayIndexValues(targets.GRPCRoutes)
	case "TLSRoute":
		return gatewayIndexValues(targets.TLSRoutes)
	case "TCPRoute":
		return gatewayIndexValues(targets.TCPRoutes)
	case "UDPRoute":
		return gatewayIndexValues(targets.UDPRoutes)
	default:
		return nil
	}
}

func gatewayIndexValues(index map[string]unstructured.Unstructured) []unstructured.Unstructured {
	values := make([]unstructured.Unstructured, 0, len(index))
	for _, object := range index {
		values = append(values, object)
	}
	sort.Slice(values, func(i, j int) bool {
		return objectRefText(values[i]) < objectRefText(values[j])
	})
	return values
}

func gatewayLabelSelector(object map[string]interface{}) (labels.Selector, error) {
	selector := labels.NewSelector()
	matchLabels, _, _ := unstructured.NestedStringMap(object, "matchLabels")
	if len(matchLabels) > 0 {
		selector = labels.SelectorFromSet(matchLabels)
	}
	for _, raw := range sliceField(object, "matchExpressions") {
		expression, ok := raw.(map[string]interface{})
		if !ok {
			continue
		}
		key := stringField(expression, "key")
		operator := selectionOperator(stringField(expression, "operator"))
		var values []string
		for _, rawValue := range sliceField(expression, "values") {
			if value, ok := rawValue.(string); ok {
				values = append(values, value)
			}
		}
		requirement, err := labels.NewRequirement(key, operator, values)
		if err != nil {
			return labels.Nothing(), err
		}
		selector = selector.Add(*requirement)
	}
	return selector, nil
}

func selectionOperator(value string) selection.Operator {
	switch value {
	case "In":
		return selection.In
	case "NotIn":
		return selection.NotIn
	case "Exists":
		return selection.Exists
	case "DoesNotExist":
		return selection.DoesNotExist
	default:
		return selection.Operator(value)
	}
}

func (s *gatewayScanner) scanGatewayPolicyServiceTargets(ctx context.Context, client *kube.Client, policy unstructured.Unstructured, policyKind, layer string, serviceCache map[string]*corev1.Service, serviceErrCache map[string]error) {
	name := objectRefText(policy)
	targetRefs := gatewayPolicyTargetRefs(policy)
	if len(targetRefs) == 0 {
		s.addProblem(layer, name+" target", model.StatusFail, fmt.Sprintf("%s %s has no spec.targetRefs entries.", policyKind, name), fmt.Sprintf("%s %s has no targetRefs, so it cannot apply to any Service.", policyKind, name))
		return
	}
	for index, targetRef := range targetRefs {
		target := targetRef.ref
		targetText := gatewayPolicyTargetRefText(targetRef)
		targetName := stringField(target, "name")
		if targetName == "" {
			s.addProblem(layer, fmt.Sprintf("%s target %d", name, index+1), model.StatusFail, fmt.Sprintf("%s %s %s has no name.", policyKind, name, targetText), fmt.Sprintf("%s %s has a %s with no name.", policyKind, name, targetRef.field))
			continue
		}
		group := stringField(target, "group")
		kind := defaultString(stringField(target, "kind"), "Service")
		if group != "" || kind != "Service" {
			message := fmt.Sprintf("%s %s targets backend kind %s %s/%s; KNM does not evaluate that target type.", policyKind, name, gatewayBackendKindText(group, kind), policy.GetNamespace(), targetName)
			s.addProblemCategorized(layer, fmt.Sprintf("%s target %d", name, index+1), model.StatusWarn, "unsupported-ref", message, message)
			continue
		}
		service, err := cachedService(ctx, client, policy.GetNamespace(), targetName, serviceCache, serviceErrCache)
		if err != nil {
			s.addProblem(layer, fmt.Sprintf("%s target %d", name, index+1), model.StatusFail, fmt.Sprintf("%s %s targets missing/unreadable Service %s/%s: %v", policyKind, name, policy.GetNamespace(), targetName, err), fmt.Sprintf("%s %s targets Service %s/%s, but that Service is missing or unreadable.", policyKind, name, policy.GetNamespace(), targetName))
			continue
		}
		if sectionName := stringField(target, "sectionName"); sectionName != "" && !serviceHasPortName(service, sectionName) {
			s.addProblem(layer, fmt.Sprintf("%s target %d section", name, index+1), model.StatusFail, fmt.Sprintf("%s %s targets Service %s/%s sectionName %q, but the Service has ports %s.", policyKind, name, policy.GetNamespace(), targetName, sectionName, servicePorts(service)), fmt.Sprintf("%s %s targets Service %s/%s sectionName %q, but that Service port name does not exist.", policyKind, name, policy.GetNamespace(), targetName, sectionName))
		}
	}
}

func (s *gatewayScanner) scanBackendTLSPolicyValidation(ctx context.Context, client *kube.Client, policy unstructured.Unstructured) {
	name := objectRefText(policy)
	validation := mapField(policy.Object, "spec", "validation")
	caRefs := sliceField(validation, "caCertificateRefs")
	wellKnown := stringField(validation, "wellKnownCACertificates")
	if len(caRefs) == 0 && wellKnown == "" {
		s.addProblem("BackendTLSPolicy Layer", name+" validation", model.StatusFail, fmt.Sprintf("BackendTLSPolicy %s has no CA validation source.", name), fmt.Sprintf("BackendTLSPolicy %s does not specify caCertificateRefs or wellKnownCACertificates.", name))
	}
	if len(caRefs) > 0 && wellKnown != "" {
		s.addProblem("BackendTLSPolicy Layer", name+" validation", model.StatusFail, fmt.Sprintf("BackendTLSPolicy %s specifies both caCertificateRefs and wellKnownCACertificates.", name), fmt.Sprintf("BackendTLSPolicy %s specifies both caCertificateRefs and wellKnownCACertificates.", name))
	}
	if wellKnown != "" && wellKnown != "System" && !strings.Contains(wellKnown, "/") {
		s.addProblem("BackendTLSPolicy Layer", name+" wellKnownCACertificates", model.StatusWarn, fmt.Sprintf("BackendTLSPolicy %s uses unrecognized wellKnownCACertificates value %q.", name, wellKnown), fmt.Sprintf("BackendTLSPolicy %s uses unrecognized wellKnownCACertificates value %q.", name, wellKnown))
	}
	for index, raw := range caRefs {
		ref, ok := raw.(map[string]interface{})
		if !ok {
			continue
		}
		refName := stringField(ref, "name")
		if refName == "" {
			s.addProblem("BackendTLSPolicy Layer", fmt.Sprintf("%s caCertificateRef %d", name, index+1), model.StatusFail, fmt.Sprintf("BackendTLSPolicy %s caCertificateRef %d has no name.", name, index+1), fmt.Sprintf("BackendTLSPolicy %s has a caCertificateRef with no name.", name))
			continue
		}
		group := stringField(ref, "group")
		kind := defaultString(stringField(ref, "kind"), "ConfigMap")
		if group != "" || kind != "ConfigMap" {
			message := fmt.Sprintf("BackendTLSPolicy %s caCertificateRef %d uses %s/%s %s; KNM only validates core ConfigMap CA refs right now.", name, index+1, group, kind, refName)
			s.addProblemCategorized("BackendTLSPolicy Layer", fmt.Sprintf("%s caCertificateRef %d", name, index+1), model.StatusWarn, "unsupported-ref", message, message)
			continue
		}
		cm, err := client.Core.CoreV1().ConfigMaps(policy.GetNamespace()).Get(ctx, refName, metav1.GetOptions{})
		if err != nil {
			s.addProblem("BackendTLSPolicy Layer", fmt.Sprintf("%s caCertificateRef %d", name, index+1), model.StatusFail, fmt.Sprintf("BackendTLSPolicy %s references missing/unreadable CA ConfigMap %s/%s: %v", name, policy.GetNamespace(), refName, err), fmt.Sprintf("BackendTLSPolicy %s references CA ConfigMap %s/%s, but that ConfigMap is missing or unreadable.", name, policy.GetNamespace(), refName))
			continue
		}
		if _, ok := cm.Data["ca.crt"]; !ok {
			s.addProblem("BackendTLSPolicy Layer", fmt.Sprintf("%s caCertificateRef %d", name, index+1), model.StatusFail, fmt.Sprintf("BackendTLSPolicy %s CA ConfigMap %s/%s does not contain key ca.crt.", name, policy.GetNamespace(), refName), fmt.Sprintf("BackendTLSPolicy %s CA ConfigMap %s/%s is missing key ca.crt.", name, policy.GetNamespace(), refName))
		}
	}
}

func (s *gatewayScanner) scanEnvoyBackends(ctx context.Context, client *kube.Client, backends []unstructured.Unstructured, routeScope gatewayRouteScope, refGrants []unstructured.Unstructured) {
	for _, backend := range backends {
		if routeScope.Active && !routeScope.EnvoyBackends[objectRefText(backend)] {
			continue
		}
		s.scannedOther++
		name := objectRefText(backend)
		s.scanEnvoyBackendEndpoints(backend)
		s.scanEnvoyBackendTLS(ctx, client, backend, refGrants)
		s.addConditionProblems("Envoy Backend Layer", "Envoy Backend", name, backend.Object, []gatewayConditionRule{
			{Type: "Accepted", FalseStatus: model.StatusFail, MissingStatus: model.StatusWarn},
		})
		s.addWide("Envoy Backend Layer", name, model.StatusPass, fmt.Sprintf("Envoy Backend %s scanned.", name))
	}
}

func (s *gatewayScanner) scanEnvoyBackendEndpoints(backend unstructured.Unstructured) {
	name := objectRefText(backend)
	backendType := defaultString(stringField(backend.Object, "spec", "type"), "Endpoints")
	endpoints := sliceField(backend.Object, "spec", "endpoints")
	if backendType == "Endpoints" && len(endpoints) == 0 {
		s.addProblem("Envoy Backend Layer", name+" endpoints", model.StatusFail, fmt.Sprintf("Envoy Backend %s type Endpoints has no spec.endpoints entries.", name), fmt.Sprintf("Envoy Backend %s has no endpoints, so Gateway traffic routed to it has no backend address.", name))
		return
	}
	for index, raw := range endpoints {
		endpoint, ok := raw.(map[string]interface{})
		if !ok {
			continue
		}
		check := fmt.Sprintf("%s endpoint %d", name, index+1)
		endpointKinds := 0
		if len(mapField(endpoint, "fqdn")) > 0 {
			endpointKinds++
			fqdn := mapField(endpoint, "fqdn")
			host := stringField(fqdn, "hostname")
			if host == "" {
				s.addProblem("Envoy Backend Layer", check+" fqdn", model.StatusFail, fmt.Sprintf("Envoy Backend %s endpoint %d fqdn has no hostname.", name, index+1), fmt.Sprintf("Envoy Backend %s endpoint %d has an FQDN endpoint with no hostname.", name, index+1))
			}
			if port, ok := int32Field(fqdn, "port"); !ok || port <= 0 {
				s.addProblem("Envoy Backend Layer", check+" fqdn port", model.StatusFail, fmt.Sprintf("Envoy Backend %s endpoint %d fqdn has no valid port.", name, index+1), fmt.Sprintf("Envoy Backend %s endpoint %d has an FQDN endpoint with no valid port.", name, index+1))
			}
		}
		if len(mapField(endpoint, "ip")) > 0 {
			endpointKinds++
			ipEndpoint := mapField(endpoint, "ip")
			address := stringField(ipEndpoint, "address")
			if net.ParseIP(address) == nil {
				s.addProblem("Envoy Backend Layer", check+" ip", model.StatusFail, fmt.Sprintf("Envoy Backend %s endpoint %d has invalid IP address %q.", name, index+1, address), fmt.Sprintf("Envoy Backend %s endpoint %d has an invalid IP address.", name, index+1))
			}
			if port, ok := int32Field(ipEndpoint, "port"); !ok || port <= 0 {
				s.addProblem("Envoy Backend Layer", check+" ip port", model.StatusFail, fmt.Sprintf("Envoy Backend %s endpoint %d ip has no valid port.", name, index+1), fmt.Sprintf("Envoy Backend %s endpoint %d has an IP endpoint with no valid port.", name, index+1))
			}
		}
		if len(mapField(endpoint, "unix")) > 0 {
			endpointKinds++
			path := stringField(endpoint, "unix", "path")
			if path == "" {
				s.addProblem("Envoy Backend Layer", check+" unix", model.StatusFail, fmt.Sprintf("Envoy Backend %s endpoint %d unix has no path.", name, index+1), fmt.Sprintf("Envoy Backend %s endpoint %d has a Unix endpoint with no path.", name, index+1))
			}
			if len(path) > 108 {
				s.addProblem("Envoy Backend Layer", check+" unix path", model.StatusFail, fmt.Sprintf("Envoy Backend %s endpoint %d unix path is longer than 108 characters.", name, index+1), fmt.Sprintf("Envoy Backend %s endpoint %d has a Unix socket path longer than 108 characters.", name, index+1))
			}
		}
		if endpointKinds == 0 {
			s.addProblem("Envoy Backend Layer", check, model.StatusFail, fmt.Sprintf("Envoy Backend %s endpoint %d has no fqdn/ip/unix address.", name, index+1), fmt.Sprintf("Envoy Backend %s endpoint %d has no usable address type.", name, index+1))
		}
		if endpointKinds > 1 {
			s.addProblem("Envoy Backend Layer", check, model.StatusFail, fmt.Sprintf("Envoy Backend %s endpoint %d sets multiple address types.", name, index+1), fmt.Sprintf("Envoy Backend %s endpoint %d sets multiple address types; use exactly one of fqdn, ip, or unix.", name, index+1))
		}
	}
}

func (s *gatewayScanner) scanEnvoyBackendTLS(ctx context.Context, client *kube.Client, backend unstructured.Unstructured, refGrants []unstructured.Unstructured) {
	name := objectRefText(backend)
	tls := mapField(backend.Object, "spec", "tls")
	if len(tls) == 0 {
		return
	}
	caRefs := sliceField(tls, "caCertificateRefs")
	wellKnown := stringField(tls, "wellKnownCACertificates")
	if len(caRefs) == 0 && wellKnown == "" {
		s.addProblem("Envoy Backend Layer", name+" tls", model.StatusFail, fmt.Sprintf("Envoy Backend %s TLS has no CA validation source.", name), fmt.Sprintf("Envoy Backend %s TLS does not specify caCertificateRefs or wellKnownCACertificates.", name))
	}
	if len(caRefs) > 0 && wellKnown != "" {
		s.addProblem("Envoy Backend Layer", name+" tls", model.StatusFail, fmt.Sprintf("Envoy Backend %s TLS specifies both caCertificateRefs and wellKnownCACertificates.", name), fmt.Sprintf("Envoy Backend %s TLS specifies both caCertificateRefs and wellKnownCACertificates.", name))
	}
	for index, raw := range caRefs {
		ref, ok := raw.(map[string]interface{})
		if !ok {
			continue
		}
		s.scanEnvoyPolicyDataRef(ctx, client, backend, "Envoy Backend", fmt.Sprintf("tls caCertificateRef %d", index+1), ref, "ca.crt", refGrants)
	}
	if clientCert := mapField(tls, "clientCertificateRef"); len(clientCert) > 0 {
		s.scanEnvoyPolicyDataRef(ctx, client, backend, "Envoy Backend", "tls clientCertificateRef", clientCert, "tls.crt", refGrants)
	}
}

func (s *gatewayScanner) scanEnvoyHTTPRouteFilters(ctx context.Context, client *kube.Client, filters []unstructured.Unstructured, routeScope gatewayRouteScope, refGrants []unstructured.Unstructured) {
	for _, filter := range filters {
		if routeScope.Active && !routeScope.HTTPRouteFilters[objectRefText(filter)] {
			continue
		}
		s.scannedOther++
		name := objectRefText(filter)
		spec := mapField(filter.Object, "spec")
		if len(spec) == 0 {
			s.addProblem("Envoy HTTPRouteFilter Layer", name+" spec", model.StatusFail, fmt.Sprintf("Envoy HTTPRouteFilter %s has no spec.", name), fmt.Sprintf("Envoy HTTPRouteFilter %s has no spec, so it cannot apply any filter behavior.", name))
			continue
		}
		if directResponse := mapField(spec, "directResponse"); len(directResponse) > 0 {
			if status, ok := int32Field(directResponse, "statusCode"); ok && (status < 100 || status > 599) {
				s.addProblem("Envoy HTTPRouteFilter Layer", name+" directResponse", model.StatusFail, fmt.Sprintf("Envoy HTTPRouteFilter %s directResponse statusCode %d is outside HTTP status range.", name, status), fmt.Sprintf("Envoy HTTPRouteFilter %s directResponse has invalid HTTP status code %d.", name, status))
			}
		}
		if credential := mapField(spec, "credentialInjection", "credential", "valueRef"); len(credential) > 0 {
			s.scanEnvoyPolicyDataRef(ctx, client, filter, "Envoy HTTPRouteFilter", "credentialInjection valueRef", credential, "credential", refGrants)
		} else if len(mapField(spec, "credentialInjection")) > 0 {
			s.addProblem("Envoy HTTPRouteFilter Layer", name+" credentialInjection", model.StatusFail, fmt.Sprintf("Envoy HTTPRouteFilter %s credentialInjection has no credential.valueRef.", name), fmt.Sprintf("Envoy HTTPRouteFilter %s credentialInjection does not reference a credential Secret.", name))
		}
		if rewritePath := mapField(spec, "urlRewrite", "path"); len(rewritePath) > 0 {
			if stringField(rewritePath, "type") == "ReplaceRegexMatch" {
				regex := stringField(rewritePath, "replaceRegexMatch", "pattern")
				if regex == "" {
					s.addProblem("Envoy HTTPRouteFilter Layer", name+" urlRewrite", model.StatusFail, fmt.Sprintf("Envoy HTTPRouteFilter %s urlRewrite ReplaceRegexMatch has no pattern.", name), fmt.Sprintf("Envoy HTTPRouteFilter %s URL rewrite has no regex pattern.", name))
				} else if _, err := regexp.Compile(regex); err != nil {
					s.addProblem("Envoy HTTPRouteFilter Layer", name+" urlRewrite", model.StatusFail, fmt.Sprintf("Envoy HTTPRouteFilter %s urlRewrite regex pattern is invalid: %v", name, err), fmt.Sprintf("Envoy HTTPRouteFilter %s URL rewrite has an invalid regex pattern.", name))
				}
			}
		}
		s.addWide("Envoy HTTPRouteFilter Layer", name, model.StatusPass, fmt.Sprintf("Envoy HTTPRouteFilter %s scanned.", name))
	}
}

func (s *gatewayScanner) scanEnvoyProxies(proxies []unstructured.Unstructured) {
	for _, proxy := range proxies {
		s.scannedOther++
		name := objectRefText(proxy)
		providerType := stringField(proxy.Object, "spec", "provider", "type")
		if providerType == "" {
			// Envoy Gateway defaults to Kubernetes provider when provider is omitted.
		} else if providerType != "Kubernetes" && providerType != "Host" {
			s.addProblem("EnvoyProxy Layer", name+" provider", model.StatusFail, fmt.Sprintf("EnvoyProxy %s provider.type %q is not supported.", name, providerType), fmt.Sprintf("EnvoyProxy %s uses unsupported provider.type %q.", name, providerType))
		}
		if concurrency, ok, _ := unstructured.NestedInt64(proxy.Object, "spec", "concurrency"); ok && concurrency < 0 {
			s.addProblem("EnvoyProxy Layer", name+" concurrency", model.StatusFail, fmt.Sprintf("EnvoyProxy %s concurrency %d is invalid.", name, concurrency), fmt.Sprintf("EnvoyProxy %s has invalid negative concurrency.", name))
		}
		s.scanGatewayPolicyAncestorStatus(proxy, "EnvoyProxy", "EnvoyProxy Layer")
		s.addWide("EnvoyProxy Layer", name, model.StatusPass, fmt.Sprintf("EnvoyProxy %s scanned.", name))
	}
}

func (s *gatewayScanner) scanEnvoyPatchPolicies(policies []unstructured.Unstructured, layer string, targets gatewayPolicyTargetIndexes, routeScope gatewayRouteScope) {
	for _, policy := range policies {
		if routeScope.Active && !envoyPatchPolicyMatchesRouteScope(policy, routeScope) {
			continue
		}
		s.scannedOther++
		name := objectRefText(policy)
		target := mapField(policy.Object, "spec", "targetRef")
		if len(target) == 0 {
			s.addProblem(layer, name+" target", model.StatusFail, fmt.Sprintf("Envoy EnvoyPatchPolicy %s has no spec.targetRef.", name), fmt.Sprintf("Envoy EnvoyPatchPolicy %s has no targetRef, so KNM cannot determine what it applies to.", name))
		} else {
			s.scanEnvoyPatchPolicyTarget(policy, layer, targets)
		}
		if patchType := stringField(policy.Object, "spec", "type"); patchType == "" {
			s.addProblem(layer, name+" type", model.StatusFail, fmt.Sprintf("Envoy EnvoyPatchPolicy %s has no spec.type.", name), fmt.Sprintf("Envoy EnvoyPatchPolicy %s has no type.", name))
		} else if patchType != "JSONPatch" {
			s.addProblem(layer, name+" type", model.StatusFail, fmt.Sprintf("Envoy EnvoyPatchPolicy %s type %q is unsupported.", name, patchType), fmt.Sprintf("Envoy EnvoyPatchPolicy %s uses unsupported type %q.", name, patchType))
		}
		patches := sliceField(policy.Object, "spec", "jsonPatches")
		if len(patches) == 0 {
			s.addProblem(layer, name+" jsonPatches", model.StatusFail, fmt.Sprintf("Envoy EnvoyPatchPolicy %s has no jsonPatches.", name), fmt.Sprintf("Envoy EnvoyPatchPolicy %s has no jsonPatches, so it cannot patch any Envoy xDS resource.", name))
		}
		for index, raw := range patches {
			patch, ok := raw.(map[string]interface{})
			if !ok {
				continue
			}
			check := fmt.Sprintf("%s jsonPatch %d", name, index+1)
			if stringField(patch, "name") == "" {
				s.addProblem(layer, check+" name", model.StatusFail, fmt.Sprintf("Envoy EnvoyPatchPolicy %s jsonPatch %d has no name.", name, index+1), fmt.Sprintf("Envoy EnvoyPatchPolicy %s jsonPatch %d has no target resource name.", name, index+1))
			}
			if stringField(patch, "type") == "" {
				s.addProblem(layer, check+" type", model.StatusFail, fmt.Sprintf("Envoy EnvoyPatchPolicy %s jsonPatch %d has no xDS type.", name, index+1), fmt.Sprintf("Envoy EnvoyPatchPolicy %s jsonPatch %d has no xDS resource type.", name, index+1))
			}
			if len(mapField(patch, "operation")) == 0 {
				s.addProblem(layer, check+" operation", model.StatusFail, fmt.Sprintf("Envoy EnvoyPatchPolicy %s jsonPatch %d has no operation.", name, index+1), fmt.Sprintf("Envoy EnvoyPatchPolicy %s jsonPatch %d has no JSON patch operation.", name, index+1))
			}
		}
		s.scanGatewayPolicyAncestorStatus(policy, "Envoy EnvoyPatchPolicy", layer)
		s.addWide(layer, name, model.StatusPass, fmt.Sprintf("Envoy EnvoyPatchPolicy %s scanned.", name))
	}
}

func (s *gatewayScanner) scanEnvoyPatchPolicyTarget(policy unstructured.Unstructured, layer string, targets gatewayPolicyTargetIndexes) {
	name := objectRefText(policy)
	target := mapField(policy.Object, "spec", "targetRef")
	targetName := stringField(target, "name")
	if targetName == "" {
		s.addProblem(layer, name+" target", model.StatusFail, fmt.Sprintf("Envoy EnvoyPatchPolicy %s targetRef has no name.", name), fmt.Sprintf("Envoy EnvoyPatchPolicy %s has a targetRef with no name.", name))
		return
	}
	group := stringField(target, "group")
	kind := defaultString(stringField(target, "kind"), "Gateway")
	namespace := policy.GetNamespace()
	switch gatewayPolicyCanonicalTargetKind(group, kind) {
	case "Gateway":
		if _, ok := targets.Gateways[namespace+"/"+targetName]; !ok {
			s.addProblem(layer, name+" target", model.StatusFail, fmt.Sprintf("Envoy EnvoyPatchPolicy %s targets missing Gateway %s/%s.", name, namespace, targetName), fmt.Sprintf("Envoy EnvoyPatchPolicy %s targets Gateway %s/%s, but that Gateway was not found.", name, namespace, targetName))
		}
	case "GatewayClass":
		if _, ok := targets.GatewayClasses[targetName]; !ok {
			s.addProblem(layer, name+" target", model.StatusFail, fmt.Sprintf("Envoy EnvoyPatchPolicy %s targets missing GatewayClass %s.", name, targetName), fmt.Sprintf("Envoy EnvoyPatchPolicy %s targets GatewayClass %s, but that GatewayClass was not found.", name, targetName))
		}
	default:
		message := fmt.Sprintf("Envoy EnvoyPatchPolicy %s targets kind %s %s; KNM does not evaluate that target type.", name, gatewayBackendKindText(group, kind), targetName)
		s.addProblemCategorized(layer, name+" target", model.StatusWarn, "unsupported-ref", message, message)
	}
}

func envoyPatchPolicyMatchesRouteScope(policy unstructured.Unstructured, scope gatewayRouteScope) bool {
	target := mapField(policy.Object, "spec", "targetRef")
	targetName := stringField(target, "name")
	if targetName == "" {
		return true
	}
	group := stringField(target, "group")
	kind := defaultString(stringField(target, "kind"), "Gateway")
	if gatewayPolicyCanonicalTargetKind(group, kind) != "Gateway" {
		return false
	}
	return scope.Gateways[policy.GetNamespace()+"/"+targetName]
}

type gatewayPolicyTargetIndexes struct {
	GatewayClasses map[string]unstructured.Unstructured
	Gateways       map[string]unstructured.Unstructured
	HTTPRoutes     map[string]unstructured.Unstructured
	GRPCRoutes     map[string]unstructured.Unstructured
	TLSRoutes      map[string]unstructured.Unstructured
	TCPRoutes      map[string]unstructured.Unstructured
	UDPRoutes      map[string]unstructured.Unstructured
}

type gatewayRouteScope struct {
	Active              bool
	Gateways            map[string]bool
	GatewayAllListeners map[string]bool
	GatewayListeners    map[string]map[string]bool
	Routes              map[string]bool
	Services            map[string]bool
	EnvoyBackends       map[string]bool
	HTTPRouteFilters    map[string]bool
}

func (s gatewayRouteScope) listenerFilter(gateway string) map[string]bool {
	if !s.Active || s.GatewayAllListeners[gateway] {
		return nil
	}
	return s.GatewayListeners[gateway]
}

func (s *gatewayScanner) scanGatewayPolicyAttachments(ctx context.Context, client *kube.Client, policies []unstructured.Unstructured, policyKind, layer string, allowedKinds map[string]bool, targets gatewayPolicyTargetIndexes, routeScope gatewayRouteScope, refGrants []unstructured.Unstructured, serviceCache map[string]*corev1.Service, serviceErrCache map[string]error) {
	for _, policy := range policies {
		if routeScope.Active && !s.gatewayPolicyMatchesRouteScope(policy, policyKind, layer, routeScope, targets) {
			continue
		}
		s.scannedOther++
		name := objectRefText(policy)
		s.scanGatewayPolicyTargets(ctx, client, policy, policyKind, layer, allowedKinds, targets, serviceCache, serviceErrCache)
		if policyKind == "Envoy BackendTrafficPolicy" {
			s.scanEnvoyBackendTrafficPolicySemantics(policy, targets)
		}
		if policyKind == "Envoy ClientTrafficPolicy" {
			s.scanEnvoyClientTrafficPolicySemantics(ctx, client, policy, refGrants)
		}
		if policyKind == "Envoy SecurityPolicy" {
			s.scanEnvoySecurityPolicySemantics(ctx, client, policy, targets, refGrants, serviceCache, serviceErrCache)
		}
		if policyKind == "Envoy EnvoyExtensionPolicy" {
			s.scanEnvoyExtensionPolicySemantics(ctx, client, policy, serviceCache, serviceErrCache)
		}
		s.scanGatewayPolicyAncestorStatus(policy, policyKind, layer)
		s.addWide(layer, name, model.StatusPass, fmt.Sprintf("%s %s scanned.", policyKind, name))
	}
}

func (s *gatewayScanner) scanEnvoyBackendTrafficPolicySemantics(policy unstructured.Unstructured, targets gatewayPolicyTargetIndexes) {
	name := objectRefText(policy)
	spec := mapField(policy.Object, "spec")
	if len(spec) == 0 {
		return
	}
	targetRefs := gatewayPolicyTargetRefs(policy)
	selectedRefs, selectorWarnings := s.gatewayPolicyTargetSelectorRefs(policy, "Envoy BackendTrafficPolicy", "Envoy Gateway Policy Layer", targets)
	targetRefs = append(targetRefs, selectedRefs...)
	for _, warning := range selectorWarnings {
		s.addProblemCategorized("Envoy Gateway Policy Layer", name+" targetSelectors", model.StatusWarn, "unsupported-ref", warning, "")
	}
	if len(targetRefs) == 0 && len(sliceField(policy.Object, "spec", "targetSelectors")) > 0 {
		s.addProblemCategorized("Envoy Gateway Policy Layer", name+" targetSelectors", model.StatusWarn, "unsupported-ref", fmt.Sprintf("Envoy BackendTrafficPolicy %s targetSelectors did not select any supported Gateway API targets.", name), "")
		return
	}
	for index, targetRef := range targetRefs {
		target := targetRef.ref
		group := stringField(target, "group")
		kind := defaultString(stringField(target, "kind"), "Service")
		canonical := gatewayPolicyCanonicalTargetKind(group, kind)
		targetName := defaultString(stringField(target, "name"), "<unnamed>")
		namespace := defaultString(stringField(target, "namespace"), policy.GetNamespace())
		if canonical == "Gateway" && stringField(spec, "mergeType") != "" {
			s.addProblem("Envoy Gateway Policy Layer", fmt.Sprintf("%s target %d mergeType", name, index+1), model.StatusFail, fmt.Sprintf("Envoy BackendTrafficPolicy %s sets mergeType while targeting Gateway %s/%s.", name, namespace, targetName), fmt.Sprintf("Envoy BackendTrafficPolicy %s targets Gateway %s/%s and sets mergeType, but mergeType cannot be used when targeting a Gateway.", name, namespace, targetName))
		}
		if canonical == "GRPCRoute" && len(mapField(spec, "requestBuffer")) > 0 {
			s.addProblemCategorized("Envoy Gateway Policy Layer", fmt.Sprintf("%s target %d requestBuffer", name, index+1), model.StatusWarn, "policy-ambiguous", fmt.Sprintf("Envoy BackendTrafficPolicy %s enables requestBuffer for GRPCRoute %s/%s. This is usually only safe for unary gRPC; streaming gRPC can hang or fail.", name, namespace, targetName), "")
		}
	}
	s.scanEnvoyBackendTrafficPolicyRequestBuffer(policy, targetRefs)
	s.scanEnvoyBackendTrafficPolicyFaultInjection(policy)
	s.scanEnvoyBackendTrafficPolicyResponseOverrides(policy)
	s.scanEnvoyBackendTrafficPolicyCircuitBreaker(policy)
	s.scanEnvoyBackendTrafficPolicyRateLimit(policy)
	s.scanEnvoyBackendTrafficPolicyRetry(policy)
	s.scanEnvoyBackendTrafficPolicyHealthCheck(policy)
	s.scanEnvoyBackendTrafficPolicyAdmissionControl(policy, targetRefs)
	s.scanEnvoyBackendTrafficPolicyBandwidthLimit(policy)
	s.scanEnvoyBackendTrafficPolicyConnection(policy)
	s.scanEnvoyBackendTrafficPolicyLoadBalancer(policy)
	s.scanEnvoyBackendTrafficPolicyTimeout(policy, targetRefs)
	s.scanEnvoyBackendTrafficPolicyHTTP2(policy)
	s.scanEnvoyBackendTrafficPolicyTCPKeepalive(policy)
	s.scanEnvoyBackendTrafficPolicyUseClientProtocol(policy, targetRefs)
	s.scanEnvoyBackendTrafficPolicyCompressor(policy)
	s.scanEnvoyBackendTrafficPolicyRoutingType(policy)
	if len(sliceField(spec, "compression")) > 0 {
		s.addProblemCategorized("Envoy Gateway Policy Layer", name+" compression", model.StatusWarn, "policy-ambiguous", fmt.Sprintf("Envoy BackendTrafficPolicy %s uses deprecated compression; use compressor instead.", name), "")
	}
}

func (s *gatewayScanner) scanEnvoyBackendTrafficPolicyRequestBuffer(policy unstructured.Unstructured, targetRefs []gatewayPolicyTargetRef) {
	name := objectRefText(policy)
	spec := mapField(policy.Object, "spec")
	if len(mapField(spec, "requestBuffer")) == 0 {
		return
	}
	if len(sliceField(spec, "httpUpgrade")) == 0 {
		s.addProblemCategorized("Envoy Gateway Policy Layer", name+" requestBuffer upgrades", model.StatusWarn, "policy-ambiguous", fmt.Sprintf("Envoy BackendTrafficPolicy %s enables requestBuffer without explicit httpUpgrade settings; request buffering disables default protocol upgrade handling and can break WebSocket-style upgrades.", name), "")
	}
	for index, targetRef := range targetRefs {
		target := targetRef.ref
		group := stringField(target, "group")
		kind := defaultString(stringField(target, "kind"), "Service")
		canonical := gatewayPolicyCanonicalTargetKind(group, kind)
		if canonical == "Gateway" || canonical == "HTTPRoute" {
			targetName := defaultString(stringField(target, "name"), "<unnamed>")
			namespace := defaultString(stringField(target, "namespace"), policy.GetNamespace())
			s.addProblemCategorized("Envoy Gateway Policy Layer", fmt.Sprintf("%s target %d requestBuffer", name, index+1), model.StatusWarn, "policy-ambiguous", fmt.Sprintf("Envoy BackendTrafficPolicy %s enables requestBuffer for %s %s/%s; streaming requests and protocol upgrades can hang or fail.", name, canonical, namespace, targetName), "")
		}
	}
}

func (s *gatewayScanner) scanEnvoyBackendTrafficPolicyFaultInjection(policy unstructured.Unstructured) {
	name := objectRefText(policy)
	fault := mapField(policy.Object, "spec", "faultInjection")
	if len(fault) == 0 {
		return
	}
	if abort := mapField(fault, "abort"); len(abort) > 0 {
		percentage, ok := numberField(abort, "percentage")
		status := envoyFaultAbortStatus(abort)
		if ok && percentage >= 100 {
			message := fmt.Sprintf("Envoy BackendTrafficPolicy %s aborts 100%% of matching traffic%s.", name, status)
			s.addProblemCategorized("Envoy Gateway Policy Layer", name+" fault abort", model.StatusWarn, "conditional-routing", message, message)
		} else if ok && percentage > 0 {
			s.addProblemCategorized("Envoy Gateway Policy Layer", name+" fault abort", model.StatusWarn, "conditional-routing", fmt.Sprintf("Envoy BackendTrafficPolicy %s aborts %.3g%% of matching traffic%s.", name, percentage, status), "")
		}
	}
	if delay := mapField(fault, "delay"); len(delay) > 0 {
		percentage, ok := numberField(delay, "percentage")
		fixedDelay := stringField(delay, "fixedDelay")
		if ok && percentage >= 100 {
			message := fmt.Sprintf("Envoy BackendTrafficPolicy %s delays 100%% of matching traffic by %s.", name, defaultString(fixedDelay, "<unspecified duration>"))
			s.addProblemCategorized("Envoy Gateway Policy Layer", name+" fault delay", model.StatusWarn, "conditional-routing", message, message)
		} else if ok && percentage > 0 {
			s.addProblemCategorized("Envoy Gateway Policy Layer", name+" fault delay", model.StatusWarn, "conditional-routing", fmt.Sprintf("Envoy BackendTrafficPolicy %s delays %.3g%% of matching traffic by %s.", name, percentage, defaultString(fixedDelay, "<unspecified duration>")), "")
		}
	}
}

func envoyFaultAbortStatus(abort map[string]interface{}) string {
	if status, ok := int64Field(abort, "httpStatus"); ok {
		return fmt.Sprintf(" with HTTP status %d", status)
	}
	if status, ok := int64Field(abort, "grpcStatus"); ok {
		return fmt.Sprintf(" with gRPC status %d", status)
	}
	return ""
}

func (s *gatewayScanner) scanEnvoyBackendTrafficPolicyResponseOverrides(policy unstructured.Unstructured) {
	name := objectRefText(policy)
	for index, raw := range sliceField(policy.Object, "spec", "responseOverride") {
		override, ok := raw.(map[string]interface{})
		if !ok {
			continue
		}
		response := mapField(override, "response")
		status, hasStatus := int64Field(response, "statusCode")
		if hasStatus && status >= 500 {
			message := fmt.Sprintf("Envoy BackendTrafficPolicy %s responseOverride %d can replace matching responses with HTTP %d.", name, index+1, status)
			s.addProblemCategorized("Envoy Gateway Policy Layer", fmt.Sprintf("%s responseOverride %d", name, index+1), model.StatusWarn, "conditional-routing", message, message)
		} else if hasStatus && status >= 400 {
			s.addProblemCategorized("Envoy Gateway Policy Layer", fmt.Sprintf("%s responseOverride %d", name, index+1), model.StatusWarn, "conditional-routing", fmt.Sprintf("Envoy BackendTrafficPolicy %s responseOverride %d can replace matching responses with HTTP %d.", name, index+1, status), "")
		}
		for statusIndex, rawStatus := range sliceField(override, "match", "statusCodes") {
			statusMatch, ok := rawStatus.(map[string]interface{})
			if !ok {
				continue
			}
			if stringField(statusMatch, "type") == "Range" {
				start, startOK := int64Field(statusMatch, "range", "start")
				end, endOK := int64Field(statusMatch, "range", "end")
				if startOK && endOK && start > end {
					s.addProblem("Envoy Gateway Policy Layer", fmt.Sprintf("%s responseOverride %d statusRange %d", name, index+1, statusIndex+1), model.StatusFail, fmt.Sprintf("Envoy BackendTrafficPolicy %s responseOverride %d has status range start %d greater than end %d.", name, index+1, start, end), fmt.Sprintf("Envoy BackendTrafficPolicy %s responseOverride %d has an invalid status code range.", name, index+1))
				}
			}
		}
	}
}

func (s *gatewayScanner) scanEnvoyBackendTrafficPolicyCircuitBreaker(policy unstructured.Unstructured) {
	name := objectRefText(policy)
	cb := mapField(policy.Object, "spec", "circuitBreaker")
	if len(cb) == 0 {
		return
	}
	for _, field := range []string{"maxConnections", "maxParallelRequests", "maxParallelRetries", "maxPendingRequests", "maxRequestsPerConnection"} {
		if value, ok := int64Field(cb, field); ok && value == 0 {
			message := fmt.Sprintf("Envoy BackendTrafficPolicy %s circuitBreaker.%s is 0; matching traffic can be rejected by circuit breaking.", name, field)
			s.addProblemCategorized("Envoy Gateway Policy Layer", name+" circuitBreaker "+field, model.StatusWarn, "policy-ambiguous", message, message)
		}
	}
	if perEndpoint := mapField(cb, "perEndpoint"); len(perEndpoint) > 0 {
		if value, ok := int64Field(perEndpoint, "maxConnections"); ok && value == 0 {
			message := fmt.Sprintf("Envoy BackendTrafficPolicy %s circuitBreaker.perEndpoint.maxConnections is 0; matching traffic can be rejected by circuit breaking.", name)
			s.addProblemCategorized("Envoy Gateway Policy Layer", name+" circuitBreaker perEndpoint", model.StatusWarn, "policy-ambiguous", message, message)
		}
	}
	if budget := mapField(cb, "retryBudget"); len(budget) > 0 {
		if numerator, ok := int64Field(budget, "percent", "numerator"); ok && numerator == 0 {
			message := fmt.Sprintf("Envoy BackendTrafficPolicy %s circuitBreaker.retryBudget.percent.numerator is 0; retries can be disabled by the retry budget.", name)
			s.addProblemCategorized("Envoy Gateway Policy Layer", name+" retryBudget percent", model.StatusWarn, "policy-ambiguous", message, message)
		}
		if minRetry, ok := int64Field(budget, "minRetryConcurrency"); ok && minRetry == 0 {
			s.addProblemCategorized("Envoy Gateway Policy Layer", name+" retryBudget minRetryConcurrency", model.StatusWarn, "policy-ambiguous", fmt.Sprintf("Envoy BackendTrafficPolicy %s circuitBreaker.retryBudget.minRetryConcurrency is 0; low-traffic services may get no retry allowance.", name), "")
		}
	}
}

func (s *gatewayScanner) scanEnvoyBackendTrafficPolicyRateLimit(policy unstructured.Unstructured) {
	name := objectRefText(policy)
	rateLimit := mapField(policy.Object, "spec", "rateLimit")
	if len(rateLimit) == 0 {
		return
	}
	if stringField(rateLimit, "type") == "" {
		s.addProblem("Envoy Gateway Policy Layer", name+" rateLimit type", model.StatusFail, fmt.Sprintf("Envoy BackendTrafficPolicy %s configures rateLimit but has no spec.rateLimit.type.", name), fmt.Sprintf("Envoy BackendTrafficPolicy %s configures rateLimit, but rateLimit.type is missing.", name))
	}
	rateLimitType := stringField(rateLimit, "type")
	globalRules := sliceField(rateLimit, "global", "rules")
	localRules := sliceField(rateLimit, "local", "rules")
	if rateLimitType == "Global" && len(globalRules) == 0 {
		s.addProblem("Envoy Gateway Policy Layer", name+" rateLimit global", model.StatusFail, fmt.Sprintf("Envoy BackendTrafficPolicy %s sets rateLimit.type=Global but has no global rules.", name), fmt.Sprintf("Envoy BackendTrafficPolicy %s sets rateLimit.type=Global, but no global rate limit rules are configured.", name))
	}
	if rateLimitType == "Local" && len(localRules) == 0 {
		s.addProblem("Envoy Gateway Policy Layer", name+" rateLimit local", model.StatusFail, fmt.Sprintf("Envoy BackendTrafficPolicy %s sets rateLimit.type=Local but has no local rules.", name), fmt.Sprintf("Envoy BackendTrafficPolicy %s sets rateLimit.type=Local, but no local rate limit rules are configured.", name))
	}
	if rateLimitType == "Global" && len(localRules) > 0 && len(globalRules) == 0 {
		s.addProblem("Envoy Gateway Policy Layer", name+" rateLimit local", model.StatusFail, fmt.Sprintf("Envoy BackendTrafficPolicy %s sets rateLimit.type=Global but only local rules are configured.", name), fmt.Sprintf("Envoy BackendTrafficPolicy %s sets rateLimit.type=Global, but the configured rules are under local.", name))
	}
	if rateLimitType == "Local" && len(globalRules) > 0 && len(localRules) == 0 {
		s.addProblem("Envoy Gateway Policy Layer", name+" rateLimit global", model.StatusFail, fmt.Sprintf("Envoy BackendTrafficPolicy %s sets rateLimit.type=Local but only global rules are configured.", name), fmt.Sprintf("Envoy BackendTrafficPolicy %s sets rateLimit.type=Local, but the configured rules are under global.", name))
	}
	for scope, rules := range map[string][]interface{}{
		"global": globalRules,
		"local":  localRules,
	} {
		for index, raw := range rules {
			rule, ok := raw.(map[string]interface{})
			if !ok {
				continue
			}
			limit := mapField(rule, "limit")
			requests, hasRequests := int64Field(limit, "requests")
			shadow, _ := rule["shadowMode"].(bool)
			if hasRequests && requests == 0 && !shadow {
				message := fmt.Sprintf("Envoy BackendTrafficPolicy %s %s rateLimit rule %d allows 0 requests per %s; matching traffic can be rate-limited immediately.", name, scope, index+1, defaultString(stringField(limit, "unit"), "unit"))
				s.addProblemCategorized("Envoy Gateway Policy Layer", fmt.Sprintf("%s %s rateLimit rule %d", name, scope, index+1), model.StatusWarn, "conditional-routing", message, message)
			}
			if len(sliceField(rule, "clientSelectors")) > 0 && !envoyRateLimitRuleHasHeaderOrSourceCIDR(rule) {
				message := fmt.Sprintf("Envoy BackendTrafficPolicy %s %s rateLimit rule %d has clientSelectors but no header or sourceCIDR selector.", name, scope, index+1)
				s.addProblem("Envoy Gateway Policy Layer", fmt.Sprintf("%s %s rateLimit rule %d selectors", name, scope, index+1), model.StatusFail, message, fmt.Sprintf("Envoy BackendTrafficPolicy %s %s rateLimit rule %d cannot be translated by Envoy Gateway without at least one header or sourceCIDR selector.", name, scope, index+1))
			}
		}
	}
}

func envoyRateLimitRuleHasHeaderOrSourceCIDR(rule map[string]interface{}) bool {
	for _, raw := range sliceField(rule, "clientSelectors") {
		selector, ok := raw.(map[string]interface{})
		if !ok {
			continue
		}
		if len(sliceField(selector, "headers")) > 0 || len(mapField(selector, "sourceCIDR")) > 0 {
			return true
		}
	}
	return false
}

func (s *gatewayScanner) scanEnvoyBackendTrafficPolicyHealthCheck(policy unstructured.Unstructured) {
	name := objectRefText(policy)
	active := mapField(policy.Object, "spec", "healthCheck", "active")
	if len(active) == 0 {
		return
	}
	checkType := stringField(active, "type")
	if checkType == "" {
		s.addProblem("Envoy Gateway Policy Layer", name+" healthCheck type", model.StatusFail, fmt.Sprintf("Envoy BackendTrafficPolicy %s active healthCheck has no type.", name), fmt.Sprintf("Envoy BackendTrafficPolicy %s active healthCheck has no type.", name))
		return
	}
	protocolConfigs := map[string]bool{
		"HTTP": len(mapField(active, "http")) > 0,
		"GRPC": len(mapField(active, "grpc")) > 0,
		"TCP":  len(mapField(active, "tcp")) > 0,
	}
	if expected, ok := protocolConfigs[checkType]; ok && !expected {
		s.addProblem("Envoy Gateway Policy Layer", name+" healthCheck "+checkType, model.StatusFail, fmt.Sprintf("Envoy BackendTrafficPolicy %s active healthCheck type %s has no matching %s config.", name, checkType, strings.ToLower(checkType)), fmt.Sprintf("Envoy BackendTrafficPolicy %s active healthCheck type is %s, but the matching config is missing.", name, checkType))
	}
	configCount := 0
	for _, present := range protocolConfigs {
		if present {
			configCount++
		}
	}
	if configCount > 1 {
		s.addProblemCategorized("Envoy Gateway Policy Layer", name+" healthCheck protocols", model.StatusWarn, "policy-ambiguous", fmt.Sprintf("Envoy BackendTrafficPolicy %s active healthCheck defines multiple protocol configs; type %s controls which one is used.", name, checkType), "")
	}
	s.scanEnvoyBackendTrafficPolicyHealthCheckHTTPStatuses(policy, active)
}

func (s *gatewayScanner) scanEnvoyBackendTrafficPolicyHealthCheckHTTPStatuses(policy unstructured.Unstructured, active map[string]interface{}) {
	name := objectRefText(policy)
	statuses := sliceField(active, "http", "expectedStatuses")
	if len(statuses) == 0 {
		return
	}
	hasSuccess := false
	hasOnlyErrors := true
	for _, raw := range statuses {
		status, ok := int64Value(raw)
		if !ok {
			continue
		}
		if status >= 200 && status < 400 {
			hasSuccess = true
		}
		if status < 500 {
			hasOnlyErrors = false
		}
	}
	if hasOnlyErrors {
		message := fmt.Sprintf("Envoy BackendTrafficPolicy %s active HTTP healthCheck only treats 5xx status codes as healthy.", name)
		s.addProblemCategorized("Envoy Gateway Policy Layer", name+" healthCheck expectedStatuses", model.StatusWarn, "policy-ambiguous", message, message)
		return
	}
	if !hasSuccess {
		s.addProblemCategorized("Envoy Gateway Policy Layer", name+" healthCheck expectedStatuses", model.StatusWarn, "policy-ambiguous", fmt.Sprintf("Envoy BackendTrafficPolicy %s active HTTP healthCheck expectedStatuses has no 2xx/3xx success status.", name), "")
	}
}

func (s *gatewayScanner) scanEnvoyBackendTrafficPolicyRoutingType(policy unstructured.Unstructured) {
	name := objectRefText(policy)
	routingType := stringField(policy.Object, "spec", "routingType")
	if routingType == "" {
		return
	}
	if routingType != "Service" && routingType != "Endpoint" {
		s.addProblem("Envoy Gateway Policy Layer", name+" routingType", model.StatusFail, fmt.Sprintf("Envoy BackendTrafficPolicy %s uses unsupported routingType %q.", name, routingType), fmt.Sprintf("Envoy BackendTrafficPolicy %s uses unsupported routingType %q.", name, routingType))
	}
}

func (s *gatewayScanner) scanEnvoyBackendTrafficPolicyRetry(policy unstructured.Unstructured) {
	name := objectRefText(policy)
	retry := mapField(policy.Object, "spec", "retry")
	if len(retry) == 0 {
		return
	}
	if retries, ok := int64Field(retry, "numRetries"); ok && retries == 0 && len(mapField(retry, "retryOn")) > 0 {
		s.addProblemCategorized("Envoy Gateway Policy Layer", name+" retry", model.StatusWarn, "policy-ambiguous", fmt.Sprintf("Envoy BackendTrafficPolicy %s defines retryOn conditions but numRetries is 0, so matching requests will not be retried.", name), "")
	}
	if timeout := stringField(retry, "perRetry", "timeout"); timeout != "" {
		if duration, ok := parseGatewayDuration(timeout); ok && duration == 0 {
			s.addProblemCategorized("Envoy Gateway Policy Layer", name+" retry timeout", model.StatusWarn, "policy-ambiguous", fmt.Sprintf("Envoy BackendTrafficPolicy %s sets retry.perRetry.timeout to 0s; retry attempts can time out immediately.", name), "")
		}
	}
	if base := stringField(retry, "perRetry", "backOff", "baseInterval"); base != "" {
		if max := stringField(retry, "perRetry", "backOff", "maxInterval"); max != "" {
			if baseDuration, baseOK := parseGatewayDuration(base); baseOK {
				if maxDuration, maxOK := parseGatewayDuration(max); maxOK && baseDuration > maxDuration {
					message := fmt.Sprintf("Envoy BackendTrafficPolicy %s retry backOff baseInterval %s is greater than maxInterval %s.", name, base, max)
					s.addProblemCategorized("Envoy Gateway Policy Layer", name+" retry backOff", model.StatusWarn, "policy-ambiguous", message, message)
				}
			}
		}
	}
}

func (s *gatewayScanner) scanEnvoyBackendTrafficPolicyAdmissionControl(policy unstructured.Unstructured, targetRefs []gatewayPolicyTargetRef) {
	name := objectRefText(policy)
	admission := mapField(policy.Object, "spec", "admissionControl")
	if len(admission) == 0 {
		return
	}
	for index, targetRef := range targetRefs {
		target := targetRef.ref
		kind := gatewayPolicyCanonicalTargetKind(stringField(target, "group"), defaultString(stringField(target, "kind"), "Service"))
		if kind != "Gateway" && kind != "HTTPRoute" && kind != "GRPCRoute" {
			targetName := defaultString(stringField(target, "name"), "<unnamed>")
			namespace := defaultString(stringField(target, "namespace"), policy.GetNamespace())
			message := fmt.Sprintf("Envoy BackendTrafficPolicy %s uses admissionControl on %s %s/%s, but admissionControl only applies to Gateway, HTTPRoute, or GRPCRoute targets.", name, kind, namespace, targetName)
			s.addProblem("Envoy Gateway Policy Layer", fmt.Sprintf("%s target %d admissionControl", name, index+1), model.StatusFail, message, message)
		}
	}
	if percent, ok := int64Field(admission, "maxRejectionPercent"); ok && percent == 100 {
		message := fmt.Sprintf("Envoy BackendTrafficPolicy %s admissionControl can reject up to 100%% of matching traffic.", name)
		s.addProblemCategorized("Envoy Gateway Policy Layer", name+" admissionControl maxRejectionPercent", model.StatusWarn, "conditional-routing", message, message)
	}
	if minSuccess, ok := int64Field(admission, "minSuccessRate"); ok && minSuccess == 100 {
		s.addProblemCategorized("Envoy Gateway Policy Layer", name+" admissionControl minSuccessRate", model.StatusWarn, "policy-ambiguous", fmt.Sprintf("Envoy BackendTrafficPolicy %s admissionControl requires a 100%% success rate before avoiding rejection.", name), "")
	}
	if window := stringField(admission, "samplingWindow"); window != "" {
		if duration, ok := parseGatewayDuration(window); ok && duration < time.Second {
			message := fmt.Sprintf("Envoy BackendTrafficPolicy %s admissionControl samplingWindow %s is shorter than 1s.", name, window)
			s.addProblem("Envoy Gateway Policy Layer", name+" admissionControl samplingWindow", model.StatusFail, message, message)
		}
	}
	for _, status := range sliceField(admission, "successCriteria", "http", "statusCodes") {
		if code, ok := int64Value(status); ok && code >= 500 {
			s.addProblemCategorized("Envoy Gateway Policy Layer", name+" admissionControl http successCriteria", model.StatusWarn, "policy-ambiguous", fmt.Sprintf("Envoy BackendTrafficPolicy %s admissionControl treats HTTP %d as successful.", name, code), "")
		}
	}
	for _, raw := range sliceField(admission, "successCriteria", "grpc", "statusCodes") {
		code, _ := raw.(string)
		if code != "" && code != "Ok" {
			s.addProblemCategorized("Envoy Gateway Policy Layer", name+" admissionControl grpc successCriteria", model.StatusWarn, "policy-ambiguous", fmt.Sprintf("Envoy BackendTrafficPolicy %s admissionControl treats gRPC status %s as successful.", name, code), "")
		}
	}
}

func (s *gatewayScanner) scanEnvoyBackendTrafficPolicyBandwidthLimit(policy unstructured.Unstructured) {
	name := objectRefText(policy)
	bandwidth := mapField(policy.Object, "spec", "bandwidthLimit")
	if len(bandwidth) == 0 {
		return
	}
	if len(mapField(bandwidth, "request")) == 0 && len(mapField(bandwidth, "response")) == 0 {
		message := fmt.Sprintf("Envoy BackendTrafficPolicy %s bandwidthLimit has neither request nor response limits.", name)
		s.addProblem("Envoy Gateway Policy Layer", name+" bandwidthLimit", model.StatusFail, message, message)
	}
	for _, direction := range []string{"request", "response"} {
		limit := mapField(bandwidth, direction, "limit")
		if len(limit) == 0 {
			continue
		}
		value := limit["value"]
		if isZeroGatewayQuantity(value) {
			message := fmt.Sprintf("Envoy BackendTrafficPolicy %s bandwidthLimit.%s.limit.value is 0; matching traffic can stall.", name, direction)
			s.addProblemCategorized("Envoy Gateway Policy Layer", name+" bandwidthLimit "+direction, model.StatusWarn, "conditional-routing", message, message)
		}
		if stringField(limit, "unit") == "" {
			s.addProblem("Envoy Gateway Policy Layer", name+" bandwidthLimit "+direction+" unit", model.StatusFail, fmt.Sprintf("Envoy BackendTrafficPolicy %s bandwidthLimit.%s.limit has no unit.", name, direction), fmt.Sprintf("Envoy BackendTrafficPolicy %s bandwidthLimit.%s.limit unit is missing.", name, direction))
		}
	}
}

func (s *gatewayScanner) scanEnvoyBackendTrafficPolicyConnection(policy unstructured.Unstructured) {
	name := objectRefText(policy)
	connection := mapField(policy.Object, "spec", "connection")
	if len(connection) == 0 {
		return
	}
	for _, field := range []string{"bufferLimit", "socketBufferLimit"} {
		if isZeroGatewayQuantity(connection[field]) {
			message := fmt.Sprintf("Envoy BackendTrafficPolicy %s connection.%s is 0; backend connections may be unable to buffer traffic.", name, field)
			s.addProblemCategorized("Envoy Gateway Policy Layer", name+" connection "+field, model.StatusWarn, "policy-ambiguous", message, message)
		}
	}
	preconnect := mapField(connection, "preconnect")
	if len(preconnect) == 0 {
		return
	}
	loadBalancerType := stringField(policy.Object, "spec", "loadBalancer", "type")
	if _, ok := int64Field(preconnect, "predictivePercent"); ok && loadBalancerType != "Random" && loadBalancerType != "RoundRobin" {
		message := fmt.Sprintf("Envoy BackendTrafficPolicy %s connection.preconnect.predictivePercent only works with Random or RoundRobin load balancers.", name)
		s.addProblem("Envoy Gateway Policy Layer", name+" preconnect predictivePercent", model.StatusFail, message, message)
	}
	for _, field := range []string{"perEndpointPercent", "predictivePercent"} {
		if value, ok := int64Field(preconnect, field); ok && value == 0 {
			s.addProblemCategorized("Envoy Gateway Policy Layer", name+" preconnect "+field, model.StatusWarn, "policy-ambiguous", fmt.Sprintf("Envoy BackendTrafficPolicy %s connection.preconnect.%s is 0; preconnect will not open extra backend connections.", name, field), "")
		}
	}
}

func (s *gatewayScanner) scanEnvoyBackendTrafficPolicyLoadBalancer(policy unstructured.Unstructured) {
	name := objectRefText(policy)
	lb := mapField(policy.Object, "spec", "loadBalancer")
	if len(lb) == 0 {
		return
	}
	lbType := stringField(lb, "type")
	if lbType == "ConsistentHash" {
		hash := mapField(lb, "consistentHash")
		configured := 0
		for _, present := range []bool{
			len(mapField(hash, "cookie")) > 0,
			len(mapField(hash, "header")) > 0,
			len(sliceField(hash, "headers")) > 0,
			len(sliceField(hash, "queryParams")) > 0,
			stringField(hash, "type") == "SourceIP",
		} {
			if present {
				configured++
			}
		}
		if len(hash) == 0 || configured == 0 {
			message := fmt.Sprintf("Envoy BackendTrafficPolicy %s uses ConsistentHash load balancing without a hash source.", name)
			s.addProblem("Envoy Gateway Policy Layer", name+" loadBalancer consistentHash", model.StatusFail, message, message)
		}
		if tableSize, ok := int64Field(hash, "tableSize"); ok && tableSize == 0 {
			s.addProblemCategorized("Envoy Gateway Policy Layer", name+" loadBalancer tableSize", model.StatusWarn, "policy-ambiguous", fmt.Sprintf("Envoy BackendTrafficPolicy %s consistentHash.tableSize is 0; consistent hash distribution may be unusable.", name), "")
		}
		if configured > 1 {
			s.addProblemCategorized("Envoy Gateway Policy Layer", name+" loadBalancer hash sources", model.StatusWarn, "policy-ambiguous", fmt.Sprintf("Envoy BackendTrafficPolicy %s consistentHash defines multiple hash sources; only the selected source type is used.", name), "")
		}
	}
	if lbType != "ConsistentHash" && len(mapField(lb, "consistentHash")) > 0 {
		s.addProblemCategorized("Envoy Gateway Policy Layer", name+" loadBalancer consistentHash", model.StatusWarn, "policy-ambiguous", fmt.Sprintf("Envoy BackendTrafficPolicy %s defines consistentHash settings but loadBalancer.type is %q.", name, lbType), "")
	}
	if lbType != "LeastRequest" && len(mapField(lb, "slowStart")) > 0 {
		s.addProblemCategorized("Envoy Gateway Policy Layer", name+" loadBalancer slowStart", model.StatusWarn, "policy-ambiguous", fmt.Sprintf("Envoy BackendTrafficPolicy %s defines slowStart while loadBalancer.type is %q.", name, lbType), "")
	}
	for index, raw := range sliceField(lb, "zoneAware", "weightedZones") {
		zone, ok := raw.(map[string]interface{})
		if !ok {
			continue
		}
		if weight, ok := int64Field(zone, "weight"); ok && weight == 0 {
			message := fmt.Sprintf("Envoy BackendTrafficPolicy %s zoneAware weighted zone %d has weight 0.", name, index+1)
			s.addProblemCategorized("Envoy Gateway Policy Layer", fmt.Sprintf("%s zoneAware weightedZone %d", name, index+1), model.StatusWarn, "conditional-routing", message, message)
		}
	}
}

func (s *gatewayScanner) scanEnvoyBackendTrafficPolicyTimeout(policy unstructured.Unstructured, targetRefs []gatewayPolicyTargetRef) {
	name := objectRefText(policy)
	timeoutSpec := mapField(policy.Object, "spec", "timeout")
	if len(timeoutSpec) == 0 {
		return
	}
	httpTimeout := mapField(timeoutSpec, "http")
	tcpTimeout := mapField(timeoutSpec, "tcp")
	for _, field := range []string{"requestTimeout", "streamIdleTimeout", "connectionIdleTimeout", "maxConnectionDuration", "maxStreamDuration"} {
		value := stringField(httpTimeout, field)
		if value == "" {
			continue
		}
		if duration, ok := parseGatewayDuration(value); ok && duration == 0 {
			s.addProblemCategorized("Envoy Gateway Policy Layer", name+" timeout http "+field, model.StatusWarn, "policy-ambiguous", fmt.Sprintf("Envoy BackendTrafficPolicy %s timeout.http.%s is 0s.", name, field), "")
		}
	}
	if requestTimeout, requestOK := parseGatewayDuration(stringField(httpTimeout, "requestTimeout")); requestOK && requestTimeout > 0 {
		if perRetry, retryOK := parseGatewayDuration(stringField(policy.Object, "spec", "retry", "perRetry", "timeout")); retryOK && perRetry > requestTimeout {
			message := fmt.Sprintf("Envoy BackendTrafficPolicy %s retry.perRetry.timeout is greater than timeout.http.requestTimeout.", name)
			s.addProblemCategorized("Envoy Gateway Policy Layer", name+" retry timeout budget", model.StatusWarn, "policy-ambiguous", message, message)
		}
	}
	if value := stringField(tcpTimeout, "connectTimeout"); value != "" {
		if duration, ok := parseGatewayDuration(value); ok && duration == 0 {
			message := fmt.Sprintf("Envoy BackendTrafficPolicy %s timeout.tcp.connectTimeout is 0s; backend TCP/TLS connection attempts can fail immediately.", name)
			s.addProblemCategorized("Envoy Gateway Policy Layer", name+" timeout tcp connectTimeout", model.StatusWarn, "policy-ambiguous", message, message)
		}
	}
	for _, targetRef := range targetRefs {
		kind := gatewayPolicyCanonicalTargetKind(stringField(targetRef.ref, "group"), defaultString(stringField(targetRef.ref, "kind"), "Service"))
		if kind == "TCPRoute" && len(httpTimeout) > 0 {
			s.addProblemCategorized("Envoy Gateway Policy Layer", name+" timeout http target", model.StatusWarn, "policy-ambiguous", fmt.Sprintf("Envoy BackendTrafficPolicy %s configures HTTP timeouts while targeting TCPRoute.", name), "")
		}
		if (kind == "HTTPRoute" || kind == "GRPCRoute") && len(tcpTimeout) > 0 {
			s.addProblemCategorized("Envoy Gateway Policy Layer", name+" timeout tcp target", model.StatusWarn, "policy-ambiguous", fmt.Sprintf("Envoy BackendTrafficPolicy %s configures TCP connectTimeout while targeting %s.", name, kind), "")
		}
	}
}

func (s *gatewayScanner) scanEnvoyBackendTrafficPolicyHTTP2(policy unstructured.Unstructured) {
	name := objectRefText(policy)
	http2 := mapField(policy.Object, "spec", "http2")
	if len(http2) == 0 {
		return
	}
	if streams, ok := int64Field(http2, "maxConcurrentStreams"); ok && streams == 0 {
		message := fmt.Sprintf("Envoy BackendTrafficPolicy %s http2.maxConcurrentStreams is 0; HTTP/2 streams can be blocked.", name)
		s.addProblemCategorized("Envoy Gateway Policy Layer", name+" http2 maxConcurrentStreams", model.StatusWarn, "conditional-routing", message, message)
	}
	for _, field := range []string{"initialConnectionWindowSize", "initialStreamWindowSize"} {
		if isZeroGatewayQuantity(http2[field]) {
			message := fmt.Sprintf("Envoy BackendTrafficPolicy %s http2.%s is 0; HTTP/2 flow-control windows can block traffic.", name, field)
			s.addProblemCategorized("Envoy Gateway Policy Layer", name+" http2 "+field, model.StatusWarn, "conditional-routing", message, message)
		}
	}
	keepalive := mapField(http2, "connectionKeepalive")
	for _, field := range []string{"interval", "timeout", "idleInterval"} {
		value := stringField(keepalive, field)
		if value == "" {
			continue
		}
		if duration, ok := parseGatewayDuration(value); ok && duration == 0 {
			s.addProblemCategorized("Envoy Gateway Policy Layer", name+" http2 keepalive "+field, model.StatusWarn, "policy-ambiguous", fmt.Sprintf("Envoy BackendTrafficPolicy %s http2.connectionKeepalive.%s is 0s.", name, field), "")
		}
	}
}

func (s *gatewayScanner) scanEnvoyBackendTrafficPolicyTCPKeepalive(policy unstructured.Unstructured) {
	name := objectRefText(policy)
	keepalive := mapField(policy.Object, "spec", "tcpKeepalive")
	if len(keepalive) == 0 {
		return
	}
	if probes, ok := int64Field(keepalive, "probes"); ok && probes == 0 {
		s.addProblemCategorized("Envoy Gateway Policy Layer", name+" tcpKeepalive probes", model.StatusWarn, "policy-ambiguous", fmt.Sprintf("Envoy BackendTrafficPolicy %s tcpKeepalive.probes is 0; keepalive failure detection may not work as intended.", name), "")
	}
	for _, field := range []string{"idleTime", "interval"} {
		value := stringField(keepalive, field)
		if value == "" {
			continue
		}
		if duration, ok := parseGatewayDuration(value); ok && duration == 0 {
			s.addProblemCategorized("Envoy Gateway Policy Layer", name+" tcpKeepalive "+field, model.StatusWarn, "policy-ambiguous", fmt.Sprintf("Envoy BackendTrafficPolicy %s tcpKeepalive.%s is 0s.", name, field), "")
		}
	}
}

func (s *gatewayScanner) scanEnvoyBackendTrafficPolicyUseClientProtocol(policy unstructured.Unstructured, targetRefs []gatewayPolicyTargetRef) {
	name := objectRefText(policy)
	spec := mapField(policy.Object, "spec")
	enabled, ok := spec["useClientProtocol"].(bool)
	if !ok || !enabled {
		return
	}
	for _, targetRef := range targetRefs {
		kind := gatewayPolicyCanonicalTargetKind(stringField(targetRef.ref, "group"), defaultString(stringField(targetRef.ref, "kind"), "Service"))
		if kind == "TCPRoute" || kind == "UDPRoute" || kind == "TLSRoute" {
			s.addProblemCategorized("Envoy Gateway Policy Layer", name+" useClientProtocol target", model.StatusWarn, "policy-ambiguous", fmt.Sprintf("Envoy BackendTrafficPolicy %s enables useClientProtocol while targeting %s; this setting is only meaningful for HTTP backends.", name, kind), "")
		}
	}
}

func (s *gatewayScanner) scanEnvoyBackendTrafficPolicyCompressor(policy unstructured.Unstructured) {
	name := objectRefText(policy)
	spec := mapField(policy.Object, "spec")
	compressor := sliceField(spec, "compressor")
	compression := sliceField(spec, "compression")
	if len(compressor) > 0 && len(compression) > 0 {
		message := fmt.Sprintf("Envoy BackendTrafficPolicy %s sets both compression and compressor.", name)
		s.addProblem("Envoy Gateway Policy Layer", name+" compressor conflict", model.StatusFail, message, message)
	}
	scanCompressor := func(field string, items []interface{}) {
		seen := map[string]bool{}
		for index, raw := range items {
			item, ok := raw.(map[string]interface{})
			if !ok {
				continue
			}
			compressorType := stringField(item, "type")
			if compressorType == "" {
				s.addProblem("Envoy Gateway Policy Layer", fmt.Sprintf("%s %s %d type", name, field, index+1), model.StatusFail, fmt.Sprintf("Envoy BackendTrafficPolicy %s %s %d has no type.", name, field, index+1), fmt.Sprintf("Envoy BackendTrafficPolicy %s %s %d type is missing.", name, field, index+1))
				continue
			}
			if seen[compressorType] {
				s.addProblemCategorized("Envoy Gateway Policy Layer", fmt.Sprintf("%s %s %d duplicate", name, field, index+1), model.StatusWarn, "policy-ambiguous", fmt.Sprintf("Envoy BackendTrafficPolicy %s %s lists %s more than once; first matching compressor order wins.", name, field, compressorType), "")
			}
			seen[compressorType] = true
			if isTinyGatewayQuantity(item["minContentLength"], 30) {
				s.addProblemCategorized("Envoy Gateway Policy Layer", fmt.Sprintf("%s %s %d minContentLength", name, field, index+1), model.StatusWarn, "policy-ambiguous", fmt.Sprintf("Envoy BackendTrafficPolicy %s %s %d minContentLength is below Envoy's 30 byte minimum.", name, field, index+1), "")
			}
			configs := 0
			for _, configField := range []string{"gzip", "brotli", "zstd"} {
				if len(mapField(item, configField)) > 0 {
					configs++
				}
			}
			if configs > 1 {
				s.addProblemCategorized("Envoy Gateway Policy Layer", fmt.Sprintf("%s %s %d configs", name, field, index+1), model.StatusWarn, "policy-ambiguous", fmt.Sprintf("Envoy BackendTrafficPolicy %s %s %d defines multiple compressor config blocks; type %s controls which one is used.", name, field, index+1, compressorType), "")
			}
		}
	}
	scanCompressor("compressor", compressor)
	scanCompressor("compression", compression)
}

func (s *gatewayScanner) scanEnvoyClientTrafficPolicySemantics(ctx context.Context, client *kube.Client, policy unstructured.Unstructured, refGrants []unstructured.Unstructured) {
	name := objectRefText(policy)
	spec := mapField(policy.Object, "spec")
	if len(spec) == 0 {
		return
	}
	if _, proxyProtocolSet := spec["proxyProtocol"]; proxyProtocolSet {
		if enabled, ok := spec["enableProxyProtocol"].(bool); ok && enabled {
			s.addProblemCategorized("Envoy Gateway Policy Layer", name+" proxyProtocol", model.StatusWarn, "policy-ambiguous", fmt.Sprintf("Envoy ClientTrafficPolicy %s sets both enableProxyProtocol and proxyProtocol; proxyProtocol takes precedence.", name), "")
		}
	}
	clientValidation := mapField(spec, "tls", "clientValidation")
	for index, raw := range sliceField(clientValidation, "caCertificateRefs") {
		ref, ok := raw.(map[string]interface{})
		if !ok {
			continue
		}
		s.scanEnvoyPolicyDataRef(ctx, client, policy, "Envoy ClientTrafficPolicy", fmt.Sprintf("clientValidation caCertificateRef %d", index+1), ref, "ca.crt", refGrants)
	}
	for index, raw := range sliceField(clientValidation, "crl", "refs") {
		ref, ok := raw.(map[string]interface{})
		if !ok {
			continue
		}
		s.scanEnvoyPolicyDataRef(ctx, client, policy, "Envoy ClientTrafficPolicy", fmt.Sprintf("clientValidation crl %d", index+1), ref, "ca.crl", refGrants)
	}
}

func (s *gatewayScanner) scanEnvoyExtensionPolicySemantics(ctx context.Context, client *kube.Client, policy unstructured.Unstructured, serviceCache map[string]*corev1.Service, serviceErrCache map[string]error) {
	name := objectRefText(policy)
	for extIndex, raw := range sliceField(policy.Object, "spec", "extProc") {
		extProc, ok := raw.(map[string]interface{})
		if !ok {
			continue
		}
		refs := envoyPolicyBackendRefs(extProc)
		if len(refs) == 0 {
			s.addProblem("Envoy Gateway Policy Layer", fmt.Sprintf("%s extProc %d", name, extIndex+1), model.StatusFail, fmt.Sprintf("Envoy EnvoyExtensionPolicy %s extProc %d has no backendRef/backendRefs.", name, extIndex+1), fmt.Sprintf("Envoy EnvoyExtensionPolicy %s extProc %d does not reference an external processor backend Service.", name, extIndex+1))
			continue
		}
		for index, ref := range refs {
			s.scanEnvoyPolicyBackendRef(ctx, client, policy, "Envoy EnvoyExtensionPolicy", fmt.Sprintf("extProc %d backendRef %d", extIndex+1, index+1), ref, serviceCache, serviceErrCache)
		}
	}
}

func (s *gatewayScanner) scanEnvoySecurityPolicySemantics(ctx context.Context, client *kube.Client, policy unstructured.Unstructured, targets gatewayPolicyTargetIndexes, refGrants []unstructured.Unstructured, serviceCache map[string]*corev1.Service, serviceErrCache map[string]error) {
	name := objectRefText(policy)
	spec := mapField(policy.Object, "spec")
	if len(spec) == 0 {
		return
	}
	for index, targetRef := range gatewayPolicyTargetRefs(policy) {
		target := targetRef.ref
		targetName := stringField(target, "name")
		if targetName == "" {
			continue
		}
		group := stringField(target, "group")
		kind := defaultString(stringField(target, "kind"), "Service")
		namespace := defaultString(stringField(target, "namespace"), policy.GetNamespace())
		if gatewayPolicyCanonicalTargetKind(group, kind) == "TCPRoute" {
			targetRefName := namespace + "/" + targetName
			if gatewaySecurityPolicyHasHTTPOnlyAuth(spec) {
				s.addProblemCategorized("Envoy Gateway Policy Layer", fmt.Sprintf("%s target %d tcp auth", name, index+1), model.StatusWarn, "policy-ambiguous", fmt.Sprintf("Envoy SecurityPolicy %s targets TCPRoute %s with HTTP authentication settings; those settings do not apply to raw TCP traffic.", name, targetRefName), "")
			}
			if len(sliceField(spec, "authorization", "rules")) > 0 {
				s.addProblemCategorized("Envoy Gateway Policy Layer", fmt.Sprintf("%s target %d tcp authorization", name, index+1), model.StatusWarn, "policy-ambiguous", fmt.Sprintf("Envoy SecurityPolicy %s targets TCPRoute %s with HTTP authorization rules; only client-IP based authorization applies to TCPRoute targets.", name, targetRefName), "")
			}
		}
	}
	s.scanEnvoySecurityPolicyBasicAuth(ctx, client, policy, refGrants)
	s.scanEnvoySecurityPolicyAPIKeyAuth(ctx, client, policy, refGrants)
	s.scanEnvoySecurityPolicyOIDC(ctx, client, policy, refGrants)
	s.scanEnvoySecurityPolicyExtAuth(ctx, client, policy, serviceCache, serviceErrCache)
}

func gatewaySecurityPolicyHasHTTPOnlyAuth(spec map[string]interface{}) bool {
	for _, field := range []string{"basicAuth", "jwt", "oidc", "apiKeyAuth", "cors"} {
		if len(mapField(spec, field)) > 0 {
			return true
		}
	}
	return false
}

func (s *gatewayScanner) scanEnvoySecurityPolicyBasicAuth(ctx context.Context, client *kube.Client, policy unstructured.Unstructured, refGrants []unstructured.Unstructured) {
	name := objectRefText(policy)
	basicAuth := mapField(policy.Object, "spec", "basicAuth")
	if len(basicAuth) == 0 {
		return
	}
	users := mapField(basicAuth, "users")
	if len(users) == 0 {
		s.addProblem("Envoy Gateway Policy Layer", name+" basicAuth", model.StatusFail, fmt.Sprintf("Envoy SecurityPolicy %s basicAuth has no users Secret reference.", name), fmt.Sprintf("Envoy SecurityPolicy %s enables basicAuth but does not reference a users Secret.", name))
		return
	}
	s.scanEnvoyPolicySecretRef(ctx, client, policy, "Envoy SecurityPolicy", "basicAuth users", users, ".htpasswd", refGrants)
}

func (s *gatewayScanner) scanEnvoySecurityPolicyAPIKeyAuth(ctx context.Context, client *kube.Client, policy unstructured.Unstructured, refGrants []unstructured.Unstructured) {
	name := objectRefText(policy)
	apiKeyAuth := mapField(policy.Object, "spec", "apiKeyAuth")
	if len(apiKeyAuth) == 0 {
		return
	}
	credentialRefs := sliceField(apiKeyAuth, "credentialRefs")
	if len(credentialRefs) == 0 {
		s.addProblem("Envoy Gateway Policy Layer", name+" apiKeyAuth", model.StatusFail, fmt.Sprintf("Envoy SecurityPolicy %s apiKeyAuth has no credentialRefs.", name), fmt.Sprintf("Envoy SecurityPolicy %s enables apiKeyAuth but does not reference any credential Secrets.", name))
	}
	for index, raw := range credentialRefs {
		ref, ok := raw.(map[string]interface{})
		if !ok {
			continue
		}
		s.scanEnvoyPolicySecretRef(ctx, client, policy, "Envoy SecurityPolicy", fmt.Sprintf("apiKeyAuth credentialRef %d", index+1), ref, "", refGrants)
	}
}

func (s *gatewayScanner) scanEnvoySecurityPolicyOIDC(ctx context.Context, client *kube.Client, policy unstructured.Unstructured, refGrants []unstructured.Unstructured) {
	name := objectRefText(policy)
	oidc := mapField(policy.Object, "spec", "oidc")
	if len(oidc) == 0 {
		return
	}
	clientID := stringField(oidc, "clientID")
	clientIDRef := mapField(oidc, "clientIDRef")
	if clientID == "" && len(clientIDRef) == 0 {
		s.addProblem("Envoy Gateway Policy Layer", name+" oidc clientID", model.StatusFail, fmt.Sprintf("Envoy SecurityPolicy %s oidc has no clientID or clientIDRef.", name), fmt.Sprintf("Envoy SecurityPolicy %s enables OIDC but does not provide clientID or clientIDRef.", name))
	}
	if clientID != "" && len(clientIDRef) > 0 {
		s.addProblem("Envoy Gateway Policy Layer", name+" oidc clientID", model.StatusFail, fmt.Sprintf("Envoy SecurityPolicy %s oidc specifies both clientID and clientIDRef.", name), fmt.Sprintf("Envoy SecurityPolicy %s OIDC config specifies both clientID and clientIDRef.", name))
	}
	if len(clientIDRef) > 0 {
		s.scanEnvoyPolicySecretRef(ctx, client, policy, "Envoy SecurityPolicy", "oidc clientIDRef", clientIDRef, "client-id", refGrants)
	}
	clientSecret := mapField(oidc, "clientSecret")
	if len(clientSecret) == 0 {
		s.addProblem("Envoy Gateway Policy Layer", name+" oidc clientSecret", model.StatusFail, fmt.Sprintf("Envoy SecurityPolicy %s oidc has no clientSecret Secret reference.", name), fmt.Sprintf("Envoy SecurityPolicy %s enables OIDC but does not reference a clientSecret Secret.", name))
		return
	}
	s.scanEnvoyPolicySecretRef(ctx, client, policy, "Envoy SecurityPolicy", "oidc clientSecret", clientSecret, "client-secret", refGrants)
}

func (s *gatewayScanner) scanEnvoySecurityPolicyExtAuth(ctx context.Context, client *kube.Client, policy unstructured.Unstructured, serviceCache map[string]*corev1.Service, serviceErrCache map[string]error) {
	name := objectRefText(policy)
	extAuth := mapField(policy.Object, "spec", "extAuth")
	if len(extAuth) == 0 {
		return
	}
	backendRefs := envoySecurityPolicyExtAuthBackendRefs(extAuth)
	if len(backendRefs) == 0 {
		s.addProblem("Envoy Gateway Policy Layer", name+" extAuth", model.StatusFail, fmt.Sprintf("Envoy SecurityPolicy %s extAuth has no backendRef/backendRefs.", name), fmt.Sprintf("Envoy SecurityPolicy %s enables external authorization but does not reference an auth backend Service.", name))
		return
	}
	for index, ref := range backendRefs {
		s.scanEnvoyPolicyBackendRef(ctx, client, policy, "Envoy SecurityPolicy", fmt.Sprintf("extAuth backendRef %d", index+1), ref, serviceCache, serviceErrCache)
	}
}

func envoySecurityPolicyExtAuthBackendRefs(extAuth map[string]interface{}) []map[string]interface{} {
	return envoyPolicyBackendRefs(extAuth)
}

func envoyPolicyBackendRefs(config map[string]interface{}) []map[string]interface{} {
	var refs []map[string]interface{}
	for _, protocol := range []string{"http", "grpc", "service"} {
		service := mapField(config, protocol)
		if len(service) == 0 {
			continue
		}
		if backendRef := mapField(service, "backendRef"); len(backendRef) > 0 {
			refs = append(refs, backendRef)
		}
		for _, raw := range sliceField(service, "backendRefs") {
			ref, ok := raw.(map[string]interface{})
			if ok {
				refs = append(refs, ref)
			}
		}
	}
	if backendRef := mapField(config, "backendRef"); len(backendRef) > 0 {
		refs = append(refs, backendRef)
	}
	for _, raw := range sliceField(config, "backendRefs") {
		ref, ok := raw.(map[string]interface{})
		if ok {
			refs = append(refs, ref)
		}
	}
	return refs
}

func (s *gatewayScanner) scanEnvoyPolicyBackendRef(ctx context.Context, client *kube.Client, policy unstructured.Unstructured, policyKind, checkSuffix string, ref map[string]interface{}, serviceCache map[string]*corev1.Service, serviceErrCache map[string]error) {
	policyName := objectRefText(policy)
	targetName := stringField(ref, "name")
	check := policyName + " " + checkSuffix
	if targetName == "" {
		s.addProblem("Envoy Gateway Policy Layer", check, model.StatusFail, fmt.Sprintf("%s %s %s has no name.", policyKind, policyName, checkSuffix), fmt.Sprintf("%s %s has backendRef with no name.", policyKind, policyName))
		return
	}
	group := stringField(ref, "group")
	kind := defaultString(stringField(ref, "kind"), "Service")
	if group != "" || kind != "Service" {
		message := fmt.Sprintf("%s %s %s targets backend kind %s %s/%s; KNM only validates core Service backends right now.", policyKind, policyName, checkSuffix, gatewayBackendKindText(group, kind), policy.GetNamespace(), targetName)
		s.addProblemCategorized("Envoy Gateway Policy Layer", check, model.StatusWarn, "unsupported-ref", message, message)
		return
	}
	namespace := defaultString(stringField(ref, "namespace"), policy.GetNamespace())
	backendDescription := "backend Service"
	if policyKind == "Envoy SecurityPolicy" {
		backendDescription = "external authorization backend Service"
	}
	if policyKind == "Envoy EnvoyExtensionPolicy" {
		backendDescription = "external processor backend Service"
	}
	service, err := cachedService(ctx, client, namespace, targetName, serviceCache, serviceErrCache)
	if err != nil {
		s.addProblem("Envoy Gateway Policy Layer", check, model.StatusFail, fmt.Sprintf("%s %s %s targets missing/unreadable Service %s/%s: %v", policyKind, policyName, checkSuffix, namespace, targetName, err), fmt.Sprintf("%s %s %s %s/%s is missing or unreadable.", policyKind, policyName, backendDescription, namespace, targetName))
		return
	}
	if port, ok := int32Field(ref, "port"); ok && !serviceExposesPort(service, port) {
		s.addProblem("Envoy Gateway Policy Layer", check+" port", model.StatusFail, fmt.Sprintf("%s %s %s targets Service %s/%s port %d, but the Service exposes %s.", policyKind, policyName, checkSuffix, namespace, targetName, port, servicePorts(service)), fmt.Sprintf("%s %s %s %s/%s does not expose port %d.", policyKind, policyName, backendDescription, namespace, targetName, port))
	}
}

func (s *gatewayScanner) scanEnvoyPolicySecretRef(ctx context.Context, client *kube.Client, policy unstructured.Unstructured, policyKind, purpose string, ref map[string]interface{}, requiredKey string, refGrants []unstructured.Unstructured) {
	s.scanEnvoyPolicyDataRef(ctx, client, policy, policyKind, purpose, ref, requiredKey, refGrants)
}

func (s *gatewayScanner) scanEnvoyPolicyDataRef(ctx context.Context, client *kube.Client, policy unstructured.Unstructured, policyKind, purpose string, ref map[string]interface{}, requiredKey string, refGrants []unstructured.Unstructured) {
	name := objectRefText(policy)
	refName := stringField(ref, "name")
	check := fmt.Sprintf("%s %s", name, purpose)
	if refName == "" {
		s.addProblem("Envoy Gateway Policy Layer", check, model.StatusFail, fmt.Sprintf("%s %s %s has no reference name.", policyKind, name, purpose), fmt.Sprintf("%s %s has a %s reference with no name.", policyKind, name, purpose))
		return
	}
	group := stringField(ref, "group")
	kind := defaultString(stringField(ref, "kind"), "Secret")
	if group != "" || (kind != "Secret" && kind != "ConfigMap") {
		message := fmt.Sprintf("%s %s %s uses %s/%s %s; KNM only validates core Secret and ConfigMap refs right now.", policyKind, name, purpose, group, kind, refName)
		s.addProblemCategorized("Envoy Gateway Policy Layer", check, model.StatusWarn, "unsupported-ref", message, message)
		return
	}
	namespace := defaultString(stringField(ref, "namespace"), policy.GetNamespace())
	if namespace != policy.GetNamespace() && !referenceGrantAllows(refGrants, "gateway.envoyproxy.io", policy.GetKind(), policy.GetNamespace(), group, kind, refName, namespace) {
		s.addProblem("Envoy Gateway Policy Layer", check, model.StatusFail, fmt.Sprintf("%s %s %s references %s %s/%s without a matching ReferenceGrant.", policyKind, name, purpose, kind, namespace, refName), fmt.Sprintf("%s %s references %s %s/%s across namespaces, but that namespace does not grant the reference.", policyKind, name, kind, namespace, refName))
		return
	}
	data, err := envoyPolicyRefData(ctx, client, namespace, refName, kind)
	if err != nil {
		s.addProblem("Envoy Gateway Policy Layer", check, model.StatusFail, fmt.Sprintf("%s %s %s references missing/unreadable %s %s/%s: %v", policyKind, name, purpose, kind, namespace, refName, err), fmt.Sprintf("%s %s references %s %s/%s, but that object is missing or unreadable.", policyKind, name, kind, namespace, refName))
		return
	}
	if requiredKey != "" {
		if _, ok := data[requiredKey]; !ok {
			s.addProblem("Envoy Gateway Policy Layer", check, model.StatusFail, fmt.Sprintf("%s %s %s %s %s/%s does not contain key %s.", policyKind, name, purpose, kind, namespace, refName, requiredKey), fmt.Sprintf("%s %s %s %s %s/%s is missing key %s.", policyKind, name, purpose, kind, namespace, refName, requiredKey))
		}
		return
	}
	if len(data) == 0 {
		dataDescription := "data"
		if kind == "Secret" {
			dataDescription = "credential data"
		}
		s.addProblem("Envoy Gateway Policy Layer", check, model.StatusFail, fmt.Sprintf("%s %s %s %s %s/%s has no data entries.", policyKind, name, purpose, kind, namespace, refName), fmt.Sprintf("%s %s %s %s %s/%s has no %s.", policyKind, name, purpose, kind, namespace, refName, dataDescription))
	}
}

func envoyPolicyRefData(ctx context.Context, client *kube.Client, namespace, name, kind string) (map[string][]byte, error) {
	if kind == "ConfigMap" {
		configMap, err := client.Core.CoreV1().ConfigMaps(namespace).Get(ctx, name, metav1.GetOptions{})
		if err != nil {
			return nil, err
		}
		data := map[string][]byte{}
		for key, value := range configMap.Data {
			data[key] = []byte(value)
		}
		for key, value := range configMap.BinaryData {
			data[key] = value
		}
		return data, nil
	}
	secret, err := client.Core.CoreV1().Secrets(namespace).Get(ctx, name, metav1.GetOptions{})
	if err != nil {
		return nil, err
	}
	return secret.Data, nil
}

func (s *gatewayScanner) scanGatewayPolicyTargets(ctx context.Context, client *kube.Client, policy unstructured.Unstructured, policyKind, layer string, allowedKinds map[string]bool, targets gatewayPolicyTargetIndexes, serviceCache map[string]*corev1.Service, serviceErrCache map[string]error) {
	name := objectRefText(policy)
	targetRefs := gatewayPolicyTargetRefs(policy)
	if len(targetRefs) == 0 {
		if len(sliceField(policy.Object, "spec", "targetSelectors")) > 0 {
			s.addWide(layer, name+" targetSelectors", model.StatusInfo, fmt.Sprintf("%s %s uses targetSelectors; KNM does not resolve selector-based policy targets yet.", policyKind, name))
			return
		}
		s.addProblem(layer, name+" target", model.StatusFail, fmt.Sprintf("%s %s has no spec.targetRef or spec.targetRefs entries.", policyKind, name), fmt.Sprintf("%s %s has no targetRefs, so KNM cannot determine what it applies to.", policyKind, name))
		return
	}
	for index, targetRef := range targetRefs {
		target := targetRef.ref
		targetText := gatewayPolicyTargetRefText(targetRef)
		targetName := stringField(target, "name")
		check := fmt.Sprintf("%s target %d", name, index+1)
		if targetName == "" {
			s.addProblem(layer, check, model.StatusFail, fmt.Sprintf("%s %s %s has no name.", policyKind, name, targetText), fmt.Sprintf("%s %s has a %s with no name.", policyKind, name, targetRef.field))
			continue
		}
		group := stringField(target, "group")
		kind := defaultString(stringField(target, "kind"), "Service")
		if !gatewayPolicyKindAllowed(group, kind, allowedKinds) {
			message := fmt.Sprintf("%s %s targets kind %s %s/%s; KNM does not evaluate that target type.", policyKind, name, gatewayBackendKindText(group, kind), policy.GetNamespace(), targetName)
			s.addProblemCategorized(layer, check, model.StatusWarn, "unsupported-ref", message, message)
			continue
		}
		namespace := defaultString(stringField(target, "namespace"), policy.GetNamespace())
		sectionName := stringField(target, "sectionName")
		targetRefName := namespace + "/" + targetName
		switch gatewayPolicyCanonicalTargetKind(group, kind) {
		case "Service":
			service, err := cachedService(ctx, client, namespace, targetName, serviceCache, serviceErrCache)
			if err != nil {
				s.addProblem(layer, check, model.StatusFail, fmt.Sprintf("%s %s targets missing/unreadable Service %s: %v", policyKind, name, targetRefName, err), fmt.Sprintf("%s %s targets Service %s, but that Service is missing or unreadable.", policyKind, name, targetRefName))
				continue
			}
			if sectionName != "" && !serviceHasPortName(service, sectionName) {
				s.addProblem(layer, check+" section", model.StatusFail, fmt.Sprintf("%s %s targets Service %s sectionName %q, but the Service has ports %s.", policyKind, name, targetRefName, sectionName, servicePorts(service)), fmt.Sprintf("%s %s targets Service %s sectionName %q, but that Service port name does not exist.", policyKind, name, targetRefName, sectionName))
			}
		case "Gateway":
			gateway, ok := targets.Gateways[targetRefName]
			if !ok {
				s.addProblem(layer, check, model.StatusFail, fmt.Sprintf("%s %s targets missing Gateway %s.", policyKind, name, targetRefName), fmt.Sprintf("%s %s targets Gateway %s, but that Gateway was not found.", policyKind, name, targetRefName))
				continue
			}
			if sectionName != "" && !gatewayHasListenerName(gateway, sectionName) {
				s.addProblem(layer, check+" section", model.StatusFail, fmt.Sprintf("%s %s targets Gateway %s sectionName %q, but listener names are %s.", policyKind, name, targetRefName, sectionName, gatewayListenerNames(gateway)), fmt.Sprintf("%s %s targets Gateway %s sectionName %q, but that listener does not exist.", policyKind, name, targetRefName, sectionName))
			}
		case "HTTPRoute":
			s.scanGatewayPolicyRouteTarget(policyKind, layer, name, check, "HTTPRoute", targetRefName, sectionName, targets.HTTPRoutes)
		case "GRPCRoute":
			s.scanGatewayPolicyRouteTarget(policyKind, layer, name, check, "GRPCRoute", targetRefName, sectionName, targets.GRPCRoutes)
		case "TLSRoute":
			s.scanGatewayPolicyRouteTarget(policyKind, layer, name, check, "TLSRoute", targetRefName, sectionName, targets.TLSRoutes)
		case "TCPRoute":
			s.scanGatewayPolicyRouteTarget(policyKind, layer, name, check, "TCPRoute", targetRefName, sectionName, targets.TCPRoutes)
		case "UDPRoute":
			s.scanGatewayPolicyRouteTarget(policyKind, layer, name, check, "UDPRoute", targetRefName, sectionName, targets.UDPRoutes)
		default:
			message := fmt.Sprintf("%s %s targets kind %s %s; KNM does not evaluate that target type.", policyKind, name, gatewayBackendKindText(group, kind), targetRefName)
			s.addProblemCategorized(layer, check, model.StatusWarn, "unsupported-ref", message, message)
		}
	}
}

func (s *gatewayScanner) scanGatewayPolicyRouteTarget(policyKind, layer, policyName, check, routeKind, targetRefName, sectionName string, routes map[string]unstructured.Unstructured) {
	route, ok := routes[targetRefName]
	if !ok {
		s.addProblem(layer, check, model.StatusFail, fmt.Sprintf("%s %s targets missing %s %s.", policyKind, policyName, routeKind, targetRefName), fmt.Sprintf("%s %s targets %s %s, but that route was not found.", policyKind, policyName, routeKind, targetRefName))
		return
	}
	if sectionName != "" && !gatewayRouteHasRuleName(route, sectionName) {
		s.addProblem(layer, check+" section", model.StatusFail, fmt.Sprintf("%s %s targets %s sectionName %q, but route rule names are %s.", policyKind, policyName, targetRefName, sectionName, gatewayRouteRuleNames(route)), fmt.Sprintf("%s %s targets route %s sectionName %q, but that route rule name does not exist.", policyKind, policyName, targetRefName, sectionName))
	}
}

func gatewayPolicyKindAllowed(group, kind string, allowedKinds map[string]bool) bool {
	canonical := gatewayPolicyCanonicalTargetKind(group, kind)
	if allowedKinds == nil {
		return canonical != ""
	}
	return allowedKinds[canonical]
}

func gatewayPolicyCanonicalTargetKind(group, kind string) string {
	kind = defaultString(kind, "Service")
	switch {
	case group == "" && kind == "Service":
		return "Service"
	case (group == "" || group == gatewayv1.GroupName) && (kind == "GatewayClass" || kind == "Gateway" || kind == "HTTPRoute" || kind == "GRPCRoute" || kind == "TLSRoute" || kind == "TCPRoute" || kind == "UDPRoute"):
		return kind
	default:
		return ""
	}
}

func gatewayHasListenerName(gateway unstructured.Unstructured, name string) bool {
	for _, raw := range sliceField(gateway.Object, "spec", "listeners") {
		listener, ok := raw.(map[string]interface{})
		if ok && stringField(listener, "name") == name {
			return true
		}
	}
	return false
}

func gatewayListenerNames(gateway unstructured.Unstructured) string {
	var names []string
	for _, raw := range sliceField(gateway.Object, "spec", "listeners") {
		listener, ok := raw.(map[string]interface{})
		if ok && stringField(listener, "name") != "" {
			names = append(names, stringField(listener, "name"))
		}
	}
	sort.Strings(names)
	return strings.Join(names, ", ")
}

func gatewayRouteHasRuleName(route unstructured.Unstructured, name string) bool {
	for _, raw := range sliceField(route.Object, "spec", "rules") {
		rule, ok := raw.(map[string]interface{})
		if ok && stringField(rule, "name") == name {
			return true
		}
	}
	return false
}

func gatewayRouteRuleNames(route unstructured.Unstructured) string {
	var names []string
	for _, raw := range sliceField(route.Object, "spec", "rules") {
		rule, ok := raw.(map[string]interface{})
		if ok && stringField(rule, "name") != "" {
			names = append(names, stringField(rule, "name"))
		}
	}
	sort.Strings(names)
	if len(names) == 0 {
		return "(none)"
	}
	return strings.Join(names, ", ")
}

func (s *gatewayScanner) scanGatewayPolicyAncestorStatus(policy unstructured.Unstructured, policyKind, layer string) {
	name := objectRefText(policy)
	ancestors := sliceField(policy.Object, "status", "ancestors")
	if len(ancestors) == 0 {
		s.addProblem(layer, name+" status", model.StatusWarn, fmt.Sprintf("%s %s has no status.ancestors entries.", policyKind, name), "")
		return
	}
	for index, raw := range ancestors {
		ancestor, ok := raw.(map[string]interface{})
		if !ok {
			continue
		}
		check := fmt.Sprintf("%s ancestor %d", name, index+1)
		rules := []gatewayConditionRule{
			{Type: "Accepted", FalseStatus: model.StatusFail, MissingStatus: model.StatusWarn},
			{Type: "ResolvedRefs", FalseStatus: model.StatusFail, MissingStatus: model.StatusWarn},
		}
		if policyKind == "Envoy BackendTrafficPolicy" {
			rules[1].MissingStatus = ""
		}
		for _, rule := range rules {
			cond, ok := conditionByType(ancestor, rule.Type)
			if !ok {
				if rule.MissingStatus != "" {
					s.addProblem(layer, check+" "+rule.Type, rule.MissingStatus, fmt.Sprintf("%s %s ancestor %d has no %s condition.", policyKind, name, index+1, rule.Type), "")
				}
				continue
			}
			if strings.EqualFold(cond.Status, "False") {
				s.addProblem(layer, check+" "+rule.Type, rule.FalseStatus, fmt.Sprintf("%s %s ancestor %d condition %s=False: %s%s", policyKind, name, index+1, rule.Type, cond.Reason, conditionMessageSuffix(cond.Message)), fmt.Sprintf("%s %s is not %s: %s%s", policyKind, name, rule.Type, cond.Reason, conditionMessageSuffix(cond.Message)))
			}
		}
	}
}

func (s *gatewayScanner) scanHTTPRouteParents(route unstructured.Unstructured, gatewayIndex map[string]unstructured.Unstructured) {
	s.scanRouteParents("HTTPRoute", route, gatewayIndex)
}

func (s *gatewayScanner) scanRouteParents(kind string, route unstructured.Unstructured, gatewayIndex map[string]unstructured.Unstructured) bool {
	routeName := objectRefText(route)
	parentRefs := sliceField(route.Object, "spec", "parentRefs")
	if len(parentRefs) == 0 {
		s.addProblem("Route Attachment Layer", routeName, model.StatusWarn, fmt.Sprintf("%s %s has no spec.parentRefs.", kind, routeName), fmt.Sprintf("%s %s is not attached to any Gateway, so it will not receive Gateway traffic.", kind, routeName))
	}
	for _, raw := range parentRefs {
		parent, ok := raw.(map[string]interface{})
		if !ok {
			continue
		}
		if parentKind(parent) != "Gateway" {
			continue
		}
		parentNS := defaultString(stringField(parent, "namespace"), route.GetNamespace())
		parentName := stringField(parent, "name")
		if parentName == "" {
			continue
		}
		if _, ok := gatewayIndex[parentNS+"/"+parentName]; !ok {
			s.addProblem("Route Attachment Layer", routeName+" parent", model.StatusFail, fmt.Sprintf("%s %s references missing parent Gateway %s/%s.", kind, routeName, parentNS, parentName), fmt.Sprintf("%s %s references Gateway %s/%s, but that Gateway was not found.", kind, routeName, parentNS, parentName))
		}
	}
	parents := sliceField(route.Object, "status", "parents")
	if len(parents) == 0 {
		s.addProblem("Route Attachment Layer", routeName+" status", model.StatusWarn, fmt.Sprintf("%s %s has no status.parents entries.", kind, routeName), fmt.Sprintf("%s %s has no parent status, so no Gateway has reported accepting it yet.", kind, routeName))
		return false
	}
	accepted := false
	acceptedConditionSeen := false
	for _, raw := range parents {
		parent, ok := raw.(map[string]interface{})
		if !ok {
			continue
		}
		parentText := routeParentStatusText(route.GetNamespace(), parent)
		if cond, ok := conditionByType(parent, string(gatewayv1.RouteConditionAccepted)); ok {
			acceptedConditionSeen = true
			if strings.EqualFold(cond.Status, "True") {
				accepted = true
			}
			if strings.EqualFold(cond.Status, "False") {
				s.addProblem("Route Attachment Layer", routeName+" Accepted", model.StatusFail, fmt.Sprintf("%s %s is not accepted by %s: %s%s", kind, routeName, parentText, cond.Reason, conditionMessageSuffix(cond.Message)), fmt.Sprintf("%s %s is not accepted by %s: %s%s", kind, routeName, parentText, cond.Reason, conditionMessageSuffix(cond.Message)))
			}
		}
		if cond, ok := conditionByType(parent, string(gatewayv1.RouteConditionResolvedRefs)); ok && strings.EqualFold(cond.Status, "False") {
			s.addProblem("Route Attachment Layer", routeName+" ResolvedRefs", model.StatusFail, fmt.Sprintf("%s %s has unresolved refs for %s: %s%s", kind, routeName, parentText, cond.Reason, conditionMessageSuffix(cond.Message)), fmt.Sprintf("%s %s has unresolved references for %s: %s%s", kind, routeName, parentText, cond.Reason, conditionMessageSuffix(cond.Message)))
		}
		if cond, ok := conditionByType(parent, string(gatewayv1.RouteConditionPartiallyInvalid)); ok && strings.EqualFold(cond.Status, "True") {
			s.addProblem("Route Attachment Layer", routeName+" PartiallyInvalid", model.StatusWarn, fmt.Sprintf("%s %s is partially invalid for %s: %s%s", kind, routeName, parentText, cond.Reason, conditionMessageSuffix(cond.Message)), fmt.Sprintf("%s %s is partially invalid for %s: %s%s", kind, routeName, parentText, cond.Reason, conditionMessageSuffix(cond.Message)))
		}
	}
	if !accepted && !acceptedConditionSeen {
		s.addProblem("Route Attachment Layer", routeName+" accepted", model.StatusWarn, fmt.Sprintf("%s %s has no Accepted=True parent status.", kind, routeName), fmt.Sprintf("%s %s is not currently accepted by any Gateway parent.", kind, routeName))
	}
	return accepted
}

func (s *gatewayScanner) scanHTTPRouteBackendRefs(ctx context.Context, client *kube.Client, route unstructured.Unstructured, refGrants []unstructured.Unstructured, serviceCache map[string]*corev1.Service, serviceErrCache map[string]error, endpointReadyCache map[string]int, endpointErrCache map[string]error) {
	s.scanRouteBackendRefs(ctx, client, "HTTPRoute", route, refGrants, serviceCache, serviceErrCache, endpointReadyCache, endpointErrCache)
}

func (s *gatewayScanner) scanRouteBackendRefs(ctx context.Context, client *kube.Client, kind string, route unstructured.Unstructured, refGrants []unstructured.Unstructured, serviceCache map[string]*corev1.Service, serviceErrCache map[string]error, endpointReadyCache map[string]int, endpointErrCache map[string]error) {
	routeName := objectRefText(route)
	rules := sliceField(route.Object, "spec", "rules")
	for ruleIndex, rawRule := range rules {
		rule, ok := rawRule.(map[string]interface{})
		if !ok {
			continue
		}
		backendRefs := sliceField(rule, "backendRefs")
		if len(backendRefs) == 0 {
			if kind == "HTTPRoute" && httpRouteRuleHasRedirect(rule) {
				continue
			}
			s.addProblem("BackendRef Layer", fmt.Sprintf("%s rule %d", routeName, ruleIndex+1), model.StatusWarn, fmt.Sprintf("%s %s rule %d has no backendRefs.", kind, routeName, ruleIndex+1), fmt.Sprintf("%s %s rule %d has no backendRefs, so matching traffic will not be sent to a Service backend.", kind, routeName, ruleIndex+1))
			continue
		}
		for backendIndex, rawBackend := range backendRefs {
			backend, ok := rawBackend.(map[string]interface{})
			if !ok {
				continue
			}
			if gatewayBackendRefWeight(backend) == 0 {
				continue
			}
			s.scanRouteBackendRef(ctx, client, kind, route, ruleIndex+1, backendIndex+1, backend, refGrants, serviceCache, serviceErrCache, endpointReadyCache, endpointErrCache)
		}
	}
}

func (s *gatewayScanner) scanHTTPRouteBackendRef(ctx context.Context, client *kube.Client, route unstructured.Unstructured, ruleNumber, backendNumber int, backend map[string]interface{}, refGrants []unstructured.Unstructured, serviceCache map[string]*corev1.Service, serviceErrCache map[string]error, endpointReadyCache map[string]int, endpointErrCache map[string]error) {
	if gatewayBackendRefWeight(backend) == 0 {
		return
	}
	s.scanRouteBackendRef(ctx, client, "HTTPRoute", route, ruleNumber, backendNumber, backend, refGrants, serviceCache, serviceErrCache, endpointReadyCache, endpointErrCache)
}

func (s *gatewayScanner) scanHTTPRouteBackendRefWithDiagnosis(ctx context.Context, client *kube.Client, route unstructured.Unstructured, ruleNumber, backendNumber int, backend map[string]interface{}, refGrants []unstructured.Unstructured, serviceCache map[string]*corev1.Service, serviceErrCache map[string]error, endpointReadyCache map[string]int, endpointErrCache map[string]error, addDiagnosis bool) {
	s.scanRouteBackendRefWithDiagnosis(ctx, client, "HTTPRoute", route, ruleNumber, backendNumber, backend, refGrants, serviceCache, serviceErrCache, endpointReadyCache, endpointErrCache, addDiagnosis)
}

func (s *gatewayScanner) scanRouteBackendRef(ctx context.Context, client *kube.Client, kind string, route unstructured.Unstructured, ruleNumber, backendNumber int, backend map[string]interface{}, refGrants []unstructured.Unstructured, serviceCache map[string]*corev1.Service, serviceErrCache map[string]error, endpointReadyCache map[string]int, endpointErrCache map[string]error) {
	if gatewayBackendRefWeight(backend) == 0 {
		return
	}
	s.scanRouteBackendRefWithDiagnosis(ctx, client, kind, route, ruleNumber, backendNumber, backend, refGrants, serviceCache, serviceErrCache, endpointReadyCache, endpointErrCache, true)
}

func (s *gatewayScanner) scanRouteBackendRefWithDiagnosis(ctx context.Context, client *kube.Client, kind string, route unstructured.Unstructured, ruleNumber, backendNumber int, backend map[string]interface{}, refGrants []unstructured.Unstructured, serviceCache map[string]*corev1.Service, serviceErrCache map[string]error, endpointReadyCache map[string]int, endpointErrCache map[string]error, addDiagnosis bool) {
	if gatewayBackendRefWeight(backend) == 0 {
		return
	}
	routeName := objectRefText(route)
	name := stringField(backend, "name")
	if name == "" {
		s.addProblem("BackendRef Layer", fmt.Sprintf("%s rule %d backend %d", routeName, ruleNumber, backendNumber), model.StatusFail, fmt.Sprintf("%s %s rule %d backendRef %d has no name.", kind, routeName, ruleNumber, backendNumber), gatewayOptionalDiagnosis(addDiagnosis, fmt.Sprintf("%s %s rule %d has a backendRef with no name.", kind, routeName, ruleNumber)))
		return
	}
	group := stringField(backend, "group")
	backendKind := defaultString(stringField(backend, "kind"), "Service")
	namespace := defaultString(stringField(backend, "namespace"), route.GetNamespace())
	port, portOK := int32Field(backend, "port")
	backendText := fmt.Sprintf("%s/%s", namespace, name)
	check := fmt.Sprintf("%s rule %d backend %d %s", routeName, ruleNumber, backendNumber, backendText)
	if group != "" || backendKind != "Service" {
		message := fmt.Sprintf("%s %s rule %d routes to backend kind %s %s; KNM does not evaluate that backend type.", route.GetKind(), routeName, ruleNumber, gatewayBackendKindText(group, backendKind), backendText)
		s.addProblemCategorized("BackendRef Layer", check, model.StatusWarn, "unsupported-ref", message, gatewayOptionalDiagnosis(addDiagnosis, message))
		return
	}
	if namespace != route.GetNamespace() && !referenceGrantAllows(refGrants, gatewayv1.GroupName, route.GetKind(), route.GetNamespace(), "", "Service", name, namespace) {
		s.addProblem("BackendRef Layer", check, model.StatusFail, fmt.Sprintf("%s %s rule %d references cross-namespace Service %s without a matching ReferenceGrant.", route.GetKind(), routeName, ruleNumber, backendText), gatewayOptionalDiagnosis(addDiagnosis, fmt.Sprintf("%s %s rule %d routes to Service %s across namespaces, but namespace %q does not grant that reference.", route.GetKind(), routeName, ruleNumber, backendText, namespace)))
		return
	}
	if !portOK {
		s.addProblem("BackendRef Layer", check, model.StatusFail, fmt.Sprintf("%s %s rule %d backendRef %s has no numeric port.", route.GetKind(), routeName, ruleNumber, backendText), gatewayOptionalDiagnosis(addDiagnosis, fmt.Sprintf("%s %s backendRef %s does not specify a Service port.", route.GetKind(), routeName, backendText)))
		return
	}
	service, err := cachedService(ctx, client, namespace, name, serviceCache, serviceErrCache)
	if err != nil {
		s.addProblem("BackendRef Layer", check, model.StatusFail, fmt.Sprintf("%s %s rule %d backendRef points at missing/unreadable Service %s: %v", route.GetKind(), routeName, ruleNumber, backendText, err), gatewayOptionalDiagnosis(addDiagnosis, fmt.Sprintf("%s %s rule %d routes to Service %s, but that Service is missing or unreadable.", route.GetKind(), routeName, ruleNumber, backendText)))
		return
	}
	if !serviceHasGatewayPort(service, port) {
		s.addProblem("BackendRef Layer", check+" port", model.StatusFail, fmt.Sprintf("%s %s rule %d backendRef uses Service %s port %d, but that port is not exposed. Service ports: %s", route.GetKind(), routeName, ruleNumber, backendText, port, servicePorts(service)), gatewayOptionalDiagnosis(addDiagnosis, fmt.Sprintf("%s %s rule %d routes to Service %s port %d, but the Service exposes %s.", route.GetKind(), routeName, ruleNumber, backendText, port, servicePorts(service))))
		return
	}
	if service.Spec.Type == corev1.ServiceTypeExternalName {
		s.addWide("BackendRef Layer", check, model.StatusInfo, fmt.Sprintf("Service %s is ExternalName %q; EndpointSlice backend checks are not applicable.", backendText, service.Spec.ExternalName))
		return
	}
	ready, err := cachedReadyEndpointCount(ctx, client, namespace, name, endpointReadyCache, endpointErrCache)
	if err != nil {
		s.addProblemCategorized("Backend Endpoint Layer", check, model.StatusWarn, "api-inspection", fmt.Sprintf("Could not read EndpointSlices for Service %s: %v", backendText, err), "")
		return
	}
	if ready == 0 {
		weight := gatewayBackendRefWeight(backend)
		weightText := ""
		if weight > 0 {
			weightText = fmt.Sprintf(" weight %d", weight)
		}
		s.addProblem("Backend Endpoint Layer", check, model.StatusFail, fmt.Sprintf("%s %s rule %d backendRef%s points at Service %s port %d, but the Service has no ready EndpointSlice addresses.", route.GetKind(), routeName, ruleNumber, weightText, backendText, port), gatewayOptionalDiagnosis(addDiagnosis, fmt.Sprintf("%s %s rule %d routes to Service %s port %d, but that Service has no ready endpoints.", route.GetKind(), routeName, ruleNumber, backendText, port)))
	}
}

func gatewayOptionalDiagnosis(enabled bool, diagnosis string) string {
	if !enabled {
		return ""
	}
	return diagnosis
}

func (s *gatewayScanner) scanGatewayTrafficIntent(ctx context.Context, client *kube.Client, gateways []unstructured.Unstructured, parentGateways []unstructured.Unstructured, routes []unstructured.Unstructured, refGrants []unstructured.Unstructured, serviceCache map[string]*corev1.Service, serviceErrCache map[string]error, endpointReadyCache map[string]int, endpointErrCache map[string]error, intent gatewayTrafficIntent) {
	intent = gatewayFinalizeTrafficIntent(intent)
	s.trafficRouteKind = gatewayPrimaryRouteFamily(intent)
	scopedGateways := s.gatewayTrafficScopedGateways(gateways)
	scopedParentGateways := s.gatewayTrafficScopedGateways(parentGateways)
	scopedRoutes := s.gatewayTrafficScopedRoutes(routes)
	s.report.Add("Gateway Traffic Intent", "protocol inference", model.StatusInfo, fmt.Sprintf("Inferred protocol=%s route family=%s.", intent.Protocol, strings.Join(intent.RouteFamilies, ",")))
	listeners := gatewayTrafficMatchingListeners(scopedParentGateways, intent)
	attachedRoutes := gatewayTrafficAttachedRoutes(scopedRoutes, listeners)
	s.addGatewayTrafficScope(intent, listeners, attachedRoutes)
	s.addGatewayTrafficTLSDetails(ctx, client, listeners, refGrants)
	ruleMatches := gatewayFindRuleMatches(scopedParentGateways, scopedRoutes, intent)
	matches := gatewayFindCandidatePaths(scopedParentGateways, scopedRoutes, intent)
	selectedRules := gatewaySelectPrecedenceRules(ruleMatches)
	s.addGatewayTrafficRuleContext(ruleMatches, selectedRules)
	if len(selectedRules) > 0 {
		matches = gatewayFilterMatchesToSelectedRules(matches, selectedRules)
	}
	s.scannedGate = len(scopedGateways)
	s.scannedRoutes = len(scopedRoutes)
	intentText := gatewayTrafficIntentText(intent)
	if len(matches) == 0 {
		if gatewayTrafficIntentUsesHTTP(intent) {
			if redirect := gatewayFirstRedirectRule(defaultGatewayRuleMatches(selectedRules, ruleMatches)); redirect != nil {
				message := fmt.Sprintf("HTTPRoute %s/%s rule %d redirects this request instead of routing to backendRefs.", redirect.RouteNamespace, redirect.RouteName, redirect.RuleNumber)
				s.addProblem("Gateway Traffic Intent", "redirect", model.StatusFail, message, message)
				return
			}
		}
		reason := gatewayExplainNoTrafficMatch(scopedParentGateways, scopedRoutes, intent)
		s.addProblem("Gateway Traffic Intent", "route match", model.StatusFail, reason.Message, reason.Diagnosis)
		return
	}
	routeIndex := map[string]unstructured.Unstructured{}
	for _, route := range scopedRoutes {
		routeIndex[objectRefText(route)] = route
		if route.GetNamespace() != "" && route.GetName() != "" {
			routeIndex[route.GetNamespace()+"/"+route.GetName()] = route
		}
	}
	s.addGatewayTrafficRouteParentStatus(routeIndex, gatewayIndex(scopedParentGateways), matches)
	s.addGatewayExpectedServiceCheck(matches)
	if gatewayTrafficIntentUsesHTTP(intent) {
		s.addGatewaySelectedRuleFilterDetails(ctx, client, routeIndex, selectedRules, refGrants, serviceCache, serviceErrCache, endpointReadyCache, endpointErrCache, intent)
	}
	reported := map[string]bool{}
	backendAnalyses := map[string]gatewayBackendRefAnalysis{}
	groupAnalyses := map[string][]gatewayBackendRefAnalysis{}
	for _, match := range matches {
		check := fmt.Sprintf("%s/%s -> %s rule %d backend %d", match.GatewayNamespace, match.GatewayName, match.RouteNamespace+"/"+match.RouteName, match.RuleNumber, match.BackendNumber)
		backendText := fmt.Sprintf("%s/%s:%d", match.BackendNamespace, match.BackendName, match.BackendPort)
		routeKind := defaultString(match.RouteKind, "HTTPRoute")
		s.report.Add("Gateway Traffic Path", check, model.StatusInfo, fmt.Sprintf("%s matches listener %s/%s/%s and %s %s/%s rule %d (%s), backend %s weight %d.", intentText, match.GatewayNamespace, match.GatewayName, match.ListenerName, routeKind, match.RouteNamespace, match.RouteName, match.RuleNumber, match.MatchSummary, backendText, match.BackendWeight))
		route := routeIndex[match.RouteNamespace+"/"+match.RouteName]
		backend, ok := gatewayRouteBackendRefAt(route, match.RuleNumber, match.BackendNumber)
		if !ok {
			continue
		}
		key := fmt.Sprintf("%s/%s/%d/%d", match.RouteNamespace, match.RouteName, match.RuleNumber, match.BackendNumber)
		if reported[key] {
			continue
		}
		reported[key] = true
		analysis := gatewayAnalyzeBackendRef(ctx, client, route, match.RuleNumber, match.BackendNumber, backend, refGrants, serviceCache, serviceErrCache, endpointReadyCache, endpointErrCache)
		backendAnalyses[key] = analysis
		groupAnalyses[analysis.GroupKey] = append(groupAnalyses[analysis.GroupKey], analysis)
	}
	weightedGroups := gatewayMixedWeightedGroups(groupAnalyses)
	scanned := map[string]bool{}
	for _, match := range matches {
		route := routeIndex[match.RouteNamespace+"/"+match.RouteName]
		backend, ok := gatewayRouteBackendRefAt(route, match.RuleNumber, match.BackendNumber)
		if !ok {
			continue
		}
		key := fmt.Sprintf("%s/%s/%d/%d", match.RouteNamespace, match.RouteName, match.RuleNumber, match.BackendNumber)
		if scanned[key] {
			continue
		}
		scanned[key] = true
		analysis, ok := backendAnalyses[key]
		if !ok {
			continue
		}
		s.scanRouteBackendRefWithDiagnosis(ctx, client, route.GetKind(), route, match.RuleNumber, match.BackendNumber, backend, refGrants, serviceCache, serviceErrCache, endpointReadyCache, endpointErrCache, !weightedGroups[analysis.GroupKey])
	}
	for _, group := range gatewaySortedWeightedGroups(weightedGroups) {
		analyses := groupAnalyses[group]
		message := gatewayWeightedBackendMessage(analyses)
		if message == "" {
			continue
		}
		s.report.AddCategorized("Gateway Traffic Path", analyses[0].RouteName+" rule "+strconv.Itoa(analyses[0].RuleNumber)+" weighted backendRefs", model.StatusWarn, "conditional-routing", message)
		s.report.Diagnose(message)
	}
	if s.opts.Probe && gatewayTrafficIntentUsesHTTP(intent) {
		s.addGatewayTrafficDataplaneContext(ctx, client, scopedParentGateways, matches, endpointReadyCache, endpointErrCache)
		s.runGatewayHTTPProbes(ctx, client, scopedParentGateways, matches, intent)
	} else if s.opts.Probe {
		s.report.Add("Gateway Runtime Probe", "route family", model.StatusSkip, fmt.Sprintf("Live probes currently run for HTTP/HTTPS Gateway traffic; %s tracing is static only.", strings.Join(intent.RouteFamilies, "/")))
	}
	if s.report.CountByStatus(model.StatusFail) == 0 && s.report.CountByStatus(model.StatusWarn) == 0 {
		s.report.Add("Gateway Traffic Path", "matched backends", model.StatusPass, fmt.Sprintf("%d matching backend path(s) found for %s, and no obvious backend reference or endpoint problems were detected.", len(matches), intentText))
	}
}

func (s *gatewayScanner) addGatewayTrafficRouteParentStatus(routeIndex map[string]unstructured.Unstructured, parentGateways map[string]unstructured.Unstructured, matches []gatewayPathMatch) {
	seen := map[string]bool{}
	for _, match := range matches {
		routeKey := match.RouteNamespace + "/" + match.RouteName
		if seen[routeKey] {
			continue
		}
		seen[routeKey] = true
		route, ok := routeIndex[routeKey]
		if !ok {
			continue
		}
		s.scanRouteParents(defaultString(match.RouteKind, route.GetKind()), route, parentGateways)
	}
}

func (s *gatewayScanner) addGatewayTrafficDataplaneContext(ctx context.Context, client *kube.Client, gateways []unstructured.Unstructured, matches []gatewayPathMatch, endpointReadyCache map[string]int, endpointErrCache map[string]error) {
	gatewayIndex := gatewayIndex(gateways)
	seen := map[string]bool{}
	for _, match := range matches {
		key := match.GatewayNamespace + "/" + match.GatewayName
		if seen[key] {
			continue
		}
		seen[key] = true
		gateway, ok := gatewayIndex[key]
		if !ok {
			continue
		}
		services, err := gatewayImplementationServices(ctx, client, gateway)
		if err != nil {
			s.report.AddCategorized("Gateway Dataplane Layer", key+" services", model.StatusWarn, "api-inspection", fmt.Sprintf("Could not list implementation Services for Gateway %s: %v", key, err))
			continue
		}
		if len(services) == 0 {
			s.report.Add("Gateway Dataplane Layer", key+" services", model.StatusInfo, fmt.Sprintf("No implementation Service with label gateway.networking.k8s.io/gateway-name=%s was found for Gateway %s.", gateway.GetName(), key))
			continue
		}
		for _, service := range services {
			serviceName := service.Namespace + "/" + service.Name
			ready, err := cachedReadyEndpointCount(ctx, client, service.Namespace, service.Name, endpointReadyCache, endpointErrCache)
			if err != nil {
				s.report.AddCategorized("Gateway Dataplane Layer", serviceName+" endpoints", model.StatusWarn, "api-inspection", fmt.Sprintf("Could not read EndpointSlices for Gateway implementation Service %s: %v", serviceName, err))
				continue
			}
			if ready == 0 {
				message := fmt.Sprintf("Gateway implementation Service %s has no ready EndpointSlice addresses.", serviceName)
				s.report.Add("Gateway Dataplane Layer", serviceName+" endpoints", model.StatusFail, message)
				if !hasGatewayTrafficStaticDiagnosis(s.report) {
					s.report.Diagnose(fmt.Sprintf("Gateway implementation Service %s has no ready endpoints, so Gateway traffic has no ready dataplane pod.", serviceName))
				}
				continue
			}
			s.report.Add("Gateway Dataplane Layer", serviceName+" endpoints", model.StatusPass, fmt.Sprintf("Gateway implementation Service %s has %d ready endpoint address(es).", serviceName, ready))
		}
	}
}

func (s *gatewayScanner) runGatewayHTTPProbes(ctx context.Context, client *kube.Client, gateways []unstructured.Unstructured, matches []gatewayPathMatch, intent gatewayTrafficIntent) {
	gatewayIndex := gatewayIndex(gateways)
	seen := map[string]bool{}
	debugTargets := map[string]*ExecTarget{}
	for _, match := range matches {
		gateway, ok := gatewayIndex[match.GatewayNamespace+"/"+match.GatewayName]
		if !ok {
			continue
		}
		addresses := gatewayStatusAddressValues(gateway)
		if len(addresses) == 0 {
			s.report.Add("Gateway Runtime Probe", match.GatewayNamespace+"/"+match.GatewayName, model.StatusWarn, fmt.Sprintf("Skipped live probe because Gateway %s/%s has no status.addresses entries.", match.GatewayNamespace, match.GatewayName))
			continue
		}
		port := match.ListenerPort
		if port == 0 {
			port = intent.Port
		}
		if port == 0 {
			s.report.Add("Gateway Runtime Probe", match.GatewayNamespace+"/"+match.GatewayName, model.StatusWarn, fmt.Sprintf("Skipped live probe because Gateway listener %s/%s/%s has no port.", match.GatewayNamespace, match.GatewayName, match.ListenerName))
			continue
		}
		scheme := intent.Scheme
		if scheme == "" {
			scheme = gatewaySchemeForListenerProtocol(match.ListenerProtocol)
		}
		if scheme == "" {
			scheme = "http"
		}
		implementationServices, serviceErr := gatewayImplementationServices(ctx, client, gateway)
		if serviceErr != nil {
			s.report.Add("Gateway Runtime Probe", match.GatewayNamespace+"/"+match.GatewayName+" in-cluster", model.StatusWarn, fmt.Sprintf("Skipped in-cluster probe because implementation Services for Gateway %s/%s could not be listed: %v", match.GatewayNamespace, match.GatewayName, serviceErr))
		}
		externalPass := false
		externalFailureDiagnosis := ""
		for _, address := range addresses {
			key := fmt.Sprintf("%s/%s/%s/%s/%d/%s", match.GatewayNamespace, match.GatewayName, match.ListenerName, address, port, scheme)
			if seen[key] {
				continue
			}
			seen[key] = true
			rawURL := gatewayProbeURL(scheme, intent.Host, port, intent.Path, intent.Query)
			dialAddress, dialPort, dialText, err := gatewayProbeDialTarget(address, port, s.opts.ProbeAddress)
			check := fmt.Sprintf("%s/%s/%s via %s", match.GatewayNamespace, match.GatewayName, match.ListenerName, dialText)
			if err != nil {
				s.report.Add("Gateway Runtime Probe", check, model.StatusWarn, fmt.Sprintf("Skipped workstation/client probe because --probe-address %q is invalid: %v", s.opts.ProbeAddress, err))
				continue
			}
			result := testGatewayLocalHTTP(rawURL, dialAddress, dialPort, intent.Host, intent.Method, s.opts.Timeout, intent.Headers)
			if result.OK {
				externalPass = true
				s.report.Add("Gateway Runtime Probe", check, model.StatusPass, fmt.Sprintf("Gateway address %s:%d answered %s for host %q. HTTP status: %s", address, port, rawURL, intent.Host, result.Status))
				continue
			}
			s.report.Add("Gateway Runtime Probe", check, model.StatusFail, fmt.Sprintf("Gateway address %s:%d did not complete %s for host %q: %s", address, port, rawURL, intent.Host, result.Error))
			if externalFailureDiagnosis == "" {
				externalFailureDiagnosis = fmt.Sprintf("advertised Gateway address %s:%d did not complete %s for host %q. Error: %s", address, port, rawURL, intent.Host, compactCommandOutput(result.Error))
			}
		}
		if serviceErr != nil {
			if externalFailureDiagnosis != "" && !externalPass && !hasGatewayTrafficStaticDiagnosis(s.report) {
				s.report.Diagnose(externalFailureDiagnosis)
			}
			continue
		}
		service, servicePort, ok := gatewayImplementationServiceForPort(implementationServices, port)
		if !ok {
			s.report.Add("Gateway Runtime Probe", match.GatewayNamespace+"/"+match.GatewayName+" in-cluster", model.StatusWarn, fmt.Sprintf("Skipped in-cluster probe because no implementation Service for Gateway %s/%s exposes listener port %d.", match.GatewayNamespace, match.GatewayName, port))
			if externalFailureDiagnosis != "" && !externalPass && !hasGatewayTrafficStaticDiagnosis(s.report) {
				s.report.Diagnose(externalFailureDiagnosis)
			}
			continue
		}
		key := fmt.Sprintf("%s/%s/%s/%s/%d/%s/in-cluster", match.GatewayNamespace, match.GatewayName, match.ListenerName, service.Namespace+"/"+service.Name, servicePort, scheme)
		if seen[key] {
			continue
		}
		seen[key] = true
		target, ok := debugTargets[service.Namespace]
		if !ok {
			pod, err := ensureGatewayDebugPod(ctx, client, service.Namespace, s.opts.DebugPodName, s.opts.DebugImage, s.opts.DebugPullPolicy, maxDuration(s.opts.Timeout+30*time.Second, 60*time.Second))
			if err != nil {
				s.report.Add("Gateway Runtime Probe", service.Namespace+"/"+s.opts.DebugPodName, model.StatusWarn, fmt.Sprintf("Skipped in-cluster probe because debug pod %q in namespace %q was not ready: %v", s.opts.DebugPodName, service.Namespace, err))
				if externalFailureDiagnosis != "" && !externalPass && !hasGatewayTrafficStaticDiagnosis(s.report) {
					s.report.Diagnose(externalFailureDiagnosis)
				}
				continue
			}
			target = &ExecTarget{Client: client, Pod: *pod, Kind: "gateway debug pod"}
			debugTargets[service.Namespace] = target
			s.report.Add("Gateway Runtime Probe", service.Namespace+"/"+s.opts.DebugPodName, model.StatusPass, fmt.Sprintf("Gateway debug pod %q is Ready in namespace %q.", pod.Name, service.Namespace))
		}
		rawURL := gatewayImplementationServiceProbeURL(scheme, service, servicePort, intent.Path, intent.Query)
		headers := map[string]string{}
		for key, value := range intent.Headers {
			headers[key] = value
		}
		if intent.Host != "" {
			headers["Host"] = intent.Host
		}
		result := curlURL(ctx, *target, rawURL, s.opts.Timeout, headers)
		check := fmt.Sprintf("%s/%s/%s via Service %s/%s:%d", match.GatewayNamespace, match.GatewayName, match.ListenerName, service.Namespace, service.Name, servicePort)
		if result.OK {
			s.report.Add("Gateway Runtime Probe", check, model.StatusPass, fmt.Sprintf("Gateway implementation Service %s/%s answered %s for host %q from inside the cluster. HTTP status: %s", service.Namespace, service.Name, rawURL, intent.Host, result.StatusCode))
			runtimeStatusNeedsFollowup := gatewayRuntimeStatusNeedsServiceFollowup(result.StatusCode)
			if runtimeStatusNeedsFollowup && !hasGatewayTrafficStaticDiagnosis(s.report) {
				if inspectGatewayIstioBackendTLSMismatch(ctx, client, s.report, matches, &service, result.StatusCode) {
					// The provider-specific cause is more useful than a generic handoff.
				} else if command, ok := gatewayCheckServiceFollowupCommand(matches, &service, intent); ok {
					s.report.Diagnose(fmt.Sprintf("Gateway probe reached the in-cluster Gateway implementation Service but returned HTTP %s. Run this to verify the selected backend service path: %s", result.StatusCode, command))
				} else {
					s.report.Diagnose(fmt.Sprintf("Gateway probe reached the in-cluster Gateway implementation Service but returned HTTP %s. KNM did not generate a check service follow-up because the request did not select exactly one HTTPRoute Service backend.", result.StatusCode))
				}
			}
			if externalFailureDiagnosis != "" && !externalPass && !runtimeStatusNeedsFollowup && !hasGatewayTrafficStaticDiagnosis(s.report) {
				s.report.Diagnose(fmt.Sprintf("Gateway implementation Service %s/%s works from inside the cluster, but the workstation/client path to the %s", service.Namespace, service.Name, externalFailureDiagnosis))
			}
			continue
		}
		classification := classifyRuntimeHTTPFailure(result)
		s.report.Add("Gateway Runtime Probe", check, model.StatusFail, runtimeProbeFailureMessage(*target, rawURL, result, classification))
		if !hasGatewayTrafficStaticDiagnosis(s.report) && !externalPass {
			followup := ""
			if command, ok := gatewayCheckServiceFollowupCommand(matches, &service, intent); ok {
				followup = fmt.Sprintf(" Run this to verify the selected backend service path: %s", command)
			}
			s.report.Diagnose(fmt.Sprintf("Gateway implementation Service %s/%s failed from inside the cluster for host %q. Error: %s%s", service.Namespace, service.Name, intent.Host, compactCommandOutput(result.Error), followup))
		}
	}
}

func gatewayRuntimeStatusNeedsServiceFollowup(status string) bool {
	switch strings.TrimSpace(status) {
	case "502", "503", "504":
		return true
	default:
		return false
	}
}

func gatewayProbeDialTarget(address string, port int32, override string) (string, int32, string, error) {
	defaultText := net.JoinHostPort(address, strconv.Itoa(int(port)))
	override = strings.TrimSpace(override)
	if override == "" {
		return address, port, defaultText, nil
	}
	host, rawPort, err := net.SplitHostPort(override)
	if err == nil {
		parsedPort, parseErr := strconv.Atoi(rawPort)
		if parseErr != nil || parsedPort <= 0 || parsedPort > 65535 {
			return "", 0, defaultText, fmt.Errorf("port must be between 1 and 65535")
		}
		text := fmt.Sprintf("%s using probe address %s", defaultText, net.JoinHostPort(host, rawPort))
		probePort, _ := int32PortFromInt(parsedPort)
		return host, probePort, text, nil
	}
	if strings.Contains(override, ":") {
		return "", 0, defaultText, err
	}
	text := fmt.Sprintf("%s using probe address %s", defaultText, net.JoinHostPort(override, strconv.Itoa(int(port))))
	return override, port, text, nil
}

func inspectGatewayIstioBackendTLSMismatch(ctx context.Context, client *kube.Client, report *model.Report, matches []gatewayPathMatch, gatewayService *corev1.Service, statusCode string) bool {
	if client == nil || client.Istio == nil || gatewayService == nil {
		return false
	}
	seen := map[string]bool{}
	found := false
	for _, match := range matches {
		if defaultString(match.RouteKind, "HTTPRoute") != "HTTPRoute" || match.BackendNamespace == "" || match.BackendName == "" || match.BackendPort == 0 {
			continue
		}
		key := fmt.Sprintf("%s/%s/%d", match.BackendNamespace, match.BackendName, match.BackendPort)
		if seen[key] {
			continue
		}
		seen[key] = true
		service, err := client.Core.CoreV1().Services(match.BackendNamespace).Get(ctx, match.BackendName, metav1.GetOptions{})
		if err != nil || service.Spec.Type == corev1.ServiceTypeExternalName || len(service.Spec.Selector) == 0 {
			continue
		}
		pods, err := client.Core.CoreV1().Pods(service.Namespace).List(ctx, metav1.ListOptions{LabelSelector: labels.Set(service.Spec.Selector).String()})
		if err != nil || len(pods.Items) == 0 {
			continue
		}
		meshed := 0
		ready := 0
		for _, pod := range pods.Items {
			if podReady(pod) {
				ready++
			}
			if podHasIstioSidecar(pod) {
				meshed++
			}
		}
		if ready == 0 || meshed > 0 {
			continue
		}
		namespaces := uniqueStrings([]string{service.Namespace, gatewayService.Namespace, istioRootNamespace(ctx, client)})
		destinationRules, err := listIstioDestinationRules(ctx, client, namespaces)
		if err != nil {
			continue
		}
		destinationRules = istioServicePathDestinationRules(destinationRules, ServiceOptions{Namespace: service.Namespace, SourceNamespace: gatewayService.Namespace}, nil)
		dr, ok := gatewayFindDestinationRule(destinationRules, service)
		if !ok {
			continue
		}
		mode, ok := trafficPolicyTLSMode(dr.Spec.GetTrafficPolicy(), match.BackendPort)
		if !ok || !gatewayIstioTLSModeRequiresMeshedBackend(mode) {
			continue
		}
		drName := dr.Namespace + "/" + dr.Name
		serviceName := service.Namespace + "/" + service.Name
		report.Add("Gateway Istio Layer", drName, model.StatusFail, fmt.Sprintf("Gateway probe returned HTTP %s and DestinationRule %s applies TLS mode %s to backend Service %s, but selected backend pods are not in the mesh.", statusCode, drName, mode.String(), serviceName))
		report.Diagnose(fmt.Sprintf("Primary issue: Istio DestinationRule %q configures %s TLS for Gateway backend Service %q, but the selected backend pod(s) are not in the mesh. The Gateway proxy sends Istio mTLS to a plain workload, causing HTTP %s upstream connection failure.", drName, mode.String(), serviceName, statusCode))
		found = true
	}
	return found
}

func gatewayFindDestinationRule(items []*networkingv1.DestinationRule, service *corev1.Service) (*networkingv1.DestinationRule, bool) {
	host := service.Name + "." + service.Namespace + ".svc.cluster.local"
	if dr, ok := findDestinationRule(items, host, service.Namespace, service); ok {
		return dr, true
	}
	for _, item := range items {
		if item == nil {
			continue
		}
		drHost := istioResolveHost(item.Spec.GetHost(), item.Namespace)
		if strings.Contains(drHost, "*") && sidecarDNSHostMatches(drHost, host) {
			return item, true
		}
	}
	return nil, false
}

func gatewayIstioTLSModeRequiresMeshedBackend(mode networkingapi.ClientTLSSettings_TLSmode) bool {
	switch mode {
	case networkingapi.ClientTLSSettings_ISTIO_MUTUAL:
		return true
	default:
		return false
	}
}

func gatewayCheckServiceFollowupCommand(matches []gatewayPathMatch, gatewayService *corev1.Service, intent gatewayTrafficIntent) (string, bool) {
	if gatewayService == nil {
		return "", false
	}
	unique := map[string]gatewayPathMatch{}
	for _, match := range matches {
		if match.BackendNamespace == "" || match.BackendName == "" || match.BackendPort == 0 {
			return "", false
		}
		if defaultString(match.RouteKind, "HTTPRoute") != "HTTPRoute" {
			return "", false
		}
		key := fmt.Sprintf("%s/%s/%d", match.BackendNamespace, match.BackendName, match.BackendPort)
		unique[key] = match
	}
	if len(unique) != 1 {
		return "", false
	}
	var match gatewayPathMatch
	for _, value := range unique {
		match = value
	}
	path := intent.Path
	if path == "" {
		path = "/"
	}
	parts := []string{
		"knm", "check", "service",
		"-n", shellQuoteIfNeeded(match.BackendNamespace),
		"-t", shellQuoteIfNeeded(match.BackendName),
		"--source-namespace", shellQuoteIfNeeded(gatewayService.Namespace),
		"-s", shellQuoteIfNeeded(gatewayService.Name),
		"--port", strconv.Itoa(int(match.BackendPort)),
		"--path", shellQuoteIfNeeded(path),
	}
	return strings.Join(parts, " "), true
}

func shellQuoteIfNeeded(value string) string {
	if value == "" {
		return `""`
	}
	if strings.ContainsAny(value, " \t\r\n\"'`$&|<>;(){}[]*?!") {
		return strconv.Quote(value)
	}
	return value
}

func ensureGatewayDebugPod(ctx context.Context, client *kube.Client, namespace, name, image, imagePullPolicy string, timeout time.Duration) (*corev1.Pod, error) {
	existing, err := client.Core.CoreV1().Pods(namespace).Get(ctx, name, metav1.GetOptions{})
	if err == nil && !kube.IsKubeNetModsDebugPod(existing) {
		return nil, fmt.Errorf("refusing to reuse pod %s/%s because it is not labeled as a KubeNetMods debug pod", namespace, name)
	}
	if err == nil && existing.DeletionTimestamp == nil && existing.Status.Phase == corev1.PodRunning && podReady(*existing) {
		return existing, nil
	}
	if err == nil && existing.DeletionTimestamp != nil {
		deadline := time.Now().Add(maxDuration(timeout, 30*time.Second))
		for time.Now().Before(deadline) {
			select {
			case <-ctx.Done():
				return nil, ctx.Err()
			case <-time.After(1 * time.Second):
			}
			current, getErr := client.Core.CoreV1().Pods(namespace).Get(ctx, name, metav1.GetOptions{})
			if apierrors.IsNotFound(getErr) {
				break
			}
			if getErr != nil {
				return nil, getErr
			}
			if current.DeletionTimestamp == nil && current.Status.Phase == corev1.PodRunning && podReady(*current) {
				return current, nil
			}
		}
	}
	if err != nil && !apierrors.IsNotFound(err) {
		return nil, err
	}
	return client.EnsureDebugPod(ctx, namespace, name, image, imagePullPolicy, timeout)
}

func gatewayStatusAddressValues(gateway unstructured.Unstructured) []string {
	var out []string
	for _, raw := range sliceField(gateway.Object, "status", "addresses") {
		item, ok := raw.(map[string]interface{})
		if !ok {
			continue
		}
		if value := stringField(item, "value"); value != "" {
			out = append(out, value)
		}
	}
	return uniqueStrings(out)
}

func gatewayImplementationServices(ctx context.Context, client *kube.Client, gateway unstructured.Unstructured) ([]corev1.Service, error) {
	selector := "gateway.networking.k8s.io/gateway-name=" + gateway.GetName()
	list, err := client.Core.CoreV1().Services(gateway.GetNamespace()).List(ctx, metav1.ListOptions{LabelSelector: selector})
	if err != nil {
		return nil, err
	}
	out := append([]corev1.Service(nil), list.Items...)
	sort.Slice(out, func(i, j int) bool {
		return out[i].Namespace+"/"+out[i].Name < out[j].Namespace+"/"+out[j].Name
	})
	return out, nil
}

func gatewayImplementationServiceForPort(services []corev1.Service, listenerPort int32) (corev1.Service, int32, bool) {
	for _, service := range services {
		for _, port := range service.Spec.Ports {
			if port.Port == listenerPort {
				return service, port.Port, true
			}
		}
	}
	if len(services) == 1 && len(services[0].Spec.Ports) == 1 {
		return services[0], services[0].Spec.Ports[0].Port, true
	}
	return corev1.Service{}, 0, false
}

func gatewaySchemeForListenerProtocol(protocol string) string {
	switch strings.ToUpper(strings.TrimSpace(protocol)) {
	case "HTTPS", "TLS":
		return "https"
	default:
		return "http"
	}
}

func gatewayProbeURL(scheme, host string, port int32, path string, query url.Values) string {
	if scheme == "" {
		scheme = "http"
	}
	if path == "" {
		path = "/"
	}
	if !strings.HasPrefix(path, "/") {
		path = "/" + path
	}
	u := url.URL{
		Scheme: scheme,
		Host:   net.JoinHostPort(host, strconv.Itoa(int(port))),
		Path:   path,
	}
	if len(query) > 0 {
		u.RawQuery = query.Encode()
	}
	return u.String()
}

func gatewayImplementationServiceProbeURL(scheme string, service corev1.Service, port int32, path string, query url.Values) string {
	if scheme == "" {
		scheme = "http"
	}
	if path == "" {
		path = "/"
	}
	if !strings.HasPrefix(path, "/") {
		path = "/" + path
	}
	u := url.URL{
		Scheme: scheme,
		Host:   net.JoinHostPort(service.Name+"."+service.Namespace+".svc.cluster.local", strconv.Itoa(int(port))),
		Path:   path,
	}
	if len(query) > 0 {
		u.RawQuery = query.Encode()
	}
	return u.String()
}

func testGatewayLocalHTTP(rawURL, dialAddress string, dialPort int32, hostHeader string, method string, timeout time.Duration, headers map[string]string) localHTTPResult {
	parsed, err := url.Parse(rawURL)
	if err != nil || parsed.Scheme == "" || parsed.Host == "" {
		return localHTTPResult{Error: "invalid URL"}
	}
	dialTarget := net.JoinHostPort(dialAddress, strconv.Itoa(int(dialPort)))
	dialer := &net.Dialer{Timeout: timeout}
	transport := &http.Transport{
		Proxy: nil,
		DialContext: func(ctx context.Context, network, _ string) (net.Conn, error) {
			return dialer.DialContext(ctx, network, dialTarget)
		},
		TLSClientConfig: &tls.Config{
			InsecureSkipVerify: true,
			ServerName:         hostHeader,
		},
	}
	client := &http.Client{
		Timeout:   timeout,
		Transport: transport,
		CheckRedirect: func(req *http.Request, via []*http.Request) error {
			return http.ErrUseLastResponse
		},
	}
	if method == "" {
		method = http.MethodGet
	}
	req, err := http.NewRequest(method, rawURL, nil)
	if err != nil {
		return localHTTPResult{Error: err.Error()}
	}
	if hostHeader != "" {
		req.Host = hostHeader
	}
	for key, value := range headers {
		req.Header.Set(key, value)
	}
	resp, err := client.Do(req)
	if err != nil {
		return localHTTPResult{Error: err.Error()}
	}
	defer resp.Body.Close()
	status := strconv.Itoa(resp.StatusCode)
	if resp.StatusCode < 500 {
		return localHTTPResult{OK: true, Status: status}
	}
	return localHTTPResult{Status: status, Error: resp.Status}
}

func hasGatewayTrafficStaticDiagnosis(report *model.Report) bool {
	return len(report.Diagnoses) > 0
}

func (s *gatewayScanner) addGatewaySelectedRuleFilterDetails(ctx context.Context, client *kube.Client, routeIndex map[string]unstructured.Unstructured, selectedRules []gatewayRuleMatch, refGrants []unstructured.Unstructured, serviceCache map[string]*corev1.Service, serviceErrCache map[string]error, endpointReadyCache map[string]int, endpointErrCache map[string]error, intent gatewayTrafficIntent) {
	reportedRewrite := map[string]bool{}
	reportedMirror := map[string]bool{}
	for _, match := range selectedRules {
		route, ok := routeIndex[match.RouteNamespace+"/"+match.RouteName]
		if !ok {
			continue
		}
		ruleRef := fmt.Sprintf("%s/%s rule %d", match.RouteNamespace, match.RouteName, match.RuleNumber)
		if rewrite := gatewayURLRewriteText(match.Rule, intent); rewrite != "" && !reportedRewrite[ruleRef] {
			reportedRewrite[ruleRef] = true
			s.report.Add("Gateway Traffic Path", ruleRef+" rewrite", model.StatusInfo, fmt.Sprintf("HTTPRoute %s %s.", ruleRef, rewrite))
		}
		for mirrorIndex, mirror := range gatewayRequestMirrorBackendRefs(match.Rule) {
			key := fmt.Sprintf("%s/%d", ruleRef, mirrorIndex)
			if reportedMirror[key] {
				continue
			}
			reportedMirror[key] = true
			analysis := gatewayAnalyzeBackendRef(ctx, client, route, match.RuleNumber, mirrorIndex+1, mirror, refGrants, serviceCache, serviceErrCache, endpointReadyCache, endpointErrCache)
			if analysis.Broken {
				message := fmt.Sprintf("HTTPRoute %s mirrors this request to %s, but the mirror backend is broken: %s.", ruleRef, analysis.BackendText, analysis.Reason)
				s.report.AddCategorized("Gateway Traffic Path", ruleRef+" mirror "+strconv.Itoa(mirrorIndex+1), model.StatusWarn, "conditional-routing", message)
				s.report.Diagnose(message)
				continue
			}
			s.report.Add("Gateway Traffic Path", ruleRef+" mirror "+strconv.Itoa(mirrorIndex+1), model.StatusInfo, fmt.Sprintf("HTTPRoute %s mirrors this request to %s.", ruleRef, analysis.BackendText))
		}
	}
}

func (s *gatewayScanner) addGatewayTrafficTLSDetails(ctx context.Context, client *kube.Client, listeners []gatewayListenerCandidate, refGrants []unstructured.Unstructured) {
	for _, candidate := range listeners {
		protocol := strings.ToUpper(strings.TrimSpace(stringField(candidate.Listener, "protocol")))
		if protocol != "HTTPS" && protocol != "TLS" {
			continue
		}
		gwName := objectRefText(candidate.Gateway)
		listenerName := stringField(candidate.Listener, "name")
		check := gwName + "/" + listenerName
		status := gatewayStatusListeners(candidate.Gateway.Object)[listenerName]
		if cond, ok := conditionByType(status, string(gatewayv1.ListenerConditionProgrammed)); ok && strings.EqualFold(cond.Status, "False") {
			s.addProblem("Gateway Traffic TLS", check+" Programmed", model.StatusFail, fmt.Sprintf("Matched HTTPS listener %s is not Programmed: %s%s", check, cond.Reason, conditionMessageSuffix(cond.Message)), fmt.Sprintf("HTTPS request matched Gateway listener %s, but that listener is not Programmed: %s%s", check, cond.Reason, conditionMessageSuffix(cond.Message)))
		}
		if cond, ok := conditionByType(status, string(gatewayv1.ListenerConditionResolvedRefs)); ok && strings.EqualFold(cond.Status, "False") {
			s.addProblem("Gateway Traffic TLS", check+" ResolvedRefs", model.StatusFail, fmt.Sprintf("Matched HTTPS listener %s has unresolved TLS/reference config: %s%s", check, cond.Reason, conditionMessageSuffix(cond.Message)), fmt.Sprintf("HTTPS request matched Gateway listener %s, but its references are not resolved: %s%s", check, cond.Reason, conditionMessageSuffix(cond.Message)))
		}
		s.addGatewayTrafficTLSSecretRefs(ctx, client, candidate.Gateway, candidate.Listener, refGrants)
	}
}

func (s *gatewayScanner) addGatewayTrafficTLSSecretRefs(ctx context.Context, client *kube.Client, gateway unstructured.Unstructured, listener map[string]interface{}, refGrants []unstructured.Unstructured) {
	certRefs := sliceField(listener, "tls", "certificateRefs")
	if len(certRefs) == 0 {
		return
	}
	gwName := objectRefText(gateway)
	listenerName := stringField(listener, "name")
	checkPrefix := gwName + "/" + listenerName
	for _, raw := range certRefs {
		ref, ok := raw.(map[string]interface{})
		if !ok {
			continue
		}
		name := stringField(ref, "name")
		if name == "" {
			continue
		}
		group := stringField(ref, "group")
		kind := defaultString(stringField(ref, "kind"), "Secret")
		namespace := defaultString(stringField(ref, "namespace"), gateway.GetNamespace())
		check := fmt.Sprintf("%s cert %s/%s", checkPrefix, namespace, name)
		if group != "" || kind != "Secret" {
			s.report.AddCategorized("Gateway Traffic TLS", check, model.StatusWarn, "unsupported-ref", fmt.Sprintf("Matched HTTPS listener %s certificateRef %s/%s is %s/%s; KNM only validates core Secret refs right now.", checkPrefix, namespace, name, group, kind))
			continue
		}
		if namespace != gateway.GetNamespace() && !referenceGrantAllows(refGrants, gatewayv1.GroupName, "Gateway", gateway.GetNamespace(), "", "Secret", name, namespace) {
			message := fmt.Sprintf("HTTPS request matched Gateway listener %s, but it references TLS Secret %s/%s across namespaces without a matching ReferenceGrant.", checkPrefix, namespace, name)
			s.addProblem("Gateway Traffic TLS", check, model.StatusFail, message, message)
			continue
		}
		if _, err := client.Core.CoreV1().Secrets(namespace).Get(ctx, name, metav1.GetOptions{}); err != nil {
			message := fmt.Sprintf("HTTPS request matched Gateway listener %s, but TLS Secret %s/%s is missing or unreadable.", checkPrefix, namespace, name)
			s.addProblem("Gateway Traffic TLS", check, model.StatusFail, message, message)
			continue
		}
		s.report.Add("Gateway Traffic TLS", check, model.StatusPass, fmt.Sprintf("Matched HTTPS listener %s references readable TLS Secret %s/%s.", checkPrefix, namespace, name))
	}
}

func defaultGatewayRuleMatches(primary, fallback []gatewayRuleMatch) []gatewayRuleMatch {
	if len(primary) > 0 {
		return primary
	}
	return fallback
}

func (s *gatewayScanner) addGatewayTrafficRuleContext(matches []gatewayRuleMatch, selected []gatewayRuleMatch) {
	if len(matches) == 0 {
		return
	}
	var ruleRefs []string
	seenRules := map[string]bool{}
	for _, match := range matches {
		key := fmt.Sprintf("%s/%s rule %d", match.RouteNamespace, match.RouteName, match.RuleNumber)
		if !seenRules[key] {
			seenRules[key] = true
			ruleRefs = append(ruleRefs, key)
		}
		if filters := gatewayHTTPRouteRuleFilterSummary(match.Rule); filters != "" {
			routeKind := defaultString(match.RouteKind, "HTTPRoute")
			s.report.Add("Gateway Traffic Path", key+" filters", model.StatusInfo, fmt.Sprintf("%s %s applies filter(s): %s.", routeKind, key, filters))
		}
	}
	sort.Strings(ruleRefs)
	if len(ruleRefs) > 1 {
		routeKind := "HTTPRoute"
		if len(matches) > 0 && matches[0].RouteKind != "" {
			routeKind = matches[0].RouteKind
		}
		s.report.Add("Gateway Traffic Path", "multiple matching rules", model.StatusInfo, fmt.Sprintf("Request matches multiple %s rules: %s.", routeKind, strings.Join(ruleRefs, ", ")))
	}
	if len(selected) == 0 || len(ruleRefs) <= 1 {
		return
	}
	var selectedRefs []string
	for _, match := range selected {
		selectedRefs = append(selectedRefs, fmt.Sprintf("%s/%s/%s -> %s/%s rule %d (%s)", match.GatewayNamespace, match.GatewayName, match.ListenerName, match.RouteNamespace, match.RouteName, match.RuleNumber, gatewaySelectedRuleReason(match, matches)))
	}
	sort.Strings(selectedRefs)
	s.report.Add("Gateway Traffic Path", "selected rule", model.StatusInfo, fmt.Sprintf("Gateway API precedence selects: %s.", strings.Join(selectedRefs, "; ")))
}

func gatewaySelectedRuleReason(selected gatewayRuleMatch, matches []gatewayRuleMatch) string {
	for _, candidate := range matches {
		if !gatewaySameParent(selected, candidate) || gatewaySameRule(selected, candidate) {
			continue
		}
		if reason := gatewayPrecedenceReason(selected, candidate); reason != "" {
			return reason
		}
	}
	return "first matching rule by Gateway API tie-breakers"
}

func gatewaySameParent(left, right gatewayRuleMatch) bool {
	return left.GatewayNamespace == right.GatewayNamespace &&
		left.GatewayName == right.GatewayName &&
		left.ListenerName == right.ListenerName
}

func gatewaySameRule(left, right gatewayRuleMatch) bool {
	return left.RouteNamespace == right.RouteNamespace &&
		left.RouteName == right.RouteName &&
		left.RuleNumber == right.RuleNumber
}

func gatewayPrecedenceReason(selected, other gatewayRuleMatch) string {
	switch {
	case selected.Score.HostNonWildcardChars > other.Score.HostNonWildcardChars:
		return "more specific hostname"
	case selected.Score.HostChars > other.Score.HostChars:
		return "more specific hostname"
	case selected.Score.PathRank > other.Score.PathRank:
		return "exact path match"
	case selected.Score.PathChars > other.Score.PathChars:
		return "longer path prefix"
	case selected.Score.Method > other.Score.Method:
		return "method match"
	case selected.Score.Headers > other.Score.Headers:
		return "more header matches"
	case selected.Score.QueryParams > other.Score.QueryParams:
		return "more query parameter matches"
	}
	selectedRoute := selected.RouteNamespace + "/" + selected.RouteName
	otherRoute := other.RouteNamespace + "/" + other.RouteName
	if selectedRoute != otherRoute {
		if !selected.RouteCreated.IsZero() && !other.RouteCreated.IsZero() && selected.RouteCreated.Before(&other.RouteCreated) {
			return "older " + defaultString(selected.RouteKind, "Route") + " creation timestamp"
		}
		if selectedRoute < otherRoute {
			return "alphabetical " + defaultString(selected.RouteKind, "Route") + " tie-breaker"
		}
		return ""
	}
	if selected.RuleNumber < other.RuleNumber {
		return "first matching rule in the " + defaultString(selected.RouteKind, "Route")
	}
	return ""
}

func (s *gatewayScanner) addGatewayExpectedServiceCheck(matches []gatewayPathMatch) {
	expected, err := parseGatewayServiceRef(s.opts.ExpectService)
	if err != nil || expected.Name == "" {
		return
	}
	var matched []string
	seen := map[string]bool{}
	found := false
	var routeRules []string
	seenRouteRules := map[string]bool{}
	for _, match := range matches {
		service := gatewayObjectRef{Namespace: match.BackendNamespace, Name: match.BackendName}
		text := gatewayServiceRefText(service)
		if !seen[text] {
			seen[text] = true
			matched = append(matched, text)
		}
		routeRule := fmt.Sprintf("%s/%s rule %d", match.RouteNamespace, match.RouteName, match.RuleNumber)
		if !seenRouteRules[routeRule] {
			seenRouteRules[routeRule] = true
			routeRules = append(routeRules, routeRule)
		}
		if gatewayServiceRefEqual(service, expected) {
			found = true
		}
	}
	sort.Strings(matched)
	sort.Strings(routeRules)
	expectedText := gatewayServiceRefText(expected)
	if found {
		s.report.Add("Gateway Traffic Intent", "expected service", model.StatusPass, fmt.Sprintf("Traffic intent selected expected Service %s.", expectedText))
		return
	}
	message := fmt.Sprintf("This Gateway request routes to Service %s, not expected Service %s.", strings.Join(matched, ", "), expectedText)
	if len(routeRules) > 0 {
		message += fmt.Sprintf(" Selected route: %s.", strings.Join(routeRules, ", "))
	}
	s.addProblem("Gateway Traffic Intent", "expected service", model.StatusFail, message, message)
}

func (s *gatewayScanner) addGatewayTrafficScope(intent gatewayTrafficIntent, listeners []gatewayListenerCandidate, attachedRoutes []unstructured.Unstructured) {
	listenerNames := gatewayListenerCandidateNames(listeners)
	routeNames := objectNames(attachedRoutes)
	routeKind := gatewayPrimaryRouteFamily(intent)
	if len(listenerNames) == 0 {
		s.report.Add("Gateway Traffic Scope", "matching listeners", model.StatusInfo, fmt.Sprintf("No Gateway listeners in scope matched %s.", gatewayTrafficIntentText(intent)))
		return
	}
	s.report.Add("Gateway Traffic Scope", "matching listeners", model.StatusInfo, fmt.Sprintf("Matched listener(s): %s.", strings.Join(listenerNames, ", ")))
	if len(routeNames) == 0 {
		s.report.Add("Gateway Traffic Scope", "attached routes", model.StatusInfo, fmt.Sprintf("No %s objects in scope attach to the matched listener(s).", routeKind))
		return
	}
	s.report.Add("Gateway Traffic Scope", "attached routes", model.StatusInfo, fmt.Sprintf("Attached %s candidate(s): %s.", routeKind, strings.Join(routeNames, ", ")))
}

type gatewayBackendRefAnalysis struct {
	Key           string
	GroupKey      string
	RouteKind     string
	RouteName     string
	RuleNumber    int
	BackendNumber int
	BackendText   string
	Weight        int64
	Broken        bool
	Reason        string
}

func gatewayAnalyzeBackendRef(ctx context.Context, client *kube.Client, route unstructured.Unstructured, ruleNumber, backendNumber int, backend map[string]interface{}, refGrants []unstructured.Unstructured, serviceCache map[string]*corev1.Service, serviceErrCache map[string]error, endpointReadyCache map[string]int, endpointErrCache map[string]error) gatewayBackendRefAnalysis {
	routeName := objectRefText(route)
	name := stringField(backend, "name")
	namespace := defaultString(stringField(backend, "namespace"), route.GetNamespace())
	port, portOK := int32Field(backend, "port")
	backendText := fmt.Sprintf("%s/%s", namespace, defaultString(name, fmt.Sprintf("backend-%d", backendNumber)))
	if portOK {
		backendText = fmt.Sprintf("%s:%d", backendText, port)
	}
	analysis := gatewayBackendRefAnalysis{
		Key:           fmt.Sprintf("%s/%d/%d", routeName, ruleNumber, backendNumber),
		GroupKey:      fmt.Sprintf("%s/%d", routeName, ruleNumber),
		RouteKind:     defaultString(route.GetKind(), "HTTPRoute"),
		RouteName:     routeName,
		RuleNumber:    ruleNumber,
		BackendNumber: backendNumber,
		BackendText:   backendText,
		Weight:        gatewayBackendRefWeight(backend),
	}
	if name == "" {
		analysis.Broken = true
		analysis.Reason = "has no name"
		return analysis
	}
	group := stringField(backend, "group")
	kind := defaultString(stringField(backend, "kind"), "Service")
	if group != "" || kind != "Service" {
		analysis.Broken = true
		analysis.Reason = "backend kind " + gatewayBackendKindText(group, kind) + " is not evaluated by KNM"
		return analysis
	}
	if namespace != route.GetNamespace() && !referenceGrantAllows(refGrants, gatewayv1.GroupName, route.GetKind(), route.GetNamespace(), "", "Service", name, namespace) {
		analysis.Broken = true
		analysis.Reason = "missing ReferenceGrant"
		return analysis
	}
	if !portOK {
		analysis.Broken = true
		analysis.Reason = "has no Service port"
		return analysis
	}
	service, err := cachedService(ctx, client, namespace, name, serviceCache, serviceErrCache)
	if err != nil {
		analysis.Broken = true
		analysis.Reason = "missing Service"
		return analysis
	}
	if !serviceHasGatewayPort(service, port) {
		analysis.Broken = true
		analysis.Reason = "Service exposes " + servicePorts(service)
		return analysis
	}
	if service.Spec.Type == corev1.ServiceTypeExternalName {
		return analysis
	}
	ready, err := cachedReadyEndpointCount(ctx, client, namespace, name, endpointReadyCache, endpointErrCache)
	if err != nil {
		return analysis
	}
	if ready == 0 {
		analysis.Broken = true
		analysis.Reason = "no ready endpoints"
	}
	return analysis
}

func gatewayBackendRefWeight(backend map[string]interface{}) int64 {
	return int64FieldDefault(backend, "weight", 1)
}

func gatewayBackendKindText(group, kind string) string {
	if strings.TrimSpace(group) == "" {
		return kind
	}
	return group + "/" + kind
}

func gatewayMixedWeightedGroups(groups map[string][]gatewayBackendRefAnalysis) map[string]bool {
	out := map[string]bool{}
	for key, analyses := range groups {
		if len(analyses) < 2 {
			continue
		}
		good := false
		bad := false
		for _, analysis := range analyses {
			if analysis.Broken {
				bad = true
			} else {
				good = true
			}
		}
		if good && bad {
			out[key] = true
		}
	}
	return out
}

func gatewaySortedWeightedGroups(groups map[string]bool) []string {
	var out []string
	for group, mixed := range groups {
		if mixed {
			out = append(out, group)
		}
	}
	sort.Strings(out)
	return out
}

func gatewayWeightedBackendMessage(analyses []gatewayBackendRefAnalysis) string {
	if len(analyses) == 0 {
		return ""
	}
	sort.Slice(analyses, func(i, j int) bool {
		return analyses[i].BackendNumber < analyses[j].BackendNumber
	})
	totalWeight := gatewayTotalBackendWeight(analyses)
	var broken []string
	for _, analysis := range analyses {
		if analysis.Broken {
			broken = append(broken, fmt.Sprintf("%s %s (%s)", analysis.BackendText, gatewayBackendWeightText(analysis.Weight, totalWeight), analysis.Reason))
		}
	}
	if len(broken) == 0 {
		return ""
	}
	label := "broken backend"
	if len(broken) > 1 {
		label = "broken backends"
	}
	routeKind := defaultString(analyses[0].RouteKind, "HTTPRoute")
	return fmt.Sprintf("%s %s rule %d splits this request across weighted backendRefs; %s: %s.", routeKind, analyses[0].RouteName, analyses[0].RuleNumber, label, strings.Join(broken, "; "))
}

func gatewayTotalBackendWeight(analyses []gatewayBackendRefAnalysis) int64 {
	var total int64
	for _, analysis := range analyses {
		if analysis.Weight > 0 {
			total += analysis.Weight
		}
	}
	return total
}

func gatewayBackendWeightText(weight, total int64) string {
	if total <= 0 || total == 100 {
		return fmt.Sprintf("weight %d", weight)
	}
	return fmt.Sprintf("weight %d (%s)", weight, gatewayWeightPercentText(weight, total))
}

func gatewayWeightPercentText(weight, total int64) string {
	if total <= 0 {
		return ""
	}
	tenths := weight * 1000 / total
	if weight*1000%total >= (total+1)/2 {
		tenths++
	}
	if tenths%10 == 0 {
		return fmt.Sprintf("%d%%", tenths/10)
	}
	return fmt.Sprintf("%.1f%%", float64(tenths)/10)
}

func (s *gatewayScanner) gatewayTrafficScopedGateways(gateways []unstructured.Unstructured) []unstructured.Unstructured {
	filter := parseGatewayObjectRef(s.opts.GatewayRef, s.opts.Namespace)
	var out []unstructured.Unstructured
	for _, gateway := range gateways {
		if !gatewayObjectRefMatches(gateway, filter) {
			continue
		}
		if s.opts.GatewayClass != "" && stringField(gateway.Object, "spec", "gatewayClassName") != s.opts.GatewayClass {
			continue
		}
		out = append(out, gateway)
	}
	return out
}

func (s *gatewayScanner) gatewayTrafficScopedRoutes(routes []unstructured.Unstructured) []unstructured.Unstructured {
	routeFilter := parseGatewayObjectRef(s.opts.RouteRef, s.opts.Namespace)
	gatewayFilter := parseGatewayObjectRef(s.opts.GatewayRef, s.opts.Namespace)
	var out []unstructured.Unstructured
	for _, route := range routes {
		if !gatewayObjectRefMatches(route, routeFilter) {
			continue
		}
		if !routeMatchesGatewayFilter(route, gatewayFilter) {
			continue
		}
		out = append(out, route)
	}
	return out
}

func gatewayRouteBackendRefAt(route unstructured.Unstructured, ruleNumber, backendNumber int) (map[string]interface{}, bool) {
	if ruleNumber <= 0 || backendNumber <= 0 {
		return nil, false
	}
	rules := sliceField(route.Object, "spec", "rules")
	if ruleNumber > len(rules) {
		return nil, false
	}
	rule, ok := rules[ruleNumber-1].(map[string]interface{})
	if !ok {
		return nil, false
	}
	backendRefs := sliceField(rule, "backendRefs")
	if backendNumber > len(backendRefs) {
		return nil, false
	}
	backend, ok := backendRefs[backendNumber-1].(map[string]interface{})
	return backend, ok
}

func gatewayTrafficIntentText(intent gatewayTrafficIntent) string {
	var parts []string
	if intent.Scheme != "" {
		parts = append(parts, "scheme="+intent.Scheme)
	}
	if intent.Host != "" {
		parts = append(parts, "host="+intent.Host)
	}
	if intent.Port != 0 {
		parts = append(parts, fmt.Sprintf("port=%d", intent.Port))
	}
	switch gatewayPrimaryRouteFamily(intent) {
	case "GRPCRoute":
		if intent.GRPCService != "" {
			parts = append(parts, "grpcService="+intent.GRPCService)
		}
		if intent.GRPCMethod != "" {
			parts = append(parts, "grpcMethod="+intent.GRPCMethod)
		}
	case "TLSRoute":
		parts = append(parts, "sni="+intent.Host)
	default:
		parts = append(parts, "path="+defaultString(intent.Path, "/"))
	}
	if intent.Method != "" && gatewayTrafficIntentUsesHTTP(intent) {
		parts = append(parts, "method="+intent.Method)
	}
	if len(intent.Headers) > 0 {
		parts = append(parts, fmt.Sprintf("%d header(s)", len(intent.Headers)))
	}
	if len(intent.Query) > 0 {
		parts = append(parts, fmt.Sprintf("%d query parameter(s)", len(intent.Query)))
	}
	return strings.Join(parts, " ")
}

type gatewayNoMatchReason struct {
	Message   string
	Diagnosis string
}

func gatewayExplainNoTrafficMatch(gateways []unstructured.Unstructured, routes []unstructured.Unstructured, intent gatewayTrafficIntent) gatewayNoMatchReason {
	intentText := gatewayTrafficIntentText(intent)
	routeKind := gatewayPrimaryRouteFamily(intent)
	if len(gateways) == 0 {
		return gatewayNoMatchReason{
			Message:   fmt.Sprintf("No Gateway objects were in scope for %s.", intentText),
			Diagnosis: fmt.Sprintf("No Gateway objects were in scope for %s. Remove or adjust --gateway, --gateway-class, or --namespace scope filters.", intentText),
		}
	}
	listeners := gatewayTrafficMatchingListeners(gateways, intent)
	if len(listeners) == 0 {
		if gatewayAnyListenerHostnameMatches(gateways, intent.Host) {
			return gatewayNoMatchReason{
				Message:   fmt.Sprintf("Gateway listener hostname matched %q, but no listener matched protocol=%s port=%d.", intent.Host, intent.Protocol, intent.Port),
				Diagnosis: fmt.Sprintf("Gateway listener hostname matched %q, but no listener matched protocol=%s port=%d.", intent.Host, intent.Protocol, intent.Port),
			}
		}
		suggestion := gatewayClosestHostnameSuffix(intent.Host, gatewayListenerHostnames(gateways), "listener")
		return gatewayNoMatchReason{
			Message:   fmt.Sprintf("No Gateway listener matched %s.%s", intentText, suggestion),
			Diagnosis: fmt.Sprintf("No Gateway listener matched %s.%s", intentText, suggestion),
		}
	}
	attachedRoutes := gatewayTrafficAttachedRoutes(routes, listeners)
	if len(attachedRoutes) == 0 {
		listenerText := strings.Join(gatewayListenerCandidateNames(listeners), ", ")
		return gatewayNoMatchReason{
			Message:   fmt.Sprintf("Gateway listener(s) matched %s, but no %s in scope attaches to those listener(s). Matched listener(s): %s.", intentText, routeKind, listenerText),
			Diagnosis: fmt.Sprintf("Gateway listener(s) matched %s, but no %s attaches to them.", intentText, routeKind),
		}
	}
	hostRoutes := gatewayTrafficHostnameRoutes(attachedRoutes, intent.Host)
	if len(hostRoutes) == 0 {
		suggestion := gatewayClosestHostnameSuffix(intent.Host, gatewayRouteHostnames(attachedRoutes), "route")
		return gatewayNoMatchReason{
			Message:   fmt.Sprintf("Gateway listener matched, but no attached %s has a hostname matching %q.%s", routeKind, intent.Host, suggestion),
			Diagnosis: fmt.Sprintf("Gateway listener matched, but no attached %s has a hostname matching %q.%s", routeKind, intent.Host, suggestion),
		}
	}
	if routeKind == "GRPCRoute" {
		if !gatewayGRPCRoutesHaveServiceMatch(hostRoutes, intent.GRPCService) {
			return gatewayNoMatchReason{
				Message:   fmt.Sprintf("GRPCRoute hostnames matched %q, but no rule matched gRPC service %q.", intent.Host, intent.GRPCService),
				Diagnosis: fmt.Sprintf("GRPCRoute hostnames matched %q, but no rule matched gRPC service %q.", intent.Host, intent.GRPCService),
			}
		}
		if !gatewayGRPCRoutesHaveMethodMatch(hostRoutes, intent) {
			return gatewayNoMatchReason{
				Message:   fmt.Sprintf("GRPCRoute service matched, but no rule matched gRPC method %q.", intent.GRPCMethod),
				Diagnosis: fmt.Sprintf("GRPCRoute service matched for %s, but no rule matched gRPC method %q.", intentText, intent.GRPCMethod),
			}
		}
		if !gatewayGRPCRoutesHaveHeaderMatch(hostRoutes, intent) {
			return gatewayNoMatchReason{
				Message:   "GRPCRoute service/method matched, but request headers did not satisfy any matching rule.",
				Diagnosis: fmt.Sprintf("GRPCRoute service/method matched for %s, but request headers did not satisfy any matching rule.", intentText),
			}
		}
		return gatewayNoMatchReason{
			Message:   fmt.Sprintf("No Gateway API GRPCRoute backend matched %s within the scan scope.", intentText),
			Diagnosis: fmt.Sprintf("No Gateway API GRPCRoute backend matched %s. Check Gateway listener hostname/protocol/port, GRPCRoute hostnames, parentRefs, service/method/header matches, and backendRefs.", intentText),
		}
	}
	if routeKind == "TLSRoute" {
		return gatewayNoMatchReason{
			Message:   fmt.Sprintf("No Gateway API TLSRoute backend matched SNI host %q within the scan scope.", intent.Host),
			Diagnosis: fmt.Sprintf("No Gateway API TLSRoute backend matched SNI host %q. Check Gateway TLS listener hostname/port, TLSRoute hostnames, parentRefs, and backendRefs.", intent.Host),
		}
	}
	pathRoutes := gatewayTrafficRoutesMatchingPath(hostRoutes, intent.Path)
	if len(pathRoutes) == 0 {
		return gatewayNoMatchReason{
			Message:   fmt.Sprintf("HTTPRoute hostnames matched %q, but no rule matched path %q.", intent.Host, defaultString(intent.Path, "/")),
			Diagnosis: fmt.Sprintf("HTTPRoute hostnames matched %q, but no rule matched path %q.", intent.Host, defaultString(intent.Path, "/")),
		}
	}
	methodRoutes := gatewayTrafficRoutesMatchingMethod(pathRoutes, intent.Method)
	if len(methodRoutes) == 0 {
		return gatewayNoMatchReason{
			Message:   fmt.Sprintf("HTTPRoute path matched, but no rule matched method %q.", intent.Method),
			Diagnosis: fmt.Sprintf("HTTPRoute path matched for %s, but no rule matched method %q.", intentText, intent.Method),
		}
	}
	headerRoutes := gatewayTrafficRoutesMatchingHeaders(methodRoutes, intent.Headers)
	if len(headerRoutes) == 0 {
		return gatewayNoMatchReason{
			Message:   "HTTPRoute path/method matched, but request headers did not satisfy any matching rule.",
			Diagnosis: fmt.Sprintf("HTTPRoute path/method matched for %s, but request headers did not satisfy any matching rule.", intentText),
		}
	}
	if len(gatewayTrafficRoutesMatchingQuery(headerRoutes, intent.Query)) == 0 {
		return gatewayNoMatchReason{
			Message:   "HTTPRoute path/method/header matched, but query parameters did not satisfy any matching rule.",
			Diagnosis: fmt.Sprintf("HTTPRoute path/method/header matched for %s, but query parameters did not satisfy any matching rule.", intentText),
		}
	}
	return gatewayNoMatchReason{
		Message:   fmt.Sprintf("No Gateway API HTTPRoute backend matched %s within the scan scope.", intentText),
		Diagnosis: fmt.Sprintf("No Gateway API HTTPRoute backend matched %s. Check Gateway listener hostname/protocol/port, HTTPRoute hostnames, parentRefs, route match rules, and backendRefs.", intentText),
	}
}

type gatewayListenerCandidate struct {
	Gateway  unstructured.Unstructured
	Listener map[string]interface{}
}

func gatewayTrafficMatchingListeners(gateways []unstructured.Unstructured, intent gatewayTrafficIntent) []gatewayListenerCandidate {
	var out []gatewayListenerCandidate
	for _, gateway := range gateways {
		listeners := sliceField(gateway.Object, "spec", "listeners")
		for _, raw := range listeners {
			listener, ok := raw.(map[string]interface{})
			if ok && gatewayListenerMatchesIntent(listener, intent) {
				out = append(out, gatewayListenerCandidate{Gateway: gateway, Listener: listener})
			}
		}
	}
	return out
}

func gatewayListenerCandidateNames(listeners []gatewayListenerCandidate) []string {
	var out []string
	for _, listener := range listeners {
		out = append(out, objectRefText(listener.Gateway)+"/"+stringField(listener.Listener, "name"))
	}
	sort.Strings(out)
	return out
}

func gatewayListenerHostnames(gateways []unstructured.Unstructured) []string {
	var out []string
	for _, gateway := range gateways {
		for _, raw := range sliceField(gateway.Object, "spec", "listeners") {
			listener, ok := raw.(map[string]interface{})
			if !ok {
				continue
			}
			if hostname := stringField(listener, "hostname"); hostname != "" {
				out = append(out, hostname)
			}
		}
	}
	return out
}

func gatewayAnyListenerHostnameMatches(gateways []unstructured.Unstructured, host string) bool {
	for _, gateway := range gateways {
		for _, raw := range sliceField(gateway.Object, "spec", "listeners") {
			listener, ok := raw.(map[string]interface{})
			if ok && gatewayHostnameMatches(stringField(listener, "hostname"), host) {
				return true
			}
		}
	}
	return false
}

func gatewayRouteHostnames(routes []unstructured.Unstructured) []string {
	var out []string
	for _, route := range routes {
		for _, raw := range sliceField(route.Object, "spec", "hostnames") {
			hostname, ok := raw.(string)
			if ok && hostname != "" {
				out = append(out, hostname)
			}
		}
	}
	return out
}

func gatewayClosestHostnameSuffix(host string, candidates []string, label string) string {
	closest, ok := gatewayClosestHostname(host, candidates)
	if !ok {
		return ""
	}
	return fmt.Sprintf(" Closest %s hostname: %s.", label, closest)
}

func gatewayClosestHostname(host string, candidates []string) (string, bool) {
	host = gatewayNormalizeHostname(host)
	if host == "" {
		return "", false
	}
	best := ""
	bestDistance := 0
	for _, candidate := range candidates {
		normalized := gatewayNormalizeHostname(candidate)
		if normalized == "" {
			continue
		}
		compare := gatewayHostnameComparisonValue(host, normalized)
		if compare == "" {
			continue
		}
		distance := gatewayEditDistance(host, compare)
		threshold := gatewayHostnameSuggestionThreshold(host, compare)
		if distance > threshold {
			continue
		}
		if best == "" || distance < bestDistance || distance == bestDistance && len(candidate) < len(best) {
			best = candidate
			bestDistance = distance
		}
	}
	return best, best != ""
}

func gatewayHostnameComparisonValue(host, candidate string) string {
	if !strings.HasPrefix(candidate, "*.") {
		return candidate
	}
	firstLabel := host
	if index := strings.Index(host, "."); index > 0 {
		firstLabel = host[:index]
	}
	if firstLabel == "" || strings.Contains(firstLabel, ".") {
		return ""
	}
	return firstLabel + strings.TrimPrefix(candidate, "*")
}

func gatewayHostnameSuggestionThreshold(host, candidate string) int {
	longest := len(host)
	if len(candidate) > longest {
		longest = len(candidate)
	}
	if longest <= 12 {
		return 1
	}
	if longest <= 24 {
		return 2
	}
	return 3
}

func gatewayEditDistance(a, b string) int {
	if a == b {
		return 0
	}
	if a == "" {
		return len(b)
	}
	if b == "" {
		return len(a)
	}
	prev := make([]int, len(b)+1)
	curr := make([]int, len(b)+1)
	for j := range prev {
		prev[j] = j
	}
	for i := 1; i <= len(a); i++ {
		curr[0] = i
		for j := 1; j <= len(b); j++ {
			cost := 0
			if a[i-1] != b[j-1] {
				cost = 1
			}
			curr[j] = minInt(prev[j]+1, curr[j-1]+1, prev[j-1]+cost)
		}
		prev, curr = curr, prev
	}
	return prev[len(b)]
}

func minInt(values ...int) int {
	if len(values) == 0 {
		return 0
	}
	out := values[0]
	for _, value := range values[1:] {
		if value < out {
			out = value
		}
	}
	return out
}

func gatewayTrafficAttachedRoutes(routes []unstructured.Unstructured, listeners []gatewayListenerCandidate) []unstructured.Unstructured {
	seen := map[string]bool{}
	var out []unstructured.Unstructured
	for _, route := range routes {
		for _, listener := range listeners {
			if gatewayRouteAttachedToGateway(route, listener.Gateway, stringField(listener.Listener, "name")) {
				key := objectRefText(route)
				if !seen[key] {
					seen[key] = true
					out = append(out, route)
				}
			}
		}
	}
	return out
}

func gatewayTrafficHostnameRoutes(routes []unstructured.Unstructured, host string) []unstructured.Unstructured {
	var out []unstructured.Unstructured
	for _, route := range routes {
		if gatewayRouteHostnameMatches(route, host) {
			out = append(out, route)
		}
	}
	return out
}

func gatewayGRPCRoutesHaveServiceMatch(routes []unstructured.Unstructured, service string) bool {
	return gatewayGRPCRoutesHaveMatch(routes, func(match map[string]interface{}) bool {
		return gatewayGRPCServiceMatches(match, service)
	})
}

func gatewayGRPCRoutesHaveMethodMatch(routes []unstructured.Unstructured, intent gatewayTrafficIntent) bool {
	return gatewayGRPCRoutesHaveMatch(routes, func(match map[string]interface{}) bool {
		return gatewayGRPCServiceMatches(match, intent.GRPCService) && gatewayGRPCRouteMethodMatch(match, intent)
	})
}

func gatewayGRPCRoutesHaveHeaderMatch(routes []unstructured.Unstructured, intent gatewayTrafficIntent) bool {
	return gatewayGRPCRoutesHaveMatch(routes, func(match map[string]interface{}) bool {
		return gatewayGRPCServiceMatches(match, intent.GRPCService) &&
			gatewayGRPCRouteMethodMatch(match, intent) &&
			gatewayHTTPRouteHeadersMatch(match, intent.Headers)
	})
}

func gatewayGRPCRoutesHaveMatch(routes []unstructured.Unstructured, predicate func(map[string]interface{}) bool) bool {
	for _, route := range routes {
		for _, rawRule := range sliceField(route.Object, "spec", "rules") {
			rule, ok := rawRule.(map[string]interface{})
			if !ok {
				continue
			}
			matches := sliceField(rule, "matches")
			if len(matches) == 0 {
				matches = []interface{}{map[string]interface{}{}}
			}
			for _, rawMatch := range matches {
				match, ok := rawMatch.(map[string]interface{})
				if ok && predicate(match) {
					return true
				}
			}
		}
	}
	return false
}

func gatewayGRPCServiceMatches(match map[string]interface{}, service string) bool {
	method, ok := nestedMap(match, "method")
	if !ok || stringField(method, "service") == "" {
		return true
	}
	return service != "" && gatewayHTTPRouteValueMatches(defaultString(stringField(method, "type"), "Exact"), stringField(method, "service"), service)
}

func gatewayTrafficRoutesMatchingPath(routes []unstructured.Unstructured, path string) []unstructured.Unstructured {
	return gatewayTrafficRoutesMatching(routes, func(match map[string]interface{}) bool {
		return gatewayHTTPRoutePathMatches(match, path)
	})
}

func gatewayTrafficRoutesMatchingMethod(routes []unstructured.Unstructured, method string) []unstructured.Unstructured {
	return gatewayTrafficRoutesMatching(routes, func(match map[string]interface{}) bool {
		return gatewayHTTPRouteMethodMatches(match, method)
	})
}

func gatewayTrafficRoutesMatchingHeaders(routes []unstructured.Unstructured, headers map[string]string) []unstructured.Unstructured {
	return gatewayTrafficRoutesMatching(routes, func(match map[string]interface{}) bool {
		return gatewayHTTPRouteHeadersMatch(match, headers)
	})
}

func gatewayTrafficRoutesMatchingQuery(routes []unstructured.Unstructured, query map[string][]string) []unstructured.Unstructured {
	return gatewayTrafficRoutesMatching(routes, func(match map[string]interface{}) bool {
		return gatewayHTTPRouteQueryParamsMatch(match, query)
	})
}

func gatewayTrafficRoutesMatching(routes []unstructured.Unstructured, predicate func(map[string]interface{}) bool) []unstructured.Unstructured {
	seen := map[string]bool{}
	var out []unstructured.Unstructured
	for _, route := range routes {
		rules := sliceField(route.Object, "spec", "rules")
		for _, rawRule := range rules {
			rule, ok := rawRule.(map[string]interface{})
			if !ok {
				continue
			}
			matches := sliceField(rule, "matches")
			if len(matches) == 0 {
				matches = []interface{}{map[string]interface{}{}}
			}
			for _, rawMatch := range matches {
				match, ok := rawMatch.(map[string]interface{})
				if !ok {
					continue
				}
				if predicate(match) {
					key := objectRefText(route)
					if !seen[key] {
						seen[key] = true
						out = append(out, route)
					}
				}
			}
		}
	}
	return out
}

type gatewayConditionRule struct {
	Type          string
	FalseStatus   model.Status
	MissingStatus model.Status
}

func (s *gatewayScanner) addConditionProblems(layer, kind, name string, object map[string]interface{}, rules []gatewayConditionRule) {
	for _, rule := range rules {
		cond, ok := conditionByType(object, rule.Type)
		if !ok {
			if rule.MissingStatus != "" {
				s.addProblem(layer, name+" "+rule.Type, rule.MissingStatus, fmt.Sprintf("%s %s has no %s condition.", kind, name, rule.Type), "")
			}
			continue
		}
		if strings.EqualFold(cond.Status, "False") {
			s.addProblem(layer, name+" "+rule.Type, rule.FalseStatus, fmt.Sprintf("%s %s condition %s=False: %s%s", kind, name, rule.Type, cond.Reason, conditionMessageSuffix(cond.Message)), fmt.Sprintf("%s %s is not %s: %s%s", kind, name, rule.Type, cond.Reason, conditionMessageSuffix(cond.Message)))
		}
		if strings.EqualFold(cond.Status, "Unknown") {
			s.addProblem(layer, name+" "+rule.Type, model.StatusWarn, fmt.Sprintf("%s %s condition %s=Unknown: %s%s", kind, name, rule.Type, cond.Reason, conditionMessageSuffix(cond.Message)), "")
		}
	}
}

type gatewayCondition struct {
	Type    string
	Status  string
	Reason  string
	Message string
}

func conditionByType(object map[string]interface{}, conditionType string) (gatewayCondition, bool) {
	conditions := sliceField(object, "status", "conditions")
	if len(conditions) == 0 {
		conditions = sliceField(object, "conditions")
	}
	for _, raw := range conditions {
		cond, ok := raw.(map[string]interface{})
		if !ok {
			continue
		}
		if stringField(cond, "type") == conditionType {
			return gatewayCondition{
				Type:    conditionType,
				Status:  stringField(cond, "status"),
				Reason:  stringField(cond, "reason"),
				Message: stringField(cond, "message"),
			}, true
		}
	}
	return gatewayCondition{}, false
}

func gatewayList(ctx context.Context, client *kube.Client, gvr schema.GroupVersionResource, namespace string) ([]unstructured.Unstructured, error) {
	var list *unstructured.UnstructuredList
	var err error
	if gvr == gatewayClassGVR {
		list, err = client.Dynamic.Resource(gvr).List(ctx, metav1.ListOptions{})
	} else {
		list, err = client.Dynamic.Resource(gvr).Namespace(namespace).List(ctx, metav1.ListOptions{})
	}
	if err != nil {
		return nil, err
	}
	return list.Items, nil
}

func gatewayAPIMissing(err error) bool {
	if err == nil {
		return false
	}
	if apierrors.IsNotFound(err) || apierrors.IsMethodNotSupported(err) {
		return true
	}
	text := strings.ToLower(err.Error())
	return strings.Contains(text, "the server could not find the requested resource") ||
		strings.Contains(text, "no matches for kind") ||
		strings.Contains(text, "not found")
}

func gatewayClassIndex(classes []unstructured.Unstructured) map[string]unstructured.Unstructured {
	out := map[string]unstructured.Unstructured{}
	for _, class := range classes {
		out[class.GetName()] = class
	}
	return out
}

func gatewayIndex(gateways []unstructured.Unstructured) map[string]unstructured.Unstructured {
	out := map[string]unstructured.Unstructured{}
	for _, gateway := range gateways {
		out[objectRefText(gateway)] = gateway
	}
	return out
}

type gatewayObjectRef struct {
	Namespace string
	Name      string
}

type gatewayTrafficIntent struct {
	Scheme        string
	Host          string
	Port          int32
	Protocol      string
	RouteFamilies []string
	Path          string
	Method        string
	Headers       map[string]string
	Query         map[string][]string
	GRPCService   string
	GRPCMethod    string
}

type gatewayPathMatch struct {
	GatewayNamespace string
	GatewayName      string
	ListenerName     string
	ListenerHostname string
	ListenerPort     int32
	ListenerProtocol string
	RouteKind        string
	RouteNamespace   string
	RouteName        string
	RuleNumber       int
	BackendNumber    int
	BackendNamespace string
	BackendName      string
	BackendPort      int32
	BackendWeight    int64
	MatchSummary     string
}

type gatewayRuleMatch struct {
	GatewayNamespace string
	GatewayName      string
	ListenerName     string
	RouteKind        string
	RouteNamespace   string
	RouteName        string
	RuleNumber       int
	Rule             map[string]interface{}
	RouteCreated     metav1.Time
	Score            gatewayRulePrecedenceScore
}

type gatewayRulePrecedenceScore struct {
	HostNonWildcardChars int
	HostChars            int
	PathRank             int
	PathChars            int
	Method               int
	Headers              int
	QueryParams          int
	RegexPath            bool
}

func parseGatewayObjectRef(raw string, defaultNamespace string) gatewayObjectRef {
	raw = strings.TrimSpace(raw)
	if raw == "" {
		return gatewayObjectRef{}
	}
	parts := strings.Split(raw, "/")
	if len(parts) == 2 {
		return gatewayObjectRef{Namespace: parts[0], Name: parts[1]}
	}
	return gatewayObjectRef{Namespace: defaultNamespace, Name: raw}
}

func parseGatewayServiceRef(raw string) (gatewayObjectRef, error) {
	raw = strings.TrimSpace(raw)
	if raw == "" {
		return gatewayObjectRef{}, nil
	}
	parts := strings.Split(raw, "/")
	switch len(parts) {
	case 1:
		if parts[0] == "" {
			return gatewayObjectRef{}, fmt.Errorf("Invalid --expect-service value %q. Use name or namespace/name.", raw)
		}
		return gatewayObjectRef{Name: parts[0]}, nil
	case 2:
		if parts[0] == "" || parts[1] == "" {
			return gatewayObjectRef{}, fmt.Errorf("Invalid --expect-service value %q. Use name or namespace/name.", raw)
		}
		return gatewayObjectRef{Namespace: parts[0], Name: parts[1]}, nil
	default:
		return gatewayObjectRef{}, fmt.Errorf("Invalid --expect-service value %q. Use name or namespace/name.", raw)
	}
}

func gatewayServiceRefText(ref gatewayObjectRef) string {
	if ref.Namespace == "" {
		return ref.Name
	}
	return ref.Namespace + "/" + ref.Name
}

func gatewayServiceRefEqual(got, want gatewayObjectRef) bool {
	if want.Name == "" || got.Name != want.Name {
		return false
	}
	return want.Namespace == "" || got.Namespace == want.Namespace
}

func gatewayObjectRefMatches(object unstructured.Unstructured, filter gatewayObjectRef) bool {
	if filter.Name == "" {
		return true
	}
	if object.GetName() != filter.Name {
		return false
	}
	return filter.Namespace == "" || object.GetNamespace() == filter.Namespace
}

func routeMatchesGatewayFilter(route unstructured.Unstructured, filter gatewayObjectRef) bool {
	if filter.Name == "" {
		return true
	}
	parentRefs := sliceField(route.Object, "spec", "parentRefs")
	for _, raw := range parentRefs {
		parent, ok := raw.(map[string]interface{})
		if !ok {
			continue
		}
		if parentKind(parent) != "Gateway" {
			continue
		}
		ns := defaultString(stringField(parent, "namespace"), route.GetNamespace())
		if stringField(parent, "name") == filter.Name && (filter.Namespace == "" || ns == filter.Namespace) {
			return true
		}
	}
	return false
}

func gatewayFindRuleMatches(gateways []unstructured.Unstructured, routes []unstructured.Unstructured, intent gatewayTrafficIntent) []gatewayRuleMatch {
	if gatewayTrafficIntentUsesHTTP(intent) && intent.Path == "" {
		intent.Path = "/"
	}
	var matches []gatewayRuleMatch
	for _, gateway := range gateways {
		listeners := sliceField(gateway.Object, "spec", "listeners")
		for _, rawListener := range listeners {
			listener, ok := rawListener.(map[string]interface{})
			if !ok || !gatewayListenerMatchesIntent(listener, intent) {
				continue
			}
			listenerName := stringField(listener, "name")
			for _, route := range routes {
				if !gatewayRouteAttachedToGateway(route, gateway, listenerName) {
					continue
				}
				if !gatewayRouteHostnameMatches(route, intent.Host) {
					continue
				}
				rules := sliceField(route.Object, "spec", "rules")
				for ruleIndex, rawRule := range rules {
					rule, ok := rawRule.(map[string]interface{})
					if !ok || !gatewayRouteRuleMatches(route.GetKind(), rule, intent) {
						continue
					}
					matches = append(matches, gatewayRuleMatch{
						GatewayNamespace: gateway.GetNamespace(),
						GatewayName:      gateway.GetName(),
						ListenerName:     listenerName,
						RouteKind:        route.GetKind(),
						RouteNamespace:   route.GetNamespace(),
						RouteName:        route.GetName(),
						RuleNumber:       ruleIndex + 1,
						Rule:             rule,
						RouteCreated:     route.GetCreationTimestamp(),
						Score:            gatewayRulePrecedenceScoreForRoute(route, rule, intent),
					})
				}
			}
		}
	}
	sort.Slice(matches, func(i, j int) bool {
		left := fmt.Sprintf("%s/%s/%s/%s/%s/%03d", matches[i].GatewayNamespace, matches[i].GatewayName, matches[i].ListenerName, matches[i].RouteNamespace, matches[i].RouteName, matches[i].RuleNumber)
		right := fmt.Sprintf("%s/%s/%s/%s/%s/%03d", matches[j].GatewayNamespace, matches[j].GatewayName, matches[j].ListenerName, matches[j].RouteNamespace, matches[j].RouteName, matches[j].RuleNumber)
		return left < right
	})
	return matches
}

func gatewaySelectPrecedenceRules(matches []gatewayRuleMatch) []gatewayRuleMatch {
	if len(matches) == 0 {
		return nil
	}
	groups := map[string][]gatewayRuleMatch{}
	for _, match := range matches {
		key := match.GatewayNamespace + "/" + match.GatewayName + "/" + match.ListenerName
		groups[key] = append(groups[key], match)
	}
	var selected []gatewayRuleMatch
	for _, group := range groups {
		sort.Slice(group, func(i, j int) bool {
			return gatewayRulePrecedenceLess(group[i], group[j])
		})
		selected = append(selected, group[0])
	}
	sort.Slice(selected, func(i, j int) bool {
		left := fmt.Sprintf("%s/%s/%s/%s/%s/%03d", selected[i].GatewayNamespace, selected[i].GatewayName, selected[i].ListenerName, selected[i].RouteNamespace, selected[i].RouteName, selected[i].RuleNumber)
		right := fmt.Sprintf("%s/%s/%s/%s/%s/%03d", selected[j].GatewayNamespace, selected[j].GatewayName, selected[j].ListenerName, selected[j].RouteNamespace, selected[j].RouteName, selected[j].RuleNumber)
		return left < right
	})
	return selected
}

func gatewayFilterMatchesToSelectedRules(matches []gatewayPathMatch, selected []gatewayRuleMatch) []gatewayPathMatch {
	if len(matches) == 0 || len(selected) == 0 {
		return matches
	}
	keep := map[string]bool{}
	for _, match := range selected {
		keep[gatewayRuleKey(match.GatewayNamespace, match.GatewayName, match.ListenerName, match.RouteNamespace, match.RouteName, match.RuleNumber)] = true
	}
	var out []gatewayPathMatch
	for _, match := range matches {
		if keep[gatewayRuleKey(match.GatewayNamespace, match.GatewayName, match.ListenerName, match.RouteNamespace, match.RouteName, match.RuleNumber)] {
			out = append(out, match)
		}
	}
	return out
}

func gatewayRuleKey(gatewayNamespace, gatewayName, listenerName, routeNamespace, routeName string, ruleNumber int) string {
	return fmt.Sprintf("%s/%s/%s/%s/%s/%d", gatewayNamespace, gatewayName, listenerName, routeNamespace, routeName, ruleNumber)
}

func gatewayRulePrecedenceLess(left, right gatewayRuleMatch) bool {
	if cmp := gatewayCompareRuleScore(left.Score, right.Score); cmp != 0 {
		return cmp > 0
	}
	leftRoute := left.RouteNamespace + "/" + left.RouteName
	rightRoute := right.RouteNamespace + "/" + right.RouteName
	if leftRoute != rightRoute {
		if !left.RouteCreated.IsZero() || !right.RouteCreated.IsZero() {
			if left.RouteCreated.IsZero() {
				return false
			}
			if right.RouteCreated.IsZero() {
				return true
			}
			if !left.RouteCreated.Equal(&right.RouteCreated) {
				return left.RouteCreated.Before(&right.RouteCreated)
			}
		}
		return leftRoute < rightRoute
	}
	return left.RuleNumber < right.RuleNumber
}

func gatewayCompareRuleScore(left, right gatewayRulePrecedenceScore) int {
	leftValues := []int{left.HostNonWildcardChars, left.HostChars, left.PathRank, left.PathChars, left.Method, left.Headers, left.QueryParams}
	rightValues := []int{right.HostNonWildcardChars, right.HostChars, right.PathRank, right.PathChars, right.Method, right.Headers, right.QueryParams}
	for i := range leftValues {
		if leftValues[i] > rightValues[i] {
			return 1
		}
		if leftValues[i] < rightValues[i] {
			return -1
		}
	}
	return 0
}

func gatewayRulePrecedenceScoreForRoute(route unstructured.Unstructured, rule map[string]interface{}, intent gatewayTrafficIntent) gatewayRulePrecedenceScore {
	score := gatewayRouteHostnamePrecedenceScore(route, intent.Host)
	matchScore, ok := gatewayBestRouteMatchPrecedenceScore(route.GetKind(), rule, intent)
	if ok {
		score.PathRank = matchScore.PathRank
		score.PathChars = matchScore.PathChars
		score.Method = matchScore.Method
		score.Headers = matchScore.Headers
		score.QueryParams = matchScore.QueryParams
		score.RegexPath = matchScore.RegexPath
	}
	return score
}

func gatewayBestRouteMatchPrecedenceScore(kind string, rule map[string]interface{}, intent gatewayTrafficIntent) (gatewayRulePrecedenceScore, bool) {
	switch kind {
	case "GRPCRoute":
		return gatewayBestGRPCMatchPrecedenceScore(rule, intent)
	case "TLSRoute":
		return gatewayRulePrecedenceScore{}, true
	default:
		return gatewayBestHTTPMatchPrecedenceScore(rule, intent)
	}
}

func gatewayRouteHostnamePrecedenceScore(route unstructured.Unstructured, host string) gatewayRulePrecedenceScore {
	var best gatewayRulePrecedenceScore
	for _, raw := range sliceField(route.Object, "spec", "hostnames") {
		pattern, ok := raw.(string)
		if !ok || !gatewayHostnameMatches(pattern, host) {
			continue
		}
		candidate := gatewayHostnamePrecedenceScore(pattern)
		if gatewayCompareRuleScore(candidate, best) > 0 {
			best = candidate
		}
	}
	return best
}

func gatewayHostnamePrecedenceScore(pattern string) gatewayRulePrecedenceScore {
	pattern = gatewayNormalizeHostname(pattern)
	if pattern == "" {
		return gatewayRulePrecedenceScore{}
	}
	if strings.HasPrefix(pattern, "*.") {
		suffix := strings.TrimPrefix(pattern, "*.")
		return gatewayRulePrecedenceScore{
			HostNonWildcardChars: len(suffix),
			HostChars:            len(pattern),
		}
	}
	return gatewayRulePrecedenceScore{
		HostNonWildcardChars: len(pattern),
		HostChars:            len(pattern),
	}
}

func gatewayBestHTTPMatchPrecedenceScore(rule map[string]interface{}, intent gatewayTrafficIntent) (gatewayRulePrecedenceScore, bool) {
	matches := sliceField(rule, "matches")
	if len(matches) == 0 {
		return gatewayRulePrecedenceScore{PathRank: 1, PathChars: 1}, true
	}
	var best gatewayRulePrecedenceScore
	found := false
	for _, raw := range matches {
		match, ok := raw.(map[string]interface{})
		if !ok || !gatewayHTTPRouteSingleMatch(match, intent) {
			continue
		}
		score := gatewayHTTPMatchPrecedenceScore(match)
		if !found || gatewayCompareRuleScore(score, best) > 0 {
			best = score
			found = true
		}
	}
	return best, found
}

func gatewayHTTPMatchPrecedenceScore(match map[string]interface{}) gatewayRulePrecedenceScore {
	score := gatewayRulePrecedenceScore{}
	pathSpec, ok := nestedMap(match, "path")
	if !ok {
		score.PathRank = 1
		score.PathChars = 1
	} else {
		value := defaultString(stringField(pathSpec, "value"), "/")
		switch stringField(pathSpec, "type") {
		case "Exact":
			score.PathRank = 2
			score.PathChars = len(value)
		case "", "PathPrefix":
			score.PathRank = 1
			score.PathChars = len(value)
		case "RegularExpression":
			score.PathRank = 0
			score.PathChars = len(value)
			score.RegexPath = true
		}
	}
	if strings.TrimSpace(stringField(match, "method")) != "" {
		score.Method = 1
	}
	score.Headers = len(sliceField(match, "headers"))
	score.QueryParams = len(sliceField(match, "queryParams"))
	return score
}

func gatewayBestGRPCMatchPrecedenceScore(rule map[string]interface{}, intent gatewayTrafficIntent) (gatewayRulePrecedenceScore, bool) {
	matches := sliceField(rule, "matches")
	if len(matches) == 0 {
		return gatewayRulePrecedenceScore{}, true
	}
	var best gatewayRulePrecedenceScore
	found := false
	for _, raw := range matches {
		match, ok := raw.(map[string]interface{})
		if !ok || !gatewayGRPCRouteSingleMatch(match, intent) {
			continue
		}
		score := gatewayGRPCMatchPrecedenceScore(match)
		if !found || gatewayCompareRuleScore(score, best) > 0 {
			best = score
			found = true
		}
	}
	return best, found
}

func gatewayGRPCMatchPrecedenceScore(match map[string]interface{}) gatewayRulePrecedenceScore {
	score := gatewayRulePrecedenceScore{}
	if method, ok := nestedMap(match, "method"); ok {
		if stringField(method, "service") != "" {
			score.PathChars = len(stringField(method, "service"))
		}
		if stringField(method, "method") != "" {
			score.Method = 1
		}
	}
	score.Headers = len(sliceField(match, "headers"))
	return score
}

func gatewayFindCandidatePaths(gateways []unstructured.Unstructured, routes []unstructured.Unstructured, intent gatewayTrafficIntent) []gatewayPathMatch {
	if gatewayTrafficIntentUsesHTTP(intent) && intent.Path == "" {
		intent.Path = "/"
	}
	var matches []gatewayPathMatch
	for _, gateway := range gateways {
		listeners := sliceField(gateway.Object, "spec", "listeners")
		for _, rawListener := range listeners {
			listener, ok := rawListener.(map[string]interface{})
			if !ok || !gatewayListenerMatchesIntent(listener, intent) {
				continue
			}
			listenerName := stringField(listener, "name")
			for _, route := range routes {
				if !gatewayRouteAttachedToGateway(route, gateway, listenerName) {
					continue
				}
				if !gatewayRouteHostnameMatches(route, intent.Host) {
					continue
				}
				rules := sliceField(route.Object, "spec", "rules")
				for ruleIndex, rawRule := range rules {
					rule, ok := rawRule.(map[string]interface{})
					if !ok || !gatewayRouteRuleMatches(route.GetKind(), rule, intent) {
						continue
					}
					backendRefs := sliceField(rule, "backendRefs")
					for backendIndex, rawBackend := range backendRefs {
						backend, ok := rawBackend.(map[string]interface{})
						if !ok {
							continue
						}
						if gatewayBackendRefWeight(backend) == 0 {
							continue
						}
						backendName := stringField(backend, "name")
						if backendName == "" {
							continue
						}
						backendPort, _ := int32Field(backend, "port")
						backendNamespace := defaultString(stringField(backend, "namespace"), route.GetNamespace())
						matches = append(matches, gatewayPathMatch{
							GatewayNamespace: gateway.GetNamespace(),
							GatewayName:      gateway.GetName(),
							ListenerName:     listenerName,
							ListenerHostname: stringField(listener, "hostname"),
							ListenerPort:     int32FieldDefault(listener, "port", 0),
							ListenerProtocol: stringField(listener, "protocol"),
							RouteKind:        route.GetKind(),
							RouteNamespace:   route.GetNamespace(),
							RouteName:        route.GetName(),
							RuleNumber:       ruleIndex + 1,
							BackendNumber:    backendIndex + 1,
							BackendNamespace: backendNamespace,
							BackendName:      backendName,
							BackendPort:      backendPort,
							BackendWeight:    gatewayBackendRefWeight(backend),
							MatchSummary:     gatewayRouteRuleMatchSummary(route.GetKind(), rule),
						})
					}
				}
			}
		}
	}
	sort.Slice(matches, func(i, j int) bool {
		left := gatewayPathMatchSortKey(matches[i])
		right := gatewayPathMatchSortKey(matches[j])
		return left < right
	})
	return matches
}

func gatewayListenerMatchesIntent(listener map[string]interface{}, intent gatewayTrafficIntent) bool {
	if !gatewayProtocolMatchesIntent(intent, stringField(listener, "protocol")) {
		return false
	}
	if !gatewayListenerPortMatches(intent.Port, int32FieldDefault(listener, "port", 0)) {
		return false
	}
	return gatewayHostnameMatches(stringField(listener, "hostname"), intent.Host)
}

func gatewayProtocolMatchesIntent(intent gatewayTrafficIntent, protocol string) bool {
	protocol = strings.ToUpper(strings.TrimSpace(protocol))
	if protocol == "" {
		return true
	}
	switch gatewayPrimaryRouteFamily(intent) {
	case "GRPCRoute":
		return protocol == "HTTPS" || protocol == "HTTP2" || protocol == "H2C" || protocol == "HTTP"
	case "TLSRoute":
		return protocol == "TLS"
	default:
		return gatewayProtocolMatches(intent.Scheme, protocol)
	}
}

func gatewayProtocolMatches(scheme, protocol string) bool {
	scheme = strings.ToLower(strings.TrimSpace(scheme))
	protocol = strings.ToUpper(strings.TrimSpace(protocol))
	if scheme == "" || protocol == "" {
		return true
	}
	switch scheme {
	case "http":
		return protocol == "HTTP" || protocol == "HTTP2" || protocol == "H2C"
	case "https":
		return protocol == "HTTPS" || protocol == "TLS"
	default:
		return false
	}
}

func gatewayListenerPortMatches(intentPort, listenerPort int32) bool {
	return intentPort == 0 || listenerPort == 0 || intentPort == listenerPort
}

func gatewayRouteHostnameMatches(route unstructured.Unstructured, host string) bool {
	return gatewayHTTPRouteHostnameMatches(route, host)
}

func gatewayHTTPRouteHostnameMatches(route unstructured.Unstructured, host string) bool {
	hostnames := sliceField(route.Object, "spec", "hostnames")
	if len(hostnames) == 0 {
		return true
	}
	for _, raw := range hostnames {
		pattern, ok := raw.(string)
		if ok && gatewayHostnameMatches(pattern, host) {
			return true
		}
	}
	return false
}

func gatewayRouteRuleMatches(kind string, rule map[string]interface{}, intent gatewayTrafficIntent) bool {
	switch kind {
	case "GRPCRoute":
		return gatewayGRPCRouteRuleMatches(rule, intent)
	case "TLSRoute":
		return true
	default:
		return gatewayHTTPRouteRuleMatches(rule, intent)
	}
}

func gatewayGRPCRouteRuleMatches(rule map[string]interface{}, intent gatewayTrafficIntent) bool {
	matches := sliceField(rule, "matches")
	if len(matches) == 0 {
		return true
	}
	for _, raw := range matches {
		match, ok := raw.(map[string]interface{})
		if !ok {
			continue
		}
		if gatewayGRPCRouteSingleMatch(match, intent) {
			return true
		}
	}
	return false
}

func gatewayGRPCRouteSingleMatch(match map[string]interface{}, intent gatewayTrafficIntent) bool {
	if !gatewayGRPCRouteMethodMatch(match, intent) {
		return false
	}
	return gatewayHTTPRouteHeadersMatch(match, intent.Headers)
}

func gatewayGRPCRouteMethodMatch(match map[string]interface{}, intent gatewayTrafficIntent) bool {
	method, ok := nestedMap(match, "method")
	if !ok {
		return true
	}
	serviceWant := stringField(method, "service")
	methodWant := stringField(method, "method")
	matchType := defaultString(stringField(method, "type"), "Exact")
	if serviceWant != "" {
		if intent.GRPCService == "" || !gatewayHTTPRouteValueMatches(matchType, serviceWant, intent.GRPCService) {
			return false
		}
	}
	if methodWant != "" {
		if intent.GRPCMethod == "" || !gatewayHTTPRouteValueMatches(matchType, methodWant, intent.GRPCMethod) {
			return false
		}
	}
	return true
}

func gatewayHostnameMatches(pattern, host string) bool {
	pattern = gatewayNormalizeHostname(pattern)
	host = gatewayNormalizeHostname(host)
	if pattern == "" || host == "" {
		return true
	}
	if !strings.HasPrefix(pattern, "*.") {
		return pattern == host
	}
	suffix := strings.TrimPrefix(pattern, "*")
	if !strings.HasSuffix(host, suffix) {
		return false
	}
	prefix := strings.TrimSuffix(host, suffix)
	return prefix != "" && !strings.Contains(prefix, ".")
}

func gatewayNormalizeHostname(value string) string {
	value = strings.ToLower(strings.TrimSpace(value))
	return strings.TrimSuffix(value, ".")
}

func gatewayRouteAttachedToGateway(route unstructured.Unstructured, gateway unstructured.Unstructured, listenerName string) bool {
	parentRefs := sliceField(route.Object, "spec", "parentRefs")
	for _, raw := range parentRefs {
		parent, ok := raw.(map[string]interface{})
		if !ok || parentKind(parent) != "Gateway" {
			continue
		}
		parentNamespace := defaultString(stringField(parent, "namespace"), route.GetNamespace())
		if parentNamespace != gateway.GetNamespace() || stringField(parent, "name") != gateway.GetName() {
			continue
		}
		sectionName := stringField(parent, "sectionName")
		if sectionName == "" || listenerName == "" || sectionName == listenerName {
			return true
		}
	}
	return false
}

func gatewayHTTPRouteRuleMatches(rule map[string]interface{}, intent gatewayTrafficIntent) bool {
	matches := sliceField(rule, "matches")
	if len(matches) == 0 {
		return gatewayPathPrefixMatches("/", intent.Path)
	}
	for _, raw := range matches {
		match, ok := raw.(map[string]interface{})
		if !ok {
			continue
		}
		if gatewayHTTPRouteSingleMatch(match, intent) {
			return true
		}
	}
	return false
}

func gatewayHTTPRouteSingleMatch(match map[string]interface{}, intent gatewayTrafficIntent) bool {
	if !gatewayHTTPRoutePathMatches(match, intent.Path) {
		return false
	}
	if !gatewayHTTPRouteMethodMatches(match, intent.Method) {
		return false
	}
	if !gatewayHTTPRouteHeadersMatch(match, intent.Headers) {
		return false
	}
	return gatewayHTTPRouteQueryParamsMatch(match, intent.Query)
}

func gatewayHTTPRoutePathMatches(match map[string]interface{}, path string) bool {
	if path == "" {
		path = "/"
	}
	pathSpec, ok := nestedMap(match, "path")
	if !ok {
		return gatewayPathPrefixMatches("/", path)
	}
	value := defaultString(stringField(pathSpec, "value"), "/")
	switch stringField(pathSpec, "type") {
	case "", "PathPrefix":
		return gatewayPathPrefixMatches(value, path)
	case "Exact":
		return path == value
	case "RegularExpression":
		matched, err := regexp.MatchString(value, path)
		return err == nil && matched
	default:
		return false
	}
}

func gatewayPathPrefixMatches(prefix, path string) bool {
	if prefix == "" || prefix == "/" {
		return strings.HasPrefix(path, "/")
	}
	if path == prefix {
		return true
	}
	return strings.HasPrefix(path, strings.TrimRight(prefix, "/")+"/")
}

func gatewayHTTPRouteMethodMatches(match map[string]interface{}, method string) bool {
	want := strings.ToUpper(strings.TrimSpace(stringField(match, "method")))
	if want == "" {
		return true
	}
	return want == strings.ToUpper(strings.TrimSpace(method))
}

func gatewayHTTPRouteHeadersMatch(match map[string]interface{}, headers map[string]string) bool {
	headerMatches := sliceField(match, "headers")
	if len(headerMatches) == 0 {
		return true
	}
	normalized := map[string]string{}
	for key, value := range headers {
		normalized[strings.ToLower(key)] = value
	}
	for _, raw := range headerMatches {
		header, ok := raw.(map[string]interface{})
		if !ok {
			return false
		}
		name := strings.ToLower(stringField(header, "name"))
		value, ok := normalized[name]
		if !ok || !gatewayHTTPRouteValueMatches(stringField(header, "type"), stringField(header, "value"), value) {
			return false
		}
	}
	return true
}

func gatewayHTTPRouteQueryParamsMatch(match map[string]interface{}, query map[string][]string) bool {
	queryMatches := sliceField(match, "queryParams")
	if len(queryMatches) == 0 {
		return true
	}
	for _, raw := range queryMatches {
		queryParam, ok := raw.(map[string]interface{})
		if !ok {
			return false
		}
		values := query[stringField(queryParam, "name")]
		if len(values) == 0 {
			return false
		}
		found := false
		for _, value := range values {
			if gatewayHTTPRouteValueMatches(stringField(queryParam, "type"), stringField(queryParam, "value"), value) {
				found = true
				break
			}
		}
		if !found {
			return false
		}
	}
	return true
}

func gatewayHTTPRouteValueMatches(matchType, want, got string) bool {
	switch matchType {
	case "", "Exact":
		return got == want
	case "RegularExpression":
		matched, err := regexp.MatchString(want, got)
		return err == nil && matched
	default:
		return false
	}
}

func gatewayRouteRuleMatchSummary(kind string, rule map[string]interface{}) string {
	switch kind {
	case "GRPCRoute":
		return gatewayGRPCRouteRuleMatchSummary(rule)
	case "TLSRoute":
		return "SNI hostname match"
	default:
		return gatewayHTTPRouteRuleMatchSummary(rule)
	}
}

func gatewayHTTPRouteRuleMatchSummary(rule map[string]interface{}) string {
	matches := sliceField(rule, "matches")
	if len(matches) == 0 {
		return "all requests"
	}
	var summaries []string
	for _, raw := range matches {
		match, ok := raw.(map[string]interface{})
		if !ok {
			continue
		}
		var parts []string
		if method := stringField(match, "method"); method != "" {
			parts = append(parts, "method="+method)
		}
		if path, ok := nestedMap(match, "path"); ok {
			parts = append(parts, fmt.Sprintf("path %s %q", defaultString(stringField(path, "type"), "PathPrefix"), defaultString(stringField(path, "value"), "/")))
		}
		if count := len(sliceField(match, "headers")); count > 0 {
			parts = append(parts, fmt.Sprintf("%d header match(es)", count))
		}
		if count := len(sliceField(match, "queryParams")); count > 0 {
			parts = append(parts, fmt.Sprintf("%d query match(es)", count))
		}
		if len(parts) == 0 {
			parts = append(parts, "all requests")
		}
		summaries = append(summaries, strings.Join(parts, ", "))
	}
	return strings.Join(summaries, " OR ")
}

func gatewayGRPCRouteRuleMatchSummary(rule map[string]interface{}) string {
	matches := sliceField(rule, "matches")
	if len(matches) == 0 {
		return "all gRPC requests"
	}
	var summaries []string
	for _, raw := range matches {
		match, ok := raw.(map[string]interface{})
		if !ok {
			continue
		}
		var parts []string
		if method, ok := nestedMap(match, "method"); ok {
			if service := stringField(method, "service"); service != "" {
				parts = append(parts, "service="+service)
			}
			if name := stringField(method, "method"); name != "" {
				parts = append(parts, "method="+name)
			}
		}
		if count := len(sliceField(match, "headers")); count > 0 {
			parts = append(parts, fmt.Sprintf("%d header match(es)", count))
		}
		if len(parts) == 0 {
			parts = append(parts, "all gRPC requests")
		}
		summaries = append(summaries, strings.Join(parts, ", "))
	}
	return strings.Join(summaries, " OR ")
}

func gatewayHTTPRouteRuleFilterSummary(rule map[string]interface{}) string {
	filters := sliceField(rule, "filters")
	if len(filters) == 0 {
		return ""
	}
	var names []string
	for _, raw := range filters {
		filter, ok := raw.(map[string]interface{})
		if !ok {
			continue
		}
		filterType := stringField(filter, "type")
		if filterType == "" {
			filterType = "unknown"
		}
		names = append(names, filterType)
	}
	if len(names) == 0 {
		return ""
	}
	return strings.Join(names, ", ")
}

func gatewayURLRewriteText(rule map[string]interface{}, intent gatewayTrafficIntent) string {
	for _, raw := range sliceField(rule, "filters") {
		filter, ok := raw.(map[string]interface{})
		if !ok || stringField(filter, "type") != "URLRewrite" {
			continue
		}
		rewrite, ok := nestedMap(filter, "urlRewrite")
		if !ok {
			return "rewrites the request URL"
		}
		var parts []string
		if hostname := stringField(rewrite, "hostname"); hostname != "" {
			parts = append(parts, fmt.Sprintf("host to %q", hostname))
		}
		if path, ok := nestedMap(rewrite, "path"); ok {
			switch stringField(path, "type") {
			case "ReplaceFullPath":
				if value := stringField(path, "replaceFullPath"); value != "" {
					parts = append(parts, fmt.Sprintf("path from %q to %q", defaultString(intent.Path, "/"), value))
				}
			case "ReplacePrefixMatch":
				if value := stringField(path, "replacePrefixMatch"); value != "" {
					parts = append(parts, fmt.Sprintf("matching path prefix to %q", value))
				}
			default:
				parts = append(parts, "path")
			}
		}
		if len(parts) == 0 {
			return "rewrites the request URL"
		}
		return "rewrites " + strings.Join(parts, " and ")
	}
	return ""
}

func gatewayRequestMirrorBackendRefs(rule map[string]interface{}) []map[string]interface{} {
	var out []map[string]interface{}
	for _, raw := range sliceField(rule, "filters") {
		filter, ok := raw.(map[string]interface{})
		if !ok || stringField(filter, "type") != "RequestMirror" {
			continue
		}
		mirror, ok := nestedMap(filter, "requestMirror")
		if !ok {
			continue
		}
		backend, ok := nestedMap(mirror, "backendRef")
		if !ok {
			continue
		}
		out = append(out, backend)
	}
	return out
}

func gatewayFirstRedirectRule(matches []gatewayRuleMatch) *gatewayRuleMatch {
	for i := range matches {
		if httpRouteRuleHasRedirect(matches[i].Rule) {
			return &matches[i]
		}
	}
	return nil
}

func gatewayPathMatchSortKey(match gatewayPathMatch) string {
	return fmt.Sprintf("%s/%s/%s/%s/%s/%03d/%03d/%s/%s/%05d",
		match.GatewayNamespace,
		match.GatewayName,
		match.ListenerName,
		match.RouteNamespace,
		match.RouteName,
		match.RuleNumber,
		match.BackendNumber,
		match.BackendNamespace,
		match.BackendName,
		match.BackendPort,
	)
}

func gatewayRouteScopeForRouteFilter(httpRoutes, grpcRoutes, tlsRoutes, tcpRoutes, udpRoutes []unstructured.Unstructured, opts GatewayOptions) gatewayRouteScope {
	if opts.RouteRef == "" {
		return gatewayRouteScope{}
	}
	filter := parseGatewayObjectRef(opts.RouteRef, opts.Namespace)
	scope := gatewayRouteScope{
		Active:              true,
		Gateways:            map[string]bool{},
		GatewayAllListeners: map[string]bool{},
		GatewayListeners:    map[string]map[string]bool{},
		Routes:              map[string]bool{},
		Services:            map[string]bool{},
		EnvoyBackends:       map[string]bool{},
		HTTPRouteFilters:    map[string]bool{},
	}
	addRoutes := func(kind string, routes []unstructured.Unstructured) {
		for _, route := range routes {
			if !gatewayObjectRefMatches(route, filter) {
				continue
			}
			scope.Routes[gatewayRouteScopeRouteKey(kind, route.GetNamespace(), route.GetName())] = true
			for _, service := range gatewayRouteBackendServiceRefs(route) {
				scope.Services[service] = true
			}
			for _, backend := range gatewayRouteEnvoyBackendRefs(route) {
				scope.EnvoyBackends[backend] = true
			}
			if kind == "HTTPRoute" {
				for _, filterRef := range gatewayHTTPRouteFilterRefs(route) {
					scope.HTTPRouteFilters[filterRef] = true
				}
			}
			parentRefs := sliceField(route.Object, "spec", "parentRefs")
			for _, raw := range parentRefs {
				parent, ok := raw.(map[string]interface{})
				if !ok || parentKind(parent) != "Gateway" {
					continue
				}
				name := stringField(parent, "name")
				if name == "" {
					continue
				}
				namespace := defaultString(stringField(parent, "namespace"), route.GetNamespace())
				gatewayKey := namespace + "/" + name
				scope.Gateways[gatewayKey] = true
				sectionName := stringField(parent, "sectionName")
				if sectionName == "" {
					scope.GatewayAllListeners[gatewayKey] = true
					continue
				}
				if scope.GatewayListeners[gatewayKey] == nil {
					scope.GatewayListeners[gatewayKey] = map[string]bool{}
				}
				scope.GatewayListeners[gatewayKey][sectionName] = true
			}
		}
	}
	addRoutes("HTTPRoute", httpRoutes)
	addRoutes("GRPCRoute", grpcRoutes)
	addRoutes("TLSRoute", tlsRoutes)
	addRoutes("TCPRoute", tcpRoutes)
	addRoutes("UDPRoute", udpRoutes)
	return scope
}

func gatewayRouteEnvoyBackendRefs(route unstructured.Unstructured) []string {
	seen := map[string]bool{}
	var out []string
	for _, rawRule := range sliceField(route.Object, "spec", "rules") {
		rule, ok := rawRule.(map[string]interface{})
		if !ok {
			continue
		}
		for _, rawRef := range sliceField(rule, "backendRefs") {
			ref, ok := rawRef.(map[string]interface{})
			if !ok {
				continue
			}
			if stringField(ref, "group") != "gateway.envoyproxy.io" || defaultString(stringField(ref, "kind"), "Service") != "Backend" {
				continue
			}
			name := stringField(ref, "name")
			if name == "" {
				continue
			}
			namespace := defaultString(stringField(ref, "namespace"), route.GetNamespace())
			key := namespace + "/" + name
			if !seen[key] {
				seen[key] = true
				out = append(out, key)
			}
		}
	}
	sort.Strings(out)
	return out
}

func gatewayHTTPRouteFilterRefs(route unstructured.Unstructured) []string {
	seen := map[string]bool{}
	var out []string
	for _, rawRule := range sliceField(route.Object, "spec", "rules") {
		rule, ok := rawRule.(map[string]interface{})
		if !ok {
			continue
		}
		for _, rawFilter := range sliceField(rule, "filters") {
			filter, ok := rawFilter.(map[string]interface{})
			if !ok || stringField(filter, "type") != "ExtensionRef" {
				continue
			}
			ref := mapField(filter, "extensionRef")
			if stringField(ref, "group") != "gateway.envoyproxy.io" || stringField(ref, "kind") != "HTTPRouteFilter" {
				continue
			}
			name := stringField(ref, "name")
			if name == "" {
				continue
			}
			namespace := route.GetNamespace()
			key := namespace + "/" + name
			if !seen[key] {
				seen[key] = true
				out = append(out, key)
			}
		}
	}
	sort.Strings(out)
	return out
}

func (s *gatewayScanner) gatewayPolicyMatchesRouteScope(policy unstructured.Unstructured, policyKind, layer string, scope gatewayRouteScope, targets gatewayPolicyTargetIndexes) bool {
	targetRefs := gatewayPolicyTargetRefs(policy)
	selectedRefs, selectorWarnings := s.gatewayPolicyTargetSelectorRefs(policy, policyKind, layer, targets)
	if len(targetRefs) == 0 && len(selectedRefs) == 0 && len(selectorWarnings) > 0 {
		return true
	}
	targetRefs = append(targetRefs, selectedRefs...)
	for _, targetRef := range targetRefs {
		target := targetRef.ref
		group := stringField(target, "group")
		kind := defaultString(stringField(target, "kind"), "Service")
		namespace := defaultString(stringField(target, "namespace"), policy.GetNamespace())
		name := stringField(target, "name")
		if name == "" {
			continue
		}
		switch gatewayPolicyCanonicalTargetKind(group, kind) {
		case "Gateway":
			if scope.Gateways[namespace+"/"+name] {
				return true
			}
		case "Service":
			if scope.Services[namespace+"/"+name] {
				return true
			}
		case "HTTPRoute", "GRPCRoute", "TLSRoute", "TCPRoute", "UDPRoute":
			if scope.Routes[gatewayRouteScopeRouteKey(gatewayPolicyCanonicalTargetKind(group, kind), namespace, name)] {
				return true
			}
		}
	}
	return false
}

func gatewayRouteScopeRouteKey(kind, namespace, name string) string {
	return kind + "/" + namespace + "/" + name
}

func gatewayRouteBackendServiceRefs(route unstructured.Unstructured) []string {
	seen := map[string]bool{}
	var out []string
	for _, rawRule := range sliceField(route.Object, "spec", "rules") {
		rule, ok := rawRule.(map[string]interface{})
		if !ok {
			continue
		}
		for _, rawRef := range sliceField(rule, "backendRefs") {
			ref, ok := rawRef.(map[string]interface{})
			if !ok {
				continue
			}
			group := stringField(ref, "group")
			kind := defaultString(stringField(ref, "kind"), "Service")
			name := stringField(ref, "name")
			if name == "" || group != "" || kind != "Service" {
				continue
			}
			namespace := defaultString(stringField(ref, "namespace"), route.GetNamespace())
			key := namespace + "/" + name
			if !seen[key] {
				seen[key] = true
				out = append(out, key)
			}
		}
	}
	return out
}

func parentKind(parent map[string]interface{}) string {
	group := stringField(parent, "group")
	kind := defaultString(stringField(parent, "kind"), "Gateway")
	if group != "" && group != gatewayv1.GroupName {
		return group + "/" + kind
	}
	return kind
}

func objectRefText(object unstructured.Unstructured) string {
	if object.GetNamespace() == "" {
		return object.GetName()
	}
	return object.GetNamespace() + "/" + object.GetName()
}

func objectNames(objects []unstructured.Unstructured) []string {
	var out []string
	for _, object := range objects {
		out = append(out, objectRefText(object))
	}
	sort.Strings(out)
	return out
}

func gatewayStatusListeners(object map[string]interface{}) map[string]map[string]interface{} {
	out := map[string]map[string]interface{}{}
	listeners := sliceField(object, "status", "listeners")
	for _, raw := range listeners {
		listener, ok := raw.(map[string]interface{})
		if !ok {
			continue
		}
		name := stringField(listener, "name")
		if name != "" {
			out[name] = listener
		}
	}
	return out
}

func routeParentStatusText(defaultNamespace string, parent map[string]interface{}) string {
	parentRef, ok := nestedMap(parent, "parentRef")
	if !ok {
		return "parent"
	}
	name := stringField(parentRef, "name")
	namespace := defaultString(stringField(parentRef, "namespace"), defaultNamespace)
	if name == "" {
		return "parent"
	}
	return "Gateway " + namespace + "/" + name
}

func httpRouteRuleHasRedirect(rule map[string]interface{}) bool {
	filters := sliceField(rule, "filters")
	for _, raw := range filters {
		filter, ok := raw.(map[string]interface{})
		if !ok {
			continue
		}
		if stringField(filter, "type") == "RequestRedirect" {
			return true
		}
	}
	return false
}

func referenceGrantAllows(grants []unstructured.Unstructured, fromGroup, fromKind, fromNamespace, toGroup, toKind, toName, toNamespace string) bool {
	for _, grant := range grants {
		if grant.GetNamespace() != toNamespace {
			continue
		}
		if !referenceGrantFromAllows(grant, fromGroup, fromKind, fromNamespace) {
			continue
		}
		if referenceGrantToAllows(grant, toGroup, toKind, toName) {
			return true
		}
	}
	return false
}

func referenceGrantFromAllows(grant unstructured.Unstructured, fromGroup, fromKind, fromNamespace string) bool {
	fromList := sliceField(grant.Object, "spec", "from")
	for _, raw := range fromList {
		from, ok := raw.(map[string]interface{})
		if !ok {
			continue
		}
		if stringField(from, "group") == fromGroup &&
			stringField(from, "kind") == fromKind &&
			stringField(from, "namespace") == fromNamespace {
			return true
		}
	}
	return false
}

func referenceGrantToAllows(grant unstructured.Unstructured, toGroup, toKind, toName string) bool {
	toList := sliceField(grant.Object, "spec", "to")
	for _, raw := range toList {
		to, ok := raw.(map[string]interface{})
		if !ok {
			continue
		}
		if stringField(to, "group") != toGroup || stringField(to, "kind") != toKind {
			continue
		}
		name := stringField(to, "name")
		if name == "" || name == toName {
			return true
		}
	}
	return false
}

func cachedService(ctx context.Context, client *kube.Client, namespace, name string, cache map[string]*corev1.Service, errCache map[string]error) (*corev1.Service, error) {
	key := namespace + "/" + name
	if service, ok := cache[key]; ok {
		return service, nil
	}
	if err, ok := errCache[key]; ok {
		return nil, err
	}
	service, err := client.Core.CoreV1().Services(namespace).Get(ctx, name, metav1.GetOptions{})
	if err != nil {
		errCache[key] = err
		return nil, err
	}
	cache[key] = service
	return service, nil
}

func cachedReadyEndpointCount(ctx context.Context, client *kube.Client, namespace, service string, cache map[string]int, errCache map[string]error) (int, error) {
	key := namespace + "/" + service
	if count, ok := cache[key]; ok {
		return count, nil
	}
	if err, ok := errCache[key]; ok {
		return 0, err
	}
	slices, err := client.Core.DiscoveryV1().EndpointSlices(namespace).List(ctx, metav1.ListOptions{
		LabelSelector: discoveryv1.LabelServiceName + "=" + service,
	})
	if err != nil {
		errCache[key] = err
		return 0, err
	}
	count := 0
	for _, slice := range slices.Items {
		for _, endpoint := range slice.Endpoints {
			if endpoint.Conditions.Ready != nil && !*endpoint.Conditions.Ready {
				continue
			}
			count += len(endpoint.Addresses)
		}
	}
	cache[key] = count
	return count, nil
}

func serviceHasGatewayPort(service *corev1.Service, port int32) bool {
	if service == nil {
		return false
	}
	for _, servicePort := range service.Spec.Ports {
		if servicePort.Port == port {
			return true
		}
	}
	return false
}

func serviceHasPortName(service *corev1.Service, name string) bool {
	if service == nil || name == "" {
		return false
	}
	for _, servicePort := range service.Spec.Ports {
		if servicePort.Name == name {
			return true
		}
	}
	return false
}

func serviceExposesPort(service *corev1.Service, port int32) bool {
	if service == nil || port <= 0 {
		return false
	}
	for _, servicePort := range service.Spec.Ports {
		if servicePort.Port == port {
			return true
		}
	}
	return false
}

func stringField(object map[string]interface{}, fields ...string) string {
	value, _, _ := unstructured.NestedString(object, fields...)
	return value
}

func int32Field(object map[string]interface{}, fields ...string) (int32, bool) {
	if value, ok, _ := unstructured.NestedInt64(object, fields...); ok {
		return int32PortFromInt64(value)
	}
	raw, ok, _ := unstructured.NestedString(object, fields...)
	if !ok {
		return 0, false
	}
	parsed, err := strconv.Atoi(raw)
	if err != nil || parsed <= 0 || parsed > 65535 {
		return 0, false
	}
	return int32PortFromInt(parsed)
}

func int32FieldDefault(object map[string]interface{}, field string, fallback int32) int32 {
	value, ok := int32Field(object, field)
	if !ok {
		return fallback
	}
	return value
}

func int64FieldDefault(object map[string]interface{}, field string, fallback int64) int64 {
	value, ok, _ := unstructured.NestedInt64(object, field)
	if !ok {
		return fallback
	}
	return value
}

func int64Field(object map[string]interface{}, fields ...string) (int64, bool) {
	value, ok, _ := unstructured.NestedInt64(object, fields...)
	return value, ok
}

func numberField(object map[string]interface{}, fields ...string) (float64, bool) {
	if value, ok, _ := unstructured.NestedFloat64(object, fields...); ok {
		return value, true
	}
	if value, ok, _ := unstructured.NestedInt64(object, fields...); ok {
		return float64(value), true
	}
	return 0, false
}

func int64Value(value interface{}) (int64, bool) {
	switch typed := value.(type) {
	case int64:
		return typed, true
	case int:
		return int64(typed), true
	case int32:
		return int64(typed), true
	case float64:
		if typed == float64(int64(typed)) {
			return int64(typed), true
		}
	case string:
		parsed, err := strconv.ParseInt(typed, 10, 64)
		if err == nil {
			return parsed, true
		}
	}
	return 0, false
}

func parseGatewayDuration(value string) (time.Duration, bool) {
	if value == "" {
		return 0, false
	}
	duration, err := time.ParseDuration(value)
	if err != nil {
		return 0, false
	}
	return duration, true
}

func isZeroGatewayQuantity(value interface{}) bool {
	if value == nil {
		return false
	}
	if number, ok := int64Value(value); ok {
		return number == 0
	}
	raw, ok := value.(string)
	if !ok {
		return false
	}
	quantity, err := resource.ParseQuantity(raw)
	if err != nil {
		return false
	}
	return quantity.IsZero()
}

func isTinyGatewayQuantity(value interface{}, minimumBytes int64) bool {
	if value == nil {
		return false
	}
	if number, ok := int64Value(value); ok {
		return number > 0 && number < minimumBytes
	}
	raw, ok := value.(string)
	if !ok {
		return false
	}
	quantity, err := resource.ParseQuantity(raw)
	if err != nil {
		return false
	}
	if quantity.Sign() <= 0 {
		return false
	}
	return quantity.Cmp(*resource.NewQuantity(minimumBytes, resource.BinarySI)) < 0
}

func sliceField(object map[string]interface{}, fields ...string) []interface{} {
	value, _, _ := unstructured.NestedSlice(object, fields...)
	return value
}

func mapField(object map[string]interface{}, fields ...string) map[string]interface{} {
	value, ok, _ := unstructured.NestedMap(object, fields...)
	if !ok {
		return map[string]interface{}{}
	}
	return value
}

func nestedMap(object map[string]interface{}, fields ...string) (map[string]interface{}, bool) {
	value, ok, _ := unstructured.NestedMap(object, fields...)
	return value, ok
}

func defaultString(value string, fallback string) string {
	if value != "" {
		return value
	}
	return fallback
}

func conditionMessageSuffix(message string) string {
	if strings.TrimSpace(message) == "" {
		return ""
	}
	return ": " + strings.TrimSpace(message)
}

func gatewaySortObjects(items []unstructured.Unstructured) {
	sort.Slice(items, func(i, j int) bool {
		return objectRefText(items[i]) < objectRefText(items[j])
	})
}
