package check

import (
	"context"
	"fmt"
	"net/url"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/CoGoRepo/KubeNetMods/internal/kube"
	"github.com/CoGoRepo/KubeNetMods/internal/model"
	corev1 "k8s.io/api/core/v1"
	discoveryv1 "k8s.io/api/discovery/v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"
	"k8s.io/apimachinery/pkg/runtime/schema"
	gatewayv1 "sigs.k8s.io/gateway-api/apis/v1"
)

var (
	gatewayClassGVR = schema.GroupVersionResource{Group: gatewayv1.GroupName, Version: "v1", Resource: "gatewayclasses"}
	gatewayGVR      = schema.GroupVersionResource{Group: gatewayv1.GroupName, Version: "v1", Resource: "gateways"}
	httpRouteGVR    = schema.GroupVersionResource{Group: gatewayv1.GroupName, Version: "v1", Resource: "httproutes"}
	referenceGVR    = schema.GroupVersionResource{Group: gatewayv1.GroupName, Version: "v1", Resource: "referencegrants"}
)

type GatewayOptions struct {
	Context       string
	Namespace     string
	GatewayRef    string
	RouteRef      string
	GatewayClass  string
	URL           string
	Host          string
	Scheme        string
	Path          string
	Method        string
	HTTPHeaders   map[string]string
	ExpectService string
	Limit         int
	Wide          bool
	Timeout       time.Duration
}

func RunGateway(ctx context.Context, opts GatewayOptions) (*model.Report, error) {
	if opts.Limit <= 0 {
		opts.Limit = 50
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
		"Gateway checks currently perform a static Kubernetes/Gateway API scan; they do not run external probes or inspect provider xDS/dataplane state yet.",
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
	refGrants, refGrantErr := gatewayList(ctx, client, referenceGVR, metav1.NamespaceAll)

	if gatewayAPIMissing(classErr) && gatewayAPIMissing(gatewayErr) && gatewayAPIMissing(routeErr) && gatewayAPIMissing(parentGatewayErr) {
		report.Add("Gateway API Access", "v1 resources", model.StatusInfo, "Gateway API v1 resources were not found in this cluster.")
		return
	}
	if classErr != nil && !gatewayAPIMissing(classErr) {
		scanner.addProblem("Gateway API Access", "GatewayClass list", model.StatusWarn, fmt.Sprintf("Could not list GatewayClass objects: %v", classErr), "")
	}
	if gatewayErr != nil && !gatewayAPIMissing(gatewayErr) {
		scanner.addProblem("Gateway API Access", "Gateway list", model.StatusWarn, fmt.Sprintf("Could not list Gateway objects: %v", gatewayErr), "")
	}
	if parentGatewayErr != nil && parentGatewayErr != gatewayErr && !gatewayAPIMissing(parentGatewayErr) {
		scanner.addProblem("Gateway API Access", "Gateway parent lookup", model.StatusWarn, fmt.Sprintf("Could not list Gateway objects cluster-wide for HTTPRoute parent resolution: %v", parentGatewayErr), "")
	}
	if routeErr != nil && !gatewayAPIMissing(routeErr) {
		scanner.addProblem("Gateway API Access", "HTTPRoute list", model.StatusWarn, fmt.Sprintf("Could not list HTTPRoute objects: %v", routeErr), "")
	}
	if refGrantErr != nil && !gatewayAPIMissing(refGrantErr) {
		scanner.addProblem("Gateway API Access", "ReferenceGrant list", model.StatusWarn, fmt.Sprintf("Could not list ReferenceGrant objects: %v", refGrantErr), "")
	}
	gatewaySortObjects(classes)
	gatewaySortObjects(gateways)
	gatewaySortObjects(parentGateways)
	gatewaySortObjects(routes)
	gatewaySortObjects(refGrants)

	var classIndex map[string]unstructured.Unstructured
	if classErr == nil {
		classIndex = gatewayClassIndex(classes)
	}
	serviceCache := map[string]*corev1.Service{}
	serviceErrCache := map[string]error{}
	endpointReadyCache := map[string]int{}
	endpointErrCache := map[string]error{}
	routeParentFilter := gatewayParentsForRouteFilter(routes, opts)

	if intentMode {
		scanner.scanGatewayTrafficIntent(ctx, client, gateways, parentGateways, routes, refGrants, serviceCache, serviceErrCache, endpointReadyCache, endpointErrCache, intent)
		scanner.finish(len(classes), len(gateways), len(routes))
		dedupeGatewayDiagnoses(report)
		return
	}

	scanner.scanGatewayClasses(classes)
	scanner.scanGateways(ctx, client, gateways, classIndex, refGrants, routeParentFilter)
	scanner.scanHTTPRoutes(ctx, client, routes, parentGateways, refGrants, serviceCache, serviceErrCache, endpointReadyCache, endpointErrCache)

	scanner.finish(len(classes), len(gateways), len(routes))
	dedupeGatewayDiagnoses(report)
}

type gatewayScanner struct {
	report        *model.Report
	opts          GatewayOptions
	limit         int
	problemCount  int
	truncated     bool
	scannedClass  int
	scannedGate   int
	scannedRoutes int
	trafficIntent bool
}

func (s *gatewayScanner) addProblem(layer, check string, status model.Status, message string, diagnosis string) {
	if s.limit <= 0 {
		s.limit = 50
	}
	s.problemCount++
	if s.problemCount <= s.limit {
		s.report.Add(layer, check, status, message)
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

func (s *gatewayScanner) finish(classCount, gatewayCount, routeCount int) {
	s.addFilterMissProblems()
	filterText := s.filterText()
	if filterText != "" {
		filterText = " " + filterText
	}
	if s.trafficIntent {
		s.report.Add("Gateway API Access", "traffic scope", model.StatusInfo, fmt.Sprintf("Evaluated %d Gateway and %d HTTPRoute object(s) for the requested traffic intent%s.", s.scannedGate, s.scannedRoutes, filterText))
	} else {
		s.report.Add("Gateway API Access", "scan summary", model.StatusInfo, fmt.Sprintf("Scanned %d GatewayClass, %d Gateway, and %d HTTPRoute object(s)%s.", s.scannedClass, s.scannedGate, s.scannedRoutes, filterText))
	}
	if s.problemCount == 0 && !s.trafficIntent {
		s.report.Add("Gateway API Scan", "obvious problems", model.StatusPass, "No obvious Gateway API status, attachment, reference, or backend endpoint problems found.")
	}
	if s.truncated {
		s.report.Add("Gateway API Scan", "limit", model.StatusWarn, fmt.Sprintf("Scan found more than %d problem detail(s). Re-run with --limit %d or narrower filters for the full list.", s.limit, s.limit*2))
	}
	if classCount == 0 && gatewayCount == 0 && routeCount == 0 {
		s.report.Add("Gateway API Scan", "objects", model.StatusInfo, "Gateway API v1 is available, but no GatewayClass, Gateway, or HTTPRoute objects matched the scan scope.")
	}
}

func gatewayTrafficIntentFromOptions(opts GatewayOptions) (gatewayTrafficIntent, bool, error) {
	hasURL := strings.TrimSpace(opts.URL) != ""
	hasPartialIntent := strings.TrimSpace(opts.Host) != "" ||
		strings.TrimSpace(opts.Scheme) != "" ||
		strings.TrimSpace(opts.Path) != "" ||
		strings.TrimSpace(opts.Method) != "" ||
		len(opts.HTTPHeaders) > 0 ||
		strings.TrimSpace(opts.ExpectService) != ""
	if !hasURL && !hasPartialIntent {
		return gatewayTrafficIntent{}, false, nil
	}
	intent := gatewayTrafficIntent{
		Scheme:  strings.ToLower(strings.TrimSpace(opts.Scheme)),
		Host:    gatewayNormalizeHostname(opts.Host),
		Path:    strings.TrimSpace(opts.Path),
		Method:  strings.ToUpper(strings.TrimSpace(opts.Method)),
		Headers: opts.HTTPHeaders,
	}
	if intent.Path == "" {
		intent.Path = "/"
	}
	if !strings.HasPrefix(intent.Path, "/") {
		return gatewayTrafficIntent{}, true, fmt.Errorf("Gateway traffic intent path %q is invalid; paths must start with /.", intent.Path)
	}
	if hasURL {
		if opts.Host != "" || opts.Scheme != "" || opts.Path != "" {
			return gatewayTrafficIntent{}, true, fmt.Errorf("--url owns scheme, host, port, path, and query; do not combine it with --host, --scheme, or --path.")
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
			intent.Port = int32(parsedPort)
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
	if intent.Method == "" {
		intent.Method = "GET"
	}
	if intent.Port == 0 {
		intent.Port = gatewayDefaultPortForScheme(intent.Scheme)
	}
	return intent, true, nil
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
		if gateway := gatewayDiagnosisListenerGateway(message); gateway != "" && gatewayConcrete[gateway] && gatewayDiagnosisIsListenerStatus(message) {
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
	if !strings.HasPrefix(message, "HTTPRoute ") {
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

func (s *gatewayScanner) addFilterMissProblems() {
	if s.opts.GatewayClass != "" && s.scannedClass == 0 {
		s.addProblem("Gateway API Scan", "gateway-class filter", model.StatusFail, fmt.Sprintf("No GatewayClass matched %q.", s.opts.GatewayClass), fmt.Sprintf("GatewayClass %q was not found in the cluster.", s.opts.GatewayClass))
	}
	if s.opts.GatewayRef != "" && s.scannedGate == 0 {
		s.addProblem("Gateway API Scan", "gateway filter", model.StatusFail, fmt.Sprintf("No Gateway matched %q.", s.opts.GatewayRef), fmt.Sprintf("Gateway %q was not found in the scan scope.", s.opts.GatewayRef))
	}
	if s.opts.RouteRef != "" && s.scannedRoutes == 0 {
		s.addProblem("Gateway API Scan", "route filter", model.StatusFail, fmt.Sprintf("No HTTPRoute matched %q.", s.opts.RouteRef), fmt.Sprintf("HTTPRoute %q was not found in the scan scope.", s.opts.RouteRef))
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

func (s *gatewayScanner) scanGateways(ctx context.Context, client *kube.Client, gateways []unstructured.Unstructured, classes map[string]unstructured.Unstructured, refGrants []unstructured.Unstructured, routeParentFilter map[string]bool) {
	filter := parseGatewayObjectRef(s.opts.GatewayRef, s.opts.Namespace)
	for _, gateway := range gateways {
		if !gatewayObjectRefMatches(gateway, filter) {
			continue
		}
		if len(routeParentFilter) > 0 && !routeParentFilter[objectRefText(gateway)] {
			continue
		}
		className := stringField(gateway.Object, "spec", "gatewayClassName")
		if s.opts.GatewayClass != "" && className != s.opts.GatewayClass {
			continue
		}
		s.scannedGate++
		gwName := objectRefText(gateway)
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
		s.scanGatewayListeners(ctx, client, gateway, refGrants)
		s.addWide("Gateway Layer", gwName, model.StatusPass, fmt.Sprintf("Gateway %s scanned.", gwName))
	}
}

func (s *gatewayScanner) scanGatewayListeners(ctx context.Context, client *kube.Client, gateway unstructured.Unstructured, refGrants []unstructured.Unstructured) {
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
			s.addProblem("TLS Reference Layer", check, model.StatusWarn, fmt.Sprintf("Gateway %s listener certificateRef %s/%s is %s/%s; KNM only validates core Secret refs right now.", gwName, namespace, name, group, kind), "")
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
		s.scanHTTPRouteParents(route, gatewayIndex)
		s.scanHTTPRouteBackendRefs(ctx, client, route, refGrants, serviceCache, serviceErrCache, endpointReadyCache, endpointErrCache)
		s.addWide("HTTPRoute Layer", routeName, model.StatusPass, fmt.Sprintf("HTTPRoute %s scanned.", routeName))
	}
}

func (s *gatewayScanner) scanHTTPRouteParents(route unstructured.Unstructured, gatewayIndex map[string]unstructured.Unstructured) {
	routeName := objectRefText(route)
	parentRefs := sliceField(route.Object, "spec", "parentRefs")
	if len(parentRefs) == 0 {
		s.addProblem("Route Attachment Layer", routeName, model.StatusWarn, fmt.Sprintf("HTTPRoute %s has no spec.parentRefs.", routeName), fmt.Sprintf("HTTPRoute %s is not attached to any Gateway, so it will not receive Gateway traffic.", routeName))
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
			s.addProblem("Route Attachment Layer", routeName+" parent", model.StatusFail, fmt.Sprintf("HTTPRoute %s references missing parent Gateway %s/%s.", routeName, parentNS, parentName), fmt.Sprintf("HTTPRoute %s references Gateway %s/%s, but that Gateway was not found.", routeName, parentNS, parentName))
		}
	}
	parents := sliceField(route.Object, "status", "parents")
	if len(parents) == 0 {
		s.addProblem("Route Attachment Layer", routeName+" status", model.StatusWarn, fmt.Sprintf("HTTPRoute %s has no status.parents entries.", routeName), fmt.Sprintf("HTTPRoute %s has no parent status, so no Gateway has reported accepting it yet.", routeName))
		return
	}
	accepted := false
	for _, raw := range parents {
		parent, ok := raw.(map[string]interface{})
		if !ok {
			continue
		}
		parentText := routeParentStatusText(route.GetNamespace(), parent)
		if cond, ok := conditionByType(parent, string(gatewayv1.RouteConditionAccepted)); ok {
			if strings.EqualFold(cond.Status, "True") {
				accepted = true
			}
			if strings.EqualFold(cond.Status, "False") {
				s.addProblem("Route Attachment Layer", routeName+" Accepted", model.StatusFail, fmt.Sprintf("HTTPRoute %s is not accepted by %s: %s%s", routeName, parentText, cond.Reason, conditionMessageSuffix(cond.Message)), fmt.Sprintf("HTTPRoute %s is not accepted by %s: %s%s", routeName, parentText, cond.Reason, conditionMessageSuffix(cond.Message)))
			}
		}
		if cond, ok := conditionByType(parent, string(gatewayv1.RouteConditionResolvedRefs)); ok && strings.EqualFold(cond.Status, "False") {
			s.addProblem("Route Attachment Layer", routeName+" ResolvedRefs", model.StatusFail, fmt.Sprintf("HTTPRoute %s has unresolved refs for %s: %s%s", routeName, parentText, cond.Reason, conditionMessageSuffix(cond.Message)), fmt.Sprintf("HTTPRoute %s has unresolved references for %s: %s%s", routeName, parentText, cond.Reason, conditionMessageSuffix(cond.Message)))
		}
		if cond, ok := conditionByType(parent, string(gatewayv1.RouteConditionPartiallyInvalid)); ok && strings.EqualFold(cond.Status, "True") {
			s.addProblem("Route Attachment Layer", routeName+" PartiallyInvalid", model.StatusWarn, fmt.Sprintf("HTTPRoute %s is partially invalid for %s: %s%s", routeName, parentText, cond.Reason, conditionMessageSuffix(cond.Message)), fmt.Sprintf("HTTPRoute %s is partially invalid for %s: %s%s", routeName, parentText, cond.Reason, conditionMessageSuffix(cond.Message)))
		}
	}
	if !accepted {
		s.addProblem("Route Attachment Layer", routeName+" accepted", model.StatusWarn, fmt.Sprintf("HTTPRoute %s has no Accepted=True parent status.", routeName), fmt.Sprintf("HTTPRoute %s is not currently accepted by any Gateway parent.", routeName))
	}
}

func (s *gatewayScanner) scanHTTPRouteBackendRefs(ctx context.Context, client *kube.Client, route unstructured.Unstructured, refGrants []unstructured.Unstructured, serviceCache map[string]*corev1.Service, serviceErrCache map[string]error, endpointReadyCache map[string]int, endpointErrCache map[string]error) {
	routeName := objectRefText(route)
	rules := sliceField(route.Object, "spec", "rules")
	for ruleIndex, rawRule := range rules {
		rule, ok := rawRule.(map[string]interface{})
		if !ok {
			continue
		}
		backendRefs := sliceField(rule, "backendRefs")
		if len(backendRefs) == 0 {
			if httpRouteRuleHasRedirect(rule) {
				continue
			}
			s.addProblem("BackendRef Layer", fmt.Sprintf("%s rule %d", routeName, ruleIndex+1), model.StatusWarn, fmt.Sprintf("HTTPRoute %s rule %d has no backendRefs.", routeName, ruleIndex+1), fmt.Sprintf("HTTPRoute %s rule %d has no backendRefs, so matching traffic will not be sent to a Service backend.", routeName, ruleIndex+1))
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
			s.scanHTTPRouteBackendRef(ctx, client, route, ruleIndex+1, backendIndex+1, backend, refGrants, serviceCache, serviceErrCache, endpointReadyCache, endpointErrCache)
		}
	}
}

func (s *gatewayScanner) scanHTTPRouteBackendRef(ctx context.Context, client *kube.Client, route unstructured.Unstructured, ruleNumber, backendNumber int, backend map[string]interface{}, refGrants []unstructured.Unstructured, serviceCache map[string]*corev1.Service, serviceErrCache map[string]error, endpointReadyCache map[string]int, endpointErrCache map[string]error) {
	if gatewayBackendRefWeight(backend) == 0 {
		return
	}
	s.scanHTTPRouteBackendRefWithDiagnosis(ctx, client, route, ruleNumber, backendNumber, backend, refGrants, serviceCache, serviceErrCache, endpointReadyCache, endpointErrCache, true)
}

func (s *gatewayScanner) scanHTTPRouteBackendRefWithDiagnosis(ctx context.Context, client *kube.Client, route unstructured.Unstructured, ruleNumber, backendNumber int, backend map[string]interface{}, refGrants []unstructured.Unstructured, serviceCache map[string]*corev1.Service, serviceErrCache map[string]error, endpointReadyCache map[string]int, endpointErrCache map[string]error, addDiagnosis bool) {
	if gatewayBackendRefWeight(backend) == 0 {
		return
	}
	routeName := objectRefText(route)
	name := stringField(backend, "name")
	if name == "" {
		s.addProblem("BackendRef Layer", fmt.Sprintf("%s rule %d backend %d", routeName, ruleNumber, backendNumber), model.StatusFail, fmt.Sprintf("HTTPRoute %s rule %d backendRef %d has no name.", routeName, ruleNumber, backendNumber), gatewayOptionalDiagnosis(addDiagnosis, fmt.Sprintf("HTTPRoute %s rule %d has a backendRef with no name.", routeName, ruleNumber)))
		return
	}
	group := stringField(backend, "group")
	kind := defaultString(stringField(backend, "kind"), "Service")
	namespace := defaultString(stringField(backend, "namespace"), route.GetNamespace())
	port, portOK := int32Field(backend, "port")
	backendText := fmt.Sprintf("%s/%s", namespace, name)
	check := fmt.Sprintf("%s rule %d backend %d %s", routeName, ruleNumber, backendNumber, backendText)
	if group != "" || kind != "Service" {
		message := fmt.Sprintf("HTTPRoute %s rule %d routes to backend kind %s %s; KNM does not evaluate that backend type.", routeName, ruleNumber, gatewayBackendKindText(group, kind), backendText)
		s.addProblem("BackendRef Layer", check, model.StatusWarn, message, gatewayOptionalDiagnosis(addDiagnosis, message))
		return
	}
	if namespace != route.GetNamespace() && !referenceGrantAllows(refGrants, gatewayv1.GroupName, "HTTPRoute", route.GetNamespace(), "", "Service", name, namespace) {
		s.addProblem("BackendRef Layer", check, model.StatusFail, fmt.Sprintf("HTTPRoute %s rule %d references cross-namespace Service %s without a matching ReferenceGrant.", routeName, ruleNumber, backendText), gatewayOptionalDiagnosis(addDiagnosis, fmt.Sprintf("HTTPRoute %s rule %d routes to Service %s across namespaces, but namespace %q does not grant that reference.", routeName, ruleNumber, backendText, namespace)))
		return
	}
	if !portOK {
		s.addProblem("BackendRef Layer", check, model.StatusFail, fmt.Sprintf("HTTPRoute %s rule %d backendRef %s has no numeric port.", routeName, ruleNumber, backendText), gatewayOptionalDiagnosis(addDiagnosis, fmt.Sprintf("HTTPRoute %s backendRef %s does not specify a Service port.", routeName, backendText)))
		return
	}
	service, err := cachedService(ctx, client, namespace, name, serviceCache, serviceErrCache)
	if err != nil {
		s.addProblem("BackendRef Layer", check, model.StatusFail, fmt.Sprintf("HTTPRoute %s rule %d backendRef points at missing/unreadable Service %s: %v", routeName, ruleNumber, backendText, err), gatewayOptionalDiagnosis(addDiagnosis, fmt.Sprintf("HTTPRoute %s rule %d routes to Service %s, but that Service is missing or unreadable.", routeName, ruleNumber, backendText)))
		return
	}
	if !serviceHasGatewayPort(service, port) {
		s.addProblem("BackendRef Layer", check+" port", model.StatusFail, fmt.Sprintf("HTTPRoute %s rule %d backendRef uses Service %s port %d, but that port is not exposed. Service ports: %s", routeName, ruleNumber, backendText, port, servicePorts(service)), gatewayOptionalDiagnosis(addDiagnosis, fmt.Sprintf("HTTPRoute %s rule %d routes to Service %s port %d, but the Service exposes %s.", routeName, ruleNumber, backendText, port, servicePorts(service))))
		return
	}
	if service.Spec.Type == corev1.ServiceTypeExternalName {
		s.addWide("BackendRef Layer", check, model.StatusInfo, fmt.Sprintf("Service %s is ExternalName %q; EndpointSlice backend checks are not applicable.", backendText, service.Spec.ExternalName))
		return
	}
	ready, err := cachedReadyEndpointCount(ctx, client, namespace, name, endpointReadyCache, endpointErrCache)
	if err != nil {
		s.addProblem("Backend Endpoint Layer", check, model.StatusWarn, fmt.Sprintf("Could not read EndpointSlices for Service %s: %v", backendText, err), "")
		return
	}
	if ready == 0 {
		weight := gatewayBackendRefWeight(backend)
		weightText := ""
		if weight > 0 {
			weightText = fmt.Sprintf(" weight %d", weight)
		}
		s.addProblem("Backend Endpoint Layer", check, model.StatusFail, fmt.Sprintf("HTTPRoute %s rule %d backendRef%s points at Service %s port %d, but the Service has no ready EndpointSlice addresses.", routeName, ruleNumber, weightText, backendText, port), gatewayOptionalDiagnosis(addDiagnosis, fmt.Sprintf("HTTPRoute %s rule %d routes to Service %s port %d, but that Service has no ready endpoints.", routeName, ruleNumber, backendText, port)))
	}
}

func gatewayOptionalDiagnosis(enabled bool, diagnosis string) string {
	if !enabled {
		return ""
	}
	return diagnosis
}

func (s *gatewayScanner) scanGatewayTrafficIntent(ctx context.Context, client *kube.Client, gateways []unstructured.Unstructured, parentGateways []unstructured.Unstructured, routes []unstructured.Unstructured, refGrants []unstructured.Unstructured, serviceCache map[string]*corev1.Service, serviceErrCache map[string]error, endpointReadyCache map[string]int, endpointErrCache map[string]error, intent gatewayTrafficIntent) {
	scopedGateways := s.gatewayTrafficScopedGateways(gateways)
	scopedParentGateways := s.gatewayTrafficScopedGateways(parentGateways)
	scopedRoutes := s.gatewayTrafficScopedRoutes(routes)
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
		if redirect := gatewayFirstRedirectRule(defaultGatewayRuleMatches(selectedRules, ruleMatches)); redirect != nil {
			message := fmt.Sprintf("HTTPRoute %s/%s rule %d redirects this request instead of routing to backendRefs.", redirect.RouteNamespace, redirect.RouteName, redirect.RuleNumber)
			s.addProblem("Gateway Traffic Intent", "redirect", model.StatusFail, message, message)
			return
		}
		reason := gatewayExplainNoTrafficMatch(scopedParentGateways, scopedRoutes, intent)
		s.addProblem("Gateway Traffic Intent", "route match", model.StatusFail, reason.Message, reason.Diagnosis)
		return
	}
	s.addGatewayExpectedServiceCheck(matches)
	routeIndex := map[string]unstructured.Unstructured{}
	for _, route := range scopedRoutes {
		routeIndex[objectRefText(route)] = route
	}
	s.addGatewaySelectedRuleFilterDetails(ctx, client, routeIndex, selectedRules, refGrants, serviceCache, serviceErrCache, endpointReadyCache, endpointErrCache, intent)
	reported := map[string]bool{}
	backendAnalyses := map[string]gatewayBackendRefAnalysis{}
	groupAnalyses := map[string][]gatewayBackendRefAnalysis{}
	for _, match := range matches {
		check := fmt.Sprintf("%s/%s -> %s rule %d backend %d", match.GatewayNamespace, match.GatewayName, match.RouteNamespace+"/"+match.RouteName, match.RuleNumber, match.BackendNumber)
		backendText := fmt.Sprintf("%s/%s:%d", match.BackendNamespace, match.BackendName, match.BackendPort)
		s.report.Add("Gateway Traffic Path", check, model.StatusInfo, fmt.Sprintf("%s matches listener %s/%s/%s and HTTPRoute %s/%s rule %d (%s), backend %s weight %d.", intentText, match.GatewayNamespace, match.GatewayName, match.ListenerName, match.RouteNamespace, match.RouteName, match.RuleNumber, match.MatchSummary, backendText, match.BackendWeight))
		route := routeIndex[match.RouteNamespace+"/"+match.RouteName]
		backend, ok := gatewayHTTPRouteBackendRefAt(route, match.RuleNumber, match.BackendNumber)
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
		backend, ok := gatewayHTTPRouteBackendRefAt(route, match.RuleNumber, match.BackendNumber)
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
		s.scanHTTPRouteBackendRefWithDiagnosis(ctx, client, route, match.RuleNumber, match.BackendNumber, backend, refGrants, serviceCache, serviceErrCache, endpointReadyCache, endpointErrCache, !weightedGroups[analysis.GroupKey])
	}
	for _, group := range gatewaySortedWeightedGroups(weightedGroups) {
		analyses := groupAnalyses[group]
		message := gatewayWeightedBackendMessage(analyses)
		if message == "" {
			continue
		}
		s.report.Add("Gateway Traffic Path", analyses[0].RouteName+" rule "+strconv.Itoa(analyses[0].RuleNumber)+" weighted backendRefs", model.StatusWarn, message)
		s.report.Diagnose(message)
	}
	if s.report.CountByStatus(model.StatusFail) == 0 && s.report.CountByStatus(model.StatusWarn) == 0 {
		s.report.Add("Gateway Traffic Path", "matched backends", model.StatusPass, fmt.Sprintf("%d matching backend path(s) found for %s, and no obvious backend reference or endpoint problems were detected.", len(matches), intentText))
	}
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
				s.report.Add("Gateway Traffic Path", ruleRef+" mirror "+strconv.Itoa(mirrorIndex+1), model.StatusWarn, message)
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
			s.report.Add("Gateway Traffic TLS", check, model.StatusWarn, fmt.Sprintf("Matched HTTPS listener %s certificateRef %s/%s is %s/%s; KNM only validates core Secret refs right now.", checkPrefix, namespace, name, group, kind))
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
			s.report.Add("Gateway Traffic Path", key+" filters", model.StatusInfo, fmt.Sprintf("HTTPRoute %s applies filter(s): %s.", key, filters))
		}
	}
	sort.Strings(ruleRefs)
	if len(ruleRefs) > 1 {
		s.report.Add("Gateway Traffic Path", "multiple matching rules", model.StatusInfo, fmt.Sprintf("Request matches multiple HTTPRoute rules: %s.", strings.Join(ruleRefs, ", ")))
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
			return "older HTTPRoute creation timestamp"
		}
		if selectedRoute < otherRoute {
			return "alphabetical HTTPRoute tie-breaker"
		}
		return ""
	}
	if selected.RuleNumber < other.RuleNumber {
		return "first matching rule in the HTTPRoute"
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
	if len(listenerNames) == 0 {
		s.report.Add("Gateway Traffic Scope", "matching listeners", model.StatusInfo, fmt.Sprintf("No Gateway listeners in scope matched %s.", gatewayTrafficIntentText(intent)))
		return
	}
	s.report.Add("Gateway Traffic Scope", "matching listeners", model.StatusInfo, fmt.Sprintf("Matched listener(s): %s.", strings.Join(listenerNames, ", ")))
	if len(routeNames) == 0 {
		s.report.Add("Gateway Traffic Scope", "attached routes", model.StatusInfo, "No HTTPRoute objects in scope attach to the matched listener(s).")
		return
	}
	s.report.Add("Gateway Traffic Scope", "attached routes", model.StatusInfo, fmt.Sprintf("Attached HTTPRoute candidate(s): %s.", strings.Join(routeNames, ", ")))
}

type gatewayBackendRefAnalysis struct {
	Key           string
	GroupKey      string
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
	if namespace != route.GetNamespace() && !referenceGrantAllows(refGrants, gatewayv1.GroupName, "HTTPRoute", route.GetNamespace(), "", "Service", name, namespace) {
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
	return fmt.Sprintf("HTTPRoute %s rule %d splits this request across weighted backendRefs; %s: %s.", analyses[0].RouteName, analyses[0].RuleNumber, label, strings.Join(broken, "; "))
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

func gatewayHTTPRouteBackendRefAt(route unstructured.Unstructured, ruleNumber, backendNumber int) (map[string]interface{}, bool) {
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
	parts = append(parts, "path="+defaultString(intent.Path, "/"))
	if intent.Method != "" {
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
	if len(gateways) == 0 {
		return gatewayNoMatchReason{
			Message:   fmt.Sprintf("No Gateway objects were in scope for %s.", intentText),
			Diagnosis: fmt.Sprintf("No Gateway objects were in scope for %s. Remove or adjust --gateway, --gateway-class, or --namespace scope filters.", intentText),
		}
	}
	listeners := gatewayTrafficMatchingListeners(gateways, intent)
	if len(listeners) == 0 {
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
			Message:   fmt.Sprintf("Gateway listener(s) matched %s, but no HTTPRoute in scope attaches to those listener(s). Matched listener(s): %s.", intentText, listenerText),
			Diagnosis: fmt.Sprintf("Gateway listener(s) matched %s, but no HTTPRoute attaches to them.", intentText),
		}
	}
	hostRoutes := gatewayTrafficHostnameRoutes(attachedRoutes, intent.Host)
	if len(hostRoutes) == 0 {
		suggestion := gatewayClosestHostnameSuffix(intent.Host, gatewayRouteHostnames(attachedRoutes), "route")
		return gatewayNoMatchReason{
			Message:   fmt.Sprintf("Gateway listener matched, but no attached HTTPRoute has a hostname matching %q.%s", intent.Host, suggestion),
			Diagnosis: fmt.Sprintf("Gateway listener matched, but no attached HTTPRoute has a hostname matching %q.%s", intent.Host, suggestion),
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
		if gatewayHTTPRouteHostnameMatches(route, host) {
			out = append(out, route)
		}
	}
	return out
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
	Scheme  string
	Host    string
	Port    int32
	Path    string
	Method  string
	Headers map[string]string
	Query   map[string][]string
}

type gatewayPathMatch struct {
	GatewayNamespace string
	GatewayName      string
	ListenerName     string
	ListenerHostname string
	ListenerPort     int32
	ListenerProtocol string
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
	if intent.Path == "" {
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
				if !gatewayHTTPRouteHostnameMatches(route, intent.Host) {
					continue
				}
				rules := sliceField(route.Object, "spec", "rules")
				for ruleIndex, rawRule := range rules {
					rule, ok := rawRule.(map[string]interface{})
					if !ok || !gatewayHTTPRouteRuleMatches(rule, intent) {
						continue
					}
					matches = append(matches, gatewayRuleMatch{
						GatewayNamespace: gateway.GetNamespace(),
						GatewayName:      gateway.GetName(),
						ListenerName:     listenerName,
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
	matchScore, ok := gatewayBestHTTPMatchPrecedenceScore(rule, intent)
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

func gatewayFindCandidatePaths(gateways []unstructured.Unstructured, routes []unstructured.Unstructured, intent gatewayTrafficIntent) []gatewayPathMatch {
	if intent.Path == "" {
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
				if !gatewayHTTPRouteHostnameMatches(route, intent.Host) {
					continue
				}
				rules := sliceField(route.Object, "spec", "rules")
				for ruleIndex, rawRule := range rules {
					rule, ok := rawRule.(map[string]interface{})
					if !ok || !gatewayHTTPRouteRuleMatches(rule, intent) {
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
							RouteNamespace:   route.GetNamespace(),
							RouteName:        route.GetName(),
							RuleNumber:       ruleIndex + 1,
							BackendNumber:    backendIndex + 1,
							BackendNamespace: backendNamespace,
							BackendName:      backendName,
							BackendPort:      backendPort,
							BackendWeight:    gatewayBackendRefWeight(backend),
							MatchSummary:     gatewayHTTPRouteRuleMatchSummary(rule),
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
	if !gatewayProtocolMatches(intent.Scheme, stringField(listener, "protocol")) {
		return false
	}
	if !gatewayListenerPortMatches(intent.Port, int32FieldDefault(listener, "port", 0)) {
		return false
	}
	return gatewayHostnameMatches(stringField(listener, "hostname"), intent.Host)
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

func gatewayParentsForRouteFilter(routes []unstructured.Unstructured, opts GatewayOptions) map[string]bool {
	if opts.RouteRef == "" {
		return nil
	}
	filter := parseGatewayObjectRef(opts.RouteRef, opts.Namespace)
	out := map[string]bool{}
	for _, route := range routes {
		if !gatewayObjectRefMatches(route, filter) {
			continue
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
			out[namespace+"/"+name] = true
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

func stringField(object map[string]interface{}, fields ...string) string {
	value, _, _ := unstructured.NestedString(object, fields...)
	return value
}

func int32Field(object map[string]interface{}, fields ...string) (int32, bool) {
	if value, ok, _ := unstructured.NestedInt64(object, fields...); ok {
		if value > 0 && value <= 65535 {
			return int32(value), true
		}
		return 0, false
	}
	raw, ok, _ := unstructured.NestedString(object, fields...)
	if !ok {
		return 0, false
	}
	parsed, err := strconv.Atoi(raw)
	if err != nil || parsed <= 0 || parsed > 65535 {
		return 0, false
	}
	return int32(parsed), true
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

func sliceField(object map[string]interface{}, fields ...string) []interface{} {
	value, _, _ := unstructured.NestedSlice(object, fields...)
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
