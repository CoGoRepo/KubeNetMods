package check

import (
	"context"
	"fmt"
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
	Context      string
	Namespace    string
	GatewayRef   string
	RouteRef     string
	GatewayClass string
	Limit        int
	Wide         bool
	Timeout      time.Duration
}

func RunGateway(ctx context.Context, opts GatewayOptions) (*model.Report, error) {
	if opts.Limit <= 0 {
		opts.Limit = 50
	}
	target := model.Target{
		Context:      opts.Context,
		Namespace:    opts.Namespace,
		GatewayClass: opts.GatewayClass,
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

	runGatewayScan(ctx, client, report, opts)
	if len(report.Diagnoses) == 0 && report.CountByStatus(model.StatusFail) > 0 {
		report.Diagnose("Gateway API scan found failures, but no single dominant diagnosis was inferred yet. Review the failed Gateway, Route, and backend details.")
	}
	report.Limitations = append(report.Limitations,
		"Gateway checks currently perform a static Kubernetes/Gateway API scan; they do not run external probes or inspect provider xDS/dataplane state yet.",
	)
	return report, nil
}

func runGatewayScan(ctx context.Context, client *kube.Client, report *model.Report, opts GatewayOptions) {
	scanner := gatewayScanner{report: report, opts: opts, limit: opts.Limit}
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
	s.report.Add("Gateway API Access", "scan summary", model.StatusInfo, fmt.Sprintf("Scanned %d GatewayClass, %d Gateway, and %d HTTPRoute object(s)%s.", s.scannedClass, s.scannedGate, s.scannedRoutes, filterText))
	if s.problemCount == 0 {
		s.report.Add("Gateway API Scan", "obvious problems", model.StatusPass, "No obvious Gateway API status, attachment, reference, or backend endpoint problems found.")
	}
	if s.truncated {
		s.report.Add("Gateway API Scan", "limit", model.StatusWarn, fmt.Sprintf("Scan found more than %d problem detail(s). Re-run with --limit %d or narrower filters for the full list.", s.limit, s.limit*2))
	}
	if classCount == 0 && gatewayCount == 0 && routeCount == 0 {
		s.report.Add("Gateway API Scan", "objects", model.StatusInfo, "Gateway API v1 is available, but no GatewayClass, Gateway, or HTTPRoute objects matched the scan scope.")
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
			s.scanHTTPRouteBackendRef(ctx, client, route, ruleIndex+1, backendIndex+1, backend, refGrants, serviceCache, serviceErrCache, endpointReadyCache, endpointErrCache)
		}
	}
}

func (s *gatewayScanner) scanHTTPRouteBackendRef(ctx context.Context, client *kube.Client, route unstructured.Unstructured, ruleNumber, backendNumber int, backend map[string]interface{}, refGrants []unstructured.Unstructured, serviceCache map[string]*corev1.Service, serviceErrCache map[string]error, endpointReadyCache map[string]int, endpointErrCache map[string]error) {
	routeName := objectRefText(route)
	name := stringField(backend, "name")
	if name == "" {
		s.addProblem("BackendRef Layer", fmt.Sprintf("%s rule %d backend %d", routeName, ruleNumber, backendNumber), model.StatusFail, fmt.Sprintf("HTTPRoute %s rule %d backendRef %d has no name.", routeName, ruleNumber, backendNumber), fmt.Sprintf("HTTPRoute %s rule %d has a backendRef with no name.", routeName, ruleNumber))
		return
	}
	group := stringField(backend, "group")
	kind := defaultString(stringField(backend, "kind"), "Service")
	namespace := defaultString(stringField(backend, "namespace"), route.GetNamespace())
	port, portOK := int32Field(backend, "port")
	backendText := fmt.Sprintf("%s/%s", namespace, name)
	check := fmt.Sprintf("%s rule %d backend %d %s", routeName, ruleNumber, backendNumber, backendText)
	if group != "" || kind != "Service" {
		s.addProblem("BackendRef Layer", check, model.StatusWarn, fmt.Sprintf("HTTPRoute %s rule %d backendRef %d points at %s/%s %s. KNM only validates core Service backendRefs right now.", routeName, ruleNumber, backendNumber, group, kind, backendText), "")
		return
	}
	if namespace != route.GetNamespace() && !referenceGrantAllows(refGrants, gatewayv1.GroupName, "HTTPRoute", route.GetNamespace(), "", "Service", name, namespace) {
		s.addProblem("BackendRef Layer", check, model.StatusFail, fmt.Sprintf("HTTPRoute %s rule %d references cross-namespace Service %s without a matching ReferenceGrant.", routeName, ruleNumber, backendText), fmt.Sprintf("HTTPRoute %s routes to Service %s across namespaces, but the Service namespace does not grant that reference.", routeName, backendText))
		return
	}
	if !portOK {
		s.addProblem("BackendRef Layer", check, model.StatusFail, fmt.Sprintf("HTTPRoute %s rule %d backendRef %s has no numeric port.", routeName, ruleNumber, backendText), fmt.Sprintf("HTTPRoute %s backendRef %s does not specify a Service port.", routeName, backendText))
		return
	}
	service, err := cachedService(ctx, client, namespace, name, serviceCache, serviceErrCache)
	if err != nil {
		s.addProblem("BackendRef Layer", check, model.StatusFail, fmt.Sprintf("HTTPRoute %s rule %d backendRef points at missing/unreadable Service %s: %v", routeName, ruleNumber, backendText, err), fmt.Sprintf("HTTPRoute %s routes to Service %s, but that Service is missing or unreadable.", routeName, backendText))
		return
	}
	if !serviceHasGatewayPort(service, port) {
		s.addProblem("BackendRef Layer", check+" port", model.StatusFail, fmt.Sprintf("HTTPRoute %s rule %d backendRef uses Service %s port %d, but that port is not exposed. Service ports: %s", routeName, ruleNumber, backendText, port, servicePorts(service)), fmt.Sprintf("HTTPRoute %s routes to Service %s port %d, but the Service does not expose that port.", routeName, backendText, port))
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
		weight := int64FieldDefault(backend, "weight", 1)
		weightText := ""
		if weight > 0 {
			weightText = fmt.Sprintf(" weight %d", weight)
		}
		s.addProblem("Backend Endpoint Layer", check, model.StatusFail, fmt.Sprintf("HTTPRoute %s rule %d backendRef%s points at Service %s port %d, but the Service has no ready EndpointSlice addresses.", routeName, ruleNumber, weightText, backendText, port), fmt.Sprintf("HTTPRoute %s routes to Service %s port %d, but that Service has no ready endpoints.", routeName, backendText, port))
	}
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
							BackendWeight:    int64FieldDefault(backend, "weight", 1),
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
