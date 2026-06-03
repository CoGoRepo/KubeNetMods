package check

import (
	"context"
	"fmt"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/CoGoRepo/KubeNetMods/internal/kube"
	"github.com/CoGoRepo/KubeNetMods/internal/model"
	networkingapi "istio.io/api/networking/v1alpha3"
	securityapi "istio.io/api/security/v1beta1"
	networkingv1 "istio.io/client-go/pkg/apis/networking/v1"
	corev1 "k8s.io/api/core/v1"
	"k8s.io/apimachinery/pkg/labels"
)

func inspectIstioTrafficRouting(ctx context.Context, client *kube.Client, report *model.Report, opts ServiceOptions, service *corev1.Service, targetPods []corev1.Pod, source *ExecTarget, rawURL string) {
	if client.Istio == nil {
		return
	}
	if hasTargetBackendDiagnosis(report) {
		return
	}
	namespaces := istioConfigNamespaces(opts, source)
	virtualServices, err := listIstioVirtualServices(ctx, client, namespaces)
	if err != nil {
		addIstioListWarning(report, "Istio Traffic Routing Layer", "virtual services", err)
		return
	}
	virtualServices = istioServicePathVirtualServices(virtualServices, opts, source)
	destinationRules, err := listIstioDestinationRules(ctx, client, namespaces)
	if err != nil {
		addIstioListWarning(report, "Istio Traffic Routing Layer", "destination rules", err)
		return
	}
	destinationRules = istioServicePathDestinationRules(destinationRules, opts, source)
	for _, vs := range virtualServices {
		if !istioVirtualServiceHostsService(vs, service) {
			continue
		}
		request := newIstioHTTPRequest(opts, service, source, rawURL)
		for _, dest := range istioRouteDestinations(vs, request) {
			if !istioHostMatchesService(dest.Host, vs.Namespace, service) || dest.Subset == "" {
				continue
			}
			dr, ok := findDestinationRule(destinationRules, dest.Host, vs.Namespace, service)
			if !ok {
				continue
			}
			subsetLabels, ok := destinationRuleSubsetLabels(dr, dest.Subset)
			if !ok {
				name := vs.Namespace + "/" + vs.Name
				report.Add("Istio Traffic Routing Layer", name, model.StatusFail, fmt.Sprintf("VirtualService %s %s%s routes Service %q to subset %q, but no matching DestinationRule subset was found.", name, dest.RouteText(), dest.MatchSuffix(), service.Name, dest.Subset))
				report.Diagnose(fmt.Sprintf("Primary issue: Istio VirtualService %q %s%s routes Service %q to subset %q, but the DestinationRule subset is missing.", name, dest.RouteText(), dest.MatchSuffix(), serviceName(service), dest.Subset))
				return
			}
			if readyPodsMatchingLabels(targetPods, subsetLabels) == 0 {
				vsName := vs.Namespace + "/" + vs.Name
				drName := dr.Namespace + "/" + dr.Name
				subsetText := labels.Set(subsetLabels).String()
				observedText := readyPodLabelValuesForKeys(targetPods, subsetLabels)
				message := fmt.Sprintf("VirtualService %s %s%s routes Service %q to DestinationRule %s subset %q%s, but no ready target pods match subset labels %s.", vsName, dest.RouteText(), dest.MatchSuffix(), service.Name, drName, dest.Subset, dest.WeightText(), subsetText)
				diagnosis := fmt.Sprintf("Primary issue: Istio VirtualService %q %s%s routes Service %q to DestinationRule %q subset %q%s, but no ready backend pods match labels %s.", vsName, dest.RouteText(), dest.MatchSuffix(), serviceName(service), drName, dest.Subset, dest.WeightText(), subsetText)
				if observedText != "" {
					message += " Ready backend pod label values for those keys: " + observedText + "."
					diagnosis += " Ready backend pod label values for those keys: " + observedText + "."
				}
				report.Add("Istio Traffic Routing Layer", vsName, model.StatusFail, message)
				report.Diagnose(diagnosis)
				return
			}
		}
	}
	report.Add("Istio Traffic Routing Layer", "traffic routes", model.StatusWarn, "Envoy returned no healthy upstream, but no matching VirtualService/DestinationRule subset issue was identified by static inspection.")
	report.Diagnose(fmt.Sprintf("Primary issue: Envoy returned no healthy upstream for Service %q, but KubeNetMods could not identify the exact Istio route/subset object.", serviceName(service)))
}

func inspectIstioWeightedRouteRisks(ctx context.Context, client *kube.Client, report *model.Report, opts ServiceOptions, service *corev1.Service, targetPods []corev1.Pod, source *ExecTarget, rawURL string) bool {
	if client.Istio == nil || service == nil || rawURL == "" {
		return false
	}
	if hasTargetBackendDiagnosis(report) {
		return false
	}
	namespaces := istioConfigNamespaces(opts, source)
	virtualServices, err := listIstioVirtualServices(ctx, client, namespaces)
	if err != nil {
		addIstioListWarning(report, "Istio Traffic Routing Layer", "virtual services", err)
		return false
	}
	virtualServices = istioServicePathVirtualServices(virtualServices, opts, source)
	destinationRules, err := listIstioDestinationRules(ctx, client, namespaces)
	if err != nil {
		addIstioListWarning(report, "Istio Traffic Routing Layer", "destination rules", err)
		return false
	}
	destinationRules = istioServicePathDestinationRules(destinationRules, opts, source)
	peerAuth := effectivePeerAuthenticationForPods(ctx, client, service, opts.ServicePort, targetPods)
	request := newIstioHTTPRequest(opts, service, source, rawURL)
	for _, vs := range virtualServices {
		if !istioVirtualServiceHostsService(vs, service) {
			continue
		}
		routeGroups := istioRouteDestinationGroups(vs, request)
		for _, routeDests := range routeGroups {
			if len(routeDests) < 2 {
				continue
			}
			good, bad := classifyIstioWeightedDestinations(routeDests, vs, destinationRules, service, targetPods, peerAuth, report.Target.ServicePort)
			if len(good) == 0 || len(bad) == 0 {
				continue
			}
			vsName := vs.Namespace + "/" + vs.Name
			first := routeDests[0]
			report.Add("Istio Traffic Routing Layer", vsName+" weighted destinations", model.StatusWarn, fmt.Sprintf("VirtualService %s %s%s splits traffic across weighted destinations. Healthy destination(s): %s. Risky destination(s): %s.", vsName, first.RouteText(), first.MatchSuffix(), strings.Join(good, "; "), strings.Join(bad, "; ")))
			report.Diagnose(fmt.Sprintf("Primary issue candidate: Istio VirtualService %q %s%s splits traffic across weighted destinations, and %s. This can cause intermittent 503 responses even when some probes pass through healthy destination(s): %s.", vsName, first.RouteText(), first.MatchSuffix(), strings.Join(bad, "; "), strings.Join(good, "; ")))
			return true
		}
	}
	return false
}

type istioIntentionalRouteBehavior struct {
	ID             string
	RuntimeStatus  model.Status
	RuntimeMessage string
	LayerCheck     string
	LayerStatus    model.Status
	LayerMessage   string
	Diagnosis      string
}

func inspectIstioIntentionalRouteBehavior(ctx context.Context, client *kube.Client, report *model.Report, opts ServiceOptions, service *corev1.Service, source *ExecTarget, rawURL string, result RuntimeHTTPResult, reported map[string]bool) (istioIntentionalRouteBehavior, bool) {
	if client.Istio == nil || service == nil || rawURL == "" {
		return istioIntentionalRouteBehavior{}, false
	}
	virtualServices, err := listIstioVirtualServices(ctx, client, istioConfigNamespaces(opts, source))
	if err != nil {
		addIstioListWarning(report, "Istio Traffic Routing Layer", "virtual services", err)
		return istioIntentionalRouteBehavior{}, false
	}
	virtualServices = istioServicePathVirtualServices(virtualServices, opts, source)
	request := newIstioHTTPRequest(opts, service, source, rawURL)
	for _, vs := range virtualServices {
		if !istioVirtualServiceHostsService(vs, service) {
			continue
		}
		for index, route := range vs.Spec.GetHttp() {
			matchText, ok := istioHTTPRouteMatchText(route, request)
			if !ok {
				continue
			}
			behavior, ok := istioIntentionalRouteBehaviorForResult(vs, route, index+1, matchText, service, result)
			if !ok {
				continue
			}
			if !reported[behavior.ID] {
				report.Add("Istio Traffic Routing Layer", behavior.LayerCheck, behavior.LayerStatus, behavior.LayerMessage)
				report.Diagnose(behavior.Diagnosis)
				reported[behavior.ID] = true
			}
			return behavior, true
		}
	}
	return istioIntentionalRouteBehavior{}, false
}

func istioIntentionalRouteBehaviorForResult(vs *networkingv1.VirtualService, route *networkingapi.HTTPRoute, routeNum int, matchText string, service *corev1.Service, result RuntimeHTTPResult) (istioIntentionalRouteBehavior, bool) {
	routeText := istioRouteDestination{RouteName: route.GetName(), RouteNum: routeNum, MatchText: matchText}.RouteText()
	matchSuffix := istioRouteDestination{MatchText: matchText}.MatchSuffix()
	vsName := vs.Namespace + "/" + vs.Name
	statusCode := runtimeStatusCode(result)
	check := vsName + " " + routeText
	if route.GetDirectResponse() != nil {
		status := int(route.GetDirectResponse().GetStatus())
		if status == 0 || statusCode != status || status < 400 {
			return istioIntentionalRouteBehavior{}, false
		}
		return istioIntentionalRouteBehavior{
			ID:             "direct-response|" + check,
			RuntimeStatus:  model.StatusFail,
			RuntimeMessage: fmt.Sprintf("Envoy returned HTTP %d from VirtualService direct response %s.", status, check),
			LayerCheck:     check,
			LayerStatus:    model.StatusFail,
			LayerMessage:   fmt.Sprintf("VirtualService %s %s%s returns a direct HTTP %d response for Service %q.", vsName, routeText, matchSuffix, status, service.Name),
			Diagnosis:      fmt.Sprintf("Primary issue: Istio VirtualService %q %s%s directly returns HTTP %d for Service %q instead of routing to backend pods.", vsName, routeText, matchSuffix, status, serviceName(service)),
		}, true
	}
	if route.GetRedirect() != nil {
		redirect := route.GetRedirect()
		configured := int(redirect.GetRedirectCode())
		if configured == 0 {
			configured = 301
		}
		if statusCode < 300 || statusCode > 399 {
			return istioIntentionalRouteBehavior{}, false
		}
		statusText := fmt.Sprintf("HTTP %d", configured)
		if configured != statusCode {
			statusText = fmt.Sprintf("HTTP %d observed, redirect config defaults/sets HTTP %d", statusCode, configured)
		}
		return istioIntentionalRouteBehavior{
			ID:             "redirect|" + check,
			RuntimeStatus:  model.StatusWarn,
			RuntimeMessage: fmt.Sprintf("Envoy returned redirect %s from VirtualService %s.", statusText, check),
			LayerCheck:     check,
			LayerStatus:    model.StatusWarn,
			LayerMessage:   fmt.Sprintf("VirtualService %s %s%s redirects matching requests for Service %q. Observed %s.", vsName, routeText, matchSuffix, service.Name, statusText),
			Diagnosis:      fmt.Sprintf("Primary issue candidate: Istio VirtualService %q %s%s redirects requests for Service %q. The request is reaching Envoy, but the route intentionally sends a redirect instead of backend traffic.", vsName, routeText, matchSuffix, serviceName(service)),
		}, true
	}
	fault := route.GetFault()
	if fault == nil {
		return istioIntentionalRouteBehavior{}, false
	}
	if abort := fault.GetAbort(); abort != nil {
		status := int(abort.GetHttpStatus())
		percent := istioPercentValue(abort.GetPercentage(), 0)
		if status > 0 && percent > 0 {
			percentText := istioPercentText(percent)
			if statusCode == status {
				prefix := "Primary issue"
				layerStatus := model.StatusFail
				if percent < 100 {
					prefix = "Primary issue candidate"
					layerStatus = model.StatusWarn
				}
				return istioIntentionalRouteBehavior{
					ID:             "fault-abort|" + check,
					RuntimeStatus:  model.StatusFail,
					RuntimeMessage: fmt.Sprintf("Envoy returned HTTP %d from VirtualService fault abort %s.", status, check),
					LayerCheck:     check,
					LayerStatus:    layerStatus,
					LayerMessage:   fmt.Sprintf("VirtualService %s %s%s aborts %s of matching requests for Service %q with HTTP %d.", vsName, routeText, matchSuffix, percentText, service.Name, status),
					Diagnosis:      fmt.Sprintf("%s: Istio VirtualService %q %s%s intentionally aborts %s of requests to Service %q with HTTP %d.", prefix, vsName, routeText, matchSuffix, percentText, serviceName(service), status),
				}, true
			}
			if result.OK && percent < 100 {
				return istioIntentionalRouteBehavior{
					ID:             "fault-abort-risk|" + check,
					RuntimeStatus:  model.StatusWarn,
					RuntimeMessage: fmt.Sprintf("This probe reached the Service, but VirtualService %s fault-aborts %s of matching requests with HTTP %d.", check, percentText, status),
					LayerCheck:     check,
					LayerStatus:    model.StatusWarn,
					LayerMessage:   fmt.Sprintf("VirtualService %s %s%s aborts %s of matching requests for Service %q with HTTP %d. This can cause intermittent failures even when one probe succeeds.", vsName, routeText, matchSuffix, percentText, service.Name, status),
					Diagnosis:      fmt.Sprintf("Primary issue candidate: Istio VirtualService %q %s%s fault-aborts %s of requests to Service %q with HTTP %d. This can make the path fail intermittently.", vsName, routeText, matchSuffix, percentText, serviceName(service), status),
				}, true
			}
		}
	}
	if delay := fault.GetDelay(); delay != nil {
		percent := istioPercentValue(delay.GetPercentage(), delay.GetPercent())
		if percent <= 0 {
			return istioIntentionalRouteBehavior{}, false
		}
		delayText := istioDelayText(delay)
		if result.OK && percent < 100 {
			return istioIntentionalRouteBehavior{
				ID:             "fault-delay-risk|" + check,
				RuntimeStatus:  model.StatusWarn,
				RuntimeMessage: fmt.Sprintf("This probe reached the Service, but VirtualService %s delays %s of matching requests by %s.", check, istioPercentText(percent), delayText),
				LayerCheck:     check,
				LayerStatus:    model.StatusWarn,
				LayerMessage:   fmt.Sprintf("VirtualService %s %s%s delays %s of matching requests for Service %q by %s. This can cause intermittent slow requests or client timeouts.", vsName, routeText, matchSuffix, istioPercentText(percent), service.Name, delayText),
				Diagnosis:      fmt.Sprintf("Primary issue candidate: Istio VirtualService %q %s%s delays %s of requests to Service %q by %s. This can make the path intermittently slow or timeout.", vsName, routeText, matchSuffix, istioPercentText(percent), serviceName(service), delayText),
			}, true
		}
		if !result.OK && runtimeLooksLikeTimeout(result) {
			prefix := "Primary issue"
			layerStatus := model.StatusFail
			if percent < 100 {
				prefix = "Primary issue candidate"
				layerStatus = model.StatusWarn
			}
			return istioIntentionalRouteBehavior{
				ID:             "fault-delay|" + check,
				RuntimeStatus:  model.StatusFail,
				RuntimeMessage: fmt.Sprintf("Probe timed out and VirtualService %s delays %s of matching requests by %s.", check, istioPercentText(percent), delayText),
				LayerCheck:     check,
				LayerStatus:    layerStatus,
				LayerMessage:   fmt.Sprintf("VirtualService %s %s%s delays %s of matching requests for Service %q by %s.", vsName, routeText, matchSuffix, istioPercentText(percent), service.Name, delayText),
				Diagnosis:      fmt.Sprintf("%s: Istio VirtualService %q %s%s delays %s of requests to Service %q by %s, and the runtime probe timed out.", prefix, vsName, routeText, matchSuffix, istioPercentText(percent), serviceName(service), delayText),
			}, true
		}
	}
	return istioIntentionalRouteBehavior{}, false
}

func classifyIstioWeightedDestinations(routeDests []istioRouteDestination, vs *networkingv1.VirtualService, destinationRules []*networkingv1.DestinationRule, service *corev1.Service, targetPods []corev1.Pod, peerAuth effectivePeerAuthentication, servicePort int32) ([]string, []string) {
	var good []string
	var bad []string
	for _, dest := range routeDests {
		if dest.Weight <= 0 || !istioHostMatchesService(dest.Host, vs.Namespace, service) || dest.Subset == "" {
			continue
		}
		dr, ok := findDestinationRule(destinationRules, dest.Host, vs.Namespace, service)
		if !ok {
			bad = append(bad, fmt.Sprintf("subset %q with weight %d has no matching DestinationRule", dest.Subset, dest.Weight))
			continue
		}
		subsetLabels, ok := destinationRuleSubsetLabels(dr, dest.Subset)
		if !ok {
			bad = append(bad, fmt.Sprintf("subset %q with weight %d is missing from DestinationRule %q", dest.Subset, dest.Weight, dr.Namespace+"/"+dr.Name))
			continue
		}
		if peerAuth.Mode == securityapi.PeerAuthentication_MutualTLS_STRICT {
			if tlsMode, ok := destinationRuleTLSModeForSubset(dr, dest.Subset, servicePort); ok && tlsMode != networkingapi.ClientTLSSettings_ISTIO_MUTUAL {
				bad = append(bad, fmt.Sprintf("subset %q with weight %d sets DestinationRule %q TLS mode %s while target mTLS is STRICT", dest.Subset, dest.Weight, dr.Namespace+"/"+dr.Name, tlsMode.String()))
				continue
			}
		}
		subsetText := labels.Set(subsetLabels).String()
		if readyPodsMatchingLabels(targetPods, subsetLabels) == 0 {
			text := fmt.Sprintf("subset %q with weight %d has no ready pods matching %s", dest.Subset, dest.Weight, subsetText)
			if observedText := readyPodLabelValuesForKeys(targetPods, subsetLabels); observedText != "" {
				text += " (ready pod values: " + observedText + ")"
			}
			bad = append(bad, text)
			continue
		}
		good = append(good, fmt.Sprintf("subset %q with weight %d matches ready pods with %s", dest.Subset, dest.Weight, subsetText))
	}
	sort.Strings(good)
	sort.Strings(bad)
	return good, bad
}

type istioRouteDestination struct {
	Host      string
	Subset    string
	RouteName string
	RouteNum  int
	Weight    int32
	MatchText string
}

func (dest istioRouteDestination) RouteText() string {
	if dest.RouteName != "" {
		return fmt.Sprintf("HTTP route %d (%q)", dest.RouteNum, dest.RouteName)
	}
	if dest.RouteNum > 0 {
		return fmt.Sprintf("HTTP route %d", dest.RouteNum)
	}
	return "HTTP route"
}

func (dest istioRouteDestination) WeightText() string {
	if dest.Weight <= 0 {
		return ""
	}
	return fmt.Sprintf(" with weight %d", dest.Weight)
}

func (dest istioRouteDestination) MatchSuffix() string {
	if dest.MatchText == "" {
		return ""
	}
	return " matched by " + dest.MatchText
}

func istioRouteDestinations(vs *networkingv1.VirtualService, request istioHTTPRequest) []istioRouteDestination {
	var out []istioRouteDestination
	for _, routeDests := range istioRouteDestinationGroups(vs, request) {
		out = append(out, routeDests...)
	}
	return out
}

func istioRouteDestinationGroups(vs *networkingv1.VirtualService, request istioHTTPRequest) [][]istioRouteDestination {
	var out [][]istioRouteDestination
	for i, httpRoute := range vs.Spec.GetHttp() {
		matchText, ok := istioHTTPRouteMatchText(httpRoute, request)
		if !ok {
			continue
		}
		var group []istioRouteDestination
		for _, route := range httpRoute.GetRoute() {
			dest := route.GetDestination()
			host := dest.GetHost()
			if host == "" {
				continue
			}
			group = append(group, istioRouteDestination{
				Host:      host,
				Subset:    dest.GetSubset(),
				RouteName: httpRoute.GetName(),
				RouteNum:  i + 1,
				Weight:    route.GetWeight(),
				MatchText: matchText,
			})
		}
		if len(group) > 0 {
			out = append(out, group)
		}
	}
	return out
}

func istioVirtualServiceHostsService(vs *networkingv1.VirtualService, service *corev1.Service) bool {
	for _, host := range vs.Spec.GetHosts() {
		if istioHostMatchesService(host, vs.Namespace, service) {
			return true
		}
	}
	return false
}

func istioHostMatchesService(host string, configNamespace string, service *corev1.Service) bool {
	if service == nil {
		return false
	}
	host = istioResolveHost(host, configNamespace)
	candidates := istioServiceHosts(service)
	for _, candidate := range candidates {
		if host == candidate {
			return true
		}
	}
	return false
}

func findDestinationRule(items []*networkingv1.DestinationRule, host string, hostNamespace string, service *corev1.Service) (*networkingv1.DestinationRule, bool) {
	resolvedHost := istioResolveHost(host, hostNamespace)
	for _, item := range items {
		drHost := istioResolveHost(item.Spec.GetHost(), item.Namespace)
		if drHost == resolvedHost || istioHostMatchesService(item.Spec.GetHost(), item.Namespace, service) {
			return item, true
		}
	}
	return nil, false
}

func istioResolveHost(host string, configNamespace string) string {
	host = strings.TrimSuffix(strings.ToLower(strings.TrimSpace(host)), ".")
	if host == "" || strings.Contains(host, "*") {
		return host
	}
	if !strings.Contains(host, ".") && configNamespace != "" {
		return host + "." + strings.ToLower(configNamespace) + ".svc.cluster.local"
	}
	if strings.Count(host, ".") == 1 {
		return host + ".svc.cluster.local"
	}
	if strings.HasSuffix(host, ".svc") {
		return host + ".cluster.local"
	}
	return host
}

func istioServiceHosts(service *corev1.Service) []string {
	if service == nil {
		return nil
	}
	name := strings.ToLower(service.Name)
	namespace := strings.ToLower(service.Namespace)
	return []string{
		name + "." + namespace + ".svc.cluster.local",
		name + "." + namespace + ".svc",
		name + "." + namespace,
		name,
	}
}

func destinationRuleSubsetLabels(dr *networkingv1.DestinationRule, subset string) (map[string]string, bool) {
	for _, current := range dr.Spec.GetSubsets() {
		if current.GetName() != subset {
			continue
		}
		return current.GetLabels(), true
	}
	return nil, false
}

func readyPodsMatchingLabels(pods []corev1.Pod, subset map[string]string) int {
	count := 0
	for _, pod := range pods {
		if podReady(pod) && labels.SelectorFromSet(subset).Matches(labels.Set(pod.Labels)) {
			count++
		}
	}
	return count
}

func readyPodLabelValuesForKeys(pods []corev1.Pod, subset map[string]string) string {
	if len(subset) == 0 {
		return ""
	}
	valuesByKey := map[string]map[string]bool{}
	for key := range subset {
		valuesByKey[key] = map[string]bool{}
	}
	for _, pod := range pods {
		if !podReady(pod) {
			continue
		}
		for key := range subset {
			value, ok := pod.Labels[key]
			if !ok {
				value = "(missing)"
			}
			valuesByKey[key][value] = true
		}
	}
	var parts []string
	for key := range subset {
		var values []string
		for value := range valuesByKey[key] {
			values = append(values, value)
		}
		if len(values) == 0 {
			continue
		}
		sort.Strings(values)
		parts = append(parts, key+"="+strings.Join(values, "|"))
	}
	sort.Strings(parts)
	return strings.Join(parts, ", ")
}

func runtimeStatusCode(result RuntimeHTTPResult) int {
	status, err := strconv.Atoi(strings.TrimSpace(result.StatusCode))
	if err != nil {
		return 0
	}
	return status
}

func runtimeLooksLikeTimeout(result RuntimeHTTPResult) bool {
	text := strings.ToLower(result.Error + " " + result.Output)
	return strings.Contains(text, "timed out") ||
		strings.Contains(text, "timeout") ||
		strings.Contains(text, "operation timed out") ||
		strings.Contains(text, "context deadline exceeded")
}

func istioPercentValue(percent *networkingapi.Percent, legacyPercent int32) float64 {
	if percent != nil {
		return percent.GetValue()
	}
	if legacyPercent > 0 {
		return float64(legacyPercent)
	}
	return 0
}

func istioPercentText(percent float64) string {
	if percent == float64(int64(percent)) {
		return fmt.Sprintf("%.0f%%", percent)
	}
	return fmt.Sprintf("%.2f%%", percent)
}

func istioDelayText(delay *networkingapi.HTTPFaultInjection_Delay) string {
	if delay == nil {
		return "an unspecified delay"
	}
	if fixed := delay.GetFixedDelay(); fixed != nil {
		return istioFormatDuration(time.Duration(fixed.Seconds)*time.Second + time.Duration(fixed.Nanos)*time.Nanosecond)
	}
	if exponential := delay.GetExponentialDelay(); exponential != nil {
		return "exponential delay around " + istioFormatDuration(time.Duration(exponential.Seconds)*time.Second+time.Duration(exponential.Nanos)*time.Nanosecond)
	}
	return "an unspecified delay"
}

func istioFormatDuration(value time.Duration) string {
	if value <= 0 {
		return "0s"
	}
	return value.String()
}
