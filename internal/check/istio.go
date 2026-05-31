package check

import (
	"context"
	"fmt"
	"net/url"
	"regexp"
	"sort"
	"strings"

	"github.com/CoGoRepo/KubeNetMods/internal/kube"
	"github.com/CoGoRepo/KubeNetMods/internal/model"
	networkingapi "istio.io/api/networking/v1alpha3"
	securityapi "istio.io/api/security/v1beta1"
	istiotype "istio.io/api/type/v1beta1"
	networkingv1 "istio.io/client-go/pkg/apis/networking/v1"
	securityv1 "istio.io/client-go/pkg/apis/security/v1"
	corev1 "k8s.io/api/core/v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/labels"
	"k8s.io/apimachinery/pkg/util/intstr"
)

type istioRuntimeSignal string

const (
	istioSignalNone              istioRuntimeSignal = ""
	istioSignalRBACDenied        istioRuntimeSignal = "rbac-denied"
	istioSignalJWTDenied         istioRuntimeSignal = "jwt-denied"
	istioSignalNoHealthyUpstream istioRuntimeSignal = "no-healthy-upstream"
	istioSignalUpstreamReset     istioRuntimeSignal = "upstream-reset"
)

func classifyIstioRuntime(result RuntimeHTTPResult, source *ExecTarget, targetPods []corev1.Pod) istioRuntimeSignal {
	text := strings.ToLower(result.Output + " " + result.Error)
	envoy := strings.Contains(text, "server: envoy") || strings.Contains(text, "x-envoy-") || pathHasIstioSidecar(source, targetPods)
	switch {
	case result.StatusCode == "401" && envoy && (strings.Contains(text, "jwt") || strings.Contains(text, "unauthorized")):
		return istioSignalJWTDenied
	case result.StatusCode == "403" && envoy && strings.Contains(text, "rbac: access denied"):
		return istioSignalRBACDenied
	case result.StatusCode == "503" && envoy && strings.Contains(text, "no healthy upstream"):
		return istioSignalNoHealthyUpstream
	case result.StatusCode == "503" && envoy && (strings.Contains(text, "upstream connect error") || strings.Contains(text, "reset before headers") || strings.Contains(text, "connection termination")):
		return istioSignalUpstreamReset
	default:
		return istioSignalNone
	}
}

func pathHasIstioSidecar(source *ExecTarget, targetPods []corev1.Pod) bool {
	if source != nil && podHasIstioSidecar(source.Pod) {
		return true
	}
	for _, pod := range targetPods {
		if podHasIstioSidecar(pod) {
			return true
		}
	}
	return false
}

func podHasIstioSidecar(pod corev1.Pod) bool {
	if _, ok := pod.Annotations["sidecar.istio.io/status"]; ok {
		return true
	}
	for _, container := range pod.Spec.Containers {
		if container.Name == "istio-proxy" {
			return true
		}
	}
	return false
}

func istioRuntimeMessage(source ExecTarget, rawURL string, result RuntimeHTTPResult, signal istioRuntimeSignal) string {
	switch signal {
	case istioSignalRBACDenied:
		return fmt.Sprintf("%s %q reached %s, but Envoy returned HTTP 403 RBAC: access denied.", source.Kind, source.Pod.Name, rawURL)
	case istioSignalJWTDenied:
		return fmt.Sprintf("%s %q reached %s, but Envoy returned HTTP 401 unauthorized.", source.Kind, source.Pod.Name, rawURL)
	case istioSignalNoHealthyUpstream:
		return fmt.Sprintf("%s %q reached %s, but Envoy returned HTTP 503: no healthy upstream.", source.Kind, source.Pod.Name, rawURL)
	case istioSignalUpstreamReset:
		return fmt.Sprintf("%s %q reached %s, but Envoy returned HTTP 503 upstream connect/reset before headers.", source.Kind, source.Pod.Name, rawURL)
	default:
		return fmt.Sprintf("%s %q reached %s. HTTP status: %s", source.Kind, source.Pod.Name, rawURL, result.StatusCode)
	}
}

func inspectIstioRuntimeSignal(ctx context.Context, client *kube.Client, report *model.Report, opts ServiceOptions, service *corev1.Service, targetPods []corev1.Pod, source *ExecTarget, rawURL string, result RuntimeHTTPResult, signal istioRuntimeSignal) {
	if signal == istioSignalNone || service == nil || source == nil {
		return
	}
	switch signal {
	case istioSignalRBACDenied:
		inspectIstioAuthorizationPolicy(ctx, client, report, opts, service, targetPods, source, rawURL)
	case istioSignalJWTDenied:
		inspectIstioRequestAuthentication(ctx, client, report, service, targetPods, model.StatusFail)
	case istioSignalNoHealthyUpstream:
		inspectIstioTrafficRouting(ctx, client, report, opts, service, targetPods, source, rawURL)
	case istioSignalUpstreamReset:
		if !inspectIstioDestinationRuleMTLSMismatch(ctx, client, report, opts, service, targetPods, source, rawURL, result) {
			if !hasIstioDiagnosis(report) {
				report.Add("Istio Upstream Layer", "upstream reset", model.StatusWarn, "Envoy returned 503 upstream connect/reset before headers, but KubeNetMods could not identify a specific Istio TLS or routing object.")
				report.Diagnose(fmt.Sprintf("Primary issue candidate: Envoy returned upstream connect/reset before headers for Service %q. Check DestinationRule TLS settings, PeerAuthentication mTLS mode, upstream workload readiness, and application listener behavior.", serviceName(service)))
			}
		}
	}
}

func inspectIstioMTLSReset(ctx context.Context, client *kube.Client, report *model.Report, service *corev1.Service, servicePort int32, targetPods []corev1.Pod, source *ExecTarget, result RuntimeHTTPResult) bool {
	if client.Istio == nil || service == nil || source == nil || !runtimeLooksLikeConnectionReset(result) || podHasIstioSidecar(source.Pod) {
		return false
	}
	policy := effectivePeerAuthenticationForPods(ctx, client, service, servicePort, targetPods)
	if policy.Mode != securityapi.PeerAuthentication_MutualTLS_STRICT {
		return false
	}
	if reportHasResult(report, "Istio mTLS Layer", policy.Name) {
		return true
	}
	report.Add("Istio mTLS Layer", policy.Name, model.StatusFail, fmt.Sprintf("Target workload for Service %q is under Istio STRICT mTLS for workload port %d via PeerAuthentication %s, but source pod %q is not in the mesh.", service.Name, policy.Port, policy.Name, source.Pod.Name))
	report.Diagnose(fmt.Sprintf("Primary issue: Target workload is under Istio STRICT mTLS for workload port %d, but the source pod %q is not in the mesh. Add the source workload to the mesh or relax PeerAuthentication %q for this path.", policy.Port, source.Pod.Namespace+"/"+source.Pod.Name, policy.Name))
	return true
}

func inspectIstioDestinationRuleMTLSMismatch(ctx context.Context, client *kube.Client, report *model.Report, opts ServiceOptions, service *corev1.Service, targetPods []corev1.Pod, source *ExecTarget, rawURL string, result RuntimeHTTPResult) bool {
	if client.Istio == nil || service == nil || source == nil || !runtimeLooksLikeConnectionReset(result) || !podHasIstioSidecar(source.Pod) {
		return false
	}
	peerAuth := effectivePeerAuthenticationForPods(ctx, client, service, opts.ServicePort, targetPods)
	if peerAuth.Mode != securityapi.PeerAuthentication_MutualTLS_STRICT {
		return false
	}
	destinationRules, err := listIstioDestinationRules(ctx, client, istioConfigNamespaces(opts, source))
	if err != nil {
		return false
	}
	virtualServices, _ := listIstioVirtualServices(ctx, client, istioConfigNamespaces(opts, source))
	tls, ok := effectiveDestinationRuleTLSModeForRequest(virtualServices, destinationRules, opts, service, source, rawURL, report.Target.ServicePort)
	if !ok || tls.Mode == networkingapi.ClientTLSSettings_ISTIO_MUTUAL {
		return false
	}
	drName := tls.DestinationRule
	if reportHasResult(report, "Istio mTLS Layer", drName) {
		return true
	}
	report.Add("Istio mTLS Layer", drName, model.StatusFail, fmt.Sprintf("Target workload for Service %q is under STRICT mTLS for workload port %d via PeerAuthentication %s, but DestinationRule %s sets client TLS mode %s%s.", service.Name, peerAuth.Port, peerAuth.Name, drName, tls.Mode.String(), tls.ScopeText()))
	report.Diagnose(fmt.Sprintf("Primary issue: target workload is under Istio STRICT mTLS for workload port %d via PeerAuthentication %q, but DestinationRule %q sets client TLS mode %s%s for Service %q. Use ISTIO_MUTUAL or remove the conflicting TLS setting for mesh-internal mTLS.", peerAuth.Port, peerAuth.Name, drName, tls.Mode.String(), tls.ScopeText(), serviceName(service)))
	return true
}

func reportHasResult(report *model.Report, layer string, check string) bool {
	for _, result := range report.Results {
		if result.Layer == layer && result.Check == check {
			return true
		}
	}
	return false
}

func inspectIstioSidecarEgressScope(ctx context.Context, client *kube.Client, report *model.Report, service *corev1.Service, source *ExecTarget) bool {
	if client.Istio == nil || service == nil || source == nil || !podHasIstioSidecar(source.Pod) {
		return false
	}
	sidecar, ok := effectiveIstioSidecarForSource(ctx, client, source.Pod)
	if !ok || sidecar == nil || len(sidecar.Spec.GetEgress()) == 0 {
		return false
	}
	if istioSidecarEgressAllowsService(sidecar, service) {
		return false
	}
	name := sidecar.Namespace + "/" + sidecar.Name
	hosts := istioSidecarEgressHosts(sidecar)
	report.Add("Istio Sidecar Scope Layer", name, model.StatusWarn, fmt.Sprintf("Source pod %q is selected by Sidecar %s, but its egress hosts do not include Service %q. Configured hosts: %s.", source.Pod.Name, name, serviceName(service), formatList(hosts)))
	report.Diagnose(fmt.Sprintf("Primary issue candidate: source pod %q is selected by Istio Sidecar %q, but the Sidecar egress hosts do not include Service %q. Istio Sidecar scoping trims outbound config; unmatched traffic may fail or bypass normal service routing depending on mesh outbound policy.", source.Pod.Namespace+"/"+source.Pod.Name, name, serviceName(service)))
	return true
}

func inspectIstioAuthorizationPolicy(ctx context.Context, client *kube.Client, report *model.Report, opts ServiceOptions, service *corev1.Service, targetPods []corev1.Pod, source *ExecTarget, rawURL string) {
	if client.Istio == nil {
		return
	}
	items, err := client.Istio.SecurityV1().AuthorizationPolicies(opts.Namespace).List(ctx, metav1.ListOptions{})
	if err != nil {
		addIstioListWarning(report, "Istio Authorization Layer", "authorization policies", err)
		return
	}
	request := newIstioHTTPRequest(opts, service, source, rawURL)
	matchingCustom := matchingIstioAuthorizationPolicies(items.Items, service, targetPods, securityapi.AuthorizationPolicy_CUSTOM, request)
	for _, item := range items.Items {
		if !istioAuthorizationPolicySelectsTarget(item, service, targetPods) {
			continue
		}
		if item.Spec.GetAction() != securityapi.AuthorizationPolicy_DENY {
			continue
		}
		matchingRules := istioAuthorizationRuleNumbers(item.Spec.GetRules(), item.Namespace, request)
		if len(matchingRules) > 0 {
			name := item.Namespace + "/" + item.Name
			ruleText := formatRuleNumbers(matchingRules)
			report.Add("Istio Authorization Layer", name, model.StatusFail, fmt.Sprintf("AuthorizationPolicy %s denies requests to target pods selected by Service %q via %s.", name, service.Name, ruleText))
			report.Diagnose(fmt.Sprintf("Primary issue: Istio AuthorizationPolicy %q denies requests from source pod %q to Service %q via %s.", name, source.Pod.Name, serviceName(service), ruleText))
			return
		}
	}
	if istioAuthorizationUsesJWT(items.Items, service, targetPods) && inspectIstioRequestAuthentication(ctx, client, report, service, targetPods, model.StatusWarn) {
		return
	}
	if allowText, ok := istioAllowDefaultDeny(items.Items, service, targetPods, request); ok {
		report.Add("Istio Authorization Layer", "allow policies", model.StatusFail, fmt.Sprintf("Target pods selected by Service %q are selected by Istio ALLOW AuthorizationPolicy object(s), but none match this source/request. Policies: %s.", service.Name, allowText))
		report.Diagnose(fmt.Sprintf("Primary issue: Target workload is selected by Istio ALLOW AuthorizationPolicy object(s), but none match source pod %q for Service %q, so Envoy denies the request. Policies: %s.", source.Pod.Name, serviceName(service), allowText))
		return
	}
	if riskyRules := riskyIstioDenyHTTPRules(items.Items, service, targetPods); len(riskyRules) > 0 {
		riskyText := strings.Join(riskyRules, ", ")
		report.Add("Istio Authorization Layer", "authorization policies", model.StatusFail, fmt.Sprintf("Envoy returned RBAC access denied and selected DENY AuthorizationPolicy rule(s) %s use HTTP match fields without an explicit port constraint.", riskyText))
		report.Diagnose(fmt.Sprintf("Primary issue: Istio DENY AuthorizationPolicy rule(s) %s use HTTP-only match fields without an explicit port constraint. Istio can apply those DENY rules more broadly than expected when HTTP attributes are unavailable; add operation.ports or a destination.port condition to bound the rule.", riskyText))
		return
	}
	if len(matchingCustom) > 0 {
		customText := strings.Join(matchingCustom, ", ")
		report.Add("Istio Authorization Layer", "custom authorization", model.StatusWarn, fmt.Sprintf("Request matches Istio CUSTOM AuthorizationPolicy object(s) %s. CUSTOM policies delegate authorization to external provider(s), which KubeNetMods does not evaluate.", customText))
		report.Diagnose(fmt.Sprintf("Primary issue candidate: Request matches Istio CUSTOM AuthorizationPolicy object(s) %s, which delegate authorization to external provider(s). KubeNetMods does not evaluate external auth providers; check the provider logs/config.", customText))
		return
	}
	report.Add("Istio Authorization Layer", "authorization policies", model.StatusWarn, "Envoy returned RBAC access denied, but no matching DENY AuthorizationPolicy was identified by static inspection.")
	report.Diagnose(fmt.Sprintf("Primary issue: Envoy denied the request to Service %q with RBAC: access denied, but KubeNetMods could not identify the exact AuthorizationPolicy.", serviceName(service)))
}

func inspectIstioRequestAuthentication(ctx context.Context, client *kube.Client, report *model.Report, service *corev1.Service, targetPods []corev1.Pod, status model.Status) bool {
	if client.Istio == nil || service == nil {
		return false
	}
	items, err := client.Istio.SecurityV1().RequestAuthentications(service.Namespace).List(ctx, metav1.ListOptions{})
	if err != nil {
		addIstioListWarning(report, "Istio JWT Layer", "request authentications", err)
		return false
	}
	var matches []string
	for _, item := range items.Items {
		if requestAuthenticationSelectsTarget(item, service, targetPods) {
			matches = append(matches, requestAuthenticationSummary(item))
		}
	}
	if len(matches) == 0 {
		return false
	}
	sort.Strings(matches)
	text := strings.Join(matches, ", ")
	report.Add("Istio JWT Layer", "request authentication", status, fmt.Sprintf("Target workload for Service %q is selected by Istio RequestAuthentication object(s): %s. KubeNetMods does not validate JWT tokens.", service.Name, text))
	report.Diagnose(fmt.Sprintf("Primary issue candidate: target workload for Service %q is selected by Istio RequestAuthentication object(s) %s. Check JWT issuer/audience/token and any AuthorizationPolicy request.auth/requestPrincipals requirements; KubeNetMods does not validate JWT tokens.", serviceName(service), text))
	return true
}

func inspectIstioTrafficRouting(ctx context.Context, client *kube.Client, report *model.Report, opts ServiceOptions, service *corev1.Service, targetPods []corev1.Pod, source *ExecTarget, rawURL string) {
	if client.Istio == nil {
		return
	}
	namespaces := istioConfigNamespaces(opts, source)
	virtualServices, err := listIstioVirtualServices(ctx, client, namespaces)
	if err != nil {
		addIstioListWarning(report, "Istio Traffic Routing Layer", "virtual services", err)
		return
	}
	destinationRules, err := listIstioDestinationRules(ctx, client, namespaces)
	if err != nil {
		addIstioListWarning(report, "Istio Traffic Routing Layer", "destination rules", err)
		return
	}
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
	namespaces := istioConfigNamespaces(opts, source)
	virtualServices, err := listIstioVirtualServices(ctx, client, namespaces)
	if err != nil {
		addIstioListWarning(report, "Istio Traffic Routing Layer", "virtual services", err)
		return false
	}
	destinationRules, err := listIstioDestinationRules(ctx, client, namespaces)
	if err != nil {
		addIstioListWarning(report, "Istio Traffic Routing Layer", "destination rules", err)
		return false
	}
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

type istioHTTPRequest struct {
	Path                 string
	Scheme               string
	Method               string
	Port                 uint32
	PortText             string
	AuthorityHosts       []string
	QueryParams          map[string]string
	Headers              map[string]string
	SourceNamespace      string
	SourceLabels         map[string]string
	SourceServiceAccount string
	SourcePrincipals     []string
	RequestPrincipals    []string
}

func newIstioHTTPRequest(opts ServiceOptions, service *corev1.Service, source *ExecTarget, rawURL string) istioHTTPRequest {
	path := opts.URLPath
	if path == "" {
		path = "/"
	}
	queryParams := map[string]string{}
	if parsed, err := url.ParseRequestURI(path); err == nil {
		path = parsed.Path
		for key, values := range parsed.Query() {
			if len(values) > 0 {
				queryParams[strings.ToLower(key)] = values[0]
			}
		}
	}
	if path == "" {
		path = "/"
	}
	scheme := opts.URLScheme
	if scheme == "" {
		scheme = "http"
	}
	port := uint32(opts.ServicePort)
	if port == 0 && service != nil && len(service.Spec.Ports) > 0 {
		port = uint32(service.Spec.Ports[0].Port)
	}
	authzPort := port
	if service != nil {
		if selected, ok := selectServicePort(service, opts.ServicePort); ok && selected.TargetPort.Type == intstr.Int && selected.TargetPort.IntVal > 0 {
			authzPort = uint32(selected.TargetPort.IntVal)
		}
	}
	sourceNamespace := opts.SourceNamespace
	sourceServiceAccount := ""
	sourceLabels := map[string]string{}
	if source != nil {
		if sourceNamespace == "" {
			sourceNamespace = source.Pod.Namespace
		}
		sourceServiceAccount = source.Pod.Spec.ServiceAccountName
		if sourceServiceAccount == "" {
			sourceServiceAccount = "default"
		}
		for key, value := range source.Pod.Labels {
			sourceLabels[key] = value
		}
	}
	var sourcePrincipals []string
	if sourceNamespace != "" && sourceServiceAccount != "" {
		sourcePrincipals = append(sourcePrincipals, "cluster.local/ns/"+sourceNamespace+"/sa/"+sourceServiceAccount)
	}
	authorityHosts := istioServiceHosts(service)
	if parsed, err := url.Parse(rawURL); err == nil && parsed.Hostname() != "" {
		host := strings.TrimSuffix(strings.ToLower(parsed.Hostname()), ".")
		authorityHosts = []string{host}
		if parsed.Port() != "" {
			authorityHosts = append(authorityHosts, host+":"+parsed.Port())
		}
	}
	headers := map[string]string{}
	for key, value := range opts.HTTPHeaders {
		headers[strings.ToLower(key)] = value
	}
	return istioHTTPRequest{
		Path:                 path,
		Scheme:               strings.ToLower(scheme),
		Method:               "GET",
		Port:                 port,
		PortText:             fmt.Sprintf("%d", authzPort),
		AuthorityHosts:       authorityHosts,
		QueryParams:          queryParams,
		Headers:              headers,
		SourceNamespace:      sourceNamespace,
		SourceLabels:         sourceLabels,
		SourceServiceAccount: sourceServiceAccount,
		SourcePrincipals:     sourcePrincipals,
		RequestPrincipals:    nil,
	}
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

func istioConfigNamespaces(opts ServiceOptions, source *ExecTarget) []string {
	namespaces := []string{opts.Namespace}
	if opts.SourceNamespace != "" {
		namespaces = append(namespaces, opts.SourceNamespace)
	}
	if source != nil {
		namespaces = append(namespaces, source.Pod.Namespace)
	}
	return uniqueStrings(namespaces)
}

func listIstioVirtualServices(ctx context.Context, client *kube.Client, namespaces []string) ([]*networkingv1.VirtualService, error) {
	var out []*networkingv1.VirtualService
	for _, namespace := range namespaces {
		items, err := client.Istio.NetworkingV1().VirtualServices(namespace).List(ctx, metav1.ListOptions{})
		if err != nil {
			return nil, err
		}
		out = append(out, items.Items...)
	}
	return out, nil
}

func listIstioDestinationRules(ctx context.Context, client *kube.Client, namespaces []string) ([]*networkingv1.DestinationRule, error) {
	var out []*networkingv1.DestinationRule
	for _, namespace := range namespaces {
		items, err := client.Istio.NetworkingV1().DestinationRules(namespace).List(ctx, metav1.ListOptions{})
		if err != nil {
			return nil, err
		}
		out = append(out, items.Items...)
	}
	return out, nil
}

func istioHTTPRouteMatchesRequest(route *networkingapi.HTTPRoute, request istioHTTPRequest) bool {
	_, ok := istioHTTPRouteMatchText(route, request)
	return ok
}

func istioHTTPRouteMatchText(route *networkingapi.HTTPRoute, request istioHTTPRequest) (string, bool) {
	matches := route.GetMatch()
	if len(matches) == 0 {
		return "catch-all route", true
	}
	for _, match := range matches {
		if match == nil {
			continue
		}
		if istioHTTPMatchRequestMatches(match, request) {
			return istioHTTPMatchRequestSummary(match), true
		}
	}
	return "", false
}

func istioHTTPMatchRequestSummary(match *networkingapi.HTTPMatchRequest) string {
	var parts []string
	if text := istioStringMatchSummary("uri", match.GetUri()); text != "" {
		parts = append(parts, text)
	}
	if text := istioStringMatchSummary("method", match.GetMethod()); text != "" {
		parts = append(parts, text)
	}
	if text := istioStringMatchSummary("scheme", match.GetScheme()); text != "" {
		parts = append(parts, text)
	}
	if match.GetPort() != 0 {
		parts = append(parts, fmt.Sprintf("port=%d", match.GetPort()))
	}
	if match.GetSourceNamespace() != "" {
		parts = append(parts, "sourceNamespace="+match.GetSourceNamespace())
	}
	if len(match.GetSourceLabels()) > 0 {
		parts = append(parts, "sourceLabels "+labels.Set(match.GetSourceLabels()).String())
	}
	if text := istioStringMatchSummary("authority", match.GetAuthority()); text != "" {
		parts = append(parts, text)
	}
	for _, key := range sortedStringMatchKeys(match.GetHeaders()) {
		parts = append(parts, istioStringMatchSummary("header "+key, match.GetHeaders()[key]))
	}
	for _, key := range sortedStringMatchKeys(match.GetWithoutHeaders()) {
		parts = append(parts, "without "+istioStringMatchSummary("header "+key, match.GetWithoutHeaders()[key]))
	}
	for _, key := range sortedStringMatchKeys(match.GetQueryParams()) {
		parts = append(parts, istioStringMatchSummary("query "+key, match.GetQueryParams()[key]))
	}
	if len(parts) == 0 {
		return "empty match"
	}
	return strings.Join(parts, ", ")
}

func sortedStringMatchKeys(values map[string]*networkingapi.StringMatch) []string {
	var keys []string
	for key := range values {
		keys = append(keys, key)
	}
	sort.Strings(keys)
	return keys
}

func istioStringMatchSummary(name string, match *networkingapi.StringMatch) string {
	if match == nil {
		return ""
	}
	switch typed := match.GetMatchType().(type) {
	case *networkingapi.StringMatch_Exact:
		return fmt.Sprintf("%s=%q", name, typed.Exact)
	case *networkingapi.StringMatch_Prefix:
		return fmt.Sprintf("%s prefix %q", name, typed.Prefix)
	case *networkingapi.StringMatch_Regex:
		return fmt.Sprintf("%s regex %q", name, typed.Regex)
	default:
		return ""
	}
}

func istioHTTPMatchRequestMatches(match *networkingapi.HTTPMatchRequest, request istioHTTPRequest) bool {
	if !istioStringMatchMatches(match.GetUri(), request.Path, match.GetIgnoreUriCase()) {
		return false
	}
	if !istioStringMatchMatches(match.GetScheme(), request.Scheme, false) {
		return false
	}
	if !istioStringMatchMatches(match.GetMethod(), request.Method, false) {
		return false
	}
	if match.GetPort() != 0 && request.Port != 0 && match.GetPort() != request.Port {
		return false
	}
	if match.GetSourceNamespace() != "" && match.GetSourceNamespace() != request.SourceNamespace {
		return false
	}
	if len(match.GetSourceLabels()) > 0 && !labels.SelectorFromSet(match.GetSourceLabels()).Matches(labels.Set(request.SourceLabels)) {
		return false
	}
	if !istioAuthorityMatches(match.GetAuthority(), request.AuthorityHosts) {
		return false
	}
	if !istioHeaderMatches(match.GetHeaders(), request.Headers) {
		return false
	}
	if !istioWithoutHeaderMatches(match.GetWithoutHeaders(), request.Headers) {
		return false
	}
	if !istioQueryParamsMatch(match.GetQueryParams(), request.QueryParams) {
		return false
	}
	return true
}

func istioStringMatchMatches(match *networkingapi.StringMatch, value string, ignoreCase bool) bool {
	if match == nil {
		return true
	}
	switch typed := match.GetMatchType().(type) {
	case *networkingapi.StringMatch_Exact:
		exact := typed.Exact
		if ignoreCase {
			value = strings.ToLower(value)
			exact = strings.ToLower(exact)
		}
		return value == exact
	case *networkingapi.StringMatch_Prefix:
		prefix := typed.Prefix
		if ignoreCase {
			value = strings.ToLower(value)
			prefix = strings.ToLower(prefix)
		}
		return strings.HasPrefix(value, prefix)
	case *networkingapi.StringMatch_Regex:
		ok, err := regexp.MatchString(typed.Regex, value)
		return err == nil && ok
	default:
		return true
	}
}

func istioAuthorityMatches(match *networkingapi.StringMatch, authorities []string) bool {
	if match == nil {
		return true
	}
	for _, authority := range authorities {
		if istioStringMatchMatches(match, authority, false) {
			return true
		}
	}
	return false
}

func istioHeaderMatches(matches map[string]*networkingapi.StringMatch, headers map[string]string) bool {
	for key, match := range matches {
		value, ok := headers[strings.ToLower(key)]
		if !ok {
			return false
		}
		if !istioStringMatchMatches(match, value, false) {
			return false
		}
	}
	return true
}

func istioWithoutHeaderMatches(matches map[string]*networkingapi.StringMatch, headers map[string]string) bool {
	for key, match := range matches {
		value, ok := headers[strings.ToLower(key)]
		if !ok {
			continue
		}
		if istioStringMatchMatches(match, value, false) {
			return false
		}
	}
	return true
}

func istioQueryParamsMatch(matches map[string]*networkingapi.StringMatch, params map[string]string) bool {
	for key, match := range matches {
		value, ok := params[strings.ToLower(key)]
		if !ok {
			return false
		}
		if !istioStringMatchMatches(match, value, false) {
			return false
		}
	}
	return true
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

type destinationRuleTLSMode struct {
	Mode            networkingapi.ClientTLSSettings_TLSmode
	DestinationRule string
	Subset          string
	Port            int32
}

func (mode destinationRuleTLSMode) ScopeText() string {
	scope := ""
	if mode.Subset != "" {
		scope = fmt.Sprintf(" for subset %q", mode.Subset)
	}
	if mode.Port > 0 {
		if scope == "" {
			scope = fmt.Sprintf(" for service port %d", mode.Port)
		} else {
			scope += fmt.Sprintf(" on service port %d", mode.Port)
		}
	}
	return scope
}

func effectiveDestinationRuleTLSModeForRequest(virtualServices []*networkingv1.VirtualService, destinationRules []*networkingv1.DestinationRule, opts ServiceOptions, service *corev1.Service, source *ExecTarget, rawURL string, servicePort int32) (destinationRuleTLSMode, bool) {
	request := newIstioHTTPRequest(opts, service, source, rawURL)
	for _, vs := range virtualServices {
		if !istioVirtualServiceHostsService(vs, service) {
			continue
		}
		for _, dest := range istioRouteDestinations(vs, request) {
			if !istioHostMatchesService(dest.Host, vs.Namespace, service) {
				continue
			}
			dr, ok := findDestinationRule(destinationRules, dest.Host, vs.Namespace, service)
			if !ok {
				continue
			}
			mode, ok := destinationRuleTLSModeForSubset(dr, dest.Subset, servicePort)
			if ok {
				return destinationRuleTLSMode{Mode: mode, DestinationRule: dr.Namespace + "/" + dr.Name, Subset: dest.Subset, Port: servicePort}, true
			}
		}
	}
	dr, ok := findDestinationRule(destinationRules, service.Name+"."+service.Namespace+".svc.cluster.local", service.Namespace, service)
	if !ok {
		return destinationRuleTLSMode{}, false
	}
	mode, ok := destinationRuleTLSModeForSubset(dr, "", servicePort)
	if !ok {
		return destinationRuleTLSMode{}, false
	}
	return destinationRuleTLSMode{Mode: mode, DestinationRule: dr.Namespace + "/" + dr.Name, Port: servicePort}, true
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

func destinationRuleTLSModeForSubset(dr *networkingv1.DestinationRule, subset string, servicePort int32) (networkingapi.ClientTLSSettings_TLSmode, bool) {
	if dr == nil {
		return networkingapi.ClientTLSSettings_DISABLE, false
	}
	if subset != "" {
		for _, current := range dr.Spec.GetSubsets() {
			if current.GetName() != subset {
				continue
			}
			if mode, ok := trafficPolicyTLSMode(current.GetTrafficPolicy(), servicePort); ok {
				return mode, true
			}
			break
		}
	}
	return trafficPolicyTLSMode(dr.Spec.GetTrafficPolicy(), servicePort)
}

func trafficPolicyTLSMode(policy *networkingapi.TrafficPolicy, servicePort int32) (networkingapi.ClientTLSSettings_TLSmode, bool) {
	if policy == nil {
		return networkingapi.ClientTLSSettings_DISABLE, false
	}
	for _, portPolicy := range policy.GetPortLevelSettings() {
		if portPolicy.GetPort().GetNumber() == uint32(servicePort) && portPolicy.GetTls() != nil {
			return portPolicy.GetTls().GetMode(), true
		}
	}
	if tls := policy.GetTls(); tls != nil {
		return tls.GetMode(), true
	}
	return networkingapi.ClientTLSSettings_DISABLE, false
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

func runtimeLooksLikeConnectionReset(result RuntimeHTTPResult) bool {
	text := strings.ToLower(result.Error + " " + result.Output)
	return strings.Contains(text, "connection reset by peer") ||
		strings.Contains(text, "recv failure") ||
		strings.Contains(text, "connection reset") ||
		strings.Contains(text, "reset reason")
}

type effectivePeerAuthentication struct {
	Name string
	Mode securityapi.PeerAuthentication_MutualTLS_Mode
	Port uint32
}

func effectivePeerAuthenticationForPods(ctx context.Context, client *kube.Client, service *corev1.Service, servicePort int32, pods []corev1.Pod) effectivePeerAuthentication {
	workloadPort := peerAuthenticationWorkloadPort(service, servicePort)
	namespaces := map[string]bool{}
	for _, pod := range pods {
		if pod.Namespace != "" {
			namespaces[pod.Namespace] = true
		}
	}
	var namespaceList []string
	for namespace := range namespaces {
		namespaceList = append(namespaceList, namespace)
	}
	sort.Strings(namespaceList)
	rootNamespace := istioRootNamespace(ctx, client)
	for _, namespace := range namespaceList {
		nsPods := podsInNamespace(pods, namespace)
		if selected, ok := selectedPeerAuthentication(ctx, client, namespace, nsPods, workloadPort); ok {
			if selected.Mode != securityapi.PeerAuthentication_MutualTLS_UNSET {
				return selected
			}
		}
		if rootNamespace != "" && rootNamespace != namespace {
			if selected, ok := meshPeerAuthentication(ctx, client, rootNamespace, workloadPort); ok {
				return selected
			}
		}
	}
	return effectivePeerAuthentication{Mode: securityapi.PeerAuthentication_MutualTLS_UNSET, Port: workloadPort}
}

func selectedPeerAuthentication(ctx context.Context, client *kube.Client, namespace string, pods []corev1.Pod, workloadPort uint32) (effectivePeerAuthentication, bool) {
	items, err := client.Istio.SecurityV1().PeerAuthentications(namespace).List(ctx, metav1.ListOptions{})
	if err != nil {
		return effectivePeerAuthentication{}, false
	}
	var namespaceDefault *securityv1.PeerAuthentication
	for _, item := range items.Items {
		if item == nil {
			continue
		}
		if peerAuthenticationHasSelector(item) {
			if istioWorkloadSelectorMatchesAny(item.Spec.GetSelector(), pods) {
				return peerAuthenticationEffectiveMode(item, workloadPort), true
			}
			continue
		}
		if namespaceDefault == nil {
			namespaceDefault = item
		}
	}
	if namespaceDefault != nil {
		return peerAuthenticationEffectiveMode(namespaceDefault, workloadPort), true
	}
	return effectivePeerAuthentication{}, false
}

func meshPeerAuthentication(ctx context.Context, client *kube.Client, rootNamespace string, workloadPort uint32) (effectivePeerAuthentication, bool) {
	items, err := client.Istio.SecurityV1().PeerAuthentications(rootNamespace).List(ctx, metav1.ListOptions{})
	if err != nil {
		return effectivePeerAuthentication{}, false
	}
	for _, item := range items.Items {
		if item != nil && !peerAuthenticationHasSelector(item) {
			return peerAuthenticationEffectiveMode(item, workloadPort), true
		}
	}
	return effectivePeerAuthentication{}, false
}

func peerAuthenticationEffectiveMode(item *securityv1.PeerAuthentication, workloadPort uint32) effectivePeerAuthentication {
	name := item.Namespace + "/" + item.Name
	mode := item.Spec.GetMtls().GetMode()
	if workloadPort > 0 {
		if portMode := item.Spec.GetPortLevelMtls()[workloadPort]; portMode != nil && portMode.GetMode() != securityapi.PeerAuthentication_MutualTLS_UNSET {
			mode = portMode.GetMode()
		}
	}
	return effectivePeerAuthentication{Name: name, Mode: mode, Port: workloadPort}
}

func peerAuthenticationHasSelector(item *securityv1.PeerAuthentication) bool {
	return item != nil && len(item.Spec.GetSelector().GetMatchLabels()) > 0
}

func peerAuthenticationWorkloadPort(service *corev1.Service, servicePort int32) uint32 {
	if service == nil || len(service.Spec.Ports) == 0 {
		return 0
	}
	selected, ok := selectServicePort(service, servicePort)
	if !ok {
		return 0
	}
	if selected.TargetPort.Type == intstr.Int && selected.TargetPort.IntVal > 0 {
		return uint32(selected.TargetPort.IntVal)
	}
	if selected.TargetPort.Type == intstr.String && selected.Port > 0 {
		return uint32(selected.Port)
	}
	if selected.Port > 0 {
		return uint32(selected.Port)
	}
	return 0
}

func istioRootNamespace(ctx context.Context, client *kube.Client) string {
	const defaultRootNamespace = "istio-system"
	if client == nil || client.Core == nil {
		return defaultRootNamespace
	}
	configMap, err := client.Core.CoreV1().ConfigMaps(defaultRootNamespace).Get(ctx, "istio", metav1.GetOptions{})
	if err != nil {
		return defaultRootNamespace
	}
	data := configMap.Data["mesh"]
	for _, line := range strings.Split(data, "\n") {
		line = strings.TrimSpace(line)
		if strings.HasPrefix(line, "rootNamespace:") {
			root := strings.Trim(strings.TrimSpace(strings.TrimPrefix(line, "rootNamespace:")), "\"'")
			if root != "" {
				return root
			}
		}
	}
	return defaultRootNamespace
}

func podsInNamespace(pods []corev1.Pod, namespace string) []corev1.Pod {
	var out []corev1.Pod
	for _, pod := range pods {
		if pod.Namespace == namespace {
			out = append(out, pod)
		}
	}
	return out
}

func requestAuthenticationSelectsTarget(item *securityv1.RequestAuthentication, service *corev1.Service, pods []corev1.Pod) bool {
	if item == nil {
		return false
	}
	if len(item.Spec.GetTargetRefs()) > 0 {
		return targetRefsContainService(item.Spec.GetTargetRefs(), service, item.Namespace)
	}
	if item.Spec.GetTargetRef() != nil {
		return targetRefMatchesService(item.Spec.GetTargetRef(), service, item.Namespace)
	}
	return istioWorkloadSelectorMatchesAny(item.Spec.GetSelector(), pods)
}

func requestAuthenticationSummary(item *securityv1.RequestAuthentication) string {
	name := item.Namespace + "/" + item.Name
	var issuers []string
	for _, rule := range item.Spec.GetJwtRules() {
		if rule.GetIssuer() != "" {
			issuers = append(issuers, rule.GetIssuer())
		}
	}
	sort.Strings(issuers)
	if len(issuers) == 0 {
		return name
	}
	return fmt.Sprintf("%s issuer(s) %s", name, strings.Join(issuers, "|"))
}

func effectiveIstioSidecarForSource(ctx context.Context, client *kube.Client, pod corev1.Pod) (*networkingv1.Sidecar, bool) {
	items, err := client.Istio.NetworkingV1().Sidecars(pod.Namespace).List(ctx, metav1.ListOptions{})
	if err != nil {
		return nil, false
	}
	var defaultSidecar *networkingv1.Sidecar
	for _, item := range items.Items {
		if item == nil {
			continue
		}
		selector := item.Spec.GetWorkloadSelector()
		if selector == nil || len(selector.GetLabels()) == 0 {
			if defaultSidecar == nil {
				defaultSidecar = item
			}
			continue
		}
		if labels.SelectorFromSet(selector.GetLabels()).Matches(labels.Set(pod.Labels)) {
			return item, true
		}
	}
	if defaultSidecar != nil {
		return defaultSidecar, true
	}
	return nil, false
}

func istioSidecarEgressAllowsService(sidecar *networkingv1.Sidecar, service *corev1.Service) bool {
	for _, host := range istioSidecarEgressHosts(sidecar) {
		if istioSidecarHostMatchesService(host, sidecar.Namespace, service) {
			return true
		}
	}
	return false
}

func istioSidecarEgressHosts(sidecar *networkingv1.Sidecar) []string {
	var out []string
	for _, egress := range sidecar.Spec.GetEgress() {
		out = append(out, egress.GetHosts()...)
	}
	sort.Strings(out)
	return uniqueStrings(out)
}

func istioSidecarHostMatchesService(host string, sidecarNamespace string, service *corev1.Service) bool {
	parts := strings.SplitN(strings.TrimSpace(host), "/", 2)
	if len(parts) != 2 || service == nil {
		return false
	}
	namespaceScope := strings.ToLower(parts[0])
	dnsName := strings.ToLower(strings.TrimSuffix(parts[1], "."))
	serviceNamespace := strings.ToLower(service.Namespace)
	if namespaceScope == "*" && dnsName == "*" {
		return true
	}
	if namespaceScope == "~" {
		return false
	}
	if namespaceScope == "." {
		namespaceScope = strings.ToLower(sidecarNamespace)
	}
	if namespaceScope != "*" && namespaceScope != serviceNamespace {
		return false
	}
	if dnsName == "*" {
		return true
	}
	for _, candidate := range istioServiceHosts(service) {
		if sidecarDNSHostMatches(dnsName, candidate) {
			return true
		}
	}
	return false
}

func sidecarDNSHostMatches(pattern string, value string) bool {
	pattern = strings.ToLower(strings.TrimSuffix(pattern, "."))
	value = strings.ToLower(strings.TrimSuffix(value, "."))
	if pattern == value {
		return true
	}
	if strings.HasPrefix(pattern, "*.") {
		return strings.HasSuffix(value, strings.TrimPrefix(pattern, "*"))
	}
	return false
}

func istioAuthorizationPolicySelectsTarget(item *securityv1.AuthorizationPolicy, service *corev1.Service, pods []corev1.Pod) bool {
	if len(item.Spec.GetTargetRefs()) > 0 {
		return targetRefsContainService(item.Spec.GetTargetRefs(), service, item.Namespace)
	}
	if item.Spec.GetTargetRef() != nil {
		return targetRefMatchesService(item.Spec.GetTargetRef(), service, item.Namespace)
	}
	return istioWorkloadSelectorMatchesAny(item.Spec.GetSelector(), pods)
}

func istioWorkloadSelectorMatchesAny(selector *istiotype.WorkloadSelector, pods []corev1.Pod) bool {
	matchLabels := selector.GetMatchLabels()
	if len(matchLabels) == 0 {
		return true
	}
	labelSelector := labels.SelectorFromSet(matchLabels)
	for _, pod := range pods {
		if labelSelector.Matches(labels.Set(pod.Labels)) {
			return true
		}
	}
	return false
}

func targetRefsContainService(refs []*istiotype.PolicyTargetReference, service *corev1.Service, policyNamespace string) bool {
	for _, ref := range refs {
		if targetRefMatchesService(ref, service, policyNamespace) {
			return true
		}
	}
	return false
}

func targetRefMatchesService(ref *istiotype.PolicyTargetReference, service *corev1.Service, policyNamespace string) bool {
	if ref == nil || service == nil {
		return false
	}
	group := strings.ToLower(ref.GetGroup())
	kind := strings.ToLower(ref.GetKind())
	namespace := ref.GetNamespace()
	if namespace == "" {
		namespace = policyNamespace
	}
	return (group == "" || group == "core") &&
		kind == "service" &&
		namespace == service.Namespace &&
		ref.GetName() == service.Name
}

func istioAuthorizationRuleNumbers(rules []*securityapi.Rule, policyNamespace string, request istioHTTPRequest) []int {
	var out []int
	for i, rule := range rules {
		if rule == nil {
			continue
		}
		if istioAuthorizationRuleMatches(rule, policyNamespace, request) {
			out = append(out, i+1)
		}
	}
	return out
}

func istioAuthorizationRuleMatches(rule *securityapi.Rule, policyNamespace string, request istioHTTPRequest) bool {
	return istioAuthorizationFromMatches(rule.GetFrom(), policyNamespace, request) &&
		istioAuthorizationToMatches(rule.GetTo(), request) &&
		istioAuthorizationWhenMatches(rule.GetWhen(), request)
}

func matchingIstioAuthorizationPolicies(items []*securityv1.AuthorizationPolicy, service *corev1.Service, pods []corev1.Pod, action securityapi.AuthorizationPolicy_Action, request istioHTTPRequest) []string {
	var out []string
	for _, item := range items {
		if item == nil ||
			item.Spec.GetAction() != action ||
			!istioAuthorizationPolicySelectsTarget(item, service, pods) {
			continue
		}
		matchingRules := istioAuthorizationRuleNumbers(item.Spec.GetRules(), item.Namespace, request)
		if len(matchingRules) == 0 {
			continue
		}
		out = append(out, item.Namespace+"/"+item.Name+" "+formatRuleNumbers(matchingRules)+istioProviderText(item))
	}
	sort.Strings(out)
	return out
}

func istioAllowDefaultDeny(items []*securityv1.AuthorizationPolicy, service *corev1.Service, pods []corev1.Pod, request istioHTTPRequest) (string, bool) {
	var selected []string
	var matching []string
	for _, item := range items {
		if item == nil ||
			item.Spec.GetAction() != securityapi.AuthorizationPolicy_ALLOW ||
			!istioAuthorizationPolicySelectsTarget(item, service, pods) {
			continue
		}
		name := item.Namespace + "/" + item.Name
		selected = append(selected, name)
		matchingRules := istioAuthorizationRuleNumbers(item.Spec.GetRules(), item.Namespace, request)
		if len(matchingRules) > 0 {
			matching = append(matching, name+" "+formatRuleNumbers(matchingRules))
		}
	}
	if len(selected) == 0 || len(matching) > 0 {
		return "", false
	}
	sort.Strings(selected)
	return strings.Join(selected, ", "), true
}

func istioProviderText(item *securityv1.AuthorizationPolicy) string {
	provider := item.Spec.GetProvider()
	if provider == nil || provider.GetName() == "" {
		return ""
	}
	return fmt.Sprintf(" provider %q", provider.GetName())
}

func riskyIstioDenyHTTPRules(items []*securityv1.AuthorizationPolicy, service *corev1.Service, pods []corev1.Pod) []string {
	var out []string
	for _, item := range items {
		if item == nil ||
			item.Spec.GetAction() != securityapi.AuthorizationPolicy_DENY ||
			!istioAuthorizationPolicySelectsTarget(item, service, pods) {
			continue
		}
		for i, rule := range item.Spec.GetRules() {
			if istioDenyRuleHasHTTPAttributesWithoutPort(rule) {
				out = append(out, fmt.Sprintf("%s/%s rule %d", item.Namespace, item.Name, i+1))
			}
		}
	}
	return out
}

func istioAuthorizationUsesJWT(items []*securityv1.AuthorizationPolicy, service *corev1.Service, pods []corev1.Pod) bool {
	for _, item := range items {
		if item == nil || !istioAuthorizationPolicySelectsTarget(item, service, pods) {
			continue
		}
		for _, rule := range item.Spec.GetRules() {
			if istioAuthorizationRuleUsesJWT(rule) {
				return true
			}
		}
	}
	return false
}

func istioAuthorizationRuleUsesJWT(rule *securityapi.Rule) bool {
	if rule == nil {
		return false
	}
	for _, from := range rule.GetFrom() {
		source := from.GetSource()
		if source == nil {
			continue
		}
		if len(source.GetRequestPrincipals()) > 0 || len(source.GetNotRequestPrincipals()) > 0 {
			return true
		}
	}
	for _, condition := range rule.GetWhen() {
		if condition == nil {
			continue
		}
		if strings.HasPrefix(strings.ToLower(condition.GetKey()), "request.auth.") {
			return true
		}
	}
	return false
}

func istioDenyRuleHasHTTPAttributesWithoutPort(rule *securityapi.Rule) bool {
	if rule == nil {
		return false
	}
	hasHTTPAttribute := false
	hasPortConstraint := false
	for _, to := range rule.GetTo() {
		if to == nil {
			continue
		}
		operation := to.GetOperation()
		if operation == nil {
			continue
		}
		if len(operation.GetMethods()) > 0 ||
			len(operation.GetNotMethods()) > 0 ||
			len(operation.GetPaths()) > 0 ||
			len(operation.GetNotPaths()) > 0 ||
			len(operation.GetHosts()) > 0 ||
			len(operation.GetNotHosts()) > 0 {
			hasHTTPAttribute = true
		}
		if len(operation.GetPorts()) > 0 || len(operation.GetNotPorts()) > 0 {
			hasPortConstraint = true
		}
	}
	for _, condition := range rule.GetWhen() {
		if condition == nil {
			continue
		}
		key := strings.ToLower(condition.GetKey())
		if strings.HasPrefix(key, "request.") || strings.HasPrefix(key, "experimental.envoy.filters.http.") {
			hasHTTPAttribute = true
		}
		if key == "destination.port" {
			hasPortConstraint = true
		}
	}
	return hasHTTPAttribute && !hasPortConstraint
}

func istioAuthorizationFromMatches(from []*securityapi.Rule_From, policyNamespace string, request istioHTTPRequest) bool {
	if len(from) == 0 {
		return true
	}
	for _, item := range from {
		if item == nil || istioAuthorizationSourceMatches(item.GetSource(), policyNamespace, request) {
			return true
		}
	}
	return false
}

func istioAuthorizationSourceMatches(source *securityapi.Source, policyNamespace string, request istioHTTPRequest) bool {
	if source == nil {
		return true
	}
	if !istioStringListMatches(source.GetNamespaces(), request.SourceNamespace, false) ||
		istioStringListAnyMatches(source.GetNotNamespaces(), request.SourceNamespace, false) {
		return false
	}
	if !istioStringListMatches(source.GetServiceAccounts(), istioRelativeServiceAccount(request.SourceNamespace, request.SourceServiceAccount, policyNamespace), false) ||
		istioStringListAnyMatches(source.GetNotServiceAccounts(), istioRelativeServiceAccount(request.SourceNamespace, request.SourceServiceAccount, policyNamespace), false) {
		return false
	}
	if len(source.GetPrincipals()) > 0 && !istioAnyStringListMatches(source.GetPrincipals(), request.SourcePrincipals, false) {
		return false
	}
	if len(source.GetNotPrincipals()) > 0 && istioAnyStringListAnyMatches(source.GetNotPrincipals(), request.SourcePrincipals, false) {
		return false
	}
	if len(source.GetRequestPrincipals()) > 0 && !istioAnyStringListMatches(source.GetRequestPrincipals(), request.RequestPrincipals, false) {
		return false
	}
	if len(source.GetNotRequestPrincipals()) > 0 && istioAnyStringListAnyMatches(source.GetNotRequestPrincipals(), request.RequestPrincipals, false) {
		return false
	}
	return true
}

func istioAuthorizationToMatches(to []*securityapi.Rule_To, request istioHTTPRequest) bool {
	if len(to) == 0 {
		return true
	}
	for _, item := range to {
		if item == nil || istioAuthorizationOperationMatches(item.GetOperation(), request) {
			return true
		}
	}
	return false
}

func istioAuthorizationOperationMatches(operation *securityapi.Operation, request istioHTTPRequest) bool {
	if operation == nil {
		return true
	}
	if !istioAnyStringListMatches(operation.GetHosts(), request.AuthorityHosts, true) ||
		istioAnyStringListAnyMatches(operation.GetNotHosts(), request.AuthorityHosts, true) {
		return false
	}
	if !istioStringListMatches(operation.GetPorts(), request.PortText, false) ||
		istioStringListAnyMatches(operation.GetNotPorts(), request.PortText, false) {
		return false
	}
	if !istioStringListMatches(operation.GetMethods(), request.Method, false) ||
		istioStringListAnyMatches(operation.GetNotMethods(), request.Method, false) {
		return false
	}
	if !istioStringListMatches(operation.GetPaths(), request.Path, false) ||
		istioStringListAnyMatches(operation.GetNotPaths(), request.Path, false) {
		return false
	}
	return true
}

func istioAuthorizationWhenMatches(conditions []*securityapi.Condition, request istioHTTPRequest) bool {
	for _, condition := range conditions {
		if condition == nil {
			continue
		}
		value, ok := istioConditionValue(condition.GetKey(), request)
		if !ok {
			return false
		}
		if !istioStringListMatches(condition.GetValues(), value, false) ||
			istioStringListAnyMatches(condition.GetNotValues(), value, false) {
			return false
		}
	}
	return true
}

func istioConditionValue(key string, request istioHTTPRequest) (string, bool) {
	switch strings.ToLower(key) {
	case "source.namespace":
		return request.SourceNamespace, request.SourceNamespace != ""
	case "source.serviceaccount":
		if request.SourceNamespace == "" || request.SourceServiceAccount == "" {
			return "", false
		}
		return request.SourceNamespace + "/" + request.SourceServiceAccount, true
	case "request.method":
		return request.Method, request.Method != ""
	case "request.url_path":
		return request.Path, request.Path != ""
	case "destination.port":
		return request.PortText, request.PortText != "" && request.PortText != "0"
	}
	return "", false
}

func istioStringListMatches(patterns []string, value string, ignoreCase bool) bool {
	if len(patterns) == 0 {
		return true
	}
	return istioStringListAnyMatches(patterns, value, ignoreCase)
}

func istioStringListAnyMatches(patterns []string, value string, ignoreCase bool) bool {
	for _, pattern := range patterns {
		if istioAuthPatternMatches(pattern, value, ignoreCase) {
			return true
		}
	}
	return false
}

func istioAnyStringListMatches(patterns []string, values []string, ignoreCase bool) bool {
	if len(patterns) == 0 {
		return true
	}
	return istioAnyStringListAnyMatches(patterns, values, ignoreCase)
}

func istioAnyStringListAnyMatches(patterns []string, values []string, ignoreCase bool) bool {
	for _, value := range values {
		if istioStringListAnyMatches(patterns, value, ignoreCase) {
			return true
		}
	}
	return false
}

func istioAuthPatternMatches(pattern string, value string, ignoreCase bool) bool {
	if ignoreCase {
		pattern = strings.ToLower(pattern)
		value = strings.ToLower(value)
	}
	switch {
	case pattern == "*":
		return value != ""
	case strings.HasPrefix(pattern, "*") && len(pattern) > 1:
		return strings.HasSuffix(value, strings.TrimPrefix(pattern, "*"))
	case strings.HasSuffix(pattern, "*") && len(pattern) > 1:
		return strings.HasPrefix(value, strings.TrimSuffix(pattern, "*"))
	default:
		return pattern == value
	}
}

func istioRelativeServiceAccount(namespace string, serviceAccount string, policyNamespace string) string {
	if serviceAccount == "" {
		return ""
	}
	if namespace == "" || namespace == policyNamespace {
		return serviceAccount
	}
	return namespace + "/" + serviceAccount
}

func formatRuleNumbers(numbers []int) string {
	if len(numbers) == 1 {
		return fmt.Sprintf("rule %d", numbers[0])
	}
	var values []string
	for _, number := range numbers {
		values = append(values, fmt.Sprintf("%d", number))
	}
	return "rules " + strings.Join(values, ", ")
}

func addIstioListWarning(report *model.Report, layer string, check string, err error) {
	if apierrors.IsNotFound(err) {
		return
	}
	report.Add(layer, check, model.StatusWarn, fmt.Sprintf("Could not inspect Istio %s: %v", check, err))
}
