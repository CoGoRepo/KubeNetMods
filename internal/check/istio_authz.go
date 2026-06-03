package check

import (
	"context"
	"fmt"
	"sort"
	"strings"

	"github.com/CoGoRepo/KubeNetMods/internal/kube"
	"github.com/CoGoRepo/KubeNetMods/internal/model"
	securityapi "istio.io/api/security/v1beta1"
	istiotype "istio.io/api/type/v1beta1"
	securityv1 "istio.io/client-go/pkg/apis/security/v1"
	corev1 "k8s.io/api/core/v1"
	"k8s.io/apimachinery/pkg/labels"
)

func inspectIstioAuthorizationPolicy(ctx context.Context, client *kube.Client, report *model.Report, opts ServiceOptions, service *corev1.Service, targetPods []corev1.Pod, source *ExecTarget, rawURL string) {
	if client.Istio == nil {
		return
	}
	items, err := listIstioAuthorizationPolicies(ctx, client, istioTargetPolicyNamespaces(ctx, client, opts.Namespace))
	if err != nil {
		addIstioListWarning(report, "Istio Authorization Layer", "authorization policies", err)
		if len(items) == 0 {
			return
		}
	}
	items = enforcedIstioAuthorizationPolicies(items)
	request := newIstioHTTPRequest(opts, service, source, rawURL)
	matchingCustom := matchingIstioAuthorizationPolicies(items, service, targetPods, securityapi.AuthorizationPolicy_CUSTOM, request)
	for _, item := range items {
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
	if istioAuthorizationUsesJWT(items, service, targetPods) && inspectIstioRequestAuthentication(ctx, client, report, service, targetPods, model.StatusWarn) {
		return
	}
	if allowText, ok := istioAllowDefaultDeny(items, service, targetPods, request); ok {
		report.Add("Istio Authorization Layer", "allow policies", model.StatusFail, fmt.Sprintf("Target pods selected by Service %q are selected by Istio ALLOW AuthorizationPolicy object(s), but none match this source/request. Policies: %s.", service.Name, allowText))
		report.Diagnose(fmt.Sprintf("Primary issue: Target workload is selected by Istio ALLOW AuthorizationPolicy object(s), but none match source pod %q for Service %q, so Envoy denies the request. Policies: %s.", source.Pod.Name, serviceName(service), allowText))
		return
	}
	if riskyRules := riskyIstioDenyHTTPRules(items, service, targetPods); len(riskyRules) > 0 {
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

func enforcedIstioAuthorizationPolicies(items []*securityv1.AuthorizationPolicy) []*securityv1.AuthorizationPolicy {
	var out []*securityv1.AuthorizationPolicy
	for _, item := range items {
		if item == nil || istioAuthorizationPolicyDryRun(item) {
			continue
		}
		out = append(out, item)
	}
	return out
}

func istioAuthorizationPolicyDryRun(item *securityv1.AuthorizationPolicy) bool {
	value := item.Annotations["istio.io/dry-run"]
	return strings.EqualFold(strings.TrimSpace(value), "true")
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
