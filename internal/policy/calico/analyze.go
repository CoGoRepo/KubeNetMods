package calico

import (
	"context"
	"fmt"
	"net/netip"
	"sort"
	"strings"

	"github.com/CoGoRepo/KubeNetMods/internal/kube"
	"github.com/CoGoRepo/KubeNetMods/internal/policy"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"
	"k8s.io/apimachinery/pkg/runtime/schema"
	"k8s.io/apimachinery/pkg/util/intstr"
)

type DNSContext struct {
	Nameservers      []string
	CoreDNSServiceIP string
	CoreDNSPods      []corev1.Pod
	NodeLocalDNSPods []corev1.Pod
	KubeSystemNS     *corev1.Namespace
}

type serviceAccountLabels map[string]map[string]string

var (
	calicoNetworkPolicyGVR = schema.GroupVersionResource{
		Group:    "projectcalico.org",
		Version:  "v3",
		Resource: "networkpolicies",
	}
	calicoGlobalNetworkPolicyGVR = schema.GroupVersionResource{
		Group:    "projectcalico.org",
		Version:  "v3",
		Resource: "globalnetworkpolicies",
	}
	calicoStagedNetworkPolicyGVR = schema.GroupVersionResource{
		Group:    "projectcalico.org",
		Version:  "v3",
		Resource: "stagednetworkpolicies",
	}
	calicoStagedGlobalNetworkPolicyGVR = schema.GroupVersionResource{
		Group:    "projectcalico.org",
		Version:  "v3",
		Resource: "stagedglobalnetworkpolicies",
	}
	calicoNetworkSetGVR = schema.GroupVersionResource{
		Group:    "projectcalico.org",
		Version:  "v3",
		Resource: "networksets",
	}
	calicoGlobalNetworkSetGVR = schema.GroupVersionResource{
		Group:    "projectcalico.org",
		Version:  "v3",
		Resource: "globalnetworksets",
	}
	calicoTierGVR = schema.GroupVersionResource{
		Group:    "projectcalico.org",
		Version:  "v3",
		Resource: "tiers",
	}
	calicoProfileGVR = schema.GroupVersionResource{
		Group:    "projectcalico.org",
		Version:  "v3",
		Resource: "profiles",
	}
	calicoHostEndpointGVR = schema.GroupVersionResource{
		Group:    "projectcalico.org",
		Version:  "v3",
		Resource: "hostendpoints",
	}
)

func Analyze(ctx context.Context, client *kube.Client, targetNamespace corev1.Namespace, targetPods []corev1.Pod, sourceNamespace *corev1.Namespace, sourcePod *corev1.Pod, service *corev1.Service, ports []int32, dns DNSContext) ([]policy.Insight, error) {
	var insights []policy.Insight

	namespaces := []string{targetNamespace.Name}
	if sourceNamespace != nil && sourceNamespace.Name != targetNamespace.Name {
		namespaces = append(namespaces, sourceNamespace.Name)
	}
	namespaced, err := listNamespacedCalico(ctx, client, calicoNetworkPolicyGVR, namespaces)
	if err != nil {
		if isNoMatch(err) {
			return nil, nil
		}
		return []policy.Insight{{
			Provider: "Calico",
			Layer:    "Calico Policy Layer",
			Check:    "networkpolicies",
			Status:   "WARN",
			Message:  fmt.Sprintf("Could not list Calico NetworkPolicy objects: %v", err),
		}}, nil
	}

	global, globalErr := client.Dynamic.Resource(calicoGlobalNetworkPolicyGVR).List(ctx, metav1.ListOptions{})
	if globalErr != nil && !isNoMatch(globalErr) {
		insights = append(insights, policy.Insight{
			Provider: "Calico",
			Layer:    "Calico Policy Layer",
			Check:    "globalnetworkpolicies",
			Status:   "WARN",
			Message:  fmt.Sprintf("Could not list Calico GlobalNetworkPolicy objects: %v", globalErr),
		})
	}
	stagedPolicies := listOptionalCalico(ctx, client, calicoStagedNetworkPolicyGVR, namespaces)
	stagedGlobal := listOptionalGlobalCalico(ctx, client, calicoStagedGlobalNetworkPolicyGVR)
	networkSets := listOptionalCalico(ctx, client, calicoNetworkSetGVR, namespaces)
	globalNetworkSets := listOptionalGlobalCalico(ctx, client, calicoGlobalNetworkSetGVR)
	tiers := listOptionalGlobalCalico(ctx, client, calicoTierGVR)
	profiles := listOptionalGlobalCalico(ctx, client, calicoProfileGVR)
	serviceAccounts := loadServiceAccountLabels(ctx, client, namespaces)
	insights = append(insights, unsupportedPolicyInsights(append(stagedPolicies, stagedGlobal...), append(namespaced.Items, safeGlobalItems(global)...))...)
	if len(stagedPolicies)+len(stagedGlobal) > 0 {
		insights = append(insights, policy.Insight{
			Provider: "Calico",
			Layer:    "Calico Policy Layer",
			Check:    "staged policies",
			Status:   "INFO",
			Message:  fmt.Sprintf("%d staged Calico policy object(s) were detected but are not enforced; they are not used for path decisions.", len(stagedPolicies)+len(stagedGlobal)),
		})
	}

	targetIngressMatching := []string{}
	malformed := []string{}
	for _, item := range namespaced.Items {
		if !policyHasType(item, "Ingress") {
			continue
		}
		matches, bad := policySelectsTarget(item, targetNamespace, targetPods, nil)
		if bad != "" {
			malformed = append(malformed, fmt.Sprintf("%s: %s", item.GetName(), bad))
		}
		if matches {
			targetIngressMatching = append(targetIngressMatching, item.GetName())
		}
	}
	if globalErr == nil && global != nil {
		for _, item := range global.Items {
			if !policyHasType(item, "Ingress") {
				continue
			}
			matches, bad := policySelectsTarget(item, targetNamespace, targetPods, sourceNamespace)
			if bad != "" {
				malformed = append(malformed, fmt.Sprintf("%s: %s", item.GetName(), bad))
			}
			if matches {
				targetIngressMatching = append(targetIngressMatching, "global/"+item.GetName())
			}
		}
	}

	if len(malformed) > 0 {
		insights = append(insights, policy.Insight{
			Provider:  "Calico",
			Layer:     "Calico Policy Layer",
			Check:     "selector parse",
			Status:    "WARN",
			Message:   "Calico selector parse errors: " + strings.Join(malformed, "; "),
			Diagnosis: "One or more Calico selectors could not be parsed by Calico's selector engine. Fix malformed selector syntax before trusting policy analysis.",
		})
	}
	if len(targetIngressMatching) == 0 {
		if len(namespaced.Items) == 0 && (global == nil || len(global.Items) == 0) {
			insights = append(insights, policy.Insight{
				Provider: "Calico",
				Layer:    "Calico Policy Layer",
				Check:    "target ingress policies",
				Status:   "INFO",
				Message:  "No Calico policy objects were found in the inspected namespaces.",
			})
		} else {
			insights = append(insights, policy.Insight{
				Provider: "Calico",
				Layer:    "Calico Policy Layer",
				Check:    "target ingress policies",
				Status:   "INFO",
				Message:  "No Calico ingress policies obviously select the target pod(s). Source egress policy may still affect this path.",
			})
		}
	} else {
		insights = append(insights, policy.Insight{
			Provider: "Calico",
			Layer:    "Calico Policy Layer",
			Check:    "target ingress policies",
			Status:   "WARN",
			Message:  "Target pod(s) are selected by Calico ingress policy: " + strings.Join(targetIngressMatching, ", "),
		})
	}
	if sourcePod != nil && sourceNamespace != nil {
		sets := append(networkSets, globalNetworkSets...)
		all := append([]unstructured.Unstructured{}, namespaced.Items...)
		all = append(all, safeGlobalItems(global)...)
		sourceEgressPolicies := policiesForPod(all, *sourceNamespace, *sourcePod, "Egress")
		if len(sourceEgressPolicies) == 0 {
			insights = append(insights, policy.Insight{
				Provider: "Calico",
				Layer:    "Calico Policy Layer",
				Check:    "source egress policies",
				Status:   "PASS",
				Message:  "No Calico egress policies select the source pod.",
			})
		} else {
			insights = append(insights, policy.Insight{
				Provider: "Calico",
				Layer:    "Calico Policy Layer",
				Check:    "source egress policies",
				Status:   "WARN",
				Message:  "Source pod is selected by Calico egress policy: " + strings.Join(calicoPolicyNames(sourceEgressPolicies), ", "),
			})
		}
		insights = append(insights, analyzePath(namespaced.Items, safeGlobalItems(global), tiers, sets, profiles, serviceAccounts, targetNamespace, targetPods, *sourceNamespace, *sourcePod, service, ports)...)
		insights = append(insights, analyzeDNSEgress(namespaced.Items, safeGlobalItems(global), tiers, sets, profiles, serviceAccounts, *sourceNamespace, *sourcePod, dns)...)
	}
	return insights, nil
}

func AnalyzeIngressSurface(ctx context.Context, client *kube.Client, service *corev1.Service) ([]policy.Insight, error) {
	global, err := client.Dynamic.Resource(calicoGlobalNetworkPolicyGVR).List(ctx, metav1.ListOptions{})
	if err != nil {
		if isNoMatch(err) {
			return nil, nil
		}
		return []policy.Insight{{
			Provider: "Calico",
			Layer:    "Calico Host Policy Layer",
			Check:    "globalnetworkpolicies",
			Status:   "WARN",
			Message:  fmt.Sprintf("Could not list Calico GlobalNetworkPolicy objects: %v", err),
		}}, nil
	}
	hostEndpoints := listOptionalGlobalCalico(ctx, client, calicoHostEndpointGVR)
	tiers := listOptionalGlobalCalico(ctx, client, calicoTierGVR)
	return analyzeIngressSurface(global.Items, hostEndpoints, tiers, calicoIngressPorts(service)), nil
}

func listNamespacedCalico(ctx context.Context, client *kube.Client, gvr schema.GroupVersionResource, namespaces []string) (*unstructured.UnstructuredList, error) {
	combined := &unstructured.UnstructuredList{}
	for _, namespace := range unique(namespaces) {
		list, err := client.Dynamic.Resource(gvr).Namespace(namespace).List(ctx, metav1.ListOptions{})
		if err != nil {
			return nil, err
		}
		combined.Items = append(combined.Items, list.Items...)
	}
	return combined, nil
}

func listOptionalCalico(ctx context.Context, client *kube.Client, gvr schema.GroupVersionResource, namespaces []string) []unstructured.Unstructured {
	list, err := listNamespacedCalico(ctx, client, gvr, namespaces)
	if err != nil || list == nil {
		return nil
	}
	return list.Items
}

func listOptionalGlobalCalico(ctx context.Context, client *kube.Client, gvr schema.GroupVersionResource) []unstructured.Unstructured {
	list, err := client.Dynamic.Resource(gvr).List(ctx, metav1.ListOptions{})
	if err != nil || list == nil {
		return nil
	}
	return list.Items
}

func loadServiceAccountLabels(ctx context.Context, client *kube.Client, namespaces []string) serviceAccountLabels {
	out := serviceAccountLabels{}
	for _, namespace := range unique(namespaces) {
		list, err := client.Core.CoreV1().ServiceAccounts(namespace).List(ctx, metav1.ListOptions{})
		if err != nil {
			continue
		}
		for _, account := range list.Items {
			out[serviceAccountKey(namespace, account.Name)] = cloneMap(account.Labels)
		}
	}
	return out
}

func serviceAccountKey(namespace, name string) string {
	if name == "" {
		name = "default"
	}
	return namespace + "/" + name
}

func safeGlobalItems(list *unstructured.UnstructuredList) []unstructured.Unstructured {
	if list == nil {
		return nil
	}
	return list.Items
}

func unsupportedPolicyInsights(staged []unstructured.Unstructured, enforced []unstructured.Unstructured) []policy.Insight {
	var insights []policy.Insight
	for _, item := range enforced {
		name := calicoPolicyDisplayName(item)
		if truthySpecField(item, "preDNAT") {
			insights = append(insights, policy.Insight{
				Provider:  "Calico",
				Layer:     "Calico Policy Layer",
				Check:     "preDNAT policy",
				Status:    "WARN",
				Message:   fmt.Sprintf("Policy %q uses preDNAT. Service/pod path reasoning may not reflect traffic handled before Kubernetes DNAT.", name),
				Diagnosis: "A Calico preDNAT policy is present. If NodePort, LoadBalancer, host endpoint, or externally-originated traffic is failing, inspect preDNAT policy separately.",
			})
		}
		if truthySpecField(item, "doNotTrack") {
			insights = append(insights, policy.Insight{
				Provider:  "Calico",
				Layer:     "Calico Policy Layer",
				Check:     "doNotTrack policy",
				Status:    "WARN",
				Message:   fmt.Sprintf("Policy %q uses doNotTrack. This can affect host-forwarded traffic differently from normal workload policy.", name),
				Diagnosis: "A Calico doNotTrack policy is present. KubeNetMods does not fully model untracked dataplane behavior.",
			})
		}
		if truthySpecField(item, "applyOnForward") {
			insights = append(insights, policy.Insight{
				Provider: "Calico",
				Layer:    "Calico Policy Layer",
				Check:    "applyOnForward policy",
				Status:   "WARN",
				Message:  fmt.Sprintf("Policy %q uses applyOnForward. Forwarded host endpoint traffic may be affected outside the pod-to-Service model.", name),
			})
		}
		for _, direction := range []string{"ingress", "egress"} {
			rules, _, _ := unstructured.NestedSlice(item.Object, "spec", direction)
			for _, raw := range rules {
				rule, ok := raw.(map[string]interface{})
				if !ok {
					continue
				}
				if _, ok := rule["http"]; ok {
					insights = append(insights, policy.Insight{
						Provider: "Calico",
						Layer:    "Calico Policy Layer",
						Check:    "HTTP policy",
						Status:   "WARN",
						Message:  fmt.Sprintf("Policy %q contains HTTP/application-layer criteria. Go KubeNetMods does not fully emulate Calico L7 policy matching yet.", name),
					})
					break
				}
				if _, ok := rule["icmp"]; ok {
					insights = append(insights, policy.Insight{
						Provider: "Calico",
						Layer:    "Calico Policy Layer",
						Check:    "ICMP policy",
						Status:   "INFO",
						Message:  fmt.Sprintf("Policy %q contains ICMP criteria. The tested service path is treated as TCP, so ICMP is not used for the path decision.", name),
					})
					break
				}
			}
		}
	}
	return insights
}

func truthySpecField(item unstructured.Unstructured, field string) bool {
	value, ok, _ := unstructured.NestedBool(item.Object, "spec", field)
	return ok && value
}

func analyzeIngressSurface(globalPolicies []unstructured.Unstructured, hostEndpoints []unstructured.Unstructured, tiers []unstructured.Unstructured, ports []int32) []policy.Insight {
	var hostPolicies []unstructured.Unstructured
	var insights []policy.Insight
	for _, item := range globalPolicies {
		if truthySpecField(item, "preDNAT") || truthySpecField(item, "doNotTrack") || truthySpecField(item, "applyOnForward") {
			if invalid := invalidHostPolicyInsight(item); invalid != nil {
				insights = append(insights, *invalid)
				continue
			}
			hostPolicies = append(hostPolicies, item)
		}
	}
	if len(hostPolicies) == 0 {
		return append(insights, policy.Insight{
			Provider: "Calico",
			Layer:    "Calico Host Policy Layer",
			Check:    "host/forwarded policies",
			Status:   "INFO",
			Message:  "No Calico preDNAT, doNotTrack, or applyOnForward GlobalNetworkPolicy objects were found.",
		})
	}
	if len(hostEndpoints) == 0 {
		return append(insights, policy.Insight{
			Provider:  "Calico",
			Layer:     "Calico Host Policy Layer",
			Check:     "host endpoints",
			Status:    "WARN",
			Message:   fmt.Sprintf("%d Calico host/forwarded policy object(s) exist, but no HostEndpoint objects were found/readable.", len(hostPolicies)),
			Diagnosis: "Calico host/pre-DNAT policy is configured but KubeNetMods cannot map it to HostEndpoints. If external, NodePort, LoadBalancer, or ingress-controller traffic fails, inspect HostEndpoint coverage.",
		})
	}
	selectedByPolicy := map[string][]string{}
	selectedCount := 0
	for _, item := range hostPolicies {
		var selected []unstructured.Unstructured
		for _, hep := range hostEndpoints {
			if calicoPolicySelectsHostEndpoint(item, hep) {
				selected = append(selected, hep)
			}
		}
		name := calicoPolicyDisplayName(item)
		if len(selected) == 0 {
			insights = append(insights, policy.Insight{
				Provider: "Calico",
				Layer:    "Calico Host Policy Layer",
				Check:    name,
				Status:   "INFO",
				Message:  fmt.Sprintf("Host/forwarded policy %q exists but does not obviously select any readable HostEndpoint.", name),
			})
			continue
		}
		selectedCount++
		selectedByPolicy[name] = hostEndpointNames(selected)
		if truthySpecField(item, "doNotTrack") {
			insights = append(insights, policy.Insight{
				Provider: "Calico",
				Layer:    "Calico Host Policy Layer",
				Check:    name + " doNotTrack",
				Status:   "WARN",
				Message:  fmt.Sprintf("Policy %q uses doNotTrack. It is evaluated before normal conntrack and may behave differently from regular host policy.", name),
			})
		} else if truthySpecField(item, "preDNAT") {
			insights = append(insights, policy.Insight{
				Provider: "Calico",
				Layer:    "Calico Host Policy Layer",
				Check:    name + " preDNAT",
				Status:   "WARN",
				Message:  fmt.Sprintf("Policy %q uses preDNAT. It is evaluated before Kubernetes DNAT, so NodePort/LB traffic is checked against the node-facing port.", name),
			})
		} else if truthySpecField(item, "applyOnForward") {
			insights = append(insights, policy.Insight{
				Provider: "Calico",
				Layer:    "Calico Host Policy Layer",
				Check:    name + " applyOnForward",
				Status:   "INFO",
				Message:  fmt.Sprintf("Policy %q uses applyOnForward without preDNAT. It applies to forwarded traffic after DNAT, not before DNAT.", name),
			})
		}
	}
	if selectedCount == 0 {
		insights = append(insights, policy.Insight{
			Provider: "Calico",
			Layer:    "Calico Host Policy Path",
			Check:    "external ingress to node",
			Status:   "PASS",
			Message:  "No readable HostEndpoint is selected by Calico applyOnForward/preDNAT/doNotTrack policy. Forwarded traffic is not blocked by host policy based on visible Calico objects.",
		})
		return insights
	}
	insights = append(insights, policy.Insight{
		Provider: "Calico",
		Layer:    "Calico Host Policy Layer",
		Check:    "selected host endpoints",
		Status:   "WARN",
		Message:  "Calico host/forwarded policy selects HostEndpoint(s): " + formatSelectedHostPolicies(selectedByPolicy),
	})
	matches, misses := hostPolicyRuleMatches(hostPolicies, hostEndpoints, tiers, ports)
	if ambiguity := hostNamedPortAmbiguityInsight(hostPolicies, hostEndpoints); ambiguity != nil {
		insights = append(insights, *ambiguity)
	}
	if len(matches) == 0 {
		diagnosis := fmt.Sprintf("Primary issue: Calico host/pre-DNAT policy may default-deny external or forwarded ingress on TCP port(s) %s.", formatPorts(ports))
		if len(misses) > 0 {
			diagnosis += " Closest allow-rule miss: " + misses[0] + "."
		}
		insights = append(insights, policy.Insight{
			Provider:  "Calico",
			Layer:     "Calico Host Policy Path",
			Check:     "external ingress to node",
			Status:    "FAIL",
			Message:   fmt.Sprintf("Calico host/forwarded policy selects HostEndpoint(s), but no matching Allow rule was found for TCP port(s) %s.", formatPorts(ports)),
			Diagnosis: diagnosis,
		})
		if len(misses) > 0 {
			insights = append(insights, policy.Insight{
				Provider: "Calico",
				Layer:    "Calico Host Policy Path",
				Check:    "closest allow-rule miss",
				Status:   "INFO",
				Message:  strings.Join(misses, "; "),
			})
		}
		return insights
	}
	first := matches[0]
	if first.Action == "deny" {
		insights = append(insights, policy.Insight{
			Provider:  "Calico",
			Layer:     "Calico Host Policy Path",
			Check:     "external ingress to node",
			Status:    "FAIL",
			Message:   fmt.Sprintf("First matching Calico host/forwarded action is Deny: %s rule %d in tier %q. Reason: %s.", first.Policy, first.RuleIndex, first.Tier, first.Reason),
			Diagnosis: fmt.Sprintf("Primary issue: Calico host/pre-DNAT policy %s rule %d in tier %q denies external or forwarded ingress before normal Service/backend policy. Reason: %s.", first.Policy, first.RuleIndex, first.Tier, first.Reason),
		})
		return insights
	}
	if first.Action == "allow" {
		insights = append(insights, policy.Insight{
			Provider: "Calico",
			Layer:    "Calico Host Policy Path",
			Check:    "external ingress to node",
			Status:   "PASS",
			Message:  fmt.Sprintf("First matching Calico host/forwarded action is Allow: %s rule %d in tier %q. Reason: %s.", first.Policy, first.RuleIndex, first.Tier, first.Reason),
		})
		return insights
	}
	insights = append(insights, policy.Insight{
		Provider: "Calico",
		Layer:    "Calico Host Policy Path",
		Check:    "external ingress to node",
		Status:   "WARN",
		Message:  fmt.Sprintf("First matching Calico host/forwarded action is %s via %s rule %d. KubeNetMods does not fully model host policy action %q.", first.Action, first.Policy, first.RuleIndex, first.Action),
	})
	return insights
}

func hostPolicyRuleMatches(policies []unstructured.Unstructured, hostEndpoints []unstructured.Unstructured, tiers []unstructured.Unstructured, ports []int32) ([]calicoRuleMatch, []string) {
	var matches []calicoRuleMatch
	var missReasons []string
	portCandidates := make([]calicoPortCandidate, 0, len(ports))
	for _, port := range ports {
		portCandidates = appendUniquePortCandidate(portCandidates, calicoPortCandidate{Number: port})
	}
	for _, item := range policies {
		selected := false
		for _, hep := range hostEndpoints {
			if calicoPolicySelectsHostEndpoint(item, hep) {
				selected = true
				break
			}
		}
		if !selected || !policyHasType(item, "Ingress") {
			continue
		}
		tier := calicoPolicyTier(item)
		policyName := calicoPolicyDisplayName(item)
		rules, _, _ := unstructured.NestedSlice(item.Object, "spec", "ingress")
		for index, raw := range rules {
			rule, ok := raw.(map[string]interface{})
			if !ok {
				continue
			}
			matched, reason := hostPolicyRuleMatchesIngress(rule, portCandidates)
			if !matched {
				action := strings.ToLower(stringFromMap(rule, "action"))
				if action == "" {
					action = "allow"
				}
				if action == "allow" || action == "pass" {
					missReasons = appendUniqueLimited(missReasons, fmt.Sprintf("%s rule %d: %s", policyName, index+1, reason), 3)
				}
				continue
			}
			action := strings.ToLower(stringFromMap(rule, "action"))
			if action == "" {
				action = "allow"
			}
			if action == "log" {
				continue
			}
			matches = append(matches, calicoRuleMatch{
				Policy:      policyName,
				Tier:        tier,
				TierOrder:   calicoTierOrder(tier, tiers),
				PolicyOrder: calicoPolicyOrder(item),
				RuleIndex:   index + 1,
				Action:      action,
				Reason:      reason,
			})
			if action == "allow" || action == "deny" {
				break
			}
		}
	}
	sortRuleMatches(matches)
	return matches, missReasons
}

func hostPolicyRuleMatchesIngress(rule map[string]interface{}, ports []calicoPortCandidate) (bool, string) {
	if !calicoRuleProtocolMatches(rule) {
		return false, "rule protocol does not match tested protocol"
	}
	destination, _ := rule["destination"].(map[string]interface{})
	if !calicoEntityPortsMatch(destination, ports) {
		return false, "destination port/notPort criteria do not match tested external port(s)"
	}
	source, _ := rule["source"].(map[string]interface{})
	if len(source) == 0 {
		return true, "no source criteria, applies broadly to external ingress"
	}
	return true, "source criteria exist; external source identity cannot be fully proven statically"
}

func invalidHostPolicyInsight(item unstructured.Unstructured) *policy.Insight {
	name := calicoPolicyDisplayName(item)
	preDNAT := truthySpecField(item, "preDNAT")
	doNotTrack := truthySpecField(item, "doNotTrack")
	applyOnForward := truthySpecField(item, "applyOnForward")
	if preDNAT && doNotTrack {
		return &policy.Insight{
			Provider:  "Calico",
			Layer:     "Calico Host Policy Layer",
			Check:     name + " invalid host policy",
			Status:    "WARN",
			Message:   fmt.Sprintf("Policy %q sets both preDNAT and doNotTrack. Calico host policy should not set both modes on the same policy; skipping host-path reasoning for this policy.", name),
			Diagnosis: fmt.Sprintf("Calico host policy %q has inconsistent preDNAT/doNotTrack configuration.", name),
		}
	}
	if (preDNAT || doNotTrack) && !applyOnForward {
		mode := "preDNAT"
		if doNotTrack {
			mode = "doNotTrack"
		}
		return &policy.Insight{
			Provider:  "Calico",
			Layer:     "Calico Host Policy Layer",
			Check:     name + " invalid host policy",
			Status:    "WARN",
			Message:   fmt.Sprintf("Policy %q sets %s but does not set applyOnForward=true. Calico requires applyOnForward for %s host policy; skipping host-path reasoning for this policy.", name, mode, mode),
			Diagnosis: fmt.Sprintf("Calico host policy %q has invalid %s/applyOnForward configuration.", name, mode),
		}
	}
	if preDNAT && !policyHasType(item, "Ingress") {
		return &policy.Insight{
			Provider:  "Calico",
			Layer:     "Calico Host Policy Layer",
			Check:     name + " invalid host policy",
			Status:    "WARN",
			Message:   fmt.Sprintf("Policy %q sets preDNAT but is not an Ingress policy. Calico preDNAT policy is only valid for ingress; skipping host-path reasoning for this policy.", name),
			Diagnosis: fmt.Sprintf("Calico host policy %q has invalid preDNAT policy type.", name),
		}
	}
	return nil
}

func hostNamedPortAmbiguityInsight(policies []unstructured.Unstructured, hostEndpoints []unstructured.Unstructured) *policy.Insight {
	var examples []string
	for _, item := range policies {
		selected := false
		for _, hep := range hostEndpoints {
			if calicoPolicySelectsHostEndpoint(item, hep) {
				selected = true
				break
			}
		}
		if !selected {
			continue
		}
		rules, _, _ := unstructured.NestedSlice(item.Object, "spec", "ingress")
		for index, raw := range rules {
			rule, ok := raw.(map[string]interface{})
			if !ok {
				continue
			}
			destination, _ := rule["destination"].(map[string]interface{})
			for _, token := range portTokens(destination) {
				if _, err := fmt.Sscanf(token, "%d", new(int)); err == nil || strings.Contains(token, ":") {
					continue
				}
				examples = appendUniqueLimited(examples, fmt.Sprintf("%s rule %d uses named host port %q", calicoPolicyDisplayName(item), index+1, token), 3)
			}
		}
	}
	if len(examples) == 0 {
		return nil
	}
	return &policy.Insight{
		Provider: "Calico",
		Layer:    "Calico Host Policy Path",
		Check:    "named host ports",
		Status:   "WARN",
		Message:  "Named ports on HostEndpoint-oriented policy are ambiguous without reliable host endpoint port metadata: " + strings.Join(examples, "; ") + ".",
	}
}

func portTokens(entity map[string]interface{}) []string {
	var out []string
	for _, key := range []string{"ports", "notPorts"} {
		raw, ok := entity[key]
		if !ok {
			continue
		}
		items, ok := raw.([]interface{})
		if !ok {
			continue
		}
		for _, item := range items {
			if value, ok := item.(string); ok {
				out = append(out, value)
			}
		}
	}
	return out
}

func calicoPolicySelectsHostEndpoint(item unstructured.Unstructured, hep unstructured.Unstructured) bool {
	selectorRaw, _, _ := unstructured.NestedString(item.Object, "spec", "selector")
	if strings.TrimSpace(selectorRaw) == "" {
		selectorRaw = "all()"
	}
	selector, err := ParseSelector(selectorRaw)
	if err != nil {
		return false
	}
	return selector.Matches(labelsFromUnstructured(hep))
}

func labelsFromUnstructured(item unstructured.Unstructured) map[string]string {
	labels := cloneMap(item.GetLabels())
	if item.GetName() != "" {
		labels["projectcalico.org/name"] = item.GetName()
	}
	return labels
}

func hostEndpointNames(items []unstructured.Unstructured) []string {
	var names []string
	for _, item := range items {
		names = append(names, item.GetName())
	}
	return unique(names)
}

func formatSelectedHostPolicies(selected map[string][]string) string {
	var parts []string
	for policyName, endpoints := range selected {
		parts = append(parts, fmt.Sprintf("%s -> %s", policyName, strings.Join(endpoints, ",")))
	}
	sort.Strings(parts)
	return strings.Join(parts, "; ")
}

func calicoIngressPorts(service *corev1.Service) []int32 {
	if service == nil {
		return nil
	}
	seen := map[int32]bool{}
	var out []int32
	for _, port := range service.Spec.Ports {
		for _, candidate := range []int32{port.Port, port.NodePort} {
			if candidate > 0 && !seen[candidate] {
				seen[candidate] = true
				out = append(out, candidate)
			}
		}
	}
	sort.Slice(out, func(i, j int) bool { return out[i] < out[j] })
	return out
}

func policySelectsTarget(item unstructured.Unstructured, namespace corev1.Namespace, pods []corev1.Pod, sourceNamespace *corev1.Namespace) (bool, string) {
	if item.GetNamespace() != "" && item.GetNamespace() != namespace.Name {
		return false, ""
	}
	namespaceSelector, _, _ := unstructured.NestedString(item.Object, "spec", "namespaceSelector")
	if namespaceSelector != "" {
		selector, err := ParseSelector(namespaceSelector)
		if err != nil {
			return false, fmt.Sprintf("namespaceSelector: %v", err)
		}
		if !selector.Matches(calicoNamespaceLabels(namespace)) {
			return false, ""
		}
	}

	rawSelector, _, _ := unstructured.NestedString(item.Object, "spec", "selector")
	if rawSelector == "" {
		rawSelector = "all()"
	}
	selector, err := ParseSelector(rawSelector)
	if err != nil {
		return false, fmt.Sprintf("selector: %v", err)
	}
	for _, pod := range pods {
		if selector.Matches(calicoPodLabels(pod)) {
			return true, ""
		}
	}
	return false, ""
}

func calicoNamespaceLabels(namespace corev1.Namespace) map[string]string {
	labels := cloneMap(namespace.Labels)
	labels["projectcalico.org/name"] = namespace.Name
	labels["kubernetes.io/metadata.name"] = namespace.Name
	return labels
}

func calicoPodLabels(pod corev1.Pod) map[string]string {
	labels := cloneMap(pod.Labels)
	labels["projectcalico.org/namespace"] = pod.Namespace
	return labels
}

func cloneMap(in map[string]string) map[string]string {
	out := map[string]string{}
	for k, v := range in {
		out[k] = v
	}
	return out
}

func analyzePath(namespaced []unstructured.Unstructured, global []unstructured.Unstructured, tiers []unstructured.Unstructured, networkSets []unstructured.Unstructured, profiles []unstructured.Unstructured, serviceAccounts serviceAccountLabels, targetNamespace corev1.Namespace, targetPods []corev1.Pod, sourceNamespace corev1.Namespace, sourcePod corev1.Pod, service *corev1.Service, ports []int32) []policy.Insight {
	all := append([]unstructured.Unstructured{}, namespaced...)
	all = append(all, global...)
	var insights []policy.Insight
	insights = append(insights, calicoDirectionDecision(policiesForPod(all, sourceNamespace, sourcePod, "Egress"), "egress", tiers, networkSets, profiles, serviceAccounts, sourceNamespace, sourcePod, targetNamespace, targetPods, service, ports))
	insights = append(insights, calicoDirectionDecision(policiesForAnyPod(all, targetNamespace, targetPods, "Ingress"), "ingress", tiers, networkSets, profiles, serviceAccounts, sourceNamespace, sourcePod, targetNamespace, targetPods, service, ports))
	return insights
}

func analyzeDNSEgress(namespaced []unstructured.Unstructured, global []unstructured.Unstructured, tiers []unstructured.Unstructured, networkSets []unstructured.Unstructured, profiles []unstructured.Unstructured, serviceAccounts serviceAccountLabels, sourceNamespace corev1.Namespace, sourcePod corev1.Pod, dns DNSContext) []policy.Insight {
	if len(dns.Nameservers) == 0 {
		return nil
	}
	all := append([]unstructured.Unstructured{}, namespaced...)
	all = append(all, global...)
	policies := policiesForPod(all, sourceNamespace, sourcePod, "Egress")
	if len(policies) == 0 {
		for _, resolver := range unique(dns.Nameservers) {
			if decision, ok := calicoDNSProfileFallbackDecision(profiles, networkSets, serviceAccounts, sourceNamespace, sourcePod, resolver, dns); ok && decision.Status != "PASS" {
				decision.Message = "No Calico egress policies select the source pod for DNS traffic. " + decision.Message
				return []policy.Insight{decision}
			}
		}
		return []policy.Insight{{
			Provider: "Calico",
			Layer:    "Calico DNS Policy Path",
			Check:    "source DNS egress",
			Status:   "PASS",
			Message:  "No Calico egress policies select the source pod for DNS traffic.",
		}}
	}
	for _, resolver := range unique(dns.Nameservers) {
		decision := calicoDNSDecision(policies, tiers, networkSets, profiles, serviceAccounts, sourceNamespace, sourcePod, resolver, dns)
		if decision.Status == "FAIL" || decision.Status == "WARN" {
			return []policy.Insight{decision}
		}
	}
	return []policy.Insight{{
		Provider: "Calico",
		Layer:    "Calico DNS Policy Path",
		Check:    "source DNS egress",
		Status:   "PASS",
		Message:  fmt.Sprintf("Calico egress policy appears to allow source pod runtime DNS resolver(s): %s.", strings.Join(unique(dns.Nameservers), ", ")),
	}}
}

func calicoDNSDecision(policies []unstructured.Unstructured, tiers []unstructured.Unstructured, networkSets []unstructured.Unstructured, profiles []unstructured.Unstructured, serviceAccounts serviceAccountLabels, sourceNamespace corev1.Namespace, sourcePod corev1.Pod, resolver string, dns DNSContext) policy.Insight {
	var matches []calicoRuleMatch
	for _, item := range policies {
		tier := calicoPolicyTier(item)
		policyName := calicoPolicyDisplayName(item)
		rules, _, _ := unstructured.NestedSlice(item.Object, "spec", "egress")
		for index, raw := range rules {
			rule, ok := raw.(map[string]interface{})
			matched, reason := ruleMatchesDNSResolver(rule, networkSets, serviceAccounts, sourceNamespace, sourcePod, resolver, dns)
			if !ok || !matched {
				continue
			}
			action := strings.ToLower(stringFromMap(rule, "action"))
			if action == "" {
				action = "allow"
			}
			if action == "log" {
				continue
			}
			matches = append(matches, calicoRuleMatch{
				Policy:      policyName,
				Tier:        tier,
				TierOrder:   calicoTierOrder(tier, tiers),
				PolicyOrder: calicoPolicyOrder(item),
				RuleIndex:   index + 1,
				Action:      action,
				Reason:      reason,
			})
		}
	}
	sortRuleMatches(matches)
	if len(matches) > 0 && matches[0].Action == "pass" {
		pass := matches[0]
		for _, candidate := range matches[1:] {
			if candidate.TierOrder > pass.TierOrder {
				matches[0] = candidate
				break
			}
		}
		if matches[0] == pass {
			if fallback, ok := calicoDNSProfileFallbackDecision(profiles, networkSets, serviceAccounts, sourceNamespace, sourcePod, resolver, dns); ok {
				fallback.Message = fmt.Sprintf("Calico DNS egress first matching action is Pass in tier %q via %s. %s", pass.Tier, pass.Policy, fallback.Message)
				if fallback.Diagnosis != "" {
					fallback.Diagnosis = "Calico DNS Pass falls through to workload profile evaluation. " + fallback.Diagnosis
				}
				return fallback
			}
			return policy.Insight{
				Provider: "Calico",
				Layer:    "Calico DNS Policy Path",
				Check:    "source DNS egress",
				Status:   "WARN",
				Message:  fmt.Sprintf("Calico DNS egress first matching action is Pass in tier %q via %s. No inferred workload profile decision could be made.", pass.Tier, pass.Policy),
			}
		}
	}
	if len(matches) > 0 {
		first := matches[0]
		if first.Action == "deny" {
			return policy.Insight{
				Provider:  "Calico",
				Layer:     "Calico DNS Policy Path",
				Check:     "source DNS egress",
				Status:    "FAIL",
				Message:   fmt.Sprintf("Calico denies DNS egress from source pod %q to runtime resolver %s. First match: %s in tier %q. Reason: %s.", sourcePod.Name, describeResolver(resolver), first.Policy, first.Tier, first.Reason),
				Diagnosis: fmt.Sprintf("Primary issue: Calico policy denies DNS egress from source pod %q to its runtime resolver %s.", sourcePod.Name, describeResolver(resolver)),
			}
		}
		if first.Action == "allow" {
			return policy.Insight{
				Provider: "Calico",
				Layer:    "Calico DNS Policy Path",
				Check:    "source DNS egress",
				Status:   "PASS",
				Message:  fmt.Sprintf("Calico allows DNS egress from source pod %q to runtime resolver %s. First match: %s in tier %q.", sourcePod.Name, describeResolver(resolver), first.Policy, first.Tier),
			}
		}
	}
	names := calicoPolicyNames(policies)
	return policy.Insight{
		Provider:  "Calico",
		Layer:     "Calico DNS Policy Path",
		Check:     "source DNS egress",
		Status:    "FAIL",
		Message:   fmt.Sprintf("Calico egress policy selects source pod %q, but no allow rule obviously permits DNS to runtime resolver %s. Policies: %s.", sourcePod.Name, describeResolver(resolver), strings.Join(names, ", ")),
		Diagnosis: fmt.Sprintf("Primary issue: Calico egress policy does not allow the source pod runtime DNS resolver %s. Add UDP/TCP 53 egress for that resolver or adjust the pod DNS path.", describeResolver(resolver)),
	}
}

func calicoDNSProfileFallbackDecision(profiles []unstructured.Unstructured, networkSets []unstructured.Unstructured, serviceAccounts serviceAccountLabels, sourceNamespace corev1.Namespace, sourcePod corev1.Pod, resolver string, dns DNSContext) (policy.Insight, bool) {
	selected := calicoProfilesForPod(profiles, sourceNamespace, sourcePod)
	if len(selected) == 0 {
		return policy.Insight{}, false
	}
	var checked []string
	for _, profile := range selected {
		name := profile.GetName()
		checked = append(checked, name)
		rules, _, _ := unstructured.NestedSlice(profile.Object, "spec", "egress")
		for index, raw := range rules {
			rule, ok := raw.(map[string]interface{})
			if !ok {
				continue
			}
			matched, reason := ruleMatchesDNSResolver(rule, networkSets, serviceAccounts, sourceNamespace, sourcePod, resolver, dns)
			if !matched {
				continue
			}
			action := strings.ToLower(stringFromMap(rule, "action"))
			if action == "" {
				action = "allow"
			}
			if action == "log" {
				continue
			}
			if action == "allow" {
				return policy.Insight{
					Provider: "Calico",
					Layer:    "Calico DNS Policy Path",
					Check:    "source DNS egress",
					Status:   "PASS",
					Message:  fmt.Sprintf("Calico workload profile fallback allows DNS to runtime resolver %s via profile %q rule %d.", describeResolver(resolver), name, index+1),
				}, true
			}
			if action == "deny" {
				return policy.Insight{
					Provider:  "Calico",
					Layer:     "Calico DNS Policy Path",
					Check:     "source DNS egress",
					Status:    "FAIL",
					Message:   fmt.Sprintf("Calico workload profile fallback denies DNS to runtime resolver %s via profile %q rule %d. Reason: %s.", describeResolver(resolver), name, index+1, reason),
					Diagnosis: fmt.Sprintf("Primary issue: Calico workload profile %q denies DNS egress from source pod %q to runtime resolver %s.", name, sourcePod.Name, describeResolver(resolver)),
				}, true
			}
		}
	}
	return policy.Insight{
		Provider:  "Calico",
		Layer:     "Calico DNS Policy Path",
		Check:     "source DNS egress",
		Status:    "FAIL",
		Message:   fmt.Sprintf("Calico workload profile fallback found profile(s) %s, but no matching Allow rule was found for DNS resolver %s.", strings.Join(checked, ", "), describeResolver(resolver)),
		Diagnosis: fmt.Sprintf("Primary issue: Calico workload profile fallback default-denies DNS egress to runtime resolver %s.", describeResolver(resolver)),
	}, true
}

func policiesForPod(policies []unstructured.Unstructured, namespace corev1.Namespace, pod corev1.Pod, direction string) []unstructured.Unstructured {
	var out []unstructured.Unstructured
	for _, item := range policies {
		if !policyHasType(item, direction) {
			continue
		}
		matches, _ := policySelectsTarget(item, namespace, []corev1.Pod{pod}, nil)
		if matches {
			out = append(out, item)
		}
	}
	return out
}

func policiesForAnyPod(policies []unstructured.Unstructured, namespace corev1.Namespace, pods []corev1.Pod, direction string) []unstructured.Unstructured {
	var out []unstructured.Unstructured
	for _, item := range policies {
		if !policyHasType(item, direction) {
			continue
		}
		matches, _ := policySelectsTarget(item, namespace, pods, nil)
		if matches {
			out = append(out, item)
		}
	}
	return out
}

type calicoRuleMatch struct {
	Policy      string
	Tier        string
	TierOrder   float64
	PolicyOrder float64
	RuleIndex   int
	Action      string
	Reason      string
}

type calicoPortCandidate struct {
	Number int32
	Name   string
}

func calicoDirectionDecision(policies []unstructured.Unstructured, direction string, tiers []unstructured.Unstructured, networkSets []unstructured.Unstructured, profiles []unstructured.Unstructured, serviceAccounts serviceAccountLabels, sourceNamespace corev1.Namespace, sourcePod corev1.Pod, targetNamespace corev1.Namespace, targetPods []corev1.Pod, service *corev1.Service, ports []int32) policy.Insight {
	check := "source egress to target"
	if direction == "ingress" {
		check = "target ingress from source"
	}
	if len(policies) == 0 {
		if fallback, ok := calicoProfileFallbackDecision(direction, profiles, networkSets, serviceAccounts, sourceNamespace, sourcePod, targetNamespace, targetPods, service, ports); ok {
			fallback.Check = check
			fallback.Message = fmt.Sprintf("No Calico %s policies select this side of the path. %s", direction, fallback.Message)
			return fallback
		}
		return policy.Insight{Provider: "Calico", Layer: "Calico Policy Path", Check: check, Status: "PASS", Message: fmt.Sprintf("No Calico %s policies select this side of the path.", direction)}
	}
	names := calicoPolicyNames(policies)
	var matches []calicoRuleMatch
	var missReasons []string
	for _, item := range policies {
		tier := calicoPolicyTier(item)
		policyName := calicoPolicyDisplayName(item)
		rules, _, _ := unstructured.NestedSlice(item.Object, "spec", direction)
		if len(rules) == 0 {
			rules, _, _ = unstructured.NestedSlice(item.Object, "spec", strings.ToLower(direction))
		}
		for index, raw := range rules {
			rule, ok := raw.(map[string]interface{})
			matched, reason := ruleMatchesPath(rule, direction, networkSets, serviceAccounts, sourceNamespace, sourcePod, targetNamespace, targetPods, service, ports)
			if !ok || !matched {
				if ok {
					action := strings.ToLower(stringFromMap(rule, "action"))
					if action == "" {
						action = "allow"
					}
					if (action == "allow" || action == "pass") && reason != "rule protocol does not match tested protocol" {
						missReasons = appendUniqueLimited(missReasons, fmt.Sprintf("%s rule %d: %s", policyName, index+1, reason), 3)
					}
				}
				continue
			}
			action := strings.ToLower(stringFromMap(rule, "action"))
			if action == "" {
				action = "allow"
			}
			if action == "log" {
				continue
			}
			matches = append(matches, calicoRuleMatch{
				Policy:      policyName,
				Tier:        tier,
				TierOrder:   calicoTierOrder(tier, tiers),
				PolicyOrder: calicoPolicyOrder(item),
				RuleIndex:   index + 1,
				Action:      action,
				Reason:      reason,
			})
			if action == "allow" || action == "deny" {
				break
			}
		}
	}
	sortRuleMatches(matches)
	if len(matches) > 0 {
		first, ok := effectiveCalicoMatchAfterPass(matches)
		if !ok {
			pass := matches[0]
			if fallback, fallbackOK := calicoProfileFallbackDecision(direction, profiles, networkSets, serviceAccounts, sourceNamespace, sourcePod, targetNamespace, targetPods, service, ports); fallbackOK {
				fallback.Check = check
				fallback.Message = fmt.Sprintf("Calico %s first matching action is Pass in tier %q via %s. %s", direction, pass.Tier, pass.Policy, fallback.Message)
				if fallback.Diagnosis != "" {
					fallback.Diagnosis = fmt.Sprintf("Calico Pass falls through to workload profile evaluation. %s", fallback.Diagnosis)
				}
				return fallback
			}
			return policy.Insight{Provider: "Calico", Layer: "Calico Policy Path", Check: check, Status: "WARN", Message: fmt.Sprintf("Calico %s first matching action is Pass in tier %q via %s. No later tier match was found, and no inferred workload profile decision could be made.", direction, pass.Tier, pass.Policy)}
		}
		if first.Action == "deny" {
			additionalDenies := additionalCalicoDenies(matches, first)
			message := fmt.Sprintf("For the target service path, first matching Calico action is Deny: %s %s in tier %q. Reason: %s.", first.Policy, direction, first.Tier, first.Reason)
			if len(additionalDenies) > 0 {
				message += " Additional matching Deny policies also select this path: " + strings.Join(additionalDenies, ", ") + "."
			}
			return policy.Insight{
				Provider:  "Calico",
				Layer:     "Calico Policy Path",
				Check:     check,
				Status:    "FAIL",
				Message:   message,
				Diagnosis: fmt.Sprintf("Primary issue: Calico %s rule %d in tier %q denies the %s path between source pod %q and Service %q. Reason: %s.", first.Policy, first.RuleIndex, first.Tier, direction, sourcePod.Name, calicoServiceName(service), first.Reason),
			}
		}
		if first.Action == "allow" {
			return policy.Insight{Provider: "Calico", Layer: "Calico Policy Path", Check: check, Status: "PASS", Message: fmt.Sprintf("For the target service path, first matching Calico action is Allow: %s %s in tier %q. Reason: %s.", first.Policy, direction, first.Tier, first.Reason)}
		}
	}
	message := fmt.Sprintf("Calico %s policy selects this side of the path (%s), but no matching Allow rule was found for TCP port(s) %s.", direction, strings.Join(names, ", "), formatPorts(ports))
	diagnosis := fmt.Sprintf("Calico %s default-deny likely blocks traffic between source pod %q and Service %q. Policies: %s.", direction, sourcePod.Name, calicoServiceName(service), strings.Join(names, ", "))
	if len(missReasons) > 0 {
		message += " Closest allow-rule miss: " + strings.Join(missReasons, "; ") + "."
		diagnosis += " Closest allow-rule miss: " + missReasons[0] + "."
	}
	return policy.Insight{
		Provider:  "Calico",
		Layer:     "Calico Policy Path",
		Check:     check,
		Status:    "FAIL",
		Message:   message,
		Diagnosis: diagnosis,
	}
}

func calicoProfileFallbackDecision(direction string, profiles []unstructured.Unstructured, networkSets []unstructured.Unstructured, serviceAccounts serviceAccountLabels, sourceNamespace corev1.Namespace, sourcePod corev1.Pod, targetNamespace corev1.Namespace, targetPods []corev1.Pod, service *corev1.Service, ports []int32) (policy.Insight, bool) {
	if len(profiles) == 0 {
		return policy.Insight{}, false
	}
	if direction == "egress" {
		return calicoProfilesForEndpointDecision(direction, profiles, networkSets, serviceAccounts, sourceNamespace, sourcePod, targetNamespace, targetPods, service, ports)
	}
	if len(targetPods) == 0 {
		return policy.Insight{}, false
	}
	var allowed []string
	for _, targetPod := range targetPods {
		insight, ok := calicoProfilesForEndpointDecision(direction, profiles, networkSets, serviceAccounts, targetNamespace, targetPod, sourceNamespace, []corev1.Pod{sourcePod}, service, ports)
		if !ok {
			return policy.Insight{}, false
		}
		if insight.Status == "FAIL" {
			insight.Message = fmt.Sprintf("Calico workload profile fallback for target pod %q denies the ingress path. %s", targetPod.Name, insight.Message)
			if insight.Diagnosis != "" {
				insight.Diagnosis = fmt.Sprintf("Calico workload profile fallback denies ingress to target pod %q. %s", targetPod.Name, insight.Diagnosis)
			}
			return insight, true
		}
		if insight.Status == "WARN" {
			return insight, true
		}
		allowed = append(allowed, targetPod.Name)
	}
	return policy.Insight{
		Provider: "Calico",
		Layer:    "Calico Policy Path",
		Status:   "PASS",
		Message:  fmt.Sprintf("Calico workload profile fallback allows ingress to target pod(s): %s.", strings.Join(allowed, ", ")),
	}, true
}

func calicoProfilesForEndpointDecision(direction string, profiles []unstructured.Unstructured, networkSets []unstructured.Unstructured, serviceAccounts serviceAccountLabels, endpointNamespace corev1.Namespace, endpointPod corev1.Pod, peerNamespace corev1.Namespace, peerPods []corev1.Pod, service *corev1.Service, ports []int32) (policy.Insight, bool) {
	selected := calicoProfilesForPod(profiles, endpointNamespace, endpointPod)
	if len(selected) == 0 {
		return policy.Insight{}, false
	}
	sourceNamespace, sourcePod := endpointNamespace, endpointPod
	targetNamespace, targetPods := peerNamespace, peerPods
	if direction == "ingress" {
		sourceNamespace, sourcePod = peerNamespace, peerPods[0]
		targetNamespace, targetPods = endpointNamespace, []corev1.Pod{endpointPod}
	}
	var checked []string
	lowerDirection := strings.ToLower(direction)
	for _, profile := range selected {
		name := profile.GetName()
		checked = append(checked, name)
		rules, _, _ := unstructured.NestedSlice(profile.Object, "spec", lowerDirection)
		for index, raw := range rules {
			rule, ok := raw.(map[string]interface{})
			if !ok {
				continue
			}
			matched, reason := ruleMatchesPath(rule, lowerDirection, networkSets, serviceAccounts, sourceNamespace, sourcePod, targetNamespace, targetPods, service, ports)
			if !matched {
				continue
			}
			action := strings.ToLower(stringFromMap(rule, "action"))
			if action == "" {
				action = "allow"
			}
			if action == "log" {
				continue
			}
			if action == "allow" {
				return policy.Insight{
					Provider: "Calico",
					Layer:    "Calico Policy Path",
					Status:   "PASS",
					Message:  fmt.Sprintf("Calico workload profile fallback allows %s via profile %q rule %d. Reason: %s.", lowerDirection, name, index+1, reason),
				}, true
			}
			if action == "deny" {
				return policy.Insight{
					Provider:  "Calico",
					Layer:     "Calico Policy Path",
					Status:    "FAIL",
					Message:   fmt.Sprintf("Calico workload profile fallback denies %s via profile %q rule %d. Reason: %s.", lowerDirection, name, index+1, reason),
					Diagnosis: fmt.Sprintf("Primary issue: Calico workload profile %q rule %d denies the %s path. Reason: %s.", name, index+1, lowerDirection, reason),
				}, true
			}
		}
	}
	return policy.Insight{
		Provider:  "Calico",
		Layer:     "Calico Policy Path",
		Status:    "FAIL",
		Message:   fmt.Sprintf("Calico workload profile fallback found profile(s) %s, but no matching Allow rule was found for TCP port(s) %s.", strings.Join(checked, ", "), formatPorts(ports)),
		Diagnosis: fmt.Sprintf("Primary issue: Calico workload profile fallback default-denies the %s path because no matching Allow rule was found.", lowerDirection),
	}, true
}

func calicoProfilesForPod(profiles []unstructured.Unstructured, namespace corev1.Namespace, pod corev1.Pod) []unstructured.Unstructured {
	names := []string{"kns." + namespace.Name}
	serviceAccountName := pod.Spec.ServiceAccountName
	if serviceAccountName == "" {
		serviceAccountName = "default"
	}
	names = append(names, "ksa."+namespace.Name+"."+serviceAccountName)
	byName := map[string]unstructured.Unstructured{}
	for _, profile := range profiles {
		byName[profile.GetName()] = profile
	}
	var out []unstructured.Unstructured
	for _, name := range names {
		if profile, ok := byName[name]; ok {
			out = append(out, profile)
		}
	}
	return out
}

func sortRuleMatches(matches []calicoRuleMatch) {
	sort.SliceStable(matches, func(i, j int) bool {
		if matches[i].TierOrder != matches[j].TierOrder {
			return matches[i].TierOrder < matches[j].TierOrder
		}
		if matches[i].PolicyOrder != matches[j].PolicyOrder {
			return matches[i].PolicyOrder < matches[j].PolicyOrder
		}
		if matches[i].RuleIndex != matches[j].RuleIndex {
			return matches[i].RuleIndex < matches[j].RuleIndex
		}
		return matches[i].Policy < matches[j].Policy
	})
}

func effectiveCalicoMatchAfterPass(matches []calicoRuleMatch) (calicoRuleMatch, bool) {
	if len(matches) == 0 {
		return calicoRuleMatch{}, false
	}
	current := matches[0]
	for current.Action == "pass" {
		found := false
		for _, candidate := range matches {
			if candidate.TierOrder > current.TierOrder {
				current = candidate
				found = true
				break
			}
		}
		if !found {
			return current, false
		}
	}
	return current, true
}

func additionalCalicoDenies(matches []calicoRuleMatch, first calicoRuleMatch) []string {
	var out []string
	for _, match := range matches {
		if match.Action != "deny" || match.Policy == first.Policy {
			continue
		}
		out = appendUniqueLimited(out, match.Policy, 4)
	}
	return out
}

func appendUniqueLimited(items []string, value string, limit int) []string {
	if value == "" {
		return items
	}
	for _, item := range items {
		if item == value {
			return items
		}
	}
	if limit > 0 && len(items) >= limit {
		return items
	}
	return append(items, value)
}

func ruleMatchesPath(rule map[string]interface{}, direction string, networkSets []unstructured.Unstructured, serviceAccounts serviceAccountLabels, sourceNamespace corev1.Namespace, sourcePod corev1.Pod, targetNamespace corev1.Namespace, targetPods []corev1.Pod, service *corev1.Service, ports []int32) (bool, string) {
	if !calicoRuleProtocolMatches(rule) {
		return false, "rule protocol does not match tested protocol"
	}
	entityKey := "destination"
	if direction == "ingress" {
		entityKey = "source"
	}
	entity, _ := rule[entityKey].(map[string]interface{})
	if !calicoEntityPortsMatch(entity, calicoPathPortCandidates(ports, service, targetPods)) {
		return false, "port/notPort criteria do not match tested path"
	}
	if direction == "egress" {
		if sourceEntity, _ := rule["source"].(map[string]interface{}); len(sourceEntity) > 0 {
			if ok, reason := calicoEntityMatchesPod(sourceEntity, sourceNamespace, sourcePod, nil, networkSets, serviceAccounts); !ok {
				return false, "source criteria do not match source pod: " + reason
			}
		}
		if len(entity) == 0 {
			return true, "no destination criteria, matches all destinations"
		}
		var missReasons []string
		for _, pod := range targetPods {
			if ok, reason := calicoEntityMatchesPod(entity, targetNamespace, pod, service, networkSets, serviceAccounts); ok {
				return true, reason
			} else {
				missReasons = appendUniqueLimited(missReasons, reason, 2)
			}
		}
		if len(missReasons) > 0 {
			return false, "destination criteria do not match target service/pods: " + strings.Join(missReasons, "; ")
		}
		return false, "destination criteria do not match target service/pods"
	}
	if destinationEntity, _ := rule["destination"].(map[string]interface{}); len(destinationEntity) > 0 {
		for _, pod := range targetPods {
			if ok, reason := calicoEntityMatchesPod(destinationEntity, targetNamespace, pod, service, networkSets, serviceAccounts); ok {
				return calicoEntityMatchesPod(entity, sourceNamespace, sourcePod, nil, networkSets, serviceAccounts)
			} else if len(targetPods) == 1 {
				return false, "destination criteria do not match target pod: " + reason
			}
		}
		return false, "destination criteria do not match target pod"
	}
	if len(entity) == 0 {
		return true, "no source criteria, matches all sources"
	}
	return calicoEntityMatchesPod(entity, sourceNamespace, sourcePod, nil, networkSets, serviceAccounts)
}

func ruleMatchesDNSResolver(rule map[string]interface{}, networkSets []unstructured.Unstructured, serviceAccounts serviceAccountLabels, sourceNamespace corev1.Namespace, sourcePod corev1.Pod, resolver string, dns DNSContext) (bool, string) {
	if !calicoDNSProtocolMatches(rule) {
		return false, "rule protocol does not match DNS UDP/TCP"
	}
	entity, _ := rule["destination"].(map[string]interface{})
	if !calicoEntityPortsMatch(entity, []calicoPortCandidate{{Number: 53}}) {
		return false, "DNS port 53 is not allowed by port/notPort criteria"
	}
	if len(entity) == 0 {
		return true, "no destination criteria, matches DNS resolver"
	}

	resolverNamespace := corev1.Namespace{ObjectMeta: metav1.ObjectMeta{Name: "kube-system"}}
	if dns.KubeSystemNS != nil {
		resolverNamespace = *dns.KubeSystemNS
	}
	fakeResolverPod := corev1.Pod{
		ObjectMeta: metav1.ObjectMeta{Name: "runtime-dns-resolver", Namespace: resolverNamespace.Name},
		Status:     corev1.PodStatus{PodIP: resolver},
	}
	var fakeService *corev1.Service
	if dns.CoreDNSServiceIP != "" && resolver == dns.CoreDNSServiceIP {
		fakeService = &corev1.Service{
			ObjectMeta: metav1.ObjectMeta{Name: "kube-dns", Namespace: "kube-system"},
			Spec:       corev1.ServiceSpec{ClusterIP: dns.CoreDNSServiceIP},
		}
	}
	if ok, reason := calicoEntityMatchesPod(entity, resolverNamespace, fakeResolverPod, fakeService, networkSets, serviceAccounts); ok {
		return true, reason
	}

	for _, pod := range dnsPodsForResolver(resolver, dns) {
		ns := resolverNamespace
		if pod.Namespace != "" && pod.Namespace != resolverNamespace.Name {
			ns = corev1.Namespace{ObjectMeta: metav1.ObjectMeta{Name: pod.Namespace}}
		}
		if ok, reason := calicoEntityMatchesPod(entity, ns, pod, fakeService, networkSets, serviceAccounts); ok {
			return true, reason
		}
	}
	return false, "destination criteria do not match the source pod runtime DNS resolver"
}

func calicoRuleProtocolMatches(rule map[string]interface{}) bool {
	proto := strings.ToLower(fmt.Sprintf("%v", rule["protocol"]))
	return proto == "" || proto == "<nil>" || proto == "tcp"
}

func calicoDNSProtocolMatches(rule map[string]interface{}) bool {
	proto := strings.ToLower(fmt.Sprintf("%v", rule["protocol"]))
	return proto == "" || proto == "<nil>" || proto == "udp" || proto == "tcp"
}

func calicoEntityPortsMatch(entity map[string]interface{}, ports []calicoPortCandidate) bool {
	if entity == nil {
		return true
	}
	if len(ports) == 0 {
		return true
	}
	candidates := append([]calicoPortCandidate{}, ports...)
	if raw, exists := entity["ports"]; exists {
		items, ok := raw.([]interface{})
		if !ok || len(items) == 0 {
			return len(candidates) > 0
		}
		var included []calicoPortCandidate
		for _, item := range items {
			for _, port := range candidates {
				if portTokenMatches(item, port) && !containsPortCandidate(included, port) {
					included = append(included, port)
				}
			}
		}
		if len(included) == 0 {
			return false
		}
		candidates = included
	}
	if raw, exists := entity["notPorts"]; exists {
		items, ok := raw.([]interface{})
		if ok {
			var remaining []calicoPortCandidate
			for _, port := range candidates {
				excluded := false
				for _, item := range items {
					if portTokenMatches(item, port) {
						excluded = true
						break
					}
				}
				if !excluded {
					remaining = append(remaining, port)
				}
			}
			candidates = remaining
			if len(candidates) == 0 {
				return false
			}
		}
	}
	return len(candidates) > 0
}

func calicoPathPortCandidates(ports []int32, service *corev1.Service, pods []corev1.Pod) []calicoPortCandidate {
	var candidates []calicoPortCandidate
	for _, port := range ports {
		candidates = appendUniquePortCandidate(candidates, calicoPortCandidate{Number: port})
	}
	if service != nil {
		for _, servicePort := range service.Spec.Ports {
			if containsPortNumber(ports, servicePort.Port) && servicePort.Name != "" {
				candidates = appendUniquePortCandidate(candidates, calicoPortCandidate{Number: servicePort.Port, Name: servicePort.Name})
			}
			if servicePort.TargetPort.Type == intstr.String && servicePort.TargetPort.StrVal != "" {
				number := servicePort.Port
				for _, pod := range pods {
					for _, container := range pod.Spec.Containers {
						for _, containerPort := range container.Ports {
							if containerPort.Name == servicePort.TargetPort.StrVal {
								number = containerPort.ContainerPort
							}
						}
					}
				}
				candidates = appendUniquePortCandidate(candidates, calicoPortCandidate{Number: number, Name: servicePort.TargetPort.StrVal})
			}
		}
	}
	for _, pod := range pods {
		for _, container := range pod.Spec.Containers {
			for _, containerPort := range container.Ports {
				if containerPort.Name != "" && containsPortNumber(ports, containerPort.ContainerPort) {
					candidates = appendUniquePortCandidate(candidates, calicoPortCandidate{Number: containerPort.ContainerPort, Name: containerPort.Name})
				}
			}
		}
	}
	return candidates
}

func portTokenMatches(token interface{}, port calicoPortCandidate) bool {
	switch value := token.(type) {
	case int:
		return port.Number == int32(value)
	case int32:
		return port.Number == value
	case int64:
		return port.Number == int32(value)
	case float64:
		return port.Number == int32(value)
	case string:
		var parsed int
		if _, err := fmt.Sscanf(value, "%d", &parsed); err == nil {
			return port.Number == int32(parsed)
		}
		if strings.Contains(value, ":") {
			parts := strings.SplitN(value, ":", 2)
			var start, end int
			if _, err := fmt.Sscanf(parts[0], "%d", &start); err == nil {
				if _, err := fmt.Sscanf(parts[1], "%d", &end); err == nil && start <= end {
					if port.Number >= int32(start) && port.Number <= int32(end) {
						return true
					}
				}
			}
		}
		return port.Name != "" && value == port.Name
	case map[string]interface{}:
		min, minOK := numericField(value, "min")
		max, maxOK := numericField(value, "max")
		if minOK && maxOK {
			if port.Number >= min && port.Number <= max {
				return true
			}
		}
	}
	return false
}

func calicoEntityMatchesPod(entity map[string]interface{}, namespace corev1.Namespace, pod corev1.Pod, service *corev1.Service, networkSets []unstructured.Unstructured, serviceAccounts serviceAccountLabels) (bool, string) {
	if entity == nil {
		return true, "no entity criteria, matches all packets"
	}
	if nets, ok := stringSliceField(entity, "nets"); ok && len(nets) > 0 {
		if !ipInAnyCIDR(pod.Status.PodIP, nets) && (service == nil || !ipInAnyCIDR(service.Spec.ClusterIP, nets)) {
			return false, "nets do not include tested service/pod IPs"
		}
	}
	if notNets, ok := stringSliceField(entity, "notNets"); ok && len(notNets) > 0 {
		if ipInAnyCIDR(pod.Status.PodIP, notNets) || (service != nil && ipInAnyCIDR(service.Spec.ClusterIP, notNets)) {
			return false, "notNets exclude tested service/pod IPs"
		}
	}
	if !calicoServicesMatch(entity, service) {
		return false, "service match does not target this Service"
	}
	if !calicoServiceAccountMatches(entity, pod, serviceAccounts) {
		return false, "serviceAccount criteria do not match peer pod service account"
	}
	if selectorRaw := stringFromMap(entity, "selector"); selectorRaw != "" {
		if calicoNetworkSetMatchesAny(networkSets, selectorRaw, stringFromMap(entity, "namespaceSelector"), namespace, pod, service) {
			return true, "selector matches NetworkSet/GlobalNetworkSet"
		}
	}
	if nsSelectorRaw := stringFromMap(entity, "namespaceSelector"); nsSelectorRaw != "" {
		selector, err := ParseSelector(nsSelectorRaw)
		if err != nil || !selector.Matches(calicoNamespaceLabels(namespace)) {
			return false, "namespaceSelector does not match peer namespace"
		}
	}
	if selectorRaw := stringFromMap(entity, "selector"); selectorRaw != "" {
		selector, err := ParseSelector(selectorRaw)
		if err != nil || !selector.Matches(calicoPodLabels(pod)) {
			return false, "selector does not match peer pod or network set"
		}
	}
	if notSelectorRaw := stringFromMap(entity, "notSelector"); notSelectorRaw != "" {
		selector, err := ParseSelector(notSelectorRaw)
		if err == nil && selector.Matches(calicoPodLabels(pod)) {
			return false, "notSelector excludes peer pod"
		}
		if calicoNetworkSetMatchesAny(networkSets, notSelectorRaw, stringFromMap(entity, "namespaceSelector"), namespace, pod, service) {
			return false, "notSelector excludes matching NetworkSet/GlobalNetworkSet"
		}
	}
	return true, "IP/service/selector criteria match"
}

func policyHasType(item unstructured.Unstructured, direction string) bool {
	rawTypes, _, _ := unstructured.NestedStringSlice(item.Object, "spec", "types")
	if len(rawTypes) == 0 {
		rules, _, _ := unstructured.NestedSlice(item.Object, "spec", strings.ToLower(direction))
		if strings.EqualFold(direction, "Ingress") {
			return true
		}
		return len(rules) > 0
	}
	for _, policyType := range rawTypes {
		if strings.EqualFold(policyType, direction) {
			return true
		}
	}
	return false
}

func calicoServicesMatch(entity map[string]interface{}, service *corev1.Service) bool {
	raw, ok := entity["services"]
	if !ok {
		return true
	}
	if service == nil {
		return false
	}
	services, ok := raw.([]interface{})
	if !ok {
		if item, ok := raw.(map[string]interface{}); ok {
			return calicoServiceEntryMatches(item, service)
		}
		return false
	}
	if len(services) == 0 {
		return true
	}
	for _, entry := range services {
		item, ok := entry.(map[string]interface{})
		if !ok {
			continue
		}
		if calicoServiceEntryMatches(item, service) {
			return true
		}
	}
	return false
}

func calicoServiceEntryMatches(item map[string]interface{}, service *corev1.Service) bool {
	name := stringFromMap(item, "name")
	namespace := stringFromMap(item, "namespace")
	if namespace == "" {
		namespace = service.Namespace
	}
	return name == service.Name && namespace == service.Namespace
}

func calicoServiceAccountMatches(entity map[string]interface{}, pod corev1.Pod, serviceAccounts serviceAccountLabels) bool {
	raw, ok := entity["serviceAccounts"]
	if !ok || raw == nil {
		return true
	}
	saMap, ok := raw.(map[string]interface{})
	if !ok {
		return true
	}
	names, ok := stringSliceField(saMap, "names")
	if ok && len(names) > 0 {
		podSA := pod.Spec.ServiceAccountName
		if podSA == "" {
			podSA = "default"
		}
		if !containsString(names, podSA) {
			return false
		}
	}
	if selector := stringFromMap(saMap, "selector"); selector != "" {
		labels := serviceAccounts[serviceAccountKey(pod.Namespace, pod.Spec.ServiceAccountName)]
		if len(labels) == 0 {
			return false
		}
		parsed, err := ParseSelector(selector)
		if err != nil || !parsed.Matches(labels) {
			return false
		}
	}
	return true
}

func calicoNetworkSetMatchesAny(networkSets []unstructured.Unstructured, selectorRaw string, namespaceSelectorRaw string, peerNamespace corev1.Namespace, pod corev1.Pod, service *corev1.Service) bool {
	if selectorRaw == "" || len(networkSets) == 0 {
		return false
	}
	selector, err := ParseSelector(selectorRaw)
	if err != nil {
		return false
	}
	for _, networkSet := range networkSets {
		if !selector.Matches(calicoUnstructuredLabels(networkSet)) {
			continue
		}
		if !calicoNetworkSetNamespaceMatches(networkSet, namespaceSelectorRaw, peerNamespace) {
			continue
		}
		nets, _, _ := unstructured.NestedStringSlice(networkSet.Object, "spec", "nets")
		if ipInAnyCIDR(pod.Status.PodIP, nets) || (service != nil && ipInAnyCIDR(service.Spec.ClusterIP, nets)) {
			return true
		}
	}
	return false
}

func calicoNetworkSetNamespaceMatches(networkSet unstructured.Unstructured, namespaceSelectorRaw string, peerNamespace corev1.Namespace) bool {
	if networkSet.GetNamespace() == "" {
		if strings.TrimSpace(namespaceSelectorRaw) == "global()" {
			return true
		}
		if namespaceSelectorRaw == "" {
			return true
		}
		selector, err := ParseSelector(namespaceSelectorRaw)
		if err != nil {
			return false
		}
		return selector.Matches(map[string]string{})
	}
	if namespaceSelectorRaw == "" {
		return networkSet.GetNamespace() == peerNamespace.Name
	}
	selector, err := ParseSelector(namespaceSelectorRaw)
	if err != nil {
		return false
	}
	return selector.Matches(calicoNamespaceLabels(peerNamespace))
}

func calicoUnstructuredLabels(item unstructured.Unstructured) map[string]string {
	labels := cloneMap(item.GetLabels())
	labels["projectcalico.org/name"] = item.GetName()
	if item.GetNamespace() != "" {
		labels["projectcalico.org/namespace"] = item.GetNamespace()
	}
	return labels
}

func calicoPolicyTier(item unstructured.Unstructured) string {
	tier, _, _ := unstructured.NestedString(item.Object, "spec", "tier")
	if tier == "" {
		return "default"
	}
	return tier
}

func calicoPolicyOrder(item unstructured.Unstructured) float64 {
	spec, _, _ := unstructured.NestedMap(item.Object, "spec")
	if value, ok := numericFloatField(spec, "order"); ok {
		return value
	}
	return 1000000
}

func calicoTierOrder(tierName string, tiers []unstructured.Unstructured) float64 {
	if tierName == "" {
		tierName = "default"
	}
	for _, tier := range tiers {
		if tier.GetName() == tierName {
			spec, _, _ := unstructured.NestedMap(tier.Object, "spec")
			if value, ok := numericFloatField(spec, "order"); ok {
				return value
			}
		}
	}
	if tierName == "default" {
		return 1000000
	}
	return 500000
}

func calicoPolicyDisplayName(policy unstructured.Unstructured) string {
	if policy.GetNamespace() == "" {
		return "global/" + policy.GetName()
	}
	return policy.GetNamespace() + "/" + policy.GetName()
}

func calicoPolicyNames(policies []unstructured.Unstructured) []string {
	var names []string
	for _, policy := range policies {
		prefix := ""
		if policy.GetNamespace() == "" {
			prefix = "global/"
		}
		names = append(names, prefix+policy.GetName())
	}
	return unique(names)
}

func stringFromMap(item map[string]interface{}, key string) string {
	if item == nil {
		return ""
	}
	if value, ok := item[key]; ok {
		return strings.TrimSpace(fmt.Sprintf("%v", value))
	}
	return ""
}

func numericField(item map[string]interface{}, key string) (int32, bool) {
	value, ok := item[key]
	if !ok {
		return 0, false
	}
	switch typed := value.(type) {
	case int:
		return int32(typed), true
	case int32:
		return typed, true
	case int64:
		return int32(typed), true
	case float64:
		return int32(typed), true
	}
	return 0, false
}

func numericFloatField(item map[string]interface{}, key string) (float64, bool) {
	value, ok := item[key]
	if !ok {
		return 0, false
	}
	switch typed := value.(type) {
	case int:
		return float64(typed), true
	case int32:
		return float64(typed), true
	case int64:
		return float64(typed), true
	case float64:
		return typed, true
	}
	return 0, false
}

func stringSliceField(item map[string]interface{}, key string) ([]string, bool) {
	value, ok := item[key]
	if !ok {
		return nil, false
	}
	switch typed := value.(type) {
	case []string:
		return typed, true
	case []interface{}:
		var out []string
		for _, entry := range typed {
			out = append(out, fmt.Sprintf("%v", entry))
		}
		return out, true
	}
	return nil, false
}

func containsString(values []string, wanted string) bool {
	for _, value := range values {
		if value == wanted {
			return true
		}
	}
	return false
}

func ipInAnyCIDR(address string, cidrs []string) bool {
	if address == "" || address == "None" {
		return false
	}
	ip, err := netip.ParseAddr(address)
	if err != nil {
		return false
	}
	for _, cidr := range cidrs {
		prefix, err := netip.ParsePrefix(cidr)
		if err == nil && prefix.Contains(ip) {
			return true
		}
	}
	return false
}

func containsPort(ports []int32, port int32) bool {
	if len(ports) == 0 {
		return true
	}
	for _, current := range ports {
		if current == port {
			return true
		}
	}
	return false
}

func containsExactPort(ports []int32, port int32) bool {
	for _, current := range ports {
		if current == port {
			return true
		}
	}
	return false
}

func containsPortNumber(ports []int32, port int32) bool {
	for _, current := range ports {
		if current == port {
			return true
		}
	}
	return false
}

func appendUniquePortCandidate(candidates []calicoPortCandidate, candidate calicoPortCandidate) []calicoPortCandidate {
	if containsPortCandidate(candidates, candidate) {
		return candidates
	}
	return append(candidates, candidate)
}

func containsPortCandidate(candidates []calicoPortCandidate, candidate calicoPortCandidate) bool {
	for _, item := range candidates {
		if item.Number == candidate.Number && item.Name == candidate.Name {
			return true
		}
	}
	return false
}

func formatPorts(ports []int32) string {
	if len(ports) == 0 {
		return "(unknown)"
	}
	var values []string
	for _, port := range ports {
		values = append(values, fmt.Sprintf("%d", port))
	}
	return strings.Join(values, ", ")
}

func calicoServiceName(service *corev1.Service) string {
	if service == nil {
		return "(unknown service)"
	}
	return service.Namespace + "/" + service.Name
}

func dnsPodsForResolver(resolver string, dns DNSContext) []corev1.Pod {
	if isNodeLocalResolver(resolver) {
		return dns.NodeLocalDNSPods
	}
	if dns.CoreDNSServiceIP != "" && resolver == dns.CoreDNSServiceIP {
		return dns.CoreDNSPods
	}
	if len(dns.CoreDNSPods) > 0 {
		for _, pod := range dns.CoreDNSPods {
			if pod.Status.PodIP == resolver {
				return dns.CoreDNSPods
			}
		}
	}
	if len(dns.NodeLocalDNSPods) > 0 {
		for _, pod := range dns.NodeLocalDNSPods {
			if pod.Status.PodIP == resolver {
				return dns.NodeLocalDNSPods
			}
		}
	}
	return nil
}

func describeResolver(resolver string) string {
	if isNodeLocalResolver(resolver) {
		return resolver + " (NodeLocalDNS/link-local)"
	}
	return resolver
}

func isNodeLocalResolver(resolver string) bool {
	return strings.HasPrefix(resolver, "169.254.") || strings.HasPrefix(resolver, "fe80:")
}

func unique(values []string) []string {
	seen := map[string]bool{}
	var out []string
	for _, value := range values {
		if value == "" || seen[value] {
			continue
		}
		seen[value] = true
		out = append(out, value)
	}
	sort.Strings(out)
	return out
}

func isNoMatch(err error) bool {
	if err == nil {
		return false
	}
	text := err.Error()
	return strings.Contains(text, "the server could not find the requested resource") ||
		strings.Contains(text, "no matches for kind") ||
		strings.Contains(text, "not found")
}
