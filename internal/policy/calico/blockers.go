package calico

import (
	"context"
	"fmt"
	"sort"
	"strings"

	"github.com/CoGoRepo/KubeNetMods/internal/kube"
	"github.com/CoGoRepo/KubeNetMods/internal/policy"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"
)

func ShowBlockers(ctx context.Context, client *kube.Client, subjectNamespace corev1.Namespace, subjectPod corev1.Pod, direction string, ports []int32, portNames []string, portText string, targetNamespace *corev1.Namespace, targetPods []corev1.Pod, service *corev1.Service) ([]policy.Insight, error) {
	namespaces := []string{subjectNamespace.Name}
	if targetNamespace != nil && targetNamespace.Name != subjectNamespace.Name {
		namespaces = append(namespaces, targetNamespace.Name)
	}
	namespaced, err := listNamespacedCalico(ctx, client, calicoNetworkPolicyGVR, namespaces)
	if err != nil {
		if isNoMatch(err) {
			return nil, nil
		}
		return nil, err
	}
	global, globalErr := client.Dynamic.Resource(calicoGlobalNetworkPolicyGVR).List(ctx, metav1.ListOptions{})
	if globalErr != nil && !isNoMatch(globalErr) {
		return []policy.Insight{{
			Provider: "Calico",
			Layer:    "Calico Blockers",
			Check:    "globalnetworkpolicies",
			Status:   "WARN",
			Message:  fmt.Sprintf("Could not list Calico GlobalNetworkPolicy objects: %v", globalErr),
		}}, nil
	}

	tiers := listOptionalGlobalCalico(ctx, client, calicoTierGVR)
	networkSets := append(listOptionalCalico(ctx, client, calicoNetworkSetGVR, namespaces), listOptionalGlobalCalico(ctx, client, calicoGlobalNetworkSetGVR)...)
	serviceAccounts := loadServiceAccountLabels(ctx, client, namespaces)
	all := append([]unstructured.Unstructured{}, namespaced.Items...)
	all = append(all, safeGlobalItems(global)...)

	var selected []unstructured.Unstructured
	if direction == "egress" {
		selected = policiesForPod(all, subjectNamespace, subjectPod, "Egress")
	} else {
		selected = policiesForPod(all, subjectNamespace, subjectPod, "Ingress")
	}
	if len(selected) == 0 {
		return []policy.Insight{{
			Provider: "Calico",
			Layer:    "Calico Blockers",
			Check:    "selected policies",
			Status:   "PASS",
			Message:  fmt.Sprintf("No Calico %s policies select pod %s/%s.", direction, subjectNamespace.Name, subjectPod.Name),
		}}, nil
	}

	var insights []policy.Insight
	insights = append(insights, policy.Insight{
		Provider: "Calico",
		Layer:    "Calico Blockers",
		Check:    "selected policies",
		Status:   "WARN",
		Message:  fmt.Sprintf("Pod %s/%s is selected by Calico %s policy: %s.", subjectNamespace.Name, subjectPod.Name, direction, strings.Join(calicoPolicyNames(selected), ", ")),
	})

	if targetNamespace != nil && (service != nil || len(targetPods) > 0) {
		insights = append(insights, pathSpecificBlockers(selected, direction, tiers, networkSets, serviceAccounts, subjectNamespace, subjectPod, *targetNamespace, targetPods, service, ports, portNames, portText)...)
		return insights, nil
	}

	insights = append(insights, portPostureBlockers(selected, direction, tiers, serviceAccounts, subjectNamespace, subjectPod, ports, portNames, portText)...)
	return insights, nil
}

func pathSpecificBlockers(policies []unstructured.Unstructured, direction string, tiers []unstructured.Unstructured, networkSets []unstructured.Unstructured, serviceAccounts serviceAccountLabels, subjectNamespace corev1.Namespace, subjectPod corev1.Pod, targetNamespace corev1.Namespace, targetPods []corev1.Pod, service *corev1.Service, ports []int32, portNames []string, portText string) []policy.Insight {
	var matches []calicoRuleMatch
	var allowMatches []calicoRuleMatch
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
			if !ok {
				continue
			}
			matched, reason := blockerRuleMatchesPath(rule, direction, networkSets, serviceAccounts, subjectNamespace, subjectPod, targetNamespace, targetPods, service, ports, portNames)
			if !matched {
				action := strings.ToLower(stringFromMap(rule, "action"))
				if action == "" {
					action = "allow"
				}
				if action == "allow" && reason != "rule protocol does not match tested protocol" {
					missReasons = appendUniqueLimited(missReasons, fmt.Sprintf("%s rule %d: %s", policyName, index+1, reason), 4)
				}
				continue
			}
			action := strings.ToLower(stringFromMap(rule, "action"))
			if action == "" {
				action = "allow"
			}
			match := calicoRuleMatch{
				Policy:      policyName,
				Tier:        tier,
				TierOrder:   calicoTierOrder(tier, tiers),
				PolicyOrder: calicoPolicyOrder(item),
				RuleIndex:   index + 1,
				Action:      action,
				Reason:      reason,
			}
			if action == "deny" {
				matches = append(matches, match)
			}
			if action == "allow" {
				allowMatches = append(allowMatches, match)
			}
			if action == "allow" {
				break
			}
		}
	}
	sortRuleMatches(matches)
	sortRuleMatches(allowMatches)
	var insights []policy.Insight
	for _, match := range matches {
		insights = append(insights, policy.Insight{
			Provider:  "Calico",
			Layer:     "Calico Blockers",
			Check:     "explicit deny",
			Status:    "FAIL",
			Message:   fmt.Sprintf("%s rule %d explicitly Denies TCP/%s in tier %q. Reason: %s.", match.Policy, match.RuleIndex, formatBlockerPorts(ports, portNames, portText), match.Tier, match.Reason),
			Diagnosis: fmt.Sprintf("Primary issue: Calico %s rule %d in tier %q explicitly denies %s TCP/%s. Reason: %s.", match.Policy, match.RuleIndex, match.Tier, direction, formatBlockerPorts(ports, portNames, portText), match.Reason),
		})
	}
	if len(matches) == 0 && len(allowMatches) == 0 {
		message := fmt.Sprintf("Calico %s policy selects this pod, but no matching Allow rule was found for TCP/%s.", direction, formatBlockerPorts(ports, portNames, portText))
		diagnosis := fmt.Sprintf("Default-deny risk: Calico %s policy selects pod %s/%s and no matching Allow was found for TCP/%s.", direction, subjectNamespace.Name, subjectPod.Name, formatBlockerPorts(ports, portNames, portText))
		if len(missReasons) > 0 {
			message += " Closest allow-rule miss: " + strings.Join(missReasons, "; ") + "."
			diagnosis += " Closest allow-rule miss: " + missReasons[0] + "."
		}
		insights = append(insights, policy.Insight{
			Provider:  "Calico",
			Layer:     "Calico Blockers",
			Check:     "default deny",
			Status:    "FAIL",
			Message:   message,
			Diagnosis: diagnosis,
		})
	}
	if len(matches) == 0 && len(allowMatches) > 0 {
		parts := make([]string, 0, len(allowMatches))
		for _, match := range allowMatches {
			parts = append(parts, fmt.Sprintf("%s rule %d", match.Policy, match.RuleIndex))
		}
		insights = append(insights, policy.Insight{
			Provider: "Calico",
			Layer:    "Calico Blockers",
			Check:    "allow",
			Status:   "PASS",
			Message:  "Matching Allow rule(s) found: " + strings.Join(parts, ", ") + ".",
		})
	}
	return insights
}

func portPostureBlockers(policies []unstructured.Unstructured, direction string, tiers []unstructured.Unstructured, serviceAccounts serviceAccountLabels, subjectNamespace corev1.Namespace, subjectPod corev1.Pod, ports []int32, portNames []string, portText string) []policy.Insight {
	var denyMatches []calicoRuleMatch
	var allowMatches []calicoRuleMatch
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
			if !ok || !calicoRuleProtocolMatches(rule) {
				continue
			}
			action := strings.ToLower(stringFromMap(rule, "action"))
			if action == "" {
				action = "allow"
			}
			if action == "allow" {
				if reason := portPostureAllowMissReason(rule, direction, serviceAccounts, subjectNamespace, subjectPod, ports, portNames); reason != "" {
					missReasons = appendUniqueLimited(missReasons, fmt.Sprintf("%s rule %d: %s", policyName, index+1, reason), 4)
				}
			}
			if ok, _ := ruleAppliesToSubject(rule, direction, serviceAccounts, subjectNamespace, subjectPod); !ok {
				continue
			}
			peerKey := "destination"
			if direction == "ingress" {
				peerKey = "source"
			}
			peerEntity, _ := rule[peerKey].(map[string]interface{})
			if !calicoEntityPortsMatch(peerEntity, blockerPortCandidates(ports, portNames, nil, nil)) {
				continue
			}
			subjectKey := "source"
			if direction == "ingress" {
				subjectKey = "destination"
			}
			subjectEntity, _ := rule[subjectKey].(map[string]interface{})
			match := calicoRuleMatch{
				Policy:      policyName,
				Tier:        tier,
				TierOrder:   calicoTierOrder(tier, tiers),
				PolicyOrder: calicoPolicyOrder(item),
				RuleIndex:   index + 1,
				Action:      action,
				Reason:      portPostureReason(subjectEntity, peerEntity, direction),
			}
			if action == "deny" {
				denyMatches = append(denyMatches, match)
			}
			if action == "allow" {
				allowMatches = append(allowMatches, match)
			}
			if action == "allow" {
				break
			}
		}
	}
	sortRuleMatches(denyMatches)
	sortRuleMatches(allowMatches)
	var insights []policy.Insight
	for _, match := range denyMatches {
		message := fmt.Sprintf("%s rule %d explicitly Denies TCP/%s in tier %q. Reason: %s.", match.Policy, match.RuleIndex, formatBlockerPorts(ports, portNames, portText), match.Tier, match.Reason)
		diagnosis := fmt.Sprintf("Primary issue: Calico %s rule %d in tier %q explicitly denies %s TCP/%s. Reason: %s.", match.Policy, match.RuleIndex, match.Tier, direction, formatBlockerPorts(ports, portNames, portText), match.Reason)
		if len(missReasons) > 0 {
			message += " Earlier allow-rule miss: " + strings.Join(missReasons, "; ") + "."
			diagnosis += " Earlier allow-rule miss: " + missReasons[0] + "."
		}
		insights = append(insights, policy.Insight{
			Provider:  "Calico",
			Layer:     "Calico Blockers",
			Check:     "explicit deny",
			Status:    "FAIL",
			Message:   message,
			Diagnosis: diagnosis,
		})
	}
	if len(denyMatches) == 0 && len(allowMatches) == 0 {
		message := fmt.Sprintf("Calico %s policy selects this pod, but no matching Allow rule was found for TCP/%s. Destination was not supplied, so destination selectors could not be fully evaluated.", direction, formatBlockerPorts(ports, portNames, portText))
		diagnosis := fmt.Sprintf("Default-deny risk: Calico %s policy selects pod %s/%s and no matching Allow was found for TCP/%s.", direction, subjectNamespace.Name, subjectPod.Name, formatBlockerPorts(ports, portNames, portText))
		if len(missReasons) > 0 {
			message += " Closest allow-rule miss: " + strings.Join(missReasons, "; ") + "."
			diagnosis += " Closest allow-rule miss: " + missReasons[0] + "."
		}
		insights = append(insights, policy.Insight{
			Provider:  "Calico",
			Layer:     "Calico Blockers",
			Check:     "default deny",
			Status:    "FAIL",
			Message:   message,
			Diagnosis: diagnosis,
		})
	} else if len(allowMatches) > 0 {
		parts := make([]string, 0, len(allowMatches))
		for _, match := range allowMatches {
			parts = append(parts, fmt.Sprintf("%s rule %d", match.Policy, match.RuleIndex))
		}
		insights = append(insights, policy.Insight{
			Provider: "Calico",
			Layer:    "Calico Blockers",
			Check:    "allow candidates",
			Status:   "INFO",
			Message:  "Allow rule(s) mention this port, but without a destination they are candidates only: " + strings.Join(parts, ", ") + ".",
		})
	}
	return insights
}

func portPostureAllowMissReason(rule map[string]interface{}, direction string, serviceAccounts serviceAccountLabels, namespace corev1.Namespace, pod corev1.Pod, ports []int32, portNames []string) string {
	var reasons []string
	subjectKey := "source"
	if direction == "ingress" {
		subjectKey = "destination"
	}
	subjectEntity, _ := rule[subjectKey].(map[string]interface{})
	if ok, _ := ruleAppliesToSubject(rule, direction, serviceAccounts, namespace, pod); !ok {
		reasons = append(reasons, "subject criteria "+formatEntityCriteria(subjectEntity)+" do not match pod labels "+formatStringMapLocal(pod.Labels)+serviceAccountSummary(pod))
	}
	peerKey := "destination"
	if direction == "ingress" {
		peerKey = "source"
	}
	peerEntity, _ := rule[peerKey].(map[string]interface{})
	if !calicoEntityPortsMatch(peerEntity, blockerPortCandidates(ports, portNames, nil, nil)) {
		reasons = append(reasons, "port criteria "+formatRulePortCriteria(peerEntity)+" do not include TCP/"+formatBlockerPorts(ports, portNames, ""))
	}
	return strings.Join(reasons, "; ")
}

func formatRulePortCriteria(entity map[string]interface{}) string {
	if entity == nil {
		return "(any port)"
	}
	var parts []string
	if raw, exists := entity["ports"]; exists {
		parts = append(parts, "ports="+formatInterfaceList(raw))
	}
	if raw, exists := entity["notPorts"]; exists {
		parts = append(parts, "notPorts="+formatInterfaceList(raw))
	}
	if len(parts) == 0 {
		return "(any port)"
	}
	return strings.Join(parts, ", ")
}

func formatInterfaceList(raw interface{}) string {
	items, ok := raw.([]interface{})
	if !ok {
		return fmt.Sprintf("%v", raw)
	}
	values := make([]string, 0, len(items))
	for _, item := range items {
		values = append(values, fmt.Sprintf("%v", item))
	}
	return strings.Join(values, ",")
}

func formatStringMapLocal(values map[string]string) string {
	keys := make([]string, 0, len(values))
	for key := range values {
		keys = append(keys, key)
	}
	sort.Strings(keys)
	parts := make([]string, 0, len(keys))
	for _, key := range keys {
		parts = append(parts, key+"="+values[key])
	}
	return strings.Join(parts, ",")
}

func ruleAppliesToSubject(rule map[string]interface{}, direction string, serviceAccounts serviceAccountLabels, namespace corev1.Namespace, pod corev1.Pod) (bool, string) {
	entityKey := "source"
	if direction == "ingress" {
		entityKey = "destination"
	}
	entity, _ := rule[entityKey].(map[string]interface{})
	if len(entity) == 0 {
		return true, "no same-side criteria"
	}
	return calicoEntityMatchesPod(entity, namespace, pod, nil, nil, serviceAccounts)
}

func blockerRuleMatchesPath(rule map[string]interface{}, direction string, networkSets []unstructured.Unstructured, serviceAccounts serviceAccountLabels, subjectNamespace corev1.Namespace, subjectPod corev1.Pod, targetNamespace corev1.Namespace, targetPods []corev1.Pod, service *corev1.Service, ports []int32, portNames []string) (bool, string) {
	// Reuse the same path logic for numeric ports. Named-only blocker checks need
	// a wider candidate list, so handle their port match before falling through.
	if len(portNames) > 0 && len(ports) == 0 {
		if !calicoRuleProtocolMatches(rule) {
			return false, "rule protocol does not match tested protocol"
		}
		entityKey := "destination"
		if direction == "ingress" {
			entityKey = "source"
		}
		entity, _ := rule[entityKey].(map[string]interface{})
		if !calicoEntityPortsMatch(entity, blockerPortCandidates(ports, portNames, service, targetPods)) {
			return false, "port/notPort criteria do not match tested path"
		}
		if direction == "egress" {
			if sourceEntity, _ := rule["source"].(map[string]interface{}); len(sourceEntity) > 0 {
				if ok, reason := calicoEntityMatchesPod(sourceEntity, subjectNamespace, subjectPod, nil, networkSets, serviceAccounts); !ok {
					return false, "source criteria do not match source pod: " + reason
				}
			}
			if len(entity) == 0 {
				return true, "no destination criteria, matches all destinations"
			}
			for _, pod := range targetPods {
				if ok, reason := calicoEntityMatchesPod(entity, targetNamespace, pod, service, networkSets, serviceAccounts); ok {
					return true, reason
				}
			}
			return false, "destination criteria do not match target service/pods"
		}
		if destinationEntity, _ := rule["destination"].(map[string]interface{}); len(destinationEntity) > 0 {
			for _, pod := range targetPods {
				if ok, reason := calicoEntityMatchesPod(destinationEntity, targetNamespace, pod, service, networkSets, serviceAccounts); !ok {
					return false, "destination criteria do not match target pod: " + reason
				}
			}
		}
		if len(entity) == 0 {
			return true, "no source criteria, matches all sources"
		}
		return calicoEntityMatchesPod(entity, subjectNamespace, subjectPod, nil, networkSets, serviceAccounts)
	}
	if direction == "egress" {
		return ruleMatchesPath(rule, direction, networkSets, serviceAccounts, subjectNamespace, subjectPod, targetNamespace, targetPods, service, ports)
	}
	return ruleMatchesPath(rule, direction, networkSets, serviceAccounts, targetNamespace, firstPod(targetPods), subjectNamespace, []corev1.Pod{subjectPod}, nil, ports)
}

func firstPod(pods []corev1.Pod) corev1.Pod {
	if len(pods) == 0 {
		return corev1.Pod{}
	}
	return pods[0]
}

func intPortCandidates(ports []int32) []calicoPortCandidate {
	out := make([]calicoPortCandidate, 0, len(ports))
	for _, port := range ports {
		out = append(out, calicoPortCandidate{Number: port})
	}
	return out
}

func blockerPortCandidates(ports []int32, names []string, service *corev1.Service, pods []corev1.Pod) []calicoPortCandidate {
	candidates := calicoPathPortCandidates(ports, service, pods)
	for _, name := range names {
		candidates = appendUniquePortCandidate(candidates, calicoPortCandidate{Name: name})
	}
	return candidates
}

func formatBlockerPorts(ports []int32, names []string, fallback string) string {
	if fallback != "" {
		return fallback
	}
	if len(names) > 0 {
		return strings.Join(names, ", ")
	}
	return formatPorts(ports)
}

func portPostureReason(subjectEntity map[string]interface{}, peerEntity map[string]interface{}, direction string) string {
	var parts []string
	if criteria := formatEntityCriteria(subjectEntity); criteria != "" {
		side := "source"
		if direction == "ingress" {
			side = "destination"
		}
		parts = append(parts, side+" criteria match: "+criteria)
	}
	if criteria := formatEntityCriteria(peerEntity); criteria != "" {
		side := "destination"
		if direction == "ingress" {
			side = "source"
		}
		parts = append(parts, side+" criteria match: "+criteria)
	}
	parts = append(parts, "applies to this port")
	if len(parts) == 0 {
		return "applies broadly to this port"
	}
	return strings.Join(parts, "; ")
}

func formatEntityCriteria(entity map[string]interface{}) string {
	if len(entity) == 0 {
		return ""
	}
	var parts []string
	for _, key := range []string{"selector", "namespaceSelector", "notSelector"} {
		if value := stringFromMap(entity, key); value != "" {
			parts = append(parts, key+"="+value)
		}
	}
	for _, key := range []string{"nets", "notNets", "services"} {
		if raw, ok := entity[key]; ok {
			parts = append(parts, key+"="+formatInterfaceList(raw))
		}
	}
	if raw, ok := entity["serviceAccounts"]; ok {
		parts = append(parts, "serviceAccounts="+formatServiceAccountCriteria(raw))
	}
	return strings.Join(parts, ", ")
}

func formatServiceAccountCriteria(raw interface{}) string {
	item, ok := raw.(map[string]interface{})
	if !ok {
		return fmt.Sprintf("%v", raw)
	}
	var parts []string
	if names, ok := stringSliceField(item, "names"); ok && len(names) > 0 {
		parts = append(parts, "names="+strings.Join(names, ","))
	}
	if selector := stringFromMap(item, "selector"); selector != "" {
		parts = append(parts, "selector="+selector)
	}
	if len(parts) == 0 {
		return "(present)"
	}
	return strings.Join(parts, ",")
}

func serviceAccountSummary(pod corev1.Pod) string {
	name := pod.Spec.ServiceAccountName
	if name == "" {
		name = "default"
	}
	return ", serviceAccount=" + name
}
