package cilium

import (
	"context"
	"fmt"
	"strings"

	"github.com/CoGoRepo/KubeNetMods/internal/kube"
	"github.com/CoGoRepo/KubeNetMods/internal/policy"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"
)

func ShowBlockers(ctx context.Context, client *kube.Client, subjectNamespace corev1.Namespace, subjectPod corev1.Pod, direction string, ports []int32, portNames []string, portText string, targetNamespace *corev1.Namespace, targetPods []corev1.Pod, service *corev1.Service) ([]policy.Insight, error) {
	clusterName := ciliumClusterName(ctx, client)
	cidrGroups, cidrGroupInsight := listCiliumCIDRGroups(ctx, client)

	namespaces := []string{subjectNamespace.Name}
	if targetNamespace != nil && targetNamespace.Name != subjectNamespace.Name {
		namespaces = append(namespaces, targetNamespace.Name)
	}
	namespacedItems, err := listNamespacedCilium(ctx, client, ciliumNetworkPolicyGVR, namespaces)
	if err != nil {
		if isNoMatch(err) {
			return nil, nil
		}
		return nil, err
	}
	clusterwide, clusterErr := client.Dynamic.Resource(ciliumClusterwideNetworkPolicyGVR).List(ctx, metav1.ListOptions{})
	if clusterErr != nil && !isNoMatch(clusterErr) {
		return []policy.Insight{{
			Provider: "Cilium",
			Layer:    "Cilium Blockers",
			Check:    "ciliumclusterwidenetworkpolicies",
			Status:   "WARN",
			Message:  fmt.Sprintf("Could not list CiliumClusterwideNetworkPolicy objects: %v", clusterErr),
		}}, nil
	}

	var insights []policy.Insight
	if cidrGroupInsight != nil {
		insights = append(insights, *cidrGroupInsight)
	}
	rules, bad := ciliumBlockerRules(namespacedItems, clusterwide, subjectNamespace, subjectPod, clusterName)
	if len(bad) > 0 {
		insights = append(insights, policy.Insight{
			Provider:  "Cilium",
			Layer:     "Cilium Blockers",
			Check:     "policy parse",
			Status:    "WARN",
			Message:   "Cilium policy parse errors: " + strings.Join(bad, "; "),
			Diagnosis: "One or more Cilium policies could not be parsed through Cilium's policy API. Fix malformed policy syntax before trusting blocker analysis.",
		})
	}
	if len(rules) == 0 {
		if len(namespacedItems) == 0 && (clusterwide == nil || len(clusterwide.Items) == 0) {
			return append(insights, policy.Insight{
				Provider: "Cilium",
				Layer:    "Cilium Blockers",
				Check:    "analysis",
				Status:   "INFO",
				Message:  "No Cilium policy objects were found.",
			}), nil
		}
		return append(insights, policy.Insight{
			Provider: "Cilium",
			Layer:    "Cilium Blockers",
			Check:    "selected policies",
			Status:   "PASS",
			Message:  fmt.Sprintf("No Cilium %s policies select pod %s/%s.", direction, subjectNamespace.Name, subjectPod.Name),
		}), nil
	}

	insights = append(insights, policy.Insight{
		Provider: "Cilium",
		Layer:    "Cilium Blockers",
		Check:    "selected policies",
		Status:   "WARN",
		Message:  fmt.Sprintf("Pod %s/%s is selected by Cilium %s policy: %s.", subjectNamespace.Name, subjectPod.Name, direction, strings.Join(uniqueNamedRuleNames(rules), ", ")),
	})

	candidates := ciliumBlockerPortCandidates(ports, portNames, service, targetPods)
	if targetNamespace != nil && (service != nil || len(targetPods) > 0) {
		if direction == "egress" {
			insights = append(insights, ciliumBlockerInsight(ciliumEgressDecision(rules, *targetNamespace, targetPods, subjectNamespace, subjectPod, service, candidates, clusterName, cidrGroups)))
			return insights, nil
		}
		sourceNamespace := *targetNamespace
		sourcePod := firstCiliumPod(targetPods)
		insights = append(insights, ciliumBlockerInsight(ciliumIngressDecision(rules, subjectNamespace, []corev1.Pod{subjectPod}, sourceNamespace, sourcePod, service, candidates, clusterName)))
		return insights, nil
	}

	if direction == "egress" {
		insights = append(insights, ciliumEgressPortPosture(rules, subjectNamespace, subjectPod, candidates, portText, clusterName))
		return insights, nil
	}
	insights = append(insights, ciliumIngressPortPosture(rules, subjectNamespace, subjectPod, candidates, portText, clusterName))
	return insights, nil
}

func ciliumBlockerRules(namespacedItems []unstructured.Unstructured, clusterwide *unstructured.UnstructuredList, subjectNamespace corev1.Namespace, subjectPod corev1.Pod, clusterName string) ([]namedRule, []string) {
	var rules []namedRule
	var bad []string
	for _, item := range namespacedItems {
		parsed, _, err := ciliumPolicyRulesAndTargetMatch(item, subjectNamespace, []corev1.Pod{subjectPod}, clusterName)
		if err != nil {
			bad = append(bad, fmt.Sprintf("%s/%s: %v", item.GetNamespace(), item.GetName(), err))
			continue
		}
		rules = append(rules, namedRules(item.GetNamespace()+"/"+item.GetName(), parsed)...)
	}
	if clusterwide != nil {
		for _, item := range clusterwide.Items {
			parsed, _, err := ciliumPolicyRulesAndTargetMatch(item, subjectNamespace, []corev1.Pod{subjectPod}, clusterName)
			if err != nil {
				bad = append(bad, fmt.Sprintf("clusterwide/%s: %v", item.GetName(), err))
				continue
			}
			rules = append(rules, namedRules("clusterwide/"+item.GetName(), parsed)...)
		}
	}
	var selected []namedRule
	labels := ciliumPodLabelsForCluster(subjectPod, subjectNamespace, clusterName)
	for _, wrapped := range rules {
		if wrapped.Rule != nil && ciliumEndpointSelectorMatches(wrapped.Rule.EndpointSelector, labels) {
			selected = append(selected, wrapped)
		}
	}
	return selected, bad
}

func ciliumBlockerPortCandidates(ports []int32, names []string, service *corev1.Service, pods []corev1.Pod) []ciliumPortCandidate {
	candidates := ciliumPathPortCandidates(ports, service, pods)
	for _, name := range names {
		candidates = appendUniqueCiliumPortCandidate(candidates, ciliumPortCandidate{Name: name, Protocol: "TCP"})
	}
	return candidates
}

func ciliumBlockerInsight(in policy.Insight) policy.Insight {
	in.Layer = "Cilium Blockers"
	return in
}

func ciliumEgressPortPosture(rules []namedRule, namespace corev1.Namespace, pod corev1.Pod, ports []ciliumPortCandidate, portText string, clusterName string) policy.Insight {
	var selecting, allows, l7Allows, misses []string
	var denies []ciliumRuleMatch
	labels := ciliumPodLabelsForCluster(pod, namespace, clusterName)
	for _, wrapped := range rules {
		if wrapped.Rule == nil || !ciliumEndpointSelectorMatches(wrapped.Rule.EndpointSelector, labels) {
			continue
		}
		if len(wrapped.Rule.EgressDeny) > 0 {
			selecting = append(selecting, wrapped.Name)
			for index, deny := range wrapped.Rule.EgressDeny {
				if ciliumDenyPortsMatch(deny.ToPorts, ports) {
					denies = append(denies, ciliumRuleMatch{Policy: wrapped.Name, RuleIndex: index + 1, Action: "Deny", Reason: ciliumPortReason(deny.ToPorts, ports)})
				}
			}
		}
		if len(wrapped.Rule.Egress) > 0 {
			selecting = append(selecting, wrapped.Name)
			for index, allow := range wrapped.Rule.Egress {
				if ciliumPortsMatch(allow.ToPorts, ports) {
					if ciliumPortRulesHaveL7(allow.ToPorts) {
						l7Allows = append(l7Allows, fmt.Sprintf("%s rule %d (%s)", wrapped.Name, index+1, ciliumL7Summary(allow.ToPorts)))
					} else if ciliumPortRulesUseNamedPorts(allow.ToPorts) {
						l7Allows = append(l7Allows, fmt.Sprintf("%s rule %d (named port)", wrapped.Name, index+1))
					} else {
						allows = append(allows, fmt.Sprintf("%s rule %d", wrapped.Name, index+1))
					}
				} else {
					misses = appendUniqueLimited(misses, fmt.Sprintf("%s rule %d: %s", wrapped.Name, index+1, ciliumPortReason(allow.ToPorts, ports)), 3)
				}
			}
		}
	}
	if len(denies) > 0 {
		first := denies[0]
		message := fmt.Sprintf("%s rule %d explicitly Denies TCP/%s. Reason: %s.", first.Policy, first.RuleIndex, blockerPortText(portText, ports), first.Reason)
		if len(denies) > 1 {
			message += fmt.Sprintf(" %d additional matching deny rule(s) also select this port.", len(denies)-1)
		}
		return policy.Insight{Provider: "Cilium", Layer: "Cilium Blockers", Check: "explicit deny", Status: "FAIL", Message: message, Diagnosis: fmt.Sprintf("Primary issue: Cilium egressDeny %s rule %d blocks egress TCP/%s. Reason: %s.", first.Policy, first.RuleIndex, blockerPortText(portText, ports), first.Reason)}
	}
	if len(selecting) == 0 {
		return policy.Insight{Provider: "Cilium", Layer: "Cilium Blockers", Check: "egress", Status: "PASS", Message: fmt.Sprintf("No Cilium egress policies select pod %s/%s.", namespace.Name, pod.Name)}
	}
	if len(allows) > 0 {
		return policy.Insight{Provider: "Cilium", Layer: "Cilium Blockers", Check: "allow candidates", Status: "INFO", Message: "Allow rule(s) mention this port, but without a destination they are candidates only: " + strings.Join(uniqueStrings(allows), ", ") + "."}
	}
	if len(l7Allows) > 0 {
		return policy.Insight{Provider: "Cilium", Layer: "Cilium Blockers", Check: "ambiguous allow candidates", Status: "WARN", Message: "Allow rule(s) mention this port with L7 or named-port constraints, but without a destination/runtime request they are candidates only: " + strings.Join(uniqueStrings(l7Allows), ", ") + "."}
	}
	message := fmt.Sprintf("Cilium egress policy selects this pod, but no egress allow rule mentions TCP/%s. Destination was not supplied.", blockerPortText(portText, ports))
	if len(misses) > 0 {
		message += " Closest allow-rule miss: " + strings.Join(misses, "; ") + "."
	}
	return policy.Insight{Provider: "Cilium", Layer: "Cilium Blockers", Check: "default deny", Status: "FAIL", Message: message, Diagnosis: fmt.Sprintf("Primary issue: Cilium egress default-deny selects pod %s/%s and no matching Allow was found for TCP/%s. Selected policy/policies: %s.", namespace.Name, pod.Name, blockerPortText(portText, ports), strings.Join(uniqueStrings(selecting), ", "))}
}

func ciliumIngressPortPosture(rules []namedRule, namespace corev1.Namespace, pod corev1.Pod, ports []ciliumPortCandidate, portText string, clusterName string) policy.Insight {
	var selecting, allows, l7Allows, misses []string
	var denies []ciliumRuleMatch
	labels := ciliumPodLabelsForCluster(pod, namespace, clusterName)
	for _, wrapped := range rules {
		if wrapped.Rule == nil || !ciliumEndpointSelectorMatches(wrapped.Rule.EndpointSelector, labels) {
			continue
		}
		if len(wrapped.Rule.IngressDeny) > 0 {
			selecting = append(selecting, wrapped.Name)
			for index, deny := range wrapped.Rule.IngressDeny {
				if ciliumDenyPortsMatch(deny.ToPorts, ports) {
					denies = append(denies, ciliumRuleMatch{Policy: wrapped.Name, RuleIndex: index + 1, Action: "Deny", Reason: ciliumPortReason(deny.ToPorts, ports)})
				}
			}
		}
		if len(wrapped.Rule.Ingress) > 0 {
			selecting = append(selecting, wrapped.Name)
			for index, allow := range wrapped.Rule.Ingress {
				if ciliumPortsMatch(allow.ToPorts, ports) {
					if ciliumPortRulesHaveL7(allow.ToPorts) {
						l7Allows = append(l7Allows, fmt.Sprintf("%s rule %d (%s)", wrapped.Name, index+1, ciliumL7Summary(allow.ToPorts)))
					} else if ciliumPortRulesUseNamedPorts(allow.ToPorts) {
						l7Allows = append(l7Allows, fmt.Sprintf("%s rule %d (named port)", wrapped.Name, index+1))
					} else {
						allows = append(allows, fmt.Sprintf("%s rule %d", wrapped.Name, index+1))
					}
				} else {
					misses = appendUniqueLimited(misses, fmt.Sprintf("%s rule %d: %s", wrapped.Name, index+1, ciliumPortReason(allow.ToPorts, ports)), 3)
				}
			}
		}
	}
	if len(denies) > 0 {
		first := denies[0]
		message := fmt.Sprintf("%s rule %d explicitly Denies TCP/%s. Reason: %s.", first.Policy, first.RuleIndex, blockerPortText(portText, ports), first.Reason)
		if len(denies) > 1 {
			message += fmt.Sprintf(" %d additional matching deny rule(s) also select this port.", len(denies)-1)
		}
		return policy.Insight{Provider: "Cilium", Layer: "Cilium Blockers", Check: "explicit deny", Status: "FAIL", Message: message, Diagnosis: fmt.Sprintf("Primary issue: Cilium ingressDeny %s rule %d blocks ingress TCP/%s. Reason: %s.", first.Policy, first.RuleIndex, blockerPortText(portText, ports), first.Reason)}
	}
	if len(selecting) == 0 {
		return policy.Insight{Provider: "Cilium", Layer: "Cilium Blockers", Check: "ingress", Status: "PASS", Message: fmt.Sprintf("No Cilium ingress policies select pod %s/%s.", namespace.Name, pod.Name)}
	}
	if len(allows) > 0 {
		return policy.Insight{Provider: "Cilium", Layer: "Cilium Blockers", Check: "allow candidates", Status: "INFO", Message: "Allow rule(s) mention this port, but without a source they are candidates only: " + strings.Join(uniqueStrings(allows), ", ") + "."}
	}
	if len(l7Allows) > 0 {
		return policy.Insight{Provider: "Cilium", Layer: "Cilium Blockers", Check: "ambiguous allow candidates", Status: "WARN", Message: "Allow rule(s) mention this port with L7 or named-port constraints, but without a source/runtime request they are candidates only: " + strings.Join(uniqueStrings(l7Allows), ", ") + "."}
	}
	message := fmt.Sprintf("Cilium ingress policy selects this pod, but no ingress allow rule mentions TCP/%s. Source was not supplied.", blockerPortText(portText, ports))
	if len(misses) > 0 {
		message += " Closest allow-rule miss: " + strings.Join(misses, "; ") + "."
	}
	return policy.Insight{Provider: "Cilium", Layer: "Cilium Blockers", Check: "default deny", Status: "FAIL", Message: message, Diagnosis: fmt.Sprintf("Primary issue: Cilium ingress default-deny selects pod %s/%s and no matching Allow was found for TCP/%s. Selected policy/policies: %s.", namespace.Name, pod.Name, blockerPortText(portText, ports), strings.Join(uniqueStrings(selecting), ", "))}
}

func firstCiliumPod(pods []corev1.Pod) corev1.Pod {
	if len(pods) == 0 {
		return corev1.Pod{ObjectMeta: metav1.ObjectMeta{Name: "unknown-source"}}
	}
	return pods[0]
}

func blockerPortText(raw string, ports []ciliumPortCandidate) string {
	if raw != "" {
		return raw
	}
	return formatPortCandidates(ports)
}

func uniqueNamedRuleNames(rules []namedRule) []string {
	var names []string
	for _, rule := range rules {
		names = append(names, rule.Name)
	}
	return uniqueStrings(names)
}
