package cilium

import (
	"context"
	"fmt"
	"log/slog"
	"strconv"
	"strings"

	"github.com/CoGoRepo/KubeNetMods/internal/kube"
	"github.com/CoGoRepo/KubeNetMods/internal/policy"
	ciliumv2 "github.com/cilium/cilium/pkg/k8s/apis/cilium.io/v2"
	slimlabels "github.com/cilium/cilium/pkg/k8s/slim/k8s/apis/labels"
	ciliumapi "github.com/cilium/cilium/pkg/policy/api"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/runtime/schema"
)

var (
	ciliumNetworkPolicyGVR = schema.GroupVersionResource{
		Group:    "cilium.io",
		Version:  "v2",
		Resource: "ciliumnetworkpolicies",
	}
	ciliumClusterwideNetworkPolicyGVR = schema.GroupVersionResource{
		Group:    "cilium.io",
		Version:  "v2",
		Resource: "ciliumclusterwidenetworkpolicies",
	}
)

func Analyze(ctx context.Context, client *kube.Client, namespace string, targetPods []corev1.Pod, sourcePod *corev1.Pod, service *corev1.Service, ports []int32) ([]policy.Insight, error) {
	var insights []policy.Insight
	namespaced, err := client.Dynamic.Resource(ciliumNetworkPolicyGVR).Namespace(namespace).List(ctx, metav1.ListOptions{})
	if err != nil {
		if isNoMatch(err) {
			return nil, nil
		}
		return []policy.Insight{{
			Provider: "Cilium",
			Layer:    "Cilium Policy Layer",
			Check:    "ciliumnetworkpolicies",
			Status:   "WARN",
			Message:  fmt.Sprintf("Could not list CiliumNetworkPolicy objects: %v", err),
		}}, nil
	}
	clusterwide, clusterErr := client.Dynamic.Resource(ciliumClusterwideNetworkPolicyGVR).List(ctx, metav1.ListOptions{})
	if clusterErr != nil && !isNoMatch(clusterErr) {
		insights = append(insights, policy.Insight{
			Provider: "Cilium",
			Layer:    "Cilium Policy Layer",
			Check:    "ciliumclusterwidenetworkpolicies",
			Status:   "WARN",
			Message:  fmt.Sprintf("Could not list CiliumClusterwideNetworkPolicy objects: %v", clusterErr),
		})
	}

	matching := []string{}
	bad := []string{}
	var allRules []namedRule
	for _, item := range namespaced.Items {
		rules, matches, err := ciliumPolicyRulesAndTargetMatch(item, targetPods)
		if err != nil {
			bad = append(bad, fmt.Sprintf("%s: %v", item.GetName(), err))
			continue
		}
		allRules = append(allRules, namedRules(item.GetName(), rules)...)
		if matches {
			matching = append(matching, item.GetName())
		}
	}
	if clusterErr == nil && clusterwide != nil {
		for _, item := range clusterwide.Items {
			rules, matches, err := ciliumPolicyRulesAndTargetMatch(item, targetPods)
			if err != nil {
				bad = append(bad, fmt.Sprintf("%s: %v", item.GetName(), err))
				continue
			}
			allRules = append(allRules, namedRules("clusterwide/"+item.GetName(), rules)...)
			if matches {
				matching = append(matching, "clusterwide/"+item.GetName())
			}
		}
	}

	if len(bad) > 0 {
		insights = append(insights, policy.Insight{
			Provider:  "Cilium",
			Layer:     "Cilium Policy Layer",
			Check:     "policy parse",
			Status:    "WARN",
			Message:   "Cilium policy parse errors: " + strings.Join(bad, "; "),
			Diagnosis: "One or more Cilium policies could not be parsed through Cilium's policy API. Fix malformed policy syntax before trusting policy analysis.",
		})
	}
	if len(matching) == 0 {
		if len(namespaced.Items) == 0 && (clusterwide == nil || len(clusterwide.Items) == 0) {
			insights = append(insights, policy.Insight{
				Provider: "Cilium",
				Layer:    "Cilium Policy Layer",
				Check:    "target policies",
				Status:   "INFO",
				Message:  "No Cilium policy objects were found.",
			})
		} else {
			insights = append(insights, policy.Insight{
				Provider: "Cilium",
				Layer:    "Cilium Policy Layer",
				Check:    "target policies",
				Status:   "INFO",
				Message:  "Cilium policy objects exist, but none obviously select the target pods.",
			})
		}
		return insights, nil
	}
	insights = append(insights, policy.Insight{
		Provider:  "Cilium",
		Layer:     "Cilium Policy Layer",
		Check:     "target policies",
		Status:    "WARN",
		Message:   "Target pod(s) are selected by Cilium policy: " + strings.Join(matching, ", "),
		Diagnosis: "Cilium policy selects the target pods. If traffic fails, evaluate Cilium ingress/egress, deny rules, L7 constraints, toServices, endpoint selectors, and port/protocol match.",
	})
	if sourcePod != nil {
		insights = append(insights, analyzeCiliumPath(allRules, targetPods, *sourcePod, service, ports)...)
	}
	return insights, nil
}

type namedRule struct {
	Name string
	Rule *ciliumapi.Rule
}

func namedRules(name string, rules ciliumapi.Rules) []namedRule {
	out := make([]namedRule, 0, len(rules))
	for _, rule := range rules {
		out = append(out, namedRule{Name: name, Rule: rule})
	}
	return out
}

func ciliumPolicyRulesAndTargetMatch(item unstructured.Unstructured, pods []corev1.Pod) (ciliumapi.Rules, bool, error) {
	var cnp ciliumv2.CiliumNetworkPolicy
	if err := runtime.DefaultUnstructuredConverter.FromUnstructured(item.Object, &cnp); err != nil {
		return nil, false, err
	}
	rules, err := cnp.Parse(slog.Default(), "")
	if err != nil {
		return nil, false, err
	}
	return rules, ciliumRulesSelectPods(rules, pods), nil
}

func ciliumRulesSelectPods(rules ciliumapi.Rules, pods []corev1.Pod) bool {
	for _, rule := range rules {
		for _, pod := range pods {
			if rule.EndpointSelector.Matches(ciliumPodLabels(pod)) {
				return true
			}
		}
	}
	return false
}

func analyzeCiliumPath(rules []namedRule, targetPods []corev1.Pod, sourcePod corev1.Pod, service *corev1.Service, ports []int32) []policy.Insight {
	var insights []policy.Insight
	insights = append(insights, ciliumEgressDecision(rules, targetPods, sourcePod, service, ports))
	insights = append(insights, ciliumIngressDecision(rules, targetPods, sourcePod, service, ports))
	return insights
}

func ciliumEgressDecision(rules []namedRule, targetPods []corev1.Pod, sourcePod corev1.Pod, service *corev1.Service, ports []int32) policy.Insight {
	var selecting, allows []string
	for _, wrapped := range rules {
		if wrapped.Rule == nil || !wrapped.Rule.EndpointSelector.Matches(ciliumPodLabels(sourcePod)) {
			continue
		}
		if len(wrapped.Rule.EgressDeny) > 0 {
			for _, deny := range wrapped.Rule.EgressDeny {
				if ciliumEgressPeerMatches(deny.EgressCommonRule, targetPods, service) && ciliumDenyPortsMatch(deny.ToPorts, ports) {
					return policy.Insight{Provider: "Cilium", Layer: "Cilium Policy Path", Check: "source egress to target", Status: "FAIL", Message: fmt.Sprintf("Cilium policy %q has a matching egressDeny rule for this path.", wrapped.Name), Diagnosis: fmt.Sprintf("Cilium explicit deny blocks source pod %q from reaching Service %q. Policy: %s.", sourcePod.Name, ciliumServiceName(service), wrapped.Name)}
				}
			}
		}
		if len(wrapped.Rule.Egress) > 0 {
			selecting = append(selecting, wrapped.Name)
			for _, allow := range wrapped.Rule.Egress {
				if ciliumEgressPeerMatches(allow.EgressCommonRule, targetPods, service) && ciliumPortsMatch(allow.ToPorts, ports) {
					allows = append(allows, wrapped.Name)
				}
			}
		}
	}
	if len(selecting) == 0 {
		return policy.Insight{Provider: "Cilium", Layer: "Cilium Policy Path", Check: "source egress to target", Status: "PASS", Message: "No Cilium egress rules select the source pod."}
	}
	if len(allows) > 0 {
		return policy.Insight{Provider: "Cilium", Layer: "Cilium Policy Path", Check: "source egress to target", Status: "PASS", Message: "Cilium egress policy appears to allow this target path. Matching policy/rule found in: " + strings.Join(uniqueStrings(allows), ", ")}
	}
	return policy.Insight{Provider: "Cilium", Layer: "Cilium Policy Path", Check: "source egress to target", Status: "FAIL", Message: fmt.Sprintf("Cilium egress policy selects source pod %q, but no egress allow rule obviously permits Service %q on TCP port(s) %s. Policies: %s.", sourcePod.Name, ciliumServiceName(service), formatPorts(ports), strings.Join(uniqueStrings(selecting), ", ")), Diagnosis: fmt.Sprintf("Cilium egress default-deny likely blocks source pod %q from reaching Service %q.", sourcePod.Name, ciliumServiceName(service))}
}

func ciliumIngressDecision(rules []namedRule, targetPods []corev1.Pod, sourcePod corev1.Pod, service *corev1.Service, ports []int32) policy.Insight {
	var selecting, allows []string
	sourceLabels := ciliumPodLabels(sourcePod)
	for _, wrapped := range rules {
		if wrapped.Rule == nil || !ciliumRuleSelectsAnyTarget(wrapped.Rule, targetPods) {
			continue
		}
		if len(wrapped.Rule.IngressDeny) > 0 {
			for _, deny := range wrapped.Rule.IngressDeny {
				if ciliumIngressPeerMatches(deny.IngressCommonRule, sourceLabels) && ciliumDenyPortsMatch(deny.ToPorts, ports) {
					return policy.Insight{Provider: "Cilium", Layer: "Cilium Policy Path", Check: "target ingress from source", Status: "FAIL", Message: fmt.Sprintf("Cilium policy %q has a matching ingressDeny rule for this path.", wrapped.Name), Diagnosis: fmt.Sprintf("Cilium explicit deny blocks source pod %q from reaching Service %q. Policy: %s.", sourcePod.Name, ciliumServiceName(service), wrapped.Name)}
				}
			}
		}
		if len(wrapped.Rule.Ingress) > 0 {
			selecting = append(selecting, wrapped.Name)
			for _, allow := range wrapped.Rule.Ingress {
				if ciliumIngressPeerMatches(allow.IngressCommonRule, sourceLabels) && ciliumPortsMatch(allow.ToPorts, ports) {
					allows = append(allows, wrapped.Name)
				}
			}
		}
	}
	if len(selecting) == 0 {
		return policy.Insight{Provider: "Cilium", Layer: "Cilium Policy Path", Check: "target ingress from source", Status: "PASS", Message: "No Cilium ingress rules select the target pods."}
	}
	if len(allows) > 0 {
		return policy.Insight{Provider: "Cilium", Layer: "Cilium Policy Path", Check: "target ingress from source", Status: "PASS", Message: "Cilium ingress policy appears to allow this source path. Matching policy/rule found in: " + strings.Join(uniqueStrings(allows), ", ")}
	}
	return policy.Insight{Provider: "Cilium", Layer: "Cilium Policy Path", Check: "target ingress from source", Status: "FAIL", Message: fmt.Sprintf("Cilium ingress policy selects target pods, but no ingress allow rule obviously permits source pod %q on TCP port(s) %s. Policies: %s.", sourcePod.Name, formatPorts(ports), strings.Join(uniqueStrings(selecting), ", ")), Diagnosis: fmt.Sprintf("Cilium ingress default-deny likely blocks source pod %q from reaching Service %q.", sourcePod.Name, ciliumServiceName(service))}
}

func ciliumPodLabels(pod corev1.Pod) slimlabels.Set {
	labels := slimlabels.Set{}
	for k, v := range pod.Labels {
		labels[k] = v
		labels["k8s:"+k] = v
	}
	labels["io.kubernetes.pod.namespace"] = pod.Namespace
	labels["k8s:io.kubernetes.pod.namespace"] = pod.Namespace
	return labels
}

func ciliumRuleSelectsAnyTarget(rule *ciliumapi.Rule, pods []corev1.Pod) bool {
	for _, pod := range pods {
		if rule.EndpointSelector.Matches(ciliumPodLabels(pod)) {
			return true
		}
	}
	return false
}

func ciliumEgressPeerMatches(rule ciliumapi.EgressCommonRule, targetPods []corev1.Pod, service *corev1.Service) bool {
	if len(rule.ToEndpoints) == 0 && len(rule.ToCIDR) == 0 && len(rule.ToCIDRSet) == 0 && len(rule.ToServices) == 0 && len(rule.ToEntities) == 0 {
		return true
	}
	for _, selector := range rule.ToEndpoints {
		for _, pod := range targetPods {
			if selector.Matches(ciliumPodLabels(pod)) {
				return true
			}
		}
	}
	if service != nil {
		for _, svc := range rule.ToServices {
			if svc.K8sService != nil && svc.K8sService.ServiceName == service.Name && (svc.K8sService.Namespace == "" || svc.K8sService.Namespace == service.Namespace) {
				return true
			}
			if svc.K8sServiceSelector != nil {
				selector := ciliumapi.EndpointSelector(svc.K8sServiceSelector.Selector)
				if !selector.Matches(slimlabels.Set(service.Labels)) {
					continue
				}
				if svc.K8sServiceSelector.Namespace == "" || svc.K8sServiceSelector.Namespace == service.Namespace {
					return true
				}
			}
		}
	}
	for _, entity := range rule.ToEntities {
		if strings.EqualFold(string(entity), "all") || strings.EqualFold(string(entity), "cluster") {
			return true
		}
	}
	return false
}

func ciliumIngressPeerMatches(rule ciliumapi.IngressCommonRule, sourceLabels slimlabels.Set) bool {
	if len(rule.FromEndpoints) == 0 && len(rule.FromCIDR) == 0 && len(rule.FromCIDRSet) == 0 && len(rule.FromEntities) == 0 {
		return true
	}
	for _, selector := range rule.FromEndpoints {
		if selector.Matches(sourceLabels) {
			return true
		}
	}
	for _, entity := range rule.FromEntities {
		if strings.EqualFold(string(entity), "all") || strings.EqualFold(string(entity), "cluster") {
			return true
		}
	}
	return false
}

func ciliumPortsMatch(portRules ciliumapi.PortRules, ports []int32) bool {
	if len(portRules) == 0 || len(ports) == 0 {
		return true
	}
	for _, rule := range portRules {
		if len(rule.Ports) == 0 {
			return true
		}
		for _, port := range rule.Ports {
			if ciliumPortProtocolMatches(port, ports) {
				return true
			}
		}
	}
	return false
}

func ciliumDenyPortsMatch(portRules ciliumapi.PortDenyRules, ports []int32) bool {
	if len(portRules) == 0 || len(ports) == 0 {
		return true
	}
	for _, rule := range portRules {
		if len(rule.Ports) == 0 {
			return true
		}
		for _, port := range rule.Ports {
			if ciliumPortProtocolMatches(port, ports) {
				return true
			}
		}
	}
	return false
}

func ciliumPortProtocolMatches(rule ciliumapi.PortProtocol, ports []int32) bool {
	protocol := strings.ToUpper(string(rule.Protocol))
	if protocol != "" && protocol != "ANY" && protocol != "TCP" {
		return false
	}
	if rule.Port == "" {
		return true
	}
	parsed, err := strconv.Atoi(rule.Port)
	if err != nil {
		return false
	}
	for _, port := range ports {
		if int32(parsed) == port || (rule.EndPort > 0 && port >= int32(parsed) && port <= rule.EndPort) {
			return true
		}
	}
	return false
}

func formatPorts(ports []int32) string {
	if len(ports) == 0 {
		return "(unknown)"
	}
	values := make([]string, 0, len(ports))
	for _, port := range ports {
		values = append(values, fmt.Sprintf("%d", port))
	}
	return strings.Join(values, ", ")
}

func ciliumServiceName(service *corev1.Service) string {
	if service == nil {
		return "(unknown service)"
	}
	return service.Namespace + "/" + service.Name
}

func uniqueStrings(values []string) []string {
	seen := map[string]bool{}
	var out []string
	for _, value := range values {
		if value == "" || seen[value] {
			continue
		}
		seen[value] = true
		out = append(out, value)
	}
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
