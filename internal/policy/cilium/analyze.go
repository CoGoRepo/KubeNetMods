package cilium

import (
	"context"
	"encoding/json"
	"fmt"
	"log/slog"
	"net/netip"
	"strconv"
	"strings"

	"github.com/CoGoRepo/KubeNetMods/internal/kube"
	"github.com/CoGoRepo/KubeNetMods/internal/policy"
	"github.com/cilium/cilium/pkg/defaults"
	"github.com/cilium/cilium/pkg/fqdn/re"
	ciliumv2 "github.com/cilium/cilium/pkg/k8s/apis/cilium.io/v2"
	slimlabels "github.com/cilium/cilium/pkg/k8s/slim/k8s/apis/labels"
	slimmetav1 "github.com/cilium/cilium/pkg/k8s/slim/k8s/apis/meta/v1"
	ciliumapi "github.com/cilium/cilium/pkg/policy/api"
	corev1 "k8s.io/api/core/v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"
	"k8s.io/apimachinery/pkg/runtime/schema"
	"k8s.io/apimachinery/pkg/util/intstr"
)

func init() {
	_ = re.InitRegexCompileLRU(slog.Default(), defaults.FQDNRegexCompileLRUSize)
}

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
	ciliumEndpointGVR = schema.GroupVersionResource{
		Group:    "cilium.io",
		Version:  "v2",
		Resource: "ciliumendpoints",
	}
	ciliumCIDRGroupGVR = schema.GroupVersionResource{
		Group:    "cilium.io",
		Version:  "v2",
		Resource: "ciliumcidrgroups",
	}
)

type DNSContext struct {
	Nameservers      []string
	CoreDNSServiceIP string
	CoreDNSPods      []corev1.Pod
	NodeLocalDNSPods []corev1.Pod
}

func Analyze(ctx context.Context, client *kube.Client, targetNamespace corev1.Namespace, targetPods []corev1.Pod, sourceNamespace *corev1.Namespace, sourcePod *corev1.Pod, service *corev1.Service, ports []int32, dns DNSContext) ([]policy.Insight, error) {
	var insights []policy.Insight
	clusterName := ciliumClusterName(ctx, client)
	insights = append(insights, analyzeCiliumEndpointState(ctx, client, targetPods, sourcePod)...)
	cidrGroups, cidrGroupInsight := listCiliumCIDRGroups(ctx, client)
	if cidrGroupInsight != nil {
		insights = append(insights, *cidrGroupInsight)
	}
	namespaces := []string{targetNamespace.Name}
	if sourceNamespace != nil && sourceNamespace.Name != targetNamespace.Name {
		namespaces = append(namespaces, sourceNamespace.Name)
	}
	namespacedItems, err := listNamespacedCilium(ctx, client, ciliumNetworkPolicyGVR, namespaces)
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
	for _, item := range namespacedItems {
		rules, matches, err := ciliumPolicyRulesAndTargetMatch(item, targetNamespace, targetPods, clusterName)
		if err != nil {
			bad = append(bad, fmt.Sprintf("%s: %v", item.GetName(), err))
			continue
		}
		allRules = append(allRules, namedRules(item.GetNamespace()+"/"+item.GetName(), rules)...)
		if matches {
			matching = append(matching, item.GetNamespace()+"/"+item.GetName())
		}
	}
	if clusterErr == nil && clusterwide != nil {
		for _, item := range clusterwide.Items {
			rules, matches, err := ciliumPolicyRulesAndTargetMatch(item, targetNamespace, targetPods, clusterName)
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
		if len(namespacedItems) == 0 && (clusterwide == nil || len(clusterwide.Items) == 0) {
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
	} else {
		insights = append(insights, policy.Insight{
			Provider: "Cilium",
			Layer:    "Cilium Policy Layer",
			Check:    "target policies",
			Status:   "WARN",
			Message:  "Target pod(s) are selected by Cilium policy: " + strings.Join(matching, ", "),
		})
	}
	if sourcePod != nil && sourceNamespace != nil {
		insights = append(insights, analyzeCiliumPath(allRules, targetNamespace, targetPods, *sourceNamespace, *sourcePod, service, ports, clusterName, cidrGroups)...)
		insights = append(insights, analyzeCiliumDNS(allRules, *sourceNamespace, *sourcePod, dns, clusterName, cidrGroups)...)
	}
	return insights, nil
}

func AnalyzeExternalEgress(ctx context.Context, client *kube.Client, sourceNamespace corev1.Namespace, sourcePod corev1.Pod, host string, port int32) ([]policy.Insight, error) {
	if host == "" || port <= 0 {
		return nil, nil
	}
	clusterName := ciliumClusterName(ctx, client)
	namespacedItems, err := listNamespacedCilium(ctx, client, ciliumNetworkPolicyGVR, []string{sourceNamespace.Name})
	if err != nil {
		if isNoMatch(err) {
			return nil, nil
		}
		return []policy.Insight{{
			Provider: "Cilium",
			Layer:    "Cilium External Policy Posture",
			Check:    "ciliumnetworkpolicies",
			Status:   "WARN",
			Message:  fmt.Sprintf("Could not list CiliumNetworkPolicy objects: %v", err),
		}}, nil
	}
	clusterwide, clusterErr := client.Dynamic.Resource(ciliumClusterwideNetworkPolicyGVR).List(ctx, metav1.ListOptions{})
	if clusterErr != nil && !isNoMatch(clusterErr) {
		return []policy.Insight{{
			Provider: "Cilium",
			Layer:    "Cilium External Policy Posture",
			Check:    "ciliumclusterwidenetworkpolicies",
			Status:   "WARN",
			Message:  fmt.Sprintf("Could not list CiliumClusterwideNetworkPolicy objects: %v", clusterErr),
		}}, nil
	}
	var rules []namedRule
	var bad []string
	for _, item := range namespacedItems {
		parsed, _, err := ciliumPolicyRulesAndTargetMatch(item, sourceNamespace, []corev1.Pod{sourcePod}, clusterName)
		if err != nil {
			bad = append(bad, fmt.Sprintf("%s/%s: %v", item.GetNamespace(), item.GetName(), err))
			continue
		}
		rules = append(rules, namedRules(item.GetNamespace()+"/"+item.GetName(), parsed)...)
	}
	if clusterErr == nil && clusterwide != nil {
		for _, item := range clusterwide.Items {
			parsed, _, err := ciliumPolicyRulesAndTargetMatch(item, sourceNamespace, []corev1.Pod{sourcePod}, clusterName)
			if err != nil {
				bad = append(bad, fmt.Sprintf("clusterwide/%s: %v", item.GetName(), err))
				continue
			}
			rules = append(rules, namedRules("clusterwide/"+item.GetName(), parsed)...)
		}
	}
	var insights []policy.Insight
	if len(bad) > 0 {
		insights = append(insights, policy.Insight{
			Provider:  "Cilium",
			Layer:     "Cilium External Policy Posture",
			Check:     "policy parse",
			Status:    "WARN",
			Message:   "Cilium policy parse errors: " + strings.Join(bad, "; "),
			Diagnosis: "One or more Cilium policies could not be parsed through Cilium's policy API. Fix malformed policy syntax before trusting external egress analysis.",
		})
	}
	decision := ciliumExternalEgressDecision(rules, sourceNamespace, sourcePod, host, port, clusterName)
	if decision.Message != "" {
		insights = append(insights, decision)
	}
	return insights, nil
}

func AnalyzeDNS(ctx context.Context, client *kube.Client, sourceNamespace corev1.Namespace, sourcePod corev1.Pod, dns DNSContext) ([]policy.Insight, error) {
	clusterName := ciliumClusterName(ctx, client)
	cidrGroups, cidrGroupInsight := listCiliumCIDRGroups(ctx, client)
	var insights []policy.Insight
	if cidrGroupInsight != nil {
		insights = append(insights, *cidrGroupInsight)
	}
	namespacedItems, err := listNamespacedCilium(ctx, client, ciliumNetworkPolicyGVR, []string{sourceNamespace.Name})
	if err != nil {
		if isNoMatch(err) {
			return nil, nil
		}
		return []policy.Insight{{
			Provider: "Cilium",
			Layer:    "Cilium DNS Policy Path",
			Check:    "ciliumnetworkpolicies",
			Status:   "WARN",
			Message:  fmt.Sprintf("Could not list CiliumNetworkPolicy objects: %v", err),
		}}, nil
	}
	clusterwide, clusterErr := client.Dynamic.Resource(ciliumClusterwideNetworkPolicyGVR).List(ctx, metav1.ListOptions{})
	if clusterErr != nil && !isNoMatch(clusterErr) {
		insights = append(insights, policy.Insight{
			Provider: "Cilium",
			Layer:    "Cilium DNS Policy Path",
			Check:    "ciliumclusterwidenetworkpolicies",
			Status:   "WARN",
			Message:  fmt.Sprintf("Could not list CiliumClusterwideNetworkPolicy objects: %v", clusterErr),
		})
	}
	var rules []namedRule
	for _, item := range namespacedItems {
		parsed, _, err := ciliumPolicyRulesAndTargetMatch(item, sourceNamespace, []corev1.Pod{sourcePod}, clusterName)
		if err == nil {
			rules = append(rules, namedRules(item.GetNamespace()+"/"+item.GetName(), parsed)...)
		}
	}
	if clusterErr == nil && clusterwide != nil {
		for _, item := range clusterwide.Items {
			parsed, _, err := ciliumPolicyRulesAndTargetMatch(item, sourceNamespace, []corev1.Pod{sourcePod}, clusterName)
			if err == nil {
				rules = append(rules, namedRules("clusterwide/"+item.GetName(), parsed)...)
			}
		}
	}
	insights = append(insights, analyzeCiliumDNS(rules, sourceNamespace, sourcePod, dns, clusterName, cidrGroups)...)
	return insights, nil
}

func ciliumClusterName(ctx context.Context, client *kube.Client) string {
	config, err := client.Core.CoreV1().ConfigMaps("kube-system").Get(ctx, "cilium-config", metav1.GetOptions{})
	if err != nil || config == nil {
		return "default"
	}
	if name := strings.TrimSpace(config.Data["cluster-name"]); name != "" {
		return name
	}
	return "default"
}

func listNamespacedCilium(ctx context.Context, client *kube.Client, gvr schema.GroupVersionResource, namespaces []string) ([]unstructured.Unstructured, error) {
	var combined []unstructured.Unstructured
	seen := map[string]bool{}
	for _, namespace := range namespaces {
		if namespace == "" || seen[namespace] {
			continue
		}
		seen[namespace] = true
		list, err := client.Dynamic.Resource(gvr).Namespace(namespace).List(ctx, metav1.ListOptions{})
		if err != nil {
			return nil, err
		}
		combined = append(combined, list.Items...)
	}
	return combined, nil
}

type ciliumCIDRGroup struct {
	Name   string
	Labels map[string]string
	CIDRs  []string
}

func listCiliumCIDRGroups(ctx context.Context, client *kube.Client) ([]ciliumCIDRGroup, *policy.Insight) {
	list, err := client.Dynamic.Resource(ciliumCIDRGroupGVR).List(ctx, metav1.ListOptions{})
	if err != nil {
		if isNoMatch(err) || apierrors.IsNotFound(err) {
			return nil, nil
		}
		return nil, &policy.Insight{
			Provider: "Cilium",
			Layer:    "Cilium Policy Layer",
			Check:    "ciliumcidrgroups",
			Status:   "WARN",
			Message:  fmt.Sprintf("Could not list CiliumCIDRGroup objects: %v", err),
		}
	}
	var groups []ciliumCIDRGroup
	for _, item := range list.Items {
		cidrs, _, _ := unstructured.NestedStringSlice(item.Object, "spec", "externalCIDRs")
		groups = append(groups, ciliumCIDRGroup{
			Name:   item.GetName(),
			Labels: item.GetLabels(),
			CIDRs:  cidrs,
		})
	}
	if len(groups) == 0 {
		return nil, nil
	}
	return groups, &policy.Insight{
		Provider: "Cilium",
		Layer:    "Cilium Policy Layer",
		Check:    "ciliumcidrgroups",
		Status:   "INFO",
		Message:  fmt.Sprintf("Loaded %d CiliumCIDRGroup object(s) for CIDRGroupRef/selector evaluation.", len(groups)),
	}
}

func analyzeCiliumEndpointState(ctx context.Context, client *kube.Client, targetPods []corev1.Pod, sourcePod *corev1.Pod) []policy.Insight {
	var insights []policy.Insight
	if sourcePod != nil {
		insights = append(insights, ciliumEndpointStateInsight(ctx, client, "source endpoint", *sourcePod))
	}
	if len(targetPods) == 0 {
		return insights
	}
	var ready, missing int
	var summaries []string
	for _, pod := range targetPods {
		cep, err := getCiliumEndpoint(ctx, client, pod)
		if err != nil {
			if isNoMatch(err) || apierrors.IsNotFound(err) {
				missing++
				continue
			}
			insights = append(insights, policy.Insight{
				Provider: "Cilium",
				Layer:    "Cilium Endpoint State",
				Check:    "target endpoint " + pod.Name,
				Status:   "WARN",
				Message:  fmt.Sprintf("Could not read CiliumEndpoint for target pod %q: %v", pod.Name, err),
			})
			continue
		}
		if strings.EqualFold(ciliumEndpointString(cep, "status", "state"), "ready") {
			ready++
		}
		summaries = appendUniqueLimited(summaries, ciliumEndpointSummary(cep, pod), 4)
	}
	status := "PASS"
	message := fmt.Sprintf("%d/%d selected target pod(s) have CiliumEndpoint state ready.", ready, len(targetPods))
	if len(summaries) > 0 {
		message += " " + strings.Join(summaries, "; ")
	}
	if missing > 0 || ready < len(targetPods) {
		status = "WARN"
		message = fmt.Sprintf("%d/%d selected target pod(s) have readable ready CiliumEndpoint state; %d missing/unready.", ready, len(targetPods), len(targetPods)-ready)
		if len(summaries) > 0 {
			message += " " + strings.Join(summaries, "; ")
		}
	}
	insights = append(insights, policy.Insight{
		Provider: "Cilium",
		Layer:    "Cilium Endpoint State",
		Check:    "target endpoints",
		Status:   status,
		Message:  message,
	})
	return insights
}

func ciliumEndpointStateInsight(ctx context.Context, client *kube.Client, check string, pod corev1.Pod) policy.Insight {
	cep, err := getCiliumEndpoint(ctx, client, pod)
	if err != nil {
		status := "WARN"
		message := fmt.Sprintf("Could not read CiliumEndpoint for pod %q in namespace %q: %v", pod.Name, pod.Namespace, err)
		if isNoMatch(err) || apierrors.IsNotFound(err) {
			message = fmt.Sprintf("No CiliumEndpoint was found for pod %q in namespace %q. Cilium may not manage this pod yet, the endpoint may not be ready, or RBAC may hide it.", pod.Name, pod.Namespace)
		}
		return policy.Insight{Provider: "Cilium", Layer: "Cilium Endpoint State", Check: check, Status: status, Message: message}
	}
	status := "PASS"
	state := ciliumEndpointString(cep, "status", "state")
	if !strings.EqualFold(state, "ready") {
		status = "WARN"
	}
	return policy.Insight{
		Provider: "Cilium",
		Layer:    "Cilium Endpoint State",
		Check:    check,
		Status:   status,
		Message:  ciliumEndpointSummary(cep, pod),
	}
}

func getCiliumEndpoint(ctx context.Context, client *kube.Client, pod corev1.Pod) (*unstructured.Unstructured, error) {
	return client.Dynamic.Resource(ciliumEndpointGVR).Namespace(pod.Namespace).Get(ctx, pod.Name, metav1.GetOptions{})
}

func ciliumEndpointSummary(cep *unstructured.Unstructured, pod corev1.Pod) string {
	state := ciliumEndpointString(cep, "status", "state")
	id, _, _ := unstructured.NestedInt64(cep.Object, "status", "id")
	identity, _, _ := unstructured.NestedInt64(cep.Object, "status", "identity", "id")
	node := ciliumEndpointString(cep, "status", "networking", "node")
	serviceAccount := ciliumEndpointString(cep, "status", "service-account")
	ip := ciliumEndpointIPv4(cep)
	ports := ciliumEndpointNamedPorts(cep)
	parts := []string{fmt.Sprintf("%s/%s", pod.Namespace, pod.Name)}
	if state != "" {
		parts = append(parts, "state="+state)
	}
	if id > 0 {
		parts = append(parts, fmt.Sprintf("endpointID=%d", id))
	}
	if identity > 0 {
		parts = append(parts, fmt.Sprintf("identity=%d", identity))
	}
	if ip != "" {
		parts = append(parts, "ip="+ip)
	}
	if node != "" {
		parts = append(parts, "node="+node)
	}
	if serviceAccount != "" {
		parts = append(parts, "serviceAccount="+serviceAccount)
	}
	if ports != "" {
		parts = append(parts, "namedPorts="+ports)
	}
	return strings.Join(parts, " ")
}

func ciliumEndpointString(cep *unstructured.Unstructured, fields ...string) string {
	value, _, _ := unstructured.NestedString(cep.Object, fields...)
	return value
}

func ciliumEndpointIPv4(cep *unstructured.Unstructured) string {
	addresses, _, _ := unstructured.NestedSlice(cep.Object, "status", "networking", "addressing")
	for _, item := range addresses {
		address, ok := item.(map[string]interface{})
		if !ok {
			continue
		}
		if value, ok := address["ipv4"].(string); ok && value != "" {
			return value
		}
	}
	return ""
}

func ciliumEndpointNamedPorts(cep *unstructured.Unstructured) string {
	items, _, _ := unstructured.NestedSlice(cep.Object, "status", "named-ports")
	if len(items) == 0 {
		return ""
	}
	var ports []string
	for _, item := range items {
		port, ok := item.(map[string]interface{})
		if !ok {
			continue
		}
		name, _ := port["name"].(string)
		protocol, _ := port["protocol"].(string)
		number := int64(0)
		switch value := port["port"].(type) {
		case int64:
			number = value
		case int:
			number = int64(value)
		case float64:
			number = int64(value)
		}
		if name == "" || number == 0 {
			continue
		}
		if protocol == "" {
			protocol = "TCP"
		}
		ports = appendUniqueLimited(ports, fmt.Sprintf("%s/%s:%d", name, protocol, number), 6)
	}
	return strings.Join(ports, ",")
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

func ciliumPolicyRulesAndTargetMatch(item unstructured.Unstructured, namespace corev1.Namespace, pods []corev1.Pod, clusterName string) (rules ciliumapi.Rules, matches bool, err error) {
	defer func() {
		if recovered := recover(); recovered != nil {
			rules = nil
			matches = false
			err = fmt.Errorf("panic while parsing Cilium policy: %v", recovered)
		}
	}()
	var cnp ciliumv2.CiliumNetworkPolicy
	data, err := json.Marshal(item.Object)
	if err != nil {
		return nil, false, err
	}
	if err := json.Unmarshal(data, &cnp); err != nil {
		return nil, false, err
	}
	rules, err = cnp.Parse(slog.Default(), "")
	if err != nil {
		return nil, false, err
	}
	return rules, ciliumRulesSelectPods(rules, namespace, pods, clusterName), nil
}

func ciliumRulesSelectPods(rules ciliumapi.Rules, namespace corev1.Namespace, pods []corev1.Pod, clusterName string) bool {
	for _, rule := range rules {
		for _, pod := range pods {
			if ciliumEndpointSelectorMatches(rule.EndpointSelector, ciliumPodLabelsForCluster(pod, namespace, clusterName)) {
				return true
			}
		}
	}
	return false
}

func analyzeCiliumPath(rules []namedRule, targetNamespace corev1.Namespace, targetPods []corev1.Pod, sourceNamespace corev1.Namespace, sourcePod corev1.Pod, service *corev1.Service, ports []int32, clusterName string, cidrGroups []ciliumCIDRGroup) []policy.Insight {
	var insights []policy.Insight
	candidates := ciliumPathPortCandidates(ports, service, targetPods)
	insights = append(insights, ciliumEgressDecision(rules, targetNamespace, targetPods, sourceNamespace, sourcePod, service, candidates, clusterName, cidrGroups))
	insights = append(insights, ciliumIngressDecision(rules, targetNamespace, targetPods, sourceNamespace, sourcePod, service, candidates, clusterName))
	return insights
}

type ciliumRuleMatch struct {
	Policy    string
	RuleIndex int
	Action    string
	Reason    string
}

type ciliumPortCandidate struct {
	Number   int32
	Name     string
	Protocol string
}

func ciliumEgressDecision(rules []namedRule, targetNamespace corev1.Namespace, targetPods []corev1.Pod, sourceNamespace corev1.Namespace, sourcePod corev1.Pod, service *corev1.Service, ports []ciliumPortCandidate, clusterName string, cidrGroups []ciliumCIDRGroup) policy.Insight {
	var selecting, allows, l7Allows, ambiguousAllows, ambiguousDenies, misses []string
	var denies []ciliumRuleMatch
	sourceLabels := ciliumPodLabelsForCluster(sourcePod, sourceNamespace, clusterName)
	for _, wrapped := range rules {
		if wrapped.Rule == nil || !ciliumEndpointSelectorMatches(wrapped.Rule.EndpointSelector, sourceLabels) {
			continue
		}
		if len(wrapped.Rule.EgressDeny) > 0 {
			selecting = append(selecting, wrapped.Name)
			for index, deny := range wrapped.Rule.EgressDeny {
				if ok, reason := ciliumEgressPeerMatches(deny.EgressCommonRule, targetNamespace, targetPods, service, clusterName, cidrGroups); ok {
					if ciliumDenyPortsMatch(deny.ToPorts, ports) {
						if strings.Contains(reason, "CIDR criteria include") {
							ambiguousDenies = append(ambiguousDenies, fmt.Sprintf("%s rule %d: %s; %s", wrapped.Name, index+1, reason, ciliumPortReason(deny.ToPorts, ports)))
						} else {
							denies = append(denies, ciliumRuleMatch{Policy: wrapped.Name, RuleIndex: index + 1, Action: "Deny", Reason: reason + "; " + ciliumPortReason(deny.ToPorts, ports)})
						}
					}
				}
			}
		}
		if len(wrapped.Rule.Egress) > 0 {
			selecting = append(selecting, wrapped.Name)
			for index, allow := range wrapped.Rule.Egress {
				peerOK, peerReason := ciliumEgressPeerMatches(allow.EgressCommonRule, targetNamespace, targetPods, service, clusterName, cidrGroups)
				portOK := ciliumPortsMatch(allow.ToPorts, ports)
				if peerOK && portOK {
					if strings.Contains(peerReason, "CIDR criteria include") {
						ambiguousAllows = append(ambiguousAllows, fmt.Sprintf("%s rule %d: %s", wrapped.Name, index+1, peerReason))
						continue
					}
					if ciliumPortRulesHaveL7(allow.ToPorts) {
						l7Allows = append(l7Allows, fmt.Sprintf("%s rule %d (%s)", wrapped.Name, index+1, ciliumL7Summary(allow.ToPorts)))
					} else {
						allows = append(allows, fmt.Sprintf("%s rule %d", wrapped.Name, index+1))
					}
				} else if !peerOK && portOK && strings.Contains(peerReason, "toServices selector does not match") {
					ambiguousAllows = append(ambiguousAllows, fmt.Sprintf("%s rule %d: %s", wrapped.Name, index+1, peerReason))
				} else {
					misses = appendUniqueLimited(misses, fmt.Sprintf("%s rule %d: %s", wrapped.Name, index+1, ciliumMissReason(peerOK, peerReason, portOK, ciliumPortReason(allow.ToPorts, ports))), 3)
				}
			}
		}
	}
	if len(denies) > 0 {
		first := denies[0]
		message := fmt.Sprintf("Cilium egressDeny blocks source pod %q from Service %q. First matching deny: %s rule %d. Reason: %s.", sourcePod.Name, ciliumServiceName(service), first.Policy, first.RuleIndex, first.Reason)
		if len(denies) > 1 {
			message += fmt.Sprintf(" %d additional matching deny rule(s) also select this path.", len(denies)-1)
		}
		return policy.Insight{Provider: "Cilium", Layer: "Cilium Policy Path", Check: "source egress to target", Status: "FAIL", Message: message, Diagnosis: fmt.Sprintf("Cilium explicit egressDeny blocks source pod %q from reaching Service %q.", sourcePod.Name, ciliumServiceName(service))}
	}
	if len(selecting) == 0 {
		return policy.Insight{Provider: "Cilium", Layer: "Cilium Policy Path", Check: "source egress to target", Status: "PASS", Message: "No Cilium egress rules select the source pod."}
	}
	if len(ambiguousDenies) > 0 {
		return policy.Insight{Provider: "Cilium", Layer: "Cilium Policy Path", Check: "source egress to target", Status: "WARN", Message: "Cilium egressDeny has CIDR criteria that include the target Service/pod IP, but in-cluster endpoint traffic may be enforced by identity rather than CIDR. Possible matching deny: " + strings.Join(uniqueStrings(ambiguousDenies), ", ") + ". Use runtime connectivity as the tie-breaker."}
	}
	if len(allows) > 0 {
		return policy.Insight{Provider: "Cilium", Layer: "Cilium Policy Path", Check: "source egress to target", Status: "PASS", Message: "Cilium egress policy appears to allow this target path. Matching policy/rule found in: " + strings.Join(uniqueStrings(allows), ", ")}
	}
	if len(l7Allows) > 0 {
		return policy.Insight{Provider: "Cilium", Layer: "Cilium Policy Path", Check: "source egress to target", Status: "WARN", Message: "Cilium egress policy allows the target at L3/L4, but L7 constraints are present: " + strings.Join(uniqueStrings(l7Allows), ", ") + ". Runtime HTTP/SNI/DNS behavior may still be blocked by these rules.", Diagnosis: "Cilium egress policy contains L7 constraints on the source-to-target path. If TCP connects but HTTP/SNI/DNS behavior fails, check those L7 rules."}
	}
	if len(ambiguousAllows) > 0 {
		return policy.Insight{Provider: "Cilium", Layer: "Cilium Policy Path", Check: "source egress to target", Status: "WARN", Message: "Cilium egress policy has an allow rule that may match this path, but static modeling cannot prove it cleanly: " + strings.Join(uniqueStrings(ambiguousAllows), ", ") + ". Use runtime connectivity as the tie-breaker."}
	}
	message := fmt.Sprintf("Cilium egress policy selects source pod %q, but no egress allow rule permits Service %q on the tested path. Policies: %s.", sourcePod.Name, ciliumServiceName(service), strings.Join(uniqueStrings(selecting), ", "))
	if len(misses) > 0 {
		message += " Closest allow-rule miss: " + strings.Join(misses, "; ") + "."
	}
	return policy.Insight{Provider: "Cilium", Layer: "Cilium Policy Path", Check: "source egress to target", Status: "FAIL", Message: message, Diagnosis: fmt.Sprintf("Cilium egress default-deny likely blocks source pod %q from reaching Service %q.", sourcePod.Name, ciliumServiceName(service))}
}

func ciliumExternalEgressDecision(rules []namedRule, sourceNamespace corev1.Namespace, sourcePod corev1.Pod, host string, port int32, clusterName string) policy.Insight {
	var selecting, allows, l7Allows, ambiguousAllows, misses []string
	var denies []ciliumRuleMatch
	sourceLabels := ciliumPodLabelsForCluster(sourcePod, sourceNamespace, clusterName)
	ports := []ciliumPortCandidate{{Number: port, Protocol: "TCP"}}
	for _, wrapped := range rules {
		if wrapped.Rule == nil || !ciliumEndpointSelectorMatches(wrapped.Rule.EndpointSelector, sourceLabels) {
			continue
		}
		if len(wrapped.Rule.EgressDeny) > 0 {
			selecting = append(selecting, wrapped.Name)
			for index, deny := range wrapped.Rule.EgressDeny {
				if ok, reason := ciliumExternalEgressCommonPeerMatches(deny.EgressCommonRule, host); ok && ciliumDenyPortsMatch(deny.ToPorts, ports) {
					denies = append(denies, ciliumRuleMatch{Policy: wrapped.Name, RuleIndex: index + 1, Action: "Deny", Reason: reason + "; " + ciliumPortReason(deny.ToPorts, ports)})
				}
			}
		}
		if len(wrapped.Rule.Egress) > 0 {
			selecting = append(selecting, wrapped.Name)
			for index, allow := range wrapped.Rule.Egress {
				peerOK, peerReason := ciliumExternalEgressAllowPeerMatches(allow, host)
				portOK := ciliumPortsMatch(allow.ToPorts, ports)
				if peerOK && portOK {
					if ciliumPortRulesHaveL7(allow.ToPorts) {
						l7Allows = append(l7Allows, fmt.Sprintf("%s rule %d (%s)", wrapped.Name, index+1, ciliumL7Summary(allow.ToPorts)))
					} else {
						allows = append(allows, fmt.Sprintf("%s rule %d (%s)", wrapped.Name, index+1, peerReason))
					}
				} else if !peerOK && portOK && strings.Contains(peerReason, "CIDR") {
					ambiguousAllows = append(ambiguousAllows, fmt.Sprintf("%s rule %d: %s", wrapped.Name, index+1, peerReason))
				} else {
					misses = appendUniqueLimited(misses, fmt.Sprintf("%s rule %d: %s", wrapped.Name, index+1, ciliumMissReason(peerOK, peerReason, portOK, ciliumPortReason(allow.ToPorts, ports))), 3)
				}
			}
		}
	}
	target := fmt.Sprintf("%s:%d", host, port)
	if len(denies) > 0 {
		first := denies[0]
		message := fmt.Sprintf("Cilium egressDeny blocks source pod %q from external target %s. First matching deny: %s rule %d. Reason: %s.", sourcePod.Name, target, first.Policy, first.RuleIndex, first.Reason)
		return policy.Insight{Provider: "Cilium", Layer: "Cilium External Policy Posture", Check: "external egress", Status: "FAIL", Message: message, Diagnosis: fmt.Sprintf("Cilium explicit egressDeny blocks source pod %q from reaching external target %s.", sourcePod.Name, target)}
	}
	if len(selecting) == 0 {
		return policy.Insight{Provider: "Cilium", Layer: "Cilium External Policy Posture", Check: "external egress", Status: "PASS", Message: fmt.Sprintf("No Cilium egress rules select source pod %q for external target %s.", sourcePod.Name, target)}
	}
	if len(allows) > 0 {
		return policy.Insight{Provider: "Cilium", Layer: "Cilium External Policy Posture", Check: "external egress", Status: "PASS", Message: "Cilium egress policy appears to allow this external target. Matching policy/rule found in: " + strings.Join(uniqueStrings(allows), ", ")}
	}
	if len(l7Allows) > 0 {
		return policy.Insight{Provider: "Cilium", Layer: "Cilium External Policy Posture", Check: "external egress", Status: "WARN", Message: "Cilium egress policy allows this external target at L3/L4, but L7 constraints are present: " + strings.Join(uniqueStrings(l7Allows), ", ") + ". Runtime HTTP/SNI/DNS behavior may still be blocked by these rules.", Diagnosis: "Cilium external egress policy contains L7 constraints. If TCP connects but HTTP/SNI/DNS behavior fails, check those L7 rules."}
	}
	if len(ambiguousAllows) > 0 {
		return policy.Insight{Provider: "Cilium", Layer: "Cilium External Policy Posture", Check: "external egress", Status: "WARN", Message: "Cilium egress policy has an allow rule that may match after DNS resolution, but static host-only modeling cannot prove it: " + strings.Join(uniqueStrings(ambiguousAllows), ", ") + ". Runtime connectivity is the tie-breaker."}
	}
	message := fmt.Sprintf("Cilium egress policy selects source pod %q, but no egress allow rule permits external target %s. Policies: %s.", sourcePod.Name, target, strings.Join(uniqueStrings(selecting), ", "))
	if len(misses) > 0 {
		message += " Closest allow-rule miss: " + strings.Join(misses, "; ") + "."
	}
	return policy.Insight{Provider: "Cilium", Layer: "Cilium External Policy Posture", Check: "external egress", Status: "FAIL", Message: message, Diagnosis: fmt.Sprintf("Cilium egress default-deny likely blocks source pod %q from reaching external target %s.", sourcePod.Name, target)}
}

func ciliumExternalEgressAllowPeerMatches(rule ciliumapi.EgressRule, host string) (bool, string) {
	if len(rule.ToFQDNs) > 0 {
		var patterns []string
		for _, selector := range rule.ToFQDNs {
			if ciliumFQDNSelectorMatches(selector, host) {
				return true, "toFQDNs matches " + host
			}
			if selector.MatchName != "" {
				patterns = append(patterns, selector.MatchName)
			}
			if selector.MatchPattern != "" {
				patterns = append(patterns, selector.MatchPattern)
			}
		}
		return false, "toFQDNs " + strings.Join(uniqueStrings(patterns), ",") + " do not match " + host
	}
	return ciliumExternalEgressCommonPeerMatches(rule.EgressCommonRule, host)
}

func ciliumExternalEgressCommonPeerMatches(rule ciliumapi.EgressCommonRule, host string) (bool, string) {
	if len(rule.ToEndpoints) == 0 && len(rule.ToCIDR) == 0 && len(rule.ToCIDRSet) == 0 && len(rule.ToServices) == 0 && len(rule.ToEntities) == 0 {
		return true, "no destination peer criteria, matches external target"
	}
	for _, entity := range rule.ToEntities {
		value := strings.ToLower(string(entity))
		if value == "all" || value == "world" {
			return true, "toEntities includes " + string(entity)
		}
	}
	if len(rule.ToCIDR) > 0 || len(rule.ToCIDRSet) > 0 {
		return false, "CIDR criteria require resolved destination IP evidence"
	}
	if len(rule.ToEndpoints) > 0 || len(rule.ToServices) > 0 {
		return false, "cluster endpoint/service criteria do not match an external URL target"
	}
	return false, "destination peer criteria do not match external target"
}

func ciliumFQDNSelectorMatches(selector ciliumapi.FQDNSelector, host string) bool {
	host = strings.TrimSuffix(strings.ToLower(strings.TrimSpace(host)), ".")
	matchName := strings.TrimSuffix(strings.ToLower(strings.TrimSpace(selector.MatchName)), ".")
	if matchName != "" && host == matchName {
		return true
	}
	pattern := strings.TrimSuffix(strings.ToLower(strings.TrimSpace(selector.MatchPattern)), ".")
	if pattern == "" {
		return false
	}
	return ciliumWildcardHostMatches(pattern, host)
}

func ciliumWildcardHostMatches(pattern, host string) bool {
	if pattern == "*" {
		return host != ""
	}
	parts := strings.Split(pattern, "*")
	if len(parts) == 1 {
		return host == pattern
	}
	if !strings.HasPrefix(host, parts[0]) {
		return false
	}
	pos := len(parts[0])
	for _, part := range parts[1 : len(parts)-1] {
		if part == "" {
			continue
		}
		idx := strings.Index(host[pos:], part)
		if idx < 0 {
			return false
		}
		pos += idx + len(part)
	}
	last := parts[len(parts)-1]
	return last == "" || strings.HasSuffix(host, last)
}

func ciliumIngressDecision(rules []namedRule, targetNamespace corev1.Namespace, targetPods []corev1.Pod, sourceNamespace corev1.Namespace, sourcePod corev1.Pod, service *corev1.Service, ports []ciliumPortCandidate, clusterName string) policy.Insight {
	var selecting, allows, l7Allows, misses []string
	var denies []ciliumRuleMatch
	sourceLabels := ciliumPodLabelsForCluster(sourcePod, sourceNamespace, clusterName)
	for _, wrapped := range rules {
		if wrapped.Rule == nil || !ciliumRuleSelectsAnyTarget(wrapped.Rule, targetPods, targetNamespace, clusterName) {
			continue
		}
		if len(wrapped.Rule.IngressDeny) > 0 {
			selecting = append(selecting, wrapped.Name)
			for index, deny := range wrapped.Rule.IngressDeny {
				if ok, reason := ciliumIngressPeerMatches(deny.IngressCommonRule, sourceLabels); ok {
					if ciliumDenyPortsMatch(deny.ToPorts, ports) {
						denies = append(denies, ciliumRuleMatch{Policy: wrapped.Name, RuleIndex: index + 1, Action: "Deny", Reason: reason + "; " + ciliumPortReason(deny.ToPorts, ports)})
					}
				}
			}
		}
		if len(wrapped.Rule.Ingress) > 0 {
			selecting = append(selecting, wrapped.Name)
			for index, allow := range wrapped.Rule.Ingress {
				peerOK, peerReason := ciliumIngressPeerMatches(allow.IngressCommonRule, sourceLabels)
				portOK := ciliumPortsMatch(allow.ToPorts, ports)
				if peerOK && portOK {
					if ciliumPortRulesHaveL7(allow.ToPorts) {
						l7Allows = append(l7Allows, fmt.Sprintf("%s rule %d (%s)", wrapped.Name, index+1, ciliumL7Summary(allow.ToPorts)))
					} else {
						allows = append(allows, fmt.Sprintf("%s rule %d", wrapped.Name, index+1))
					}
				} else {
					misses = appendUniqueLimited(misses, fmt.Sprintf("%s rule %d: %s", wrapped.Name, index+1, ciliumMissReason(peerOK, peerReason, portOK, ciliumPortReason(allow.ToPorts, ports))), 3)
				}
			}
		}
	}
	if len(denies) > 0 {
		first := denies[0]
		message := fmt.Sprintf("Cilium ingressDeny blocks source pod %q from Service %q. First matching deny: %s rule %d. Reason: %s.", sourcePod.Name, ciliumServiceName(service), first.Policy, first.RuleIndex, first.Reason)
		if len(denies) > 1 {
			message += fmt.Sprintf(" %d additional matching deny rule(s) also select this path.", len(denies)-1)
		}
		return policy.Insight{Provider: "Cilium", Layer: "Cilium Policy Path", Check: "target ingress from source", Status: "FAIL", Message: message, Diagnosis: fmt.Sprintf("Cilium explicit ingressDeny blocks source pod %q from reaching Service %q.", sourcePod.Name, ciliumServiceName(service))}
	}
	if len(selecting) == 0 {
		return policy.Insight{Provider: "Cilium", Layer: "Cilium Policy Path", Check: "target ingress from source", Status: "PASS", Message: "No Cilium ingress rules select the target pods."}
	}
	if len(allows) > 0 {
		return policy.Insight{Provider: "Cilium", Layer: "Cilium Policy Path", Check: "target ingress from source", Status: "PASS", Message: "Cilium ingress policy appears to allow this source path. Matching policy/rule found in: " + strings.Join(uniqueStrings(allows), ", ")}
	}
	if len(l7Allows) > 0 {
		return policy.Insight{Provider: "Cilium", Layer: "Cilium Policy Path", Check: "target ingress from source", Status: "WARN", Message: "Cilium ingress policy allows the source at L3/L4, but L7 constraints are present: " + strings.Join(uniqueStrings(l7Allows), ", ") + ". Runtime HTTP/SNI/DNS behavior may still be blocked by these rules.", Diagnosis: "Cilium ingress policy contains L7 constraints on the source-to-target path. If TCP connects but HTTP/SNI/DNS behavior fails, check those L7 rules."}
	}
	message := fmt.Sprintf("Cilium ingress policy selects target pods, but no ingress allow rule permits source pod %q on the tested path. Policies: %s.", sourcePod.Name, strings.Join(uniqueStrings(selecting), ", "))
	if len(misses) > 0 {
		message += " Closest allow-rule miss: " + strings.Join(misses, "; ") + "."
	}
	return policy.Insight{Provider: "Cilium", Layer: "Cilium Policy Path", Check: "target ingress from source", Status: "FAIL", Message: message, Diagnosis: fmt.Sprintf("Cilium ingress default-deny likely blocks source pod %q from reaching Service %q.", sourcePod.Name, ciliumServiceName(service))}
}

func analyzeCiliumDNS(rules []namedRule, sourceNamespace corev1.Namespace, sourcePod corev1.Pod, dns DNSContext, clusterName string, cidrGroups []ciliumCIDRGroup) []policy.Insight {
	if len(dns.Nameservers) == 0 {
		return nil
	}
	sourceLabels := ciliumPodLabelsForCluster(sourcePod, sourceNamespace, clusterName)
	var selecting []string
	for _, wrapped := range rules {
		if wrapped.Rule != nil && ciliumEndpointSelectorMatches(wrapped.Rule.EndpointSelector, sourceLabels) && (len(wrapped.Rule.Egress) > 0 || len(wrapped.Rule.EgressDeny) > 0) {
			selecting = append(selecting, wrapped.Name)
		}
	}
	if len(selecting) == 0 {
		return []policy.Insight{{Provider: "Cilium", Layer: "Cilium DNS Policy Path", Check: "source DNS egress", Status: "PASS", Message: "No Cilium egress rules select the source pod for DNS traffic."}}
	}
	for _, resolver := range uniqueStrings(dns.Nameservers) {
		for _, wrapped := range rules {
			if wrapped.Rule == nil || !ciliumEndpointSelectorMatches(wrapped.Rule.EndpointSelector, sourceLabels) {
				continue
			}
			for index, deny := range wrapped.Rule.EgressDeny {
				if ciliumDNSPeerMatches(deny.EgressCommonRule, resolver, dns, clusterName, cidrGroups) && ciliumDenyPortsMatch(deny.ToPorts, ciliumDNSPortCandidates()) {
					return []policy.Insight{{Provider: "Cilium", Layer: "Cilium DNS Policy Path", Check: "source DNS egress", Status: "FAIL", Message: fmt.Sprintf("Cilium egressDeny blocks DNS from source pod %q to runtime resolver %s via %s rule %d.", sourcePod.Name, describeResolver(resolver), wrapped.Name, index+1), Diagnosis: fmt.Sprintf("Primary issue: Cilium egressDeny blocks DNS from source pod %q to its runtime resolver %s.", sourcePod.Name, describeResolver(resolver))}}
				}
			}
			for _, allow := range wrapped.Rule.Egress {
				if ciliumDNSPeerMatches(allow.EgressCommonRule, resolver, dns, clusterName, cidrGroups) && ciliumPortsMatch(allow.ToPorts, ciliumDNSPortCandidates()) {
					return []policy.Insight{{Provider: "Cilium", Layer: "Cilium DNS Policy Path", Check: "source DNS egress", Status: "PASS", Message: fmt.Sprintf("Cilium egress policy appears to allow DNS from source pod %q to runtime resolver %s.", sourcePod.Name, describeResolver(resolver))}}
				}
			}
		}
		return []policy.Insight{{Provider: "Cilium", Layer: "Cilium DNS Policy Path", Check: "source DNS egress", Status: "FAIL", Message: fmt.Sprintf("Cilium egress policy selects source pod %q, but no egress allow rule permits DNS to runtime resolver %s. Policies: %s.", sourcePod.Name, describeResolver(resolver), strings.Join(uniqueStrings(selecting), ", ")), Diagnosis: fmt.Sprintf("Primary issue: Cilium egress policy does not allow source pod %q to reach its runtime DNS resolver %s.", sourcePod.Name, describeResolver(resolver))}}
	}
	return nil
}

func ciliumPodLabels(pod corev1.Pod, namespace corev1.Namespace) slimlabels.Set {
	return ciliumPodLabelsForCluster(pod, namespace, "default")
}

func ciliumPodLabelsForCluster(pod corev1.Pod, namespace corev1.Namespace, clusterName string) slimlabels.Set {
	labels := slimlabels.Set{}
	if clusterName == "" {
		clusterName = "default"
	}
	for k, v := range pod.Labels {
		labels[k] = v
		labels["k8s:"+k] = v
		labels["any:"+k] = v
	}
	serviceAccount := pod.Spec.ServiceAccountName
	if serviceAccount == "" {
		serviceAccount = "default"
	}
	labels["io.kubernetes.pod.namespace"] = pod.Namespace
	labels["k8s:io.kubernetes.pod.namespace"] = pod.Namespace
	labels["any:io.kubernetes.pod.namespace"] = pod.Namespace
	labels["io.cilium.k8s.policy.serviceaccount"] = serviceAccount
	labels["k8s:io.cilium.k8s.policy.serviceaccount"] = serviceAccount
	labels["any:io.cilium.k8s.policy.serviceaccount"] = serviceAccount
	labels["io.cilium.k8s.policy.cluster"] = clusterName
	labels["k8s:io.cilium.k8s.policy.cluster"] = clusterName
	labels["any:io.cilium.k8s.policy.cluster"] = clusterName
	for k, v := range namespace.Labels {
		key := "io.cilium.k8s.namespace.labels." + k
		labels[key] = v
		labels["k8s:"+key] = v
		labels["any:"+key] = v
	}
	return labels
}

func ciliumEndpointSelectorMatches(selector ciliumapi.EndpointSelector, labels slimlabels.Set) bool {
	if selector.Matches(labels) {
		return true
	}
	for key, want := range selector.LabelSelector.MatchLabels {
		if !ciliumLabelValueMatches(labels, key, []string{want}) {
			return false
		}
	}
	for _, expr := range selector.LabelSelector.MatchExpressions {
		switch strings.ToLower(string(expr.Operator)) {
		case "in":
			if !ciliumLabelValueMatches(labels, expr.Key, expr.Values) {
				return false
			}
		case "notin":
			if ciliumLabelValueMatches(labels, expr.Key, expr.Values) {
				return false
			}
		case "exists":
			if !ciliumLabelExists(labels, expr.Key) {
				return false
			}
		case "doesnotexist":
			if ciliumLabelExists(labels, expr.Key) {
				return false
			}
		default:
			return false
		}
	}
	return true
}

func ciliumLabelValueMatches(labels slimlabels.Set, key string, values []string) bool {
	for _, candidate := range ciliumLabelKeyCandidates(key) {
		if !labels.Has(candidate) {
			continue
		}
		got := labels.Get(candidate)
		for _, value := range values {
			if got == value {
				return true
			}
		}
	}
	return false
}

func ciliumLabelExists(labels slimlabels.Set, key string) bool {
	for _, candidate := range ciliumLabelKeyCandidates(key) {
		if labels.Has(candidate) {
			return true
		}
	}
	return false
}

func ciliumLabelKeyCandidates(key string) []string {
	candidates := []string{key}
	if strings.HasPrefix(key, "any.") {
		trimmed := strings.TrimPrefix(key, "any.")
		candidates = append(candidates, trimmed, "any:"+trimmed, "k8s:"+trimmed, "k8s."+trimmed)
	}
	if strings.HasPrefix(key, "k8s.") {
		trimmed := strings.TrimPrefix(key, "k8s.")
		candidates = append(candidates, trimmed, "k8s:"+trimmed, "any:"+trimmed, "any."+trimmed)
	}
	for _, prefix := range []string{"any:", "k8s:"} {
		if strings.HasPrefix(key, prefix) {
			trimmed := strings.TrimPrefix(key, prefix)
			candidates = append(candidates, trimmed)
			if prefix == "any:" {
				candidates = append(candidates, "k8s:"+trimmed)
			} else {
				candidates = append(candidates, "any:"+trimmed)
			}
		} else {
			candidates = append(candidates, prefix+key)
		}
	}
	return uniqueStrings(candidates)
}

func ciliumRuleSelectsAnyTarget(rule *ciliumapi.Rule, pods []corev1.Pod, namespace corev1.Namespace, clusterName string) bool {
	for _, pod := range pods {
		if ciliumEndpointSelectorMatches(rule.EndpointSelector, ciliumPodLabelsForCluster(pod, namespace, clusterName)) {
			return true
		}
	}
	return false
}

func ciliumEgressPeerMatches(rule ciliumapi.EgressCommonRule, targetNamespace corev1.Namespace, targetPods []corev1.Pod, service *corev1.Service, clusterName string, cidrGroups []ciliumCIDRGroup) (bool, string) {
	if len(rule.ToEndpoints) == 0 && len(rule.ToCIDR) == 0 && len(rule.ToCIDRSet) == 0 && len(rule.ToServices) == 0 && len(rule.ToEntities) == 0 {
		return true, "no destination peer criteria, matches the target"
	}
	var misses []string
	for _, selector := range rule.ToEndpoints {
		matched := false
		for _, pod := range targetPods {
			if ciliumEndpointSelectorMatches(selector, ciliumPodLabelsForCluster(pod, targetNamespace, clusterName)) {
				matched = true
				break
			}
		}
		if matched {
			if !ciliumRequiresMatch(rule.ToRequires, targetPods, targetNamespace, clusterName) {
				return false, "toRequires constraints do not match target pod labels"
			}
			return true, "toEndpoints selector matches target pod labels"
		}
		misses = appendUniqueLimited(misses, "toEndpoints selector does not match target pod labels", 2)
	}
	if service != nil {
		for _, svc := range rule.ToServices {
			if svc.K8sService != nil && svc.K8sService.ServiceName == service.Name && (svc.K8sService.Namespace == "" || svc.K8sService.Namespace == service.Namespace) {
				return true, "toServices matches target Service name/namespace"
			}
			if svc.K8sServiceSelector != nil {
				selector := ciliumapi.EndpointSelector(svc.K8sServiceSelector.Selector)
				if !ciliumEndpointSelectorMatches(selector, ciliumServiceLabels(service)) {
					misses = appendUniqueLimited(misses, "toServices selector does not match target Service labels", 2)
					continue
				}
				if svc.K8sServiceSelector.Namespace == "" || svc.K8sServiceSelector.Namespace == service.Namespace {
					return true, "toServices selector matches target Service labels"
				}
				misses = appendUniqueLimited(misses, "toServices namespace does not match target Service namespace", 2)
			}
		}
	}
	for _, entity := range rule.ToEntities {
		if strings.EqualFold(string(entity), "all") || strings.EqualFold(string(entity), "cluster") {
			return true, "toEntities includes " + string(entity)
		}
	}
	if ciliumCIDRMatches(rule.ToCIDR, rule.ToCIDRSet, service, targetPods, cidrGroups) {
		return true, "CIDR criteria include target Service/pod IP"
	}
	if len(misses) > 0 {
		return false, strings.Join(misses, "; ")
	}
	return false, "destination peer criteria do not match target Service/pods"
}

func ciliumIngressPeerMatches(rule ciliumapi.IngressCommonRule, sourceLabels slimlabels.Set) (bool, string) {
	if len(rule.FromEndpoints) == 0 && len(rule.FromCIDR) == 0 && len(rule.FromCIDRSet) == 0 && len(rule.FromEntities) == 0 {
		return true, "no source peer criteria, matches the source"
	}
	var misses []string
	for _, selector := range rule.FromEndpoints {
		if ciliumEndpointSelectorMatches(selector, sourceLabels) {
			if !ciliumSourceRequiresMatch(rule.FromRequires, sourceLabels) {
				return false, "fromRequires constraints do not match source pod labels"
			}
			return true, "fromEndpoints selector matches source pod labels"
		}
		misses = appendUniqueLimited(misses, "fromEndpoints selector does not match source pod labels", 2)
	}
	for _, entity := range rule.FromEntities {
		if strings.EqualFold(string(entity), "all") || strings.EqualFold(string(entity), "cluster") {
			return true, "fromEntities includes " + string(entity)
		}
	}
	if len(rule.FromCIDR) > 0 || len(rule.FromCIDRSet) > 0 {
		misses = appendUniqueLimited(misses, "fromCIDR/fromCIDRSet cannot be proven for in-cluster pod source identity", 2)
	}
	if len(misses) > 0 {
		return false, strings.Join(misses, "; ")
	}
	return false, "source peer criteria do not match source pod"
}

func ciliumPortsMatch(portRules ciliumapi.PortRules, ports []ciliumPortCandidate) bool {
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

func ciliumDenyPortsMatch(portRules ciliumapi.PortDenyRules, ports []ciliumPortCandidate) bool {
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

func ciliumPortProtocolMatches(rule ciliumapi.PortProtocol, ports []ciliumPortCandidate) bool {
	protocol := strings.ToUpper(string(rule.Protocol))
	if rule.Port == "" {
		return true
	}
	parsed, err := strconv.Atoi(rule.Port)
	if err != nil {
		for _, port := range ports {
			if ciliumCandidateProtocolMatches(protocol, port) && port.Name != "" && port.Name == rule.Port {
				return true
			}
		}
		return false
	}
	for _, port := range ports {
		if !ciliumCandidateProtocolMatches(protocol, port) {
			continue
		}
		if int32(parsed) == port.Number || (rule.EndPort > 0 && port.Number >= int32(parsed) && port.Number <= rule.EndPort) {
			return true
		}
	}
	return false
}

func ciliumCandidateProtocolMatches(ruleProtocol string, candidate ciliumPortCandidate) bool {
	if ruleProtocol == "" || ruleProtocol == "ANY" {
		return true
	}
	candidateProtocol := strings.ToUpper(candidate.Protocol)
	if candidateProtocol == "" {
		candidateProtocol = "TCP"
	}
	return ruleProtocol == candidateProtocol
}

func ciliumPortReason[T interface {
	GetPortProtocols() []ciliumapi.PortProtocol
}](portRules []T, ports []ciliumPortCandidate) string {
	if len(portRules) == 0 || len(ports) == 0 {
		return "no port criteria, applies to tested path"
	}
	var allowed []string
	for _, rule := range portRules {
		if len(rule.GetPortProtocols()) == 0 {
			return "empty port criteria, applies to tested path"
		}
		for _, port := range rule.GetPortProtocols() {
			allowed = append(allowed, ciliumPortProtocolText(port))
			if ciliumPortProtocolMatches(port, ports) {
				return "port criteria matches " + formatPortCandidates(ports)
			}
		}
	}
	return fmt.Sprintf("port criteria %s do not include tested path %s", strings.Join(uniqueStrings(allowed), ","), formatPortCandidates(ports))
}

func ciliumMissReason(peerOK bool, peerReason string, portOK bool, portReason string) string {
	var parts []string
	if !peerOK {
		parts = append(parts, peerReason)
	}
	if !portOK {
		parts = append(parts, portReason)
	}
	if len(parts) == 0 {
		return "rule did not match"
	}
	return strings.Join(parts, "; ")
}

func ciliumPortProtocolText(port ciliumapi.PortProtocol) string {
	proto := strings.ToUpper(string(port.Protocol))
	if proto == "" {
		proto = "ANY"
	}
	if port.EndPort > 0 {
		return fmt.Sprintf("%s:%d/%s", port.Port, port.EndPort, proto)
	}
	return fmt.Sprintf("%s/%s", port.Port, proto)
}

func ciliumPortRulesHaveL7(portRules ciliumapi.PortRules) bool {
	for _, rule := range portRules {
		if rule.Rules != nil && !rule.Rules.IsEmpty() {
			return true
		}
		if len(rule.ServerNames) > 0 || rule.TerminatingTLS != nil || rule.OriginatingTLS != nil || rule.Listener != nil {
			return true
		}
	}
	return false
}

func ciliumL7Summary(portRules ciliumapi.PortRules) string {
	var parts []string
	for _, rule := range portRules {
		if rule.Rules != nil {
			if len(rule.Rules.HTTP) > 0 {
				parts = append(parts, "HTTP")
			}
			if len(rule.Rules.Kafka) > 0 {
				parts = append(parts, "Kafka")
			}
			if len(rule.Rules.DNS) > 0 {
				parts = append(parts, "DNS")
			}
			if len(rule.Rules.L7) > 0 || rule.Rules.L7Proto != "" {
				if rule.Rules.L7Proto != "" {
					parts = append(parts, "L7:"+rule.Rules.L7Proto)
				} else {
					parts = append(parts, "L7")
				}
			}
		}
		if len(rule.ServerNames) > 0 {
			parts = append(parts, "SNI")
		}
		if rule.TerminatingTLS != nil || rule.OriginatingTLS != nil {
			parts = append(parts, "TLS")
		}
		if rule.Listener != nil {
			parts = append(parts, "listener")
		}
	}
	parts = uniqueStrings(parts)
	if len(parts) == 0 {
		return "L7 constraints"
	}
	return strings.Join(parts, "+")
}

func ciliumPathPortCandidates(ports []int32, service *corev1.Service, pods []corev1.Pod) []ciliumPortCandidate {
	var candidates []ciliumPortCandidate
	if service != nil {
		for _, servicePort := range service.Spec.Ports {
			selected := containsPortNumber(ports, servicePort.Port)
			if servicePort.TargetPort.Type == intstr.String && servicePort.TargetPort.StrVal != "" {
				for _, pod := range pods {
					for _, container := range pod.Spec.Containers {
						for _, containerPort := range container.Ports {
							if containerPort.Name == servicePort.TargetPort.StrVal {
								selected = true
								candidates = appendUniqueCiliumPortCandidate(candidates, ciliumPortCandidate{Number: containerPort.ContainerPort, Name: servicePort.TargetPort.StrVal, Protocol: string(containerPort.Protocol)})
							}
						}
					}
				}
			} else if servicePort.TargetPort.Type == intstr.Int && servicePort.TargetPort.IntValue() > 0 {
				target := int32(servicePort.TargetPort.IntValue())
				if selected || containsPortNumber(ports, target) {
					candidates = appendUniqueCiliumPortCandidate(candidates, ciliumPortCandidate{Number: target, Name: ciliumContainerPortName(pods, target), Protocol: string(servicePort.Protocol)})
				}
			} else if selected {
				candidates = appendUniqueCiliumPortCandidate(candidates, ciliumPortCandidate{Number: servicePort.Port, Name: ciliumContainerPortName(pods, servicePort.Port), Protocol: string(servicePort.Protocol)})
			}
		}
	}
	for _, pod := range pods {
		for _, container := range pod.Spec.Containers {
			for _, containerPort := range container.Ports {
				if containerPort.Name != "" && containsPortNumber(ports, containerPort.ContainerPort) {
					candidates = appendUniqueCiliumPortCandidate(candidates, ciliumPortCandidate{Number: containerPort.ContainerPort, Name: containerPort.Name, Protocol: string(containerPort.Protocol)})
				}
			}
		}
	}
	if len(candidates) == 0 {
		for _, port := range ports {
			candidates = appendUniqueCiliumPortCandidate(candidates, ciliumPortCandidate{Number: port, Protocol: "TCP"})
		}
	}
	return candidates
}

func appendUniqueCiliumPortCandidate(candidates []ciliumPortCandidate, candidate ciliumPortCandidate) []ciliumPortCandidate {
	for _, existing := range candidates {
		if existing.Number == candidate.Number && existing.Name == candidate.Name && strings.EqualFold(existing.Protocol, candidate.Protocol) {
			return candidates
		}
	}
	return append(candidates, candidate)
}

func ciliumContainerPortName(pods []corev1.Pod, number int32) string {
	for _, pod := range pods {
		for _, container := range pod.Spec.Containers {
			for _, port := range container.Ports {
				if port.ContainerPort == number && port.Name != "" {
					return port.Name
				}
			}
		}
	}
	return ""
}

func formatPortCandidates(ports []ciliumPortCandidate) string {
	if len(ports) == 0 {
		return "(unknown)"
	}
	var values []string
	for _, port := range ports {
		proto := strings.ToUpper(port.Protocol)
		if proto == "" {
			proto = "TCP"
		}
		if port.Name != "" {
			values = append(values, fmt.Sprintf("%d/%s/%s", port.Number, port.Name, proto))
		} else {
			values = append(values, fmt.Sprintf("%d/%s", port.Number, proto))
		}
	}
	return strings.Join(uniqueStrings(values), ",")
}

func ciliumDNSPortCandidates() []ciliumPortCandidate {
	return []ciliumPortCandidate{{Number: 53, Protocol: "UDP"}, {Number: 53, Protocol: "TCP"}}
}

func ciliumServiceLabels(service *corev1.Service) slimlabels.Set {
	labels := slimlabels.Set{}
	if service == nil {
		return labels
	}
	for k, v := range service.Labels {
		labels[k] = v
		labels["k8s:"+k] = v
		labels["any:"+k] = v
	}
	return labels
}

func ciliumRequiresMatch(selectors []ciliumapi.EndpointSelector, pods []corev1.Pod, namespace corev1.Namespace, clusterName string) bool {
	for _, selector := range selectors {
		found := false
		for _, pod := range pods {
			if ciliumEndpointSelectorMatches(selector, ciliumPodLabelsForCluster(pod, namespace, clusterName)) {
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

func ciliumSourceRequiresMatch(selectors []ciliumapi.EndpointSelector, labels slimlabels.Set) bool {
	for _, selector := range selectors {
		if !ciliumEndpointSelectorMatches(selector, labels) {
			return false
		}
	}
	return true
}

func ciliumCIDRMatches(cidrs ciliumapi.CIDRSlice, cidrRules ciliumapi.CIDRRuleSlice, service *corev1.Service, pods []corev1.Pod, cidrGroups []ciliumCIDRGroup) bool {
	var ips []string
	if service != nil && service.Spec.ClusterIP != "" && service.Spec.ClusterIP != "None" {
		ips = append(ips, service.Spec.ClusterIP)
	}
	for _, pod := range pods {
		if pod.Status.PodIP != "" {
			ips = append(ips, pod.Status.PodIP)
		}
	}
	for _, ip := range ips {
		for _, cidr := range cidrs {
			if ipInCIDR(ip, string(cidr), nil) {
				return true
			}
		}
		for _, rule := range cidrRules {
			var except []string
			for _, cidr := range rule.ExceptCIDRs {
				except = append(except, string(cidr))
			}
			if ipInCIDR(ip, string(rule.Cidr), except) {
				return true
			}
			for _, cidr := range ciliumCIDRGroupCIDRs(rule, cidrGroups) {
				if ipInCIDR(ip, cidr, except) {
					return true
				}
			}
		}
	}
	return false
}

func ciliumCIDRGroupCIDRs(rule ciliumapi.CIDRRule, groups []ciliumCIDRGroup) []string {
	var cidrs []string
	if rule.CIDRGroupRef != "" {
		for _, group := range groups {
			if group.Name == string(rule.CIDRGroupRef) {
				cidrs = append(cidrs, group.CIDRs...)
			}
		}
	}
	if rule.CIDRGroupSelector != nil {
		for _, group := range groups {
			if ciliumCIDRGroupSelectorMatches(rule.CIDRGroupSelector, group) {
				cidrs = append(cidrs, group.CIDRs...)
			}
		}
	}
	return uniqueStrings(cidrs)
}

func ciliumCIDRGroupSelectorMatches(selector *slimmetav1.LabelSelector, group ciliumCIDRGroup) bool {
	if selector == nil {
		return false
	}
	for key, want := range selector.MatchLabels {
		if group.Labels[key] != want {
			return false
		}
	}
	for _, expr := range selector.MatchExpressions {
		switch strings.ToLower(string(expr.Operator)) {
		case "in":
			if !stringInSlice(group.Labels[expr.Key], expr.Values) {
				return false
			}
		case "notin":
			if stringInSlice(group.Labels[expr.Key], expr.Values) {
				return false
			}
		case "exists":
			if _, ok := group.Labels[expr.Key]; !ok {
				return false
			}
		case "doesnotexist":
			if _, ok := group.Labels[expr.Key]; ok {
				return false
			}
		default:
			return false
		}
	}
	return true
}

func ipInCIDR(address, cidr string, except []string) bool {
	if address == "" || cidr == "" {
		return false
	}
	ip, err := netip.ParseAddr(address)
	if err != nil {
		return false
	}
	prefix, err := netip.ParsePrefix(cidr)
	if err != nil || !prefix.Contains(ip) {
		return false
	}
	for _, item := range except {
		exceptPrefix, err := netip.ParsePrefix(item)
		if err == nil && exceptPrefix.Contains(ip) {
			return false
		}
	}
	return true
}

func ciliumDNSPeerMatches(rule ciliumapi.EgressCommonRule, resolver string, dns DNSContext, clusterName string, cidrGroups []ciliumCIDRGroup) bool {
	if len(rule.ToEndpoints) == 0 && len(rule.ToCIDR) == 0 && len(rule.ToCIDRSet) == 0 && len(rule.ToServices) == 0 && len(rule.ToEntities) == 0 {
		return true
	}
	resolverNamespace := corev1.Namespace{ObjectMeta: metav1.ObjectMeta{Name: "kube-system"}}
	resolverPods := dnsPodsForResolver(resolver, dns)
	var resolverService *corev1.Service
	if resolver != dns.CoreDNSServiceIP {
		resolverService = fakeDNSService(resolver, dns)
	}
	for _, pod := range resolverPods {
		if ok, _ := ciliumEgressPeerMatches(rule, resolverNamespace, []corev1.Pod{pod}, resolverService, clusterName, cidrGroups); ok {
			return true
		}
	}
	if len(resolverPods) == 0 && ciliumCIDRMatches(rule.ToCIDR, rule.ToCIDRSet, fakeDNSService(resolver, dns), []corev1.Pod{{Status: corev1.PodStatus{PodIP: resolver}}}, cidrGroups) {
		return true
	}
	return false
}

func fakeDNSService(resolver string, dns DNSContext) *corev1.Service {
	if dns.CoreDNSServiceIP != "" && resolver == dns.CoreDNSServiceIP {
		return &corev1.Service{ObjectMeta: metav1.ObjectMeta{Name: "kube-dns", Namespace: "kube-system"}, Spec: corev1.ServiceSpec{ClusterIP: dns.CoreDNSServiceIP}}
	}
	return nil
}

func dnsPodsForResolver(resolver string, dns DNSContext) []corev1.Pod {
	if isNodeLocalResolver(resolver) {
		return dns.NodeLocalDNSPods
	}
	if dns.CoreDNSServiceIP != "" && resolver == dns.CoreDNSServiceIP {
		return dns.CoreDNSPods
	}
	for _, pod := range append(dns.CoreDNSPods, dns.NodeLocalDNSPods...) {
		if pod.Status.PodIP == resolver {
			return []corev1.Pod{pod}
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

func containsPortNumber(ports []int32, port int32) bool {
	for _, current := range ports {
		if current == port {
			return true
		}
	}
	return false
}

func stringInSlice(value string, values []string) bool {
	for _, current := range values {
		if value == current {
			return true
		}
	}
	return false
}

func appendUniqueLimited(values []string, value string, limit int) []string {
	if value == "" {
		return values
	}
	for _, existing := range values {
		if existing == value {
			return values
		}
	}
	if limit > 0 && len(values) >= limit {
		return values
	}
	return append(values, value)
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
