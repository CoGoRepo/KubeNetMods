package native

import (
	"fmt"
	"net/netip"
	"sort"
	"strings"

	corev1 "k8s.io/api/core/v1"
	networkingv1 "k8s.io/api/networking/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/labels"
	"k8s.io/apimachinery/pkg/util/intstr"
)

func PolicyNamesSelectingPods(policies []networkingv1.NetworkPolicy, pods []corev1.Pod) []string {
	var names []string
	for _, policy := range policies {
		selector, err := metav1.LabelSelectorAsSelector(&policy.Spec.PodSelector)
		if err != nil {
			continue
		}
		for _, pod := range pods {
			if selector.Matches(labels.Set(pod.Labels)) {
				names = append(names, policy.Name)
				break
			}
		}
	}
	sort.Strings(names)
	return names
}

func PolicySelectsPod(netpol networkingv1.NetworkPolicy, pod corev1.Pod) bool {
	selector, err := metav1.LabelSelectorAsSelector(&netpol.Spec.PodSelector)
	if err != nil {
		return false
	}
	return selector.Matches(labels.Set(pod.Labels))
}

func HasPolicyType(netpol networkingv1.NetworkPolicy, policyType networkingv1.PolicyType) bool {
	if len(netpol.Spec.PolicyTypes) == 0 {
		if policyType == networkingv1.PolicyTypeIngress {
			return true
		}
		if policyType == networkingv1.PolicyTypeEgress {
			return len(netpol.Spec.Egress) > 0
		}
	}
	for _, current := range netpol.Spec.PolicyTypes {
		if current == policyType {
			return true
		}
	}
	return false
}

func EgressRuleAllows(rule networkingv1.NetworkPolicyEgressRule, targetNamespace corev1.Namespace, targets []corev1.Pod, service *corev1.Service, ports []int32, policyNamespace string) bool {
	if !PortsAllow(rule.Ports, ports) {
		return false
	}
	if len(rule.To) == 0 {
		return true
	}
	clusterIP := ""
	if service != nil && service.Spec.ClusterIP != "None" {
		clusterIP = service.Spec.ClusterIP
	}
	for _, peer := range rule.To {
		if clusterIP != "" && IPBlockContains(peer.IPBlock, clusterIP) {
			return true
		}
		for _, pod := range targets {
			if PeerMatchesPod(peer, pod, targetNamespace, policyNamespace) {
				return true
			}
			if pod.Status.PodIP != "" && IPBlockContains(peer.IPBlock, pod.Status.PodIP) {
				return true
			}
		}
	}
	return false
}

func IngressRuleAllows(rule networkingv1.NetworkPolicyIngressRule, source corev1.Pod, sourceNamespace corev1.Namespace, ports []int32) bool {
	if !PortsAllow(rule.Ports, ports) {
		return false
	}
	if len(rule.From) == 0 {
		return true
	}
	for _, peer := range rule.From {
		if PeerMatchesPod(peer, source, sourceNamespace, "") {
			return true
		}
		if source.Status.PodIP != "" && IPBlockContains(peer.IPBlock, source.Status.PodIP) {
			return true
		}
	}
	return false
}

func PeerMatchesPod(peer networkingv1.NetworkPolicyPeer, pod corev1.Pod, namespace corev1.Namespace, policyNamespace string) bool {
	if peer.NamespaceSelector == nil && peer.PodSelector == nil {
		return false
	}
	if peer.NamespaceSelector != nil {
		nsSelector, err := metav1.LabelSelectorAsSelector(peer.NamespaceSelector)
		if err != nil || !nsSelector.Matches(labels.Set(namespace.Labels)) {
			return false
		}
	} else if policyNamespace != "" && namespace.Name != policyNamespace {
		return false
	}
	if peer.PodSelector != nil {
		podSelector, err := metav1.LabelSelectorAsSelector(peer.PodSelector)
		if err != nil || !podSelector.Matches(labels.Set(pod.Labels)) {
			return false
		}
	}
	return true
}

func PortsAllow(policyPorts []networkingv1.NetworkPolicyPort, ports []int32) bool {
	if len(policyPorts) == 0 || len(ports) == 0 {
		return true
	}
	for _, policyPort := range policyPorts {
		if policyPort.Protocol != nil && *policyPort.Protocol != corev1.ProtocolTCP {
			continue
		}
		if policyPort.Port == nil {
			return true
		}
		for _, port := range ports {
			policyPortNumber, ok := int32PortFromInt(policyPort.Port.IntValue())
			if ok && policyPort.Port.Type == intstr.Int && policyPortNumber == port {
				return true
			}
		}
	}
	return false
}

func int32PortFromInt(value int) (int32, bool) {
	if value <= 0 || value > 65535 {
		return 0, false
	}
	return int32(value), true
}

func AnyRuleMentionsPort(policies []networkingv1.NetworkPolicy, direction string, ports []int32) bool {
	for _, netpol := range policies {
		if direction == "egress" {
			for _, rule := range netpol.Spec.Egress {
				if PortsAllow(rule.Ports, ports) {
					return true
				}
			}
			continue
		}
		for _, rule := range netpol.Spec.Ingress {
			if PortsAllow(rule.Ports, ports) {
				return true
			}
		}
	}
	return false
}

func PolicyNames(policies []networkingv1.NetworkPolicy) []string {
	var names []string
	for _, policy := range policies {
		names = append(names, policy.Name)
	}
	return uniqueStrings(names)
}

func FormatPorts(ports []int32) string {
	if len(ports) == 0 {
		return "(unknown)"
	}
	var values []string
	for _, port := range ports {
		values = append(values, fmt.Sprintf("%d", port))
	}
	return strings.Join(uniqueStrings(values), ", ")
}

func IPBlockContains(block *networkingv1.IPBlock, address string) bool {
	if block == nil || address == "" {
		return false
	}
	prefix, err := netip.ParsePrefix(block.CIDR)
	if err != nil {
		return false
	}
	ip, err := netip.ParseAddr(address)
	if err != nil || !prefix.Contains(ip) {
		return false
	}
	for _, except := range block.Except {
		exceptPrefix, err := netip.ParsePrefix(except)
		if err == nil && exceptPrefix.Contains(ip) {
			return false
		}
	}
	return true
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
	sort.Strings(out)
	return out
}
