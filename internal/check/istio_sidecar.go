package check

import (
	"context"
	"fmt"
	"sort"
	"strings"

	"github.com/CoGoRepo/KubeNetMods/internal/kube"
	"github.com/CoGoRepo/KubeNetMods/internal/model"
	networkingv1 "istio.io/client-go/pkg/apis/networking/v1"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/labels"
)

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
