package check

import (
	"context"
	"fmt"
	"sort"
	"strings"

	"github.com/CoGoRepo/KubeNetMods/internal/kube"
	"github.com/CoGoRepo/KubeNetMods/internal/model"
	networkingapi "istio.io/api/networking/v1alpha3"
	securityapi "istio.io/api/security/v1beta1"
	networkingv1 "istio.io/client-go/pkg/apis/networking/v1"
	securityv1 "istio.io/client-go/pkg/apis/security/v1"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/util/intstr"
)

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
	destinationRules = istioServicePathDestinationRules(destinationRules, opts, source)
	virtualServices, _ := listIstioVirtualServices(ctx, client, istioConfigNamespaces(opts, source))
	virtualServices = istioServicePathVirtualServices(virtualServices, opts, source)
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
