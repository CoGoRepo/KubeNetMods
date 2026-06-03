package check

import (
	"context"
	"fmt"
	"sort"
	"strings"

	"github.com/CoGoRepo/KubeNetMods/internal/kube"
	"github.com/CoGoRepo/KubeNetMods/internal/model"
	"github.com/CoGoRepo/KubeNetMods/internal/policy"
	calicopolicy "github.com/CoGoRepo/KubeNetMods/internal/policy/calico"
	ciliumpolicy "github.com/CoGoRepo/KubeNetMods/internal/policy/cilium"
	nativepolicy "github.com/CoGoRepo/KubeNetMods/internal/policy/native"
	corev1 "k8s.io/api/core/v1"
	networkingv1 "k8s.io/api/networking/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/util/intstr"
)

func checkNativeNetworkPolicies(ctx context.Context, client *kube.Client, report *model.Report, opts ServiceOptions, service *corev1.Service, pods []corev1.Pod, source *ExecTarget) {
	layer := "NetworkPolicy Layer"
	targetPolicies, err := client.Core.NetworkingV1().NetworkPolicies(opts.Namespace).List(ctx, metav1.ListOptions{})
	if err != nil {
		report.Add(layer, "native policies", model.StatusWarn, fmt.Sprintf("Could not inspect native NetworkPolicies: %v", err))
		return
	}
	sourcePolicies := targetPolicies
	if source != nil && source.Pod.Namespace != opts.Namespace {
		sourcePolicies, err = client.Core.NetworkingV1().NetworkPolicies(source.Pod.Namespace).List(ctx, metav1.ListOptions{})
		if err != nil {
			report.Add(layer, "source native policies", model.StatusWarn, fmt.Sprintf("Could not inspect source namespace NetworkPolicies: %v", err))
			sourcePolicies = &networkingv1.NetworkPolicyList{}
		}
	}
	if len(targetPolicies.Items) == 0 && (sourcePolicies == nil || len(sourcePolicies.Items) == 0) {
		report.Add(layer, "native policies", model.StatusInfo, "No native Kubernetes NetworkPolicy objects found in the target/source namespace.")
		return
	}
	targetSelected := policyNamesSelectingPods(targetPolicies.Items, pods)
	if len(targetSelected) == 0 {
		report.Add(layer, "target policies", model.StatusInfo, fmt.Sprintf("%d native NetworkPolicy object(s) exist in target namespace, but none obviously select the target pods.", len(targetPolicies.Items)))
	} else {
		report.Add(layer, "target policies", model.StatusWarn, "Target pod(s) are selected by native NetworkPolicy: "+strings.Join(targetSelected, ", "))
	}
	if source == nil {
		if len(targetSelected) > 0 {
			report.Diagnose("Native NetworkPolicy selects the target pods. Provide a source pod/selector to evaluate whether the actual source is allowed.")
		}
		return
	}
	sourceNamespace, err := client.Core.CoreV1().Namespaces().Get(ctx, source.Pod.Namespace, metav1.GetOptions{})
	if err != nil {
		report.Add(layer, "source namespace labels", model.StatusWarn, fmt.Sprintf("Could not read source namespace labels: %v", err))
		return
	}
	targetNamespace, err := client.Core.CoreV1().Namespaces().Get(ctx, opts.Namespace, metav1.GetOptions{})
	if err != nil {
		report.Add(layer, "target namespace labels", model.StatusWarn, fmt.Sprintf("Could not read target namespace labels: %v", err))
		return
	}
	ports := selectedConnectionPortCandidates(service, collectContainerPorts(pods), report.Target.ServicePort)
	analyzeNativeEgress(report, source.Pod, *targetNamespace, pods, sourcePolicies.Items, service, ports)
	analyzeNativeIngress(report, source.Pod, *sourceNamespace, pods, *targetNamespace, targetPolicies.Items, service, ports)
}

func checkCniPolicies(ctx context.Context, client *kube.Client, report *model.Report, opts ServiceOptions, service *corev1.Service, pods []corev1.Pod, source *ExecTarget) {
	if len(pods) == 0 {
		report.Add("CNI Policy Layer", "provider policies", model.StatusSkip, "Skipped CNI policy analysis because no target pods were selected.")
		return
	}
	targetNamespace, err := client.Core.CoreV1().Namespaces().Get(ctx, opts.Namespace, metav1.GetOptions{})
	if err != nil {
		report.Add("CNI Policy Layer", "target namespace labels", model.StatusWarn, fmt.Sprintf("Could not read target namespace labels for CNI policy analysis: %v", err))
		return
	}
	var sourceNamespace *corev1.Namespace
	if opts.SourceNamespace != "" {
		if ns, err := client.Core.CoreV1().Namespaces().Get(ctx, opts.SourceNamespace, metav1.GetOptions{}); err == nil {
			sourceNamespace = ns
		}
	}

	var sourcePod *corev1.Pod
	if source != nil {
		sourcePod = &source.Pod
	}
	ports := selectedConnectionPortCandidates(service, collectContainerPorts(pods), report.Target.ServicePort)
	calicoInsights, err := calicopolicy.Analyze(ctx, client, *targetNamespace, pods, sourceNamespace, sourcePod, service, ports, buildCalicoDNSContext(ctx, client, source))
	if err != nil {
		report.Add("Calico Policy Layer", "analysis", model.StatusWarn, fmt.Sprintf("Calico policy analysis failed: %v", err))
	} else {
		addInsights(report, calicoInsights)
	}
	if service != nil && (service.Spec.Type == corev1.ServiceTypeNodePort || service.Spec.Type == corev1.ServiceTypeLoadBalancer) {
		hostInsights, err := calicopolicy.AnalyzeIngressSurface(ctx, client, service)
		if err != nil {
			report.Add("Calico Host Policy Layer", "analysis", model.StatusWarn, fmt.Sprintf("Calico host/forwarded policy analysis failed: %v", err))
		} else {
			addInsights(report, hostInsights)
		}
	}

	ciliumInsights, err := ciliumpolicy.Analyze(ctx, client, *targetNamespace, pods, sourceNamespace, sourcePod, service, ports, buildCiliumDNSContext(ctx, client, source))
	if err != nil {
		report.Add("Cilium Policy Layer", "analysis", model.StatusWarn, fmt.Sprintf("Cilium policy analysis failed: %v", err))
	} else {
		addInsights(report, ciliumInsights)
	}
}

func buildCalicoDNSContext(ctx context.Context, client *kube.Client, source *ExecTarget) calicopolicy.DNSContext {
	var dns calicopolicy.DNSContext
	if source != nil {
		if resolv, err := readResolvConf(ctx, *source); err == nil {
			dns.Nameservers = resolv.Nameservers
		}
	}
	if service, err := client.Core.CoreV1().Services("kube-system").Get(ctx, "kube-dns", metav1.GetOptions{}); err == nil {
		dns.CoreDNSServiceIP = service.Spec.ClusterIP
	}
	if namespace, err := client.Core.CoreV1().Namespaces().Get(ctx, "kube-system", metav1.GetOptions{}); err == nil {
		dns.KubeSystemNS = namespace
	}
	pods, err := client.Core.CoreV1().Pods("kube-system").List(ctx, metav1.ListOptions{})
	if err != nil {
		return dns
	}
	for _, pod := range pods.Items {
		name := strings.ToLower(pod.Name)
		k8sApp := strings.ToLower(pod.Labels["k8s-app"])
		app := strings.ToLower(pod.Labels["app"])
		if strings.Contains(name, "node-local-dns") || strings.Contains(name, "nodelocaldns") || strings.Contains(k8sApp, "node-local-dns") || strings.Contains(app, "node-local-dns") {
			dns.NodeLocalDNSPods = append(dns.NodeLocalDNSPods, pod)
			continue
		}
		if strings.Contains(name, "coredns") || strings.Contains(name, "kube-dns") || strings.Contains(k8sApp, "kube-dns") || strings.Contains(k8sApp, "coredns") || strings.Contains(app, "coredns") {
			dns.CoreDNSPods = append(dns.CoreDNSPods, pod)
		}
	}
	return dns
}

func buildCiliumDNSContext(ctx context.Context, client *kube.Client, source *ExecTarget) ciliumpolicy.DNSContext {
	calicoDNS := buildCalicoDNSContext(ctx, client, source)
	return ciliumpolicy.DNSContext{
		Nameservers:      calicoDNS.Nameservers,
		CoreDNSServiceIP: calicoDNS.CoreDNSServiceIP,
		CoreDNSPods:      calicoDNS.CoreDNSPods,
		NodeLocalDNSPods: calicoDNS.NodeLocalDNSPods,
	}
}

func addInsights(report *model.Report, insights []policy.Insight) {
	for _, insight := range insights {
		report.Add(insight.Layer, insight.Check, model.Status(insight.Status), insight.Message)
		if insight.Diagnosis != "" {
			report.Diagnose(insight.Diagnosis)
		}
	}
}

func policyNamesSelectingPods(policies []networkingv1.NetworkPolicy, pods []corev1.Pod) []string {
	return nativepolicy.PolicyNamesSelectingPods(policies, pods)
}

func analyzeNativeEgress(report *model.Report, source corev1.Pod, targetNamespace corev1.Namespace, targets []corev1.Pod, policies []networkingv1.NetworkPolicy, service *corev1.Service, ports []int32) {
	var selecting []networkingv1.NetworkPolicy
	for _, netpol := range policies {
		if policySelectsPod(netpol, source) && hasPolicyType(netpol, networkingv1.PolicyTypeEgress) {
			selecting = append(selecting, netpol)
		}
	}
	if len(selecting) == 0 {
		report.Add("NetworkPolicy Path Analysis", "source egress to target", model.StatusPass, fmt.Sprintf("No egress NetworkPolicies select source pod %q.", source.Name))
		return
	}
	var reasons []string
	for _, netpol := range selecting {
		for _, rule := range netpol.Spec.Egress {
			if nativeEgressRuleAllows(rule, targetNamespace, targets, service, ports, source.Namespace) {
				reasons = append(reasons, netpol.Name)
				break
			}
		}
	}
	names := nativePolicyNames(selecting)
	if len(reasons) > 0 {
		report.Add("NetworkPolicy Path Analysis", "source egress to target", model.StatusPass, fmt.Sprintf("Source egress NetworkPolicy appears to allow this target path. Matching policy/rule found in: %s.", strings.Join(uniqueStrings(reasons), ", ")))
		return
	}
	report.Add("NetworkPolicy Path Analysis", "source egress to target", model.StatusWarn, fmt.Sprintf("Source pod %q is egress-isolated by NetworkPolicy (%s), and no rule obviously allows target namespace %q on TCP port(s) %s.", source.Name, strings.Join(names, ", "), targetNamespace.Name, formatPorts(ports)))
	report.Diagnose(fmt.Sprintf("Primary issue: native egress NetworkPolicy default-deny blocks source pod %q from Service %q on TCP port(s) %s. Selected policy/policies: %s.", source.Namespace+"/"+source.Name, serviceName(service), formatPorts(ports), strings.Join(names, ", ")))
}

func analyzeNativeIngress(report *model.Report, source corev1.Pod, sourceNamespace corev1.Namespace, targets []corev1.Pod, targetNamespace corev1.Namespace, policies []networkingv1.NetworkPolicy, service *corev1.Service, ports []int32) {
	var selecting []networkingv1.NetworkPolicy
	for _, netpol := range policies {
		if hasPolicyType(netpol, networkingv1.PolicyTypeIngress) {
			for _, pod := range targets {
				if policySelectsPod(netpol, pod) {
					selecting = append(selecting, netpol)
					break
				}
			}
		}
	}
	if len(selecting) == 0 {
		report.Add("NetworkPolicy Path Analysis", "target ingress from source", model.StatusPass, "No ingress NetworkPolicies select the target pods.")
		return
	}
	var reasons []string
	for _, netpol := range selecting {
		for _, rule := range netpol.Spec.Ingress {
			if nativeIngressRuleAllows(rule, source, sourceNamespace, ports) {
				reasons = append(reasons, netpol.Name)
				break
			}
		}
	}
	names := nativePolicyNames(selecting)
	if len(reasons) > 0 {
		report.Add("NetworkPolicy Path Analysis", "target ingress from source", model.StatusPass, fmt.Sprintf("Target ingress NetworkPolicy appears to allow source pod %q. Matching policy/rule found in: %s.", source.Name, strings.Join(uniqueStrings(reasons), ", ")))
		return
	}
	report.Add("NetworkPolicy Path Analysis", "target ingress from source", model.StatusWarn, fmt.Sprintf("Target pods are ingress-isolated by NetworkPolicy (%s), and no rule obviously allows source namespace %q on TCP port(s) %s.", strings.Join(names, ", "), sourceNamespace.Name, formatPorts(ports)))
	report.Diagnose(fmt.Sprintf("Primary issue: native ingress NetworkPolicy default-deny blocks source pod %q from Service %q on TCP port(s) %s. Selected policy/policies: %s.", source.Namespace+"/"+source.Name, serviceName(service), formatPorts(ports), strings.Join(names, ", ")))
}

func policySelectsPod(netpol networkingv1.NetworkPolicy, pod corev1.Pod) bool {
	return nativepolicy.PolicySelectsPod(netpol, pod)
}

func hasPolicyType(netpol networkingv1.NetworkPolicy, policyType networkingv1.PolicyType) bool {
	return nativepolicy.HasPolicyType(netpol, policyType)
}

func nativeEgressRuleAllows(rule networkingv1.NetworkPolicyEgressRule, targetNamespace corev1.Namespace, targets []corev1.Pod, service *corev1.Service, ports []int32, policyNamespace string) bool {
	return nativepolicy.EgressRuleAllows(rule, targetNamespace, targets, service, ports, policyNamespace)
}

func nativeIngressRuleAllows(rule networkingv1.NetworkPolicyIngressRule, source corev1.Pod, sourceNamespace corev1.Namespace, ports []int32) bool {
	return nativepolicy.IngressRuleAllows(rule, source, sourceNamespace, ports)
}

func nativePeerMatchesPod(peer networkingv1.NetworkPolicyPeer, pod corev1.Pod, namespace corev1.Namespace, policyNamespace string) bool {
	return nativepolicy.PeerMatchesPod(peer, pod, namespace, policyNamespace)
}

func nativePortsAllow(policyPorts []networkingv1.NetworkPolicyPort, ports []int32) bool {
	return nativepolicy.PortsAllow(policyPorts, ports)
}
func selectedConnectionPortCandidates(service *corev1.Service, containerPorts []containerPort, requested int32) []int32 {
	if service == nil || len(service.Spec.Ports) == 0 {
		return nil
	}
	selected, ok := selectServicePort(service, requested)
	if !ok {
		return nil
	}
	seen := map[int32]bool{}
	var out []int32
	add := func(value int32) {
		if value > 0 && !seen[value] {
			seen[value] = true
			out = append(out, value)
		}
	}
	add(selected.Port)
	if selected.TargetPort.Type == intstr.Int {
		add(int32(selected.TargetPort.IntValue()))
	} else if selected.TargetPort.Type == intstr.String {
		for _, port := range containerPorts {
			if port.PortName == selected.TargetPort.StrVal {
				add(port.Port)
			}
		}
	}
	sort.Slice(out, func(i, j int) bool { return out[i] < out[j] })
	return out
}

func nativePolicyNames(policies []networkingv1.NetworkPolicy) []string {
	return nativepolicy.PolicyNames(policies)
}

func formatPorts(ports []int32) string {
	return nativepolicy.FormatPorts(ports)
}

func serviceName(service *corev1.Service) string {
	if service == nil {
		return "(unknown service)"
	}
	return service.Namespace + "/" + service.Name
}

func ipBlockContains(block *networkingv1.IPBlock, address string) bool {
	return nativepolicy.IPBlockContains(block, address)
}
