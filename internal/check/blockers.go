package check

import (
	"context"
	"fmt"
	"sort"
	"strings"
	"time"

	"github.com/CoGoRepo/KubeNetMods/internal/kube"
	"github.com/CoGoRepo/KubeNetMods/internal/model"
	calicopolicy "github.com/CoGoRepo/KubeNetMods/internal/policy/calico"
	ciliumpolicy "github.com/CoGoRepo/KubeNetMods/internal/policy/cilium"
	corev1 "k8s.io/api/core/v1"
	networkingv1 "k8s.io/api/networking/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/labels"
)

type BlockersOptions struct {
	Context        string
	Namespace      string
	PodName        string
	PodSelector    string
	PodLabels      map[string]string
	ServiceAccount string
	Direction      string
	Protocol       string
	Port           string
	ToNamespace    string
	ToService      string
	ToSelector     string
	Timeout        time.Duration
}

type BlockerPort struct {
	Raw     string
	Numbers []int32
	Names   []string
}

func RunBlockers(ctx context.Context, opts BlockersOptions) (*model.Report, error) {
	if opts.Namespace == "" {
		opts.Namespace = "default"
	}
	if opts.Direction == "" {
		opts.Direction = "egress"
	}
	opts.Direction = strings.ToLower(opts.Direction)
	if opts.Direction != "egress" && opts.Direction != "ingress" {
		return nil, fmt.Errorf("--direction must be egress or ingress")
	}
	if opts.Protocol == "" {
		opts.Protocol = "tcp"
	}
	if strings.ToLower(opts.Protocol) != "tcp" {
		return nil, fmt.Errorf("only --protocol tcp is currently supported")
	}
	portSpec, err := parseBlockerPort(opts.Port)
	if err != nil {
		return nil, err
	}
	if portSpec.Raw == "" {
		return nil, fmt.Errorf("--port is required")
	}

	client, err := kube.New(opts.Context)
	if err != nil {
		return nil, err
	}
	rep := model.NewReport("show blockers", model.Target{
		Context:   client.Context,
		Namespace: opts.Namespace,
		SourceNS:  opts.Namespace,
	})

	namespace, err := client.Core.CoreV1().Namespaces().Get(ctx, opts.Namespace, metav1.GetOptions{})
	if err != nil {
		return rep, fmt.Errorf("read namespace %q: %w", opts.Namespace, err)
	}
	subject, subjectSource, err := resolveBlockerSubject(ctx, client, opts)
	if err != nil {
		return rep, err
	}
	rep.Target.SourcePod = subject.Name
	rep.Add("Subject", "pod", model.StatusInfo, subjectSource)
	rep.Add("Subject", "direction", model.StatusInfo, fmt.Sprintf("Checking %s policy for TCP/%s.", opts.Direction, portSpec.Raw))

	var targetNamespace *corev1.Namespace
	var targetPods []corev1.Pod
	var service *corev1.Service
	if opts.ToService != "" {
		toNamespace := opts.ToNamespace
		if toNamespace == "" {
			toNamespace = opts.Namespace
		}
		ns, err := client.Core.CoreV1().Namespaces().Get(ctx, toNamespace, metav1.GetOptions{})
		if err != nil {
			return rep, fmt.Errorf("read target namespace %q: %w", toNamespace, err)
		}
		targetNamespace = ns
		svc, err := client.Core.CoreV1().Services(toNamespace).Get(ctx, opts.ToService, metav1.GetOptions{})
		if err != nil {
			return rep, fmt.Errorf("read target service %q/%q: %w", toNamespace, opts.ToService, err)
		}
		service = svc
		selectorText := labels.Set(svc.Spec.Selector).String()
		if opts.ToSelector != "" {
			selectorText = opts.ToSelector
		}
		pods, err := podsBySelector(ctx, client, toNamespace, selectorText)
		if err != nil {
			return rep, fmt.Errorf("read target pods: %w", err)
		}
		targetPods = pods
		rep.Target.Service = opts.ToService
		rep.Add("Target", "service", model.StatusInfo, fmt.Sprintf("Path-specific mode: target Service %s/%s, selector %s.", toNamespace, opts.ToService, selectorText))
	} else if opts.ToNamespace != "" || opts.ToSelector != "" {
		toNamespace := opts.ToNamespace
		if toNamespace == "" {
			toNamespace = opts.Namespace
		}
		ns, err := client.Core.CoreV1().Namespaces().Get(ctx, toNamespace, metav1.GetOptions{})
		if err != nil {
			return rep, fmt.Errorf("read target namespace %q: %w", toNamespace, err)
		}
		targetNamespace = ns
		if opts.ToSelector != "" {
			pods, err := podsBySelector(ctx, client, toNamespace, opts.ToSelector)
			if err != nil {
				return rep, fmt.Errorf("read target pods: %w", err)
			}
			targetPods = pods
		}
		rep.Add("Target", "selector", model.StatusInfo, fmt.Sprintf("Path-specific mode: target namespace %s selector %q.", toNamespace, opts.ToSelector))
	} else {
		rep.Add("Target", "none", model.StatusInfo, "Port posture mode: no destination supplied. Explicit Deny and default-deny risk are evaluated for the subject/port, but destination selectors cannot be fully proven.")
	}

	ports := portSpec.Numbers
	addNativeBlockers(ctx, rep, client, opts, *namespace, *subject, targetNamespace, targetPods, service, ports, portSpec.Raw)

	insights, err := calicopolicy.ShowBlockers(ctx, client, *namespace, *subject, opts.Direction, ports, portSpec.Names, portSpec.Raw, targetNamespace, targetPods, service)
	if err != nil {
		rep.Add("Calico Blockers", "analysis", model.StatusWarn, fmt.Sprintf("Could not run Calico blocker analysis: %v", err))
	} else if len(insights) == 0 {
		rep.Add("Calico Blockers", "analysis", model.StatusInfo, "No Calico policy analysis was produced. Calico CRDs may not be installed or readable.")
	} else {
		addInsights(rep, insights)
	}

	ciliumInsights, err := ciliumpolicy.ShowBlockers(ctx, client, *namespace, *subject, opts.Direction, ports, portSpec.Names, portSpec.Raw, targetNamespace, targetPods, service)
	if err != nil {
		rep.Add("Cilium Blockers", "analysis", model.StatusWarn, fmt.Sprintf("Could not run Cilium blocker analysis: %v", err))
	} else if len(ciliumInsights) == 0 {
		rep.Add("Cilium Blockers", "analysis", model.StatusInfo, "No Cilium policy analysis was produced. Cilium CRDs may not be installed or readable.")
	} else {
		addInsights(rep, ciliumInsights)
	}

	if rep.CountByStatus(model.StatusFail) == 0 {
		rep.Diagnose("No policy blocker was identified for the requested subject and port.")
	}
	return rep, nil
}

func parseBlockerPort(raw string) (BlockerPort, error) {
	raw = strings.TrimSpace(raw)
	if raw == "" {
		return BlockerPort{}, nil
	}
	spec := BlockerPort{Raw: raw}
	if strings.Contains(raw, ":") {
		parts := strings.SplitN(raw, ":", 2)
		var start, end int
		if _, err := fmt.Sscanf(parts[0], "%d", &start); err != nil {
			return spec, fmt.Errorf("--port range start must be numeric: %s", raw)
		}
		if _, err := fmt.Sscanf(parts[1], "%d", &end); err != nil {
			return spec, fmt.Errorf("--port range end must be numeric: %s", raw)
		}
		if start <= 0 || end <= 0 || start > end || end > 65535 {
			return spec, fmt.Errorf("--port range must be between 1 and 65535 with start <= end: %s", raw)
		}
		for port := start; port <= end; port++ {
			spec.Numbers = append(spec.Numbers, int32(port))
		}
		return spec, nil
	}
	var parsed int
	if _, err := fmt.Sscanf(raw, "%d", &parsed); err == nil {
		if parsed <= 0 || parsed > 65535 {
			return spec, fmt.Errorf("--port must be between 1 and 65535")
		}
		spec.Numbers = []int32{int32(parsed)}
		return spec, nil
	}
	spec.Names = []string{raw}
	return spec, nil
}

func resolveBlockerSubject(ctx context.Context, client *kube.Client, opts BlockersOptions) (*corev1.Pod, string, error) {
	if opts.PodName != "" {
		pod, err := client.Core.CoreV1().Pods(opts.Namespace).Get(ctx, opts.PodName, metav1.GetOptions{})
		if err != nil {
			return nil, "", fmt.Errorf("read pod %q/%q: %w", opts.Namespace, opts.PodName, err)
		}
		return pod, fmt.Sprintf("Using deployed pod %s/%s.", opts.Namespace, opts.PodName), nil
	}
	if opts.PodSelector != "" {
		pods, err := podsBySelector(ctx, client, opts.Namespace, opts.PodSelector)
		if err != nil {
			return nil, "", err
		}
		if len(pods) == 0 {
			return nil, "", fmt.Errorf("no pods found for selector %q in namespace %q", opts.PodSelector, opts.Namespace)
		}
		sort.Slice(pods, func(i, j int) bool { return pods[i].Name < pods[j].Name })
		return &pods[0], fmt.Sprintf("Using deployed pod %s/%s selected by %q.", opts.Namespace, pods[0].Name, opts.PodSelector), nil
	}
	if len(opts.PodLabels) > 0 {
		sa := opts.ServiceAccount
		if sa == "" {
			sa = "default"
		}
		pod := &corev1.Pod{
			ObjectMeta: metav1.ObjectMeta{
				Name:      "preflight-subject",
				Namespace: opts.Namespace,
				Labels:    cloneStringMap(opts.PodLabels),
			},
			Spec: corev1.PodSpec{ServiceAccountName: sa},
		}
		return pod, fmt.Sprintf("Using preflight labels in namespace %s: %s. ServiceAccount=%s.", opts.Namespace, formatStringMap(opts.PodLabels), sa), nil
	}
	return nil, "", fmt.Errorf("provide --pod, --selector, or one or more --labels key=value")
}

func addNativeBlockers(ctx context.Context, rep *model.Report, client *kube.Client, opts BlockersOptions, subjectNamespace corev1.Namespace, subjectPod corev1.Pod, targetNamespace *corev1.Namespace, targetPods []corev1.Pod, service *corev1.Service, ports []int32, portText string) {
	if len(ports) == 0 {
		rep.Add("NetworkPolicy Blockers", "port", model.StatusInfo, fmt.Sprintf("Native Kubernetes NetworkPolicy does not support named port posture without pod container metadata here; skipping native evaluation for TCP/%s.", portText))
		return
	}
	namespaces := []string{subjectNamespace.Name}
	if targetNamespace != nil && targetNamespace.Name != subjectNamespace.Name {
		namespaces = append(namespaces, targetNamespace.Name)
	}
	var policies []networkingv1.NetworkPolicy
	for _, namespace := range uniqueStringsLocal(namespaces) {
		list, err := client.Core.NetworkingV1().NetworkPolicies(namespace).List(ctx, metav1.ListOptions{})
		if err != nil {
			rep.Add("NetworkPolicy Blockers", namespace, model.StatusWarn, fmt.Sprintf("Could not list NetworkPolicy objects in namespace %s: %v", namespace, err))
			continue
		}
		policies = append(policies, list.Items...)
	}
	if opts.Direction == "egress" {
		addNativeEgressBlockers(rep, subjectPod, subjectNamespace, targetNamespace, targetPods, service, policies, ports)
		return
	}
	addNativeIngressBlockers(rep, subjectPod, subjectNamespace, policies, ports)
}

func addNativeEgressBlockers(rep *model.Report, source corev1.Pod, sourceNamespace corev1.Namespace, targetNamespace *corev1.Namespace, targetPods []corev1.Pod, service *corev1.Service, policies []networkingv1.NetworkPolicy, ports []int32) {
	var selecting []networkingv1.NetworkPolicy
	for _, netpol := range policies {
		if netpol.Namespace == sourceNamespace.Name && hasPolicyType(netpol, networkingv1.PolicyTypeEgress) && policySelectsPod(netpol, source) {
			selecting = append(selecting, netpol)
		}
	}
	if len(selecting) == 0 {
		rep.Add("NetworkPolicy Blockers", "egress", model.StatusPass, fmt.Sprintf("No native egress NetworkPolicies select pod %s/%s.", sourceNamespace.Name, source.Name))
		return
	}
	rep.Add("NetworkPolicy Blockers", "selected policies", model.StatusWarn, "Pod is selected by native egress NetworkPolicy: "+strings.Join(nativePolicyNames(selecting), ", "))
	if targetNamespace == nil || len(targetPods) == 0 {
		if nativeAnyRuleMentionsPort(selecting, "egress", ports) {
			rep.Add("NetworkPolicy Blockers", "port posture", model.StatusInfo, fmt.Sprintf("At least one native egress rule mentions TCP/%s, but no destination was supplied, so blockers cannot be proven.", formatPorts(ports)))
			return
		}
		policyList := strings.Join(nativePolicyNames(selecting), ", ")
		rep.Add("NetworkPolicy Blockers", "default deny", model.StatusFail, fmt.Sprintf("Native egress NetworkPolicy selects this pod, but no egress rule mentions TCP/%s. Destination was not supplied. Policies: %s.", formatPorts(ports), policyList))
		rep.Diagnose(fmt.Sprintf("Primary issue: native egress NetworkPolicy default-deny risk for pod %s/%s on TCP/%s. Selected policy/policies: %s.", sourceNamespace.Name, source.Name, formatPorts(ports), policyList))
		return
	}
	var allowing []string
	for _, netpol := range selecting {
		for _, rule := range netpol.Spec.Egress {
			if nativeEgressRuleAllows(rule, *targetNamespace, targetPods, service, ports, netpol.Namespace) {
				allowing = append(allowing, netpol.Name)
				break
			}
		}
	}
	if len(allowing) > 0 {
		rep.Add("NetworkPolicy Blockers", "allow", model.StatusPass, "Native egress Allow rule(s) found in: "+strings.Join(uniqueStringsLocal(allowing), ", "))
		return
	}
	policyList := strings.Join(nativePolicyNames(selecting), ", ")
	rep.Add("NetworkPolicy Blockers", "default deny", model.StatusFail, fmt.Sprintf("Native egress NetworkPolicy selects this pod, but no rule allows the target path on TCP/%s. Policies: %s.", formatPorts(ports), policyList))
	rep.Diagnose(fmt.Sprintf("Primary issue: native egress NetworkPolicy default-deny blocks pod %s/%s from the requested target on TCP/%s. Selected policy/policies: %s.", sourceNamespace.Name, source.Name, formatPorts(ports), policyList))
}

func addNativeIngressBlockers(rep *model.Report, target corev1.Pod, targetNamespace corev1.Namespace, policies []networkingv1.NetworkPolicy, ports []int32) {
	var selecting []networkingv1.NetworkPolicy
	for _, netpol := range policies {
		if netpol.Namespace == targetNamespace.Name && hasPolicyType(netpol, networkingv1.PolicyTypeIngress) && policySelectsPod(netpol, target) {
			selecting = append(selecting, netpol)
		}
	}
	if len(selecting) == 0 {
		rep.Add("NetworkPolicy Blockers", "ingress", model.StatusPass, fmt.Sprintf("No native ingress NetworkPolicies select pod %s/%s.", targetNamespace.Name, target.Name))
		return
	}
	if nativeAnyRuleMentionsPort(selecting, "ingress", ports) {
		rep.Add("NetworkPolicy Blockers", "port posture", model.StatusInfo, fmt.Sprintf("At least one native ingress rule mentions TCP/%s. Supply a source path for stronger ingress reasoning.", formatPorts(ports)))
		return
	}
	policyList := strings.Join(nativePolicyNames(selecting), ", ")
	rep.Add("NetworkPolicy Blockers", "default deny", model.StatusFail, fmt.Sprintf("Native ingress NetworkPolicy selects this pod, but no ingress rule mentions TCP/%s. Policies: %s.", formatPorts(ports), policyList))
	rep.Diagnose(fmt.Sprintf("Primary issue: native ingress NetworkPolicy default-deny risk for pod %s/%s on TCP/%s. Selected policy/policies: %s.", targetNamespace.Name, target.Name, formatPorts(ports), policyList))
}

func nativeAnyRuleMentionsPort(policies []networkingv1.NetworkPolicy, direction string, ports []int32) bool {
	for _, netpol := range policies {
		if direction == "egress" {
			for _, rule := range netpol.Spec.Egress {
				if nativePortsAllow(rule.Ports, ports) {
					return true
				}
			}
			continue
		}
		for _, rule := range netpol.Spec.Ingress {
			if nativePortsAllow(rule.Ports, ports) {
				return true
			}
		}
	}
	return false
}

func podsBySelector(ctx context.Context, client *kube.Client, namespace string, selectorText string) ([]corev1.Pod, error) {
	if selectorText == "" {
		return nil, nil
	}
	list, err := client.Core.CoreV1().Pods(namespace).List(ctx, metav1.ListOptions{LabelSelector: selectorText})
	if err != nil {
		return nil, err
	}
	return list.Items, nil
}

func cloneStringMap(in map[string]string) map[string]string {
	out := map[string]string{}
	for k, v := range in {
		out[k] = v
	}
	return out
}

func formatStringMap(values map[string]string) string {
	keys := make([]string, 0, len(values))
	for key := range values {
		keys = append(keys, key)
	}
	sort.Strings(keys)
	var parts []string
	for _, key := range keys {
		parts = append(parts, key+"="+values[key])
	}
	return strings.Join(parts, ", ")
}

func uniqueStringsLocal(values []string) []string {
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
