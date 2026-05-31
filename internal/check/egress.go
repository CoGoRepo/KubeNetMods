package check

import (
	"context"
	"fmt"
	"net/url"
	"strings"
	"time"

	"github.com/CoGoRepo/KubeNetMods/internal/kube"
	"github.com/CoGoRepo/KubeNetMods/internal/model"
	calicopolicy "github.com/CoGoRepo/KubeNetMods/internal/policy/calico"
	ciliumpolicy "github.com/CoGoRepo/KubeNetMods/internal/policy/cilium"
	corev1 "k8s.io/api/core/v1"
	networkingv1 "k8s.io/api/networking/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
)

type EgressOptions struct {
	Context         string
	SourceNamespace string
	SourcePodName   string
	SourceSelector  string
	SourceContainer string
	UseDebugPod     bool
	DebugImage      string
	DebugPullPolicy string
	SourceDebugPod  string
	URLs            []string
	Timeout         time.Duration
}

func RunEgress(ctx context.Context, opts EgressOptions) (*model.Report, error) {
	if opts.SourceNamespace == "" {
		opts.SourceNamespace = "default"
	}
	if opts.DebugImage == "" {
		opts.DebugImage = "nicolaka/netshoot:latest"
	}
	if opts.DebugPullPolicy == "" {
		opts.DebugPullPolicy = "IfNotPresent"
	}
	if opts.SourceDebugPod == "" {
		opts.SourceDebugPod = "kubenetmods-egress-debug"
	}
	target := model.Target{
		Context:   opts.Context,
		Namespace: opts.SourceNamespace,
		SourceNS:  opts.SourceNamespace,
		SourcePod: opts.SourcePodName,
	}
	report := model.NewReport("check egress", target)
	client, err := kube.New(opts.Context)
	if err != nil {
		report.Add("Source Access", "context", model.StatusFail, err.Error())
		report.Diagnose("Cannot build Kubernetes client. Check kubeconfig, context, and credentials.")
		return report, nil
	}
	if report.Target.Context == "" {
		report.Target.Context = client.Context
	}
	if opts.UseDebugPod {
		defer func() { _ = client.DeletePodIfExists(context.Background(), opts.SourceNamespace, opts.SourceDebugPod) }()
	}

	sourceNamespace, err := client.Core.CoreV1().Namespaces().Get(ctx, opts.SourceNamespace, metav1.GetOptions{})
	if err != nil {
		report.Add("Source Access", "source namespace", model.StatusFail, fmt.Sprintf("Source namespace %q is not accessible: %v", opts.SourceNamespace, err))
		report.Diagnose(fmt.Sprintf("Cannot access source namespace %q. Fix kubeconfig/RBAC/namespace before testing egress.", opts.SourceNamespace))
		return report, nil
	}
	report.Add("Source Access", "source namespace", model.StatusPass, fmt.Sprintf("Source namespace %q exists.", opts.SourceNamespace))

	source := selectEgressSource(ctx, client, report, opts)
	if source == nil {
		report.Add("Outbound Reachability", "urls", model.StatusSkip, "Skipped URL checks because no executable source path was available.")
		return report, nil
	}

	if resolv, err := readResolvConf(ctx, *source); err == nil {
		report.Add("Source DNS", "resolv.conf", model.StatusPass, fmt.Sprintf("Runtime nameserver(s): %s; search domains: %s", formatList(resolv.Nameservers), formatList(resolv.Searches)))
		if hasNodeLocalResolver(resolv.Nameservers) {
			report.Add("Source DNS", "runtime resolver", model.StatusInfo, "Source path uses a NodeLocalDNS/link-local resolver.")
		}
		inspectCiliumDNSPosture(ctx, client, report, *sourceNamespace, source.Pod, resolv)
	} else {
		report.Add("Source DNS", "resolv.conf", model.StatusWarn, fmt.Sprintf("Could not read /etc/resolv.conf from %s %q: %v", source.Kind, source.Pod.Name, err))
	}

	inspectEgressPolicyContext(ctx, client, report, *source)

	if len(opts.URLs) == 0 {
		report.Add("Outbound Reachability", "urls", model.StatusFail, "No URLs were supplied for egress testing.")
		report.Diagnose("No outbound target was supplied. Provide one or more URLs to test reachability.")
		return report, nil
	}
	for _, rawURL := range opts.URLs {
		parsed, err := url.Parse(rawURL)
		if err != nil || parsed.Hostname() == "" || parsed.Scheme == "" {
			report.Add("Outbound Reachability", rawURL, model.StatusFail, fmt.Sprintf("URL %q is not a valid absolute URL.", rawURL))
			report.Diagnose(fmt.Sprintf("Invalid egress URL %q. Provide an absolute URL such as https://example.com.", rawURL))
			continue
		}
		host := parsed.Hostname()
		targetClass := classifyURLTarget(host)
		report.Add("Outbound Reachability", "target "+host, model.StatusInfo, fmt.Sprintf("Testing %s://%s on port %s. Target class: %s.", parsed.Scheme, host, urlPortText(parsed), targetClass))
		if port, ok := urlPortNumber(parsed); ok {
			inspectNativeEgressPortPosture(ctx, client, report, *sourceNamespace, source.Pod, port)
			inspectCalicoEgressPortPosture(ctx, client, report, *sourceNamespace, source.Pod, port)
			inspectCiliumExternalEgressPosture(ctx, client, report, *sourceNamespace, source.Pod, host, port)
		} else {
			report.Add("Outbound Policy Posture", "target "+host, model.StatusInfo, fmt.Sprintf("Skipped port-specific policy posture for %q because no numeric port could be inferred.", rawURL))
		}
		if err := resolveHost(ctx, *source, host); err != nil {
			report.Add("Outbound Reachability", "resolve "+host, model.StatusFail, fmt.Sprintf("%s %q could not resolve %q.", source.Kind, source.Pod.Name, host))
			if !hasDiagnosisContaining(report, "runtime DNS resolver") {
				report.Diagnose(fmt.Sprintf("DNS resolution failed for outbound target %q from source pod %q. Check DNS policy, CoreDNS/NodeLocalDNS, egress DNS policy, proxy, or upstream resolver access.", host, source.Pod.Name))
			}
		} else {
			report.Add("Outbound Reachability", "resolve "+host, model.StatusPass, fmt.Sprintf("%s %q resolved %q.", source.Kind, source.Pod.Name, host))
		}
		curl := curlURL(ctx, *source, rawURL, opts.Timeout, nil)
		if curl.OK {
			report.Add("Outbound Reachability", rawURL, model.StatusPass, fmt.Sprintf("%s %q reached %q. HTTP status: %s", source.Kind, source.Pod.Name, rawURL, curl.StatusCode))
		} else {
			classification := classifyRuntimeHTTPFailure(curl)
			report.Add("Outbound Reachability", rawURL, model.StatusFail, runtimeProbeFailureMessage(*source, rawURL, curl, classification))
			if classification.Diagnosis != "" {
				report.Diagnose(fmt.Sprintf("Primary issue: %s for %q from source pod %q. %s", classification.Summary, rawURL, source.Pod.Name, classification.Diagnosis))
				continue
			}
			if !hasDiagnosisContaining(report, "egress default-deny") && !hasDiagnosisContaining(report, "DNS resolution failed") && !hasDiagnosisContaining(report, "runtime DNS resolver") {
				if hasDiagnosisContaining(report, "no egress allow candidate mentions") ||
					hasDiagnosisContaining(report, "Calico ") ||
					hasDiagnosisContaining(report, "Cilium ") ||
					hasDiagnosisContaining(report, "NetworkPolicy ") {
					continue
				}
				report.Diagnose(fmt.Sprintf("Outbound reachability to %q failed from source pod %q. Check egress NetworkPolicy/CNI policy, DNS, firewall, NAT gateway, proxy, route tables, or cloud security controls.", rawURL, source.Pod.Name))
			}
		}
	}
	return report, nil
}

func classifyURLTarget(host string) string {
	lower := strings.ToLower(strings.TrimSuffix(host, "."))
	switch {
	case lower == "localhost" || lower == "127.0.0.1" || lower == "::1":
		return "local host"
	case strings.HasSuffix(lower, ".svc") || strings.Contains(lower, ".svc.") || strings.HasSuffix(lower, ".svc.cluster.local"):
		return "cluster-local service"
	default:
		return "external or non-cluster DNS name"
	}
}

func inspectCiliumExternalEgressPosture(ctx context.Context, client *kube.Client, report *model.Report, sourceNamespace corev1.Namespace, sourcePod corev1.Pod, host string, port int32) {
	insights, err := ciliumpolicy.AnalyzeExternalEgress(ctx, client, sourceNamespace, sourcePod, host, port)
	if err != nil {
		report.Add("Cilium Outbound Policy Posture", fmt.Sprintf("TCP/%d", port), model.StatusWarn, fmt.Sprintf("Could not inspect Cilium outbound policy posture: %v", err))
		return
	}
	addInsights(report, insights)
}

func inspectCiliumDNSPosture(ctx context.Context, client *kube.Client, report *model.Report, sourceNamespace corev1.Namespace, sourcePod corev1.Pod, resolv ResolvConf) {
	dns := buildCiliumDNSContext(ctx, client, &ExecTarget{Client: client, Pod: sourcePod, Kind: "source pod"})
	dns.Nameservers = resolv.Nameservers
	insights, err := ciliumpolicy.AnalyzeDNS(ctx, client, sourceNamespace, sourcePod, dns)
	if err != nil {
		report.Add("Cilium DNS Policy Path", "source DNS egress", model.StatusWarn, fmt.Sprintf("Could not inspect Cilium DNS egress policy posture: %v", err))
		return
	}
	addInsights(report, insights)
}

func inspectNativeEgressPortPosture(ctx context.Context, client *kube.Client, report *model.Report, sourceNamespace corev1.Namespace, sourcePod corev1.Pod, port int32) {
	policies, err := client.Core.NetworkingV1().NetworkPolicies(sourceNamespace.Name).List(ctx, metav1.ListOptions{})
	if err != nil {
		report.Add("Outbound Policy Posture", fmt.Sprintf("native TCP/%d", port), model.StatusWarn, fmt.Sprintf("Could not inspect NetworkPolicies in namespace %q: %v", sourceNamespace.Name, err))
		return
	}
	var selecting []networkingv1.NetworkPolicy
	for _, netpol := range policies.Items {
		if policySelectsPod(netpol, sourcePod) && hasPolicyType(netpol, networkingv1.PolicyTypeEgress) {
			selecting = append(selecting, netpol)
		}
	}
	if len(selecting) == 0 {
		return
	}
	if nativeAnyRuleMentionsPort(selecting, "egress", []int32{port}) {
		report.Add("Outbound Policy Posture", fmt.Sprintf("native TCP/%d", port), model.StatusInfo, fmt.Sprintf("At least one native egress rule mentions TCP/%d. Destination-specific rules may still apply.", port))
		return
	}
	report.Add("Outbound Policy Posture", fmt.Sprintf("native TCP/%d", port), model.StatusFail, fmt.Sprintf("Native egress NetworkPolicy selects source pod %q, but no egress rule mentions TCP/%d.", sourcePod.Name, port))
	report.Diagnose(fmt.Sprintf("Primary issue: native egress NetworkPolicy selects source pod %q, but no egress allow candidate mentions TCP/%d.", sourcePod.Name, port))
}

func inspectCalicoEgressPortPosture(ctx context.Context, client *kube.Client, report *model.Report, sourceNamespace corev1.Namespace, sourcePod corev1.Pod, port int32) {
	insights, err := calicopolicy.ShowBlockers(ctx, client, sourceNamespace, sourcePod, "egress", []int32{port}, nil, fmt.Sprintf("%d", port), nil, nil, nil)
	if err != nil {
		report.Add("Calico Outbound Policy Posture", fmt.Sprintf("TCP/%d", port), model.StatusWarn, fmt.Sprintf("Could not inspect Calico outbound policy posture: %v", err))
		return
	}
	if len(insights) == 0 {
		return
	}
	for i := range insights {
		if insights[i].Layer == "Calico Blockers" {
			insights[i].Layer = "Calico Outbound Policy Posture"
		}
	}
	addInsights(report, insights)
}

func inspectEgressPolicyContext(ctx context.Context, client *kube.Client, report *model.Report, source ExecTarget) {
	policies, err := client.Core.NetworkingV1().NetworkPolicies(source.Pod.Namespace).List(ctx, metav1.ListOptions{})
	if err != nil {
		report.Add("Source Policy Posture", "native policies", model.StatusWarn, fmt.Sprintf("Could not inspect NetworkPolicies in namespace %q: %v", source.Pod.Namespace, err))
		return
	}
	var selecting []networkingv1.NetworkPolicy
	var defaultDeny []string
	for _, netpol := range policies.Items {
		if policySelectsPod(netpol, source.Pod) && hasPolicyType(netpol, networkingv1.PolicyTypeEgress) {
			selecting = append(selecting, netpol)
			if len(netpol.Spec.Egress) == 0 {
				defaultDeny = append(defaultDeny, netpol.Name)
			}
		}
	}
	if len(selecting) == 0 {
		report.Add("Source Policy Posture", "native egress", model.StatusPass, fmt.Sprintf("No native egress NetworkPolicies select %s %q.", source.Kind, source.Pod.Name))
		return
	}
	names := nativePolicyNames(selecting)
	if len(defaultDeny) > 0 {
		report.Add("Source Policy Posture", "native egress", model.StatusWarn, fmt.Sprintf("%s %q is selected by egress NetworkPolicy (%s). Policy object(s) with no egress rules default-deny all egress: %s.", source.Kind, source.Pod.Name, strings.Join(names, ", "), strings.Join(defaultDeny, ", ")))
		report.Diagnose(fmt.Sprintf("Primary issue: source pod %q has native egress default-deny policy (%s). Outbound DNS and URL traffic may be blocked before it leaves the cluster.", source.Pod.Name, strings.Join(defaultDeny, ", ")))
		return
	}
	report.Add("Source Policy Posture", "native egress", model.StatusWarn, fmt.Sprintf("%s %q is selected by egress NetworkPolicy (%s). Outbound URL checks are the runtime tie-breaker.", source.Kind, source.Pod.Name, strings.Join(names, ", ")))
}

func urlPortText(parsed *url.URL) string {
	if parsed == nil {
		return "(unknown)"
	}
	if parsed.Port() != "" {
		return parsed.Port()
	}
	switch strings.ToLower(parsed.Scheme) {
	case "https":
		return "443"
	case "http":
		return "80"
	default:
		return "(scheme default/unknown)"
	}
}

func urlPortNumber(parsed *url.URL) (int32, bool) {
	if parsed == nil {
		return 0, false
	}
	if parsed.Port() != "" {
		var value int
		if _, err := fmt.Sscanf(parsed.Port(), "%d", &value); err == nil && value > 0 && value <= 65535 {
			return int32(value), true
		}
		return 0, false
	}
	switch strings.ToLower(parsed.Scheme) {
	case "https":
		return 443, true
	case "http":
		return 80, true
	default:
		return 0, false
	}
}

func selectEgressSource(ctx context.Context, client *kube.Client, report *model.Report, opts EgressOptions) *ExecTarget {
	if opts.SourcePodName != "" {
		pod, err := client.Core.CoreV1().Pods(opts.SourceNamespace).Get(ctx, opts.SourcePodName, metav1.GetOptions{})
		if err != nil {
			report.Add("Source Access", "source pod selected", model.StatusFail, fmt.Sprintf("Could not read supplied source pod %q: %v", opts.SourcePodName, err))
			return nil
		}
		status := model.StatusPass
		if !podReady(*pod) || pod.Status.Phase != corev1.PodRunning {
			status = model.StatusWarn
		}
		report.Add("Source Access", "source pod selected", status, fmt.Sprintf("Using supplied source pod %q phase=%s ready=%t.", pod.Name, pod.Status.Phase, podReady(*pod)))
		return &ExecTarget{Client: client, Pod: *pod, Container: opts.SourceContainer, Kind: "source pod"}
	}
	if opts.SourceSelector != "" {
		pods, err := client.Core.CoreV1().Pods(opts.SourceNamespace).List(ctx, metav1.ListOptions{LabelSelector: opts.SourceSelector})
		if err != nil {
			report.Add("Source Access", "source pod selected", model.StatusFail, fmt.Sprintf("Could not select source pod with selector %q: %v", opts.SourceSelector, err))
			return nil
		}
		selected := selectReadyPod(pods.Items)
		if selected == nil {
			report.Add("Source Access", "source pod selected", model.StatusFail, fmt.Sprintf("No running Ready source pod matched selector %q.", opts.SourceSelector))
			return nil
		}
		report.Add("Source Access", "source pod selected", model.StatusInfo, fmt.Sprintf("Using source pod %q selected by %q.", selected.Name, opts.SourceSelector))
		return &ExecTarget{Client: client, Pod: *selected, Container: opts.SourceContainer, Kind: "source pod"}
	}
	if opts.UseDebugPod {
		pod, err := client.EnsureDebugPod(ctx, opts.SourceNamespace, opts.SourceDebugPod, opts.DebugImage, opts.DebugPullPolicy, maxDuration(opts.Timeout, 30*time.Second))
		if err != nil {
			report.Add("Source debug pod", "debug pod ready", model.StatusFail, fmt.Sprintf("Debug pod %q did not become Ready: %v", opts.SourceDebugPod, err))
			report.Diagnose("Debug pod creation failed. Active egress checks cannot run until RBAC, image access, or scheduling is fixed.")
			return nil
		}
		report.Add("Source debug pod", "debug pod ready", model.StatusPass, fmt.Sprintf("Debug pod %q is Ready in namespace %q.", pod.Name, opts.SourceNamespace))
		return &ExecTarget{Client: client, Pod: *pod, Kind: "source debug pod"}
	}
	report.Add("Source Access", "source path", model.StatusFail, "No source workload pod was provided and debug pod creation is disabled. Provide --source-pod, --source-selector, or --use-debug-pod.")
	report.Diagnose("No executable source path was available for egress testing.")
	return nil
}
