package check

import (
	"context"
	"fmt"
	"net/url"
	"time"

	"github.com/CoGoRepo/KubeNetMods/internal/kube"
	"github.com/CoGoRepo/KubeNetMods/internal/model"
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

	if _, err := client.Core.CoreV1().Namespaces().Get(ctx, opts.SourceNamespace, metav1.GetOptions{}); err != nil {
		report.Add("Source Access", "source namespace", model.StatusFail, fmt.Sprintf("Source namespace %q is not accessible: %v", opts.SourceNamespace, err))
		report.Diagnose(fmt.Sprintf("Cannot access source namespace %q. Fix kubeconfig/RBAC/namespace before testing egress.", opts.SourceNamespace))
		return report, nil
	}
	report.Add("Source Access", "source namespace", model.StatusPass, fmt.Sprintf("Source namespace %q exists.", opts.SourceNamespace))

	source := selectEgressSource(ctx, client, report, opts)
	if source == nil {
		report.Add("External Egress", "urls", model.StatusSkip, "Skipped URL checks because no executable source path was available.")
		return report, nil
	}

	if resolv, err := readResolvConf(ctx, *source); err == nil {
		report.Add("Source DNS", "resolv.conf", model.StatusPass, fmt.Sprintf("Runtime nameserver(s): %s; search domains: %s", formatList(resolv.Nameservers), formatList(resolv.Searches)))
	} else {
		report.Add("Source DNS", "resolv.conf", model.StatusWarn, fmt.Sprintf("Could not read /etc/resolv.conf from %s %q: %v", source.Kind, source.Pod.Name, err))
	}

	if len(opts.URLs) == 0 {
		report.Add("External Egress", "urls", model.StatusFail, "No URLs were supplied for egress testing.")
		report.Diagnose("No external egress target was supplied. Provide one or more URLs to test outbound connectivity.")
		return report, nil
	}
	for _, rawURL := range opts.URLs {
		parsed, err := url.Parse(rawURL)
		if err != nil || parsed.Hostname() == "" || parsed.Scheme == "" {
			report.Add("External Egress", rawURL, model.StatusFail, fmt.Sprintf("URL %q is not a valid absolute URL.", rawURL))
			report.Diagnose(fmt.Sprintf("Invalid egress URL %q. Provide an absolute URL such as https://example.com.", rawURL))
			continue
		}
		host := parsed.Hostname()
		if err := resolveHost(ctx, *source, host); err != nil {
			report.Add("External Egress", "resolve "+host, model.StatusFail, fmt.Sprintf("%s %q could not resolve %q.", source.Kind, source.Pod.Name, host))
			report.Diagnose(fmt.Sprintf("External DNS resolution failed for %q from source pod %q. Check DNS policy, CoreDNS/NodeLocalDNS, egress DNS policy, proxy, or upstream resolver access.", host, source.Pod.Name))
		} else {
			report.Add("External Egress", "resolve "+host, model.StatusPass, fmt.Sprintf("%s %q resolved %q.", source.Kind, source.Pod.Name, host))
		}
		curl := curlURL(ctx, *source, rawURL, opts.Timeout)
		if curl.OK {
			report.Add("External Egress", rawURL, model.StatusPass, fmt.Sprintf("%s %q reached %q. HTTP status: %s", source.Kind, source.Pod.Name, rawURL, curl.StatusCode))
		} else {
			report.Add("External Egress", rawURL, model.StatusFail, fmt.Sprintf("%s %q could not reach %q. %s", source.Kind, source.Pod.Name, rawURL, curl.Error))
			report.Diagnose(fmt.Sprintf("External egress to %q failed from source pod %q. Check egress NetworkPolicy/CNI policy, DNS, firewall, NAT gateway, proxy, route tables, or cloud security controls.", rawURL, source.Pod.Name))
		}
	}
	return report, nil
}

func selectEgressSource(ctx context.Context, client *kube.Client, report *model.Report, opts EgressOptions) *ExecTarget {
	if opts.SourcePodName != "" {
		pod, err := client.Core.CoreV1().Pods(opts.SourceNamespace).Get(ctx, opts.SourcePodName, metav1.GetOptions{})
		if err != nil {
			report.Add("Source Access", "source pod selected", model.StatusFail, fmt.Sprintf("Could not read supplied source pod %q: %v", opts.SourcePodName, err))
			return nil
		}
		report.Add("Source Access", "source pod selected", model.StatusInfo, fmt.Sprintf("Using supplied source pod %q.", pod.Name))
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
