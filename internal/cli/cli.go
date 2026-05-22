package cli

import (
	"context"
	"flag"
	"fmt"
	"io"
	"strings"
	"time"

	"github.com/CoGoRepo/KubeNetMods/internal/check"
	"github.com/CoGoRepo/KubeNetMods/internal/model"
	"github.com/CoGoRepo/KubeNetMods/internal/report"
)

func Run(ctx context.Context, args []string, stdout io.Writer, stderr io.Writer) int {
	if len(args) == 0 {
		usage(stdout)
		return 0
	}
	switch args[0] {
	case "check":
		return runCheck(ctx, args[1:], stdout, stderr)
	case "discover":
		return runDiscover(ctx, args[1:], stdout, stderr)
	case "show":
		return runShow(ctx, args[1:], stdout, stderr)
	case "service":
		return runService(ctx, args[1:], stdout, stderr)
	case "egress":
		return runEgress(ctx, args[1:], stdout, stderr)
	case "ingress":
		return runIngress(ctx, args[1:], stdout, stderr)
	case "help", "-h", "--help":
		usage(stdout)
		return 0
	default:
		fmt.Fprintf(stderr, "unknown command %q\n\n", args[0])
		usage(stderr)
		return 2
	}
}

func runShow(ctx context.Context, args []string, stdout io.Writer, stderr io.Writer) int {
	if len(args) == 0 {
		fmt.Fprintln(stderr, "missing show type")
		fmt.Fprintln(stderr, "usage: knm show blockers [options]")
		return 2
	}
	switch args[0] {
	case "blockers":
		return runShowBlockers(ctx, args[1:], stdout, stderr)
	default:
		fmt.Fprintf(stderr, "unknown show type %q\n", args[0])
		return 2
	}
}

func runCheck(ctx context.Context, args []string, stdout io.Writer, stderr io.Writer) int {
	if len(args) == 0 {
		fmt.Fprintln(stderr, "missing check type")
		fmt.Fprintln(stderr, "usage: knm check service [options]")
		return 2
	}
	switch args[0] {
	case "service":
		return runService(ctx, args[1:], stdout, stderr)
	case "egress":
		return runEgress(ctx, args[1:], stdout, stderr)
	case "ingress":
		return runIngress(ctx, args[1:], stdout, stderr)
	default:
		fmt.Fprintf(stderr, "unknown check type %q\n", args[0])
		return 2
	}
}

func runDiscover(ctx context.Context, args []string, stdout io.Writer, stderr io.Writer) int {
	fs := flag.NewFlagSet("knm discover", flag.ContinueOnError)
	fs.SetOutput(stderr)

	var opts check.DiscoverOptions
	var timeoutSeconds int
	var filterLabels keyValueFlag

	fs.StringVar(&opts.Context, "context", "", "kubeconfig context")
	fs.StringVar(&opts.Context, "cluster", "", "alias for --context")
	fs.StringVar(&opts.Namespace, "namespace", "", "namespace filter; searches all namespaces when omitted")
	fs.StringVar(&opts.Kind, "kind", "", "kind filter: pod, service, deployment, statefulset, daemonset, replicaset")
	fs.StringVar(&opts.ExactName, "name", "", "exact object name filter")
	fs.Var(&filterLabels, "label", "object/template label filter as key=value; repeatable")
	fs.StringVar(&opts.LabelSelector, "label-selector", "", "Kubernetes label selector filter")
	fs.StringVar(&opts.ServiceAccount, "service-account", "", "pod service account filter")
	fs.StringVar(&opts.Node, "node", "", "pod node name filter")
	fs.IntVar(&timeoutSeconds, "timeout", 10, "timeout in seconds")

	normalizedArgs := normalizeDiscoverArgs(args)
	if err := fs.Parse(normalizedArgs); err != nil {
		if err == flag.ErrHelp {
			return 0
		}
		return 2
	}
	if fs.NArg() == 0 {
		fmt.Fprintln(stderr, "missing search text")
		fmt.Fprintln(stderr, "usage: knm discover <text> [--cluster name] [--namespace name] [--kind kind]")
		return 2
	}
	opts.Query = strings.Join(fs.Args(), " ")
	opts.Labels = filterLabels
	if timeoutSeconds <= 0 {
		timeoutSeconds = 10
	}
	opts.Timeout = time.Duration(timeoutSeconds) * time.Second
	runCtx, cancel := context.WithTimeout(ctx, opts.Timeout)
	defer cancel()

	results, err := check.RunDiscover(runCtx, opts)
	if err != nil {
		fmt.Fprintln(stderr, err)
		return 1
	}
	printDiscover(stdout, results, opts)
	if len(results) == 0 {
		return 1
	}
	return 0
}

func normalizeDiscoverArgs(args []string) []string {
	valueFlags := map[string]bool{
		"--context": true, "-context": true,
		"--cluster": true, "-cluster": true,
		"--namespace": true, "-namespace": true,
		"--kind": true, "-kind": true,
		"--name": true, "-name": true,
		"--label": true, "-label": true,
		"--label-selector": true, "-label-selector": true,
		"--service-account": true, "-service-account": true,
		"--node": true, "-node": true,
		"--timeout": true, "-timeout": true,
	}
	var flags []string
	var positionals []string
	for i := 0; i < len(args); i++ {
		arg := args[i]
		if strings.HasPrefix(arg, "-") {
			flags = append(flags, arg)
			if valueFlags[arg] && i+1 < len(args) {
				flags = append(flags, args[i+1])
				i++
			}
			continue
		}
		positionals = append(positionals, arg)
	}
	return append(flags, positionals...)
}

func runShowBlockers(ctx context.Context, args []string, stdout io.Writer, stderr io.Writer) int {
	fs := flag.NewFlagSet("knm show blockers", flag.ContinueOnError)
	fs.SetOutput(stderr)

	var opts check.BlockersOptions
	var labels keyValueFlag
	var jsonPath string
	var htmlPath string
	var quiet bool
	var wide bool
	var timeoutSeconds int

	fs.StringVar(&opts.Context, "context", "", "kubeconfig context")
	fs.StringVar(&opts.Context, "cluster", "", "alias for --context")
	fs.StringVar(&opts.Namespace, "namespace", "default", "subject pod namespace")
	fs.StringVar(&opts.PodName, "pod", "", "subject pod name")
	fs.StringVar(&opts.PodSelector, "selector", "", "subject pod label selector")
	fs.Var(&labels, "labels", "preflight subject labels as key=value; repeatable")
	fs.StringVar(&opts.ServiceAccount, "service-account", "", "preflight subject service account")
	fs.StringVar(&opts.Direction, "direction", "egress", "policy direction: egress or ingress")
	fs.StringVar(&opts.Protocol, "protocol", "tcp", "protocol to evaluate")
	fs.StringVar(&opts.Port, "port", "", "TCP port to evaluate; accepts number, name, or range like 23:53")
	fs.StringVar(&opts.ToNamespace, "to-namespace", "", "target namespace for path-specific evaluation")
	fs.StringVar(&opts.ToService, "to-service", "", "target Service for path-specific evaluation")
	fs.StringVar(&opts.ToSelector, "to-selector", "", "target pod selector override for path-specific evaluation")
	fs.IntVar(&timeoutSeconds, "timeout", 10, "timeout in seconds")
	fs.StringVar(&jsonPath, "json", "", "write JSON report to path")
	fs.StringVar(&htmlPath, "html", "", "write HTML report to path")
	fs.BoolVar(&quiet, "quiet", false, "do not print terminal report")
	fs.BoolVar(&wide, "wide", false, "print detailed blocker cards instead of compact table")

	if err := fs.Parse(args); err != nil {
		if err == flag.ErrHelp {
			return 0
		}
		return 2
	}
	opts.PodLabels = labels
	if timeoutSeconds <= 0 {
		timeoutSeconds = 10
	}
	opts.Timeout = time.Duration(timeoutSeconds) * time.Second
	runCtx, cancel := context.WithTimeout(ctx, opts.Timeout+60*time.Second)
	defer cancel()

	rep, err := check.RunBlockers(runCtx, opts)
	return finishBlockersReport(rep, err, quiet, wide, jsonPath, htmlPath, stdout, stderr)
}

func runEgress(ctx context.Context, args []string, stdout io.Writer, stderr io.Writer) int {
	fs := flag.NewFlagSet("knm check egress", flag.ContinueOnError)
	fs.SetOutput(stderr)

	var opts check.EgressOptions
	var jsonPath string
	var htmlPath string
	var quiet bool
	var timeoutSeconds int
	var urls multiFlag

	fs.StringVar(&opts.Context, "context", "", "kubeconfig context")
	fs.StringVar(&opts.Context, "cluster", "", "alias for --context")
	fs.StringVar(&opts.SourceNamespace, "source-namespace", "default", "source namespace")
	fs.StringVar(&opts.SourcePodName, "source-pod", "", "source workload pod name")
	fs.StringVar(&opts.SourceSelector, "source-selector", "", "source workload pod label selector")
	fs.StringVar(&opts.SourceContainer, "source-container", "", "source workload container name")
	fs.BoolVar(&opts.UseDebugPod, "use-debug-pod", false, "create a temporary source debug pod when no source pod is supplied")
	fs.StringVar(&opts.DebugImage, "debug-image", "nicolaka/netshoot:latest", "debug pod image")
	fs.StringVar(&opts.DebugPullPolicy, "debug-pull-policy", "IfNotPresent", "debug pod image pull policy")
	fs.StringVar(&opts.SourceDebugPod, "source-debug-pod", "kubenetmods-egress-debug", "source debug pod name")
	fs.Var(&urls, "url", "external URL to test; repeatable")
	fs.IntVar(&timeoutSeconds, "timeout", 10, "timeout in seconds")
	fs.StringVar(&jsonPath, "json", "", "write JSON report to path")
	fs.StringVar(&htmlPath, "html", "", "write HTML report to path")
	fs.BoolVar(&quiet, "quiet", false, "do not print terminal report")

	if err := fs.Parse(args); err != nil {
		if err == flag.ErrHelp {
			return 0
		}
		return 2
	}
	opts.URLs = urls
	if timeoutSeconds <= 0 {
		timeoutSeconds = 10
	}
	opts.Timeout = time.Duration(timeoutSeconds) * time.Second
	runCtx, cancel := context.WithTimeout(ctx, opts.Timeout+60*time.Second)
	defer cancel()

	rep, err := check.RunEgress(runCtx, opts)
	return finishReport(rep, err, quiet, jsonPath, htmlPath, stdout, stderr)
}

func runIngress(ctx context.Context, args []string, stdout io.Writer, stderr io.Writer) int {
	fs := flag.NewFlagSet("knm check ingress", flag.ContinueOnError)
	fs.SetOutput(stderr)

	var opts check.IngressOptions
	var jsonPath string
	var htmlPath string
	var quiet bool
	var timeoutSeconds int
	var servicePort int
	var ingressURLs multiFlag
	var externalURLs multiFlag

	fs.StringVar(&opts.Context, "context", "", "kubeconfig context")
	fs.StringVar(&opts.Context, "cluster", "", "alias for --context")
	fs.StringVar(&opts.Namespace, "namespace", "default", "target Service namespace")
	fs.StringVar(&opts.Service, "service", "nginx", "target Service name")
	fs.IntVar(&servicePort, "port", 0, "target Service port; defaults to first Service port")
	fs.Var(&ingressURLs, "ingress-url", "explicit ingress URL to test; repeatable")
	fs.Var(&externalURLs, "external-url", "explicit external URL to test; repeatable")
	fs.BoolVar(&opts.TestLoadBalancer, "test-load-balancer", false, "inspect/test LoadBalancer external paths")
	fs.IntVar(&timeoutSeconds, "timeout", 10, "timeout in seconds")
	fs.StringVar(&jsonPath, "json", "", "write JSON report to path")
	fs.StringVar(&htmlPath, "html", "", "write HTML report to path")
	fs.BoolVar(&quiet, "quiet", false, "do not print terminal report")

	if err := fs.Parse(args); err != nil {
		if err == flag.ErrHelp {
			return 0
		}
		return 2
	}
	opts.IngressURLs = ingressURLs
	opts.ExternalURLs = externalURLs
	opts.ServicePort = int32(servicePort)
	if timeoutSeconds <= 0 {
		timeoutSeconds = 10
	}
	opts.Timeout = time.Duration(timeoutSeconds) * time.Second
	runCtx, cancel := context.WithTimeout(ctx, opts.Timeout+30*time.Second)
	defer cancel()

	rep, err := check.RunIngress(runCtx, opts)
	return finishReport(rep, err, quiet, jsonPath, htmlPath, stdout, stderr)
}

func runService(ctx context.Context, args []string, stdout io.Writer, stderr io.Writer) int {
	fs := flag.NewFlagSet("knm check service", flag.ContinueOnError)
	fs.SetOutput(stderr)

	var opts check.ServiceOptions
	var jsonPath string
	var htmlPath string
	var quiet bool
	var timeoutSeconds int
	var servicePort int

	fs.StringVar(&opts.Context, "context", "", "target kubeconfig context")
	fs.StringVar(&opts.Context, "cluster", "", "alias for --context")
	fs.StringVar(&opts.Namespace, "namespace", "default", "target Service namespace")
	fs.StringVar(&opts.TargetName, "target", "", "target Service/workload shortcut; sets target Service and default Deployment")
	fs.StringVar(&opts.Service, "service", "nginx", "target Service name")
	fs.StringVar(&opts.Deployment, "deployment", "", "target Deployment name; defaults to Service name")
	fs.IntVar(&servicePort, "port", 0, "target Service port; defaults to first Service port")
	fs.StringVar(&opts.SourceContext, "source-context", "", "source kubeconfig context")
	fs.StringVar(&opts.SourceContext, "source-cluster", "", "alias for --source-context")
	fs.StringVar(&opts.SourceNamespace, "source-namespace", "", "source namespace; defaults to target namespace")
	fs.StringVar(&opts.SourceName, "source", "", "source pod/workload/service name; resolves to a source pod when explicit source flags are omitted")
	fs.StringVar(&opts.SourceDeployment, "source-deployment", "", "source Deployment name; resolves to that Deployment's pod selector")
	fs.StringVar(&opts.SourcePodName, "source-pod", "", "source workload pod name")
	fs.StringVar(&opts.SourcePodSelector, "source-selector", "", "source workload pod label selector")
	fs.StringVar(&opts.SourceContainer, "source-container", "", "source workload container name")
	fs.StringVar(&opts.TargetPodSelector, "target-selector", "", "override target backend pod selector")
	fs.StringVar(&opts.URLScheme, "scheme", "http", "URL scheme for HTTP checks")
	fs.StringVar(&opts.URLPath, "path", "/", "URL path for HTTP checks")
	fs.BoolVar(&opts.UseDebugPod, "use-debug-pod", false, "create a temporary source debug pod when no source pod is supplied")
	fs.StringVar(&opts.DebugImage, "debug-image", "nicolaka/netshoot:latest", "debug pod image")
	fs.StringVar(&opts.DebugPullPolicy, "debug-pull-policy", "IfNotPresent", "debug pod image pull policy")
	fs.StringVar(&opts.SourceDebugPod, "source-debug-pod", "kubenetmods-source-debug", "source debug pod name")
	fs.BoolVar(&opts.SkipNodePort, "skip-nodeport", false, "skip NodePort/host reachability checks")
	fs.IntVar(&timeoutSeconds, "timeout", 10, "API timeout in seconds")
	fs.StringVar(&jsonPath, "json", "", "write JSON report to path")
	fs.StringVar(&htmlPath, "html", "", "write HTML report to path")
	fs.BoolVar(&quiet, "quiet", false, "do not print terminal report")

	if err := fs.Parse(args); err != nil {
		if err == flag.ErrHelp {
			return 0
		}
		return 2
	}
	if opts.TargetName != "" {
		opts.Service = opts.TargetName
	}
	if opts.Deployment == "" {
		opts.Deployment = opts.Service
		opts.DeploymentDefaulted = true
	}
	opts.ServicePort = int32(servicePort)
	if timeoutSeconds <= 0 {
		timeoutSeconds = 10
	}
	opts.Timeout = time.Duration(timeoutSeconds) * time.Second
	runCtx, cancel := context.WithTimeout(ctx, serviceRunTimeout(opts.Timeout))
	defer cancel()

	rep, err := check.RunService(runCtx, opts)
	return finishReport(rep, err, quiet, jsonPath, htmlPath, stdout, stderr)
}

func serviceRunTimeout(perCheck time.Duration) time.Duration {
	if perCheck <= 0 {
		perCheck = 10 * time.Second
	}
	total := perCheck*8 + 60*time.Second
	if total < 2*time.Minute {
		return 2 * time.Minute
	}
	return total
}

func printDiscover(w io.Writer, results []check.DiscoverResult, opts check.DiscoverOptions) {
	fmt.Fprintln(w, "KubeNetMods discover")
	if len(results) == 0 {
		fmt.Fprintln(w, "No matching Kubernetes objects found.")
		contextName := opts.Context
		if contextName == "" {
			contextName = "(current context)"
		}
		namespace := opts.Namespace
		if namespace == "" {
			namespace = "(all namespaces)"
		}
		fmt.Fprintf(w, "Searched context/cluster: %s\n", contextName)
		fmt.Fprintf(w, "Searched namespace:       %s\n", namespace)
		return
	}
	fmt.Fprintf(w, "%-14s %-24s %-38s %-18s %s\n", "KIND", "NAMESPACE", "NAME", "MATCH", "HINT")
	fmt.Fprintf(w, "%-14s %-24s %-38s %-18s %s\n", "----", "---------", "----", "-----", "----")
	for _, result := range results {
		fmt.Fprintf(w, "%-14s %-24s %-38s %-18s %s\n", result.Kind, result.Namespace, result.Name, result.Match, result.Hint)
	}
}

func finishReport(rep *model.Report, err error, quiet bool, jsonPath string, htmlPath string, stdout io.Writer, stderr io.Writer) int {
	if err != nil {
		fmt.Fprintln(stderr, err)
		return 1
	}
	if rep == nil {
		fmt.Fprintln(stderr, "no report was produced")
		return 1
	}
	if !quiet {
		report.PrintText(stdout, rep)
	}
	if jsonPath != "" {
		if err := report.WriteJSON(jsonPath, rep); err != nil {
			fmt.Fprintf(stderr, "write JSON report: %v\n", err)
			return 1
		}
		fmt.Fprintf(stdout, "JSON report written to %s\n", jsonPath)
	}
	if htmlPath != "" {
		if err := report.WriteHTML(htmlPath, rep); err != nil {
			fmt.Fprintf(stderr, "write HTML report: %v\n", err)
			return 1
		}
		fmt.Fprintf(stdout, "HTML report written to %s\n", htmlPath)
	}
	if rep.CountByStatus("FAIL") > 0 {
		return 1
	}
	return 0
}

func finishBlockersReport(rep *model.Report, err error, quiet bool, wide bool, jsonPath string, htmlPath string, stdout io.Writer, stderr io.Writer) int {
	if err != nil {
		fmt.Fprintln(stderr, err)
		return 1
	}
	if rep == nil {
		fmt.Fprintln(stderr, "no report was produced")
		return 1
	}
	if !quiet {
		report.PrintBlockers(stdout, rep, wide)
	}
	if jsonPath != "" {
		if err := report.WriteJSON(jsonPath, rep); err != nil {
			fmt.Fprintf(stderr, "write JSON report: %v\n", err)
			return 1
		}
		fmt.Fprintf(stdout, "JSON report written to %s\n", jsonPath)
	}
	if htmlPath != "" {
		if err := report.WriteHTML(htmlPath, rep); err != nil {
			fmt.Fprintf(stderr, "write HTML report: %v\n", err)
			return 1
		}
		fmt.Fprintf(stdout, "HTML report written to %s\n", htmlPath)
	}
	if rep.CountByStatus("FAIL") > 0 {
		return 1
	}
	return 0
}

type multiFlag []string

func (m *multiFlag) String() string {
	return fmt.Sprintf("%v", []string(*m))
}

func (m *multiFlag) Set(value string) error {
	*m = append(*m, value)
	return nil
}

type keyValueFlag map[string]string

func (k *keyValueFlag) String() string {
	if k == nil {
		return "{}"
	}
	return fmt.Sprintf("%v", map[string]string(*k))
}

func (k *keyValueFlag) Set(value string) error {
	parts := strings.SplitN(value, "=", 2)
	if len(parts) != 2 || parts[0] == "" {
		return fmt.Errorf("expected key=value")
	}
	if *k == nil {
		*k = map[string]string{}
	}
	(*k)[parts[0]] = parts[1]
	return nil
}

func usage(w io.Writer) {
	fmt.Fprintln(w, "KubeNetMods Go CLI")
	fmt.Fprintln(w)
	fmt.Fprintln(w, "Usage:")
	fmt.Fprintln(w, "  knm discover <text> [options]")
	fmt.Fprintln(w, "  knm check service [options]")
	fmt.Fprintln(w, "  knm check egress [options]")
	fmt.Fprintln(w, "  knm check ingress [options]")
	fmt.Fprintln(w, "  knm show blockers [options]")
	fmt.Fprintln(w, "  knm service [options]")
	fmt.Fprintln(w)
	fmt.Fprintln(w, "Examples:")
	fmt.Fprintln(w, "  knm discover checkout-client --cluster prod --namespace apps")
	fmt.Fprintln(w, "  knm check service --namespace default --service nginx")
	fmt.Fprintln(w, "  knm check service --namespace database --target postgres --source-namespace web --source frontend --port 5432 --html report.html")
	fmt.Fprintln(w, "  knm check egress --source-namespace app --source-selector app=api --url https://example.com")
	fmt.Fprintln(w, "  knm check ingress --namespace app --service api --ingress-url https://api.example.com")
	fmt.Fprintln(w, "  knm show blockers --namespace app --pod api-1234 --direction egress --port 5432")
}
