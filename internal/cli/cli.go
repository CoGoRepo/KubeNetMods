package cli

import (
	"context"
	"flag"
	"fmt"
	"io"
	"strings"
	"text/tabwriter"
	"time"

	"github.com/CoGoRepo/KubeNetMods/internal/check"
	"github.com/CoGoRepo/KubeNetMods/internal/model"
	"github.com/CoGoRepo/KubeNetMods/internal/report"
)

type terminalOutputMode string

const (
	terminalOutputFull      terminalOutputMode = "full"
	terminalOutputDiagnosis terminalOutputMode = "diagnosis"
	terminalOutputNone      terminalOutputMode = "none"
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
	case "gateway":
		return runGateway(ctx, args[1:], stdout, stderr)
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
		fmt.Fprintln(stderr, "usage: knm check <service|ingress|egress|gateway> [options]")
		return 2
	}
	switch args[0] {
	case "service":
		return runService(ctx, args[1:], stdout, stderr)
	case "egress":
		return runEgress(ctx, args[1:], stdout, stderr)
	case "ingress":
		return runIngress(ctx, args[1:], stdout, stderr)
	case "gateway":
		return runGateway(ctx, args[1:], stdout, stderr)
	default:
		fmt.Fprintf(stderr, "unknown check type %q\n", args[0])
		return 2
	}
}

func runDiscover(ctx context.Context, args []string, stdout io.Writer, stderr io.Writer) int {
	fs := flag.NewFlagSet("knm discover", flag.ContinueOnError)
	fs.SetOutput(stderr)
	fs.Usage = func() { discoverUsage(stderr) }

	var opts check.DiscoverOptions
	var timeoutSeconds int
	var filterLabels keyValueFlag
	var wide bool

	fs.StringVar(&opts.Context, "context", "", "kubeconfig context")
	fs.StringVar(&opts.Context, "cluster", "", "alias for --context")
	fs.StringVar(&opts.Context, "c", "", "alias for --context")
	fs.StringVar(&opts.Namespace, "namespace", "", "namespace filter; searches all namespaces when omitted")
	fs.StringVar(&opts.Namespace, "n", "", "alias for --namespace")
	fs.StringVar(&opts.Kind, "kind", "", "kind filter: pod, service, deployment, statefulset, daemonset, replicaset")
	fs.StringVar(&opts.ExactName, "name", "", "exact object name filter")
	fs.Var(&filterLabels, "label", "object/template label filter as key=value; repeatable")
	fs.StringVar(&opts.LabelSelector, "label-selector", "", "Kubernetes label selector filter")
	fs.StringVar(&opts.ServiceAccount, "service-account", "", "pod service account filter")
	fs.StringVar(&opts.Node, "node", "", "pod node name filter")
	fs.BoolVar(&wide, "wide", false, "show every matched object instead of grouped compact output")
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
		fmt.Fprintln(stderr, "usage: knm discover <text|*> [--cluster name] [--namespace name] [--kind kind] [--wide]")
		return 2
	} else {
		opts.Query = strings.Join(fs.Args(), " ")
	}
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
	printDiscover(stdout, results, opts, wide)
	if len(results) == 0 {
		return 1
	}
	return 0
}

func normalizeDiscoverArgs(args []string) []string {
	valueFlags := map[string]bool{
		"--context": true, "-context": true,
		"--cluster": true, "-cluster": true,
		"-c":          true,
		"--namespace": true, "-namespace": true,
		"-n":     true,
		"--kind": true, "-kind": true,
		"--name": true, "-name": true,
		"--label": true, "-label": true,
		"--label-selector": true, "-label-selector": true,
		"--service-account": true, "-service-account": true,
		"--node": true, "-node": true,
		"--timeout": true, "-timeout": true,
		"--wide": false, "-wide": false,
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
	fs.Usage = func() { blockersUsage(stderr) }

	var opts check.BlockersOptions
	var labels keyValueFlag
	var jsonPath string
	var htmlPath string
	var quiet bool
	var noTerminal bool
	var wide bool
	var timeoutSeconds int

	fs.StringVar(&opts.Context, "context", "", "kubeconfig context")
	fs.StringVar(&opts.Context, "cluster", "", "alias for --context")
	fs.StringVar(&opts.Context, "c", "", "alias for --context")
	fs.StringVar(&opts.Namespace, "namespace", "default", "subject pod namespace")
	fs.StringVar(&opts.Namespace, "n", "default", "alias for --namespace")
	fs.StringVar(&opts.PodName, "pod", "", "subject pod name")
	fs.StringVar(&opts.PodSelector, "selector", "", "subject pod label selector")
	fs.Var(&labels, "labels", "preflight subject labels as key=value; repeatable")
	fs.StringVar(&opts.ServiceAccount, "service-account", "", "preflight subject service account")
	fs.StringVar(&opts.Direction, "direction", "egress", "policy direction: egress or ingress")
	fs.StringVar(&opts.Protocol, "protocol", "tcp", "protocol to evaluate")
	fs.StringVar(&opts.Port, "port", "", "TCP port to evaluate; accepts number, name, or range like 23:53")
	fs.StringVar(&opts.Port, "p", "", "alias for --port")
	fs.StringVar(&opts.ToNamespace, "to-namespace", "", "target namespace for path-specific evaluation")
	fs.StringVar(&opts.ToService, "to-service", "", "target Service for path-specific evaluation")
	fs.StringVar(&opts.ToSelector, "to-selector", "", "target pod selector override for path-specific evaluation")
	fs.IntVar(&timeoutSeconds, "timeout", 10, "timeout in seconds")
	fs.StringVar(&jsonPath, "json", "", "write JSON report to path")
	fs.StringVar(&htmlPath, "html", "", "write HTML report to path")
	fs.BoolVar(&quiet, "quiet", false, "print only diagnosis to terminal")
	fs.BoolVar(&noTerminal, "no-terminal", false, "do not print terminal output")
	fs.BoolVar(&noTerminal, "no-term", false, "alias for --no-terminal")
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
	return finishBlockersReport(rep, err, terminalMode(quiet, noTerminal), wide, jsonPath, htmlPath, stdout, stderr)
}

func runEgress(ctx context.Context, args []string, stdout io.Writer, stderr io.Writer) int {
	fs := flag.NewFlagSet("knm check egress", flag.ContinueOnError)
	fs.SetOutput(stderr)
	fs.Usage = func() { egressUsage(stderr) }

	var opts check.EgressOptions
	var jsonPath string
	var htmlPath string
	var quiet bool
	var noTerminal bool
	var timeoutSeconds int
	var urls multiFlag

	fs.StringVar(&opts.Context, "context", "", "kubeconfig context")
	fs.StringVar(&opts.Context, "cluster", "", "alias for --context")
	fs.StringVar(&opts.Context, "c", "", "alias for --context")
	fs.StringVar(&opts.SourceNamespace, "source-namespace", "default", "source namespace")
	fs.StringVar(&opts.SourceNamespace, "n", "default", "alias for --source-namespace")
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
	fs.BoolVar(&quiet, "quiet", false, "print only diagnosis to terminal")
	fs.BoolVar(&noTerminal, "no-terminal", false, "do not print terminal output")
	fs.BoolVar(&noTerminal, "no-term", false, "alias for --no-terminal")

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
	return finishReport(rep, err, terminalMode(quiet, noTerminal), jsonPath, htmlPath, stdout, stderr)
}

func runIngress(ctx context.Context, args []string, stdout io.Writer, stderr io.Writer) int {
	fs := flag.NewFlagSet("knm check ingress", flag.ContinueOnError)
	fs.SetOutput(stderr)
	fs.Usage = func() { ingressUsage(stderr) }

	var opts check.IngressOptions
	var jsonPath string
	var htmlPath string
	var quiet bool
	var noTerminal bool
	var timeoutSeconds int
	var servicePort int
	var ingressURLs multiFlag
	var externalURLs multiFlag

	fs.StringVar(&opts.Context, "context", "", "kubeconfig context")
	fs.StringVar(&opts.Context, "cluster", "", "alias for --context")
	fs.StringVar(&opts.Context, "c", "", "alias for --context")
	fs.StringVar(&opts.Namespace, "namespace", "default", "target Service namespace")
	fs.StringVar(&opts.Namespace, "n", "default", "alias for --namespace")
	fs.StringVar(&opts.Service, "service", "nginx", "target Service name")
	fs.StringVar(&opts.Service, "t", "nginx", "alias for --service")
	fs.IntVar(&servicePort, "port", 0, "target Service port; defaults to first Service port")
	fs.IntVar(&servicePort, "p", 0, "alias for --port")
	fs.Var(&ingressURLs, "ingress-url", "explicit ingress URL to test; repeatable")
	fs.Var(&externalURLs, "external-url", "explicit external URL to test; repeatable")
	fs.BoolVar(&opts.TestLoadBalancer, "test-load-balancer", false, "inspect/test LoadBalancer external paths")
	fs.IntVar(&timeoutSeconds, "timeout", 10, "timeout in seconds")
	fs.StringVar(&jsonPath, "json", "", "write JSON report to path")
	fs.StringVar(&htmlPath, "html", "", "write HTML report to path")
	fs.BoolVar(&quiet, "quiet", false, "print only diagnosis to terminal")
	fs.BoolVar(&noTerminal, "no-terminal", false, "do not print terminal output")
	fs.BoolVar(&noTerminal, "no-term", false, "alias for --no-terminal")

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
	return finishReport(rep, err, terminalMode(quiet, noTerminal), jsonPath, htmlPath, stdout, stderr)
}

func runGateway(ctx context.Context, args []string, stdout io.Writer, stderr io.Writer) int {
	fs := flag.NewFlagSet("knm check gateway", flag.ContinueOnError)
	fs.SetOutput(stderr)
	fs.Usage = func() { gatewayUsage(stderr) }

	var opts check.GatewayOptions
	var jsonPath string
	var htmlPath string
	var quiet bool
	var noTerminal bool
	var timeoutSeconds int
	var headers keyValueFlag

	fs.StringVar(&opts.Context, "context", "", "kubeconfig context")
	fs.StringVar(&opts.Context, "cluster", "", "alias for --context")
	fs.StringVar(&opts.Context, "c", "", "alias for --context")
	fs.StringVar(&opts.Namespace, "namespace", "", "namespace scope; scans all namespaces when omitted")
	fs.StringVar(&opts.Namespace, "n", "", "alias for --namespace")
	fs.StringVar(&opts.GatewayRef, "gateway", "", "Gateway to inspect as name or namespace/name")
	fs.StringVar(&opts.RouteRef, "route", "", "HTTPRoute to inspect as name or namespace/name")
	fs.StringVar(&opts.GatewayClass, "gateway-class", "", "GatewayClass filter")
	fs.StringVar(&opts.URL, "url", "", "request URL to trace through Gateway API")
	fs.StringVar(&opts.Host, "host", "", "request host to trace through Gateway API")
	fs.StringVar(&opts.Scheme, "scheme", "", "request scheme for traffic intent")
	fs.StringVar(&opts.Path, "path", "", "request path for traffic intent; defaults to / when --host is used")
	fs.StringVar(&opts.Method, "method", "", "request method for traffic intent")
	fs.Var(&headers, "header", "request header as Name=Value for traffic intent; repeatable")
	fs.IntVar(&opts.Limit, "limit", 50, "maximum problem details to print in scan mode")
	fs.BoolVar(&opts.Wide, "wide", false, "include healthy scan summaries and extra context")
	fs.IntVar(&timeoutSeconds, "timeout", 10, "timeout in seconds")
	fs.StringVar(&jsonPath, "json", "", "write JSON report to path")
	fs.StringVar(&htmlPath, "html", "", "write HTML report to path")
	fs.BoolVar(&quiet, "quiet", false, "print only diagnosis to terminal")
	fs.BoolVar(&noTerminal, "no-terminal", false, "do not print terminal output")
	fs.BoolVar(&noTerminal, "no-term", false, "alias for --no-terminal")

	if err := fs.Parse(args); err != nil {
		if err == flag.ErrHelp {
			return 0
		}
		return 2
	}
	if timeoutSeconds <= 0 {
		timeoutSeconds = 10
	}
	opts.HTTPHeaders = headers
	opts.Timeout = time.Duration(timeoutSeconds) * time.Second
	runCtx, cancel := context.WithTimeout(ctx, opts.Timeout+30*time.Second)
	defer cancel()

	rep, err := check.RunGateway(runCtx, opts)
	return finishReport(rep, err, terminalMode(quiet, noTerminal), jsonPath, htmlPath, stdout, stderr)
}

func runService(ctx context.Context, args []string, stdout io.Writer, stderr io.Writer) int {
	fs := flag.NewFlagSet("knm check service", flag.ContinueOnError)
	fs.SetOutput(stderr)
	fs.Usage = func() { serviceUsage(stderr) }

	var opts check.ServiceOptions
	var jsonPath string
	var htmlPath string
	var quiet bool
	var noTerminal bool
	var timeoutSeconds int
	var servicePort int
	var headers keyValueFlag

	fs.StringVar(&opts.Context, "context", "", "target kubeconfig context")
	fs.StringVar(&opts.Context, "cluster", "", "alias for --context")
	fs.StringVar(&opts.Context, "c", "", "alias for --context")
	fs.StringVar(&opts.Namespace, "namespace", "default", "target Service namespace")
	fs.StringVar(&opts.Namespace, "n", "default", "alias for --namespace")
	fs.StringVar(&opts.TargetName, "target", "", "target Service/workload shortcut; sets target Service and default Deployment")
	fs.StringVar(&opts.TargetName, "t", "", "alias for --target")
	fs.StringVar(&opts.Service, "service", "nginx", "target Service name")
	fs.StringVar(&opts.Deployment, "deployment", "", "target Deployment name; defaults to Service name")
	fs.StringVar(&opts.Deployment, "d", "", "alias for --deployment")
	fs.IntVar(&servicePort, "port", 0, "target Service port; defaults to first Service port")
	fs.IntVar(&servicePort, "p", 0, "alias for --port")
	fs.StringVar(&opts.SourceContext, "source-context", "", "source kubeconfig context")
	fs.StringVar(&opts.SourceContext, "source-cluster", "", "alias for --source-context")
	fs.StringVar(&opts.SourceNamespace, "source-namespace", "", "source namespace; defaults to target namespace")
	fs.StringVar(&opts.SourceName, "source", "", "source pod/workload/service name; resolves to a source pod when explicit source flags are omitted")
	fs.StringVar(&opts.SourceName, "s", "", "alias for --source")
	fs.StringVar(&opts.SourceDeployment, "source-deployment", "", "source Deployment name; resolves to that Deployment's pod selector")
	fs.StringVar(&opts.SourcePodName, "source-pod", "", "source workload pod name")
	fs.StringVar(&opts.SourcePodSelector, "source-selector", "", "source workload pod label selector")
	fs.StringVar(&opts.SourceContainer, "source-container", "", "source workload container name")
	fs.StringVar(&opts.TargetPodSelector, "target-selector", "", "override target backend pod selector")
	fs.StringVar(&opts.URLScheme, "scheme", "http", "URL scheme for HTTP checks")
	fs.StringVar(&opts.URLPath, "path", "/", "URL path for HTTP checks")
	fs.Var(&headers, "header", "HTTP request header for runtime probes as Name=Value; repeatable")
	fs.BoolVar(&opts.UseDebugPod, "use-debug-pod", false, "create a temporary source debug pod when no source pod is supplied")
	fs.StringVar(&opts.DebugImage, "debug-image", "nicolaka/netshoot:latest", "debug pod image")
	fs.StringVar(&opts.DebugPullPolicy, "debug-pull-policy", "IfNotPresent", "debug pod image pull policy")
	fs.StringVar(&opts.SourceDebugPod, "source-debug-pod", "kubenetmods-source-debug", "source debug pod name")
	fs.BoolVar(&opts.SkipNodePort, "skip-nodeport", false, "skip NodePort/host reachability checks")
	fs.IntVar(&timeoutSeconds, "timeout", 10, "API timeout in seconds")
	fs.StringVar(&jsonPath, "json", "", "write JSON report to path")
	fs.StringVar(&htmlPath, "html", "", "write HTML report to path")
	fs.BoolVar(&quiet, "quiet", false, "print only diagnosis to terminal")
	fs.BoolVar(&noTerminal, "no-terminal", false, "do not print terminal output")
	fs.BoolVar(&noTerminal, "no-term", false, "alias for --no-terminal")

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
	opts.HTTPHeaders = headers
	if timeoutSeconds <= 0 {
		timeoutSeconds = 10
	}
	opts.Timeout = time.Duration(timeoutSeconds) * time.Second
	runCtx, cancel := context.WithTimeout(ctx, serviceRunTimeout(opts.Timeout))
	defer cancel()

	rep, err := check.RunService(runCtx, opts)
	return finishReport(rep, err, terminalMode(quiet, noTerminal), jsonPath, htmlPath, stdout, stderr)
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

func printDiscover(w io.Writer, results []check.DiscoverResult, opts check.DiscoverOptions, wide bool) {
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
	if !wide {
		groups := check.CompactDiscoverResults(results)
		fmt.Fprintf(w, "%-24s %-34s %-22s %s\n", "NAMESPACE", "NAME", "KINDS", "HINT")
		fmt.Fprintf(w, "%-24s %-34s %-22s %s\n", "---------", "----", "-----", "----")
		for _, group := range groups {
			fmt.Fprintf(w, "%-24s %-34s %-22s %s\n", group.Namespace, group.Name, strings.Join(group.Kinds, ","), group.Hint)
		}
		fmt.Fprintln(w)
		fmt.Fprintln(w, "Use --wide to show every matched object.")
		return
	}
	fmt.Fprintf(w, "%-14s %-24s %-38s %-18s %s\n", "KIND", "NAMESPACE", "NAME", "MATCH", "HINT")
	fmt.Fprintf(w, "%-14s %-24s %-38s %-18s %s\n", "----", "---------", "----", "-----", "----")
	for _, result := range results {
		fmt.Fprintf(w, "%-14s %-24s %-38s %-18s %s\n", result.Kind, result.Namespace, result.Name, result.Match, result.Hint)
	}
}

func terminalMode(quiet bool, noTerminal bool) terminalOutputMode {
	if noTerminal {
		return terminalOutputNone
	}
	if quiet {
		return terminalOutputDiagnosis
	}
	return terminalOutputFull
}

func finishReport(rep *model.Report, err error, mode terminalOutputMode, jsonPath string, htmlPath string, stdout io.Writer, stderr io.Writer) int {
	if err != nil {
		fmt.Fprintln(stderr, err)
		return 1
	}
	if rep == nil {
		fmt.Fprintln(stderr, "no report was produced")
		return 1
	}
	switch mode {
	case terminalOutputFull:
		report.PrintText(stdout, rep)
	case terminalOutputDiagnosis:
		report.PrintDiagnosis(stdout, rep)
	}
	if jsonPath != "" {
		if err := report.WriteJSON(jsonPath, rep); err != nil {
			fmt.Fprintf(stderr, "write JSON report: %v\n", err)
			return 1
		}
		if mode == terminalOutputFull {
			fmt.Fprintf(stdout, "JSON report written to %s\n", jsonPath)
		}
	}
	if htmlPath != "" {
		if err := report.WriteHTML(htmlPath, rep); err != nil {
			fmt.Fprintf(stderr, "write HTML report: %v\n", err)
			return 1
		}
		if mode == terminalOutputFull {
			fmt.Fprintf(stdout, "HTML report written to %s\n", htmlPath)
		}
	}
	if rep.CountByStatus("FAIL") > 0 {
		return 1
	}
	return 0
}

func finishBlockersReport(rep *model.Report, err error, mode terminalOutputMode, wide bool, jsonPath string, htmlPath string, stdout io.Writer, stderr io.Writer) int {
	if err != nil {
		fmt.Fprintln(stderr, err)
		return 1
	}
	if rep == nil {
		fmt.Fprintln(stderr, "no report was produced")
		return 1
	}
	switch mode {
	case terminalOutputFull:
		report.PrintBlockers(stdout, rep, wide)
	case terminalOutputDiagnosis:
		report.PrintDiagnosis(stdout, rep)
	}
	if jsonPath != "" {
		if err := report.WriteJSON(jsonPath, rep); err != nil {
			fmt.Fprintf(stderr, "write JSON report: %v\n", err)
			return 1
		}
		if mode == terminalOutputFull {
			fmt.Fprintf(stdout, "JSON report written to %s\n", jsonPath)
		}
	}
	if htmlPath != "" {
		if err := report.WriteHTML(htmlPath, rep); err != nil {
			fmt.Fprintf(stderr, "write HTML report: %v\n", err)
			return 1
		}
		if mode == terminalOutputFull {
			fmt.Fprintf(stdout, "HTML report written to %s\n", htmlPath)
		}
	}
	if rep.CountByStatus("FAIL") > 0 {
		return 1
	}
	return 0
}

type helpFlag struct {
	Names       string
	Value       string
	Description string
}

func printCommandHelp(w io.Writer, title string, usageLine string, aliases []string, examples []string, flags []helpFlag) {
	fmt.Fprintln(w, title)
	fmt.Fprintln(w)
	fmt.Fprintln(w, "Usage:")
	fmt.Fprintf(w, "  %s\n", usageLine)
	if len(aliases) > 0 {
		fmt.Fprintln(w)
		fmt.Fprintln(w, "Aliases:")
		for _, alias := range aliases {
			fmt.Fprintf(w, "  %s\n", alias)
		}
	}
	if len(examples) > 0 {
		fmt.Fprintln(w)
		fmt.Fprintln(w, "Examples:")
		for _, example := range examples {
			fmt.Fprintf(w, "  %s\n", example)
		}
	}
	if len(flags) > 0 {
		fmt.Fprintln(w)
		fmt.Fprintln(w, "Options:")
		tw := tabwriter.NewWriter(w, 0, 0, 2, ' ', 0)
		for _, flag := range flags {
			name := flag.Names
			if flag.Value != "" {
				name += " " + flag.Value
			}
			fmt.Fprintf(tw, "  %s\t%s\n", name, flag.Description)
		}
		_ = tw.Flush()
	}
}

func discoverUsage(w io.Writer) {
	printCommandHelp(w,
		"KubeNetMods discover",
		"knm discover <text|*> [options]",
		nil,
		[]string{
			"knm discover checkout-client -c prod -n apps",
			"knm discover * --cluster prod --namespace apps --kind service",
			"knm discover ledger-api --wide",
		},
		[]helpFlag{
			{"-c, --context, --cluster", "name", "kubeconfig context / cluster name"},
			{"-n, --namespace", "name", "namespace filter; searches all namespaces when omitted"},
			{"--kind", "kind", "pod, service, deployment, statefulset, daemonset, replicaset, ingress, networkpolicy"},
			{"--name", "name", "exact object name filter"},
			{"--label", "key=value", "object/template label filter; repeatable"},
			{"--label-selector", "selector", "Kubernetes label selector filter"},
			{"--service-account", "name", "pod service account filter"},
			{"--node", "name", "pod node name filter"},
			{"--wide", "", "show every matched object instead of grouped compact output"},
			{"--timeout", "seconds", "timeout in seconds"},
		})
}

func serviceUsage(w io.Writer) {
	printCommandHelp(w,
		"KubeNetMods check service",
		"knm check service [options]",
		[]string{"knm service [options]"},
		[]string{
			"knm service -c prod -n database -t postgres -s frontend -p 5432",
			"knm check service --source-namespace apps --source-deployment api --namespace database --target postgres --port 5432",
			"knm service -n default -t api --use-debug-pod --html service.html",
		},
		[]helpFlag{
			{"-c, --context, --cluster", "name", "target kubeconfig context / cluster name"},
			{"-n, --namespace", "name", "target Service namespace"},
			{"-t, --target", "name", "target Service/workload shortcut; sets target Service and default Deployment"},
			{"--service", "name", "target Service name"},
			{"-d, --deployment", "name", "target Deployment name; defaults to Service name"},
			{"-p, --port", "port", "target Service port; defaults to first Service port"},
			{"--source-context, --source-cluster", "name", "source kubeconfig context / cluster name"},
			{"--source-namespace", "name", "source namespace; defaults to target namespace"},
			{"-s, --source", "name", "source pod/workload/service name"},
			{"--source-deployment", "name", "source Deployment name"},
			{"--source-pod", "name", "exact source workload pod name"},
			{"--source-selector", "selector", "source workload pod label selector"},
			{"--source-container", "name", "source workload container name"},
			{"--target-selector", "selector", "override target backend pod selector"},
			{"--scheme", "http|https", "URL scheme for runtime probes"},
			{"--path", "path", "URL path for runtime probes"},
			{"--header", "Name=Value", "HTTP request header for runtime probes; repeatable"},
			{"--use-debug-pod", "", "create a temporary source debug pod when no source pod is supplied"},
			{"--debug-image", "image", "debug pod image"},
			{"--skip-nodeport", "", "skip NodePort/host reachability checks"},
			{"--timeout", "seconds", "per-probe/API timeout in seconds"},
			{"--html", "path", "write HTML report"},
			{"--json", "path", "write JSON report"},
			{"--quiet", "", "print only diagnosis to terminal"},
			{"--no-terminal, --no-term", "", "do not print terminal output"},
		})
}

func egressUsage(w io.Writer) {
	printCommandHelp(w,
		"KubeNetMods check egress",
		"knm check egress [options]",
		[]string{"knm egress [options]"},
		[]string{
			"knm egress -c prod -n apps --source-selector app=api --url https://example.com",
			"knm check egress --source-namespace apps --source-pod api-123 --url https://login.microsoftonline.com",
		},
		[]helpFlag{
			{"-c, --context, --cluster", "name", "kubeconfig context / cluster name"},
			{"-n, --source-namespace", "name", "source namespace"},
			{"--source-pod", "name", "source workload pod name"},
			{"--source-selector", "selector", "source workload pod label selector"},
			{"--source-container", "name", "source workload container name"},
			{"--use-debug-pod", "", "create a temporary source debug pod when no source pod is supplied"},
			{"--debug-image", "image", "debug pod image"},
			{"--url", "url", "outbound URL to test; repeatable"},
			{"--timeout", "seconds", "timeout in seconds"},
			{"--html", "path", "write HTML report"},
			{"--json", "path", "write JSON report"},
			{"--quiet", "", "print only diagnosis to terminal"},
			{"--no-terminal, --no-term", "", "do not print terminal output"},
		})
}

func ingressUsage(w io.Writer) {
	printCommandHelp(w,
		"KubeNetMods check ingress",
		"knm check ingress [options]",
		[]string{"knm ingress [options]"},
		[]string{
			"knm ingress -c prod -n apps -t api -p 443 --ingress-url https://api.example.com",
			"knm check ingress --namespace apps --service api --test-load-balancer",
		},
		[]helpFlag{
			{"-c, --context, --cluster", "name", "kubeconfig context / cluster name"},
			{"-n, --namespace", "name", "target Service namespace"},
			{"-t, --service", "name", "target Service name"},
			{"-p, --port", "port", "target Service port; defaults to first Service port"},
			{"--ingress-url", "url", "explicit ingress URL to test; repeatable"},
			{"--external-url", "url", "explicit external URL to test; repeatable"},
			{"--test-load-balancer", "", "inspect/test LoadBalancer external paths"},
			{"--timeout", "seconds", "timeout in seconds"},
			{"--html", "path", "write HTML report"},
			{"--json", "path", "write JSON report"},
			{"--quiet", "", "print only diagnosis to terminal"},
			{"--no-terminal, --no-term", "", "do not print terminal output"},
		})
}

func gatewayUsage(w io.Writer) {
	printCommandHelp(w,
		"KubeNetMods check gateway",
		"knm check gateway [options]",
		[]string{"knm gateway [options]"},
		[]string{
			"knm check gateway",
			"knm check gateway -n apps",
			"knm check gateway --gateway infra/public",
			"knm check gateway --route apps/api-route --wide",
			"knm check gateway --host payments.example.com --path /api",
			"knm check gateway --url https://payments.example.com/api --method POST",
		},
		[]helpFlag{
			{"-c, --context, --cluster", "name", "kubeconfig context / cluster name"},
			{"--url", "URL", "traffic intent URL; owns scheme, host, port, path, and query"},
			{"--host", "host", "traffic intent host when --url is not used"},
			{"--scheme", "http|https", "traffic intent scheme when --url is not used"},
			{"--path", "path", "traffic intent path; defaults to / with --host"},
			{"--method", "method", "traffic intent HTTP method"},
			{"--header", "Name=Value", "traffic intent header; repeatable"},
			{"-n, --namespace", "name", "scope filter: scan routes/services in namespace; all namespaces when omitted"},
			{"--gateway", "name|namespace/name", "scope filter: only consider this Gateway"},
			{"--route", "name|namespace/name", "scope filter: only consider this HTTPRoute"},
			{"--gateway-class", "name", "scope filter: only consider Gateways using this GatewayClass"},
			{"--limit", "count", "maximum problem details to print in scan mode"},
			{"--wide", "", "include healthy scan summaries and extra context"},
			{"--timeout", "seconds", "timeout in seconds"},
			{"--html", "path", "write HTML report"},
			{"--json", "path", "write JSON report"},
			{"--quiet", "", "print only diagnosis to terminal"},
			{"--no-terminal, --no-term", "", "do not print terminal output"},
		})
}

func blockersUsage(w io.Writer) {
	printCommandHelp(w,
		"KubeNetMods show blockers",
		"knm show blockers [options]",
		nil,
		[]string{
			"knm show blockers -c prod -n apps --selector app=api --direction egress -p 5432",
			"knm show blockers -n apps --labels app=api --labels env=prod --direction egress -p 443 --wide",
		},
		[]helpFlag{
			{"-c, --context, --cluster", "name", "kubeconfig context / cluster name"},
			{"-n, --namespace", "name", "subject pod namespace"},
			{"--pod", "name", "subject pod name"},
			{"--selector", "selector", "subject pod label selector"},
			{"--labels", "key=value", "preflight subject labels; repeatable"},
			{"--service-account", "name", "preflight subject service account"},
			{"--direction", "egress|ingress", "policy direction"},
			{"--protocol", "tcp|udp", "protocol to evaluate"},
			{"-p, --port", "port", "port to evaluate; accepts number, name, or range like 23:53"},
			{"--to-namespace", "name", "target namespace for path-specific evaluation"},
			{"--to-service", "name", "target Service for path-specific evaluation"},
			{"--to-selector", "selector", "target pod selector override for path-specific evaluation"},
			{"--wide", "", "print detailed blocker cards instead of compact table"},
			{"--timeout", "seconds", "timeout in seconds"},
			{"--html", "path", "write HTML report"},
			{"--json", "path", "write JSON report"},
			{"--quiet", "", "print only diagnosis to terminal"},
			{"--no-terminal, --no-term", "", "do not print terminal output"},
		})
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
	fmt.Fprintln(w, "  knm check gateway [options]")
	fmt.Fprintln(w, "  knm show blockers [options]")
	fmt.Fprintln(w, "  knm service [options]")
	fmt.Fprintln(w)
	fmt.Fprintln(w, "Examples:")
	fmt.Fprintln(w, "  knm discover checkout-client --cluster prod --namespace apps")
	fmt.Fprintln(w, "  knm check service --namespace default --service nginx")
	fmt.Fprintln(w, "  knm check service --namespace database --target postgres --source-namespace web --source frontend --port 5432 --html report.html")
	fmt.Fprintln(w, "  knm check egress --source-namespace app --source-selector app=api --url https://example.com")
	fmt.Fprintln(w, "  knm check ingress --namespace app --service api --ingress-url https://api.example.com")
	fmt.Fprintln(w, "  knm check gateway")
	fmt.Fprintln(w, "  knm show blockers --namespace app --pod api-1234 --direction egress --port 5432")
}
