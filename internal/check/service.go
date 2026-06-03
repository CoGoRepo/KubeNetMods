package check

import (
	"context"
	"fmt"
	"time"

	"github.com/CoGoRepo/KubeNetMods/internal/kube"
	"github.com/CoGoRepo/KubeNetMods/internal/model"
)

type ServiceOptions struct {
	Context             string
	Namespace           string
	TargetName          string
	Service             string
	Deployment          string
	ServicePort         int32
	SourceContext       string
	SourceNamespace     string
	SourceName          string
	SourceDeployment    string
	SourcePodName       string
	SourcePodSelector   string
	TargetPodSelector   string
	SourceContainer     string
	URLScheme           string
	URLPath             string
	UseDebugPod         bool
	DebugImage          string
	DebugPullPolicy     string
	TargetDebugPod      string
	SourceDebugPod      string
	HTTPHeaders         map[string]string
	SkipNodePort        bool
	Timeout             time.Duration
	DeploymentDefaulted bool
}

func RunService(ctx context.Context, opts ServiceOptions) (*model.Report, error) {
	if opts.Namespace == "" {
		opts.Namespace = "default"
	}
	if opts.TargetName != "" {
		opts.Service = opts.TargetName
		if opts.Deployment == "" {
			opts.Deployment = opts.TargetName
			opts.DeploymentDefaulted = true
		}
	}
	if opts.Service == "" {
		opts.Service = "nginx"
	}
	if opts.Deployment == "" {
		opts.Deployment = opts.Service
		opts.DeploymentDefaulted = true
	}
	if opts.SourceNamespace == "" {
		opts.SourceNamespace = opts.Namespace
	}
	if opts.URLScheme == "" {
		opts.URLScheme = "http"
	}
	if opts.URLPath == "" {
		opts.URLPath = "/"
	}
	if opts.DebugImage == "" {
		opts.DebugImage = "nicolaka/netshoot:latest"
	}
	if opts.DebugPullPolicy == "" {
		opts.DebugPullPolicy = "IfNotPresent"
	}
	if opts.TargetDebugPod == "" {
		opts.TargetDebugPod = "kubenetmods-debug"
	}
	if opts.SourceDebugPod == "" {
		opts.SourceDebugPod = "kubenetmods-source-debug"
	}

	target := model.Target{
		Context:        opts.Context,
		Namespace:      opts.Namespace,
		Service:        opts.Service,
		Deployment:     opts.Deployment,
		ServicePort:    opts.ServicePort,
		SourceContext:  opts.SourceContext,
		SourceNS:       opts.SourceNamespace,
		SourcePod:      opts.SourcePodName,
		SourceSelector: opts.SourcePodSelector,
	}
	report := model.NewReport("check service", target)

	client, err := kube.New(opts.Context)
	if err != nil {
		report.Add("Cluster Access", "target context", model.StatusFail, err.Error())
		report.Diagnose("Cannot build Kubernetes client. Check kubeconfig, context, and credentials.")
		return report, nil
	}
	if report.Target.Context == "" {
		report.Target.Context = client.Context
	}
	if opts.UseDebugPod {
		defer func() {
			_ = client.DeletePodIfExists(context.Background(), opts.SourceNamespace, opts.SourceDebugPod)
			_ = client.DeletePodIfExists(context.Background(), opts.Namespace, opts.TargetDebugPod)
		}()
	}

	checkCluster(ctx, client, report, opts)
	service, serviceOK := checkService(ctx, client, report, opts)
	deployment := checkDeployment(ctx, client, report, opts, service)
	pods := checkTargetPods(ctx, client, report, opts, service, deployment)
	checkEndpoints(ctx, client, report, opts, service, pods)
	checkTargetPort(report, service, pods, opts)
	sourceTarget := checkSource(ctx, client, report, opts)
	checkNativeNetworkPolicies(ctx, client, report, opts, service, pods, sourceTarget)
	checkCniPolicies(ctx, client, report, opts, service, pods, sourceTarget)
	checkMTUPath(ctx, client, report, service, pods, sourceTarget)
	checkRuntimePath(ctx, client, report, opts, service, pods, sourceTarget)
	checkNodePortAndHost(ctx, client, report, opts, service)
	checkEvents(ctx, client, report, opts)

	if !serviceOK {
		report.Diagnose(fmt.Sprintf("Target Service %q is missing or unreadable. Fix the Service before debugging lower networking layers.", opts.Service))
	}
	if len(report.Diagnoses) == 0 && report.CountByStatus(model.StatusFail) > 0 {
		report.Diagnose("Failures were found, but no single dominant diagnosis was inferred yet. Review the failed layer details.")
	}
	report.Limitations = append(report.Limitations,
		"Service checks reason from Kubernetes/CNI objects and runtime exec tests; they do not inspect live dataplane rules or packet traces.",
		"Calico/Cilium policy analysis is heuristic and focuses on the tested source-to-Service path.",
	)
	return report, nil
}
