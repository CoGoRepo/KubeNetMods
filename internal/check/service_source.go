package check

import (
	"context"
	"fmt"
	"sort"
	"strings"
	"time"

	"github.com/CoGoRepo/KubeNetMods/internal/kube"
	"github.com/CoGoRepo/KubeNetMods/internal/model"
	corev1 "k8s.io/api/core/v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/labels"
)

type sourceResolverResult struct {
	Kind       string
	ObjectName string
	Selector   string
	Pod        *corev1.Pod
}

func resolveSourceName(ctx context.Context, client *kube.Client, namespace string, name string) (*sourceResolverResult, error) {
	if strings.TrimSpace(name) == "" {
		return nil, fmt.Errorf("source name was empty")
	}
	if pod, err := client.Core.CoreV1().Pods(namespace).Get(ctx, name, metav1.GetOptions{}); err == nil {
		return &sourceResolverResult{Kind: "Pod", ObjectName: pod.Name, Pod: pod}, nil
	} else if err != nil && !apierrors.IsNotFound(err) {
		return nil, fmt.Errorf("could not read source pod %q: %v", name, err)
	}

	var candidates []sourceResolverResult
	addSelectorCandidate := func(kind, objectName, selector string) {
		if selector == "" {
			return
		}
		pods, err := client.Core.CoreV1().Pods(namespace).List(ctx, metav1.ListOptions{LabelSelector: selector})
		if err != nil || len(pods.Items) == 0 {
			return
		}
		selected := selectReadyPod(pods.Items)
		if selected == nil {
			selected = &pods.Items[0]
		}
		candidates = append(candidates, sourceResolverResult{
			Kind:       kind,
			ObjectName: objectName,
			Selector:   selector,
			Pod:        selected,
		})
	}
	if deployment, err := client.Core.AppsV1().Deployments(namespace).Get(ctx, name, metav1.GetOptions{}); err == nil {
		addSelectorCandidate("Deployment", deployment.Name, metav1.FormatLabelSelector(deployment.Spec.Selector))
	} else if err != nil && !apierrors.IsNotFound(err) {
		return nil, fmt.Errorf("could not read source Deployment %q: %v", name, err)
	}
	if statefulSet, err := client.Core.AppsV1().StatefulSets(namespace).Get(ctx, name, metav1.GetOptions{}); err == nil {
		addSelectorCandidate("StatefulSet", statefulSet.Name, metav1.FormatLabelSelector(statefulSet.Spec.Selector))
	} else if err != nil && !apierrors.IsNotFound(err) {
		return nil, fmt.Errorf("could not read source StatefulSet %q: %v", name, err)
	}
	if daemonSet, err := client.Core.AppsV1().DaemonSets(namespace).Get(ctx, name, metav1.GetOptions{}); err == nil {
		addSelectorCandidate("DaemonSet", daemonSet.Name, metav1.FormatLabelSelector(daemonSet.Spec.Selector))
	} else if err != nil && !apierrors.IsNotFound(err) {
		return nil, fmt.Errorf("could not read source DaemonSet %q: %v", name, err)
	}
	if replicaSet, err := client.Core.AppsV1().ReplicaSets(namespace).Get(ctx, name, metav1.GetOptions{}); err == nil {
		addSelectorCandidate("ReplicaSet", replicaSet.Name, metav1.FormatLabelSelector(replicaSet.Spec.Selector))
	} else if err != nil && !apierrors.IsNotFound(err) {
		return nil, fmt.Errorf("could not read source ReplicaSet %q: %v", name, err)
	}
	if service, err := client.Core.CoreV1().Services(namespace).Get(ctx, name, metav1.GetOptions{}); err == nil {
		addSelectorCandidate("Service", service.Name, labels.SelectorFromSet(labels.Set(service.Spec.Selector)).String())
	} else if err != nil && !apierrors.IsNotFound(err) {
		return nil, fmt.Errorf("could not read source Service %q: %v", name, err)
	}

	for _, key := range []string{"app", "app.kubernetes.io/name", "k8s-app", "component"} {
		addSelectorCandidate("label selector", key+"="+name, labels.SelectorFromSet(labels.Set{key: name}).String())
	}

	if len(candidates) == 0 {
		return nil, fmt.Errorf("source %q did not match a Pod, workload, Service selector, or common app label in namespace %q", name, namespace)
	}

	seen := map[string]sourceResolverResult{}
	for _, candidate := range candidates {
		podName := ""
		if candidate.Pod != nil {
			podName = candidate.Pod.Name
		}
		key := candidate.Selector + "|" + podName
		if _, ok := seen[key]; !ok {
			seen[key] = candidate
		}
	}
	if len(seen) == 1 {
		for _, candidate := range seen {
			return &candidate, nil
		}
	}

	var descriptions []string
	for _, candidate := range candidates {
		descriptions = append(descriptions, fmt.Sprintf("%s/%s selector=%s", candidate.Kind, candidate.ObjectName, candidate.Selector))
	}
	sort.Strings(descriptions)
	return nil, fmt.Errorf("source %q matched multiple possible sources in namespace %q: %s. Use --source-pod or --source-selector to choose one", name, namespace, strings.Join(uniqueStrings(descriptions), "; "))
}

func checkSource(ctx context.Context, client *kube.Client, report *model.Report, opts ServiceOptions) *ExecTarget {
	if opts.SourcePodName == "" && opts.SourcePodSelector == "" && opts.SourceDeployment == "" && opts.SourceName == "" {
		if !opts.UseDebugPod {
			report.Add("Source Path Layer", "source workload", model.StatusSkip, "No source pod name/selector was supplied and debug pod creation is disabled.")
			return nil
		}
		pod, err := client.EnsureDebugPod(ctx, opts.SourceNamespace, opts.SourceDebugPod, opts.DebugImage, opts.DebugPullPolicy, maxDuration(opts.Timeout, 30*time.Second))
		if err != nil {
			report.Add("Source debug pod path", "debug pod ready", model.StatusFail, fmt.Sprintf("Source debug pod %q did not become Ready: %v", opts.SourceDebugPod, err))
			report.Diagnose("Debug pod creation failed in the source namespace. Active DNS/curl checks cannot run until RBAC, image access, or scheduling is fixed.")
			return nil
		}
		report.Add("Source debug pod path", "debug pod ready", model.StatusPass, fmt.Sprintf("Source debug pod %q is Ready in namespace %q.", pod.Name, opts.SourceNamespace))
		return &ExecTarget{Client: client, Pod: *pod, Kind: "source debug pod"}
	}
	sourceClient := client
	if opts.SourceContext != "" && opts.SourceContext != opts.Context {
		other, err := kube.New(opts.SourceContext)
		if err != nil {
			report.Add("Source Path Layer", "source context", model.StatusFail, fmt.Sprintf("Source context %q is not usable: %v", opts.SourceContext, err))
			return nil
		}
		sourceClient = other
	}
	if opts.SourcePodName == "" && opts.SourcePodSelector == "" && opts.SourceDeployment != "" {
		deployment, err := sourceClient.Core.AppsV1().Deployments(opts.SourceNamespace).Get(ctx, opts.SourceDeployment, metav1.GetOptions{})
		if err != nil {
			report.Add("Source Resolver Layer", "source deployment", model.StatusFail, fmt.Sprintf("Source Deployment %q is not readable: %v", opts.SourceDeployment, err))
			report.Diagnose(fmt.Sprintf("Could not resolve source Deployment %q in namespace %q. Check the source namespace/name or use --source-selector.", opts.SourceDeployment, opts.SourceNamespace))
			return nil
		}
		opts.SourcePodSelector = metav1.FormatLabelSelector(deployment.Spec.Selector)
		report.Target.SourceSelector = opts.SourcePodSelector
		report.Add("Source Resolver Layer", "source deployment", model.StatusInfo, fmt.Sprintf("Resolved source Deployment %q to selector %s.", deployment.Name, opts.SourcePodSelector))
	}
	if opts.SourcePodName == "" && opts.SourcePodSelector == "" && opts.SourceName != "" {
		resolved, err := resolveSourceName(ctx, sourceClient, opts.SourceNamespace, opts.SourceName)
		if err != nil {
			report.Add("Source Resolver Layer", "source name", model.StatusFail, err.Error())
			report.Diagnose(fmt.Sprintf("Could not resolve source %q in namespace %q. Use --source-pod for an exact pod or --source-selector for labels.", opts.SourceName, opts.SourceNamespace))
			return nil
		}
		report.Target.SourceSelector = resolved.Selector
		if resolved.Pod != nil {
			report.Target.SourcePod = resolved.Pod.Name
			status := model.StatusPass
			if !podReady(*resolved.Pod) {
				status = model.StatusWarn
			}
			report.Add("Source Resolver Layer", "source name", status, fmt.Sprintf("Resolved source %q to %s %q, using pod %q phase=%s ready=%t.", opts.SourceName, resolved.Kind, resolved.ObjectName, resolved.Pod.Name, resolved.Pod.Status.Phase, podReady(*resolved.Pod)))
			return &ExecTarget{Client: sourceClient, Pod: *resolved.Pod, Container: opts.SourceContainer, Kind: "source pod"}
		}
		opts.SourcePodSelector = resolved.Selector
		report.Target.SourceSelector = resolved.Selector
		report.Add("Source Resolver Layer", "source name", model.StatusInfo, fmt.Sprintf("Resolved source %q to %s %q selector %s.", opts.SourceName, resolved.Kind, resolved.ObjectName, resolved.Selector))
	}
	if opts.SourcePodName != "" {
		pod, err := sourceClient.Core.CoreV1().Pods(opts.SourceNamespace).Get(ctx, opts.SourcePodName, metav1.GetOptions{})
		if err != nil {
			report.Add("Source Path Layer", "source pod", model.StatusFail, fmt.Sprintf("Source pod %q is not readable: %v", opts.SourcePodName, err))
			return nil
		}
		status := model.StatusPass
		if !podReady(*pod) {
			status = model.StatusWarn
		}
		report.Add("Source Path Layer", "source pod", status, fmt.Sprintf("Source pod %q phase=%s ready=%t.", pod.Name, pod.Status.Phase, podReady(*pod)))
		return &ExecTarget{Client: sourceClient, Pod: *pod, Container: opts.SourceContainer, Kind: "source pod"}
	}
	pods, err := sourceClient.Core.CoreV1().Pods(opts.SourceNamespace).List(ctx, metav1.ListOptions{LabelSelector: opts.SourcePodSelector})
	if err != nil {
		report.Add("Source Path Layer", "source selector", model.StatusFail, fmt.Sprintf("Could not list source pods: %v", err))
		return nil
	}
	if len(pods.Items) == 0 {
		report.Add("Source Path Layer", "source selector", model.StatusFail, "No source pods matched selector "+opts.SourcePodSelector)
		return nil
	}
	selected := selectReadyPod(pods.Items)
	if selected == nil {
		report.Add("Source Path Layer", "source selector", model.StatusFail, fmt.Sprintf("%d source pod(s) matched selector %s, but none are Running and Ready.", len(pods.Items), opts.SourcePodSelector))
		return nil
	}
	report.Add("Source Path Layer", "source selector", model.StatusPass, fmt.Sprintf("Using source pod %q selected by %s.", selected.Name, opts.SourcePodSelector))
	return &ExecTarget{Client: sourceClient, Pod: *selected, Container: opts.SourceContainer, Kind: "source pod"}
}
