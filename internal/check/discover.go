package check

import (
	"context"
	"fmt"
	"sort"
	"strings"
	"time"

	"github.com/CoGoRepo/KubeNetMods/internal/kube"
	networkingv1 "k8s.io/api/networking/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/labels"
)

type DiscoverOptions struct {
	Context        string
	Namespace      string
	Query          string
	Kind           string
	ExactName      string
	Labels         map[string]string
	LabelSelector  string
	ServiceAccount string
	Node           string
	Timeout        time.Duration
}

type DiscoverResult struct {
	Kind      string
	Namespace string
	Name      string
	Match     string
	Hint      string
}

func RunDiscover(ctx context.Context, opts DiscoverOptions) ([]DiscoverResult, error) {
	client, err := kube.New(opts.Context)
	if err != nil {
		return nil, err
	}
	query := strings.ToLower(strings.TrimSpace(opts.Query))
	kind := normalizeKind(opts.Kind)
	selector, err := parseOptionalSelector(opts.LabelSelector)
	if err != nil {
		return nil, err
	}
	namespace := opts.Namespace
	if namespace == "" {
		namespace = metav1.NamespaceAll
	}

	var results []DiscoverResult
	if kind == "" || kind == "pod" {
		pods, err := client.Core.CoreV1().Pods(namespace).List(ctx, metav1.ListOptions{})
		if err != nil {
			return nil, fmt.Errorf("list pods: %v", err)
		}
		for _, pod := range pods.Items {
			if !objectFilterMatch(opts, selector, pod.Name, pod.Labels, pod.Spec.ServiceAccountName, pod.Spec.NodeName) {
				continue
			}
			if match, ok := discoverMatch(query, pod.Name, pod.Labels, nil); ok {
				results = append(results, DiscoverResult{
					Kind:      "Pod",
					Namespace: pod.Namespace,
					Name:      pod.Name,
					Match:     match,
					Hint:      fmt.Sprintf("source-pod=%s serviceAccount=%s node=%s", pod.Name, pod.Spec.ServiceAccountName, pod.Spec.NodeName),
				})
			}
		}
	}
	if kind == "" || kind == "service" {
		services, err := client.Core.CoreV1().Services(namespace).List(ctx, metav1.ListOptions{})
		if err != nil {
			return nil, fmt.Errorf("list services: %v", err)
		}
		for _, service := range services.Items {
			if !objectFilterMatch(opts, selector, service.Name, service.Labels, "", "") {
				continue
			}
			if match, ok := discoverMatch(query, service.Name, service.Labels, service.Spec.Selector); ok {
				results = append(results, DiscoverResult{
					Kind:      "Service",
					Namespace: service.Namespace,
					Name:      service.Name,
					Match:     match,
					Hint:      fmt.Sprintf("target=%s selector=%s", service.Name, labels.Set(service.Spec.Selector).String()),
				})
			}
		}
	}
	if kind == "" || kind == "deployment" {
		deployments, err := client.Core.AppsV1().Deployments(namespace).List(ctx, metav1.ListOptions{})
		if err != nil {
			return nil, fmt.Errorf("list deployments: %v", err)
		}
		for _, deployment := range deployments.Items {
			addWorkloadResult(&results, opts, selector, query, "Deployment", deployment.Namespace, deployment.Name, deployment.Labels, deployment.Spec.Template.Labels, metav1.FormatLabelSelector(deployment.Spec.Selector))
		}
	}
	if kind == "" || kind == "statefulset" {
		statefulSets, err := client.Core.AppsV1().StatefulSets(namespace).List(ctx, metav1.ListOptions{})
		if err != nil {
			return nil, fmt.Errorf("list statefulsets: %v", err)
		}
		for _, statefulSet := range statefulSets.Items {
			addWorkloadResult(&results, opts, selector, query, "StatefulSet", statefulSet.Namespace, statefulSet.Name, statefulSet.Labels, statefulSet.Spec.Template.Labels, metav1.FormatLabelSelector(statefulSet.Spec.Selector))
		}
	}
	if kind == "" || kind == "daemonset" {
		daemonSets, err := client.Core.AppsV1().DaemonSets(namespace).List(ctx, metav1.ListOptions{})
		if err != nil {
			return nil, fmt.Errorf("list daemonsets: %v", err)
		}
		for _, daemonSet := range daemonSets.Items {
			addWorkloadResult(&results, opts, selector, query, "DaemonSet", daemonSet.Namespace, daemonSet.Name, daemonSet.Labels, daemonSet.Spec.Template.Labels, metav1.FormatLabelSelector(daemonSet.Spec.Selector))
		}
	}
	if kind == "" || kind == "replicaset" {
		replicaSets, err := client.Core.AppsV1().ReplicaSets(namespace).List(ctx, metav1.ListOptions{})
		if err != nil {
			return nil, fmt.Errorf("list replicasets: %v", err)
		}
		for _, replicaSet := range replicaSets.Items {
			addWorkloadResult(&results, opts, selector, query, "ReplicaSet", replicaSet.Namespace, replicaSet.Name, replicaSet.Labels, replicaSet.Spec.Template.Labels, metav1.FormatLabelSelector(replicaSet.Spec.Selector))
		}
	}
	if kind == "" || kind == "ingress" {
		ingresses, err := client.Core.NetworkingV1().Ingresses(namespace).List(ctx, metav1.ListOptions{})
		if err == nil {
			for _, ingress := range ingresses.Items {
				addIngressResult(&results, opts, selector, query, ingress)
			}
		}
	}
	if kind == "" || kind == "networkpolicy" {
		policies, err := client.Core.NetworkingV1().NetworkPolicies(namespace).List(ctx, metav1.ListOptions{})
		if err == nil {
			for _, policy := range policies.Items {
				addNetworkPolicyResult(&results, opts, selector, query, policy)
			}
		}
	}

	sort.Slice(results, func(i, j int) bool {
		if results[i].Namespace != results[j].Namespace {
			return results[i].Namespace < results[j].Namespace
		}
		if results[i].Kind != results[j].Kind {
			return results[i].Kind < results[j].Kind
		}
		return results[i].Name < results[j].Name
	})
	return results, nil
}

func addWorkloadResult(results *[]DiscoverResult, opts DiscoverOptions, selector labels.Selector, query, kind, namespace, name string, objectLabels, templateLabels map[string]string, podSelector string) {
	if !objectFilterMatch(opts, selector, name, mergeMaps(objectLabels, templateLabels), "", "") {
		return
	}
	match, ok := discoverMatch(query, name, objectLabels, templateLabels)
	if !ok && strings.Contains(strings.ToLower(podSelector), query) {
		match, ok = "selector", true
	}
	if !ok {
		return
	}
	*results = append(*results, DiscoverResult{
		Kind:      kind,
		Namespace: namespace,
		Name:      name,
		Match:     match,
		Hint:      fmt.Sprintf("source=%s selector=%s", name, podSelector),
	})
}

func addIngressResult(results *[]DiscoverResult, opts DiscoverOptions, selector labels.Selector, query string, ingress networkingv1.Ingress) {
	if !objectFilterMatch(opts, selector, ingress.Name, ingress.Labels, "", "") {
		return
	}
	var tokens []string
	for _, rule := range ingress.Spec.Rules {
		tokens = append(tokens, rule.Host)
		if rule.HTTP != nil {
			for _, path := range rule.HTTP.Paths {
				tokens = append(tokens, path.Path, path.Backend.Service.Name)
			}
		}
	}
	if ingress.Spec.DefaultBackend != nil && ingress.Spec.DefaultBackend.Service != nil {
		tokens = append(tokens, ingress.Spec.DefaultBackend.Service.Name)
	}
	match, ok := discoverMatch(query, ingress.Name, ingress.Labels, nil)
	if !ok && containsAny(tokens, query) {
		match, ok = "route/backend", true
	}
	if !ok {
		return
	}
	*results = append(*results, DiscoverResult{Kind: "Ingress", Namespace: ingress.Namespace, Name: ingress.Name, Match: match, Hint: "check ingress"})
}

func addNetworkPolicyResult(results *[]DiscoverResult, opts DiscoverOptions, selector labels.Selector, query string, policy networkingv1.NetworkPolicy) {
	if !objectFilterMatch(opts, selector, policy.Name, policy.Labels, "", "") {
		return
	}
	podSelector := metav1.FormatLabelSelector(&policy.Spec.PodSelector)
	match, ok := discoverMatch(query, policy.Name, policy.Labels, nil)
	if !ok && strings.Contains(strings.ToLower(podSelector), query) {
		match, ok = "podSelector", true
	}
	if !ok {
		return
	}
	*results = append(*results, DiscoverResult{Kind: "NetworkPolicy", Namespace: policy.Namespace, Name: policy.Name, Match: match, Hint: "podSelector=" + podSelector})
}

func objectFilterMatch(opts DiscoverOptions, selector labels.Selector, name string, objectLabels map[string]string, serviceAccount string, node string) bool {
	if opts.ExactName != "" && name != opts.ExactName {
		return false
	}
	for key, value := range opts.Labels {
		if objectLabels[key] != value {
			return false
		}
	}
	if selector != nil && !selector.Matches(labels.Set(objectLabels)) {
		return false
	}
	if opts.ServiceAccount != "" && serviceAccount != opts.ServiceAccount {
		return false
	}
	if opts.Node != "" && node != opts.Node {
		return false
	}
	return true
}

func discoverMatch(query string, name string, objectLabels map[string]string, extra map[string]string) (string, bool) {
	if query == "" {
		return "filter", true
	}
	if strings.Contains(strings.ToLower(name), query) {
		return "name", true
	}
	if labelsContain(objectLabels, query) {
		return "labels", true
	}
	if labelsContain(extra, query) {
		return "selector/template", true
	}
	return "", false
}

func labelsContain(values map[string]string, query string) bool {
	for key, value := range values {
		if strings.Contains(strings.ToLower(key), query) || strings.Contains(strings.ToLower(value), query) {
			return true
		}
	}
	return false
}

func containsAny(values []string, query string) bool {
	for _, value := range values {
		if strings.Contains(strings.ToLower(value), query) {
			return true
		}
	}
	return false
}

func parseOptionalSelector(raw string) (labels.Selector, error) {
	if strings.TrimSpace(raw) == "" {
		return nil, nil
	}
	return labels.Parse(raw)
}

func normalizeKind(kind string) string {
	switch strings.ToLower(strings.TrimSpace(kind)) {
	case "", "all":
		return ""
	case "po", "pods":
		return "pod"
	case "svc", "services":
		return "service"
	case "deploy", "deployments":
		return "deployment"
	case "sts", "statefulsets":
		return "statefulset"
	case "ds", "daemonsets":
		return "daemonset"
	case "rs", "replicasets":
		return "replicaset"
	case "ing", "ingresses":
		return "ingress"
	case "netpol", "networkpolicies":
		return "networkpolicy"
	default:
		return strings.ToLower(strings.TrimSpace(kind))
	}
}

func mergeMaps(first map[string]string, second map[string]string) map[string]string {
	out := map[string]string{}
	for key, value := range first {
		out[key] = value
	}
	for key, value := range second {
		out[key] = value
	}
	return out
}
