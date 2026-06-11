package check

import (
	"context"
	"fmt"
	"sort"
	"strings"
	"time"

	"github.com/CoGoRepo/KubeNetMods/internal/kube"
	appsv1 "k8s.io/api/apps/v1"
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
	Group     string
}

type DiscoverGroup struct {
	Namespace string
	Name      string
	Kinds     []string
	Hint      string
}

func RunDiscover(ctx context.Context, opts DiscoverOptions) ([]DiscoverResult, error) {
	client, err := kube.New(opts.Context)
	if err != nil {
		return nil, err
	}
	query := normalizeDiscoverQuery(opts.Query)
	kind := normalizeKind(opts.Kind)
	selector, err := parseOptionalSelector(opts.LabelSelector)
	if err != nil {
		return nil, err
	}
	namespace := opts.Namespace
	if namespace == "" {
		namespace = metav1.NamespaceAll
	}
	replicaSets, rsToDeployment, _ := discoverReplicaSetOwners(ctx, client, namespace)
	deployments, deploymentSelectors, _ := discoverDeployments(ctx, client, namespace)

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
					Group:     discoverPodGroup(pod.Namespace, pod.Name, pod.Labels, pod.OwnerReferences, rsToDeployment),
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
					Group:     discoverServiceGroup(service.Name, service.Namespace, service.Spec.Selector, deploymentSelectors, kind),
				})
			}
		}
	}
	if kind == "" || kind == "deployment" {
		if deployments == nil {
			return nil, fmt.Errorf("list deployments: unavailable")
		}
		for _, deployment := range deployments {
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
		if replicaSets == nil {
			return nil, fmt.Errorf("list replicasets: unavailable")
		}
		for _, replicaSet := range replicaSets {
			group := replicaSet.Name
			if owner := rsToDeployment[replicaSet.Namespace+"/"+replicaSet.Name]; owner != "" {
				group = owner
			}
			addWorkloadResultWithGroup(&results, opts, selector, query, "ReplicaSet", replicaSet.Namespace, replicaSet.Name, replicaSet.Labels, replicaSet.Spec.Template.Labels, metav1.FormatLabelSelector(replicaSet.Spec.Selector), group)
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

func discoverDeployments(ctx context.Context, client *kube.Client, namespace string) ([]appsv1.Deployment, map[string]string, error) {
	list, err := client.Core.AppsV1().Deployments(namespace).List(ctx, metav1.ListOptions{})
	if err != nil {
		return nil, nil, err
	}
	selectorToDeployment := map[string]string{}
	for _, deployment := range list.Items {
		selectorText := metav1.FormatLabelSelector(deployment.Spec.Selector)
		if selectorText != "" {
			selectorToDeployment[deployment.Namespace+"/"+selectorText] = deployment.Name
		}
	}
	return list.Items, selectorToDeployment, nil
}

func discoverReplicaSetOwners(ctx context.Context, client *kube.Client, namespace string) ([]appsv1.ReplicaSet, map[string]string, error) {
	list, err := client.Core.AppsV1().ReplicaSets(namespace).List(ctx, metav1.ListOptions{})
	if err != nil {
		return nil, nil, err
	}
	rsToDeployment := map[string]string{}
	for _, replicaSet := range list.Items {
		for _, owner := range replicaSet.OwnerReferences {
			if owner.Kind == "Deployment" && owner.Name != "" {
				rsToDeployment[replicaSet.Namespace+"/"+replicaSet.Name] = owner.Name
			}
		}
	}
	return list.Items, rsToDeployment, nil
}

func CompactDiscoverResults(results []DiscoverResult) []DiscoverGroup {
	byKey := map[string]*DiscoverGroup{}
	kindOrder := map[string]int{
		"Deployment":    1,
		"StatefulSet":   2,
		"DaemonSet":     3,
		"Service":       4,
		"Pod":           5,
		"ReplicaSet":    6,
		"Ingress":       7,
		"NetworkPolicy": 8,
	}
	for _, result := range results {
		name := result.Group
		if name == "" {
			name = result.Name
		}
		key := result.Namespace + "/" + name
		group := byKey[key]
		if group == nil {
			group = &DiscoverGroup{Namespace: result.Namespace, Name: name}
			byKey[key] = group
		}
		if !containsString(group.Kinds, kindAbbrev(result.Kind)) {
			group.Kinds = append(group.Kinds, kindAbbrev(result.Kind))
		}
		if group.Hint == "" || betterDiscoverHint(result.Hint, group.Hint) {
			group.Hint = result.Hint
		}
		sort.SliceStable(group.Kinds, func(i, j int) bool {
			return kindOrder[expandKindAbbrev(group.Kinds[i])] < kindOrder[expandKindAbbrev(group.Kinds[j])]
		})
	}
	var groups []DiscoverGroup
	for _, group := range byKey {
		groups = append(groups, *group)
	}
	sort.Slice(groups, func(i, j int) bool {
		if groups[i].Namespace != groups[j].Namespace {
			return groups[i].Namespace < groups[j].Namespace
		}
		return groups[i].Name < groups[j].Name
	})
	return groups
}

func addWorkloadResult(results *[]DiscoverResult, opts DiscoverOptions, selector labels.Selector, query, kind, namespace, name string, objectLabels, templateLabels map[string]string, podSelector string) {
	addWorkloadResultWithGroup(results, opts, selector, query, kind, namespace, name, objectLabels, templateLabels, podSelector, name)
}

func addWorkloadResultWithGroup(results *[]DiscoverResult, opts DiscoverOptions, selector labels.Selector, query, kind, namespace, name string, objectLabels, templateLabels map[string]string, podSelector string, group string) {
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
		Group:     group,
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
	*results = append(*results, DiscoverResult{Kind: "Ingress", Namespace: ingress.Namespace, Name: ingress.Name, Match: match, Hint: "legacy Ingress object", Group: ingress.Name})
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
	*results = append(*results, DiscoverResult{Kind: "NetworkPolicy", Namespace: policy.Namespace, Name: policy.Name, Match: match, Hint: "podSelector=" + podSelector, Group: policy.Name})
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
	if discoverAll(query) {
		return "all", true
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

func normalizeDiscoverQuery(query string) string {
	return strings.ToLower(strings.TrimSpace(query))
}

func DiscoverAllQuery(query string) bool {
	return discoverAll(normalizeDiscoverQuery(query))
}

func discoverAll(query string) bool {
	return query == "*"
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

func containsString(values []string, target string) bool {
	for _, value := range values {
		if value == target {
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

func discoverPodGroup(namespace string, name string, podLabels map[string]string, owners []metav1.OwnerReference, rsToDeployment map[string]string) string {
	for _, owner := range owners {
		if owner.Kind == "ReplicaSet" && owner.Name != "" {
			if deployment := rsToDeployment[namespace+"/"+owner.Name]; deployment != "" {
				return deployment
			}
			return owner.Name
		}
		if owner.Kind == "Node" {
			return name
		}
		if owner.Kind != "" && owner.Name != "" {
			return owner.Name
		}
	}
	if app := podLabels["app.kubernetes.io/name"]; app != "" {
		return app
	}
	if app := podLabels["app"]; app != "" {
		return app
	}
	return name
}

func discoverServiceGroup(name string, namespace string, selectorMap map[string]string, deploymentSelectors map[string]string, kindFilter string) string {
	if kindFilter == "service" {
		return name
	}
	selectorText := labels.SelectorFromSet(labels.Set(selectorMap)).String()
	if selectorText == "" {
		return name
	}
	if deployment := deploymentSelectors[namespace+"/"+selectorText]; deployment != "" {
		return deployment
	}
	return name
}

func kindAbbrev(kind string) string {
	switch kind {
	case "Deployment":
		return "deploy"
	case "StatefulSet":
		return "sts"
	case "DaemonSet":
		return "ds"
	case "ReplicaSet":
		return "rs"
	case "Service":
		return "svc"
	case "Pod":
		return "pod"
	case "Ingress":
		return "ing"
	case "NetworkPolicy":
		return "netpol"
	default:
		return strings.ToLower(kind)
	}
}

func expandKindAbbrev(kind string) string {
	switch kind {
	case "deploy":
		return "Deployment"
	case "sts":
		return "StatefulSet"
	case "ds":
		return "DaemonSet"
	case "rs":
		return "ReplicaSet"
	case "svc":
		return "Service"
	case "pod":
		return "Pod"
	case "ing":
		return "Ingress"
	case "netpol":
		return "NetworkPolicy"
	default:
		return kind
	}
}

func betterDiscoverHint(candidate string, current string) bool {
	score := func(value string) int {
		switch {
		case strings.HasPrefix(value, "target="):
			return 4
		case strings.HasPrefix(value, "source="):
			return 3
		case strings.HasPrefix(value, "source-pod="):
			return 2
		default:
			return 1
		}
	}
	return score(candidate) > score(current)
}
