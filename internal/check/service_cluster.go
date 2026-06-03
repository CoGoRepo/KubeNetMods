package check

import (
	"context"
	"fmt"
	"strings"
	"time"

	"github.com/CoGoRepo/KubeNetMods/internal/kube"
	"github.com/CoGoRepo/KubeNetMods/internal/model"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
)

func checkCluster(ctx context.Context, client *kube.Client, report *model.Report, opts ServiceOptions) {
	layer := "Cluster Access"
	if _, err := client.Core.CoreV1().Namespaces().Get(ctx, opts.Namespace, metav1.GetOptions{}); err != nil {
		report.Add(layer, "target namespace", model.StatusFail, fmt.Sprintf("Target namespace %q is not accessible: %v", opts.Namespace, err))
		report.Diagnose(fmt.Sprintf("Cannot access target namespace %q. Fix kubeconfig/RBAC/namespace before debugging networking.", opts.Namespace))
	} else {
		report.Add(layer, "target namespace", model.StatusPass, fmt.Sprintf("Target namespace %q exists.", opts.Namespace))
	}
	if opts.SourceNamespace != opts.Namespace || opts.SourceContext != "" {
		sourceClient := client
		if opts.SourceContext != "" && opts.SourceContext != opts.Context {
			other, err := kube.New(opts.SourceContext)
			if err != nil {
				report.Add(layer, "source context", model.StatusFail, fmt.Sprintf("Source context %q is not usable: %v", opts.SourceContext, err))
				return
			}
			sourceClient = other
		}
		if _, err := sourceClient.Core.CoreV1().Namespaces().Get(ctx, opts.SourceNamespace, metav1.GetOptions{}); err != nil {
			report.Add(layer, "source namespace", model.StatusFail, fmt.Sprintf("Source namespace %q is not accessible: %v", opts.SourceNamespace, err))
		} else {
			report.Add(layer, "source namespace", model.StatusPass, fmt.Sprintf("Source namespace %q exists.", opts.SourceNamespace))
		}
	}

	layer = "Cluster Health"
	nodes, err := client.Core.CoreV1().Nodes().List(ctx, metav1.ListOptions{})
	if err != nil {
		report.Add(layer, "nodes", model.StatusWarn, fmt.Sprintf("Could not inspect nodes: %v", err))
	} else {
		ready := 0
		var problems []string
		for _, node := range nodes.Items {
			for _, condition := range node.Status.Conditions {
				if condition.Type == corev1.NodeReady && condition.Status == corev1.ConditionTrue {
					ready++
				}
				if condition.Status == corev1.ConditionTrue && (condition.Type == corev1.NodeNetworkUnavailable || condition.Type == corev1.NodeMemoryPressure || condition.Type == corev1.NodeDiskPressure || condition.Type == corev1.NodePIDPressure) {
					problems = append(problems, fmt.Sprintf("%s:%s=%s", node.Name, condition.Type, condition.Reason))
				}
			}
		}
		if len(nodes.Items) == 0 {
			report.Add(layer, "node readiness", model.StatusWarn, "No nodes were returned. RBAC may block node reads.")
		} else if ready == len(nodes.Items) {
			report.Add(layer, "node readiness", model.StatusPass, fmt.Sprintf("%d/%d node(s) are Ready.", ready, len(nodes.Items)))
		} else {
			report.Add(layer, "node readiness", model.StatusFail, fmt.Sprintf("%d/%d node(s) are Ready.", ready, len(nodes.Items)))
			report.Diagnose("Some nodes are not Ready. Fix node health before chasing service-level networking.")
		}
		if len(problems) > 0 {
			report.Add(layer, "node conditions", model.StatusWarn, "Node pressure/network conditions detected: "+strings.Join(problems, "; "))
		} else {
			report.Add(layer, "node conditions", model.StatusPass, "No NetworkUnavailable/pressure node conditions detected.")
		}
	}

	pods, err := client.Core.CoreV1().Pods("kube-system").List(ctx, metav1.ListOptions{})
	if err != nil {
		report.Add(layer, "kube-system add-ons", model.StatusWarn, fmt.Sprintf("Could not inspect kube-system add-ons: %v", err))
		return
	}
	reportAddonHealth(report, "CNI add-ons", pods.Items, func(name string, labels map[string]string) bool {
		n := strings.ToLower(name)
		return strings.Contains(n, "calico") || strings.Contains(n, "cilium") || strings.Contains(n, "flannel") || strings.Contains(n, "kindnet") || strings.Contains(n, "antrea") || strings.Contains(n, "aws-node")
	})
	reportAddonHealth(report, "CoreDNS", pods.Items, func(name string, labels map[string]string) bool {
		n := strings.ToLower(name)
		return strings.Contains(n, "coredns") || strings.Contains(n, "kube-dns") || strings.Contains(n, "node-local-dns") || strings.Contains(n, "nodelocaldns")
	})
}

func reportAddonHealth(report *model.Report, name string, pods []corev1.Pod, match func(string, map[string]string) bool) {
	var selected []corev1.Pod
	for _, pod := range pods {
		if match(pod.Name, pod.Labels) {
			selected = append(selected, pod)
		}
	}
	if len(selected) == 0 {
		report.Add("Cluster Health", name, model.StatusInfo, fmt.Sprintf("No obvious %s pod found in kube-system.", name))
		return
	}
	ready := 0
	for _, pod := range selected {
		if podReady(pod) {
			ready++
		}
	}
	if ready == len(selected) {
		report.Add("Cluster Health", name, model.StatusPass, fmt.Sprintf("%d/%d %s pod(s) are Ready.", ready, len(selected), name))
	} else {
		report.Add("Cluster Health", name, model.StatusWarn, fmt.Sprintf("%d/%d %s pod(s) are Ready.", ready, len(selected), name))
	}
}

func checkEvents(ctx context.Context, client *kube.Client, report *model.Report, opts ServiceOptions) {
	namespaces := uniqueStrings([]string{opts.Namespace, opts.SourceNamespace})
	for _, namespace := range namespaces {
		if namespace == "" {
			continue
		}
		events, err := client.Core.CoreV1().Events(namespace).List(ctx, metav1.ListOptions{})
		if err != nil {
			report.Add("Events Layer", namespace+" warnings", model.StatusWarn, fmt.Sprintf("Could not inspect events in namespace %q: %v", namespace, err))
			continue
		}
		var warnings []string
		cutoff := time.Now().Add(-30 * time.Minute)
		for _, event := range events.Items {
			if event.Type != corev1.EventTypeWarning {
				continue
			}
			eventTime := event.LastTimestamp.Time
			if eventTime.IsZero() {
				eventTime = event.EventTime.Time
			}
			if !eventTime.IsZero() && eventTime.Before(cutoff) {
				continue
			}
			warnings = append(warnings, fmt.Sprintf("%s/%s: %s", event.InvolvedObject.Kind, event.InvolvedObject.Name, event.Reason))
		}
		if len(warnings) == 0 {
			report.Add("Events Layer", namespace+" warnings", model.StatusPass, fmt.Sprintf("No recent Warning events found in namespace %q.", namespace))
		} else {
			if len(warnings) > 8 {
				warnings = append(warnings[:8], fmt.Sprintf("... +%d more", len(warnings)-8))
			}
			report.Add("Events Layer", namespace+" warnings", model.StatusWarn, fmt.Sprintf("Recent Warning events in %q: %s", namespace, strings.Join(warnings, "; ")))
		}
	}
}
