package check

import (
	"context"
	"fmt"

	"github.com/CoGoRepo/KubeNetMods/internal/kube"
	"github.com/CoGoRepo/KubeNetMods/internal/model"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
)

func checkNodePortAndHost(ctx context.Context, client *kube.Client, report *model.Report, opts ServiceOptions, service *corev1.Service) {
	layer := "NodePort And Host Layer"
	if opts.SkipNodePort {
		report.Add(layer, "nodeport", model.StatusSkip, "Skipped by --skip-nodeport.")
		return
	}
	if service == nil {
		report.Add(layer, "nodeport", model.StatusSkip, "Skipped because the Service was not readable.")
		return
	}
	if service.Spec.Type != corev1.ServiceTypeNodePort && service.Spec.Type != corev1.ServiceTypeLoadBalancer {
		report.Add(layer, "nodeport", model.StatusSkip, "Service type is not NodePort/LoadBalancer.")
		return
	}
	selected, ok := selectServicePort(service, report.Target.ServicePort)
	if !ok {
		report.Add(layer, "nodeport", model.StatusSkip, "Skipped because the selected Service port was not found.")
		return
	}
	if selected.Protocol != "" && selected.Protocol != corev1.ProtocolTCP {
		report.Add(layer, "nodeport", model.StatusSkip, fmt.Sprintf("Skipped HTTP NodePort checks because selected Service port %d uses %s, not TCP.", selected.Port, selected.Protocol))
		return
	}
	var nodePorts []int32
	if selected.NodePort > 0 {
		nodePorts = append(nodePorts, selected.NodePort)
	}
	if len(nodePorts) == 0 {
		report.Add(layer, "nodeport", model.StatusSkip, "No nodePort value was found for the selected Service port.")
		return
	}
	nodes, err := client.Core.CoreV1().Nodes().List(ctx, metav1.ListOptions{})
	if err != nil {
		report.Add(layer, "nodes", model.StatusWarn, fmt.Sprintf("Could not list nodes for NodePort checks: %v", err))
		return
	}
	for _, node := range nodes.Items {
		address := nodeAddress(node)
		if address == "" {
			continue
		}
		for _, port := range nodePorts {
			rawURL := fmt.Sprintf("%s://%s:%d%s", opts.URLScheme, address, port, normalizedPath(opts.URLPath))
			test := testLocalHTTP(rawURL, opts.Timeout)
			if test.OK {
				report.Add(layer, rawURL, model.StatusPass, fmt.Sprintf("Local host reached NodePort. HTTP status: %s", test.Status))
			} else {
				report.Add(layer, rawURL, model.StatusFail, "Local host could not reach NodePort: "+test.Error)
				report.Diagnose("Host-to-NodePort reachability failed. Check node address routing, firewall/security groups, Docker Desktop/WSL routing, kube-proxy/CNI service routing, or Service backends.")
			}
		}
	}
}

func nodeAddress(node corev1.Node) string {
	var internal, external, hostname string
	for _, address := range node.Status.Addresses {
		switch address.Type {
		case corev1.NodeExternalIP:
			external = address.Address
		case corev1.NodeInternalIP:
			internal = address.Address
		case corev1.NodeHostName:
			hostname = address.Address
		}
	}
	if external != "" {
		return external
	}
	if internal != "" {
		return internal
	}
	return hostname
}
