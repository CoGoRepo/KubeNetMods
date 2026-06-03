package check

import (
	"context"
	"fmt"
	"strings"

	"github.com/CoGoRepo/KubeNetMods/internal/kube"
	"github.com/CoGoRepo/KubeNetMods/internal/model"
	networkingv1 "istio.io/client-go/pkg/apis/networking/v1"
	securityv1 "istio.io/client-go/pkg/apis/security/v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
)

func istioConfigNamespaces(opts ServiceOptions, source *ExecTarget) []string {
	namespaces := []string{opts.Namespace}
	if opts.SourceNamespace != "" {
		namespaces = append(namespaces, opts.SourceNamespace)
	}
	if source != nil {
		namespaces = append(namespaces, source.Pod.Namespace)
	}
	return uniqueStrings(namespaces)
}

func istioTargetPolicyNamespaces(ctx context.Context, client *kube.Client, namespace string) []string {
	namespaces := []string{namespace}
	if root := istioRootNamespace(ctx, client); root != "" {
		namespaces = append(namespaces, root)
	}
	return uniqueStrings(namespaces)
}

func listIstioVirtualServices(ctx context.Context, client *kube.Client, namespaces []string) ([]*networkingv1.VirtualService, error) {
	var out []*networkingv1.VirtualService
	for _, namespace := range namespaces {
		items, err := client.Istio.NetworkingV1().VirtualServices(namespace).List(ctx, metav1.ListOptions{})
		if err != nil {
			return nil, err
		}
		out = append(out, items.Items...)
	}
	return out, nil
}

func listIstioDestinationRules(ctx context.Context, client *kube.Client, namespaces []string) ([]*networkingv1.DestinationRule, error) {
	var out []*networkingv1.DestinationRule
	for _, namespace := range namespaces {
		items, err := client.Istio.NetworkingV1().DestinationRules(namespace).List(ctx, metav1.ListOptions{})
		if err != nil {
			return nil, err
		}
		out = append(out, items.Items...)
	}
	return out, nil
}

func istioServicePathVirtualServices(items []*networkingv1.VirtualService, opts ServiceOptions, source *ExecTarget) []*networkingv1.VirtualService {
	consumerNamespace := istioServicePathConsumerNamespace(opts, source)
	var out []*networkingv1.VirtualService
	for _, item := range items {
		if item == nil ||
			!istioVirtualServiceAppliesToMesh(item) ||
			!istioExportToVisible(item.Spec.GetExportTo(), item.Namespace, consumerNamespace) {
			continue
		}
		out = append(out, item)
	}
	return out
}

func istioServicePathDestinationRules(items []*networkingv1.DestinationRule, opts ServiceOptions, source *ExecTarget) []*networkingv1.DestinationRule {
	consumerNamespace := istioServicePathConsumerNamespace(opts, source)
	var out []*networkingv1.DestinationRule
	for _, item := range items {
		if item == nil || !istioExportToVisible(item.Spec.GetExportTo(), item.Namespace, consumerNamespace) {
			continue
		}
		out = append(out, item)
	}
	return out
}

func istioServicePathConsumerNamespace(opts ServiceOptions, source *ExecTarget) string {
	if source != nil && source.Pod.Namespace != "" {
		return source.Pod.Namespace
	}
	if opts.SourceNamespace != "" {
		return opts.SourceNamespace
	}
	return opts.Namespace
}

func istioVirtualServiceAppliesToMesh(item *networkingv1.VirtualService) bool {
	gateways := item.Spec.GetGateways()
	if len(gateways) == 0 {
		return true
	}
	for _, gateway := range gateways {
		if strings.EqualFold(strings.TrimSpace(gateway), "mesh") {
			return true
		}
	}
	return false
}

func istioExportToVisible(exportTo []string, configNamespace string, consumerNamespace string) bool {
	if consumerNamespace == "" || len(exportTo) == 0 {
		return true
	}
	configNamespace = strings.ToLower(strings.TrimSpace(configNamespace))
	consumerNamespace = strings.ToLower(strings.TrimSpace(consumerNamespace))
	for _, raw := range exportTo {
		value := strings.ToLower(strings.TrimSpace(raw))
		switch value {
		case "*":
			return true
		case ".":
			if consumerNamespace == configNamespace {
				return true
			}
		default:
			if value == consumerNamespace {
				return true
			}
		}
	}
	return false
}

func listIstioAuthorizationPolicies(ctx context.Context, client *kube.Client, namespaces []string) ([]*securityv1.AuthorizationPolicy, error) {
	var out []*securityv1.AuthorizationPolicy
	var listErr error
	for index, namespace := range namespaces {
		items, err := client.Istio.SecurityV1().AuthorizationPolicies(namespace).List(ctx, metav1.ListOptions{})
		if err != nil {
			if apierrors.IsNotFound(err) {
				continue
			}
			if index == 0 {
				return nil, err
			}
			if listErr == nil {
				listErr = err
			}
			continue
		}
		out = append(out, items.Items...)
	}
	return out, listErr
}

func listIstioRequestAuthentications(ctx context.Context, client *kube.Client, namespaces []string) ([]*securityv1.RequestAuthentication, error) {
	var out []*securityv1.RequestAuthentication
	var listErr error
	for index, namespace := range namespaces {
		items, err := client.Istio.SecurityV1().RequestAuthentications(namespace).List(ctx, metav1.ListOptions{})
		if err != nil {
			if apierrors.IsNotFound(err) {
				continue
			}
			if index == 0 {
				return nil, err
			}
			if listErr == nil {
				listErr = err
			}
			continue
		}
		out = append(out, items.Items...)
	}
	return out, listErr
}

func addIstioListWarning(report *model.Report, layer string, check string, err error) {
	if apierrors.IsNotFound(err) {
		return
	}
	report.Add(layer, check, model.StatusWarn, fmt.Sprintf("Could not inspect Istio %s: %v", check, err))
}
