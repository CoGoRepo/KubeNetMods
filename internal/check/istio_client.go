package check

import (
	"context"
	"fmt"

	"github.com/CoGoRepo/KubeNetMods/internal/kube"
	"github.com/CoGoRepo/KubeNetMods/internal/model"
	networkingv1 "istio.io/client-go/pkg/apis/networking/v1"
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

func addIstioListWarning(report *model.Report, layer string, check string, err error) {
	if apierrors.IsNotFound(err) {
		return
	}
	report.Add(layer, check, model.StatusWarn, fmt.Sprintf("Could not inspect Istio %s: %v", check, err))
}
