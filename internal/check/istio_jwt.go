package check

import (
	"context"
	"fmt"
	"sort"
	"strings"

	"github.com/CoGoRepo/KubeNetMods/internal/kube"
	"github.com/CoGoRepo/KubeNetMods/internal/model"
	securityv1 "istio.io/client-go/pkg/apis/security/v1"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
)

func inspectIstioRequestAuthentication(ctx context.Context, client *kube.Client, report *model.Report, service *corev1.Service, targetPods []corev1.Pod, status model.Status) bool {
	if client.Istio == nil || service == nil {
		return false
	}
	items, err := client.Istio.SecurityV1().RequestAuthentications(service.Namespace).List(ctx, metav1.ListOptions{})
	if err != nil {
		addIstioListWarning(report, "Istio JWT Layer", "request authentications", err)
		return false
	}
	var matches []string
	for _, item := range items.Items {
		if requestAuthenticationSelectsTarget(item, service, targetPods) {
			matches = append(matches, requestAuthenticationSummary(item))
		}
	}
	if len(matches) == 0 {
		return false
	}
	sort.Strings(matches)
	text := strings.Join(matches, ", ")
	report.Add("Istio JWT Layer", "request authentication", status, fmt.Sprintf("Target workload for Service %q is selected by Istio RequestAuthentication object(s): %s. KubeNetMods does not validate JWT tokens.", service.Name, text))
	report.Diagnose(fmt.Sprintf("Primary issue candidate: target workload for Service %q is selected by Istio RequestAuthentication object(s) %s. Check JWT issuer/audience/token and any AuthorizationPolicy request.auth/requestPrincipals requirements; KubeNetMods does not validate JWT tokens.", serviceName(service), text))
	return true
}

func requestAuthenticationSelectsTarget(item *securityv1.RequestAuthentication, service *corev1.Service, pods []corev1.Pod) bool {
	if item == nil {
		return false
	}
	if len(item.Spec.GetTargetRefs()) > 0 {
		return targetRefsContainService(item.Spec.GetTargetRefs(), service, item.Namespace)
	}
	if item.Spec.GetTargetRef() != nil {
		return targetRefMatchesService(item.Spec.GetTargetRef(), service, item.Namespace)
	}
	return istioWorkloadSelectorMatchesAny(item.Spec.GetSelector(), pods)
}

func requestAuthenticationSummary(item *securityv1.RequestAuthentication) string {
	name := item.Namespace + "/" + item.Name
	var issuers []string
	for _, rule := range item.Spec.GetJwtRules() {
		if rule.GetIssuer() != "" {
			issuers = append(issuers, rule.GetIssuer())
		}
	}
	sort.Strings(issuers)
	if len(issuers) == 0 {
		return name
	}
	return fmt.Sprintf("%s issuer(s) %s", name, strings.Join(issuers, "|"))
}
