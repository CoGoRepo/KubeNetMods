package check

import (
	"context"
	"fmt"
	"strings"

	"github.com/CoGoRepo/KubeNetMods/internal/kube"
	"github.com/CoGoRepo/KubeNetMods/internal/model"
	corev1 "k8s.io/api/core/v1"
)

type istioRuntimeSignal string

const (
	istioSignalNone              istioRuntimeSignal = ""
	istioSignalRBACDenied        istioRuntimeSignal = "rbac-denied"
	istioSignalJWTDenied         istioRuntimeSignal = "jwt-denied"
	istioSignalNoHealthyUpstream istioRuntimeSignal = "no-healthy-upstream"
	istioSignalUpstreamReset     istioRuntimeSignal = "upstream-reset"
)

func classifyIstioRuntime(result RuntimeHTTPResult, source *ExecTarget, targetPods []corev1.Pod) istioRuntimeSignal {
	text := strings.ToLower(result.Output + " " + result.Error)
	envoy := strings.Contains(text, "server: envoy") || strings.Contains(text, "x-envoy-") || pathHasIstioSidecar(source, targetPods)
	switch {
	case result.StatusCode == "401" && envoy && (strings.Contains(text, "jwt") || strings.Contains(text, "unauthorized")):
		return istioSignalJWTDenied
	case result.StatusCode == "403" && envoy && strings.Contains(text, "rbac: access denied"):
		return istioSignalRBACDenied
	case result.StatusCode == "503" && envoy && strings.Contains(text, "no healthy upstream"):
		return istioSignalNoHealthyUpstream
	case result.StatusCode == "503" && envoy && (strings.Contains(text, "upstream connect error") || strings.Contains(text, "reset before headers") || strings.Contains(text, "connection termination")):
		return istioSignalUpstreamReset
	default:
		return istioSignalNone
	}
}

func pathHasIstioSidecar(source *ExecTarget, targetPods []corev1.Pod) bool {
	if source != nil && podHasIstioSidecar(source.Pod) {
		return true
	}
	for _, pod := range targetPods {
		if podHasIstioSidecar(pod) {
			return true
		}
	}
	return false
}

func podHasIstioSidecar(pod corev1.Pod) bool {
	if _, ok := pod.Annotations["sidecar.istio.io/status"]; ok {
		return true
	}
	for _, container := range pod.Spec.Containers {
		if container.Name == "istio-proxy" {
			return true
		}
	}
	return false
}

func istioRuntimeMessage(source ExecTarget, rawURL string, result RuntimeHTTPResult, signal istioRuntimeSignal) string {
	switch signal {
	case istioSignalRBACDenied:
		return fmt.Sprintf("%s %q reached %s, but Envoy returned HTTP 403 RBAC: access denied.", source.Kind, source.Pod.Name, rawURL)
	case istioSignalJWTDenied:
		return fmt.Sprintf("%s %q reached %s, but Envoy returned HTTP 401 unauthorized.", source.Kind, source.Pod.Name, rawURL)
	case istioSignalNoHealthyUpstream:
		return fmt.Sprintf("%s %q reached %s, but Envoy returned HTTP 503: no healthy upstream.", source.Kind, source.Pod.Name, rawURL)
	case istioSignalUpstreamReset:
		return fmt.Sprintf("%s %q reached %s, but Envoy returned HTTP 503 upstream connect/reset before headers.", source.Kind, source.Pod.Name, rawURL)
	default:
		return fmt.Sprintf("%s %q reached %s. HTTP status: %s", source.Kind, source.Pod.Name, rawURL, result.StatusCode)
	}
}

func inspectIstioRuntimeSignal(ctx context.Context, client *kube.Client, report *model.Report, opts ServiceOptions, service *corev1.Service, targetPods []corev1.Pod, source *ExecTarget, rawURL string, result RuntimeHTTPResult, signal istioRuntimeSignal) {
	if signal == istioSignalNone || service == nil || source == nil {
		return
	}
	switch signal {
	case istioSignalRBACDenied:
		inspectIstioAuthorizationPolicy(ctx, client, report, opts, service, targetPods, source, rawURL)
	case istioSignalJWTDenied:
		inspectIstioRequestAuthentication(ctx, client, report, service, targetPods, model.StatusFail)
	case istioSignalNoHealthyUpstream:
		inspectIstioTrafficRouting(ctx, client, report, opts, service, targetPods, source, rawURL)
	case istioSignalUpstreamReset:
		if !inspectIstioDestinationRuleMTLSMismatch(ctx, client, report, opts, service, targetPods, source, rawURL, result) {
			if !hasIstioDiagnosis(report) {
				report.Add("Istio Upstream Layer", "upstream reset", model.StatusWarn, "Envoy returned 503 upstream connect/reset before headers, but KubeNetMods could not identify a specific Istio TLS or routing object.")
				report.Diagnose(fmt.Sprintf("Primary issue candidate: Envoy returned upstream connect/reset before headers for Service %q. Check DestinationRule TLS settings, PeerAuthentication mTLS mode, upstream workload readiness, and application listener behavior.", serviceName(service)))
			}
		}
	}
}
