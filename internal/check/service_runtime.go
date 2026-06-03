package check

import (
	"context"
	"fmt"
	"strings"

	"github.com/CoGoRepo/KubeNetMods/internal/kube"
	"github.com/CoGoRepo/KubeNetMods/internal/model"
	corev1 "k8s.io/api/core/v1"
	"k8s.io/apimachinery/pkg/util/intstr"
)

func checkRuntimePath(ctx context.Context, client *kube.Client, report *model.Report, opts ServiceOptions, service *corev1.Service, targetPods []corev1.Pod, source *ExecTarget) {
	if service == nil {
		report.Add("Source-to-Target Runtime Layer", "service path", model.StatusSkip, "Skipped because the target Service was not readable.")
		return
	}
	selected, ok := selectServicePort(service, report.Target.ServicePort)
	if !ok {
		report.Add("Source-to-Target Runtime Layer", "service path", model.StatusSkip, "Skipped because the selected Service port was not found.")
		return
	}
	if selected.Protocol != "" && selected.Protocol != corev1.ProtocolTCP {
		report.Add("Source-to-Target Runtime Layer", "service path", model.StatusSkip, fmt.Sprintf("Skipped HTTP runtime checks because selected Service port %d uses %s, not TCP.", selected.Port, selected.Protocol))
		return
	}
	if source == nil {
		report.Add("Source-to-Target Runtime Layer", "service path", model.StatusSkip, "Skipped because no executable source pod/debug pod was available.")
		return
	}

	resolv, err := readResolvConf(ctx, *source)
	if err != nil {
		report.Add("Source DNS Layer", "resolv.conf", model.StatusWarn, fmt.Sprintf("Could not read /etc/resolv.conf from %s %q: %v", source.Kind, source.Pod.Name, err))
	} else {
		report.Add("Source DNS Layer", "resolv.conf", model.StatusPass, fmt.Sprintf("Runtime nameserver(s): %s; search domains: %s", formatList(resolv.Nameservers), formatList(resolv.Searches)))
		if hasNodeLocalResolver(resolv.Nameservers) {
			report.Add("Source DNS Layer", "runtime resolver", model.StatusInfo, "Source path uses a NodeLocalDNS/link-local resolver.")
		}
	}

	servicePort := report.Target.ServicePort
	urls := buildServiceURLs(service, opts.Namespace, opts.Service, opts.URLScheme, opts.URLPath, servicePort)
	inspectIstioWeightedRouteRisks(ctx, client, report, opts, service, targetPods, source, serviceFQDNURL(service, opts.Namespace, opts.Service, opts.URLScheme, opts.URLPath, servicePort))
	istioSignalsReported := map[istioRuntimeSignal]bool{}
	istioIntentionalRoutesReported := map[string]bool{}
	servicePathSucceeded := false
	for _, rawURL := range urls {
		host := hostFromURL(rawURL)
		if host != "" && host != service.Spec.ClusterIP {
			if host == opts.Service && source.Pod.Namespace != opts.Namespace {
				report.Add("Source-to-Target DNS Layer", "short name "+host, model.StatusInfo, fmt.Sprintf("Short name %q is source-namespace local. Cross-namespace checks use %q or the Service ClusterIP.", host, opts.Service+"."+opts.Namespace))
				report.Add("Source-to-Target Runtime Layer", rawURL, model.StatusSkip, fmt.Sprintf("Skipped short-name curl because source namespace %q differs from target namespace %q.", source.Pod.Namespace, opts.Namespace))
				continue
			}
			if err := resolveHost(ctx, *source, host); err != nil {
				report.Add("Source-to-Target DNS Layer", "resolve "+host, model.StatusFail, fmt.Sprintf("%s %q could not resolve %q.", source.Kind, source.Pod.Name, host))
				if !hasDiagnosisContaining(report, "runtime DNS resolver") {
					report.Diagnose(fmt.Sprintf("Source namespace %q cannot resolve target service name %q. Check DNS policy, CoreDNS/NodeLocalDNS, and egress DNS policy.", source.Pod.Namespace, host))
				}
				report.Add("Source-to-Target Runtime Layer", rawURL, model.StatusSkip, fmt.Sprintf("Skipped curl because %q did not resolve from %s %q.", host, source.Kind, source.Pod.Name))
				continue
			} else {
				report.Add("Source-to-Target DNS Layer", "resolve "+host, model.StatusPass, fmt.Sprintf("%s %q resolved %q.", source.Kind, source.Pod.Name, host))
			}
		}
		result := curlURL(ctx, *source, rawURL, opts.Timeout, opts.HTTPHeaders)
		if result.OK {
			if signal := classifyIstioRuntime(result, source, targetPods); signal != istioSignalNone {
				report.Add("Source-to-Target Runtime Layer", rawURL, model.StatusFail, istioRuntimeMessage(*source, rawURL, result, signal))
				if !istioSignalsReported[signal] {
					inspectIstioRuntimeSignal(ctx, client, report, opts, service, targetPods, source, rawURL, result, signal)
					istioSignalsReported[signal] = true
				}
			} else if behavior, ok := inspectIstioIntentionalRouteBehavior(ctx, client, report, opts, service, source, rawURL, result, istioIntentionalRoutesReported); ok {
				report.Add("Source-to-Target Runtime Layer", rawURL, behavior.RuntimeStatus, fmt.Sprintf("%s %q reached %s, but %s", source.Kind, source.Pod.Name, rawURL, behavior.RuntimeMessage))
				if behavior.RuntimeStatus != model.StatusFail {
					servicePathSucceeded = true
				}
			} else {
				report.Add("Source-to-Target Runtime Layer", rawURL, model.StatusPass, fmt.Sprintf("%s %q reached %s. HTTP status: %s", source.Kind, source.Pod.Name, rawURL, result.StatusCode))
				servicePathSucceeded = true
			}
		} else {
			classification := classifyRuntimeHTTPFailure(result)
			report.Add("Source-to-Target Runtime Layer", rawURL, model.StatusFail, runtimeProbeFailureMessage(*source, rawURL, result, classification))
			if classification.Diagnosis != "" {
				if !hasDiagnosisContaining(report, classification.Summary) {
					report.Diagnose(fmt.Sprintf("Primary issue: %s for %s from source pod %q. %s", classification.Summary, rawURL, source.Pod.Name, classification.Diagnosis))
				}
				continue
			}
			if behavior, ok := inspectIstioIntentionalRouteBehavior(ctx, client, report, opts, service, source, rawURL, result, istioIntentionalRoutesReported); ok {
				report.Add("Source-to-Target Runtime Layer", rawURL, behavior.RuntimeStatus, fmt.Sprintf("%s %q could not complete %s because %s", source.Kind, source.Pod.Name, rawURL, behavior.RuntimeMessage))
				continue
			}
			if inspectIstioMTLSReset(ctx, client, report, service, report.Target.ServicePort, targetPods, source, result) {
				continue
			}
			if inspectIstioDestinationRuleMTLSMismatch(ctx, client, report, opts, service, targetPods, source, rawURL, result) {
				continue
			}
			if inspectIstioSidecarEgressScope(ctx, client, report, service, source) {
				continue
			}
			if !hasPolicyPathDiagnosis(report) &&
				!hasDiagnosisContaining(report, "targetPort mismatch") &&
				!hasDiagnosisContaining(report, "Headless Service") &&
				!hasTargetBackendDiagnosis(report) &&
				!(len(service.Spec.Selector) == 0 && service.Spec.Type != corev1.ServiceTypeExternalName) {
				report.Diagnose(fmt.Sprintf("Primary issue: source pod %q failed to reach %s for Service %q. Error: %s. Check source egress policy, target ingress policy, service routing, and app listener.", source.Pod.Name, rawURL, opts.Service, compactCommandOutput(result.Error)))
			}
		}
	}

	podPort := int32(0)
	directCandidates := directPodPortCandidates(service, report.Target.ServicePort, collectContainerPorts(targetPods))
	if len(directCandidates) > 0 {
		podPort = directCandidates[0]
	}
	if podPort == 0 {
		report.Add("Pod-to-Pod Connectivity Layer", "direct target pod", model.StatusSkip, "No usable target pod port candidate was found.")
		return
	}
	for _, pod := range targetPods {
		if !podReady(pod) || pod.Status.PodIP == "" {
			continue
		}
		rawURL := fmt.Sprintf("%s://%s:%d%s", opts.URLScheme, pod.Status.PodIP, podPort, normalizedPath(opts.URLPath))
		result := curlURL(ctx, *source, rawURL, opts.Timeout, opts.HTTPHeaders)
		if result.OK {
			if signal := classifyIstioRuntime(result, source, targetPods); signal != istioSignalNone {
				report.Add("Pod-to-Pod Connectivity Layer", fmt.Sprintf("%s to %s:%d", source.Kind, pod.Name, podPort), model.StatusFail, istioRuntimeMessage(*source, rawURL, result, signal))
				if !istioSignalsReported[signal] {
					inspectIstioRuntimeSignal(ctx, client, report, opts, service, targetPods, source, rawURL, result, signal)
					istioSignalsReported[signal] = true
				}
			} else {
				report.Add("Pod-to-Pod Connectivity Layer", fmt.Sprintf("%s to %s:%d", source.Kind, pod.Name, podPort), model.StatusPass, fmt.Sprintf("%s reachable from %s %q. HTTP status: %s", rawURL, source.Kind, source.Pod.Name, result.StatusCode))
			}
		} else {
			classification := classifyRuntimeHTTPFailure(result)
			if servicePathSucceeded && pathHasIstioSidecar(source, targetPods) {
				report.Add("Pod-to-Pod Connectivity Layer", fmt.Sprintf("%s to %s:%d", source.Kind, pod.Name, podPort), model.StatusInfo, directPodProbeFailureMessage(*source, rawURL, result, classification)+" Service path already succeeded; direct pod IP checks can bypass normal Istio service routing/SNI/TLS behavior.")
				continue
			}
			report.Add("Pod-to-Pod Connectivity Layer", fmt.Sprintf("%s to %s:%d", source.Kind, pod.Name, podPort), model.StatusFail, directPodProbeFailureMessage(*source, rawURL, result, classification))
			if classification.Diagnosis != "" {
				if !hasDiagnosisContaining(report, classification.Summary) {
					report.Diagnose(fmt.Sprintf("Primary issue: %s for direct pod check %s from source pod %q. %s", classification.Summary, rawURL, source.Pod.Name, classification.Diagnosis))
				}
				continue
			}
			if inspectIstioMTLSReset(ctx, client, report, service, report.Target.ServicePort, targetPods, source, result) {
				continue
			}
			if !hasIstioDiagnosis(report) &&
				!hasPolicyPathDiagnosis(report) &&
				!hasDiagnosisContaining(report, "targetPort mismatch") {
				report.Diagnose(fmt.Sprintf("Primary issue: direct pod IP connectivity failed from source pod %q to target pod %q on %s. Check CNI/overlay, NetworkPolicy/CNI policy, and whether the app listens on that port.", source.Pod.Name, pod.Name, rawURL))
			}
		}
	}
}

func compactCommandOutput(value string) string {
	value = strings.TrimSpace(value)
	value = strings.Join(strings.Fields(value), " ")
	if value == "" {
		return "(no error text)"
	}
	if len(value) > 220 {
		return value[:217] + "..."
	}
	return value
}

func serviceFQDNURL(service *corev1.Service, namespace, name, scheme, path string, port int32) string {
	if service == nil {
		return ""
	}
	if scheme == "" {
		scheme = "http"
	}
	if path == "" {
		path = "/"
	}
	if !strings.HasPrefix(path, "/") {
		path = "/" + path
	}
	if port == 0 && len(service.Spec.Ports) > 0 {
		port = service.Spec.Ports[0].Port
	}
	if service.Spec.Type == corev1.ServiceTypeExternalName {
		return fmt.Sprintf("%s://%s:%d%s", scheme, service.Spec.ExternalName, port, path)
	}
	return fmt.Sprintf("%s://%s.%s.svc.cluster.local:%d%s", scheme, name, namespace, port, path)
}

func normalizedPath(path string) string {
	if path == "" {
		return "/"
	}
	if strings.HasPrefix(path, "/") {
		return path
	}
	return "/" + path
}

func directPodPortCandidates(service *corev1.Service, servicePort int32, ports []containerPort) []int32 {
	var out []int32
	seen := map[int32]bool{}
	if service != nil && len(service.Spec.Ports) > 0 {
		selected, ok := selectServicePort(service, servicePort)
		if !ok {
			selected = service.Spec.Ports[0]
		}
		target := selected.TargetPort
		for _, port := range ports {
			if targetPortMatches(target, []containerPort{port}) && !seen[port.Port] {
				seen[port.Port] = true
				out = append(out, port.Port)
			}
		}
		if len(out) == 0 && target.Type == intstr.Int && target.IntVal > 0 && !seen[int32(target.IntVal)] {
			seen[int32(target.IntVal)] = true
			out = append(out, int32(target.IntVal))
		}
	}
	for _, port := range ports {
		if port.Protocol == corev1.ProtocolTCP && port.Port > 0 && !seen[port.Port] {
			seen[port.Port] = true
			out = append(out, port.Port)
		}
	}
	return out
}
