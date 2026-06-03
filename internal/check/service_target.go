package check

import (
	"context"
	"fmt"
	"sort"
	"strings"

	"github.com/CoGoRepo/KubeNetMods/internal/kube"
	"github.com/CoGoRepo/KubeNetMods/internal/model"
	appsv1 "k8s.io/api/apps/v1"
	corev1 "k8s.io/api/core/v1"
	discoveryv1 "k8s.io/api/discovery/v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/labels"
	"k8s.io/apimachinery/pkg/util/intstr"
)

func checkDeployment(ctx context.Context, client *kube.Client, report *model.Report, opts ServiceOptions, service *corev1.Service) *appsv1.Deployment {
	layer := "Deployment Layer"
	if opts.Deployment == "" {
		report.Add(layer, "deployment", model.StatusSkip, "No deployment name supplied.")
		return nil
	}
	if service != nil && service.Spec.Type == corev1.ServiceTypeExternalName && opts.DeploymentDefaulted {
		report.Add(layer, "deployment", model.StatusSkip, "Skipped default Deployment lookup because ExternalName Services do not select backend pods.")
		return nil
	}
	if service != nil && len(service.Spec.Selector) == 0 && opts.TargetPodSelector == "" && opts.DeploymentDefaulted {
		report.Add(layer, "deployment", model.StatusSkip, "Skipped default Deployment lookup because the Service has no selector and no target selector override was supplied.")
		return nil
	}
	deployment, err := client.Core.AppsV1().Deployments(opts.Namespace).Get(ctx, opts.Deployment, metav1.GetOptions{})
	if err != nil {
		if apierrors.IsNotFound(err) {
			report.Add(layer, "deployment exists", model.StatusWarn, fmt.Sprintf("Deployment %q was not found. Continuing with Service/pod checks.", opts.Deployment))
			return nil
		}
		report.Add(layer, "deployment exists", model.StatusWarn, fmt.Sprintf("Could not read Deployment %q: %v", opts.Deployment, err))
		return nil
	}
	desired := int32(0)
	if deployment.Spec.Replicas != nil {
		desired = *deployment.Spec.Replicas
	}
	available := deployment.Status.AvailableReplicas
	ready := deployment.Status.ReadyReplicas
	if desired == available && desired == ready {
		report.Add(layer, "replicas", model.StatusPass, fmt.Sprintf("Deployment %q has %d/%d available replica(s).", opts.Deployment, available, desired))
	} else {
		report.Add(layer, "replicas", model.StatusFail, fmt.Sprintf("Deployment %q has %d/%d available replica(s) and %d/%d ready replica(s).", opts.Deployment, available, desired, ready, desired))
		report.Diagnose(fmt.Sprintf("Primary issue: Deployment %q is not healthy: %d/%d available replica(s), %d/%d ready replica(s). Fix scheduling, image pulls, crashes, probes, or app startup before chasing service networking.", opts.Deployment, available, desired, ready, desired))
	}
	return deployment
}

func checkService(ctx context.Context, client *kube.Client, report *model.Report, opts ServiceOptions) (*corev1.Service, bool) {
	layer := "Service Layer"
	service, err := client.Core.CoreV1().Services(opts.Namespace).Get(ctx, opts.Service, metav1.GetOptions{})
	if err != nil {
		report.Add(layer, "service exists", model.StatusFail, fmt.Sprintf("Service %q is not readable: %v", opts.Service, err))
		return nil, false
	}
	report.Add(layer, "service exists", model.StatusPass, fmt.Sprintf("Service %q exists.", opts.Service))
	selector := "(none)"
	if len(service.Spec.Selector) > 0 {
		selector = labels.Set(service.Spec.Selector).String()
	}
	report.Add(layer, "service details", model.StatusInfo, fmt.Sprintf("Type=%s; ClusterIP=%s; ExternalName=%s; Ports=%s; Selector=%s", service.Spec.Type, serviceClusterIPText(service), service.Spec.ExternalName, servicePorts(service), selector))
	if service.Spec.Type == corev1.ServiceTypeExternalName {
		report.Add(layer, "service shape", model.StatusInfo, fmt.Sprintf("ExternalName Service points at %q. Runtime checks should treat this as DNS/upstream reachability, not Kubernetes pod backends.", service.Spec.ExternalName))
		report.Diagnose("The target is an ExternalName Service. Kubernetes EndpointSlice and pod selector checks will not explain upstream DNS/provider reachability.")
	}
	if service.Spec.ClusterIP == corev1.ClusterIPNone {
		report.Add(layer, "service shape", model.StatusInfo, "Headless Service detected. ClusterIP curl is not expected; DNS should return endpoint records.")
	}
	if len(service.Spec.Selector) == 0 && service.Spec.Type != corev1.ServiceTypeExternalName {
		report.Add(layer, "selector", model.StatusWarn, "Service has no selector. EndpointSlice objects must be managed separately.")
		report.Diagnose(fmt.Sprintf("Primary issue candidate: Service %q has no selector. If it is unreachable, inspect manually managed EndpointSlices or external endpoints for this Service.", service.Name))
	}
	return service, true
}

func checkTargetPods(ctx context.Context, client *kube.Client, report *model.Report, opts ServiceOptions, service *corev1.Service, deployment *appsv1.Deployment) []corev1.Pod {
	layer := "Pod Health Layer"
	if service != nil && service.Spec.Type == corev1.ServiceTypeExternalName && opts.TargetPodSelector == "" && deployment == nil {
		report.Add(layer, "pod selector", model.StatusSkip, "Skipped because ExternalName Services do not select backend pods.")
		return nil
	}
	selector := opts.TargetPodSelector
	if selector == "" && service != nil && len(service.Spec.Selector) > 0 {
		selector = labels.Set(service.Spec.Selector).String()
	}
	if selector == "" && deployment != nil {
		selector = metav1.FormatLabelSelector(deployment.Spec.Selector)
	}
	if selector == "" {
		report.Add(layer, "pod selector", model.StatusSkip, "No target pod selector could be inferred.")
		return nil
	}
	report.Add(layer, "pod selector", model.StatusInfo, "Using target pod selector: "+selector)
	pods, err := client.Core.CoreV1().Pods(opts.Namespace).List(ctx, metav1.ListOptions{LabelSelector: selector})
	if err != nil {
		report.Add(layer, "pods", model.StatusFail, fmt.Sprintf("Could not list target pods: %v", err))
		return nil
	}
	if len(pods.Items) == 0 {
		report.Add(layer, "pods exist", model.StatusFail, "No pods found for the selected labels.")
		report.Diagnose(noTargetPodsDiagnosis(selector, opts.Namespace, service, deployment))
		return nil
	}
	running := 0
	ready := 0
	var states []string
	for _, pod := range pods.Items {
		if pod.Status.Phase == corev1.PodRunning {
			running++
		}
		if podReady(pod) {
			ready++
		}
		states = append(states, containerProblems(pod)...)
	}
	report.Add(layer, "pods exist", model.StatusPass, fmt.Sprintf("%d pod(s) found.", len(pods.Items)))
	status := model.StatusPass
	if running != len(pods.Items) {
		status = model.StatusFail
	}
	report.Add(layer, "running", status, fmt.Sprintf("%d/%d pod(s) are Running.", running, len(pods.Items)))
	status = model.StatusPass
	if ready != len(pods.Items) {
		status = model.StatusFail
		report.Diagnose(fmt.Sprintf("Primary issue: target pods for Service %q are not Ready: %d/%d ready. Services normally avoid routing to unready pods, so fix workload health first.", opts.Service, ready, len(pods.Items)))
	}
	report.Add(layer, "ready", status, fmt.Sprintf("%d/%d pod(s) are Ready.", ready, len(pods.Items)))
	if len(states) > 0 {
		report.Add(layer, "container states", model.StatusFail, "Problem states detected: "+strings.Join(states, "; "))
		report.Diagnose(containerStateDiagnosis(states))
	} else {
		report.Add(layer, "container states", model.StatusPass, "No CrashLoopBackOff/ImagePullBackOff-style waiting reasons detected.")
	}
	return pods.Items
}

func noTargetPodsDiagnosis(selector, namespace string, service *corev1.Service, deployment *appsv1.Deployment) string {
	base := fmt.Sprintf("Primary issue: no target pods matched selector %q in namespace %q.", selector, namespace)
	if hint := serviceDeploymentSelectorHint(service, deployment); hint != "" {
		return base + " " + hint
	}
	return base + " The Service selector/deployment labels may be wrong, or the workload has not created pods."
}

func serviceDeploymentSelectorHint(service *corev1.Service, deployment *appsv1.Deployment) string {
	if service == nil || deployment == nil || len(service.Spec.Selector) == 0 {
		return ""
	}
	templateLabels := deployment.Spec.Template.Labels
	if len(templateLabels) == 0 {
		return fmt.Sprintf("Service %q selects %s, but Deployment %q pod template has no labels.", service.Name, labels.Set(service.Spec.Selector).String(), deployment.Name)
	}
	var mismatches []string
	for key, wanted := range service.Spec.Selector {
		actual, ok := templateLabels[key]
		switch {
		case !ok:
			mismatches = append(mismatches, fmt.Sprintf("%s=%s is missing from Deployment pod labels", key, wanted))
		case actual != wanted:
			mismatches = append(mismatches, fmt.Sprintf("Service expects %s=%s, but Deployment pod label is %s=%s", key, wanted, key, actual))
		}
	}
	if len(mismatches) == 0 {
		return fmt.Sprintf("Service %q selector matches Deployment %q pod-template labels (%s), so the workload may not have created pods yet or pods may be in another namespace.", service.Name, deployment.Name, labels.Set(service.Spec.Selector).String())
	}
	sort.Strings(mismatches)
	return fmt.Sprintf("Service %q selector is %s, but Deployment %q creates pods with labels %s. Mismatch: %s. The Service selector should match the target pod labels, likely %s.",
		service.Name,
		labels.Set(service.Spec.Selector).String(),
		deployment.Name,
		labels.Set(templateLabels).String(),
		strings.Join(mismatches, "; "),
		metav1.FormatLabelSelector(deployment.Spec.Selector),
	)
}

func checkEndpoints(ctx context.Context, client *kube.Client, report *model.Report, opts ServiceOptions, service *corev1.Service, pods []corev1.Pod) {
	layer := "Endpoint Mapping Layer"
	if service == nil {
		report.Add(layer, "endpoint slices", model.StatusSkip, "Skipped because the target Service was not readable.")
		return
	}
	if service.Spec.Type == corev1.ServiceTypeExternalName {
		report.Add(layer, "endpoint slices", model.StatusSkip, "Skipped because ExternalName Services do not use Kubernetes EndpointSlices for backend pods.")
		return
	}
	slices, err := client.Core.DiscoveryV1().EndpointSlices(opts.Namespace).List(ctx, metav1.ListOptions{
		LabelSelector: discoveryv1.LabelServiceName + "=" + opts.Service,
	})
	if err != nil {
		report.Add(layer, "endpoint slices", model.StatusFail, fmt.Sprintf("Could not read EndpointSlices: %v", err))
		return
	}
	var readyIPs []string
	for _, slice := range slices.Items {
		for _, endpoint := range slice.Endpoints {
			if endpoint.Conditions.Ready != nil && !*endpoint.Conditions.Ready {
				continue
			}
			readyIPs = append(readyIPs, endpoint.Addresses...)
		}
	}
	sort.Strings(readyIPs)
	if len(readyIPs) == 0 {
		report.Add(layer, "endpoint slices", model.StatusFail, fmt.Sprintf("No ready EndpointSlice addresses found for Service %q.", opts.Service))
		if service != nil {
			if len(service.Spec.Selector) == 0 {
				report.Diagnose(fmt.Sprintf("Primary issue: selectorless Service %q has no ready EndpointSlice addresses. Manually managed EndpointSlices or external endpoints are missing/unready.", opts.Service))
			} else if !hasDiagnosisContaining(report, "no target pods matched selector") {
				report.Diagnose(fmt.Sprintf("Primary issue: Service %q has no ready EndpointSlice addresses for selector %q. This usually means selector mismatch, pod readiness failure, or missing manually managed endpoints.", opts.Service, labels.Set(service.Spec.Selector).String()))
			}
		}
		return
	}
	report.Add(layer, "endpoint slices", model.StatusPass, "Ready endpoint IPs: "+strings.Join(readyIPs, ", "))
	if len(pods) == 0 {
		return
	}
	podIPs := map[string]bool{}
	for _, pod := range pods {
		if pod.Status.PodIP != "" && podReady(pod) {
			podIPs[pod.Status.PodIP] = true
		}
	}
	missing := []string{}
	for ip := range podIPs {
		if !contains(readyIPs, ip) {
			missing = append(missing, ip)
		}
	}
	if len(missing) > 0 {
		sort.Strings(missing)
		report.Add(layer, "pod to endpoint match", model.StatusWarn, "Ready pod IPs missing from EndpointSlices: "+strings.Join(missing, ", "))
		report.Diagnose(fmt.Sprintf("Primary issue candidate: Service %q has ready pod IPs missing from EndpointSlices: %s.", opts.Service, strings.Join(missing, ", ")))
	} else {
		report.Add(layer, "pod to endpoint match", model.StatusPass, "Selected ready pod IPs appear in ready EndpointSlices.")
	}
}

func checkTargetPort(report *model.Report, service *corev1.Service, pods []corev1.Pod, opts ServiceOptions) {
	if service == nil || len(service.Spec.Ports) == 0 {
		return
	}
	layer := "Service Layer"
	selected, found := selectServicePort(service, opts.ServicePort)
	if !found {
		report.Add(layer, "selected port", model.StatusFail, fmt.Sprintf("Service port %d was not found.", opts.ServicePort))
		report.Diagnose(fmt.Sprintf("The Service does not expose expected port %d. Check the Service port definition or rerun with the port it actually exposes.", opts.ServicePort))
		return
	}
	report.Target.ServicePort = selected.Port
	report.Add(layer, "selected port", model.StatusInfo, fmt.Sprintf("Testing Service port %s.", describeServicePort(selected)))
	if selected.Protocol != "" && selected.Protocol != corev1.ProtocolTCP {
		report.Add(layer, "protocol", model.StatusWarn, fmt.Sprintf("Selected Service port uses %s. Active runtime checks use HTTP/curl and are TCP-oriented, so non-TCP behavior is not fully validated.", selected.Protocol))
		report.Diagnose(fmt.Sprintf("The selected Service port is %s, but active runtime checks are HTTP/TCP-oriented. Use protocol-specific tooling for full validation.", selected.Protocol))
	}
	if service.Spec.ClusterIP == corev1.ClusterIPNone {
		if headlessTarget, ok := resolvedTargetPort(selected, collectContainerPorts(pods)); ok && headlessTarget != selected.Port {
			report.Add(layer, "headless port", model.StatusWarn, fmt.Sprintf("Headless Service port %d resolves directly to pod endpoints, but selected targetPort is %d. Without kube-proxy translation, clients may need to use the pod listener/SRV port.", selected.Port, headlessTarget))
			report.Diagnose(fmt.Sprintf("Headless Service %q maps Service port %d to targetPort %d. Headless DNS returns endpoint addresses directly, so clients using port %d may fail unless pods listen there.", service.Name, selected.Port, headlessTarget, selected.Port))
		}
	}
	if len(pods) == 0 {
		return
	}
	ports := collectContainerPorts(pods)
	if len(ports) == 0 {
		report.Add(layer, "targetPort metadata", model.StatusWarn, "Selected pods do not declare container ports. Kubernetes allows this, but static comparison is limited.")
		return
	}
	if targetPortMatches(selected.TargetPort, ports) {
		report.Add(layer, "targetPort metadata", model.StatusPass, fmt.Sprintf("Service targetPort %s matches declared container port(s): %s.", selected.TargetPort.String(), matchingContainerPorts(selected.TargetPort, ports)))
		return
	}
	report.Add(layer, "targetPort metadata", model.StatusWarn, fmt.Sprintf("Service targetPort %s does not match declared container ports: %s.", selected.TargetPort.String(), summarizePorts(ports)))
	report.Diagnose(fmt.Sprintf("Primary issue: Service %q targetPort mismatch. The Service maps port %d to targetPort %s, but selected pods declare container ports: %s.", service.Name, selected.Port, selected.TargetPort.String(), summarizePorts(ports)))
}

func podReady(pod corev1.Pod) bool {
	for _, condition := range pod.Status.Conditions {
		if condition.Type == corev1.PodReady && condition.Status == corev1.ConditionTrue {
			return true
		}
	}
	return false
}

func containerProblems(pod corev1.Pod) []string {
	var out []string
	for _, status := range pod.Status.ContainerStatuses {
		if status.State.Waiting != nil {
			out = append(out, fmt.Sprintf("%s/%s=%s", pod.Name, status.Name, status.State.Waiting.Reason))
		}
		if status.State.Terminated != nil {
			out = append(out, fmt.Sprintf("%s/%s=%s", pod.Name, status.Name, status.State.Terminated.Reason))
		}
		if status.LastTerminationState.Terminated != nil {
			out = append(out, fmt.Sprintf("%s/%s=last:%s", pod.Name, status.Name, status.LastTerminationState.Terminated.Reason))
		}
	}
	return out
}

func containerStateDiagnosis(states []string) string {
	joined := strings.Join(states, "; ")
	if strings.Contains(joined, "ImagePullBackOff") || strings.Contains(joined, "ErrImagePull") {
		return "Primary issue: container image pull failure. Check the image name/tag, registry access, imagePullSecret, and node egress to the registry."
	}
	if strings.Contains(joined, "CrashLoopBackOff") {
		return "Primary issue: container is crashing. Check the container command, application logs, config, secrets, and startup/readiness behavior before debugging networking."
	}
	return "Container waiting/terminated states were detected. Check image pulls, crashes, commands, probes, and app logs."
}

func servicePorts(service *corev1.Service) string {
	var ports []string
	for _, port := range service.Spec.Ports {
		nodePort := ""
		if port.NodePort != 0 {
			nodePort = fmt.Sprintf(" nodePort=%d", port.NodePort)
		}
		name := ""
		if port.Name != "" {
			name = " name=" + port.Name
		}
		ports = append(ports, fmt.Sprintf("%d->%s/%s%s%s", port.Port, port.TargetPort.String(), port.Protocol, name, nodePort))
	}
	return strings.Join(ports, ", ")
}

func serviceClusterIPText(service *corev1.Service) string {
	if service == nil {
		return ""
	}
	if service.Spec.ClusterIP == corev1.ClusterIPNone {
		return "None(headless)"
	}
	return service.Spec.ClusterIP
}

func describeServicePort(port corev1.ServicePort) string {
	name := port.Name
	if name == "" {
		name = "(unnamed)"
	}
	nodePort := ""
	if port.NodePort > 0 {
		nodePort = fmt.Sprintf("; nodePort=%d", port.NodePort)
	}
	return fmt.Sprintf("%d/%s name=%s -> targetPort %s%s", port.Port, port.Protocol, name, port.TargetPort.String(), nodePort)
}

func resolvedTargetPort(port corev1.ServicePort, ports []containerPort) (int32, bool) {
	switch port.TargetPort.Type {
	case intstr.Int:
		value := int32(port.TargetPort.IntValue())
		return value, value > 0
	case intstr.String:
		for _, candidate := range ports {
			if candidate.PortName == port.TargetPort.StrVal && candidate.Port > 0 {
				return candidate.Port, true
			}
		}
	}
	return 0, false
}

func selectServicePort(service *corev1.Service, requested int32) (corev1.ServicePort, bool) {
	if requested == 0 {
		return service.Spec.Ports[0], true
	}
	for _, port := range service.Spec.Ports {
		if port.Port == requested {
			return port, true
		}
	}
	return corev1.ServicePort{}, false
}

type containerPort struct {
	Pod       string
	PortName  string
	Port      int32
	Protocol  corev1.Protocol
	Container string
}

func collectContainerPorts(pods []corev1.Pod) []containerPort {
	var out []containerPort
	for _, pod := range pods {
		for _, container := range pod.Spec.Containers {
			for _, port := range container.Ports {
				out = append(out, containerPort{
					Pod:       pod.Name,
					PortName:  port.Name,
					Port:      port.ContainerPort,
					Protocol:  port.Protocol,
					Container: container.Name,
				})
			}
		}
	}
	return out
}

func targetPortMatches(target intstr.IntOrString, ports []containerPort) bool {
	for _, port := range ports {
		switch target.Type {
		case intstr.Int:
			if int32(target.IntValue()) == port.Port {
				return true
			}
		case intstr.String:
			if target.StrVal == port.PortName {
				return true
			}
		}
	}
	return false
}

func matchingContainerPorts(target intstr.IntOrString, ports []containerPort) string {
	seen := map[string]bool{}
	var matches []string
	for _, port := range ports {
		if !targetPortMatches(target, []containerPort{port}) {
			continue
		}
		name := port.PortName
		if name == "" {
			name = "(unnamed)"
		}
		value := fmt.Sprintf("%s/%s:%d/%s name=%s", port.Pod, port.Container, port.Port, port.Protocol, name)
		if !seen[value] {
			seen[value] = true
			matches = append(matches, value)
		}
	}
	sort.Strings(matches)
	if len(matches) == 0 {
		return "(none)"
	}
	if len(matches) > 4 {
		return strings.Join(matches[:4], ", ") + fmt.Sprintf(", ... +%d more", len(matches)-4)
	}
	return strings.Join(matches, ", ")
}

func summarizePorts(ports []containerPort) string {
	seen := map[string]bool{}
	var values []string
	for _, port := range ports {
		name := port.PortName
		if name == "" {
			name = "(unnamed)"
		}
		value := fmt.Sprintf("%d/%s name=%s", port.Port, port.Protocol, name)
		if !seen[value] {
			seen[value] = true
			values = append(values, value)
		}
	}
	sort.Strings(values)
	if len(values) > 6 {
		return strings.Join(values[:6], ", ") + fmt.Sprintf(", ... +%d more", len(values)-6)
	}
	return strings.Join(values, ", ")
}

func contains(values []string, needle string) bool {
	for _, value := range values {
		if value == needle {
			return true
		}
	}
	return false
}
