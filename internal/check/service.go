package check

import (
	"context"
	"fmt"
	"net/netip"
	"sort"
	"strings"
	"time"

	"github.com/CoGoRepo/KubeNetMods/internal/kube"
	"github.com/CoGoRepo/KubeNetMods/internal/model"
	"github.com/CoGoRepo/KubeNetMods/internal/policy"
	calicopolicy "github.com/CoGoRepo/KubeNetMods/internal/policy/calico"
	ciliumpolicy "github.com/CoGoRepo/KubeNetMods/internal/policy/cilium"
	appsv1 "k8s.io/api/apps/v1"
	corev1 "k8s.io/api/core/v1"
	discoveryv1 "k8s.io/api/discovery/v1"
	networkingv1 "k8s.io/api/networking/v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/labels"
	"k8s.io/apimachinery/pkg/util/intstr"
)

type ServiceOptions struct {
	Context             string
	Namespace           string
	TargetName          string
	Service             string
	Deployment          string
	ServicePort         int32
	SourceContext       string
	SourceNamespace     string
	SourceName          string
	SourceDeployment    string
	SourcePodName       string
	SourcePodSelector   string
	TargetPodSelector   string
	SourceContainer     string
	URLScheme           string
	URLPath             string
	UseDebugPod         bool
	DebugImage          string
	DebugPullPolicy     string
	TargetDebugPod      string
	SourceDebugPod      string
	SkipNodePort        bool
	Timeout             time.Duration
	DeploymentDefaulted bool
}

func RunService(ctx context.Context, opts ServiceOptions) (*model.Report, error) {
	if opts.Namespace == "" {
		opts.Namespace = "default"
	}
	if opts.TargetName != "" {
		opts.Service = opts.TargetName
		if opts.Deployment == "" {
			opts.Deployment = opts.TargetName
			opts.DeploymentDefaulted = true
		}
	}
	if opts.Service == "" {
		opts.Service = "nginx"
	}
	if opts.Deployment == "" {
		opts.Deployment = opts.Service
		opts.DeploymentDefaulted = true
	}
	if opts.SourceNamespace == "" {
		opts.SourceNamespace = opts.Namespace
	}
	if opts.URLScheme == "" {
		opts.URLScheme = "http"
	}
	if opts.URLPath == "" {
		opts.URLPath = "/"
	}
	if opts.DebugImage == "" {
		opts.DebugImage = "nicolaka/netshoot:latest"
	}
	if opts.DebugPullPolicy == "" {
		opts.DebugPullPolicy = "IfNotPresent"
	}
	if opts.TargetDebugPod == "" {
		opts.TargetDebugPod = "kubenetmods-debug"
	}
	if opts.SourceDebugPod == "" {
		opts.SourceDebugPod = "kubenetmods-source-debug"
	}

	target := model.Target{
		Context:        opts.Context,
		Namespace:      opts.Namespace,
		Service:        opts.Service,
		Deployment:     opts.Deployment,
		ServicePort:    opts.ServicePort,
		SourceContext:  opts.SourceContext,
		SourceNS:       opts.SourceNamespace,
		SourcePod:      opts.SourcePodName,
		SourceSelector: opts.SourcePodSelector,
	}
	report := model.NewReport("check service", target)

	client, err := kube.New(opts.Context)
	if err != nil {
		report.Add("Cluster Access", "target context", model.StatusFail, err.Error())
		report.Diagnose("Cannot build Kubernetes client. Check kubeconfig, context, and credentials.")
		return report, nil
	}
	if report.Target.Context == "" {
		report.Target.Context = client.Context
	}
	if opts.UseDebugPod {
		defer func() {
			_ = client.DeletePodIfExists(context.Background(), opts.SourceNamespace, opts.SourceDebugPod)
			_ = client.DeletePodIfExists(context.Background(), opts.Namespace, opts.TargetDebugPod)
		}()
	}

	checkCluster(ctx, client, report, opts)
	service, serviceOK := checkService(ctx, client, report, opts)
	deployment := checkDeployment(ctx, client, report, opts, service)
	pods := checkTargetPods(ctx, client, report, opts, service, deployment)
	checkEndpoints(ctx, client, report, opts, service, pods)
	checkTargetPort(report, service, pods, opts)
	sourceTarget := checkSource(ctx, client, report, opts)
	checkNativeNetworkPolicies(ctx, client, report, opts, service, pods, sourceTarget)
	checkCniPolicies(ctx, client, report, opts, service, pods, sourceTarget)
	checkRuntimePath(ctx, client, report, opts, service, pods, sourceTarget)
	checkNodePortAndHost(ctx, client, report, opts, service)
	checkEvents(ctx, client, report, opts)

	if !serviceOK {
		report.Diagnose(fmt.Sprintf("Target Service %q is missing or unreadable. Fix the Service before debugging lower networking layers.", opts.Service))
	}
	if len(report.Diagnoses) == 0 && report.CountByStatus(model.StatusFail) > 0 {
		report.Diagnose("Failures were found, but no single dominant diagnosis was inferred yet. Review the failed layer details.")
	}
	report.Limitations = append(report.Limitations,
		"Service checks reason from Kubernetes/CNI objects and runtime exec tests; they do not inspect live dataplane rules or packet traces.",
		"Calico/Cilium policy analysis is heuristic and focuses on the tested source-to-Service path.",
	)
	return report, nil
}

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

func checkNativeNetworkPolicies(ctx context.Context, client *kube.Client, report *model.Report, opts ServiceOptions, service *corev1.Service, pods []corev1.Pod, source *ExecTarget) {
	layer := "NetworkPolicy Layer"
	targetPolicies, err := client.Core.NetworkingV1().NetworkPolicies(opts.Namespace).List(ctx, metav1.ListOptions{})
	if err != nil {
		report.Add(layer, "native policies", model.StatusWarn, fmt.Sprintf("Could not inspect native NetworkPolicies: %v", err))
		return
	}
	sourcePolicies := targetPolicies
	if source != nil && source.Pod.Namespace != opts.Namespace {
		sourcePolicies, err = client.Core.NetworkingV1().NetworkPolicies(source.Pod.Namespace).List(ctx, metav1.ListOptions{})
		if err != nil {
			report.Add(layer, "source native policies", model.StatusWarn, fmt.Sprintf("Could not inspect source namespace NetworkPolicies: %v", err))
			sourcePolicies = &networkingv1.NetworkPolicyList{}
		}
	}
	if len(targetPolicies.Items) == 0 && (sourcePolicies == nil || len(sourcePolicies.Items) == 0) {
		report.Add(layer, "native policies", model.StatusInfo, "No native Kubernetes NetworkPolicy objects found in the target/source namespace.")
		return
	}
	targetSelected := policyNamesSelectingPods(targetPolicies.Items, pods)
	if len(targetSelected) == 0 {
		report.Add(layer, "target policies", model.StatusInfo, fmt.Sprintf("%d native NetworkPolicy object(s) exist in target namespace, but none obviously select the target pods.", len(targetPolicies.Items)))
	} else {
		report.Add(layer, "target policies", model.StatusWarn, "Target pod(s) are selected by native NetworkPolicy: "+strings.Join(targetSelected, ", "))
	}
	if source == nil {
		if len(targetSelected) > 0 {
			report.Diagnose("Native NetworkPolicy selects the target pods. Provide a source pod/selector to evaluate whether the actual source is allowed.")
		}
		return
	}
	sourceNamespace, err := client.Core.CoreV1().Namespaces().Get(ctx, source.Pod.Namespace, metav1.GetOptions{})
	if err != nil {
		report.Add(layer, "source namespace labels", model.StatusWarn, fmt.Sprintf("Could not read source namespace labels: %v", err))
		return
	}
	targetNamespace, err := client.Core.CoreV1().Namespaces().Get(ctx, opts.Namespace, metav1.GetOptions{})
	if err != nil {
		report.Add(layer, "target namespace labels", model.StatusWarn, fmt.Sprintf("Could not read target namespace labels: %v", err))
		return
	}
	ports := selectedConnectionPortCandidates(service, collectContainerPorts(pods), report.Target.ServicePort)
	analyzeNativeEgress(report, source.Pod, *targetNamespace, pods, sourcePolicies.Items, service, ports)
	analyzeNativeIngress(report, source.Pod, *sourceNamespace, pods, *targetNamespace, targetPolicies.Items, service, ports)
}

func checkCniPolicies(ctx context.Context, client *kube.Client, report *model.Report, opts ServiceOptions, service *corev1.Service, pods []corev1.Pod, source *ExecTarget) {
	if len(pods) == 0 {
		report.Add("CNI Policy Layer", "provider policies", model.StatusSkip, "Skipped CNI policy analysis because no target pods were selected.")
		return
	}
	targetNamespace, err := client.Core.CoreV1().Namespaces().Get(ctx, opts.Namespace, metav1.GetOptions{})
	if err != nil {
		report.Add("CNI Policy Layer", "target namespace labels", model.StatusWarn, fmt.Sprintf("Could not read target namespace labels for CNI policy analysis: %v", err))
		return
	}
	var sourceNamespace *corev1.Namespace
	if opts.SourceNamespace != "" {
		if ns, err := client.Core.CoreV1().Namespaces().Get(ctx, opts.SourceNamespace, metav1.GetOptions{}); err == nil {
			sourceNamespace = ns
		}
	}

	var sourcePod *corev1.Pod
	if source != nil {
		sourcePod = &source.Pod
	}
	ports := selectedConnectionPortCandidates(service, collectContainerPorts(pods), report.Target.ServicePort)
	calicoInsights, err := calicopolicy.Analyze(ctx, client, *targetNamespace, pods, sourceNamespace, sourcePod, service, ports, buildCalicoDNSContext(ctx, client, source))
	if err != nil {
		report.Add("Calico Policy Layer", "analysis", model.StatusWarn, fmt.Sprintf("Calico policy analysis failed: %v", err))
	} else {
		addInsights(report, calicoInsights)
	}
	if service != nil && (service.Spec.Type == corev1.ServiceTypeNodePort || service.Spec.Type == corev1.ServiceTypeLoadBalancer) {
		hostInsights, err := calicopolicy.AnalyzeIngressSurface(ctx, client, service)
		if err != nil {
			report.Add("Calico Host Policy Layer", "analysis", model.StatusWarn, fmt.Sprintf("Calico host/forwarded policy analysis failed: %v", err))
		} else {
			addInsights(report, hostInsights)
		}
	}

	ciliumInsights, err := ciliumpolicy.Analyze(ctx, client, *targetNamespace, pods, sourceNamespace, sourcePod, service, ports, buildCiliumDNSContext(ctx, client, source))
	if err != nil {
		report.Add("Cilium Policy Layer", "analysis", model.StatusWarn, fmt.Sprintf("Cilium policy analysis failed: %v", err))
	} else {
		addInsights(report, ciliumInsights)
	}
}

func buildCalicoDNSContext(ctx context.Context, client *kube.Client, source *ExecTarget) calicopolicy.DNSContext {
	var dns calicopolicy.DNSContext
	if source != nil {
		if resolv, err := readResolvConf(ctx, *source); err == nil {
			dns.Nameservers = resolv.Nameservers
		}
	}
	if service, err := client.Core.CoreV1().Services("kube-system").Get(ctx, "kube-dns", metav1.GetOptions{}); err == nil {
		dns.CoreDNSServiceIP = service.Spec.ClusterIP
	}
	if namespace, err := client.Core.CoreV1().Namespaces().Get(ctx, "kube-system", metav1.GetOptions{}); err == nil {
		dns.KubeSystemNS = namespace
	}
	pods, err := client.Core.CoreV1().Pods("kube-system").List(ctx, metav1.ListOptions{})
	if err != nil {
		return dns
	}
	for _, pod := range pods.Items {
		name := strings.ToLower(pod.Name)
		k8sApp := strings.ToLower(pod.Labels["k8s-app"])
		app := strings.ToLower(pod.Labels["app"])
		if strings.Contains(name, "node-local-dns") || strings.Contains(name, "nodelocaldns") || strings.Contains(k8sApp, "node-local-dns") || strings.Contains(app, "node-local-dns") {
			dns.NodeLocalDNSPods = append(dns.NodeLocalDNSPods, pod)
			continue
		}
		if strings.Contains(name, "coredns") || strings.Contains(name, "kube-dns") || strings.Contains(k8sApp, "kube-dns") || strings.Contains(k8sApp, "coredns") || strings.Contains(app, "coredns") {
			dns.CoreDNSPods = append(dns.CoreDNSPods, pod)
		}
	}
	return dns
}

func buildCiliumDNSContext(ctx context.Context, client *kube.Client, source *ExecTarget) ciliumpolicy.DNSContext {
	calicoDNS := buildCalicoDNSContext(ctx, client, source)
	return ciliumpolicy.DNSContext{
		Nameservers:      calicoDNS.Nameservers,
		CoreDNSServiceIP: calicoDNS.CoreDNSServiceIP,
		CoreDNSPods:      calicoDNS.CoreDNSPods,
		NodeLocalDNSPods: calicoDNS.NodeLocalDNSPods,
	}
}

func addInsights(report *model.Report, insights []policy.Insight) {
	for _, insight := range insights {
		report.Add(insight.Layer, insight.Check, model.Status(insight.Status), insight.Message)
		if insight.Diagnosis != "" {
			report.Diagnose(insight.Diagnosis)
		}
	}
}

type sourceResolverResult struct {
	Kind       string
	ObjectName string
	Selector   string
	Pod        *corev1.Pod
}

func resolveSourceName(ctx context.Context, client *kube.Client, namespace string, name string) (*sourceResolverResult, error) {
	if strings.TrimSpace(name) == "" {
		return nil, fmt.Errorf("source name was empty")
	}
	if pod, err := client.Core.CoreV1().Pods(namespace).Get(ctx, name, metav1.GetOptions{}); err == nil {
		return &sourceResolverResult{Kind: "Pod", ObjectName: pod.Name, Pod: pod}, nil
	} else if err != nil && !apierrors.IsNotFound(err) {
		return nil, fmt.Errorf("could not read source pod %q: %v", name, err)
	}

	var candidates []sourceResolverResult
	addSelectorCandidate := func(kind, objectName, selector string) {
		if selector == "" {
			return
		}
		pods, err := client.Core.CoreV1().Pods(namespace).List(ctx, metav1.ListOptions{LabelSelector: selector})
		if err != nil || len(pods.Items) == 0 {
			return
		}
		selected := selectReadyPod(pods.Items)
		if selected == nil {
			selected = &pods.Items[0]
		}
		candidates = append(candidates, sourceResolverResult{
			Kind:       kind,
			ObjectName: objectName,
			Selector:   selector,
			Pod:        selected,
		})
	}
	if deployment, err := client.Core.AppsV1().Deployments(namespace).Get(ctx, name, metav1.GetOptions{}); err == nil {
		addSelectorCandidate("Deployment", deployment.Name, metav1.FormatLabelSelector(deployment.Spec.Selector))
	} else if err != nil && !apierrors.IsNotFound(err) {
		return nil, fmt.Errorf("could not read source Deployment %q: %v", name, err)
	}
	if statefulSet, err := client.Core.AppsV1().StatefulSets(namespace).Get(ctx, name, metav1.GetOptions{}); err == nil {
		addSelectorCandidate("StatefulSet", statefulSet.Name, metav1.FormatLabelSelector(statefulSet.Spec.Selector))
	} else if err != nil && !apierrors.IsNotFound(err) {
		return nil, fmt.Errorf("could not read source StatefulSet %q: %v", name, err)
	}
	if daemonSet, err := client.Core.AppsV1().DaemonSets(namespace).Get(ctx, name, metav1.GetOptions{}); err == nil {
		addSelectorCandidate("DaemonSet", daemonSet.Name, metav1.FormatLabelSelector(daemonSet.Spec.Selector))
	} else if err != nil && !apierrors.IsNotFound(err) {
		return nil, fmt.Errorf("could not read source DaemonSet %q: %v", name, err)
	}
	if replicaSet, err := client.Core.AppsV1().ReplicaSets(namespace).Get(ctx, name, metav1.GetOptions{}); err == nil {
		addSelectorCandidate("ReplicaSet", replicaSet.Name, metav1.FormatLabelSelector(replicaSet.Spec.Selector))
	} else if err != nil && !apierrors.IsNotFound(err) {
		return nil, fmt.Errorf("could not read source ReplicaSet %q: %v", name, err)
	}
	if service, err := client.Core.CoreV1().Services(namespace).Get(ctx, name, metav1.GetOptions{}); err == nil {
		addSelectorCandidate("Service", service.Name, labels.SelectorFromSet(labels.Set(service.Spec.Selector)).String())
	} else if err != nil && !apierrors.IsNotFound(err) {
		return nil, fmt.Errorf("could not read source Service %q: %v", name, err)
	}

	for _, key := range []string{"app", "app.kubernetes.io/name", "k8s-app", "component"} {
		addSelectorCandidate("label selector", key+"="+name, labels.SelectorFromSet(labels.Set{key: name}).String())
	}

	if len(candidates) == 0 {
		return nil, fmt.Errorf("source %q did not match a Pod, workload, Service selector, or common app label in namespace %q", name, namespace)
	}

	seen := map[string]sourceResolverResult{}
	for _, candidate := range candidates {
		podName := ""
		if candidate.Pod != nil {
			podName = candidate.Pod.Name
		}
		key := candidate.Selector + "|" + podName
		if _, ok := seen[key]; !ok {
			seen[key] = candidate
		}
	}
	if len(seen) == 1 {
		for _, candidate := range seen {
			return &candidate, nil
		}
	}

	var descriptions []string
	for _, candidate := range candidates {
		descriptions = append(descriptions, fmt.Sprintf("%s/%s selector=%s", candidate.Kind, candidate.ObjectName, candidate.Selector))
	}
	sort.Strings(descriptions)
	return nil, fmt.Errorf("source %q matched multiple possible sources in namespace %q: %s. Use --source-pod or --source-selector to choose one", name, namespace, strings.Join(uniqueStrings(descriptions), "; "))
}

func checkSource(ctx context.Context, client *kube.Client, report *model.Report, opts ServiceOptions) *ExecTarget {
	if opts.SourcePodName == "" && opts.SourcePodSelector == "" && opts.SourceDeployment == "" && opts.SourceName == "" {
		if !opts.UseDebugPod {
			report.Add("Source Path Layer", "source workload", model.StatusSkip, "No source pod name/selector was supplied and debug pod creation is disabled.")
			return nil
		}
		pod, err := client.EnsureDebugPod(ctx, opts.SourceNamespace, opts.SourceDebugPod, opts.DebugImage, opts.DebugPullPolicy, maxDuration(opts.Timeout, 30*time.Second))
		if err != nil {
			report.Add("Source debug pod path", "debug pod ready", model.StatusFail, fmt.Sprintf("Source debug pod %q did not become Ready: %v", opts.SourceDebugPod, err))
			report.Diagnose("Debug pod creation failed in the source namespace. Active DNS/curl checks cannot run until RBAC, image access, or scheduling is fixed.")
			return nil
		}
		report.Add("Source debug pod path", "debug pod ready", model.StatusPass, fmt.Sprintf("Source debug pod %q is Ready in namespace %q.", pod.Name, opts.SourceNamespace))
		return &ExecTarget{Client: client, Pod: *pod, Kind: "source debug pod"}
	}
	sourceClient := client
	if opts.SourceContext != "" && opts.SourceContext != opts.Context {
		other, err := kube.New(opts.SourceContext)
		if err != nil {
			report.Add("Source Path Layer", "source context", model.StatusFail, fmt.Sprintf("Source context %q is not usable: %v", opts.SourceContext, err))
			return nil
		}
		sourceClient = other
	}
	if opts.SourcePodName == "" && opts.SourcePodSelector == "" && opts.SourceDeployment != "" {
		deployment, err := sourceClient.Core.AppsV1().Deployments(opts.SourceNamespace).Get(ctx, opts.SourceDeployment, metav1.GetOptions{})
		if err != nil {
			report.Add("Source Resolver Layer", "source deployment", model.StatusFail, fmt.Sprintf("Source Deployment %q is not readable: %v", opts.SourceDeployment, err))
			report.Diagnose(fmt.Sprintf("Could not resolve source Deployment %q in namespace %q. Check the source namespace/name or use --source-selector.", opts.SourceDeployment, opts.SourceNamespace))
			return nil
		}
		opts.SourcePodSelector = metav1.FormatLabelSelector(deployment.Spec.Selector)
		report.Target.SourceSelector = opts.SourcePodSelector
		report.Add("Source Resolver Layer", "source deployment", model.StatusInfo, fmt.Sprintf("Resolved source Deployment %q to selector %s.", deployment.Name, opts.SourcePodSelector))
	}
	if opts.SourcePodName == "" && opts.SourcePodSelector == "" && opts.SourceName != "" {
		resolved, err := resolveSourceName(ctx, sourceClient, opts.SourceNamespace, opts.SourceName)
		if err != nil {
			report.Add("Source Resolver Layer", "source name", model.StatusFail, err.Error())
			report.Diagnose(fmt.Sprintf("Could not resolve source %q in namespace %q. Use --source-pod for an exact pod or --source-selector for labels.", opts.SourceName, opts.SourceNamespace))
			return nil
		}
		report.Target.SourceSelector = resolved.Selector
		if resolved.Pod != nil {
			report.Target.SourcePod = resolved.Pod.Name
			status := model.StatusPass
			if !podReady(*resolved.Pod) {
				status = model.StatusWarn
			}
			report.Add("Source Resolver Layer", "source name", status, fmt.Sprintf("Resolved source %q to %s %q, using pod %q phase=%s ready=%t.", opts.SourceName, resolved.Kind, resolved.ObjectName, resolved.Pod.Name, resolved.Pod.Status.Phase, podReady(*resolved.Pod)))
			return &ExecTarget{Client: sourceClient, Pod: *resolved.Pod, Container: opts.SourceContainer, Kind: "source pod"}
		}
		opts.SourcePodSelector = resolved.Selector
		report.Target.SourceSelector = resolved.Selector
		report.Add("Source Resolver Layer", "source name", model.StatusInfo, fmt.Sprintf("Resolved source %q to %s %q selector %s.", opts.SourceName, resolved.Kind, resolved.ObjectName, resolved.Selector))
	}
	if opts.SourcePodName != "" {
		pod, err := sourceClient.Core.CoreV1().Pods(opts.SourceNamespace).Get(ctx, opts.SourcePodName, metav1.GetOptions{})
		if err != nil {
			report.Add("Source Path Layer", "source pod", model.StatusFail, fmt.Sprintf("Source pod %q is not readable: %v", opts.SourcePodName, err))
			return nil
		}
		status := model.StatusPass
		if !podReady(*pod) {
			status = model.StatusWarn
		}
		report.Add("Source Path Layer", "source pod", status, fmt.Sprintf("Source pod %q phase=%s ready=%t.", pod.Name, pod.Status.Phase, podReady(*pod)))
		return &ExecTarget{Client: sourceClient, Pod: *pod, Container: opts.SourceContainer, Kind: "source pod"}
	}
	pods, err := sourceClient.Core.CoreV1().Pods(opts.SourceNamespace).List(ctx, metav1.ListOptions{LabelSelector: opts.SourcePodSelector})
	if err != nil {
		report.Add("Source Path Layer", "source selector", model.StatusFail, fmt.Sprintf("Could not list source pods: %v", err))
		return nil
	}
	if len(pods.Items) == 0 {
		report.Add("Source Path Layer", "source selector", model.StatusFail, "No source pods matched selector "+opts.SourcePodSelector)
		return nil
	}
	selected := selectReadyPod(pods.Items)
	if selected == nil {
		report.Add("Source Path Layer", "source selector", model.StatusFail, fmt.Sprintf("%d source pod(s) matched selector %s, but none are Running and Ready.", len(pods.Items), opts.SourcePodSelector))
		return nil
	}
	report.Add("Source Path Layer", "source selector", model.StatusPass, fmt.Sprintf("Using source pod %q selected by %s.", selected.Name, opts.SourcePodSelector))
	return &ExecTarget{Client: sourceClient, Pod: *selected, Container: opts.SourceContainer, Kind: "source pod"}
}

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
		result := curlURL(ctx, *source, rawURL, opts.Timeout)
		if result.OK {
			report.Add("Source-to-Target Runtime Layer", rawURL, model.StatusPass, fmt.Sprintf("%s %q reached %s. HTTP status: %s", source.Kind, source.Pod.Name, rawURL, result.StatusCode))
		} else {
			classification := classifyRuntimeHTTPFailure(result)
			report.Add("Source-to-Target Runtime Layer", rawURL, model.StatusFail, runtimeProbeFailureMessage(*source, rawURL, result, classification))
			if classification.Diagnosis != "" {
				if !hasDiagnosisContaining(report, classification.Summary) {
					report.Diagnose(fmt.Sprintf("Primary issue: %s for %s from source pod %q. %s", classification.Summary, rawURL, source.Pod.Name, classification.Diagnosis))
				}
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
		result := curlURL(ctx, *source, rawURL, opts.Timeout)
		if result.OK {
			report.Add("Pod-to-Pod Connectivity Layer", fmt.Sprintf("%s to %s:%d", source.Kind, pod.Name, podPort), model.StatusPass, fmt.Sprintf("%s reachable from %s %q. HTTP status: %s", rawURL, source.Kind, source.Pod.Name, result.StatusCode))
		} else {
			classification := classifyRuntimeHTTPFailure(result)
			report.Add("Pod-to-Pod Connectivity Layer", fmt.Sprintf("%s to %s:%d", source.Kind, pod.Name, podPort), model.StatusFail, directPodProbeFailureMessage(*source, rawURL, result, classification))
			if classification.Diagnosis != "" {
				if !hasDiagnosisContaining(report, classification.Summary) {
					report.Diagnose(fmt.Sprintf("Primary issue: %s for direct pod check %s from source pod %q. %s", classification.Summary, rawURL, source.Pod.Name, classification.Diagnosis))
				}
				continue
			}
			if !hasPolicyPathDiagnosis(report) {
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

func hasDiagnosisContaining(report *model.Report, fragment string) bool {
	for _, diagnosis := range report.Diagnoses {
		if strings.Contains(diagnosis.Message, fragment) {
			return true
		}
	}
	return false
}

func hasPolicyPathDiagnosis(report *model.Report) bool {
	for _, diagnosis := range report.Diagnoses {
		if strings.Contains(diagnosis.Message, "Calico ") || strings.Contains(diagnosis.Message, "Cilium ") || strings.Contains(diagnosis.Message, "NetworkPolicy ") {
			return true
		}
	}
	return false
}

func hasTargetBackendDiagnosis(report *model.Report) bool {
	fragments := []string{
		"no target pods matched selector",
		"has no ready EndpointSlice addresses",
		"ready pod IPs missing from EndpointSlices",
		"target pods for Service",
	}
	for _, diagnosis := range report.Diagnoses {
		for _, fragment := range fragments {
			if strings.Contains(diagnosis.Message, fragment) {
				return true
			}
		}
	}
	return false
}

func maxDuration(a, b time.Duration) time.Duration {
	if a > b {
		return a
	}
	return b
}

func formatList(values []string) string {
	if len(values) == 0 {
		return "(none)"
	}
	return strings.Join(values, ", ")
}

func hasNodeLocalResolver(values []string) bool {
	for _, value := range values {
		if strings.HasPrefix(value, "169.254.") {
			return true
		}
	}
	return false
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

func policyNamesSelectingPods(policies []networkingv1.NetworkPolicy, pods []corev1.Pod) []string {
	var names []string
	for _, policy := range policies {
		selector, err := metav1.LabelSelectorAsSelector(&policy.Spec.PodSelector)
		if err != nil {
			continue
		}
		for _, pod := range pods {
			if selector.Matches(labels.Set(pod.Labels)) {
				names = append(names, policy.Name)
				break
			}
		}
	}
	sort.Strings(names)
	return names
}

func analyzeNativeEgress(report *model.Report, source corev1.Pod, targetNamespace corev1.Namespace, targets []corev1.Pod, policies []networkingv1.NetworkPolicy, service *corev1.Service, ports []int32) {
	var selecting []networkingv1.NetworkPolicy
	for _, netpol := range policies {
		if policySelectsPod(netpol, source) && hasPolicyType(netpol, networkingv1.PolicyTypeEgress) {
			selecting = append(selecting, netpol)
		}
	}
	if len(selecting) == 0 {
		report.Add("NetworkPolicy Path Analysis", "source egress to target", model.StatusPass, fmt.Sprintf("No egress NetworkPolicies select source pod %q.", source.Name))
		return
	}
	var reasons []string
	for _, netpol := range selecting {
		for _, rule := range netpol.Spec.Egress {
			if nativeEgressRuleAllows(rule, targetNamespace, targets, service, ports, source.Namespace) {
				reasons = append(reasons, netpol.Name)
				break
			}
		}
	}
	names := nativePolicyNames(selecting)
	if len(reasons) > 0 {
		report.Add("NetworkPolicy Path Analysis", "source egress to target", model.StatusPass, fmt.Sprintf("Source egress NetworkPolicy appears to allow this target path. Matching policy/rule found in: %s.", strings.Join(uniqueStrings(reasons), ", ")))
		return
	}
	report.Add("NetworkPolicy Path Analysis", "source egress to target", model.StatusWarn, fmt.Sprintf("Source pod %q is egress-isolated by NetworkPolicy (%s), and no rule obviously allows target namespace %q on TCP port(s) %s.", source.Name, strings.Join(names, ", "), targetNamespace.Name, formatPorts(ports)))
	report.Diagnose(fmt.Sprintf("Primary issue: native egress NetworkPolicy default-deny blocks source pod %q from Service %q on TCP port(s) %s. Selected policy/policies: %s.", source.Namespace+"/"+source.Name, serviceName(service), formatPorts(ports), strings.Join(names, ", ")))
}

func analyzeNativeIngress(report *model.Report, source corev1.Pod, sourceNamespace corev1.Namespace, targets []corev1.Pod, targetNamespace corev1.Namespace, policies []networkingv1.NetworkPolicy, service *corev1.Service, ports []int32) {
	var selecting []networkingv1.NetworkPolicy
	for _, netpol := range policies {
		if hasPolicyType(netpol, networkingv1.PolicyTypeIngress) {
			for _, pod := range targets {
				if policySelectsPod(netpol, pod) {
					selecting = append(selecting, netpol)
					break
				}
			}
		}
	}
	if len(selecting) == 0 {
		report.Add("NetworkPolicy Path Analysis", "target ingress from source", model.StatusPass, "No ingress NetworkPolicies select the target pods.")
		return
	}
	var reasons []string
	for _, netpol := range selecting {
		for _, rule := range netpol.Spec.Ingress {
			if nativeIngressRuleAllows(rule, source, sourceNamespace, ports) {
				reasons = append(reasons, netpol.Name)
				break
			}
		}
	}
	names := nativePolicyNames(selecting)
	if len(reasons) > 0 {
		report.Add("NetworkPolicy Path Analysis", "target ingress from source", model.StatusPass, fmt.Sprintf("Target ingress NetworkPolicy appears to allow source pod %q. Matching policy/rule found in: %s.", source.Name, strings.Join(uniqueStrings(reasons), ", ")))
		return
	}
	report.Add("NetworkPolicy Path Analysis", "target ingress from source", model.StatusWarn, fmt.Sprintf("Target pods are ingress-isolated by NetworkPolicy (%s), and no rule obviously allows source namespace %q on TCP port(s) %s.", strings.Join(names, ", "), sourceNamespace.Name, formatPorts(ports)))
	report.Diagnose(fmt.Sprintf("Primary issue: native ingress NetworkPolicy default-deny blocks source pod %q from Service %q on TCP port(s) %s. Selected policy/policies: %s.", source.Namespace+"/"+source.Name, serviceName(service), formatPorts(ports), strings.Join(names, ", ")))
}

func policySelectsPod(netpol networkingv1.NetworkPolicy, pod corev1.Pod) bool {
	selector, err := metav1.LabelSelectorAsSelector(&netpol.Spec.PodSelector)
	if err != nil {
		return false
	}
	return selector.Matches(labels.Set(pod.Labels))
}

func hasPolicyType(netpol networkingv1.NetworkPolicy, policyType networkingv1.PolicyType) bool {
	if len(netpol.Spec.PolicyTypes) == 0 {
		if policyType == networkingv1.PolicyTypeIngress {
			return true
		}
		if policyType == networkingv1.PolicyTypeEgress {
			return len(netpol.Spec.Egress) > 0
		}
	}
	for _, current := range netpol.Spec.PolicyTypes {
		if current == policyType {
			return true
		}
	}
	return false
}

func nativeEgressRuleAllows(rule networkingv1.NetworkPolicyEgressRule, targetNamespace corev1.Namespace, targets []corev1.Pod, service *corev1.Service, ports []int32, policyNamespace string) bool {
	if !nativePortsAllow(rule.Ports, ports) {
		return false
	}
	if len(rule.To) == 0 {
		return true
	}
	clusterIP := ""
	if service != nil && service.Spec.ClusterIP != "None" {
		clusterIP = service.Spec.ClusterIP
	}
	for _, peer := range rule.To {
		if clusterIP != "" && ipBlockContains(peer.IPBlock, clusterIP) {
			return true
		}
		for _, pod := range targets {
			if nativePeerMatchesPod(peer, pod, targetNamespace, policyNamespace) {
				return true
			}
			if pod.Status.PodIP != "" && ipBlockContains(peer.IPBlock, pod.Status.PodIP) {
				return true
			}
		}
	}
	return false
}

func nativeIngressRuleAllows(rule networkingv1.NetworkPolicyIngressRule, source corev1.Pod, sourceNamespace corev1.Namespace, ports []int32) bool {
	if !nativePortsAllow(rule.Ports, ports) {
		return false
	}
	if len(rule.From) == 0 {
		return true
	}
	for _, peer := range rule.From {
		if nativePeerMatchesPod(peer, source, sourceNamespace, "") {
			return true
		}
		if source.Status.PodIP != "" && ipBlockContains(peer.IPBlock, source.Status.PodIP) {
			return true
		}
	}
	return false
}

func nativePeerMatchesPod(peer networkingv1.NetworkPolicyPeer, pod corev1.Pod, namespace corev1.Namespace, policyNamespace string) bool {
	if peer.NamespaceSelector == nil && peer.PodSelector == nil {
		return false
	}
	if peer.NamespaceSelector != nil {
		nsSelector, err := metav1.LabelSelectorAsSelector(peer.NamespaceSelector)
		if err != nil || !nsSelector.Matches(labels.Set(namespace.Labels)) {
			return false
		}
	} else if policyNamespace != "" && namespace.Name != policyNamespace {
		return false
	}
	if peer.PodSelector != nil {
		podSelector, err := metav1.LabelSelectorAsSelector(peer.PodSelector)
		if err != nil || !podSelector.Matches(labels.Set(pod.Labels)) {
			return false
		}
	}
	return true
}

func nativePortsAllow(policyPorts []networkingv1.NetworkPolicyPort, ports []int32) bool {
	if len(policyPorts) == 0 || len(ports) == 0 {
		return true
	}
	for _, policyPort := range policyPorts {
		if policyPort.Protocol != nil && *policyPort.Protocol != corev1.ProtocolTCP {
			continue
		}
		if policyPort.Port == nil {
			return true
		}
		for _, port := range ports {
			if policyPort.Port.Type == intstr.Int && int32(policyPort.Port.IntValue()) == port {
				return true
			}
		}
	}
	return false
}

func selectedConnectionPortCandidates(service *corev1.Service, containerPorts []containerPort, requested int32) []int32 {
	if service == nil || len(service.Spec.Ports) == 0 {
		return nil
	}
	selected, ok := selectServicePort(service, requested)
	if !ok {
		return nil
	}
	seen := map[int32]bool{}
	var out []int32
	add := func(value int32) {
		if value > 0 && !seen[value] {
			seen[value] = true
			out = append(out, value)
		}
	}
	add(selected.Port)
	if selected.TargetPort.Type == intstr.Int {
		add(int32(selected.TargetPort.IntValue()))
	} else if selected.TargetPort.Type == intstr.String {
		for _, port := range containerPorts {
			if port.PortName == selected.TargetPort.StrVal {
				add(port.Port)
			}
		}
	}
	sort.Slice(out, func(i, j int) bool { return out[i] < out[j] })
	return out
}

func nativePolicyNames(policies []networkingv1.NetworkPolicy) []string {
	var names []string
	for _, policy := range policies {
		names = append(names, policy.Name)
	}
	return uniqueStrings(names)
}

func formatPorts(ports []int32) string {
	if len(ports) == 0 {
		return "(unknown)"
	}
	var values []string
	for _, port := range ports {
		values = append(values, fmt.Sprintf("%d", port))
	}
	return strings.Join(values, ", ")
}

func serviceName(service *corev1.Service) string {
	if service == nil {
		return "(unknown service)"
	}
	if service.Namespace == "" {
		return service.Name
	}
	return service.Namespace + "/" + service.Name
}

func ipBlockContains(block *networkingv1.IPBlock, address string) bool {
	if block == nil || block.CIDR == "" || address == "" {
		return false
	}
	ip, err := netip.ParseAddr(address)
	if err != nil {
		return false
	}
	prefix, err := netip.ParsePrefix(block.CIDR)
	if err != nil {
		return false
	}
	if !prefix.Contains(ip) {
		return false
	}
	for _, except := range block.Except {
		exceptPrefix, err := netip.ParsePrefix(except)
		if err == nil && exceptPrefix.Contains(ip) {
			return false
		}
	}
	return true
}

func contains(values []string, needle string) bool {
	for _, value := range values {
		if value == needle {
			return true
		}
	}
	return false
}
