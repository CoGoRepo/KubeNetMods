package check

import (
	"context"
	"crypto/tls"
	"fmt"
	"net/http"
	"net/url"
	"strings"
	"time"

	"github.com/CoGoRepo/KubeNetMods/internal/kube"
	"github.com/CoGoRepo/KubeNetMods/internal/model"
	calicopolicy "github.com/CoGoRepo/KubeNetMods/internal/policy/calico"
	corev1 "k8s.io/api/core/v1"
	networkingv1 "k8s.io/api/networking/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
)

type IngressOptions struct {
	Context          string
	Namespace        string
	Service          string
	IngressURLs      []string
	ExternalURLs     []string
	TestLoadBalancer bool
	Timeout          time.Duration
}

func RunIngress(ctx context.Context, opts IngressOptions) (*model.Report, error) {
	if opts.Namespace == "" {
		opts.Namespace = "default"
	}
	if opts.Service == "" {
		opts.Service = "nginx"
	}
	report := model.NewReport("check ingress", model.Target{Context: opts.Context, Namespace: opts.Namespace, Service: opts.Service})
	client, err := kube.New(opts.Context)
	if err != nil {
		report.Add("Cluster Access", "context", model.StatusFail, err.Error())
		report.Diagnose("Cannot build Kubernetes client. Check kubeconfig, context, and credentials.")
		return report, nil
	}
	if report.Target.Context == "" {
		report.Target.Context = client.Context
	}
	service, err := client.Core.CoreV1().Services(opts.Namespace).Get(ctx, opts.Service, metav1.GetOptions{})
	if err != nil {
		report.Add("Service Layer", "service read", model.StatusFail, fmt.Sprintf("Could not read Service %q: %v", opts.Service, err))
		report.Diagnose("Target Service is missing or unreadable. Ingress backend checks cannot be trusted until the Service exists.")
	} else {
		report.Add("Service Layer", "service read", model.StatusPass, fmt.Sprintf("Service %q exists. Type=%s; Ports=%s", opts.Service, service.Spec.Type, servicePorts(service)))
	}
	checkCalicoIngressSurface(ctx, client, report, service)
	inspectIngressObjects(ctx, client, report, opts, service)
	testIngressURLs(report, opts.IngressURLs, opts.Timeout, "Ingress Reachability Layer")
	if opts.TestLoadBalancer {
		testLoadBalancer(ctx, client, report, opts, service)
	}
	return report, nil
}

func checkCalicoIngressSurface(ctx context.Context, client *kube.Client, report *model.Report, service *corev1.Service) {
	insights, err := calicopolicy.AnalyzeIngressSurface(ctx, client, service)
	if err != nil {
		report.Add("Calico Host Policy Layer", "analysis", model.StatusWarn, fmt.Sprintf("Calico host/forwarded policy analysis failed: %v", err))
		return
	}
	addInsights(report, insights)
}

func inspectIngressObjects(ctx context.Context, client *kube.Client, report *model.Report, opts IngressOptions, service *corev1.Service) {
	ingresses, err := client.Core.NetworkingV1().Ingresses(opts.Namespace).List(ctx, metav1.ListOptions{})
	if err != nil {
		report.Add("Ingress Layer", "ingress list", model.StatusWarn, fmt.Sprintf("Could not list Ingress objects: %v", err))
		return
	}
	matches := 0
	for _, ing := range ingresses.Items {
		for _, rule := range ing.Spec.Rules {
			if rule.HTTP == nil {
				continue
			}
			for _, path := range rule.HTTP.Paths {
				if path.Backend.Service == nil || path.Backend.Service.Name != opts.Service {
					continue
				}
				matches++
				validateIngressBackend(ctx, client, report, opts, service, ing.Name, rule.Host, path.Path, ingressBackendPortString(path.Backend.Service.Port))
			}
		}
		if ing.Spec.DefaultBackend != nil && ing.Spec.DefaultBackend.Service != nil && ing.Spec.DefaultBackend.Service.Name == opts.Service {
			matches++
			validateIngressBackend(ctx, client, report, opts, service, ing.Name, "(defaultBackend)", "/*", ingressBackendPortString(ing.Spec.DefaultBackend.Service.Port))
		}
		if len(ing.Annotations) > 0 {
			report.Add("Ingress Layer", ing.Name+" annotations", model.StatusInfo, fmt.Sprintf("%d annotation(s) present: %s", len(ing.Annotations), annotationKeys(ing.Annotations)))
		}
		if len(ing.Spec.TLS) > 0 {
			for _, tls := range ing.Spec.TLS {
				if tls.SecretName == "" {
					continue
				}
				if _, err := client.Core.CoreV1().Secrets(opts.Namespace).Get(ctx, tls.SecretName, metav1.GetOptions{}); err != nil {
					report.Add("Ingress Layer", ing.Name+" TLS secret", model.StatusFail, fmt.Sprintf("TLS secret %q was not found/readable in namespace %q.", tls.SecretName, opts.Namespace))
					report.Diagnose(fmt.Sprintf("Ingress %q references missing TLS secret %q.", ing.Name, tls.SecretName))
				} else {
					report.Add("Ingress Layer", ing.Name+" TLS secret", model.StatusPass, fmt.Sprintf("TLS secret %q is readable.", tls.SecretName))
				}
			}
		}
		if ing.Spec.IngressClassName != nil && *ing.Spec.IngressClassName != "" {
			if _, err := client.Core.NetworkingV1().IngressClasses().Get(ctx, *ing.Spec.IngressClassName, metav1.GetOptions{}); err != nil {
				report.Add("Ingress Layer", "IngressClass "+*ing.Spec.IngressClassName, model.StatusFail, fmt.Sprintf("IngressClass %q was not found/readable.", *ing.Spec.IngressClassName))
				report.Diagnose(fmt.Sprintf("Ingress references class %q, but that IngressClass is missing or unreadable.", *ing.Spec.IngressClassName))
			} else {
				report.Add("Ingress Layer", "IngressClass "+*ing.Spec.IngressClassName, model.StatusPass, fmt.Sprintf("IngressClass %q exists.", *ing.Spec.IngressClassName))
			}
		}
	}
	if matches == 0 {
		report.Add("Ingress Layer", "service backends", model.StatusInfo, fmt.Sprintf("No Ingress routes in namespace %q point at Service %q.", opts.Namespace, opts.Service))
	} else {
		report.Add("Ingress Layer", "service backends", model.StatusPass, fmt.Sprintf("%d Ingress backend route(s) point at Service %q.", matches, opts.Service))
	}
}

func validateIngressBackend(ctx context.Context, client *kube.Client, report *model.Report, opts IngressOptions, service *corev1.Service, ingress, host, path, backendPort string) {
	report.Add("Ingress Layer", ingress, model.StatusWarn, fmt.Sprintf("Ingress %s host=%s path=%s backendPort=%s points at Service %q.", ingress, host, path, backendPort, opts.Service))
	if service == nil {
		return
	}
	for _, port := range service.Spec.Ports {
		if backendPort == fmt.Sprintf("%d", port.Port) || backendPort == port.Name {
			report.Add("Ingress Layer", ingress+" backend port", model.StatusPass, fmt.Sprintf("Ingress backend port %q matches Service port/name.", backendPort))
			return
		}
	}
	report.Add("Ingress Layer", ingress+" backend port", model.StatusFail, fmt.Sprintf("Ingress backend port %q does not match any port/name on Service %q.", backendPort, opts.Service))
	report.Diagnose(fmt.Sprintf("Ingress %q points at Service %q but backend port %q does not match the Service ports.", ingress, opts.Service, backendPort))
}

func ingressBackendPortString(port networkingv1.ServiceBackendPort) string {
	if port.Name != "" {
		return port.Name
	}
	if port.Number != 0 {
		return fmt.Sprintf("%d", port.Number)
	}
	return "(none)"
}

func testIngressURLs(report *model.Report, urls []string, timeout time.Duration, layer string) {
	if len(urls) == 0 {
		report.Add(layer, "ingress urls", model.StatusSkip, "No explicit URLs were supplied.")
		return
	}
	for _, raw := range urls {
		test := testLocalHTTP(raw, timeout)
		if test.OK {
			report.Add(layer, raw, model.StatusPass, fmt.Sprintf("Reachable. HTTP status: %s", test.Status))
		} else {
			report.Add(layer, raw, model.StatusFail, "Failed: "+test.Error)
			report.Diagnose(fmt.Sprintf("Ingress/external URL %q failed from the local host. Check DNS, load balancer, ingress controller, TLS, host/path rules, and backend service mapping.", raw))
		}
	}
}

func testLoadBalancer(ctx context.Context, client *kube.Client, report *model.Report, opts IngressOptions, service *corev1.Service) {
	targets := append([]string{}, opts.ExternalURLs...)
	if service != nil && service.Spec.Type == corev1.ServiceTypeLoadBalancer {
		port := int32(80)
		if len(service.Spec.Ports) > 0 {
			port = service.Spec.Ports[0].Port
		}
		for _, item := range service.Status.LoadBalancer.Ingress {
			host := item.Hostname
			if host == "" {
				host = item.IP
			}
			if host != "" {
				targets = append(targets, fmt.Sprintf("http://%s:%d/", host, port))
			}
		}
	} else if service != nil {
		report.Add("External Load Balancing Layer", "service type", model.StatusSkip, fmt.Sprintf("Service %q is type %s, not LoadBalancer.", opts.Service, service.Spec.Type))
	}
	testIngressURLs(report, targets, opts.Timeout, "External Load Balancing Layer")
}

type localHTTPResult struct {
	OK     bool
	Status string
	Error  string
}

func testLocalHTTP(raw string, timeout time.Duration) localHTTPResult {
	if _, err := url.ParseRequestURI(raw); err != nil {
		return localHTTPResult{Error: "invalid URL: " + err.Error()}
	}
	client := &http.Client{
		Timeout: timeout,
		Transport: &http.Transport{
			TLSClientConfig: &tls.Config{InsecureSkipVerify: true},
		},
		CheckRedirect: func(req *http.Request, via []*http.Request) error {
			return http.ErrUseLastResponse
		},
	}
	resp, err := client.Get(raw)
	if err != nil {
		return localHTTPResult{Error: err.Error()}
	}
	defer resp.Body.Close()
	if resp.StatusCode < 500 {
		return localHTTPResult{OK: true, Status: fmt.Sprintf("%d", resp.StatusCode)}
	}
	return localHTTPResult{Status: fmt.Sprintf("%d", resp.StatusCode), Error: resp.Status}
}

func annotationKeys(values map[string]string) string {
	keys := make([]string, 0, len(values))
	for key := range values {
		keys = append(keys, key)
	}
	return strings.Join(uniqueStrings(keys), ", ")
}
