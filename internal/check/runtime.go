package check

import (
	"context"
	"fmt"
	"net/url"
	"regexp"
	"sort"
	"strings"
	"time"

	"github.com/CoGoRepo/KubeNetMods/internal/kube"
	corev1 "k8s.io/api/core/v1"
)

type ExecTarget struct {
	Client    *kube.Client
	Pod       corev1.Pod
	Container string
	Kind      string
}

type RuntimeHTTPResult struct {
	URL        string
	OK         bool
	StatusCode string
	Output     string
	Error      string
}

type RuntimeFailureClassification struct {
	Kind      string
	Summary   string
	Diagnosis string
}

type ResolvConf struct {
	Nameservers []string
	Searches    []string
	Raw         string
}

func selectReadyPod(pods []corev1.Pod) *corev1.Pod {
	for i := range pods {
		if pods[i].Status.Phase == corev1.PodRunning && podReady(pods[i]) {
			return &pods[i]
		}
	}
	return nil
}

func buildServiceURLs(service *corev1.Service, namespace, name, scheme, path string, port int32) []string {
	if service == nil {
		return nil
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
		if service.Spec.ExternalName == "" {
			return nil
		}
		return []string{fmt.Sprintf("%s://%s:%d%s", scheme, service.Spec.ExternalName, port, path)}
	}
	fqdn := fmt.Sprintf("%s.%s.svc.cluster.local", name, namespace)
	out := []string{
		fmt.Sprintf("%s://%s:%d%s", scheme, name, port, path),
		fmt.Sprintf("%s://%s:%d%s", scheme, fqdn, port, path),
	}
	if service.Spec.ClusterIP != "" && service.Spec.ClusterIP != "None" {
		out = append(out, fmt.Sprintf("%s://%s:%d%s", scheme, service.Spec.ClusterIP, port, path))
	}
	return out
}

func execShell(ctx context.Context, target ExecTarget, command string) (string, string, error) {
	res, err := target.Client.Exec(ctx, target.Pod.Namespace, target.Pod.Name, target.Container, []string{"sh", "-c", command})
	return strings.TrimSpace(res.Stdout), strings.TrimSpace(res.Stderr), err
}

func readResolvConf(ctx context.Context, target ExecTarget) (ResolvConf, error) {
	stdout, stderr, err := execShell(ctx, target, "cat /etc/resolv.conf")
	if err != nil {
		if stderr != "" {
			return ResolvConf{}, fmt.Errorf("%v: %s", err, stderr)
		}
		return ResolvConf{}, err
	}
	return parseResolvConf(stdout), nil
}

func parseResolvConf(text string) ResolvConf {
	var nameservers, searches []string
	for _, line := range strings.Split(text, "\n") {
		fields := strings.Fields(strings.TrimSpace(line))
		if len(fields) == 0 || strings.HasPrefix(fields[0], "#") {
			continue
		}
		switch fields[0] {
		case "nameserver":
			if len(fields) > 1 {
				nameservers = append(nameservers, fields[1])
			}
		case "search":
			if len(fields) > 1 {
				searches = append(searches, fields[1:]...)
			}
		}
	}
	return ResolvConf{
		Nameservers: uniqueStrings(nameservers),
		Searches:    uniqueStrings(searches),
		Raw:         text,
	}
}

func resolveHost(ctx context.Context, target ExecTarget, host string) error {
	command := fmt.Sprintf("nslookup %s >/dev/null 2>&1 || getent hosts %s >/dev/null 2>&1", shellQuote(host), shellQuote(host))
	_, stderr, err := execShell(ctx, target, command)
	if err != nil {
		if stderr != "" {
			return fmt.Errorf("%v: %s", err, stderr)
		}
		return err
	}
	return nil
}

func curlURL(ctx context.Context, target ExecTarget, rawURL string, timeout time.Duration) RuntimeHTTPResult {
	seconds := int(timeout.Seconds())
	if seconds <= 0 {
		seconds = 5
	}
	command := fmt.Sprintf("curl -k -sS -o /dev/null -w 'HTTP_STATUS=%%{http_code}' --connect-timeout %d --max-time %d %s", seconds, seconds, shellQuote(rawURL))
	stdout, stderr, err := execShell(ctx, target, command)
	result := RuntimeHTTPResult{URL: rawURL, Output: stdout}
	result.StatusCode = httpStatus(stdout)
	if err != nil {
		result.Error = strings.TrimSpace(stderr)
		if result.Error == "" {
			result.Error = err.Error()
		}
		return result
	}
	result.OK = true
	return result
}

func classifyRuntimeHTTPFailure(result RuntimeHTTPResult) RuntimeFailureClassification {
	text := strings.ToLower(result.Error + " " + result.Output)
	switch {
	case strings.Contains(text, "certificate required") || strings.Contains(text, "alert certificate required"):
		return RuntimeFailureClassification{
			Kind:      "tls-client-cert-required",
			Summary:   "TLS handshake reached the target, but the server required a client certificate",
			Diagnosis: "Connectivity appears present; validate mTLS/client certificate requirements, protocol mode, and client credentials.",
		}
	case strings.Contains(text, "certificate verify failed") || strings.Contains(text, "unknown ca") || strings.Contains(text, "self signed certificate"):
		return RuntimeFailureClassification{
			Kind:      "tls-certificate-validation",
			Summary:   "TLS handshake reached the target, but certificate validation failed",
			Diagnosis: "Connectivity appears present; validate certificate trust, CA bundle, SNI, and TLS settings.",
		}
	case strings.Contains(text, "wrong version number") || strings.Contains(text, "http request to https") || strings.Contains(text, "https") && strings.Contains(text, "plain http"):
		return RuntimeFailureClassification{
			Kind:      "tls-protocol-mismatch",
			Summary:   "target was reachable, but TLS/cleartext protocol negotiation failed",
			Diagnosis: "Connectivity appears present; validate whether this endpoint expects HTTP, HTTPS, gRPC, or another protocol.",
		}
	case strings.Contains(text, "received http/0.9 when not allowed") || strings.Contains(text, "unsupported protocol") || strings.Contains(text, "malformed") || strings.Contains(text, "empty reply from server"):
		return RuntimeFailureClassification{
			Kind:      "application-protocol-mismatch",
			Summary:   "target was reachable, but the response did not look like normal HTTP",
			Diagnosis: "Connectivity appears present; validate the application protocol, scheme, path, and whether the endpoint expects gRPC, raw TCP, HTTPS, or a non-HTTP protocol.",
		}
	case strings.Contains(text, "connection refused"):
		return RuntimeFailureClassification{
			Kind:      "connection-refused",
			Summary:   "target IP and port were reachable, but the connection was refused",
			Diagnosis: "Check whether the application is listening on the tested port, the Service targetPort, and container listener configuration.",
		}
	case strings.Contains(text, "could not resolve host") || strings.Contains(text, "name or service not known") || strings.Contains(text, "no such host"):
		return RuntimeFailureClassification{
			Kind:      "dns-resolution",
			Summary:   "DNS resolution failed",
			Diagnosis: "Check source pod DNS configuration, CoreDNS/NodeLocalDNS health, search domains, and DNS egress policy.",
		}
	}
	return RuntimeFailureClassification{}
}

func runtimeProbeFailureMessage(target ExecTarget, rawURL string, result RuntimeHTTPResult, classification RuntimeFailureClassification) string {
	if classification.Diagnosis == "" {
		return fmt.Sprintf("%s %q could not reach %s. %s", target.Kind, target.Pod.Name, rawURL, result.Error)
	}
	switch classification.Kind {
	case "tls-client-cert-required", "tls-certificate-validation", "tls-protocol-mismatch", "application-protocol-mismatch":
		return fmt.Sprintf("%s probe to %s failed from %s %q. %s", probeLabel(classification), rawURL, target.Kind, target.Pod.Name, result.Error)
	default:
		return fmt.Sprintf("%s %q could not reach %s. %s", target.Kind, target.Pod.Name, rawURL, result.Error)
	}
}

func directPodProbeFailureMessage(target ExecTarget, rawURL string, result RuntimeHTTPResult, classification RuntimeFailureClassification) string {
	if classification.Diagnosis == "" {
		return fmt.Sprintf("%s failed from %s %q.", rawURL, target.Kind, target.Pod.Name)
	}
	switch classification.Kind {
	case "tls-client-cert-required", "tls-certificate-validation", "tls-protocol-mismatch", "application-protocol-mismatch":
		return fmt.Sprintf("%s probe to %s failed from %s %q. %s", probeLabel(classification), rawURL, target.Kind, target.Pod.Name, result.Error)
	default:
		return fmt.Sprintf("%s failed from %s %q.", rawURL, target.Kind, target.Pod.Name)
	}
}

func probeLabel(classification RuntimeFailureClassification) string {
	switch classification.Kind {
	case "tls-client-cert-required", "tls-certificate-validation", "tls-protocol-mismatch":
		return "TLS/protocol"
	case "application-protocol-mismatch":
		return "Protocol"
	default:
		return "HTTP"
	}
}

func hostFromURL(rawURL string) string {
	parsed, err := url.Parse(rawURL)
	if err != nil {
		return ""
	}
	return parsed.Hostname()
}

func httpStatus(text string) string {
	match := regexp.MustCompile(`HTTP_STATUS=(\d{3})`).FindStringSubmatch(text)
	if len(match) == 2 {
		return match[1]
	}
	return "unknown"
}

func shellQuote(value string) string {
	return "'" + strings.ReplaceAll(value, "'", "'\"'\"'") + "'"
}

func uniqueStrings(values []string) []string {
	seen := map[string]bool{}
	var out []string
	for _, value := range values {
		if value == "" || seen[value] {
			continue
		}
		seen[value] = true
		out = append(out, value)
	}
	sort.Strings(out)
	return out
}
