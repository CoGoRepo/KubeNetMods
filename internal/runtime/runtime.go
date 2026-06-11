package runtime

import (
	"context"
	"fmt"
	"net/url"
	"regexp"
	"sort"
	"strconv"
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

type MTURouteSnapshot struct {
	Target            string
	Dev               string
	Src               string
	MTU               int
	RouteMTU          int
	LinkMTU           int
	Route             string
	Link              string
	RouteDetected     bool
	InterfaceFallback bool
}

func SelectReadyPod(pods []corev1.Pod) *corev1.Pod {
	for i := range pods {
		if pods[i].Status.Phase == corev1.PodRunning && podReady(pods[i]) {
			return &pods[i]
		}
	}
	return nil
}

func podReady(pod corev1.Pod) bool {
	for _, condition := range pod.Status.Conditions {
		if condition.Type == corev1.PodReady && condition.Status == corev1.ConditionTrue {
			return true
		}
	}
	return false
}
func BuildServiceURLs(service *corev1.Service, namespace, name, scheme, path string, port int32) []string {
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

func ExecShell(ctx context.Context, target ExecTarget, command string) (string, string, error) {
	res, err := target.Client.Exec(ctx, target.Pod.Namespace, target.Pod.Name, target.Container, []string{"sh", "-c", command})
	return strings.TrimSpace(res.Stdout), strings.TrimSpace(res.Stderr), err
}

func ReadResolvConf(ctx context.Context, target ExecTarget) (ResolvConf, error) {
	stdout, stderr, err := ExecShell(ctx, target, "cat /etc/resolv.conf")
	if err != nil {
		if stderr != "" {
			return ResolvConf{}, fmt.Errorf("%v: %s", err, stderr)
		}
		return ResolvConf{}, err
	}
	return ParseResolvConf(stdout), nil
}

func ParseResolvConf(text string) ResolvConf {
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
		Nameservers: UniqueStrings(nameservers),
		Searches:    UniqueStrings(searches),
		Raw:         text,
	}
}

func ReadMTURouteSnapshot(ctx context.Context, target ExecTarget, targetIP string) (MTURouteSnapshot, error) {
	snapshot := MTURouteSnapshot{Target: targetIP}
	dev := ""
	if targetIP != "" {
		stdout, stderr, err := ExecShell(ctx, target, "ip route get "+ShellQuote(targetIP))
		if err == nil {
			snapshot.Route = stdout
			snapshot.Dev = RouteField(stdout, "dev")
			snapshot.Src = RouteField(stdout, "src")
			snapshot.RouteDetected = snapshot.Dev != ""
			if mtu := RouteMTU(stdout); mtu > 0 {
				snapshot.RouteMTU = mtu
			}
			dev = snapshot.Dev
		} else if stderr != "" {
			snapshot.Route = strings.TrimSpace(stderr)
		}
	}
	if dev == "" {
		dev = "eth0"
		snapshot.Dev = dev
		snapshot.InterfaceFallback = true
	}
	stdout, stderr, err := ExecShell(ctx, target, "ip -o link show dev "+ShellQuote(dev))
	if err != nil {
		if stderr != "" {
			return snapshot, fmt.Errorf("%v: %s", err, stderr)
		}
		return snapshot, err
	}
	snapshot.Link = stdout
	if mtu := LinkMTU(stdout); mtu > 0 {
		snapshot.LinkMTU = mtu
		snapshot.MTU = mtu
	} else if snapshot.RouteMTU > 0 {
		snapshot.MTU = snapshot.RouteMTU
	}
	return snapshot, nil
}

func RouteField(text, name string) string {
	pattern := regexp.MustCompile(`(?:^|\s)` + regexp.QuoteMeta(name) + `\s+(\S+)`)
	match := pattern.FindStringSubmatch(text)
	if len(match) == 2 {
		return strings.TrimSpace(match[1])
	}
	return ""
}

func RouteMTU(text string) int {
	return NumericRouteField(text, "mtu")
}

func LinkMTU(text string) int {
	return NumericRouteField(text, "mtu")
}

func NumericRouteField(text, name string) int {
	value := RouteField(text, name)
	if value == "" {
		return 0
	}
	parsed, err := strconv.Atoi(value)
	if err != nil {
		return 0
	}
	return parsed
}

func ResolveHost(ctx context.Context, target ExecTarget, host string) error {
	command := fmt.Sprintf("if command -v nslookup >/dev/null 2>&1; then nslookup %s >/dev/null 2>&1; elif command -v getent >/dev/null 2>&1; then getent hosts %s >/dev/null 2>&1; else echo 'no resolver tool available: nslookup/getent' >&2; exit 127; fi", ShellQuote(host), ShellQuote(host))
	_, stderr, err := ExecShell(ctx, target, command)
	if err != nil {
		if stderr != "" {
			return fmt.Errorf("%v: %s", err, stderr)
		}
		return err
	}
	return nil
}

func CurlURL(ctx context.Context, target ExecTarget, rawURL string, timeout time.Duration, headers map[string]string) RuntimeHTTPResult {
	seconds := int(timeout.Seconds())
	if seconds <= 0 {
		seconds = 5
	}
	var headerArgs []string
	for key, value := range headers {
		headerArgs = append(headerArgs, "-H "+ShellQuote(key+": "+value))
	}
	sort.Strings(headerArgs)
	command := fmt.Sprintf("curl -k -sS -i -w '\\nHTTP_STATUS=%%{http_code}' --connect-timeout %d --max-time %d %s %s", seconds, seconds, strings.Join(headerArgs, " "), ShellQuote(rawURL))
	stdout, stderr, err := ExecShell(ctx, target, command)
	result := RuntimeHTTPResult{URL: rawURL, Output: stdout}
	result.StatusCode = HTTPStatus(stdout)
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

func ClassifyRuntimeHTTPFailure(result RuntimeHTTPResult) RuntimeFailureClassification {
	text := strings.ToLower(result.Error + " " + result.Output)
	switch {
	case IsRuntimeUnavailableText(text):
		return RuntimeFailureClassification{
			Kind:      "runtime-unavailable",
			Summary:   "runtime probe could not run in the source pod",
			Diagnosis: "The selected source pod does not have usable exec/runtime tooling for this check. Static Kubernetes/CNI/Istio analysis still ran, but live DNS/curl proof is unavailable.",
		}
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

func IsRuntimeUnavailableError(err error) bool {
	if err == nil {
		return false
	}
	return IsRuntimeUnavailableText(err.Error())
}

func IsRuntimeUnavailableText(text string) bool {
	text = strings.ToLower(text)
	switch {
	case strings.Contains(text, "no resolver tool available"):
		return true
	case strings.Contains(text, "executable file not found") && strings.Contains(text, "sh"):
		return true
	case strings.Contains(text, "stat sh") && strings.Contains(text, "no such file"):
		return true
	case strings.Contains(text, "curl: not found"):
		return true
	case strings.Contains(text, "curl: command not found"):
		return true
	case strings.Contains(text, "sh: curl: not found"):
		return true
	case strings.Contains(text, "pods/exec") && strings.Contains(text, "forbidden"):
		return true
	case strings.Contains(text, "cannot create resource") && strings.Contains(text, "pods/exec"):
		return true
	case strings.Contains(text, "is forbidden") && strings.Contains(text, "exec"):
		return true
	default:
		return false
	}
}

func RuntimeProbeFailureMessage(target ExecTarget, rawURL string, result RuntimeHTTPResult, classification RuntimeFailureClassification) string {
	if classification.Diagnosis == "" {
		return fmt.Sprintf("%s %q could not reach %s. %s", target.Kind, target.Pod.Name, rawURL, result.Error)
	}
	switch classification.Kind {
	case "runtime-unavailable":
		return fmt.Sprintf("Skipped live probe to %s from %s %q because runtime exec/tooling is unavailable. %s", rawURL, target.Kind, target.Pod.Name, result.Error)
	case "tls-client-cert-required", "tls-certificate-validation", "tls-protocol-mismatch", "application-protocol-mismatch":
		return fmt.Sprintf("%s probe to %s failed from %s %q. %s", ProbeLabel(classification), rawURL, target.Kind, target.Pod.Name, result.Error)
	default:
		return fmt.Sprintf("%s %q could not reach %s. %s", target.Kind, target.Pod.Name, rawURL, result.Error)
	}
}

func DirectPodProbeFailureMessage(target ExecTarget, rawURL string, result RuntimeHTTPResult, classification RuntimeFailureClassification) string {
	if classification.Diagnosis == "" {
		return fmt.Sprintf("%s failed from %s %q.", rawURL, target.Kind, target.Pod.Name)
	}
	switch classification.Kind {
	case "runtime-unavailable":
		return fmt.Sprintf("Skipped live direct pod probe to %s from %s %q because runtime exec/tooling is unavailable. %s", rawURL, target.Kind, target.Pod.Name, result.Error)
	case "tls-client-cert-required", "tls-certificate-validation", "tls-protocol-mismatch", "application-protocol-mismatch":
		return fmt.Sprintf("%s probe to %s failed from %s %q. %s", ProbeLabel(classification), rawURL, target.Kind, target.Pod.Name, result.Error)
	default:
		return fmt.Sprintf("%s failed from %s %q.", rawURL, target.Kind, target.Pod.Name)
	}
}

func ProbeLabel(classification RuntimeFailureClassification) string {
	switch classification.Kind {
	case "tls-client-cert-required", "tls-certificate-validation", "tls-protocol-mismatch":
		return "TLS/protocol"
	case "application-protocol-mismatch":
		return "Protocol"
	default:
		return "HTTP"
	}
}

func HostFromURL(rawURL string) string {
	parsed, err := url.Parse(rawURL)
	if err != nil {
		return ""
	}
	return parsed.Hostname()
}

func HTTPStatus(text string) string {
	match := regexp.MustCompile(`HTTP_STATUS=(\d{3})`).FindStringSubmatch(text)
	if len(match) == 2 {
		return match[1]
	}
	return "unknown"
}

func ShellQuote(value string) string {
	return "'" + strings.ReplaceAll(value, "'", "'\"'\"'") + "'"
}

func UniqueStrings(values []string) []string {
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
