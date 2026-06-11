package check

import (
	"context"
	"time"

	checkruntime "github.com/CoGoRepo/KubeNetMods/internal/runtime"
	corev1 "k8s.io/api/core/v1"
)

type ExecTarget = checkruntime.ExecTarget
type RuntimeHTTPResult = checkruntime.RuntimeHTTPResult
type RuntimeFailureClassification = checkruntime.RuntimeFailureClassification
type ResolvConf = checkruntime.ResolvConf
type MTURouteSnapshot = checkruntime.MTURouteSnapshot

func selectReadyPod(pods []corev1.Pod) *corev1.Pod {
	return checkruntime.SelectReadyPod(pods)
}

func buildServiceURLs(service *corev1.Service, namespace, name, scheme, path string, port int32) []string {
	return checkruntime.BuildServiceURLs(service, namespace, name, scheme, path, port)
}

func execShell(ctx context.Context, target ExecTarget, command string) (string, string, error) {
	return checkruntime.ExecShell(ctx, target, command)
}

func readResolvConf(ctx context.Context, target ExecTarget) (ResolvConf, error) {
	return checkruntime.ReadResolvConf(ctx, target)
}

func parseResolvConf(text string) ResolvConf {
	return checkruntime.ParseResolvConf(text)
}

func readMTURouteSnapshot(ctx context.Context, target ExecTarget, targetIP string) (MTURouteSnapshot, error) {
	return checkruntime.ReadMTURouteSnapshot(ctx, target, targetIP)
}

func routeField(text, name string) string {
	return checkruntime.RouteField(text, name)
}

func routeMTU(text string) int {
	return checkruntime.RouteMTU(text)
}

func linkMTU(text string) int {
	return checkruntime.LinkMTU(text)
}

func numericRouteField(text, name string) int {
	return checkruntime.NumericRouteField(text, name)
}

func resolveHost(ctx context.Context, target ExecTarget, host string) error {
	return checkruntime.ResolveHost(ctx, target, host)
}

func curlURL(ctx context.Context, target ExecTarget, rawURL string, timeout time.Duration, headers map[string]string) RuntimeHTTPResult {
	return checkruntime.CurlURL(ctx, target, rawURL, timeout, headers)
}

func classifyRuntimeHTTPFailure(result RuntimeHTTPResult) RuntimeFailureClassification {
	return checkruntime.ClassifyRuntimeHTTPFailure(result)
}

func isRuntimeUnavailableError(err error) bool {
	return checkruntime.IsRuntimeUnavailableError(err)
}

func runtimeProbeFailureMessage(target ExecTarget, rawURL string, result RuntimeHTTPResult, classification RuntimeFailureClassification) string {
	return checkruntime.RuntimeProbeFailureMessage(target, rawURL, result, classification)
}

func directPodProbeFailureMessage(target ExecTarget, rawURL string, result RuntimeHTTPResult, classification RuntimeFailureClassification) string {
	return checkruntime.DirectPodProbeFailureMessage(target, rawURL, result, classification)
}

func probeLabel(classification RuntimeFailureClassification) string {
	return checkruntime.ProbeLabel(classification)
}

func hostFromURL(rawURL string) string {
	return checkruntime.HostFromURL(rawURL)
}

func httpStatus(text string) string {
	return checkruntime.HTTPStatus(text)
}

func shellQuote(value string) string {
	return checkruntime.ShellQuote(value)
}

func uniqueStrings(values []string) []string {
	return checkruntime.UniqueStrings(values)
}
