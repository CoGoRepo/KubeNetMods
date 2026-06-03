package check

import (
	"fmt"
	"net/url"
	"regexp"
	"sort"
	"strings"

	networkingapi "istio.io/api/networking/v1alpha3"
	corev1 "k8s.io/api/core/v1"
	"k8s.io/apimachinery/pkg/labels"
	"k8s.io/apimachinery/pkg/util/intstr"
)

type istioHTTPRequest struct {
	Path                 string
	Scheme               string
	Method               string
	Port                 uint32
	PortText             string
	AuthorityHosts       []string
	QueryParams          map[string]string
	Headers              map[string]string
	SourceNamespace      string
	SourceLabels         map[string]string
	SourceServiceAccount string
	SourcePrincipals     []string
	RequestPrincipals    []string
}

func newIstioHTTPRequest(opts ServiceOptions, service *corev1.Service, source *ExecTarget, rawURL string) istioHTTPRequest {
	path := opts.URLPath
	if path == "" {
		path = "/"
	}
	queryParams := map[string]string{}
	if parsed, err := url.ParseRequestURI(path); err == nil {
		path = parsed.Path
		for key, values := range parsed.Query() {
			if len(values) > 0 {
				queryParams[strings.ToLower(key)] = values[0]
			}
		}
	}
	if path == "" {
		path = "/"
	}
	scheme := opts.URLScheme
	if scheme == "" {
		scheme = "http"
	}
	port := uint32(opts.ServicePort)
	if port == 0 && service != nil && len(service.Spec.Ports) > 0 {
		port = uint32(service.Spec.Ports[0].Port)
	}
	authzPort := port
	if service != nil {
		if selected, ok := selectServicePort(service, opts.ServicePort); ok && selected.TargetPort.Type == intstr.Int && selected.TargetPort.IntVal > 0 {
			authzPort = uint32(selected.TargetPort.IntVal)
		}
	}
	sourceNamespace := opts.SourceNamespace
	sourceServiceAccount := ""
	sourceLabels := map[string]string{}
	if source != nil {
		if sourceNamespace == "" {
			sourceNamespace = source.Pod.Namespace
		}
		sourceServiceAccount = source.Pod.Spec.ServiceAccountName
		if sourceServiceAccount == "" {
			sourceServiceAccount = "default"
		}
		for key, value := range source.Pod.Labels {
			sourceLabels[key] = value
		}
	}
	var sourcePrincipals []string
	if sourceNamespace != "" && sourceServiceAccount != "" {
		sourcePrincipals = append(sourcePrincipals, "cluster.local/ns/"+sourceNamespace+"/sa/"+sourceServiceAccount)
	}
	authorityHosts := istioServiceHosts(service)
	if parsed, err := url.Parse(rawURL); err == nil && parsed.Hostname() != "" {
		host := strings.TrimSuffix(strings.ToLower(parsed.Hostname()), ".")
		authorityHosts = []string{host}
		if parsed.Port() != "" {
			authorityHosts = append(authorityHosts, host+":"+parsed.Port())
		}
	}
	headers := map[string]string{}
	for key, value := range opts.HTTPHeaders {
		headers[strings.ToLower(key)] = value
	}
	return istioHTTPRequest{
		Path:                 path,
		Scheme:               strings.ToLower(scheme),
		Method:               "GET",
		Port:                 port,
		PortText:             fmt.Sprintf("%d", authzPort),
		AuthorityHosts:       authorityHosts,
		QueryParams:          queryParams,
		Headers:              headers,
		SourceNamespace:      sourceNamespace,
		SourceLabels:         sourceLabels,
		SourceServiceAccount: sourceServiceAccount,
		SourcePrincipals:     sourcePrincipals,
		RequestPrincipals:    nil,
	}
}

func istioHTTPRouteMatchesRequest(route *networkingapi.HTTPRoute, request istioHTTPRequest) bool {
	_, ok := istioHTTPRouteMatchText(route, request)
	return ok
}

func istioHTTPRouteMatchText(route *networkingapi.HTTPRoute, request istioHTTPRequest) (string, bool) {
	matches := route.GetMatch()
	if len(matches) == 0 {
		return "catch-all route", true
	}
	for _, match := range matches {
		if match == nil {
			continue
		}
		if istioHTTPMatchRequestMatches(match, request) {
			return istioHTTPMatchRequestSummary(match), true
		}
	}
	return "", false
}

func istioHTTPMatchRequestSummary(match *networkingapi.HTTPMatchRequest) string {
	var parts []string
	if text := istioStringMatchSummary("uri", match.GetUri()); text != "" {
		parts = append(parts, text)
	}
	if text := istioStringMatchSummary("method", match.GetMethod()); text != "" {
		parts = append(parts, text)
	}
	if text := istioStringMatchSummary("scheme", match.GetScheme()); text != "" {
		parts = append(parts, text)
	}
	if match.GetPort() != 0 {
		parts = append(parts, fmt.Sprintf("port=%d", match.GetPort()))
	}
	if match.GetSourceNamespace() != "" {
		parts = append(parts, "sourceNamespace="+match.GetSourceNamespace())
	}
	if len(match.GetSourceLabels()) > 0 {
		parts = append(parts, "sourceLabels "+labels.Set(match.GetSourceLabels()).String())
	}
	if text := istioStringMatchSummary("authority", match.GetAuthority()); text != "" {
		parts = append(parts, text)
	}
	for _, key := range sortedStringMatchKeys(match.GetHeaders()) {
		parts = append(parts, istioStringMatchSummary("header "+key, match.GetHeaders()[key]))
	}
	for _, key := range sortedStringMatchKeys(match.GetWithoutHeaders()) {
		parts = append(parts, "without "+istioStringMatchSummary("header "+key, match.GetWithoutHeaders()[key]))
	}
	for _, key := range sortedStringMatchKeys(match.GetQueryParams()) {
		parts = append(parts, istioStringMatchSummary("query "+key, match.GetQueryParams()[key]))
	}
	if len(parts) == 0 {
		return "empty match"
	}
	return strings.Join(parts, ", ")
}

func sortedStringMatchKeys(values map[string]*networkingapi.StringMatch) []string {
	var keys []string
	for key := range values {
		keys = append(keys, key)
	}
	sort.Strings(keys)
	return keys
}

func istioStringMatchSummary(name string, match *networkingapi.StringMatch) string {
	if match == nil {
		return ""
	}
	switch typed := match.GetMatchType().(type) {
	case *networkingapi.StringMatch_Exact:
		return fmt.Sprintf("%s=%q", name, typed.Exact)
	case *networkingapi.StringMatch_Prefix:
		return fmt.Sprintf("%s prefix %q", name, typed.Prefix)
	case *networkingapi.StringMatch_Regex:
		return fmt.Sprintf("%s regex %q", name, typed.Regex)
	default:
		return ""
	}
}

func istioHTTPMatchRequestMatches(match *networkingapi.HTTPMatchRequest, request istioHTTPRequest) bool {
	if !istioStringMatchMatches(match.GetUri(), request.Path, match.GetIgnoreUriCase()) {
		return false
	}
	if !istioStringMatchMatches(match.GetScheme(), request.Scheme, false) {
		return false
	}
	if !istioStringMatchMatches(match.GetMethod(), request.Method, false) {
		return false
	}
	if match.GetPort() != 0 && request.Port != 0 && match.GetPort() != request.Port {
		return false
	}
	if match.GetSourceNamespace() != "" && match.GetSourceNamespace() != request.SourceNamespace {
		return false
	}
	if len(match.GetSourceLabels()) > 0 && !labels.SelectorFromSet(match.GetSourceLabels()).Matches(labels.Set(request.SourceLabels)) {
		return false
	}
	if !istioAuthorityMatches(match.GetAuthority(), request.AuthorityHosts) {
		return false
	}
	if !istioHeaderMatches(match.GetHeaders(), request.Headers) {
		return false
	}
	if !istioWithoutHeaderMatches(match.GetWithoutHeaders(), request.Headers) {
		return false
	}
	if !istioQueryParamsMatch(match.GetQueryParams(), request.QueryParams) {
		return false
	}
	return true
}

func istioStringMatchMatches(match *networkingapi.StringMatch, value string, ignoreCase bool) bool {
	if match == nil {
		return true
	}
	switch typed := match.GetMatchType().(type) {
	case *networkingapi.StringMatch_Exact:
		exact := typed.Exact
		if ignoreCase {
			value = strings.ToLower(value)
			exact = strings.ToLower(exact)
		}
		return value == exact
	case *networkingapi.StringMatch_Prefix:
		prefix := typed.Prefix
		if ignoreCase {
			value = strings.ToLower(value)
			prefix = strings.ToLower(prefix)
		}
		return strings.HasPrefix(value, prefix)
	case *networkingapi.StringMatch_Regex:
		ok, err := regexp.MatchString(typed.Regex, value)
		return err == nil && ok
	default:
		return true
	}
}

func istioAuthorityMatches(match *networkingapi.StringMatch, authorities []string) bool {
	if match == nil {
		return true
	}
	for _, authority := range authorities {
		if istioStringMatchMatches(match, authority, false) {
			return true
		}
	}
	return false
}

func istioHeaderMatches(matches map[string]*networkingapi.StringMatch, headers map[string]string) bool {
	for key, match := range matches {
		value, ok := headers[strings.ToLower(key)]
		if !ok {
			return false
		}
		if !istioStringMatchMatches(match, value, false) {
			return false
		}
	}
	return true
}

func istioWithoutHeaderMatches(matches map[string]*networkingapi.StringMatch, headers map[string]string) bool {
	for key, match := range matches {
		value, ok := headers[strings.ToLower(key)]
		if !ok {
			continue
		}
		if istioStringMatchMatches(match, value, false) {
			return false
		}
	}
	return true
}

func istioQueryParamsMatch(matches map[string]*networkingapi.StringMatch, params map[string]string) bool {
	for key, match := range matches {
		value, ok := params[strings.ToLower(key)]
		if !ok {
			return false
		}
		if !istioStringMatchMatches(match, value, false) {
			return false
		}
	}
	return true
}
