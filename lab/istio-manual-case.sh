#!/usr/bin/env bash
set -euo pipefail

case_name="${2:-}"

apply_manifest() {
  kubectl apply -f - >/dev/null
}

wait_for_push() {
  sleep "${1:-8}"
}

curl_pod() {
  kubectl get pod -n src -l app=curl -o jsonpath='{.items[0].metadata.name}'
}

plain_curl_pod() {
  kubectl get pod -n plain-src -l app=curl -o jsonpath='{.items[0].metadata.name}'
}

print_service_cmd() {
  local service="$1"
  local source_ns="$2"
  local source_pod="$3"
  local path="${4:-/}"
  shift 4 || true

  printf '\nRun this KNM command:\n\n'
  printf 'knm check service --namespace app --service %q --source-namespace %q --source-pod %q --port 80 --path %q' "$service" "$source_ns" "$source_pod" "$path"
  for arg in "$@"; do
    printf ' %q' "$arg"
  done
  printf '\n\n'
}

usage() {
  cat <<'EOF'
Usage:
  bash lab/istio-manual-case.sh list
  bash lab/istio-manual-case.sh setup <case>
  bash lab/istio-manual-case.sh run <case>
  bash lab/istio-manual-case.sh restore

Cases:
  authz-rule5-deny
  authz-allow-default-deny
  authz-jwt-missing
  authz-rule4-deny
  route4-bad-subset
  route2-method-trap
  route3-source-trap
  route2-query-trap
  route2-header-trap
  weighted-bad-subset
  source-namespace-route
  mtls-unmeshed-source
  mtls-destinationrule-disable
EOF
}

reset_authz() {
  kubectl delete authorizationpolicy --all -n app --ignore-not-found=true >/dev/null 2>&1 || true
  kubectl delete requestauthentication --all -n app --ignore-not-found=true >/dev/null 2>&1 || true
}

reset_routing() {
  kubectl delete virtualservice echo-bad-subset-src -n src --ignore-not-found=true >/dev/null 2>&1 || true
  kubectl delete destinationrule echo-bad-subset-src -n src --ignore-not-found=true >/dev/null 2>&1 || true
}

reset_mtls() {
  kubectl delete namespace plain-src --ignore-not-found=true >/dev/null 2>&1 || true
  kubectl delete peerauthentication echo-bad-subset-strict -n app --ignore-not-found=true >/dev/null 2>&1 || true
  kubectl delete peerauthentication echo-open-strict -n app --ignore-not-found=true >/dev/null 2>&1 || true
  kubectl delete destinationrule echo-open-disable-tls -n src --ignore-not-found=true >/dev/null 2>&1 || true
}

restore_authz_rule4() {
  reset_authz
  apply_manifest <<'YAML'
apiVersion: security.istio.io/v1
kind: AuthorizationPolicy
metadata:
  name: deny-echo-denied
  namespace: app
spec:
  action: DENY
  selector:
    matchLabels:
      app: echo-denied
  rules:
  - to:
    - operation:
        ports: ["9991"]
  - to:
    - operation:
        ports: ["9992"]
  - to:
    - operation:
        ports: ["9993"]
  - {}
YAML
}

restore_route4() {
  reset_routing
  apply_manifest <<'YAML'
apiVersion: networking.istio.io/v1
kind: VirtualService
metadata:
  name: echo-bad-subset
  namespace: app
spec:
  hosts:
  - echo-bad-subset.app.svc.cluster.local
  http:
  - match:
    - uri:
        exact: /one
    route:
    - destination:
        host: echo-bad-subset.app.svc.cluster.local
        subset: v2
  - match:
    - uri:
        exact: /two
    route:
    - destination:
        host: echo-bad-subset.app.svc.cluster.local
        subset: v2
  - match:
    - uri:
        exact: /three
    route:
    - destination:
        host: echo-bad-subset.app.svc.cluster.local
        subset: v2
  - route:
    - destination:
        host: echo-bad-subset.app.svc.cluster.local
        subset: v2
---
apiVersion: networking.istio.io/v1
kind: DestinationRule
metadata:
  name: echo-bad-subset
  namespace: app
spec:
  host: echo-bad-subset.app.svc.cluster.local
  subsets:
  - name: v1
    labels:
      version: v1
  - name: v2
    labels:
      version: v2
YAML
}

restore_all() {
  restore_authz_rule4
  restore_route4
  reset_mtls
  wait_for_push 8
  echo "Restored default Istio lab shape."
}

setup_case() {
  case "$1" in
    authz-rule5-deny)
      reset_authz
      apply_manifest <<'YAML'
apiVersion: security.istio.io/v1
kind: AuthorizationPolicy
metadata:
  name: deny-echo-denied
  namespace: app
spec:
  action: DENY
  selector:
    matchLabels:
      app: echo-denied
  rules:
  - to:
    - operation:
        ports: ["9991"]
  - to:
    - operation:
        ports: ["8080"]
        methods: ["POST"]
  - from:
    - source:
        namespaces: ["other"]
  - to:
    - operation:
        ports: ["80"]
        paths: ["/admin*"]
  - to:
    - operation:
        ports: ["8080"]
        methods: ["GET"]
        paths: ["/api/items"]
    when:
    - key: destination.port
      values: ["8080"]
YAML
      wait_for_push 12
      print_service_cmd echo-denied src "$(curl_pod)" /api/items
      ;;
    authz-allow-default-deny)
      reset_authz
      apply_manifest <<'YAML'
apiVersion: security.istio.io/v1
kind: AuthorizationPolicy
metadata:
  name: allow-echo-denied
  namespace: app
spec:
  action: ALLOW
  selector:
    matchLabels:
      app: echo-denied
  rules:
  - from:
    - source:
        namespaces: ["other"]
YAML
      wait_for_push 12
      print_service_cmd echo-denied src "$(curl_pod)" /
      ;;
    authz-jwt-missing)
      reset_authz
      apply_manifest <<'YAML'
apiVersion: security.istio.io/v1
kind: RequestAuthentication
metadata:
  name: echo-denied-jwt
  namespace: app
spec:
  selector:
    matchLabels:
      app: echo-denied
  jwtRules:
  - issuer: "https://issuer.example"
---
apiVersion: security.istio.io/v1
kind: AuthorizationPolicy
metadata:
  name: allow-jwt
  namespace: app
spec:
  action: ALLOW
  selector:
    matchLabels:
      app: echo-denied
  rules:
  - from:
    - source:
        requestPrincipals: ["https://issuer.example/*"]
YAML
      wait_for_push 12
      print_service_cmd echo-denied src "$(curl_pod)" /
      ;;
    authz-rule4-deny)
      restore_authz_rule4
      wait_for_push 12
      print_service_cmd echo-denied src "$(curl_pod)" /
      ;;
    route4-bad-subset)
      restore_route4
      wait_for_push 5
      print_service_cmd echo-bad-subset src "$(curl_pod)" /
      ;;
    route2-method-trap)
      reset_routing
      apply_manifest <<'YAML'
apiVersion: networking.istio.io/v1
kind: VirtualService
metadata:
  name: echo-bad-subset
  namespace: app
spec:
  hosts:
  - echo-bad-subset.app.svc.cluster.local
  http:
  - match:
    - method:
        exact: POST
    route:
    - destination:
        host: echo-bad-subset.app.svc.cluster.local
        subset: v2
  - route:
    - destination:
        host: echo-bad-subset.app.svc.cluster.local
        subset: v2
YAML
      wait_for_push 5
      print_service_cmd echo-bad-subset src "$(curl_pod)" /
      ;;
    route3-source-trap)
      reset_routing
      apply_manifest <<'YAML'
apiVersion: networking.istio.io/v1
kind: VirtualService
metadata:
  name: echo-bad-subset
  namespace: app
spec:
  hosts:
  - echo-bad-subset.app.svc.cluster.local
  http:
  - match:
    - sourceLabels:
        app: not-curl
    route:
    - destination:
        host: echo-bad-subset.app.svc.cluster.local
        subset: v2
  - match:
    - sourceNamespace: other
    route:
    - destination:
        host: echo-bad-subset.app.svc.cluster.local
        subset: v2
  - match:
    - sourceNamespace: src
      sourceLabels:
        app: curl
    route:
    - destination:
        host: echo-bad-subset.app.svc.cluster.local
        subset: v2
YAML
      wait_for_push 5
      print_service_cmd echo-bad-subset src "$(curl_pod)" /
      ;;
    route2-query-trap)
      reset_routing
      apply_manifest <<'YAML'
apiVersion: networking.istio.io/v1
kind: VirtualService
metadata:
  name: echo-bad-subset
  namespace: app
spec:
  hosts:
  - echo-bad-subset.app.svc.cluster.local
  http:
  - match:
    - uri:
        prefix: /api
      queryParams:
        version:
          exact: canary
    route:
    - destination:
        host: echo-bad-subset.app.svc.cluster.local
        subset: v2
  - match:
    - uri:
        prefix: /api
      queryParams:
        version:
          exact: v1
    route:
    - destination:
        host: echo-bad-subset.app.svc.cluster.local
        subset: v2
YAML
      wait_for_push 5
      print_service_cmd echo-bad-subset src "$(curl_pod)" '/api/items?version=v1'
      ;;
    route2-header-trap)
      reset_routing
      apply_manifest <<'YAML'
apiVersion: networking.istio.io/v1
kind: VirtualService
metadata:
  name: echo-bad-subset
  namespace: app
spec:
  hosts:
  - echo-bad-subset.app.svc.cluster.local
  http:
  - match:
    - headers:
        x-canary:
          exact: "false"
    route:
    - destination:
        host: echo-bad-subset.app.svc.cluster.local
        subset: v2
  - match:
    - headers:
        x-canary:
          exact: "true"
    route:
    - destination:
        host: echo-bad-subset.app.svc.cluster.local
        subset: v2
YAML
      wait_for_push 5
      print_service_cmd echo-bad-subset src "$(curl_pod)" / --header x-canary=true
      ;;
    weighted-bad-subset)
      reset_routing
      apply_manifest <<'YAML'
apiVersion: networking.istio.io/v1
kind: VirtualService
metadata:
  name: echo-bad-subset
  namespace: app
spec:
  hosts:
  - echo-bad-subset.app.svc.cluster.local
  http:
  - route:
    - destination:
        host: echo-bad-subset.app.svc.cluster.local
        subset: v1
      weight: 90
    - destination:
        host: echo-bad-subset.app.svc.cluster.local
        subset: v2
      weight: 10
YAML
      wait_for_push 5
      print_service_cmd echo-bad-subset src "$(curl_pod)" /
      ;;
    source-namespace-route)
      kubectl delete virtualservice echo-bad-subset -n app >/dev/null 2>&1 || true
      kubectl delete destinationrule echo-bad-subset -n app >/dev/null 2>&1 || true
      apply_manifest <<'YAML'
apiVersion: networking.istio.io/v1
kind: VirtualService
metadata:
  name: echo-bad-subset-src
  namespace: src
spec:
  hosts:
  - echo-bad-subset.app.svc.cluster.local
  http:
  - route:
    - destination:
        host: echo-bad-subset.app.svc.cluster.local
        subset: v2
---
apiVersion: networking.istio.io/v1
kind: DestinationRule
metadata:
  name: echo-bad-subset-src
  namespace: src
spec:
  host: echo-bad-subset.app.svc.cluster.local
  subsets:
  - name: v2
    labels:
      version: v2
YAML
      wait_for_push 5
      print_service_cmd echo-bad-subset src "$(curl_pod)" /
      ;;
    mtls-unmeshed-source)
      reset_mtls
      apply_manifest <<'YAML'
apiVersion: v1
kind: Namespace
metadata:
  name: plain-src
---
apiVersion: apps/v1
kind: Deployment
metadata:
  name: curl
  namespace: plain-src
spec:
  replicas: 1
  selector:
    matchLabels:
      app: curl
  template:
    metadata:
      labels:
        app: curl
    spec:
      containers:
      - name: curl
        image: curlimages/curl:8.17.0
        command: ["sleep", "365d"]
---
apiVersion: security.istio.io/v1
kind: PeerAuthentication
metadata:
  name: echo-bad-subset-strict
  namespace: app
spec:
  selector:
    matchLabels:
      app: echo-bad-subset
  mtls:
    mode: STRICT
YAML
      kubectl rollout status deployment/curl -n plain-src --timeout=90s >/dev/null
      wait_for_push 8
      print_service_cmd echo-bad-subset plain-src "$(plain_curl_pod)" /
      ;;
    mtls-destinationrule-disable)
      reset_mtls
      apply_manifest <<'YAML'
apiVersion: security.istio.io/v1
kind: PeerAuthentication
metadata:
  name: echo-open-strict
  namespace: app
spec:
  selector:
    matchLabels:
      app: echo-open
  mtls:
    mode: STRICT
---
apiVersion: networking.istio.io/v1
kind: DestinationRule
metadata:
  name: echo-open-disable-tls
  namespace: src
spec:
  host: echo-open.app.svc.cluster.local
  trafficPolicy:
    tls:
      mode: DISABLE
YAML
      wait_for_push 12
      print_service_cmd echo-open src "$(curl_pod)" /
      ;;
    *)
      usage
      exit 1
      ;;
  esac
}

run_case() {
  setup_case "$1"
  local pod
  pod="$(curl_pod)"
  case "$1" in
    authz-rule5-deny)
      MSYS_NO_PATHCONV=1 knm check service --namespace app --service echo-denied --source-namespace src --source-pod "$pod" --port 80 --path /api/items
      ;;
    authz-allow-default-deny|authz-jwt-missing|authz-rule4-deny)
      MSYS_NO_PATHCONV=1 knm check service --namespace app --service echo-denied --source-namespace src --source-pod "$pod" --port 80 --path /
      ;;
    route2-query-trap)
      MSYS_NO_PATHCONV=1 knm check service --namespace app --service echo-bad-subset --source-namespace src --source-pod "$pod" --port 80 --path '/api/items?version=v1'
      ;;
    route2-header-trap)
      MSYS_NO_PATHCONV=1 knm check service --namespace app --service echo-bad-subset --source-namespace src --source-pod "$pod" --port 80 --path / --header x-canary=true
      ;;
    route4-bad-subset|route2-method-trap|route3-source-trap|weighted-bad-subset|source-namespace-route)
      MSYS_NO_PATHCONV=1 knm check service --namespace app --service echo-bad-subset --source-namespace src --source-pod "$pod" --port 80 --path /
      ;;
    mtls-unmeshed-source)
      MSYS_NO_PATHCONV=1 knm check service --namespace app --service echo-bad-subset --source-namespace plain-src --source-pod "$(plain_curl_pod)" --port 80 --path /
      ;;
    mtls-destinationrule-disable)
      MSYS_NO_PATHCONV=1 knm check service --namespace app --service echo-open --source-namespace src --source-pod "$pod" --port 80 --path /
      ;;
  esac
}

cmd="${1:-}"
case "$cmd" in
  list)
    usage
    ;;
  setup)
    if [[ -z "$case_name" ]]; then
      usage
      exit 1
    fi
    setup_case "$case_name"
    ;;
  run)
    if [[ -z "$case_name" ]]; then
      usage
      exit 1
    fi
    run_case "$case_name"
    ;;
  restore)
    restore_all
    ;;
  *)
    usage
    exit 1
    ;;
esac
