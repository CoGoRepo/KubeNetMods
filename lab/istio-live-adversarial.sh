#!/usr/bin/env bash
set -euo pipefail

tmp_root="C:/util/kubenetmods/.tmp-istio-live/$$"
mkdir -p "$tmp_root"

curl_pod="$(kubectl get pod -n src -l app=curl -o jsonpath='{.items[0].metadata.name}')"

apply_manifest() {
  kubectl apply -f - >/dev/null
  sleep 3
}

run_case() {
  local name="$1"
  local path="$2"
  local expect="$3"
  local expect_fail="${4:-true}"
  shift 4 || true
  local json="$tmp_root/$name.json"

  set +e
  MSYS_NO_PATHCONV=1 knm check service \
    --namespace app \
    --service echo-bad-subset \
    --source-namespace src \
    --source-pod "$curl_pod" \
    --port 80 \
    --path "$path" \
    --quiet \
    --json "$json" \
    --timeout 4 \
    "$@" >/dev/null
  local exit_code=$?
  set -e

  if [[ ! -f "$json" ]]; then
    printf 'FAIL %-28s report not written exit=%s\n' "$name" "$exit_code"
    return 1
  fi

  local text fail_count
  text="$(grep -oE 'HTTP route [0-9]+|Istio VirtualService|Istio Traffic Routing Layer|DestinationRule subset is missing|no matching VirtualService/DestinationRule|weight [0-9]+|Envoy returned HTTP 503|HTTP status: 200' "$json" | tr '\n' ' ')"
  fail_count="$(grep -o '"status": "FAIL"' "$json" | wc -l | tr -d ' ')"

  local ok=true
  if [[ "$expect_fail" == "true" && "$exit_code" -eq 0 ]]; then
    ok=false
  fi
  if [[ "$expect_fail" == "false" && "$exit_code" -ne 0 ]]; then
    ok=false
  fi
  if [[ -n "$expect" && "$text" != *"$expect"* ]]; then
    ok=false
  fi

  if [[ "$ok" == "true" ]]; then
    printf 'PASS %-28s exit=%s fails=%s expect=%s\n' "$name" "$exit_code" "$fail_count" "${expect:-none}"
    return 0
  fi

  printf 'FAIL %-28s exit=%s fails=%s expect=%s got=%s\n' "$name" "$exit_code" "$fail_count" "${expect:-none}" "$text"
  return 1
}

restore_route4_shape() {
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

failures=0

restore_route4_shape
run_case "route4_path_catchall" "/" "HTTP route 4" true || failures=$((failures + 1))

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
run_case "route2_method_trap" "/" "HTTP route 2" true || failures=$((failures + 1))

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
run_case "route3_source_trap" "/" "HTTP route 3" true || failures=$((failures + 1))

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
run_case "route2_query_trap" "/api/items?version=v1" "HTTP route 2" true || failures=$((failures + 1))

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
        exact: /
    route:
    - destination:
        host: echo-bad-subset.app.svc.cluster.local
        subset: v1
  - route:
    - destination:
        host: echo-bad-subset.app.svc.cluster.local
        subset: v2
YAML
run_case "healthy_route_before_bad" "/" "" false || failures=$((failures + 1))

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
    - authority:
        exact: echo-bad-subset
    route:
    - destination:
        host: echo-bad-subset.app.svc.cluster.local
        subset: v2
  - route:
    - destination:
        host: echo-bad-subset.app.svc.cluster.local
        subset: v2
YAML
run_case "route2_authority_trap" "/" "HTTP route 2" true || failures=$((failures + 1))

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
        subset: missing
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
YAML
run_case "missing_subset_routes_default" "/" "" false || failures=$((failures + 1))

restore_route4_shape
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
    - port: 9999
    route:
    - destination:
        host: echo-bad-subset.app.svc.cluster.local
        subset: v2
  - match:
    - port: 80
    route:
    - destination:
        host: echo-bad-subset.app.svc.cluster.local
        subset: v2
YAML
run_case "route2_port_trap" "/" "HTTP route 2" true || failures=$((failures + 1))

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
run_case "route2_header_trap" "/" "HTTP route 2" true --header x-canary=true || failures=$((failures + 1))

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
        subset: v2
      weight: 100
YAML
run_case "weighted_bad_subset" "/" "weight 100" true || failures=$((failures + 1))

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
run_case "source_namespace_config" "/" "Istio VirtualService" true || failures=$((failures + 1))
kubectl delete virtualservice echo-bad-subset-src -n src >/dev/null 2>&1 || true
kubectl delete destinationrule echo-bad-subset-src -n src >/dev/null 2>&1 || true

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
        host: not-real-upstream.app.svc.cluster.local
YAML
run_case "unknown_upstream_does_not_overdiagnose" "/" "" false || failures=$((failures + 1))

restore_route4_shape

if [[ "$failures" -gt 0 ]]; then
  echo "FAILED $failures case(s). Reports in $tmp_root"
  exit 1
fi

echo "All adversarial Istio live cases passed. Reports in $tmp_root"
