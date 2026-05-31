#!/usr/bin/env bash
set -euo pipefail

tmp_root="C:/util/kubenetmods/.tmp-istio-authz-live/$$"
mkdir -p "$tmp_root"

curl_pod="$(kubectl get pod -n src -l app=curl -o jsonpath='{.items[0].metadata.name}')"

apply_manifest() {
  kubectl apply -f - >/dev/null
  sleep 12
}

reset_authz() {
  kubectl delete authorizationpolicy --all -n app --ignore-not-found=true >/dev/null 2>&1 || true
  local count
  for _ in 1 2 3 4 5 6 7 8 9 10; do
    count="$(kubectl get authorizationpolicy -n app --no-headers 2>/dev/null | wc -l | tr -d ' ')"
    if [[ "$count" == "0" ]]; then
      sleep 4
      return
    fi
    sleep 2
  done
  sleep 8
}

run_case() {
  local name="$1"
  local path="$2"
  local expect="$3"
  local expect_fail="${4:-true}"
  local json="$tmp_root/$name.json"
  local attempt
  local exit_code=1
  local text=""
  local fail_count="0"

  for attempt in 1 2 3 4 5; do
    set +e
    MSYS_NO_PATHCONV=1 knm check service \
      --namespace app \
      --service echo-denied \
      --source-namespace src \
      --source-pod "$curl_pod" \
      --port 80 \
      --path "$path" \
      --quiet \
      --json "$json" \
      --timeout 4 >/dev/null
    exit_code=$?
    set -e

    if [[ ! -f "$json" ]]; then
      printf 'FAIL %-30s report not written exit=%s\n' "$name" "$exit_code"
      return 1
    fi

  text="$(grep -oE 'Istio AuthorizationPolicy|CUSTOM AuthorizationPolicy|external auth providers|ALLOW AuthorizationPolicy|allow policies|RequestAuthentication|JWT|rule [0-9]+|provider \"[^\"]+\"|Envoy returned HTTP 403|HTTP status: 200' "$json" | tr '\n' ' ')"
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
      printf 'PASS %-30s exit=%s fails=%s expect=%s attempt=%s\n' "$name" "$exit_code" "$fail_count" "${expect:-none}" "$attempt"
      return 0
    fi

    sleep 10
  done

  printf 'FAIL %-30s exit=%s fails=%s expect=%s got=%s\n' "$name" "$exit_code" "$fail_count" "${expect:-none}" "$text"
  return 1
}

restore_rule4_shape() {
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

failures=0

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
run_case "rule5_specific_deny" "/api/items" "rule 5" true || failures=$((failures + 1))

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
        ports: ["80"]
        methods: ["POST"]
  - from:
    - source:
        namespaces: ["other"]
  - to:
    - operation:
        ports: ["80"]
        paths: ["/admin*"]
YAML
run_case "nonmatching_denies_pass" "/" "" false || failures=$((failures + 1))

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
run_case "allow_default_deny" "/" "ALLOW AuthorizationPolicy" true || failures=$((failures + 1))

reset_authz
apply_manifest <<'YAML'
apiVersion: security.istio.io/v1
kind: AuthorizationPolicy
metadata:
  name: allow-other
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
---
apiVersion: security.istio.io/v1
kind: AuthorizationPolicy
metadata:
  name: allow-all
  namespace: app
spec:
  action: ALLOW
  selector:
    matchLabels:
      app: echo-denied
  rules:
  - {}
YAML
run_case "multiple_allow_one_matches" "/" "" false || failures=$((failures + 1))

reset_authz
apply_manifest <<'YAML'
apiVersion: security.istio.io/v1
kind: AuthorizationPolicy
metadata:
  name: deny-near-misses
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
        ports: ["80"]
        methods: ["POST"]
  - from:
    - source:
        namespaces: ["other"]
  - to:
    - operation:
        ports: ["80"]
        paths: ["/admin*"]
---
apiVersion: security.istio.io/v1
kind: AuthorizationPolicy
metadata:
  name: allow-other
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
---
apiVersion: security.istio.io/v1
kind: AuthorizationPolicy
metadata:
  name: allow-all
  namespace: app
spec:
  action: ALLOW
  selector:
    matchLabels:
      app: echo-denied
  rules:
  - {}
YAML
run_case "near_miss_deny_allow_matches" "/" "" false || failures=$((failures + 1))

reset_authz
kubectl delete requestauthentication --all -n app --ignore-not-found=true >/dev/null 2>&1 || true
sleep 8
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
run_case "jwt_request_principal_missing" "/" "RequestAuthentication" true || failures=$((failures + 1))
kubectl delete requestauthentication echo-denied-jwt -n app >/dev/null 2>&1 || true
sleep 8

reset_authz
apply_manifest <<'YAML'
apiVersion: security.istio.io/v1
kind: AuthorizationPolicy
metadata:
  name: custom-echo-denied
  namespace: app
spec:
  action: CUSTOM
  provider:
    name: corp-authz
  selector:
    matchLabels:
      app: echo-denied
  rules:
  - {}
---
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
  - {}
YAML
run_case "deny_wins_over_custom" "/" "rule 1" true || failures=$((failures + 1))

reset_authz
restore_rule4_shape
run_case "restored_rule4_deny" "/" "rule 4" true || failures=$((failures + 1))

restore_rule4_shape
kubectl delete requestauthentication --all -n app --ignore-not-found=true >/dev/null 2>&1 || true

if [[ "$failures" -gt 0 ]]; then
  echo "FAILED $failures case(s). Reports in $tmp_root"
  exit 1
fi

echo "All adversarial Istio authz live cases passed. Reports in $tmp_root"
