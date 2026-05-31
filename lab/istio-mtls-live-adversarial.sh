#!/usr/bin/env bash
set -euo pipefail

tmp_root="C:/util/kubenetmods/.tmp-istio-mtls-live/$$"
mkdir -p "$tmp_root"

cleanup() {
  kubectl delete namespace plain-src --ignore-not-found=true >/dev/null 2>&1 || true
  kubectl delete peerauthentication echo-bad-subset-strict -n app --ignore-not-found=true >/dev/null 2>&1 || true
}
trap cleanup EXIT

cleanup

kubectl apply -f - >/dev/null <<'YAML'
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
sleep 6

plain_pod="$(kubectl get pod -n plain-src -l app=curl -o jsonpath='{.items[0].metadata.name}')"
json="$tmp_root/unmeshed_source_strict_target.json"

set +e
MSYS_NO_PATHCONV=1 knm check service \
  --namespace app \
  --service echo-bad-subset \
  --source-namespace plain-src \
  --source-pod "$plain_pod" \
  --port 80 \
  --quiet \
  --json "$json" \
  --timeout 5 >/dev/null
exit_code=$?
set -e

if [[ ! -f "$json" ]]; then
  echo "FAIL report not written exit=$exit_code"
  exit 1
fi

text="$(grep -oE 'Istio STRICT mTLS|not in the mesh|PeerAuthentication|connection reset' "$json" | tr '\n' ' ')"
fail_count="$(grep -o '"status": "FAIL"' "$json" | wc -l | tr -d ' ')"

if [[ "$exit_code" -ne 0 && "$text" == *"Istio STRICT mTLS"* && "$text" == *"not in the mesh"* ]]; then
  printf 'PASS unmeshed_source_strict_target exit=%s fails=%s\n' "$exit_code" "$fail_count"
  echo "All adversarial Istio mTLS live cases passed. Reports in $tmp_root"
  exit 0
fi

printf 'FAIL unmeshed_source_strict_target exit=%s fails=%s got=%s\n' "$exit_code" "$fail_count" "$text"
exit 1
