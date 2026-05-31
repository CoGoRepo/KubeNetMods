#!/usr/bin/env bash
set -euo pipefail

tmp_root="C:/util/kubenetmods/.tmp-istio-mtls-dr-live/$$"
mkdir -p "$tmp_root"

cleanup() {
  kubectl delete peerauthentication echo-open-strict -n app --ignore-not-found=true >/dev/null 2>&1 || true
  kubectl delete destinationrule echo-open-disable-tls -n src --ignore-not-found=true >/dev/null 2>&1 || true
}
trap cleanup EXIT

cleanup

kubectl apply -f - >/dev/null <<'YAML'
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

sleep 12
curl_pod="$(kubectl get pod -n src -l app=curl -o jsonpath='{.items[0].metadata.name}')"
json="$tmp_root/strict_target_destinationrule_disable.json"

set +e
MSYS_NO_PATHCONV=1 knm check service \
  --namespace app \
  --service echo-open \
  --source-namespace src \
  --source-pod "$curl_pod" \
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

text="$(grep -oE 'STRICT mTLS|DestinationRule|DISABLE|upstream connect/reset' "$json" | tr '\n' ' ')"
fail_count="$(grep -o '"status": "FAIL"' "$json" | wc -l | tr -d ' ')"

if [[ "$exit_code" -ne 0 && "$text" == *"STRICT mTLS"* && "$text" == *"DestinationRule"* && "$text" == *"DISABLE"* ]]; then
  printf 'PASS strict_target_destinationrule_disable exit=%s fails=%s\n' "$exit_code" "$fail_count"
  echo "All adversarial Istio DestinationRule mTLS live cases passed. Reports in $tmp_root"
  exit 0
fi

printf 'FAIL strict_target_destinationrule_disable exit=%s fails=%s got=%s\n' "$exit_code" "$fail_count" "$text"
exit 1
