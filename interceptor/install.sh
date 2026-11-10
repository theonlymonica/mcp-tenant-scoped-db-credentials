#!/usr/bin/env bash
# Build the Interceptor image and deploy it with its Envoy front and OPA.
set -euo pipefail
source "$(dirname "$0")/../lib/common.sh"
HERE="$REPO_ROOT/interceptor"

docker build -q -t interceptor:1.0.0 "$HERE" >/dev/null
kind load docker-image interceptor:1.0.0 --name "$CLUSTER_NAME" >/dev/null 2>&1
log "image interceptor:1.0.0 built and loaded"
load_image envoyproxy/envoy:distroless-v1.40.2
load_image openpolicyagent/opa:1.22.2-static

kubectl -n interceptor create configmap opa-policy --from-file=policy.rego="$REPO_ROOT/opa/policy.rego" \
  --dry-run=client -o yaml | kubectl apply -f - >/dev/null
# The CA that signed the OpenBao and Keycloak server certificates (lib/tls.sh):
# a ConfigMap is read from the pod's own namespace, so it is copied here.
kubectl -n interceptor create configmap platform-ca --from-file=ca.crt="$WORK/ca/ca.crt" \
  --dry-run=client -o yaml | kubectl apply -f - >/dev/null
kubectl apply -f "$HERE/interceptor.yaml" >/dev/null
kubectl -n interceptor rollout restart deployment/interceptor >/dev/null
kubectl -n interceptor rollout status deployment/interceptor --timeout=300s
