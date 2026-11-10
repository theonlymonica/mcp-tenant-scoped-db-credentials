#!/usr/bin/env bash
# Install the Gateway API CRDs, the agentgateway v1.7.0 CRDs and controller, then
# the gateway itself (gateway.yaml).
set -euo pipefail
source "$(dirname "$0")/../lib/common.sh"
HERE="$REPO_ROOT/agentgateway"

sha256() { shasum -a 256 "$1" | awk '{print $1}'; }

GWAPI="$WORK/gateway-api-v1.7.0.yaml"
[[ -s "$GWAPI" ]] || curl -fsSL -o "$GWAPI" \
  https://github.com/kubernetes-sigs/gateway-api/releases/download/v1.7.0/standard-install.yaml
[[ "$(sha256 "$GWAPI")" == 4e2602c4cbe1afbc394d86f4ac6522e1a5263b01133bba1e40a6d1a549e753a1 ]] \
  || die "the Gateway API manifest does not match its pinned checksum"
kubectl apply --server-side --force-conflicts -f "$GWAPI" >/dev/null

rm -rf "$WORK/agentgateway-crds" && mkdir -p "$WORK/agentgateway-crds"
tar xzf "$HERE/vendor/agentgateway-crds-v1.7.0.tgz" -C "$WORK/agentgateway-crds"
for f in "$WORK"/agentgateway-crds/agentgateway-crds/templates/*.yaml; do
  kubectl apply --server-side --force-conflicts -f "$f" >/dev/null
done

kubectl create namespace agentgateway-system --dry-run=client -o yaml | kubectl apply -f - >/dev/null
kubectl apply -n agentgateway-system -f "$HERE/vendor/agentgateway-controller-v1.7.0.yaml" >/dev/null
kubectl -n agentgateway-system rollout status deploy/agentgateway --timeout=180s
until kubectl get gatewayclass agentgateway -o jsonpath='{.status.conditions[?(@.type=="Accepted")].status}' 2>/dev/null | grep -q True; do sleep 2; done

kubectl apply -f "$HERE/gateway.yaml" >/dev/null
until kubectl -n platform get gateway mcp-gateway -o jsonpath='{.status.conditions[?(@.type=="Programmed")].status}' 2>/dev/null | grep -q True; do sleep 2; done
kubectl -n platform rollout status deploy/mcp-gateway --timeout=180s
