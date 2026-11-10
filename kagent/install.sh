#!/usr/bin/env bash
# Install the kagent 0.10.6 controller, then build and deploy the agent.
set -euo pipefail
source "$(dirname "$0")/../lib/common.sh"
HERE="$REPO_ROOT/kagent"

kubectl apply --server-side --force-conflicts -f "$HERE/vendor/kagent-crds-0.10.6.yaml" >/dev/null
kubectl wait --for=condition=Established crd/agents.kagent.dev --timeout=60s >/dev/null
kubectl create namespace kagent --dry-run=client -o yaml | kubectl apply -f - >/dev/null
if ! kubectl -n kagent get secret kagent-postgresql >/dev/null 2>&1; then
  kubectl -n kagent create secret generic kagent-postgresql \
    --from-literal=POSTGRES_PASSWORD="$(openssl rand -hex 24)" >/dev/null
fi
kubectl apply -f "$HERE/vendor/kagent-controller-0.10.6.yaml" >/dev/null
kubectl -n kagent rollout status deploy/kagent-controller --timeout=300s

docker build -q -t agent:1.0.0 "$REPO_ROOT/agent" >/dev/null
kind load docker-image agent:1.0.0 --name "$CLUSTER_NAME" >/dev/null 2>&1
log "image agent:1.0.0 built and loaded"

kubectl apply -f "$REPO_ROOT/agent/agent.yaml" >/dev/null
until kubectl -n agents get agent tvm-agent -o jsonpath='{.status.conditions[?(@.type=="Ready")].status}' 2>/dev/null | grep -q True; do sleep 3; done
kubectl -n agents rollout restart deploy/tvm-agent >/dev/null
kubectl -n agents rollout status deploy/tvm-agent --timeout=300s
