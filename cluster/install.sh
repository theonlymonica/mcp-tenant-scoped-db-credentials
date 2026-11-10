#!/usr/bin/env bash
# Create the kind cluster, install Calico, and create the namespaces.
set -euo pipefail
source "$(dirname "$0")/../lib/common.sh"
HERE="$REPO_ROOT/cluster"

if ! kind get clusters 2>/dev/null | grep -qx "$CLUSTER_NAME"; then
  kind create cluster --config "$HERE/kind-cluster.yaml"
fi
kubectl config use-context "kind-$CLUSTER_NAME" >/dev/null

kubectl apply -f "$HERE/calico.yaml" >/dev/null
kubectl -n kube-system rollout status daemonset/calico-node --timeout=300s
kubectl wait --for=condition=Ready nodes --all --timeout=300s
load_image registry.k8s.io/kubectl:v1.37.2
kubectl apply -f "$HERE/cni-token-renewer.yaml" >/dev/null

kubectl apply -f "$HERE/namespaces.yaml"
