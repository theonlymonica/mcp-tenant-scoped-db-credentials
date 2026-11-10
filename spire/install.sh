#!/usr/bin/env bash
# Install SPIRE, in its own namespace, and register the four workload identities.
#
# Each identity is bound to exactly one namespace and one ServiceAccount, and
# the Interceptor's namespace holds nothing else. The agent's SPIFFE ID names
# the software and no tenant: the tenant of a request comes only from the
# user's token.
set -euo pipefail
source "$(dirname "$0")/../lib/common.sh"
HERE="$REPO_ROOT/spire"

load_image ghcr.io/spiffe/spire-server:1.16.0
load_image ghcr.io/spiffe/spire-agent:1.16.0
load_image ghcr.io/spiffe/spiffe-csi-driver:0.3.0
load_image registry.k8s.io/sig-storage/csi-node-driver-registrar:v2.18.0

kubectl apply -f "$HERE/spire-server.yaml" >/dev/null
kubectl -n spire rollout status statefulset/spire-server --timeout=300s
until kubectl -n spire get configmap spire-bundle -o jsonpath='{.data.bundle\.crt}' | grep -q BEGIN; do sleep 2; done

# OpenBao, in `platform`, verifies the Interceptor's certificate against this
# bundle. The SPIRE Server publishes it in its own namespace only, so it is
# copied once, here: the CA lasts a year and this setup does not rotate it.
kubectl -n spire get configmap spire-bundle -o jsonpath='{.data.bundle\.crt}' \
  | kubectl -n platform create configmap spire-bundle --from-file=bundle.crt=/dev/stdin \
      --dry-run=client -o yaml | kubectl apply -f - >/dev/null

kubectl apply -f "$HERE/spire-agent.yaml" >/dev/null
kubectl -n spire rollout status daemonset/spire-agent --timeout=300s

spire() { kubectl -n spire exec spire-server-0 -c spire-server -- /opt/spire/bin/spire-server "$@"; }

# entry SPIFFE_ID [selectors...] — create it unless it already exists
entry() {
  local id="$1"; shift
  if spire entry show -spiffeID "$id" | grep -q "Entry ID"; then return; fi
  spire entry create "$@" -spiffeID "$id" >/dev/null
  log "registered $id"
}

# Every node's agent is a child of one alias, so a workload gets its identity
# on whichever node it is scheduled.
NODE_ALIAS=spiffe://tvm.local/k8s-workload
entry "$NODE_ALIAS" -node \
  -selector "k8s_psat:cluster:$CLUSTER_NAME" \
  -selector k8s_psat:agent_ns:spire \
  -selector k8s_psat:agent_sa:spire-agent

workload() {  # SPIFFE_ID NAMESPACE SERVICEACCOUNT
  entry "$1" -parentID "$NODE_ALIAS" -selector "k8s:ns:$2" -selector "k8s:sa:$3" -x509SVIDTTL 3300
}
workload spiffe://tvm.local/workload/agent        agents   tvm-agent
workload spiffe://tvm.local/platform/mcp-gateway  platform mcp-gateway
workload spiffe://tvm.local/platform/interceptor  interceptor interceptor
workload spiffe://tvm.local/platform/mcp-server   platform mcp-server
