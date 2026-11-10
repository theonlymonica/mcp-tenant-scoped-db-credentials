#!/usr/bin/env bash
# Build the MCP server image and deploy it.
set -euo pipefail
source "$(dirname "$0")/../lib/common.sh"
HERE="$REPO_ROOT/mcp-server"

docker build -q -t mcp-server:1.0.0 "$HERE" >/dev/null
kind load docker-image mcp-server:1.0.0 --name "$CLUSTER_NAME" >/dev/null 2>&1
log "image mcp-server:1.0.0 built and loaded"

kubectl apply -f "$HERE/mcp-server.yaml" >/dev/null
kubectl -n platform rollout restart deployment/mcp-server >/dev/null
kubectl -n platform rollout status deployment/mcp-server --timeout=300s
