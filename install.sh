#!/usr/bin/env bash
# Create the local cluster and install every component, in dependency order.
# About 15 minutes on a first run, most of it pulling and building images.
set -euo pipefail
cd "$(dirname "$0")"

for tool in docker kind kubectl jq openssl curl python3; do
  command -v "$tool" >/dev/null || { echo "missing: $tool" >&2; exit 1; }
done
curl -fsS -m 3 http://localhost:11434/api/version >/dev/null \
  || { echo "Ollama is not running on this machine (http://localhost:11434)" >&2; exit 1; }

python3 tenants/check_tenants.py

bash cluster/install.sh        # kind, Calico, namespaces
bash spire/install.sh          # workload identities
bash postgres/install.sh       # the database and its row-level security
bash openbao/install.sh        # the credential broker
bash keycloak/install.sh       # the users and their tenant
bash interceptor/install.sh    # the Interceptor and OPA
bash mcp-server/install.sh     # the MCP server
bash agentgateway/install.sh   # the gateway
bash kagent/install.sh         # kagent and the agent
kubectl apply -f cluster/network-policies.yaml

echo
echo "Installed. Try it with: bash demo.sh"
