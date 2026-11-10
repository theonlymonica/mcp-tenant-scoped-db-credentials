#!/usr/bin/env bash
# Delete the cluster and the generated material in .tmp/.
set -euo pipefail
cd "$(dirname "$0")"
kind delete cluster --name mcp-tenants
rm -rf .tmp
