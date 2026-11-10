#!/usr/bin/env bash
# Three requests to the shared agent, as two different users:
#
#   alice (tenant1) reads t1-001    -> the document
#   alice (tenant1) reads t2-001    -> found: false (a tenant2 document)
#   bob   (tenant2) appends to t2-001 -> refused: tenant2 may not use append
#
# The model decides the tool calls, so the wording of its answers varies; the
# tool results printed under each answer are what the system returned.
set -euo pipefail
source "$(dirname "$0")/lib/common.sh"

secret() { kubectl -n platform get secret keycloak-secrets -o jsonpath="{.data.$1}" | base64 -d; }

kubectl -n platform port-forward svc/keycloak 18080:8080 >/dev/null 2>&1 & PF1=$!
kubectl -n kagent port-forward svc/kagent-controller 18083:8083 >/dev/null 2>&1 & PF2=$!
trap 'kill $PF1 $PF2 2>/dev/null' EXIT
sleep 3

# A token for USER. The Host header makes Keycloak issue it under the
# in-cluster issuer the gateway and the Interceptor expect.
token() {
  curl -fsS http://127.0.0.1:18080/realms/tvm/protocol/openid-connect/token \
    -H 'Host: keycloak.platform.svc.cluster.local:8080' \
    -d grant_type=password -d client_id=mcp-client -d client_secret="$(secret client-secret)" \
    -d username="$1" -d password="$(secret user-password)" | jq -r .access_token
}

# ask USER PROMPT: send PROMPT to the agent through kagent, as USER
ask() {
  printf '\n\033[1m%s: %s\033[0m\n' "$1" "$2"
  jq -n --arg text "$2" '{jsonrpc: "2.0", id: "1", method: "message/send",
      params: {message: {role: "user", kind: "message", messageId: "m1",
                         parts: [{kind: "text", text: $text}]}}}' \
  | curl -fsS --max-time 300 http://127.0.0.1:18083/api/a2a/agents/tvm-agent/ \
      -H "authorization: Bearer $(token "$1")" -H 'content-type: application/json' -d @- \
  | jq -r '[.result.parts[]?, .result.status.message.parts[]?, (.result.artifacts[]?.parts[]?)]
           | map(.text) | map(select(.)) | .[0] | fromjson
           | "  answer: \(.answer // .error)",
             (.tool_calls[]? | "  tool \(.tool) \(.arguments | tojson) -> \(.result | tojson)")'
}

ask alice "Read document t1-001."
ask alice "Read document t2-001."
ask bob   "Append the reply 'checked' to document t2-001."
