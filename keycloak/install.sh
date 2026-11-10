#!/usr/bin/env bash
# Install Keycloak with the realm `tvm` and two users:
#   alice (scope_group = tenant1) and bob (scope_group = tenant2).
# The client secret and the users' password are generated and kept in the
# Secret keycloak-secrets.
set -euo pipefail
source "$(dirname "$0")/../lib/common.sh"
source "$REPO_ROOT/lib/tls.sh"
HERE="$REPO_ROOT/keycloak"

load_image quay.io/keycloak/keycloak:26.8.2

if ! kubectl -n platform get secret keycloak-secrets >/dev/null 2>&1; then
  kubectl -n platform create secret generic keycloak-secrets \
    --from-literal=admin-password="$(openssl rand -hex 24)" \
    --from-literal=client-secret="$(openssl rand -hex 24)" \
    --from-literal=user-password="$(openssl rand -hex 12)" >/dev/null
fi
secret() { kubectl -n platform get secret keycloak-secrets -o jsonpath="{.data.$1}" | base64 -d; }

# The realm file with the user profile and the generated values put in, stored
# as a Secret because it contains them.
#
# The user profile (user-profile.json) is what makes the tenant an attribute
# only an administrator can see or change. Without it `scope_group` would be an
# unmanaged attribute, which Keycloak protects only as long as nobody enables
# unmanaged attributes for the realm; with it, a user editing their own account
# cannot touch the attribute their tenant is read from.
jq --slurpfile profile "$HERE/user-profile.json" '.components = {
      "org.keycloak.userprofile.UserProfileProvider": [{
        providerId: "declarative-user-profile",
        subComponents: {},
        config: {"kc.user.profile.config": [$profile[0] | tojson]}
      }]}' "$HERE/realm.json" \
  | sed -e "s|__CLIENT_SECRET__|$(secret client-secret)|" \
        -e "s|__USER_PASSWORD__|$(secret user-password)|g" \
  | kubectl -n platform create secret generic keycloak-realm --from-file=realm-tvm.json=/dev/stdin \
      --dry-run=client -o yaml | kubectl apply -f - >/dev/null

issue_server_cert keycloak keycloak.platform.svc.cluster.local keycloak.platform.svc keycloak
generation() { kubectl -n platform get deployment keycloak -o jsonpath='{.metadata.generation}' 2>/dev/null || echo 0; }
before="$(generation)"
kubectl apply -f "$HERE/keycloak.yaml" >/dev/null
# The realm is imported at start, so a change to it restarts Keycloak: its
# checksum is a pod template annotation.
realm_sum="$(cat "$HERE/realm.json" "$HERE/user-profile.json" | shasum -a 256 | cut -c1-16)"
kubectl -n platform patch deployment keycloak --type=merge \
  -p "{\"spec\":{\"template\":{\"metadata\":{\"annotations\":{\"realm-checksum\":\"$realm_sum\"}}}}}" >/dev/null
kubectl -n platform rollout status deployment/keycloak --timeout=300s

# start-dev creates new signing keys at every start, and the gateway's
# controller keeps the keys it fetched for five minutes (cacheDuration in
# agentgateway/gateway.yaml). If Keycloak was restarted under a running
# gateway, wait here until the controller has fetched the new key: until then
# the gateway refuses every token.
if [[ "$(generation)" != "$before" ]] && kubectl -n platform get deployment mcp-gateway >/dev/null 2>&1; then
  kubectl -n platform port-forward svc/keycloak 18080:8080 >/dev/null 2>&1 & pf=$!
  sleep 3
  kid="$(curl -fsS http://127.0.0.1:18080/realms/tvm/protocol/openid-connect/certs \
           | jq -r '[.keys[] | select(.alg == "RS256") | .kid][0]')"
  kill "$pf" 2>/dev/null || true
  log "waiting for the gateway to fetch Keycloak's new signing key (up to five minutes)"
  until kubectl -n agentgateway-system get configmap -o json | grep -qF "$kid"; do sleep 5; done
fi
