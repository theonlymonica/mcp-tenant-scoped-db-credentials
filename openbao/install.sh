#!/usr/bin/env bash
# Install OpenBao and configure the two things the Interceptor uses:
#   * auth/cert: the Interceptor logs in with its SPIRE SVID;
#   * database/: one credential role per allowed (tenant, operation) pair,
#     30 s leases.
set -euo pipefail
source "$(dirname "$0")/../lib/common.sh"
source "$REPO_ROOT/lib/tls.sh"
HERE="$REPO_ROOT/openbao"

# The (tenant, operation) pairs: only the operations each tenant is allowed
# (tenants/tenants.json). Each needs a database/roles entry here, a path in
# interceptor-policy.hcl, and the tenant and operation roles in
# postgres/schema.sql. tenants/check_tenants.py checks that they agree.
PAIRS=(tenant1:read tenant1:search tenant1:append tenant2:read tenant2:search)

# How long a credential lives. A tool call needs it for milliseconds: it logs
# in once, right after the role is created. max_ttl is a ceiling nobody can
# reach, because the Interceptor's policy does not allow renewing a lease.
LEASE_TTL=30s
LEASE_MAX_TTL=60s

load_image openbao/openbao:2.7.2
issue_server_cert openbao openbao.platform.svc.cluster.local openbao.platform.svc openbao
kubectl apply -f "$HERE/openbao.yaml" >/dev/null
# OpenBao reads its configuration (the audit device is declared there) and the
# SPIRE bundle it verifies client certificates against at start, so a change to
# either restarts the pod: their checksum is a pod template annotation.
config_sum="$( (cat "$HERE/openbao.yaml"; kubectl -n platform get configmap spire-bundle -o jsonpath='{.data.bundle\.crt}') \
               | shasum -a 256 | cut -c1-16)"
kubectl -n platform patch statefulset openbao --type=merge \
  -p "{\"spec\":{\"template\":{\"metadata\":{\"annotations\":{\"config-checksum\":\"$config_sum\"}}}}}" >/dev/null
kubectl -n platform rollout status statefulset/openbao --timeout=300s
until kubectl -n platform get pod openbao-0 -o jsonpath='{.status.containerStatuses[0].ready}' 2>/dev/null | grep -q true; do sleep 2; done

bao_anon() { kubectl -n platform exec -i openbao-0 -c openbao -- bao "$@"; }
bao_status() { kubectl -n platform exec openbao-0 -c openbao -- bao status -format=json 2>/dev/null || true; }

# Initialise with a single unseal key. The key and the root token are kept in
# the Secret openbao-unseal; the unsealer container reads the key from there.
if ! bao_status | jq -e '.initialized' >/dev/null; then
  init="$(bao_anon operator init -key-shares=1 -key-threshold=1 -format=json)"
  kubectl -n platform create secret generic openbao-unseal \
    --from-literal=unseal-key="$(jq -r '.unseal_keys_b64[0]' <<<"$init")" \
    --from-literal=root-token="$(jq -r '.root_token' <<<"$init")" >/dev/null
  log "OpenBao initialised"
fi
until bao_status | jq -e '.sealed == false' >/dev/null; do sleep 2; done

ROOT_TOKEN="$(kubectl -n platform get secret openbao-unseal -o jsonpath='{.data.root-token}' | base64 -d)"
bao() { kubectl -n platform exec -i openbao-0 -c openbao -- env BAO_TOKEN="$ROOT_TOKEN" bao "$@"; }

# --- the Interceptor's login -------------------------------------------------
# The cert role trusts the SPIRE CA and accepts only the Interceptor's SPIFFE
# ID. The token it issues carries the one policy above and lives 60 seconds.
bao auth list -format=json | jq -e '."cert/"' >/dev/null || bao auth enable -local cert >/dev/null
bao policy write tvm-interceptor - <"$HERE/interceptor-policy.hcl" >/dev/null
kubectl -n platform get configmap spire-bundle -o jsonpath='{.data.bundle\.crt}' \
  | kubectl -n platform exec -i openbao-0 -c openbao -- sh -c 'cat > /tmp/spire-bundle.pem'
bao write auth/cert/certs/interceptor \
  display_name=interceptor \
  certificate=@/tmp/spire-bundle.pem \
  allowed_uri_sans=spiffe://tvm.local/platform/interceptor \
  token_policies=tvm-interceptor \
  token_no_default_policy=true \
  token_ttl=60s token_max_ttl=60s >/dev/null
log "cert auth configured for spiffe://tvm.local/platform/interceptor"

# --- the database secrets engine ----------------------------------------------
bao secrets list -format=json | jq -e '."database/"' >/dev/null || bao secrets enable database >/dev/null

allowed=""
for p in "${PAIRS[@]}"; do allowed+="${allowed:+,}${p%%:*}-${p#*:}"; done
bao_admin_pw() { kubectl -n platform get secret postgres-passwords -o jsonpath='{.data.bao_admin}' | base64 -d; }

if ! bao read database/config/tvm >/dev/null 2>&1; then
  [[ -n "$(bao_admin_pw)" ]] || die "database/config/tvm is missing and so is bao_admin's password in the Secret postgres-passwords"
  jq -n --arg pw "$(bao_admin_pw)" --arg roles "$allowed" '{
    plugin_name: "postgresql-database-plugin",
    allowed_roles: $roles,
    connection_url: "postgresql://{{username}}:{{password}}@postgres.platform.svc.cluster.local:5432/tvm?sslmode=verify-full&sslrootcert=/openbao/ca/ca.crt",
    username: "bao_admin",
    password: $pw
  }' | bao write database/config/tvm - >/dev/null
fi
# On a mount that is already configured this changes the list of roles only.
bao write database/config/tvm allowed_roles="$allowed" >/dev/null

# bao_admin can create a role in any tenant, so its password is worth every
# tenant's rows. OpenBao replaces it with one that it alone knows, and the copy
# postgres/install.sh generated is deleted: from here on nobody can log in as
# bao_admin but OpenBao.
if [[ -n "$(bao_admin_pw)" ]]; then
  bao write -f database/rotate-root/tvm >/dev/null
  kubectl -n platform patch secret postgres-passwords --type=json \
    -p '[{"op": "remove", "path": "/data/bao_admin"}]' >/dev/null
  log "bao_admin's password rotated; only OpenBao holds it now"
fi

# The role a credential is created as is a member of one tenant role and one
# operation role, and holds nothing itself. CONNECT on the database comes from
# those two memberships (postgres/schema.sql).
for p in "${PAIRS[@]}"; do
  tenant="${p%%:*}" op="${p#*:}"
  bao write "database/roles/$tenant-$op" db_name=tvm default_ttl="$LEASE_TTL" max_ttl="$LEASE_MAX_TTL" \
    creation_statements="CREATE ROLE \"{{name}}\" WITH LOGIN PASSWORD '{{password}}' VALID UNTIL '{{expiration}}' NOBYPASSRLS NOSUPERUSER NOCREATEROLE; GRANT scope_$tenant TO \"{{name}}\"; GRANT op_$op TO \"{{name}}\";" \
    revocation_statements="REVOKE op_$op FROM \"{{name}}\"; REVOKE scope_$tenant FROM \"{{name}}\"; DROP ROLE IF EXISTS \"{{name}}\";" >/dev/null
  log "database/roles/$tenant-$op"
done

# A pair that is no longer allowed loses its role, not only its policy line.
for r in $(bao list -format=json database/roles | jq -r '.[]'); do
  if [[ ",$allowed," != *",$r,"* ]]; then
    bao delete "database/roles/$r" >/dev/null
    log "removed database/roles/$r"
  fi
done
