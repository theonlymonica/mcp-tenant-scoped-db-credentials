#!/usr/bin/env bash
# Install PostgreSQL, create the schema, and check the row-level security.
set -euo pipefail
source "$(dirname "$0")/../lib/common.sh"
source "$REPO_ROOT/lib/tls.sh"
HERE="$REPO_ROOT/postgres"

load_image postgres:18.6

# Two generated passwords: the bootstrap superuser, which stays in this Secret,
# and bao_admin, the role OpenBao logs in as, which stays only until OpenBao
# rotates it (openbao/install.sh).
if ! kubectl -n platform get secret postgres-passwords >/dev/null 2>&1; then
  kubectl -n platform create secret generic postgres-passwords \
    --from-literal=postgres="$(openssl rand -hex 24)" \
    --from-literal=bao_admin="$(openssl rand -hex 24)" >/dev/null
fi

issue_server_cert postgres postgres.platform.svc.cluster.local postgres.platform.svc postgres
kubectl -n platform create configmap postgres-config \
  --from-file="$HERE/postgresql.conf" --from-file="$HERE/pg_hba.conf" \
  --dry-run=client -o yaml | kubectl apply -f - >/dev/null
kubectl apply -f "$HERE/postgres.yaml" >/dev/null
# PostgreSQL reads its two configuration files at start, so a change to either
# restarts it: their checksum is an annotation of the pod template.
config_sum="$(cat "$HERE/postgresql.conf" "$HERE/pg_hba.conf" | shasum -a 256 | cut -c1-16)"
kubectl -n platform patch statefulset postgres --type=merge \
  -p "{\"spec\":{\"template\":{\"metadata\":{\"annotations\":{\"config-checksum\":\"$config_sum\"}}}}}" >/dev/null
kubectl -n platform rollout status statefulset/postgres --timeout=300s

if [[ -z "$(pg_admin -tAc "SELECT 1 FROM pg_database WHERE datname = 'tvm'")" ]]; then
  # openbao/install.sh deletes bao_admin's password from the Secret once OpenBao
  # has rotated it; a database created after that needs a new one.
  if [[ -z "$(kubectl -n platform get secret postgres-passwords -o jsonpath='{.data.bao_admin}')" ]]; then
    kubectl -n platform patch secret postgres-passwords --type=merge \
      -p "{\"stringData\":{\"bao_admin\":\"$(openssl rand -hex 24)\"}}" >/dev/null
  fi
  pg_admin -v bao_admin_password="$(kubectl -n platform get secret postgres-passwords \
             -o jsonpath='{.data.bao_admin}' | base64 -d)" <"$HERE/schema.sql"
  log "schema created"
fi

bash "$HERE/check_rls.sh"
