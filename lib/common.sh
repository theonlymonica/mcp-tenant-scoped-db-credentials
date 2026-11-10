# Shared helpers for the install scripts. Sourced, not executed.

CLUSTER_NAME="${CLUSTER_NAME:-mcp-tenants}"
REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
WORK="$REPO_ROOT/.tmp"
mkdir -p "$WORK"

log() { printf '\033[1;34m==>\033[0m %s\n' "$*"; }
die() { printf '\033[1;31merror:\033[0m %s\n' "$*" >&2; exit 1; }

# Pull an image for the host architecture and load it onto every kind node.
# A multi-architecture image is first rebuilt as a single-architecture one,
# because `kind load` fails on a manifest list whose other platforms are not in
# the local store.
load_image() {
  local img="$1" platform="linux/$(uname -m | sed 's/x86_64/amd64/; s/aarch64/arm64/')"
  docker image inspect "$img" >/dev/null 2>&1 || docker pull --platform "$platform" "$img" >/dev/null
  if ! kind load docker-image "$img" --name "$CLUSTER_NAME" >/dev/null 2>&1; then
    printf 'FROM %s\n' "$img" | docker buildx build --platform "$platform" \
      --provenance=false --sbom=false --load -t "$img" - >/dev/null 2>&1
    kind load docker-image "$img" --name "$CLUSTER_NAME" >/dev/null 2>&1
  fi
  log "image $img loaded"
}

# Run psql inside the PostgreSQL pod as the bootstrap superuser.
pg_admin() {
  kubectl -n platform exec -i postgres-0 -c postgres -- \
    bash -c 'PGPASSWORD="$POSTGRES_PASSWORD" exec psql -X -q -v ON_ERROR_STOP=1 -U postgres "$@"' psql "$@"
}
