#!/usr/bin/env bash
# Run the row-level security catalog checks against the live database.
set -euo pipefail
source "$(dirname "$0")/../lib/common.sh"
pg_admin <"$REPO_ROOT/postgres/check_rls.sql"
