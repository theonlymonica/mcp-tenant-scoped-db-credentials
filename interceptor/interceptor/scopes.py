"""The tenants, the operations each may use, and the fixed table of credential paths.

The Interceptor never builds an OpenBao path from a string it received. It
looks the (tenant, operation) pair up in PAIR_CREDENTIAL_PATHS; a pair that is
not in the table resolves to None and no credential is requested.

The table holds only the pairs a tenant is allowed: an operation a tenant may
not use has no path here, no role in OpenBao and no line in the Interceptor's
OpenBao policy, so OPA is not the only thing that refuses it.

The same tenants and operations appear in openbao/interceptor-policy.hcl,
openbao/install.sh, postgres/schema.sql, postgres/pg_hba.conf and
opa/policy.rego. tenants/check_tenants.py checks that all of them agree with
tenants/tenants.json.
"""

from __future__ import annotations

from dataclasses import dataclass
from types import MappingProxyType
from typing import Mapping, Optional

CLAIM_NAME = "scope_group"

OPERATIONS = ("read", "search", "append")

ALLOWED_OPERATIONS: Mapping[str, tuple[str, ...]] = MappingProxyType({
    "tenant1": ("read", "search", "append"),
    "tenant2": ("read", "search"),
})

SCOPES = tuple(ALLOWED_OPERATIONS)

PAIR_CREDENTIAL_PATHS: Mapping[tuple[str, str], str] = MappingProxyType({
    (scope, operation): f"database/creds/{scope}-{operation}"
    for scope, operations in ALLOWED_OPERATIONS.items()
    for operation in operations
})


def canonical(value: object) -> str:
    """Lowercase, surrounding spaces removed. Anything but a string is ''."""
    if not isinstance(value, str):
        return ""
    return value.strip().lower()


@dataclass(frozen=True)
class ResolvedScope:
    scope: str
    operation: str
    credential_path: str


def resolve(scope: object, operation: object) -> Optional[ResolvedScope]:
    """The credential path for (scope, operation), or None if the table has none.

    `operation` is the one OPA authorized, never the tool name in the request.
    """
    s, op = canonical(scope), canonical(operation)
    path = PAIR_CREDENTIAL_PATHS.get((s, op))
    if path is None:
        return None
    return ResolvedScope(scope=s, operation=op, credential_path=path)
