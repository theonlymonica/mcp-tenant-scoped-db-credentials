"""Reading the tenant out of a verified token."""

from __future__ import annotations

from typing import Any, Mapping, Optional

from . import scopes


def scope_group_claim(claims: Mapping[str, Any]) -> Optional[str]:
    """The `scope_group` claim if it is exactly one non-empty string, else None.

    A list (a user in two tenants), a number or an empty string is None, and
    the request is denied.
    """
    value = claims.get(scopes.CLAIM_NAME) if isinstance(claims, Mapping) else None
    if not isinstance(value, str) or not scopes.canonical(value):
        return None
    return value
