"""Reading what the Interceptor put in the x-tvm-credential header, and
exchanging it for the credential.

The header must appear exactly once. A request with no header, or with two,
is refused: the gateway removes every copy the client sent, so a second copy
can only be a forgery.

The header does not carry the credential. It carries a wrapping token, which
OpenBao exchanges for the username and password once. The gateway, and
anything that records its headers, only ever sees that token. If the exchange
is refused, the token had already been used or had expired: somebody else
read the credential first, or the request was replayed. That is logged as an
error, and the tool does not run.
"""

from __future__ import annotations

import base64
import http.client
import json
import os
import ssl
from dataclasses import dataclass
from typing import Sequence

CREDENTIAL_HEADER = "x-tvm-credential"

OPENBAO_HOST = "openbao.platform.svc.cluster.local"
OPENBAO_PORT = 8200
OPENBAO_CA = "/platform-ca/ca.crt"
UNWRAP_TIMEOUT_S = float(os.environ.get("UNWRAP_TIMEOUT_S", "3"))
MAX_LEASE_SECONDS = 30


class CredentialMissing(Exception):
    pass


class UnwrapRefused(CredentialMissing):
    """OpenBao would not exchange the wrapping token."""


@dataclass(frozen=True)
class Envelope:
    tenant: str
    operation: str
    request_id: str
    wrap_token: str

    def __repr__(self) -> str:
        return (f"Envelope(tenant={self.tenant!r}, operation={self.operation!r}, "
                f"request_id={self.request_id!r}, wrap_token=<redacted>)")


@dataclass(frozen=True)
class Credential:
    tenant: str
    request_id: str
    username: str
    password: str

    def __repr__(self) -> str:
        return f"Credential(tenant={self.tenant!r}, username={self.username!r}, password=<redacted>)"


def read_envelope(values: Sequence[str]) -> Envelope:
    if len(values) != 1:
        raise CredentialMissing(f"{CREDENTIAL_HEADER} carried {len(values)} times, exactly one is accepted")
    raw = values[0]
    try:
        envelope = json.loads(base64.urlsafe_b64decode(raw + "=" * (-len(raw) % 4)))
    except ValueError:
        raise CredentialMissing(f"{CREDENTIAL_HEADER} is not a base64url JSON envelope") from None
    fields = ("served_scope", "operation", "request_id", "wrap_token")
    if not isinstance(envelope, dict) or envelope.get("v") != 2 or \
            not all(isinstance(envelope.get(f), str) and envelope[f] for f in fields):
        raise CredentialMissing(f"{CREDENTIAL_HEADER} is not a valid envelope")
    return Envelope(tenant=envelope["served_scope"], operation=envelope["operation"],
                    request_id=envelope["request_id"], wrap_token=envelope["wrap_token"])


def unwrap(envelope: Envelope) -> Credential:
    """Exchange the wrapping token for the credential. Works once per token."""
    ctx = ssl.create_default_context(cafile=OPENBAO_CA)
    conn = http.client.HTTPSConnection(OPENBAO_HOST, OPENBAO_PORT, timeout=UNWRAP_TIMEOUT_S, context=ctx)
    try:
        conn.request("POST", "/v1/sys/wrapping/unwrap", headers={"X-Vault-Token": envelope.wrap_token})
        resp = conn.getresponse()
        raw = resp.read()
    except (OSError, http.client.HTTPException) as exc:
        raise CredentialMissing(f"broker unreachable ({type(exc).__name__})") from None
    finally:
        conn.close()
    if resp.status != 200:
        raise UnwrapRefused(f"wrapping token refused (HTTP {resp.status}): already used or expired")
    try:
        body = json.loads(raw)
    except ValueError:
        body = None
    data = body.get("data") if isinstance(body, dict) else None
    lease = body.get("lease_duration") if isinstance(body, dict) else None
    if not isinstance(data, dict) or not isinstance(data.get("username"), str) or not data["username"] \
            or not isinstance(data.get("password"), str) or not data["password"] \
            or not isinstance(lease, int) or not 0 < lease <= MAX_LEASE_SECONDS:
        raise CredentialMissing("the wrapping token did not hold a database credential")
    return Credential(tenant=envelope.tenant, request_id=envelope.request_id,
                      username=data["username"], password=data["password"])
