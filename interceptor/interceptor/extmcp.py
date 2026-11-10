"""The Interceptor as Agentgateway's MCP guardrail (ExtMCP gRPC service).

Agentgateway calls CheckRequest for every `tools/call` before forwarding it to
the MCP server. For each one the Interceptor:

  1. verifies the user's token itself;
  2. reads the tenant from the `scope_group` claim, and from nowhere else;
  3. asks OPA whether that tenant may use the tool, and for which operation;
  4. looks the (tenant, operation) pair up in the fixed table of paths;
  5. checks the tenant's rate and concurrency limits;
  6. gets one wrapped credential from OpenBao: a single-use token, not the
     username and password;
  7. answers Pass, setting that token in the x-tvm-credential header and
     removing the user's token.

Any failure is a denial and the call never reaches the MCP server. Neither the
user's token, the wrapping token nor the tool arguments are ever logged. The
log line of a served call carries what is needed to go from a PostgreSQL
session back to a user: the request id, the tool, the tenant and the token's
`sub`, which is Keycloak's opaque user id, not a name or an address.
"""

from __future__ import annotations

import base64
import json
import logging
import re
import uuid

import ext_mcp_pb2 as pb
import ext_mcp_pb2_grpc as pbg

from . import claims, scopes
from .broker import MintFailure, OpenBaoMinter
from .jwt_verify import JwtVerifier, TokenInvalid, bearer_from_headers
from .limits import TenantLimiter
from .opa_client import OpaClient

log = logging.getLogger("interceptor")

CREDENTIAL_HEADER = "x-tvm-credential"


def encode_envelope(*, served_scope: str, operation: str, request_id: str, wrap_token: str) -> bytes:
    """The header value the MCP server decodes: base64url JSON, no padding.

    It names the operation the credential was issued for, so the MCP server
    can refuse to run any other tool with it, and carries the wrapping token
    in place of the credential.
    """
    body = {"v": 2, "served_scope": served_scope, "operation": operation,
            "request_id": request_id, "wrap_token": wrap_token}
    raw = json.dumps(body, separators=(",", ":"), sort_keys=True).encode()
    return base64.urlsafe_b64encode(raw).rstrip(b"=")


def _loggable(value: object) -> str:
    """A value taken from the request, made safe to put in a log line."""
    return re.sub(r"[^A-Za-z0-9._:@/-]", "?", str(value))[:64] or "-"


def _metadata_string(struct, key: str) -> str:
    """A string value from the guardrail metadata (here: the agent's SPIFFE ID)."""
    value = struct.fields.get(key) if struct is not None else None
    if value is None or value.WhichOneof("kind") != "string_value":
        return ""
    return value.string_value


class ExtMcpService(pbg.ExtMcpServicer):
    def __init__(self, minter: OpenBaoMinter, verifier: JwtVerifier, opa: OpaClient,
                 limiter: TenantLimiter) -> None:
        self._minter = minter
        self._verifier = verifier
        self._opa = opa
        self._limiter = limiter

    def CheckRequest(self, request, context):  # noqa: N802
        rid = uuid.uuid4().hex
        try:
            return self._check(request, rid)
        except Exception as exc:  # noqa: BLE001 - any error is a denial
            return self._deny(rid, f"internal_error_{type(exc).__name__}")

    def CheckResponse(self, request, context):  # noqa: N802
        return pb.McpResponseResult(**{"pass": pb.Pass()})

    def _deny(self, rid: str, reason: str, *, code=pb.AuthorizationError.PERMISSION_DENIED,
              tenant: str = "-", tool: str = "-", sub: str = "-"):
        log.warning("denied reason=%s tenant=%s tool=%s sub=%s request_id=%s",
                    reason, tenant, tool, sub, rid)
        return pb.McpRequestResult(error=pb.AuthorizationError(
            code=code, reason=f"interceptor denied this call ({reason})"))

    def _check(self, request, rid: str):
        if request.method != "tools/call":
            return pb.McpRequestResult(**{"pass": pb.Pass()})   # no credential for other methods

        tool = json.loads(request.mcp_request).get("name")       # read only to ask OPA
        if not isinstance(tool, str) or not tool:
            return self._deny(rid, "no_tool_name")
        who = {"tool": _loggable(tool)}

        # the token is verified again here, not trusted from the gateway
        try:
            verified = self._verifier.verify(bearer_from_headers(request.headers))
        except TokenInvalid as exc:
            return self._deny(rid, f"token_{exc}", **who)
        who["sub"] = _loggable(verified.get("sub", "-"))

        # the tenant comes from the verified claim and nowhere else
        tenant = scopes.canonical(claims.scope_group_claim(verified))
        if tenant not in scopes.SCOPES:
            return self._deny(rid, "no_scope", **who)
        who["tenant"] = tenant

        # OPA receives tenant, tool and agent identity, never the arguments
        agent = _metadata_string(request.metadata_context, "agent_spiffe_id")
        decision = self._opa.decide(tenant=tenant, tool=tool, agent=agent)
        if not decision.allowed:
            return self._deny(rid, decision.reason, **who)

        # the operation is the one OPA authorized, looked up in the fixed table
        resolved = scopes.resolve(tenant, decision.authorized_operation)
        if resolved is None:
            return self._deny(rid, "no_pair", **who)

        # one tenant cannot fill the queue every tenant shares
        refused = self._limiter.enter(resolved.scope)
        if refused:
            return self._deny(rid, refused, code=pb.AuthorizationError.RESOURCE_EXHAUSTED, **who)
        try:
            cred = self._minter.mint(resolved)                   # one credential, only now
        except MintFailure as exc:
            return self._deny(rid, str(exc), **who)
        finally:
            self._limiter.leave(resolved.scope)

        log.info("served tenant=%s operation=%s tool=%s sub=%s request_id=%s wrap_accessor=%s wrap_ttl_s=%d",
                 resolved.scope, resolved.operation, who["tool"], who["sub"], rid,
                 cred.accessor, cred.ttl_s)
        envelope = encode_envelope(served_scope=resolved.scope, operation=resolved.operation,
                                   request_id=rid, wrap_token=cred.wrap_token)
        return pb.McpRequestResult(
            **{"pass": pb.Pass()},
            header_mutation=pb.HeaderMutation(
                set=[pb.McpHeader(key=CREDENTIAL_HEADER, value=envelope)],
                remove=["authorization"],                        # the MCP server never sees the token
            ),
        )
