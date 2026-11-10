"""The MCP server: Streamable HTTP on :8443/mcp, mutual TLS with SPIFFE.

It reads the credential header only on tools/call, exchanges the wrapping token
in it for the credential, and runs the tool with the credential of that call.
"""

from __future__ import annotations

import contextlib
import json
import logging
import sys

import anyio
import uvicorn
from mcp.server import Server, ServerRequestContext
from mcp.server.streamable_http_manager import StreamableHTTPSessionManager
from mcp.types import (CallToolRequestParams, CallToolResult, ListToolsResult,
                       PaginatedRequestParams, TextContent)
from starlette.applications import Starlette
from starlette.routing import Route

from . import tools
from .credential import (CREDENTIAL_HEADER, CredentialMissing, Envelope, UnwrapRefused,
                         read_envelope, unwrap)
from .datastore import DatastoreError
from .mtls import SvidContext, peer_checking_protocol

log = logging.getLogger("mcp_server")

GATEWAY_SPIFFE_ID = "spiffe://tvm.local/platform/mcp-gateway"
SPIRE_SOCKET = "unix:///run/spire/sockets/agent.sock"
SVID_DIR = "/run/mcp-server"


def _result(body: dict, is_error: bool = False) -> CallToolResult:
    return CallToolResult(
        content=[TextContent(type="text", text=json.dumps(body, sort_keys=True))],
        structured_content=body, is_error=is_error)


async def list_tools(ctx: ServerRequestContext, params: PaginatedRequestParams | None) -> ListToolsResult:
    return ListToolsResult(tools=tools.TOOLS)


def _run(handler, arguments: dict, envelope: Envelope) -> tuple[dict, str]:
    """In a worker thread: get the credential, run the tool, forget the credential."""
    cred = unwrap(envelope)
    return handler(arguments, cred), cred.username


async def call_tool(ctx: ServerRequestContext, params: CallToolRequestParams) -> CallToolResult:
    name = params.name
    handler = tools.HANDLERS.get(name)
    if handler is None:
        return _result({"error": "unknown_tool"}, True)
    # ctx.request is the HTTP request this tools/call arrived on.
    headers = ctx.request.headers.getlist(CREDENTIAL_HEADER) if ctx.request is not None else []
    try:
        envelope = read_envelope(headers)
    except CredentialMissing as exc:
        log.warning("tool=%s refused: %s", name, exc)
        return _result({"error": "missing_credential"}, True)
    # The credential was issued for one operation. Checked before the wrapping
    # token is spent, so a refused call leaves nothing behind.
    if tools.OPERATION_OF.get(name) != envelope.operation:
        log.warning("tool=%s request_id=%s refused: the credential is for another operation",
                    name, envelope.request_id)
        return _result({"error": "operation_mismatch", "request_id": envelope.request_id}, True)
    try:
        body, username = await anyio.to_thread.run_sync(_run, handler,
                                                        params.arguments or {}, envelope)
    except UnwrapRefused as exc:
        log.error("tool=%s request_id=%s refused: %s", name, envelope.request_id, exc)
        return _result({"error": "missing_credential", "request_id": envelope.request_id}, True)
    except CredentialMissing as exc:
        log.warning("tool=%s request_id=%s refused: %s", name, envelope.request_id, exc)
        return _result({"error": "missing_credential", "request_id": envelope.request_id}, True)
    except (tools.InvalidArgument, DatastoreError) as exc:
        log.warning("tool=%s request_id=%s error=%s", name, envelope.request_id, exc)
        return _result({"error": str(exc), "request_id": envelope.request_id}, True)
    log.info("tool=%s tenant=%s request_id=%s credential=%s",
             name, envelope.tenant, envelope.request_id, username)
    return _result(body)


def main() -> int:
    logging.basicConfig(stream=sys.stdout, level=logging.INFO,
                        format="%(asctime)s %(levelname)s %(name)s %(message)s")
    for noisy in ("mcp", "uvicorn", "uvicorn.error", "httpx2"):
        logging.getLogger(noisy).setLevel(logging.WARNING)

    # The SDK does not validate tool arguments against the schema (its errors
    # quoted the argument values); each tool checks its own arguments.
    server = Server("documents", on_list_tools=list_tools, on_call_tool=call_tool)
    manager = StreamableHTTPSessionManager(app=server, json_response=True, stateless=True)

    @contextlib.asynccontextmanager
    async def lifespan(_app):
        async with manager.run():
            yield

    class Endpoint:  # a class, so Starlette passes the raw ASGI call through
        async def __call__(self, scope, receive, send):
            await manager.handle_request(scope, receive, send)

    app = Starlette(routes=[Route("/mcp", endpoint=Endpoint())], lifespan=lifespan)
    svid = SvidContext(SPIRE_SOCKET, SVID_DIR)
    uvicorn.Server(uvicorn.Config(
        app, host="0.0.0.0", port=8443,
        http=peer_checking_protocol(GATEWAY_SPIFFE_ID),
        ssl_context_factory=lambda _cfg, _default: svid.ssl,
        log_level="warning", access_log=False, lifespan="on",
    )).run()
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
