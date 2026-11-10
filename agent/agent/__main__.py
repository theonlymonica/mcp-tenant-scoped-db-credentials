"""The agent's A2A server, which kagent's controller forwards requests to.

The controller passes the user's Authorization header through (trusted-proxy
mode); the agent uses that token for every call to the gateway. The controller
speaks A2A 0.3, so the JSON-RPC route also accepts 0.3 requests.
"""

from __future__ import annotations

import asyncio
import json
import logging

import uvicorn
from a2a.helpers import new_text_message
from a2a.server.agent_execution import AgentExecutor, RequestContext
from a2a.server.events import EventQueue
from a2a.server.request_handlers import DefaultRequestHandler
from a2a.server.routes import create_agent_card_routes, create_jsonrpc_routes
from a2a.server.tasks import InMemoryTaskStore
from a2a.types import AgentCapabilities, AgentCard, AgentInterface, AgentSkill
from starlette.applications import Starlette

from . import graph

log = logging.getLogger("agent")

URL = "http://tvm-agent.agents.svc.cluster.local:8080/"


def bearer(headers: dict) -> str:
    value = next((v for k, v in headers.items() if str(k).lower() == "authorization"), "")
    value = value[0] if isinstance(value, list) and len(value) == 1 else value
    return value[7:].strip() if isinstance(value, str) and value[:7].lower() == "bearer " else ""


class Executor(AgentExecutor):
    def __init__(self) -> None:
        self._graph = graph.build()

    async def execute(self, context: RequestContext, event_queue: EventQueue) -> None:
        headers = context.call_context.state.get("headers", {}) if context.call_context else {}
        token = bearer(headers)
        if not token:
            result = {"error": "no user token"}
        else:
            try:
                result = await asyncio.to_thread(graph.run, self._graph, context.get_user_input(), token)
            except Exception as exc:  # noqa: BLE001
                result = {"error": type(exc).__name__}
        log.info("invocation tool_calls=%d", len(result.get("tool_calls", [])))
        # One message and nothing else: the reply is not a tracked task.
        await event_queue.enqueue_event(new_text_message(json.dumps(result)))

    async def cancel(self, context: RequestContext, event_queue: EventQueue) -> None:
        return None


def main() -> int:
    logging.basicConfig(level=logging.INFO, format="%(asctime)s %(levelname)s %(name)s %(message)s")
    logging.getLogger("httpx2").setLevel(logging.WARNING)
    card = AgentCard(
        name="tvm_agent", description="A document assistant shared by every tenant.",
        supported_interfaces=[
            AgentInterface(protocol_binding="JSONRPC", url=URL),
            AgentInterface(protocol_binding="JSONRPC", protocol_version="0.3", url=URL),
        ],
        version="1.0.0",
        capabilities=AgentCapabilities(streaming=False),
        default_input_modes=["text"], default_output_modes=["text"],
        skills=[AgentSkill(id="documents", name="documents",
                           description="Read, search and append to documents.", tags=["documents"])],
    )
    handler = DefaultRequestHandler(agent_executor=Executor(), task_store=InMemoryTaskStore(),
                                    agent_card=card)
    routes = create_agent_card_routes(card) + create_jsonrpc_routes(handler, rpc_url="/",
                                                                     enable_v0_3_compat=True)
    uvicorn.run(Starlette(routes=routes), host="0.0.0.0", port=8080, log_level="warning", access_log=False)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
