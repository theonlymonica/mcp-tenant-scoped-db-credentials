"""The agent loop, in LangGraph: the model decides which tools to call.

Both the model and the tools are reached through the gateway, with the user's
token. The agent never knows the user's tenant: it forwards the token, and the
tenant is read from it by the Interceptor.
"""

from __future__ import annotations

import asyncio
import json
import os
from typing import Any

import httpx2
from langgraph.graph import END, START, StateGraph
from mcp import ClientSession, MCPError
from mcp.client.streamable_http import streamable_http_client
from typing_extensions import TypedDict

# The egress Envoy in the same pod opens the mTLS connection to the gateway.
MODEL_URL = "http://127.0.0.1:15001/v1/chat/completions"
MCP_URL = "http://127.0.0.1:15001/mcp"
MODEL = os.environ.get("AGENT_MODEL", "qwen2.5:7b")
MAX_TOOL_ROUNDS = 5
# Across all rounds of one request. The rounds alone do not bound the calls:
# the model can ask for any number of them in one message, and each one makes
# OpenBao create a database role.
MAX_TOOL_CALLS = 8

SYSTEM_PROMPT = (
    "You are a document assistant. Use the tools to read, search and append to "
    "documents. Document ids look like 't1-001'. After the tool results, answer "
    "with a short plain-text summary. Do not invent documents."
)

TOOLS = [
    {"type": "function", "function": {
        "name": "read", "description": "Read one document by its id.",
        "parameters": {"type": "object", "properties": {"doc_id": {"type": "string"}},
                       "required": ["doc_id"]}}},
    {"type": "function", "function": {
        "name": "search", "description": "Search documents by a keyword in title or body.",
        "parameters": {"type": "object", "properties": {"keyword": {"type": "string"}},
                       "required": ["keyword"]}}},
    {"type": "function", "function": {
        "name": "append", "description": "Append a reply to one document by its id.",
        "parameters": {"type": "object",
                       "properties": {"doc_id": {"type": "string"}, "reply": {"type": "string"}},
                       "required": ["doc_id", "reply"]}}},
]


class State(TypedDict, total=False):
    messages: list[dict]
    token: str
    pending: list[dict]
    rounds: int
    tool_calls: list[dict]


def call_model(messages: list[dict], token: str) -> dict:
    r = httpx2.post(MODEL_URL, timeout=180, headers={"authorization": f"Bearer {token}"},
                    json={"model": MODEL, "messages": messages, "tools": TOOLS,
                          "temperature": 0, "stream": False})
    r.raise_for_status()
    return r.json()["choices"][0]["message"]


async def _call_tool(name: str, arguments: dict, token: str) -> dict:
    # One MCP session per tool call, carrying the user's token.
    client = httpx2.AsyncClient(headers={"authorization": f"Bearer {token}"},
                                timeout=httpx2.Timeout(30, read=60))
    async with client, streamable_http_client(MCP_URL, http_client=client) as (r, w):
        async with ClientSession(r, w) as session:
            await session.initialize()
            result = await session.call_tool(name, arguments)
    if result.structured_content:
        return result.structured_content
    text = " ".join(c.text for c in result.content if getattr(c, "text", None))
    return {"error": text} if result.is_error else {"content": text}


def call_tool(name: str, arguments: dict, token: str) -> dict:
    try:
        return asyncio.run(_call_tool(name, arguments, token))
    except Exception as exc:  # noqa: BLE001 - the error goes back to the model
        return {"error": _error_message(exc)}


def _error_message(exc: BaseException) -> str:
    """The MCP error inside the exception groups the MCP client raises."""
    if isinstance(exc, MCPError):
        return exc.message
    for inner in getattr(exc, "exceptions", ()):
        message = _error_message(inner)
        if message:
            return message
    return "" if getattr(exc, "exceptions", None) else type(exc).__name__


def model_node(state: State) -> dict:
    message = call_model(state["messages"], state["token"])
    calls = message.get("tool_calls") or []
    entry = {"role": "assistant", "content": message.get("content") or ""}
    if calls:
        entry["tool_calls"] = calls
    return {"messages": state["messages"] + [entry], "pending": calls}


def tools_node(state: State) -> dict:
    messages, record = list(state["messages"]), list(state.get("tool_calls", []))
    for call in state["pending"]:
        name = call["function"]["name"]
        args = call["function"].get("arguments") or {}
        args = json.loads(args) if isinstance(args, str) else args
        if len(record) >= MAX_TOOL_CALLS:
            result = {"error": f"not called: this request already made {MAX_TOOL_CALLS} tool calls"}
        else:
            result = call_tool(name, args, state["token"])
        record.append({"tool": name, "arguments": args, "result": result})
        messages.append({"role": "tool", "tool_call_id": call.get("id", ""), "content": json.dumps(result)})
    return {"messages": messages, "pending": [], "rounds": state.get("rounds", 0) + 1, "tool_calls": record}


def route(state: State) -> str:
    return "tools" if state.get("pending") and state.get("rounds", 0) < MAX_TOOL_ROUNDS else END


def build():
    g = StateGraph(State)
    g.add_node("model", model_node)
    g.add_node("tools", tools_node)
    g.add_edge(START, "model")
    g.add_conditional_edges("model", route, {"tools": "tools", END: END})
    g.add_edge("tools", "model")
    return g.compile()


def run(graph: Any, prompt: str, token: str) -> dict:
    state = graph.invoke({"messages": [{"role": "system", "content": SYSTEM_PROMPT},
                                       {"role": "user", "content": prompt}],
                          "token": token, "rounds": 0, "tool_calls": []})
    return {"answer": state["messages"][-1].get("content", ""), "tool_calls": state.get("tool_calls", [])}
