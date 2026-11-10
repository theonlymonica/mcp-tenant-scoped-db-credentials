"""The three tools and the one statement each of them runs.

No statement mentions the tenant: the rows a statement can see are decided by
PostgreSQL, from the role the connection logged in as. A document of another
tenant and a document that does not exist give the same answer (found: false),
so the answer does not reveal that a document exists elsewhere.
"""

from __future__ import annotations

import datetime as dt
from typing import Any, Callable, Mapping

from mcp.types import Tool

from .credential import Credential
from .datastore import run

TOOLS = [
    Tool(
        name="read",
        description="Read one document by its id. Returns found=false when no document "
                    "with that id is visible.",
        input_schema={"type": "object", "properties": {"doc_id": {"type": "string"}},
                     "required": ["doc_id"]},
    ),
    Tool(
        name="search",
        description="Search the visible documents whose title or body contains the keyword. "
                    "The empty keyword matches every visible document.",
        input_schema={"type": "object", "properties": {"keyword": {"type": "string"}},
                     "required": ["keyword"]},
    ),
    Tool(
        name="append",
        description="Append a reply to one document by its id. Returns appended=false when "
                    "no document with that id is visible.",
        input_schema={"type": "object",
                     "properties": {"doc_id": {"type": "string"}, "reply": {"type": "string"}},
                     "required": ["doc_id", "reply"]},
    ),
]

SQL_READ = "SELECT doc_id, title, body, replies, updated_at FROM app.documents WHERE doc_id = %s"
SQL_SEARCH = ("SELECT doc_id, title FROM app.documents "
              "WHERE title ILIKE '%%' || %s || '%%' OR body ILIKE '%%' || %s || '%%' ORDER BY doc_id")
SQL_APPEND = ("UPDATE app.documents SET replies = replies || %s, updated_at = now() "
              "WHERE doc_id = %s RETURNING doc_id")


class InvalidArgument(Exception):
    pass


def _arg(arguments: Mapping[str, Any], name: str) -> str:
    value = arguments.get(name)
    if not isinstance(value, str):
        raise InvalidArgument(f"argument {name!r} must be a string")
    return value


def _json(value: Any) -> Any:
    return value.isoformat() if isinstance(value, (dt.datetime, dt.date)) else value


def read(arguments, cred: Credential) -> dict:
    rows = run(cred, SQL_READ, (_arg(arguments, "doc_id"),))
    if not rows:
        return {"found": False, "request_id": cred.request_id}
    cols = ("doc_id", "title", "body", "replies", "updated_at")
    return {"found": True, "document": {c: _json(v) for c, v in zip(cols, rows[0])},
            "request_id": cred.request_id}


def search(arguments, cred: Credential) -> dict:
    keyword = _arg(arguments, "keyword")
    rows = run(cred, SQL_SEARCH, (keyword, keyword))
    results = [{"doc_id": r[0], "title": r[1]} for r in rows]
    return {"results": results, "count": len(results), "request_id": cred.request_id}


def append(arguments, cred: Credential) -> dict:
    rows = run(cred, SQL_APPEND, (_arg(arguments, "reply"), _arg(arguments, "doc_id")))
    if not rows:
        return {"appended": False, "request_id": cred.request_id}
    return {"appended": True, "doc_id": rows[0][0], "request_id": cred.request_id}


HANDLERS: dict[str, Callable[[Mapping[str, Any], Credential], dict]] = {
    "read": read, "search": search, "append": append,
}

# The operation whose credential each tool needs: the same table as
# operation_of in opa/policy.rego. A tool runs only with a credential that was
# issued for its own operation, although the read columns would be enough to
# run search too.
OPERATION_OF: dict[str, str] = {"read": "read", "search": "search", "append": "append"}
