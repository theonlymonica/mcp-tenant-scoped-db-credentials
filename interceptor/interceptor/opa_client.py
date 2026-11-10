"""Asking OPA, the sidecar in the same pod, whether a tenant may use a tool.

OPA receives the tenant, the tool name and the agent's SPIFFE ID, never the
tool arguments. Anything other than an explicit allow with an
authorized_operation is a denial.
"""

from __future__ import annotations

import json
import urllib.request
from dataclasses import dataclass
from typing import Optional

DECISION_URL = "http://127.0.0.1:8181/v1/data/tvm/mcp/decision"


@dataclass(frozen=True)
class Decision:
    allowed: bool
    authorized_operation: Optional[str]
    reason: str


class OpaClient:
    def __init__(self, timeout_s: float) -> None:
        self._timeout = timeout_s

    def decide(self, *, tenant: str, tool: str, agent: str) -> Decision:
        body = json.dumps({"input": {"tenant": tenant, "tool": tool, "agent": agent}}).encode()
        req = urllib.request.Request(DECISION_URL, data=body, method="POST",
                                     headers={"content-type": "application/json"})
        try:
            with urllib.request.urlopen(req, timeout=self._timeout) as resp:  # noqa: S310
                result = json.loads(resp.read()).get("result")
        except (OSError, ValueError, AttributeError):
            return Decision(False, None, "opa_unreachable")
        if not isinstance(result, dict) or result.get("allowed") is not True:
            return Decision(False, None, "opa_denied")
        op = result.get("authorized_operation")
        if not isinstance(op, str) or not op:
            return Decision(False, None, "opa_no_operation")
        return Decision(True, op, "allowed")
