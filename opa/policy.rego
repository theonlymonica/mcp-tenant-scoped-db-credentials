# Which tools each tenant may use. OPA runs as a sidecar of the Interceptor and
# is asked once per tools/call with {tenant, tool, agent}. It never sees the tool
# arguments.
#
# authorized_operation is what the Interceptor mints the credential for, so the
# operation comes from this decision and not from the tool name in the request.
package tvm.mcp

import rego.v1

default allowed := false

agent_identity := "spiffe://tvm.local/workload/agent"

tool_allowed := {
	"tenant1": {"read", "search", "append"},
	"tenant2": {"read", "search"},
}

operation_of := {
	"read": "read",
	"search": "search",
	"append": "append",
}

allowed if {
	input.agent == agent_identity
	input.tool in tool_allowed[input.tenant]
}

decision := {"allowed": true, "authorized_operation": operation_of[input.tool]} if allowed

decision := {"allowed": false} if not allowed
