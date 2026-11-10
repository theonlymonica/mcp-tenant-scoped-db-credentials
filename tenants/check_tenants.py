"""Checks that every file naming the tenants agrees with tenants/tenants.json.

Adding a tenant means editing this registry, postgres/schema.sql,
openbao/install.sh, openbao/interceptor-policy.hcl, opa/policy.rego and the
Interceptor's table in interceptor/interceptor/scopes.py; adding an operation
also means postgres/pg_hba.conf and the MCP server's tools. Run this after the
edit; it prints every disagreement and exits non-zero if there is one.

A (tenant, operation) pair exists only where the registry allows the tenant
that tool: nowhere may a credential path, a role or a policy line exist for a
pair the tenant is refused.

    python3 tenants/check_tenants.py
"""

from __future__ import annotations

import json
import re
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent


def read(path: str) -> str:
    return (ROOT / path).read_text()


def main() -> int:
    registry = json.loads(read("tenants/tenants.json"))
    tenants = {t["name"] for t in registry["tenants"]}
    operations = set(registry["operations"])
    tools = {t["name"]: set(t["tools"]) for t in registry["tenants"]}
    pairs = {f"{t}-{o}" for t, allowed in tools.items() for o in allowed}
    problems: list[str] = []

    def same(what: str, found: set, expected: set) -> None:
        if found != expected:
            problems.append(f"{what}: found {sorted(found)}, expected {sorted(expected)}")

    for t, allowed in tools.items():
        if not allowed <= operations:
            problems.append(f"tenants.json: {t} is allowed unknown operation(s) {sorted(allowed - operations)}")

    scopes = read("interceptor/interceptor/scopes.py")
    same("scopes.py OPERATIONS", set(re.findall(r'"([^"]+)"', re.search(r"OPERATIONS = \(([^)]*)\)", scopes)[1])), operations)
    block = re.search(r"ALLOWED_OPERATIONS[^=]*= MappingProxyType\(\{(.*?)\n\}\)", scopes, re.S)[1]
    found_allowed = {name: set(re.findall(r'"(\w+)"', ops))
                     for name, ops in re.findall(r'"([\w-]+)":\s*\(([^)]*)\)', block)}
    same("scopes.py ALLOWED_OPERATIONS tenants", set(found_allowed), tenants)
    for t in tenants & set(found_allowed):
        same(f"scopes.py ALLOWED_OPERATIONS of {t}", found_allowed[t], tools[t])

    same("interceptor-policy.hcl paths",
         set(re.findall(r'path "database/creds/([^"]+)"', read("openbao/interceptor-policy.hcl"))), pairs)

    install = read("openbao/install.sh")
    same("openbao/install.sh PAIRS",
         {p.replace(":", "-") for p in re.search(r"PAIRS=\(([^)]*)\)", install)[1].split()}, pairs)

    schema = read("postgres/schema.sql")
    same("schema.sql tenant roles", set(re.findall(r"CREATE ROLE scope_(\w+)", schema)), tenants)
    same("schema.sql operation roles", set(re.findall(r"CREATE ROLE op_(\w+)", schema)), operations)
    for kind, word in (("allow", "PERMISSIVE"), ("restrict", "RESTRICTIVE")):
        same(f"schema.sql {word} policies",
             set(re.findall(rf"CREATE POLICY documents_{kind}_(\w+)", schema)), tenants)
        for t in tenants:
            body = (f"CREATE POLICY documents_{kind}_{t} ON app.documents\n    AS {word} FOR ALL\n"
                    f"    TO scope_{t}\n    USING (scope = '{t}') WITH CHECK (scope = '{t}');")
            if body not in schema:
                problems.append(f"schema.sql: no {word} policy for {t} alone with its own condition")
    if any("USING (true)" in line for line in schema.splitlines() if not line.lstrip().startswith("--")):
        problems.append("schema.sql: a policy says USING (true)")

    hba = read("postgres/pg_hba.conf")
    same("pg_hba.conf operation roles", set(re.findall(r"\+op_(\w+)", hba)), operations)

    same("mcp-server tools.py OPERATION_OF",
         set(re.findall(r'"\w+": "(\w+)"', re.search(r"OPERATION_OF[^=]*= \{([^}]*)\}",
                                                     read("mcp-server/mcp_server/tools.py"))[1])), operations)

    rego = read("opa/policy.rego")
    block = re.search(r"tool_allowed := \{(.*?)\n\}", rego, re.S)[1]
    found_tools = {name: set(re.findall(r'"(\w+)"', allowed))
                   for name, allowed in re.findall(r'"([\w-]+)":\s*\{([^}]*)\}', block)}
    same("policy.rego tenants", set(found_tools), tenants)
    for t in tenants & set(found_tools):
        same(f"policy.rego tools of {t}", found_tools[t], tools[t])
    same("policy.rego operation_of",
         set(re.findall(r'"\w+":\s*"(\w+)"', re.search(r"operation_of := \{(.*?)\n\}", rego, re.S)[1])), operations)

    for p in problems:
        print("MISMATCH", p)
    print("tenant registry: " + ("OK" if not problems else f"{len(problems)} mismatch(es)"))
    return 1 if problems else 0


if __name__ == "__main__":
    sys.exit(main())
