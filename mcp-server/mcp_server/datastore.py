"""One PostgreSQL connection per tool call, opened with that call's credential.

The MCP server holds no database credential of its own. It connects as the
role OpenBao created for this call, runs one statement, and closes the
connection.
"""

from __future__ import annotations

import os
from typing import Any, Sequence

import psycopg

from .credential import Credential

DB_HOST = "postgres.platform.svc.cluster.local"
DB_CA = "/platform-ca/ca.crt"


class DatastoreError(Exception):
    pass


def run(cred: Credential, sql: str, params: Sequence[Any]) -> list[tuple]:
    try:
        with psycopg.connect(host=DB_HOST, port=5432, dbname="tvm",
                             user=cred.username, password=cred.password,
                             sslmode="verify-full", sslrootcert=DB_CA,
                             connect_timeout=int(os.environ.get("DB_CONNECT_TIMEOUT_S", "5")),
                             application_name="mcp-server") as conn:
            with conn.cursor() as cur:
                cur.execute(sql, params)
                rows = cur.fetchall() if cur.description else []
            conn.commit()
            return rows
    except psycopg.Error as exc:
        raise DatastoreError(f"sqlstate {exc.sqlstate or 'unknown'}") from None
