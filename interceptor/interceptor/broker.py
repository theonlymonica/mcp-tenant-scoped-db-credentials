"""Getting one PostgreSQL credential from OpenBao for one tool call.

For every call the Interceptor reads its SVID from the SPIRE Workload API,
logs in to OpenBao with it (auth/cert, mutual TLS), and reads the credential
path of the resolved (tenant, operation) pair. Nothing is cached between
calls: no SVID, no OpenBao token, no credential.

The Interceptor never holds the credential. It asks OpenBao to wrap the
response: OpenBao keeps the username and password and returns a wrapping
token that can be exchanged for them once, within WRAP_TTL_SECONDS. That token
is what travels through the gateway; the MCP server unwraps it. The
Interceptor's OpenBao policy refuses a request that does not ask for wrapping.

The SVID's key is written to a memory-backed directory only for the length of
the TLS handshake, because Python's ssl module loads keys from files.
"""

from __future__ import annotations

import http.client
import json
import os
import ssl
import tempfile
from dataclasses import dataclass
from urllib.parse import urlparse

from . import scopes

WRAP_TTL_SECONDS = 10


class MintFailure(Exception):
    """No credential. str() is a short reason, never a secret."""


@dataclass(frozen=True)
class WrappedCredential:
    wrap_token: str      # single use; exchanged for the credential by the MCP server
    accessor: str        # identifies the wrapping token in the OpenBao audit log; not a secret
    ttl_s: int

    def __repr__(self) -> str:
        return f"WrappedCredential(accessor={self.accessor!r}, wrap_token=<redacted>)"


class WorkloadApiSvidSource:
    """The Interceptor's X.509-SVID, fetched fresh from the SPIRE Agent."""

    def __init__(self, socket_path: str, timeout_s: float) -> None:
        self._socket = socket_path
        self._timeout = timeout_s

    def fetch(self) -> tuple[bytes, bytes]:
        from cryptography.hazmat.primitives import serialization
        from spiffe import WorkloadApiClient

        try:
            with WorkloadApiClient(socket_path=self._socket, default_timeout=self._timeout) as client:
                svid = client.fetch_x509_svid()
        except Exception as exc:  # noqa: BLE001
            raise MintFailure("svid_unavailable") from exc
        chain = b"".join(c.public_bytes(serialization.Encoding.PEM) for c in svid.cert_chain)
        key = svid.private_key.private_bytes(
            serialization.Encoding.PEM, serialization.PrivateFormat.PKCS8,
            serialization.NoEncryption())
        return chain, key


class OpenBaoMinter:
    def __init__(self, addr: str, ca_file: str, cert_role: str,
                 svid_source: WorkloadApiSvidSource, timeout_s: float, svid_dir: str) -> None:
        url = urlparse(addr)
        self._host, self._port = url.hostname, url.port or 443
        self._ca_file = ca_file
        self._cert_role = cert_role
        self._svid = svid_source
        self._timeout = timeout_s
        self._svid_dir = svid_dir

    def mint(self, resolved: scopes.ResolvedScope) -> WrappedCredential:
        chain, key = self._svid.fetch()
        os.makedirs(self._svid_dir, mode=0o700, exist_ok=True)
        with tempfile.TemporaryDirectory(dir=self._svid_dir) as tmp:
            cert_path, key_path = os.path.join(tmp, "svid.pem"), os.path.join(tmp, "svid.key")
            with open(cert_path, "wb") as f:
                f.write(chain)
            with os.fdopen(os.open(key_path, os.O_WRONLY | os.O_CREAT, 0o600), "wb") as f:
                f.write(key)
            ctx = ssl.create_default_context(cafile=self._ca_file)
            ctx.load_cert_chain(cert_path, key_path)
            conn = http.client.HTTPSConnection(self._host, self._port, timeout=self._timeout, context=ctx)
            try:
                conn.connect()
            except (OSError, ssl.SSLError) as exc:
                raise MintFailure("broker_unreachable") from exc
        try:
            status, body = _call(conn, "POST", "/v1/auth/cert/login", None, {"name": self._cert_role})
            token = (body.get("auth") or {}).get("client_token")
            if status != 200 or not token:
                raise MintFailure("login_refused")
            status, body = _call(conn, "GET", "/v1/" + resolved.credential_path, token, None,
                                 wrap_ttl=f"{WRAP_TTL_SECONDS}s")
            if status != 200:
                raise MintFailure("credential_refused")
        finally:
            conn.close()

        # A wrapped response carries wrap_info and no data. Anything else means
        # OpenBao answered with the credential itself, which must not go on.
        info = body.get("wrap_info") or {}
        wrap_token, accessor, ttl = info.get("token"), info.get("accessor"), info.get("ttl")
        if body.get("data") or not isinstance(wrap_token, str) or not wrap_token \
                or not isinstance(accessor, str) or not accessor \
                or not isinstance(ttl, int) or not 0 < ttl <= WRAP_TTL_SECONDS \
                or info.get("creation_path") != resolved.credential_path:
            raise MintFailure("malformed_credential")
        return WrappedCredential(wrap_token=wrap_token, accessor=accessor, ttl_s=ttl)


def _call(conn, method, path, token, body, wrap_ttl=None):
    headers = {"Content-Type": "application/json"}
    if token:
        headers["X-Vault-Token"] = token
    if wrap_ttl:
        headers["X-Vault-Wrap-TTL"] = wrap_ttl
    try:
        conn.request(method, path, body=json.dumps(body) if body is not None else None, headers=headers)
        resp = conn.getresponse()
        raw = resp.read()
    except (OSError, http.client.HTTPException) as exc:
        raise MintFailure("broker_unreachable") from exc
    try:
        parsed = json.loads(raw) if raw else {}
    except ValueError:
        parsed = {}
    return resp.status, parsed if isinstance(parsed, dict) else {}
