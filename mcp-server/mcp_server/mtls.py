"""Mutual TLS in the MCP server process, with its SPIRE SVID.

The server presents its own SVID and accepts a connection only if the peer's
SPIFFE ID is the gateway's. The SVID is rotated by SPIRE; every update is
reloaded into the same SSL context.
"""

from __future__ import annotations

import logging
import os
import ssl
import threading

from cryptography.hazmat.primitives import serialization
from uvicorn.protocols.http.h11_impl import H11Protocol

log = logging.getLogger("mcp_server")


class SvidContext:
    def __init__(self, socket_path: str, svid_dir: str) -> None:
        from spiffe import X509Source

        self._dir = svid_dir
        self._lock = threading.Lock()
        os.makedirs(svid_dir, mode=0o700, exist_ok=True)
        self._source = X509Source(socket_path=socket_path)
        self.ssl = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
        self.ssl.minimum_version = ssl.TLSVersion.TLSv1_2
        self.ssl.verify_mode = ssl.CERT_REQUIRED
        self._load()
        self._source.subscribe_for_updates(self._load)

    def _write(self, name: str, data: bytes) -> str:
        path = os.path.join(self._dir, name)
        with os.fdopen(os.open(path, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600), "wb") as f:
            f.write(data)
        return path

    def _load(self) -> None:
        with self._lock:
            svid = self._source.svid
            chain = b"".join(c.public_bytes(serialization.Encoding.PEM) for c in svid.cert_chain)
            key = svid.private_key.private_bytes(serialization.Encoding.PEM,
                                                 serialization.PrivateFormat.PKCS8,
                                                 serialization.NoEncryption())
            roots = b"".join(a.public_bytes(serialization.Encoding.PEM)
                             for b in self._source.bundles for a in b.x509_authorities)
            self.ssl.load_cert_chain(self._write("svid.pem", chain), self._write("key.pem", key))
            self.ssl.load_verify_locations(cafile=self._write("bundle.pem", roots))
            log.info("svid loaded spiffe_id=%s", svid.spiffe_id)


def peer_checking_protocol(expected_peer: str) -> type[H11Protocol]:
    """An HTTP protocol that closes any TLS connection from another SPIFFE ID."""

    class PeerCheckingH11(H11Protocol):
        def connection_made(self, transport) -> None:  # type: ignore[override]
            sslobj = transport.get_extra_info("ssl_object")
            cert = sslobj.getpeercert() if sslobj is not None else {}
            ids = [v for k, v in (cert or {}).get("subjectAltName", ()) if k == "URI"]
            if expected_peer not in ids:
                log.warning("peer refused spiffe_ids=%s", ids)
                transport.close()
                return
            super().connection_made(transport)

    return PeerCheckingH11
