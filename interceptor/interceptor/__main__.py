"""python -m interceptor: serve the ExtMCP service on loopback.

The Envoy container in the same pod terminates mutual TLS on port 9002 and
admits only the gateway's SPIFFE ID; this process listens on 127.0.0.1:9003.
"""

from __future__ import annotations

import logging
import os
import signal
import sys
import threading
from concurrent import futures

import ext_mcp_pb2_grpc as pbg
import grpc

from .broker import OpenBaoMinter, WorkloadApiSvidSource
from .extmcp import ExtMcpService
from .jwt_verify import JwtVerifier
from .limits import TenantLimiter
from .opa_client import OpaClient

LISTEN = "127.0.0.1:9003"
OPENBAO_ADDR = "https://openbao.platform.svc.cluster.local:8200"
OPENBAO_CERT_ROLE = "interceptor"
SPIRE_SOCKET = "unix:///run/spire/sockets/agent.sock"
CA_FILE = "/platform-ca/ca.crt"          # signs the OpenBao and Keycloak server certificates
SVID_DIR = "/run/interceptor"             # memory-backed emptyDir
TIMEOUT_S = float(os.environ.get("INTERCEPTOR_TIMEOUT_S", "1.5"))
# Per tenant: credentials per second, burst, and requests waiting on OpenBao at once.
TENANT_RATE = float(os.environ.get("INTERCEPTOR_TENANT_RATE", "10"))
TENANT_BURST = int(os.environ.get("INTERCEPTOR_TENANT_BURST", "20"))
TENANT_IN_FLIGHT = int(os.environ.get("INTERCEPTOR_TENANT_IN_FLIGHT", "6"))


def main() -> int:
    logging.basicConfig(stream=sys.stdout, level=logging.INFO,
                        format="%(asctime)s %(levelname)s %(name)s %(message)s")
    minter = OpenBaoMinter(OPENBAO_ADDR, CA_FILE, OPENBAO_CERT_ROLE,
                           WorkloadApiSvidSource(SPIRE_SOCKET, TIMEOUT_S), TIMEOUT_S, SVID_DIR)
    service = ExtMcpService(minter, JwtVerifier(CA_FILE, TIMEOUT_S), OpaClient(timeout_s=0.5),
                            TenantLimiter(TENANT_RATE, TENANT_BURST, TENANT_IN_FLIGHT))

    server = grpc.server(futures.ThreadPoolExecutor(max_workers=16))
    pbg.add_ExtMcpServicer_to_server(service, server)
    server.add_insecure_port(LISTEN)
    server.start()
    logging.getLogger("interceptor").info("listening on %s", LISTEN)

    stop = threading.Event()
    signal.signal(signal.SIGTERM, lambda *_: stop.set())
    signal.signal(signal.SIGINT, lambda *_: stop.set())
    stop.wait()
    server.stop(5).wait()
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
