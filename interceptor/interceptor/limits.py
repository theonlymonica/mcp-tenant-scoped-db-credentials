"""A limit on how many credentials one tenant can ask for.

Every tenant shares one OpenBao queue: OpenBao creates and drops PostgreSQL
roles one at a time. Without a limit, one tenant (or one manipulated model
calling tools in a loop) fills that queue and every other tenant waits behind
it. So before the Interceptor asks OpenBao for anything, the tenant must have:

  * a token in its bucket (RATE credentials per second, bursts of BURST);
  * fewer than IN_FLIGHT requests already waiting on OpenBao.

A refusal costs OpenBao nothing. The second limit also bounds the roles
created for requests the Interceptor has already given up on: when its timeout
fires, OpenBao still finishes creating the role.

The counters live in this process, so with several Interceptor replicas each
one enforces the limit on its own share of the traffic.
"""

from __future__ import annotations

import threading
import time
from typing import Optional


class TenantLimiter:
    def __init__(self, rate: float, burst: int, in_flight: int) -> None:
        self._rate, self._burst, self._max_in_flight = rate, burst, in_flight
        self._lock = threading.Lock()
        self._tokens: dict[str, float] = {}
        self._stamp: dict[str, float] = {}
        self._in_flight: dict[str, int] = {}

    def enter(self, tenant: str) -> Optional[str]:
        """None if the tenant may go on, otherwise the reason it may not.

        Every None must be matched by one leave().
        """
        now = time.monotonic()
        with self._lock:
            if self._in_flight.get(tenant, 0) >= self._max_in_flight:
                return "tenant_too_many_in_flight"
            elapsed = now - self._stamp.get(tenant, now)
            tokens = min(float(self._burst), self._tokens.get(tenant, float(self._burst)) + elapsed * self._rate)
            self._stamp[tenant] = now
            if tokens < 1.0:
                self._tokens[tenant] = tokens
                return "tenant_rate_exceeded"
            self._tokens[tenant] = tokens - 1.0
            self._in_flight[tenant] = self._in_flight.get(tenant, 0) + 1
            return None

    def leave(self, tenant: str) -> None:
        with self._lock:
            self._in_flight[tenant] = max(0, self._in_flight.get(tenant, 0) - 1)
