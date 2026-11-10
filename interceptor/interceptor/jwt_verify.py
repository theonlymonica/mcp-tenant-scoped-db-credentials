"""Verifying the user's token against the Keycloak keys.

The gateway verifies the token too, but the Interceptor does not trust that:
it receives the token and checks it again before it requests a credential.
Checked: RS256 signature with a key from the realm JWKS (fetched over HTTPS),
issuer, audience (the MCP endpoint), expiry, and the client the token was
issued to (`azp`). The last one matters because the tenant is a claim: any
client of the realm with a mapper of its own could put a `scope_group` and
this audience in a token, so only the client whose mappers are reviewed
(keycloak/realm.json) is accepted.
"""

from __future__ import annotations

import ssl
from typing import Any, Mapping

import jwt

ALGORITHMS = ["RS256"]
ISSUER = "http://keycloak.platform.svc.cluster.local:8080/realms/tvm"
AUDIENCE = "https://mcp-gateway.platform.svc.cluster.local:8443/mcp"
JWKS_URL = "https://keycloak.platform.svc.cluster.local:8443/realms/tvm/protocol/openid-connect/certs"
ALLOWED_CLIENTS = ("mcp-client",)


class TokenInvalid(Exception):
    """str() is a short reason, never the token."""


class JwtVerifier:
    def __init__(self, ca_file: str, timeout_s: float) -> None:
        self._jwks = jwt.PyJWKClient(
            JWKS_URL,
            cache_jwk_set=True,
            lifespan=300,
            timeout=timeout_s,
            ssl_context=ssl.create_default_context(cafile=ca_file),
        )

    def verify(self, token: str) -> Mapping[str, Any]:
        try:
            if jwt.get_unverified_header(token).get("alg") not in ALGORITHMS:
                raise TokenInvalid("algorithm_not_allowed")
            key = self._jwks.get_signing_key_from_jwt(token)
            verified = jwt.decode(
                token, key.key, algorithms=ALGORITHMS, audience=AUDIENCE, issuer=ISSUER,
                options={"require": ["exp", "iat", "iss", "aud", "sub", "azp"]},
            )
        except jwt.ExpiredSignatureError:
            raise TokenInvalid("expired") from None
        except jwt.InvalidAudienceError:
            raise TokenInvalid("wrong_audience") from None
        except jwt.PyJWKClientConnectionError:
            raise TokenInvalid("jwks_unreachable") from None
        except jwt.PyJWTError:
            raise TokenInvalid("invalid_token") from None
        if verified.get("azp") not in ALLOWED_CLIENTS:
            raise TokenInvalid("client_not_allowed")
        return verified


def bearer_from_headers(headers) -> str:
    """The token of the single `authorization: Bearer ...` header.

    Zero or two authorization headers is a refusal, not a choice.
    """
    values = [h.value for h in headers if h.key.lower() == "authorization"]
    if len(values) != 1:
        raise TokenInvalid("authorization_not_exactly_once")
    scheme, _, token = values[0].decode("ascii", "replace").partition(" ")
    if scheme.lower() != "bearer" or not token.strip():
        raise TokenInvalid("not_a_bearer_token")
    return token.strip()
