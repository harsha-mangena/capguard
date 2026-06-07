"""OAuth 2.1 resource-server auth for the HTTP MCP boundary.

Research (June 2026 MCP authorization spec, RFC 9728 / RFC 8707): a protected
MCP server is an OAuth 2.1 **resource server** — it *validates* bearer tokens
issued by an external authorization server, it does not issue them. The wire
contract this module implements:

  * Every MCP request carries ``Authorization: Bearer <token>``.
  * Missing/invalid token → ``401`` with a ``WWW-Authenticate: Bearer
    resource_metadata="…"`` header pointing at the Protected Resource Metadata
    (RFC 9728), so a client can discover the authorization server.
  * Insufficient scope → ``403`` with ``WWW-Authenticate`` (``error="insufficient_scope"``).
  * The token's **audience** MUST identify this server (RFC 8707), so a token
    minted for another resource can't be replayed here (confused-deputy defense).
  * The PRM document is served (publicly) at
    ``/.well-known/oauth-protected-resource``.

Verification is pluggable and stdlib-only (no PyJWT dependency):
  * :class:`StaticTokenVerifier` — a fixed token→principal map (tests / simple deploys).
  * :class:`HMACJWTVerifier` — verifies a compact HS256 JWS, pinning ``alg`` (to
    defeat ``alg:none`` / RS↔HS confusion), checking ``exp`` and ``aud``. Includes
    a ``mint`` helper for self-issued tokens and tests.

This is the *transport* gate ("may this caller talk to the guard at all"); it
composes with CapGuard's signed-identity gate ("which agent is acting") and the
policy/capability enforcement underneath. All deterministic.
"""

from __future__ import annotations

import base64
import hashlib
import hmac
import json
import time
from dataclasses import dataclass, field
from typing import Any, Dict, FrozenSet, List, Mapping, Optional, Protocol


class TokenError(Exception):
    """Raised when a bearer token is missing, malformed, expired, or wrong-audience."""


@dataclass
class TokenClaims:
    subject: str = ""
    scopes: FrozenSet[str] = field(default_factory=frozenset)
    audience: Optional[str] = None
    expires_at: Optional[int] = None
    raw: Dict[str, Any] = field(default_factory=dict)


class TokenVerifier(Protocol):
    def verify(self, token: str) -> TokenClaims: ...


# --------------------------------------------------------------------------- #
# base64url helpers (no padding, per JWS)
# --------------------------------------------------------------------------- #
def _b64url_encode(b: bytes) -> str:
    return base64.urlsafe_b64encode(b).rstrip(b"=").decode("ascii")


def _b64url_decode(s: str) -> bytes:
    return base64.urlsafe_b64decode(s + "=" * (-len(s) % 4))


# --------------------------------------------------------------------------- #
# verifiers
# --------------------------------------------------------------------------- #
class StaticTokenVerifier:
    """Validate against a fixed ``token -> {subject, scopes, audience}`` map."""

    def __init__(self, tokens: Mapping[str, Mapping[str, Any]],
                 *, audience: Optional[str] = None) -> None:
        self._tokens = {k: dict(v) for k, v in tokens.items()}
        self._audience = audience

    def verify(self, token: str) -> TokenClaims:
        info = self._tokens.get(token)
        if info is None:
            raise TokenError("unknown bearer token")
        aud = info.get("audience")
        if self._audience is not None and aud is not None and aud != self._audience:
            raise TokenError("token audience mismatch")
        return TokenClaims(
            subject=info.get("subject", ""),
            scopes=frozenset(info.get("scopes", [])),
            audience=aud,
            raw=dict(info),
        )


class HMACJWTVerifier:
    """Verify (and optionally mint) a compact HS256 JWT with a shared secret."""

    def __init__(self, secret: bytes, *, audience: Optional[str] = None,
                 leeway_seconds: int = 30) -> None:
        self._secret = secret
        self._audience = audience
        self._leeway = leeway_seconds

    def verify(self, token: str) -> TokenClaims:
        parts = token.split(".")
        if len(parts) != 3:
            raise TokenError("malformed JWT")
        header_b64, payload_b64, sig_b64 = parts
        try:
            header = json.loads(_b64url_decode(header_b64))
        except Exception as exc:  # noqa: BLE001
            raise TokenError("unreadable JWT header") from exc
        # pin the algorithm: defeats alg:none and RS256<->HS256 confusion attacks
        if header.get("alg") != "HS256":
            raise TokenError(f"unexpected JWT alg {header.get('alg')!r}; only HS256 accepted")
        expected = hmac.new(self._secret, f"{header_b64}.{payload_b64}".encode(), hashlib.sha256).digest()
        try:
            sig = _b64url_decode(sig_b64)
        except Exception as exc:  # noqa: BLE001
            raise TokenError("bad signature encoding") from exc
        if not hmac.compare_digest(sig, expected):
            raise TokenError("JWT signature mismatch")
        try:
            payload = json.loads(_b64url_decode(payload_b64))
        except Exception as exc:  # noqa: BLE001
            raise TokenError("unreadable JWT payload") from exc

        exp = payload.get("exp")
        if exp is not None and time.time() > float(exp) + self._leeway:
            raise TokenError("token expired")
        if self._audience is not None:
            aud = payload.get("aud")
            auds = aud if isinstance(aud, list) else ([aud] if aud else [])
            if self._audience not in auds:
                raise TokenError("token audience does not match this resource")
        scope = payload.get("scope", "")
        scopes = frozenset(scope.split()) if isinstance(scope, str) else frozenset(scope or [])
        return TokenClaims(subject=payload.get("sub", ""), scopes=scopes,
                           audience=payload.get("aud"), expires_at=exp, raw=payload)

    def mint(self, subject: str, *, scopes=(), audience: Optional[str] = None,
             ttl_seconds: int = 3600, extra: Optional[Mapping[str, Any]] = None) -> str:
        """Issue a token (for self-hosted token issuance / tests)."""
        now = int(time.time())
        payload: Dict[str, Any] = {"sub": subject, "scope": " ".join(scopes),
                                   "iat": now, "exp": now + ttl_seconds}
        aud = audience or self._audience
        if aud:
            payload["aud"] = aud
        if extra:
            payload.update(extra)
        header = {"alg": "HS256", "typ": "JWT"}
        h = _b64url_encode(json.dumps(header, separators=(",", ":")).encode())
        p = _b64url_encode(json.dumps(payload, separators=(",", ":")).encode())
        sig = _b64url_encode(hmac.new(self._secret, f"{h}.{p}".encode(), hashlib.sha256).digest())
        return f"{h}.{p}.{sig}"


# --------------------------------------------------------------------------- #
# RFC 9728 Protected Resource Metadata + WWW-Authenticate
# --------------------------------------------------------------------------- #
@dataclass
class ProtectedResourceMetadata:
    resource: str
    authorization_servers: List[str] = field(default_factory=list)
    scopes_supported: List[str] = field(default_factory=list)

    def to_dict(self) -> Dict[str, Any]:
        return {
            "resource": self.resource,
            "authorization_servers": list(self.authorization_servers),
            "scopes_supported": list(self.scopes_supported),
            "bearer_methods_supported": ["header"],
        }


WELL_KNOWN_PRM_PATH = "/.well-known/oauth-protected-resource"


def www_authenticate(*, resource_metadata_url: Optional[str] = None,
                     error: Optional[str] = None, scope: Optional[str] = None) -> str:
    params: List[str] = []
    if error:
        params.append(f'error="{error}"')
    if scope:
        params.append(f'scope="{scope}"')
    if resource_metadata_url:
        params.append(f'resource_metadata="{resource_metadata_url}"')
    return "Bearer" + ((" " + ", ".join(params)) if params else "")


def extract_bearer(authorization_header: Optional[str]) -> Optional[str]:
    if not authorization_header:
        return None
    parts = authorization_header.split(None, 1)
    if len(parts) != 2 or parts[0].lower() != "bearer":
        return None
    return parts[1].strip()
