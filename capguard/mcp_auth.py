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
  * :class:`JWKSVerifier` — verifies EdDSA or RS256 JWTs from a published JWKS,
    so the guard can trust an external authorization server without holding
    signing material.

This is the *transport* gate ("may this caller talk to the guard at all"); it
composes with CapGuard's signed-identity gate ("which agent is acting") and the
policy/capability enforcement underneath. All deterministic.
"""

from __future__ import annotations

import base64
import hashlib
import hmac
import json
import threading
import time
import urllib.parse
import urllib.request
from dataclasses import dataclass, field
from typing import Any, Dict, FrozenSet, List, Mapping, Optional, Protocol

from .net_safety import validate_http_url


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


def _validate_fetch_url(url: str, label: str) -> str:
    return validate_http_url(url, label=label, error_cls=TokenError)


def _validate_issuer_url(issuer: str) -> str:
    issuer = _validate_fetch_url(issuer, "issuer")
    parsed = urllib.parse.urlparse(issuer)
    if parsed.query or parsed.fragment:
        raise TokenError("issuer URL must not contain query or fragment")
    return issuer.rstrip("/")


def _oauth_well_known_url(issuer: str, suffix: str) -> str:
    parsed = urllib.parse.urlparse(issuer)
    issuer_path = parsed.path.rstrip("/")
    path = f"/.well-known/{suffix}{issuer_path}"
    return urllib.parse.urlunparse((parsed.scheme, parsed.netloc, path, "", "", ""))


def _oidc_well_known_url(issuer: str) -> str:
    return issuer.rstrip("/") + "/.well-known/openid-configuration"


def _metadata_urls_for_issuer(issuer: str, discovery: str = "auto") -> List[str]:
    issuer = _validate_issuer_url(issuer)
    oauth = _oauth_well_known_url(issuer, "oauth-authorization-server")
    oidc = _oidc_well_known_url(issuer)
    if discovery == "oauth":
        return [oauth]
    if discovery == "oidc":
        return [oidc]
    if discovery != "auto":
        raise TokenError("discovery must be 'auto', 'oauth', or 'oidc'")
    urls = [oauth, oidc]
    return list(dict.fromkeys(urls))


# --------------------------------------------------------------------------- #
# base64url helpers (no padding, per JWS)
# --------------------------------------------------------------------------- #
def _b64url_encode(b: bytes) -> str:
    return base64.urlsafe_b64encode(b).rstrip(b"=").decode("ascii")


def _b64url_decode(s: str) -> bytes:
    return base64.urlsafe_b64decode(s + "=" * (-len(s) % 4))


def _int_to_b64url(n: int) -> str:
    return _b64url_encode(n.to_bytes((n.bit_length() + 7) // 8 or 1, "big"))


def _b64url_to_int(s: str) -> int:
    return int.from_bytes(_b64url_decode(s), "big")


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
        if self._audience is not None and aud != self._audience:
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


def _parse_jwt_unverified(token: str):
    parts = token.split(".")
    if len(parts) != 3:
        raise TokenError("malformed JWT")
    try:
        header = json.loads(_b64url_decode(parts[0]))
        payload = json.loads(_b64url_decode(parts[1]))
    except Exception as exc:  # noqa: BLE001
        raise TokenError("unreadable JWT") from exc
    return header, payload, parts


def _claims_from_payload(payload: Mapping[str, Any], audience: Optional[str], leeway: int) -> "TokenClaims":
    exp = payload.get("exp")
    if exp is not None and time.time() > float(exp) + leeway:
        raise TokenError("token expired")
    if audience is not None:
        aud = payload.get("aud")
        auds = aud if isinstance(aud, list) else ([aud] if aud else [])
        if audience not in auds:
            raise TokenError("token audience does not match this resource")
    scope = payload.get("scope", "")
    scopes = frozenset(scope.split()) if isinstance(scope, str) else frozenset(scope or [])
    return TokenClaims(subject=payload.get("sub", ""), scopes=scopes,
                       audience=payload.get("aud"), expires_at=exp, raw=dict(payload))


class Ed25519JWTVerifier:
    """Verify (and optionally mint) EdDSA JWTs (RFC 8037) — asymmetric, so a
    resource server can verify tokens minted by an external authorization server
    using only its public key. Requires the ``cryptography`` package.
    """

    alg = "EdDSA"

    def __init__(self, public_key: Any = None, *, private_key: Any = None,
                 audience: Optional[str] = None, leeway_seconds: int = 30,
                 kid: str = "ed25519-1") -> None:
        try:
            from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
        except Exception as exc:  # noqa: BLE001
            raise TokenError("Ed25519JWTVerifier requires the 'cryptography' package") from exc
        if private_key is None and public_key is None:
            private_key = Ed25519PrivateKey.generate()
        self._priv = private_key
        self._pub = public_key or (private_key.public_key() if private_key else None)
        self._audience = audience
        self._leeway = leeway_seconds
        self._kid = kid

    def _pub_raw(self) -> bytes:
        from cryptography.hazmat.primitives import serialization
        return self._pub.public_bytes(serialization.Encoding.Raw, serialization.PublicFormat.Raw)

    def public_jwk(self) -> Dict[str, Any]:
        return {"kty": "OKP", "crv": "Ed25519", "use": "sig", "alg": "EdDSA",
                "kid": self._kid, "x": _b64url_encode(self._pub_raw())}

    def jwks(self) -> Dict[str, Any]:
        return {"keys": [self.public_jwk()]}

    def mint(self, subject: str, *, scopes=(), audience: Optional[str] = None,
             ttl_seconds: int = 3600, extra: Optional[Mapping[str, Any]] = None) -> str:
        if self._priv is None:
            raise TokenError("this verifier has no private key (verify-only)")
        now = int(time.time())
        payload: Dict[str, Any] = {"sub": subject, "scope": " ".join(scopes),
                                   "iat": now, "exp": now + ttl_seconds}
        aud = audience or self._audience
        if aud:
            payload["aud"] = aud
        if extra:
            payload.update(extra)
        header = {"alg": "EdDSA", "typ": "JWT", "kid": self._kid}
        h = _b64url_encode(json.dumps(header, separators=(",", ":")).encode())
        p = _b64url_encode(json.dumps(payload, separators=(",", ":")).encode())
        sig = _b64url_encode(self._priv.sign(f"{h}.{p}".encode()))
        return f"{h}.{p}.{sig}"

    def verify(self, token: str) -> TokenClaims:
        from cryptography.exceptions import InvalidSignature
        header, payload, parts = _parse_jwt_unverified(token)
        if header.get("alg") != "EdDSA":
            raise TokenError(f"unexpected JWT alg {header.get('alg')!r}; only EdDSA accepted")
        try:
            self._pub.verify(_b64url_decode(parts[2]), f"{parts[0]}.{parts[1]}".encode())
        except (InvalidSignature, Exception) as exc:  # noqa: BLE001
            raise TokenError("EdDSA signature invalid") from exc
        return _claims_from_payload(payload, self._audience, self._leeway)


class RS256JWTVerifier:
    """Verify (and optionally mint) RS256 JWTs using an RSA public key.

    This is the common shape for enterprise IdPs that publish RSA signing keys
    through JWKS. Requires the ``cryptography`` package.
    """

    alg = "RS256"

    def __init__(self, public_key: Any = None, *, private_key: Any = None,
                 audience: Optional[str] = None, leeway_seconds: int = 30,
                 kid: str = "rsa-1", key_size: int = 2048) -> None:
        try:
            from cryptography.hazmat.primitives.asymmetric import rsa
        except Exception as exc:  # noqa: BLE001
            raise TokenError("RS256JWTVerifier requires the 'cryptography' package") from exc
        if private_key is None and public_key is None:
            private_key = rsa.generate_private_key(public_exponent=65537, key_size=key_size)
        self._priv = private_key
        self._pub = public_key or (private_key.public_key() if private_key else None)
        self._audience = audience
        self._leeway = leeway_seconds
        self._kid = kid

    def public_jwk(self) -> Dict[str, Any]:
        numbers = self._pub.public_numbers()
        return {"kty": "RSA", "use": "sig", "alg": "RS256", "kid": self._kid,
                "n": _int_to_b64url(numbers.n), "e": _int_to_b64url(numbers.e)}

    def jwks(self) -> Dict[str, Any]:
        return {"keys": [self.public_jwk()]}

    def mint(self, subject: str, *, scopes=(), audience: Optional[str] = None,
             ttl_seconds: int = 3600, extra: Optional[Mapping[str, Any]] = None) -> str:
        if self._priv is None:
            raise TokenError("this verifier has no private key (verify-only)")
        from cryptography.hazmat.primitives import hashes
        from cryptography.hazmat.primitives.asymmetric import padding
        now = int(time.time())
        payload: Dict[str, Any] = {"sub": subject, "scope": " ".join(scopes),
                                   "iat": now, "exp": now + ttl_seconds}
        aud = audience or self._audience
        if aud:
            payload["aud"] = aud
        if extra:
            payload.update(extra)
        header = {"alg": "RS256", "typ": "JWT", "kid": self._kid}
        h = _b64url_encode(json.dumps(header, separators=(",", ":")).encode())
        p = _b64url_encode(json.dumps(payload, separators=(",", ":")).encode())
        sig = self._priv.sign(f"{h}.{p}".encode(), padding.PKCS1v15(), hashes.SHA256())
        return f"{h}.{p}.{_b64url_encode(sig)}"

    def verify(self, token: str) -> TokenClaims:
        from cryptography.exceptions import InvalidSignature
        from cryptography.hazmat.primitives import hashes
        from cryptography.hazmat.primitives.asymmetric import padding
        header, payload, parts = _parse_jwt_unverified(token)
        if header.get("alg") != "RS256":
            raise TokenError(f"unexpected JWT alg {header.get('alg')!r}; only RS256 accepted")
        try:
            self._pub.verify(_b64url_decode(parts[2]), f"{parts[0]}.{parts[1]}".encode(),
                             padding.PKCS1v15(), hashes.SHA256())
        except (InvalidSignature, Exception) as exc:  # noqa: BLE001
            raise TokenError("RS256 signature invalid") from exc
        return _claims_from_payload(payload, self._audience, self._leeway)


class JWKSVerifier:
    """Verify EdDSA or RS256 JWTs against a JWKS,
    selecting the key by the token's ``kid`` — the standard way a resource server
    trusts an external authorization server's published keys."""

    alg = "JWKS"

    def __init__(self, jwks: Mapping[str, Any], *, audience: Optional[str] = None,
                 leeway_seconds: int = 30, algorithms: Optional[List[str]] = None,
                 jwks_url: Optional[str] = None, timeout: float = 5.0,
                 cache_ttl_seconds: Optional[float] = None,
                 refresh_on_kid_miss: bool = True) -> None:
        self._audience = audience
        self._leeway = leeway_seconds
        self._allowed_algs = frozenset(algorithms or ["EdDSA", "RS256"])
        self._jwks_url = jwks_url
        self._timeout = timeout
        self._cache_ttl_seconds = cache_ttl_seconds
        self._refresh_on_kid_miss = refresh_on_kid_miss
        self._lock = threading.Lock()
        self._last_refresh = 0.0
        self._replace_jwks(jwks)

    def _parse_jwks(self, jwks: Mapping[str, Any]) -> tuple[Dict[str, List[tuple[str, Any]]],
                                                            List[tuple[str, str, Any]]]:
        from cryptography.hazmat.primitives.asymmetric import rsa
        from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey
        keys_by_kid: Dict[str, List[tuple[str, Any]]] = {}
        all_keys: List[tuple[str, str, Any]] = []
        for jwk in jwks.get("keys", []):
            kid = jwk.get("kid", "")
            jwk_alg = jwk.get("alg")
            if jwk.get("kty") == "OKP" and jwk.get("crv") == "Ed25519" and "EdDSA" in self._allowed_algs:
                if jwk_alg not in (None, "EdDSA"):
                    continue
                key = Ed25519PublicKey.from_public_bytes(_b64url_decode(jwk["x"]))
                keys_by_kid.setdefault(kid, []).append(("EdDSA", key))
                all_keys.append((kid, "EdDSA", key))
            elif jwk.get("kty") == "RSA" and "RS256" in self._allowed_algs:
                if jwk_alg not in (None, "RS256"):
                    continue
                numbers = rsa.RSAPublicNumbers(e=_b64url_to_int(jwk["e"]), n=_b64url_to_int(jwk["n"]))
                key = numbers.public_key()
                keys_by_kid.setdefault(kid, []).append(("RS256", key))
                all_keys.append((kid, "RS256", key))
        return keys_by_kid, all_keys

    def _replace_jwks(self, jwks: Mapping[str, Any]) -> None:
        keys_by_kid, all_keys = self._parse_jwks(jwks)
        if not all_keys:
            raise TokenError(f"JWKS contains no usable keys for algorithms {sorted(self._allowed_algs)!r}")
        self._keys_by_kid = keys_by_kid
        self._all_keys = all_keys
        self._last_refresh = time.time()

    def _refresh_from_url(self) -> None:
        if not self._jwks_url:
            return
        with self._lock:
            self._replace_jwks(fetch_jwks(self._jwks_url, timeout=self._timeout))

    def _refresh_if_stale(self) -> None:
        if not self._jwks_url or self._cache_ttl_seconds is None:
            return
        if time.time() < self._last_refresh + self._cache_ttl_seconds:
            return
        try:
            self._refresh_from_url()
        except Exception:
            # Keep cryptographic verification available with the last good keyset.
            pass

    def _candidates(self, kid: str, alg: str) -> List[tuple[str, Any]]:
        candidates = self._keys_by_kid.get(kid, [])
        if not candidates and not kid and len(self._all_keys) == 1:
            _, only_alg, only_key = self._all_keys[0]
            candidates = [(only_alg, only_key)]
        return [(key_alg, key) for key_alg, key in candidates if key_alg == alg]

    @classmethod
    def from_url(cls, url: str, *, audience: Optional[str] = None,
                 leeway_seconds: int = 30, timeout: float = 5.0,
                 algorithms: Optional[List[str]] = None,
                 cache_ttl_seconds: Optional[float] = 300.0,
                 refresh_on_kid_miss: bool = True) -> "JWKSVerifier":
        return cls(fetch_jwks(url, timeout=timeout),
                   audience=audience, leeway_seconds=leeway_seconds,
                   algorithms=algorithms, jwks_url=url, timeout=timeout,
                   cache_ttl_seconds=cache_ttl_seconds,
                   refresh_on_kid_miss=refresh_on_kid_miss)

    @classmethod
    def from_metadata(cls, *, issuer: Optional[str] = None,
                      metadata_url: Optional[str] = None,
                      audience: Optional[str] = None,
                      leeway_seconds: int = 30,
                      timeout: float = 5.0,
                      algorithms: Optional[List[str]] = None,
                      cache_ttl_seconds: Optional[float] = 300.0,
                      refresh_on_kid_miss: bool = True,
                      discovery: str = "auto") -> "JWKSVerifier":
        metadata = fetch_authorization_server_metadata(
            issuer=issuer, metadata_url=metadata_url, timeout=timeout,
            discovery=discovery)
        jwks_uri = metadata.get("jwks_uri")
        if not jwks_uri:
            raise TokenError("authorization-server metadata is missing jwks_uri")
        return cls.from_url(
            str(jwks_uri), audience=audience, leeway_seconds=leeway_seconds,
            timeout=timeout, algorithms=algorithms,
            cache_ttl_seconds=cache_ttl_seconds,
            refresh_on_kid_miss=refresh_on_kid_miss)

    def verify(self, token: str) -> TokenClaims:
        from cryptography.exceptions import InvalidSignature
        from cryptography.hazmat.primitives import hashes
        from cryptography.hazmat.primitives.asymmetric import padding
        header, payload, parts = _parse_jwt_unverified(token)
        alg = header.get("alg")
        if alg not in self._allowed_algs:
            raise TokenError(f"unexpected JWT alg {alg!r}; allowed: {sorted(self._allowed_algs)!r}")
        self._refresh_if_stale()
        kid = header.get("kid", "")
        candidates = self._candidates(kid, alg)
        if not candidates and self._refresh_on_kid_miss and self._jwks_url:
            try:
                self._refresh_from_url()
            except Exception as exc:  # noqa: BLE001
                raise TokenError("JWKS refresh failed while resolving unknown kid") from exc
            candidates = self._candidates(kid, alg)
        if not candidates:
            raise TokenError(f"no JWKS key matches kid {header.get('kid')!r}")
        key_alg, key = candidates[0]
        try:
            if key_alg == "EdDSA":
                key.verify(_b64url_decode(parts[2]), f"{parts[0]}.{parts[1]}".encode())
            elif key_alg == "RS256":
                key.verify(_b64url_decode(parts[2]), f"{parts[0]}.{parts[1]}".encode(),
                           padding.PKCS1v15(), hashes.SHA256())
            else:  # pragma: no cover - keys are filtered at construction
                raise TokenError(f"unsupported JWKS algorithm {key_alg!r}")
        except (InvalidSignature, Exception) as exc:  # noqa: BLE001
            raise TokenError(f"{key_alg} signature invalid for the selected JWKS key") from exc
        return _claims_from_payload(payload, self._audience, self._leeway)


def fetch_json(url: str, *, timeout: float = 5.0) -> Dict[str, Any]:
    """Fetch a JSON document over HTTP(S)."""
    url = _validate_fetch_url(url, "metadata/JWKS URL")
    req = urllib.request.Request(url, headers={"Accept": "application/json"}, method="GET")
    with urllib.request.urlopen(req, timeout=timeout) as resp:
        return json.loads(resp.read().decode("utf-8"))


def fetch_jwks(url: str, *, timeout: float = 5.0) -> Dict[str, Any]:
    """Fetch a JSON Web Key Set once at guard startup or refresh."""
    return fetch_json(url, timeout=timeout)


def fetch_authorization_server_metadata(*, issuer: Optional[str] = None,
                                        metadata_url: Optional[str] = None,
                                        timeout: float = 5.0,
                                        discovery: str = "auto") -> Dict[str, Any]:
    """Fetch OIDC/OAuth authorization-server metadata and validate its issuer.

    Supports either an exact metadata URL or an issuer URL. Issuer discovery tries
    RFC 8414 OAuth Authorization Server Metadata and OIDC Discovery endpoints.
    """
    if metadata_url:
        metadata = fetch_json(metadata_url, timeout=timeout)
        if issuer is not None and metadata.get("issuer") != _validate_issuer_url(issuer):
            raise TokenError("authorization-server metadata issuer mismatch")
        if "jwks_uri" not in metadata:
            raise TokenError("authorization-server metadata is missing jwks_uri")
        _validate_fetch_url(str(metadata["jwks_uri"]), "jwks_uri")
        return metadata
    if not issuer:
        raise TokenError("issuer or metadata_url is required for metadata discovery")
    issuer = _validate_issuer_url(issuer)
    errors: List[Exception] = []
    for url in _metadata_urls_for_issuer(issuer, discovery=discovery):
        try:
            metadata = fetch_json(url, timeout=timeout)
        except Exception as exc:  # noqa: BLE001
            errors.append(exc)
            continue
        if metadata.get("issuer") != issuer:
            raise TokenError("authorization-server metadata issuer mismatch")
        if "jwks_uri" not in metadata:
            raise TokenError("authorization-server metadata is missing jwks_uri")
        _validate_fetch_url(str(metadata["jwks_uri"]), "jwks_uri")
        return metadata
    raise TokenError(f"authorization-server metadata discovery failed for {issuer!r}") from (
        errors[-1] if errors else None
    )


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
