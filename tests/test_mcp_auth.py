"""Tests for OAuth 2.1 resource-server auth on the HTTP MCP boundary."""

from __future__ import annotations

import json
import time
import urllib.error
import urllib.request

import pytest

from capguard import (
    AgentIdentity,
    Capability,
    HMACJWTVerifier,
    HttpDownstream,
    MCPGuard,
    MCPHttpServer,
    MCPProxy,
    MCPToolDef,
    ProtectedResourceMetadata,
    Severity,
    StaticTokenVerifier,
    TokenError,
)
from capguard.mcp_auth import extract_bearer, www_authenticate
from capguard.mcp_guard import explicit_mapper
from capguard.mcp_proxy import InProcessDownstream

AUD = "https://guard.example/mcp"


# --------------------------------------------------------------------------- #
# verifier units
# --------------------------------------------------------------------------- #
def test_jwt_mint_verify_roundtrip():
    v = HMACJWTVerifier(b"secret", audience=AUD)
    tok = v.mint("alice", scopes=["mcp:call"], ttl_seconds=60)
    claims = v.verify(tok)
    assert claims.subject == "alice"
    assert "mcp:call" in claims.scopes


def test_jwt_expired_rejected():
    v = HMACJWTVerifier(b"secret", audience=AUD, leeway_seconds=0)
    tok = v.mint("alice", ttl_seconds=-10)  # already expired
    with pytest.raises(TokenError):
        v.verify(tok)


def test_jwt_audience_mismatch_rejected():
    issuer = HMACJWTVerifier(b"secret")  # mints with no aud / different aud
    tok = issuer.mint("alice", audience="https://other/mcp")
    verifier = HMACJWTVerifier(b"secret", audience=AUD)
    with pytest.raises(TokenError):
        verifier.verify(tok)


def test_jwt_tampered_signature_rejected():
    v = HMACJWTVerifier(b"secret", audience=AUD)
    tok = v.mint("alice", scopes=["mcp:call"])
    h, p, _ = tok.split(".")
    forged = f"{h}.{p}.AAAA"
    with pytest.raises(TokenError):
        v.verify(forged)


def test_jwt_alg_confusion_rejected():
    """A token claiming alg:none (or anything != HS256) must be rejected."""
    import base64
    header = base64.urlsafe_b64encode(json.dumps({"alg": "none", "typ": "JWT"}).encode()).rstrip(b"=").decode()
    payload = base64.urlsafe_b64encode(json.dumps({"sub": "attacker"}).encode()).rstrip(b"=").decode()
    v = HMACJWTVerifier(b"secret", audience=AUD)
    with pytest.raises(TokenError):
        v.verify(f"{header}.{payload}.")


def test_static_verifier():
    v = StaticTokenVerifier({"tok-1": {"subject": "svc", "scopes": ["mcp:call"]}}, audience=AUD)
    assert v.verify("tok-1").subject == "svc"
    with pytest.raises(TokenError):
        v.verify("nope")


def test_extract_bearer_and_www_authenticate():
    assert extract_bearer("Bearer abc123") == "abc123"
    assert extract_bearer("Basic xxx") is None
    assert extract_bearer(None) is None
    wa = www_authenticate(resource_metadata_url="https://x/.well-known/oauth-protected-resource",
                          error="invalid_token")
    assert wa.startswith("Bearer") and "invalid_token" in wa and "resource_metadata" in wa


# --------------------------------------------------------------------------- #
# loopback resource-server enforcement
# --------------------------------------------------------------------------- #
def _proxy():
    tools = [MCPToolDef("s1", "echo", "echo a string", {})]
    ds = InProcessDownstream("s1", tools, {"echo": lambda text="": f"echo:{text}"})
    guard = MCPGuard(capability_mapper=explicit_mapper({"echo": ([Capability.custom("echo")], Severity.LOW)}))
    agent = AgentIdentity(id="bot", allowed_capabilities=[Capability.custom("echo")])
    return MCPProxy(guard=guard, agent=agent, downstreams=[ds])


def _server(verifier, scopes=("mcp:call",)):
    prm = ProtectedResourceMetadata(resource=AUD, authorization_servers=["https://issuer.example"],
                                    scopes_supported=list(scopes))
    return MCPHttpServer(_proxy(), token_verifier=verifier, required_scopes=scopes,
                         resource_metadata=prm).start()


def _request(url, body=None, token=None, method="POST"):
    headers = {"Content-Type": "application/json"}
    if token:
        headers["Authorization"] = f"Bearer {token}"
    data = json.dumps(body).encode() if body is not None else None
    req = urllib.request.Request(url, data=data, method=method, headers=headers)
    try:
        with urllib.request.urlopen(req, timeout=10) as r:
            return r.status, dict(r.headers), r.read().decode()
    except urllib.error.HTTPError as e:
        return e.code, dict(e.headers), e.read().decode()


def test_missing_token_gets_401_with_challenge():
    v = HMACJWTVerifier(b"k", audience=AUD)
    srv = _server(v)
    try:
        code, headers, _ = _request(srv.url, {"jsonrpc": "2.0", "id": 1, "method": "tools/list"})
        assert code == 401
        assert "resource_metadata" in headers.get("WWW-Authenticate", "")
    finally:
        srv.stop()


def test_valid_token_allows_call():
    v = HMACJWTVerifier(b"k", audience=AUD)
    srv = _server(v)
    try:
        tok = v.mint("alice", scopes=["mcp:call"])
        code, _, body = _request(srv.url, {"jsonrpc": "2.0", "id": 2, "method": "tools/list"}, token=tok)
        assert code == 200
        names = {t["name"] for t in json.loads(body)["result"]["tools"]}
        assert "s1__echo" in names
    finally:
        srv.stop()


def test_invalid_token_gets_401():
    v = HMACJWTVerifier(b"k", audience=AUD)
    srv = _server(v)
    try:
        code, headers, _ = _request(srv.url, {"jsonrpc": "2.0", "id": 1, "method": "tools/list"},
                                    token="garbage.token.sig")
        assert code == 401
        assert "invalid_token" in headers.get("WWW-Authenticate", "")
    finally:
        srv.stop()


def test_insufficient_scope_gets_403():
    v = HMACJWTVerifier(b"k", audience=AUD)
    srv = _server(v, scopes=("mcp:admin",))
    try:
        tok = v.mint("alice", scopes=["mcp:call"])  # lacks mcp:admin
        code, headers, _ = _request(srv.url, {"jsonrpc": "2.0", "id": 1, "method": "tools/list"}, token=tok)
        assert code == 403
        assert "insufficient_scope" in headers.get("WWW-Authenticate", "")
    finally:
        srv.stop()


def test_protected_resource_metadata_is_public():
    v = HMACJWTVerifier(b"k", audience=AUD)
    srv = _server(v)
    try:
        url = srv.url.rstrip("/") + "/.well-known/oauth-protected-resource"
        code, _, body = _request(url, method="GET")
        assert code == 200
        doc = json.loads(body)
        assert doc["resource"] == AUD
        assert doc["authorization_servers"] == ["https://issuer.example"]
    finally:
        srv.stop()


def test_httpdownstream_sends_bearer_to_protected_server():
    v = HMACJWTVerifier(b"k", audience=AUD)
    srv = _server(v)
    try:
        tok = v.mint("svc", scopes=["mcp:call"])
        ds = HttpDownstream("remote", srv.url, headers={"Authorization": f"Bearer {tok}"})
        tools = ds.list_tools()
        # the protected server is itself a guard proxy, which re-exposes echo as s1__echo;
        # getting any tool back proves the bearer header reached the server.
        assert tools and any("echo" in t.name for t in tools)
        # and without the token, even connecting fails closed
        with pytest.raises(Exception):
            HttpDownstream("remote2", srv.url)
    finally:
        srv.stop()


def test_auth_disabled_when_no_verifier():
    srv = MCPHttpServer(_proxy()).start()  # no verifier
    try:
        code, _, body = _request(srv.url, {"jsonrpc": "2.0", "id": 1, "method": "tools/list"})
        assert code == 200
    finally:
        srv.stop()
