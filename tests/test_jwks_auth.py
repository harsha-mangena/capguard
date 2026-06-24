"""Tests for asymmetric (EdDSA) JWT + JWKS verification on the OAuth boundary."""

from __future__ import annotations

import pytest

pytest.importorskip("cryptography")

from capguard import Ed25519JWTVerifier, JWKSVerifier, TokenError  # noqa: E402

AUD = "https://guard.example/mcp"


def test_eddsa_mint_verify_roundtrip():
    v = Ed25519JWTVerifier(audience=AUD)
    tok = v.mint("alice", scopes=["mcp:call"], ttl_seconds=60)
    claims = v.verify(tok)
    assert claims.subject == "alice" and "mcp:call" in claims.scopes


def test_jwks_verifies_token_from_issuer_public_key():
    issuer = Ed25519JWTVerifier(audience=AUD, kid="k1")
    tok = issuer.mint("svc", scopes=["mcp:call"])
    # resource server only has the issuer's PUBLISHED JWKS, not the private key
    rs = JWKSVerifier(issuer.jwks(), audience=AUD)
    assert rs.verify(tok).subject == "svc"


def test_jwks_rejects_wrong_key():
    issuer = Ed25519JWTVerifier(kid="k1")
    other = Ed25519JWTVerifier(kid="k1")        # different keypair, same kid
    tok = issuer.mint("svc")
    rs = JWKSVerifier(other.jwks())
    with pytest.raises(TokenError):
        rs.verify(tok)


def test_eddsa_expiry_audience_and_alg_confusion():
    v = Ed25519JWTVerifier(audience=AUD, leeway_seconds=0)
    with pytest.raises(TokenError):
        v.verify(v.mint("a", ttl_seconds=-10))                       # expired
    wrong_aud = Ed25519JWTVerifier(audience="https://other/mcp")
    tok = wrong_aud.mint("a")  # aud=other
    with pytest.raises(TokenError):
        Ed25519JWTVerifier(public_key=wrong_aud._pub, audience=AUD).verify(tok)
    # an HS256 token must be rejected by an EdDSA verifier (alg confusion)
    from capguard import HMACJWTVerifier
    hs = HMACJWTVerifier(b"k", audience=AUD).mint("a", scopes=["x"])
    with pytest.raises(TokenError):
        v.verify(hs)


def test_tampered_eddsa_payload_rejected():
    v = Ed25519JWTVerifier(audience=AUD)
    tok = v.mint("alice", scopes=["mcp:call"])
    h, _p, s = tok.split(".")
    import base64
    import json
    forged_payload = base64.urlsafe_b64encode(
        json.dumps({"sub": "attacker", "aud": AUD}).encode()).rstrip(b"=").decode()
    with pytest.raises(TokenError):
        v.verify(f"{h}.{forged_payload}.{s}")


def test_mcp_http_server_accepts_eddsa_token():
    pytest.importorskip("fastapi")
    import json
    import urllib.error
    import urllib.request

    from capguard import (
        AgentIdentity,
        Capability,
        MCPGuard,
        MCPHttpServer,
        MCPProxy,
        MCPToolDef,
        ProtectedResourceMetadata,
        Severity,
    )
    from capguard.mcp_guard import explicit_mapper
    from capguard.mcp_proxy import InProcessDownstream

    issuer = Ed25519JWTVerifier(audience=AUD, kid="k1")
    rs = JWKSVerifier(issuer.jwks(), audience=AUD)   # resource server trusts the JWKS

    tools = [MCPToolDef("s1", "echo", "echo", {})]
    ds = InProcessDownstream("s1", tools, {"echo": lambda text="": f"echo:{text}"})
    guard = MCPGuard(capability_mapper=explicit_mapper({"echo": ([Capability.custom("echo")], Severity.LOW)}))
    agent = AgentIdentity(id="bot", allowed_capabilities=[Capability.custom("echo")])
    proxy = MCPProxy(guard=guard, agent=agent, downstreams=[ds])
    prm = ProtectedResourceMetadata(resource=AUD, authorization_servers=["https://issuer"])
    srv = MCPHttpServer(proxy, token_verifier=rs, required_scopes=["mcp:call"],
                        resource_metadata=prm).start()
    try:
        body = json.dumps({"jsonrpc": "2.0", "id": 1, "method": "tools/list"}).encode()
        tok = issuer.mint("svc", scopes=["mcp:call"])
        req = urllib.request.Request(srv.url, data=body, method="POST",
                                     headers={"Content-Type": "application/json",
                                              "Authorization": f"Bearer {tok}"})
        with urllib.request.urlopen(req, timeout=10) as r:
            assert r.status == 200
        # no token -> 401
        req2 = urllib.request.Request(srv.url, data=body, method="POST",
                                      headers={"Content-Type": "application/json"})
        try:
            urllib.request.urlopen(req2, timeout=10)
            assert False, "expected 401"
        except urllib.error.HTTPError as e:
            assert e.code == 401
    finally:
        srv.stop()
