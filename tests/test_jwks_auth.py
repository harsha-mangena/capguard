"""Tests for asymmetric JWT + JWKS verification on the OAuth boundary."""

from __future__ import annotations

import json
import threading
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

import pytest

pytest.importorskip("cryptography")

from capguard import (  # noqa: E402
    Ed25519JWTVerifier,
    JWKSVerifier,
    RS256JWTVerifier,
    TokenError,
    fetch_authorization_server_metadata,
)

AUD = "https://guard.example/mcp"


def test_eddsa_mint_verify_roundtrip():
    v = Ed25519JWTVerifier(audience=AUD)
    tok = v.mint("alice", scopes=["mcp:call"], ttl_seconds=60)
    claims = v.verify(tok)
    assert claims.subject == "alice" and "mcp:call" in claims.scopes


def test_rs256_mint_verify_roundtrip():
    v = RS256JWTVerifier(audience=AUD)
    tok = v.mint("alice", scopes=["mcp:call"], ttl_seconds=60)
    claims = v.verify(tok)
    assert claims.subject == "alice" and "mcp:call" in claims.scopes


def test_jwks_verifies_token_from_issuer_public_key():
    issuer = Ed25519JWTVerifier(audience=AUD, kid="k1")
    tok = issuer.mint("svc", scopes=["mcp:call"])
    # resource server only has the issuer's PUBLISHED JWKS, not the private key
    rs = JWKSVerifier(issuer.jwks(), audience=AUD)
    assert rs.verify(tok).subject == "svc"


def test_jwks_verifies_rs256_token_from_issuer_public_key():
    issuer = RS256JWTVerifier(audience=AUD, kid="rsa-1")
    tok = issuer.mint("svc", scopes=["mcp:call"])
    rs = JWKSVerifier(issuer.jwks(), audience=AUD, algorithms=["RS256"])
    assert rs.verify(tok).subject == "svc"


def test_jwks_handles_mixed_eddsa_and_rs256_keys():
    ed_issuer = Ed25519JWTVerifier(audience=AUD, kid="ed-1")
    rsa_issuer = RS256JWTVerifier(audience=AUD, kid="rsa-1")
    jwks = {"keys": [ed_issuer.public_jwk(), rsa_issuer.public_jwk()]}
    rs = JWKSVerifier(jwks, audience=AUD)
    assert rs.verify(ed_issuer.mint("ed-svc")).subject == "ed-svc"
    assert rs.verify(rsa_issuer.mint("rsa-svc")).subject == "rsa-svc"


def test_jwks_algorithm_allowlist_rejects_unconfigured_alg():
    ed_issuer = Ed25519JWTVerifier(audience=AUD, kid="ed-1")
    rsa_issuer = RS256JWTVerifier(audience=AUD, kid="rsa-1")
    jwks = {"keys": [ed_issuer.public_jwk(), rsa_issuer.public_jwk()]}
    rs = JWKSVerifier(jwks, audience=AUD, algorithms=["RS256"])
    assert rs.verify(rsa_issuer.mint("rsa-svc")).subject == "rsa-svc"
    with pytest.raises(TokenError):
        rs.verify(ed_issuer.mint("ed-svc"))


def test_jwks_verifier_can_load_keys_from_url():
    issuer = Ed25519JWTVerifier(audience=AUD, kid="k-url")
    jwks = issuer.jwks()

    class _JWKSHandler(BaseHTTPRequestHandler):
        def log_message(self, *a):
            pass

        def do_GET(self):
            body = json.dumps(jwks).encode()
            self.send_response(200)
            self.send_header("Content-Type", "application/json")
            self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            self.wfile.write(body)

    httpd = ThreadingHTTPServer(("127.0.0.1", 0), _JWKSHandler)
    threading.Thread(target=httpd.serve_forever, daemon=True).start()
    try:
        url = f"http://127.0.0.1:{httpd.server_address[1]}/jwks.json"
        rs = JWKSVerifier.from_url(url, audience=AUD)
        tok = issuer.mint("svc", scopes=["mcp:call"])
        assert rs.verify(tok).subject == "svc"
    finally:
        httpd.shutdown()
        httpd.server_close()


def test_jwks_verifier_refreshes_from_url_on_kid_miss():
    issuer1 = Ed25519JWTVerifier(audience=AUD, kid="old")
    issuer2 = RS256JWTVerifier(audience=AUD, kid="new")
    state = {"jwks": issuer1.jwks()}

    class _JWKSHandler(BaseHTTPRequestHandler):
        def log_message(self, *a):
            pass

        def do_GET(self):
            body = json.dumps(state["jwks"]).encode()
            self.send_response(200)
            self.send_header("Content-Type", "application/json")
            self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            self.wfile.write(body)

    httpd = ThreadingHTTPServer(("127.0.0.1", 0), _JWKSHandler)
    threading.Thread(target=httpd.serve_forever, daemon=True).start()
    try:
        url = f"http://127.0.0.1:{httpd.server_address[1]}/jwks.json"
        rs = JWKSVerifier.from_url(url, audience=AUD)
        assert rs.verify(issuer1.mint("old-svc")).subject == "old-svc"

        state["jwks"] = issuer2.jwks()
        assert rs.verify(issuer2.mint("new-svc")).subject == "new-svc"
    finally:
        httpd.shutdown()
        httpd.server_close()


def test_jwks_verifier_ttl_refresh_replaces_removed_key():
    issuer1 = RS256JWTVerifier(audience=AUD, kid="rotating")
    issuer2 = RS256JWTVerifier(audience=AUD, kid="rotating")
    state = {"jwks": issuer1.jwks()}

    class _JWKSHandler(BaseHTTPRequestHandler):
        def log_message(self, *a):
            pass

        def do_GET(self):
            body = json.dumps(state["jwks"]).encode()
            self.send_response(200)
            self.send_header("Content-Type", "application/json")
            self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            self.wfile.write(body)

    httpd = ThreadingHTTPServer(("127.0.0.1", 0), _JWKSHandler)
    threading.Thread(target=httpd.serve_forever, daemon=True).start()
    try:
        url = f"http://127.0.0.1:{httpd.server_address[1]}/jwks.json"
        rs = JWKSVerifier.from_url(url, audience=AUD, cache_ttl_seconds=0.0)
        old_token = issuer1.mint("old-svc")
        assert rs.verify(old_token).subject == "old-svc"

        state["jwks"] = issuer2.jwks()
        with pytest.raises(TokenError):
            rs.verify(old_token)
        assert rs.verify(issuer2.mint("new-svc")).subject == "new-svc"
    finally:
        httpd.shutdown()
        httpd.server_close()


def test_jwks_verifier_discovers_jwks_uri_from_oauth_issuer_metadata():
    issuer_signer = RS256JWTVerifier(audience=AUD, kid="disc-rsa")
    state = {"issuer": "", "jwks_uri": "", "jwks": issuer_signer.jwks()}

    class _DiscoveryHandler(BaseHTTPRequestHandler):
        def log_message(self, *a):
            pass

        def do_GET(self):
            if self.path == "/.well-known/oauth-authorization-server/tenant":
                body = json.dumps({"issuer": state["issuer"], "jwks_uri": state["jwks_uri"]}).encode()
            elif self.path == "/jwks.json":
                body = json.dumps(state["jwks"]).encode()
            else:
                self.send_response(404)
                self.end_headers()
                return
            self.send_response(200)
            self.send_header("Content-Type", "application/json")
            self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            self.wfile.write(body)

    httpd = ThreadingHTTPServer(("127.0.0.1", 0), _DiscoveryHandler)
    threading.Thread(target=httpd.serve_forever, daemon=True).start()
    try:
        base = f"http://127.0.0.1:{httpd.server_address[1]}"
        state["issuer"] = f"{base}/tenant"
        state["jwks_uri"] = f"{base}/jwks.json"
        metadata = fetch_authorization_server_metadata(issuer=state["issuer"], discovery="oauth")
        assert metadata["jwks_uri"] == state["jwks_uri"]
        verifier = JWKSVerifier.from_metadata(issuer=state["issuer"], audience=AUD, discovery="oauth")
        assert verifier.verify(issuer_signer.mint("svc")).subject == "svc"
    finally:
        httpd.shutdown()
        httpd.server_close()


def test_authorization_server_metadata_url_validates_issuer_mismatch():
    class _DiscoveryHandler(BaseHTTPRequestHandler):
        def log_message(self, *a):
            pass

        def do_GET(self):
            body = json.dumps({
                "issuer": "http://127.0.0.1:1/wrong",
                "jwks_uri": "http://127.0.0.1:1/jwks.json",
            }).encode()
            self.send_response(200)
            self.send_header("Content-Type", "application/json")
            self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            self.wfile.write(body)

    httpd = ThreadingHTTPServer(("127.0.0.1", 0), _DiscoveryHandler)
    threading.Thread(target=httpd.serve_forever, daemon=True).start()
    try:
        base = f"http://127.0.0.1:{httpd.server_address[1]}"
        with pytest.raises(TokenError):
            fetch_authorization_server_metadata(
                issuer=f"{base}/tenant",
                metadata_url=f"{base}/.well-known/openid-configuration",
            )
    finally:
        httpd.shutdown()
        httpd.server_close()


def test_authorization_server_metadata_rejects_plain_http_outside_loopback():
    with pytest.raises(TokenError):
        fetch_authorization_server_metadata(
            metadata_url="http://issuer.example/.well-known/openid-configuration"
        )


def test_authorization_server_metadata_rejects_unsafe_discovered_jwks_uri():
    class _DiscoveryHandler(BaseHTTPRequestHandler):
        def log_message(self, *a):
            pass

        def do_GET(self):
            issuer = f"http://127.0.0.1:{self.server.server_address[1]}"
            body = json.dumps({
                "issuer": issuer,
                "jwks_uri": "http://issuer.example/jwks.json",
            }).encode()
            self.send_response(200)
            self.send_header("Content-Type", "application/json")
            self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            self.wfile.write(body)

    httpd = ThreadingHTTPServer(("127.0.0.1", 0), _DiscoveryHandler)
    threading.Thread(target=httpd.serve_forever, daemon=True).start()
    try:
        base = f"http://127.0.0.1:{httpd.server_address[1]}"
        with pytest.raises(TokenError):
            fetch_authorization_server_metadata(issuer=base, discovery="oauth")
    finally:
        httpd.shutdown()
        httpd.server_close()


def test_jwks_url_rejects_non_public_ip_literal():
    with pytest.raises(TokenError):
        JWKSVerifier.from_url("https://169.254.169.254/latest/meta-data/jwks.json")


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


def test_rs256_expiry_audience_and_alg_confusion():
    v = RS256JWTVerifier(audience=AUD, leeway_seconds=0)
    with pytest.raises(TokenError):
        v.verify(v.mint("a", ttl_seconds=-10))
    wrong_aud = RS256JWTVerifier(audience="https://other/mcp")
    tok = wrong_aud.mint("a")
    with pytest.raises(TokenError):
        RS256JWTVerifier(public_key=wrong_aud._pub, audience=AUD).verify(tok)
    from capguard import HMACJWTVerifier
    hs = HMACJWTVerifier(b"k", audience=AUD).mint("a", scopes=["x"])
    with pytest.raises(TokenError):
        v.verify(hs)
    with pytest.raises(TokenError):
        JWKSVerifier(v.jwks(), audience=AUD).verify(hs)


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


def test_tampered_rs256_payload_rejected():
    v = RS256JWTVerifier(audience=AUD)
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
