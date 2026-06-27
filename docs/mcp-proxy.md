# Guarding MCP servers

CapGuard is a security proxy any MCP client (Claude Desktop, Cursor, an agent)
connects to, over **stdio** or **Streamable HTTP**. It guards local subprocess
*and* remote/hosted MCP servers. Poisoned, rug-pulled, and shadowed tools are
**stripped from `tools/list`** so the malicious description never reaches the
model; every `tools/call` is enforced and audited.

## stdio (local servers)

```bash
python examples/run_proxy.py     # point Claude Desktop / Cursor at this stdio proxy
```

## Streamable HTTP (remote servers)

Guard a hosted MCP server and serve the guarded proxy over HTTP:

```python
from capguard import HttpDownstream, MCPGuard, MCPProxy, MCPHttpServer, AgentIdentity, Capability, Severity
from capguard.mcp_guard import explicit_mapper

downstream = HttpDownstream("remote", "https://hosted-mcp.example/mcp")
guard = MCPGuard(capability_mapper=explicit_mapper({"search": ([Capability.custom("search")], Severity.LOW)}))
agent = AgentIdentity(id="bot", allowed_capabilities=[Capability.custom("search")])
proxy = MCPProxy(guard=guard, agent=agent, downstreams=[downstream])

MCPHttpServer(proxy, port=8080).start()    # remote clients connect here
```

Remote MCP URLs are validated before connect. HTTP is allowed for loopback
development only; production/non-loopback endpoints must be HTTPS, cannot embed
userinfo or fragments, and cannot be non-public IP literals unless the
downstream is explicitly constructed/configured with `allow_private_network`.
Plaintext non-loopback development endpoints require `allow_insecure_http`.
The same shared outbound URL policy also protects auth metadata/JWKS fetches,
cloud audit ingest, and signed policy sync.

## OAuth on the HTTP boundary

The HTTP server is an OAuth 2.1 **resource server**: it validates bearer tokens,
pins the JWT `alg`, checks the **audience** (RFC 8707), returns
`401 + WWW-Authenticate` / `403`, and serves Protected Resource Metadata
(RFC 9728) at `/.well-known/oauth-protected-resource`. JWKS verification
supports RS256 and EdDSA keys, discovers `jwks_uri` from OIDC/OAuth issuer
metadata, refreshes from the remote keyset on unknown `kid`, and can
periodically refresh by TTL for issuer key rotation. Remote metadata/JWKS URLs
must be HTTPS outside loopback and cannot use non-public IP literals.

```python
from capguard import JWKSVerifier, MCPHttpServer, ProtectedResourceMetadata

verifier = JWKSVerifier.from_metadata(
    issuer="https://issuer.example",
    audience="https://guard.example/mcp",
    cache_ttl_seconds=300,
)
prm = ProtectedResourceMetadata(resource="https://guard.example/mcp",
                                authorization_servers=["https://issuer.example"])
MCPHttpServer(proxy, port=8080, token_verifier=verifier,
              required_scopes=["mcp:call"], resource_metadata=prm).start()
```

For local/self-issued deployments, `HMACJWTVerifier` remains available, but
issuer metadata + JWKS keeps the guard verifier-only and is the safer production
shape.

## Run from a config

```bash
capguard proxy proxy.json --check     # dry-run: connect, validate HTTP auth, list post-guard tools
capguard proxy proxy.json             # serve (transport: stdio | http in the config)
```

A poisoned MCP tool is quarantined before it ever reaches the model:

```bash
python examples/demo_poison_strip.py
```
