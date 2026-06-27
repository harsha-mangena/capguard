# CLI reference

Every command returns a CI-meaningful exit code (0 good, non-zero = failure /
regression), so the same binary drops into a pipeline gate.

```text
capguard version
capguard bench                       # scripted security benchmark; exits non-zero on ASR>0 or utility<100
capguard agentdojo                   # real AgentDojo eval (pip install agentdojo)
capguard audit verify <file.jsonl>   # verify the tamper-evident hash chain
capguard audit flows  <file.jsonl>   # reconstruct data flow; flag untrusted -> sink paths
capguard packs list | show <name> | lint <name|path>
capguard mcp-scan <tooldefs.json>    # scan MCP tool definitions for poisoning
capguard proxy <config.json> [--check]   # run / dry-check the guarded MCP proxy
```

## Examples

```bash
# CI gate: fail the build if the deterministic defense regressed
capguard bench

# Incident response: which untrusted source reached which sink?
capguard audit flows audit.jsonl --sinks "send_*,transfer"

# Supply-chain check on a vendor's MCP tool list
capguard mcp-scan vendor_tools.json
```

## Proxy config (`proxy.json`)

```json
{
  "transport": "http",
  "http": {"host": "127.0.0.1", "port": 8080},
  "pack": "owasp-baseline",
  "agent": {"id": "bot", "capabilities": [{"type": "custom", "name": "search"}]},
  "downstreams": [
    {"server_id": "remote", "http": "https://hosted-mcp.example/mcp"}
  ],
  "auth": {
    "type": "jwt-jwks",
    "algorithms": ["RS256", "EdDSA"],
    "audience": "https://guard.example/mcp",
    "issuer_url": "https://issuer.example",
    "discovery": "auto",
    "jwks_cache_ttl_seconds": 300,
    "required_scopes": ["mcp:call"],
    "authorization_servers": ["https://issuer.example"]
  }
}
```

`auth.type` also supports `jwt-rs256-jwks`, `jwt-eddsa-jwks`, `jwt-hs256` for
self-issued local tokens, and `static` for simple fixed-token deployments. For
production, prefer `jwt-jwks` with `issuer_url`; CapGuard discovers `jwks_uri`
from OAuth Authorization Server Metadata or OIDC Discovery. Remote keysets
refresh on unknown `kid` and after `jwks_cache_ttl_seconds`, so normal issuer
key rotation does not require restarting the guard. Explicit `metadata_url`,
`jwks_url`, inline `jwks`, and `public_jwk` configs are also supported. Remote
metadata and JWKS URLs must be HTTPS outside loopback and cannot use non-public
IP literals.

HTTP downstream URLs are validated too: production endpoints must use HTTPS
outside loopback, must not embed userinfo or fragments, and must not be
non-public IP literals by default. For controlled internal deployments, set
`allow_private_network: true` on that downstream; for plaintext non-loopback dev
endpoints, set `allow_insecure_http: true`.

The same shared outbound URL policy protects `cloud.url` audit ingest endpoints
and `PolicyClient` signed-policy pull URLs. Loopback HTTP remains allowed for
local development; private-network targets or plaintext non-loopback endpoints
must be explicitly opted in with the matching constructor/config flag.

For HTTP proxy configs, `capguard proxy proxy.json --check` also builds the
configured token verifier, so bad issuer discovery, unsafe metadata/JWKS URLs,
missing HMAC secrets, and malformed inline JWKS material fail in CI before the
server starts.
