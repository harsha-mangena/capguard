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
    "type": "jwt-hs256",
    "secret": "shared-secret",
    "audience": "https://guard.example/mcp",
    "required_scopes": ["mcp:call"],
    "authorization_servers": ["https://issuer.example"]
  }
}
```
