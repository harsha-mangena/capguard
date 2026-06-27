# Changelog

All notable changes to CapGuard are documented here. Format loosely follows
[Keep a Changelog](https://keepachangelog.com); this project uses semantic-ish
versioning pre-1.0.

## [0.1.0] — 2026-06

Initial release candidate. A deterministic security runtime for AI agents that
sits inline on every tool call and MCP message. The repo contains **268 test
functions**; optional integration tests self-skip when their dependencies or
Docker are unavailable. Security benchmark: **0% attack-success rate / 100%
utility / ~0.04 ms per call**; real AgentDojo (97 user + 35 injection tasks):
**0% ASR / 100% utility** under deterministic ground-truth replay. Every OWASP
ASI-2026 risk has a shipped mechanism.

### Core enforcement
- Attenuable capabilities with real argument enforcement (shell / http / file / db),
  plus **normalize-before-enforce** (NFKC + control/zero-width/NUL rejection).
- Stateless, concurrency-safe runtime pipeline.
- Programmable policy DSL: `trigger → predicate → effect`, argument-level, rate
  limits, deny-overrides (`Arg` / `Provenance` / `Taint` / `Flow` / `Signal`).
- **Provenance propagation engine** — trust+confidentiality label lattice
  propagated across tool I/O (catches laundering).
- Replay-safe approval tokens; **tamper-evident hash-chained audit**.

### Identity, scope, inter-agent
- Verifiable signed identity (HMAC / Ed25519) bound to principal + tenant; delegation
  only attenuates.
- Task/intent-scoped capability envelopes (PAuth-style JIT least privilege).
- Signed A2A inter-agent messages: anti replay/tamper + per-message capability
  attenuation.

### MCP
- MCP guard: pinning, rug-pull / shadowing / tool-poisoning detection.
- Runnable MCP proxy over **stdio and Streamable HTTP** (local + remote servers);
  remote MCP URLs are hardened before connect, and poisoned tools are stripped
  from `tools/list`.
- OAuth 2.1 resource-server auth on the HTTP boundary (RFC 9728 PRM, RFC 8707
  audience, alg-pinned HS256, EdDSA, or RS256 JWTs, OIDC/OAuth issuer metadata
  discovery, JWKS verification with refresh-on-key-rotation, and HTTPS/URL
  validation for external authorization servers).

### Operations & safety
- Rogue-agent anomaly detection + circuit-breaker kill switch.
- Cumulative call/token/$ budgets; overspend trips the breaker.
- Sandboxed execution backends (subprocess rlimits / docker / deny).
- Shared outbound URL safety for remote MCP, auth discovery, cloud audit ingest,
  and signed policy sync.
- Advisory detectors (deterministic-first, probabilistic-assist).
- Forensic data-flow reconstruction from the audit log (`capguard audit flows`).

### Tooling
- `capguard` CLI: `bench`, `agentdojo`, `audit verify|flows`, `packs`, `mcp-scan`,
  `proxy`.
- Policy-pack compiler with builtin `owasp-baseline` / `finance` / `data-exfil`.
- Framework adapters: LangChain / LangGraph, OpenAI Agents SDK, CrewAI.
- Deterministic + real-AgentDojo benchmark harnesses; Hypothesis property tests.
