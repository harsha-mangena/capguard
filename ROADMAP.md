# CapGuard Roadmap

This is the forward plan. It builds on the shipped core (capabilities, policy DSL, provenance, approvals, MCP guard + proxy, sandbox, benchmark). Items are ordered by leverage; each is independently shippable.

Legend: ✅ done · 🔜 next · 🔭 later · status against the 2026 OWASP Top 10 for Agentic Applications (ASIxx).

---

## Shipped

- ✅ **Attenuable capability model** with real argument enforcement (shell/http/file/db). *(ASI02, ASI03)*
- ✅ **Stateless, concurrency-safe runtime** pipeline. *(correctness)*
- ✅ **Programmable policy DSL** — trigger → predicate → effect, argument-level, rate limits, deny-overrides. *(ASI01, ASI02)*
- ✅ **Data-provenance predicates** — deterministic indirect-prompt-injection defense. *(ASI01, ASI06)*
- ✅ **Replay-safe approval tokens** — args-bound, HMAC-signed, single-use. *(ASI09)*
- ✅ **Tamper-evident hash-chained audit.** *(ASI10 evidence)*
- ✅ **MCP security engine** — pinning, rug-pull, shadowing, tool-poisoning scan. *(ASI04, ASI07)*
- ✅ **Runnable MCP proxy** — strips poisoned tools from `tools/list`, enforces every call. *(ASI04, ASI07)*
- ✅ **Sandboxed execution backends** — subprocess (rlimits) / docker / deny. *(ASI05, ASI08)*
- ✅ **Deterministic security benchmark** — ASR/utility/latency, CI gate.
- ✅ **Provenance propagation engine** — trust+confidentiality label lattice propagated across tool I/O; `Taint`/`Flow` predicates; catches *laundering* the old per-call provenance missed. *(ASI01, ASI06)*
- ✅ **Verifiable identity + delegation attenuation** — signed (HMAC/Ed25519) assertions bound to principal+tenant, verified at the proxy boundary; sub-agent delegation only narrows authority. *(ASI03, ASI07)*
- ✅ **Normalize-before-enforce hardening** — NFKC + control/zero-width/NUL rejection so encoded payloads can't slip past `enforce`. *(ASI02)*
- ✅ **Property-based + fuzz tests** (Hypothesis) — lattice algebra, attenuation monotonicity, audit-chain tamper-evidence, smuggling rejection.
- ✅ **Framework adapters** — one-line `CapGuard` facade + `to_langchain` / `to_openai_agents` / `to_crewai` native bindings.
- ✅ **Real-AgentDojo adapter** — deterministic ground-truth replay across all four suites (97 user / 35 injection): **ASR 0% @ 100% utility**.
- ✅ **Rogue-agent detection + circuit breaker** — deterministic sliding-window anomaly detection (call/denial-rate, blast-radius, novel-tool) over the audit stream → per-agent kill switch; runtime fail-closes. *(ASI10, ASI08)*
- ✅ **Task/intent-scoped capability envelopes** — PAuth-style signed, expiring, per-argument-constrained JIT grants; issuing only attenuates. *(ASI02, ASI03)*
- ✅ **Provenance-preserving memory / RAG guard** — taint survives the write→read round-trip; optional deny-untrusted-writes. *(ASI06)*
- ✅ **Policy-pack compiler** — declarative YAML/JSON/dict profiles → `PolicyEngine` + capability templates; builtin `owasp-baseline` / `finance` / `data-exfil`.
- ✅ **Streamable-HTTP MCP transport** — guard remote/hosted MCP servers (`HttpDownstream`) and serve the guarded proxy over HTTP (`MCPHttpServer`), stdlib-only; remote MCP URLs require HTTPS outside loopback and reject userinfo/fragments/non-public IP literals by default. *(ASI04, ASI07)*
- ✅ **Unified `capguard` CLI** — `bench` / `agentdojo` / `audit verify` / `packs list|show|lint` / `mcp-scan` / `proxy --check`, each with a CI-meaningful exit code.
- ✅ **OAuth 2.1 resource-server auth on the HTTP MCP boundary** — bearer/JWT verify (alg-pinned HS256 or RS256/EdDSA + JWKS discovered from OIDC/OAuth issuer metadata, with key refresh and fetch-URL hardening, audience per RFC 8707), `401`/`403` with `WWW-Authenticate`, Protected Resource Metadata (RFC 9728); composes with the signed-identity gate. *(ASI03, ASI07)*
- ✅ **HTTP exposure safety** — loopback may run unauthenticated for local dev, but non-loopback HTTP binds fail closed unless auth is configured or an explicit lab-only override is set. *(ASI03, ASI08)*
- ✅ **Shared outbound URL safety** — remote MCP, auth metadata/JWKS, cloud audit ingest, and signed policy sync all reject userinfo/fragments, plaintext non-loopback HTTP, and non-public IP literals by default. *(ASI04, ASI08)*
- ✅ **Advisory detector hooks** — `Detector` protocol + `CallableDetector` (wire any classifier) + built-in regex-injection / PII heuristics; `Signal(...)` DSL predicate. Deterministic-first: advisory-only, fail-open, can only tighten. *(ASI01)*
- ✅ **Budgets & quotas** — cumulative call/token/$ ceilings per agent/session (cumulative or rolling window); overspend trips the circuit breaker. Closes unbounded consumption / doom-spirals. *(ASI08)*
- ✅ **Signed inter-agent (A2A) messages** — signed message envelopes (anti impersonation/tamper), single-use nonce + expiry (anti-replay), and per-message capability attenuation across hops (the scope semantics A2A/Transaction-Tokens omit); inbound payloads tainted. *(ASI07)*
- ✅ **Forensic provenance reconstruction** — rebuilds the data-flow graph from the tamper-evident audit log (result-digest → argument-digest edges + trust labels) and surfaces untrusted-source → sink paths for incident response; `capguard audit flows`. *(ASI10 evidence)*

> **Every one of the ten OWASP ASI risks now has a deterministic shipped mechanism (all ✓).** The repo currently contains 272 test functions; optional integration tests self-skip when their dependencies or Docker are unavailable.

---

## 🔜 Next (target: v0.1)

### 1. Live-LLM AgentDojo — integration shipped; numbers need a model key
The guarded runtime ships (`capguard.bench.live_agentdojo.GuardedFunctionsRuntime`):
it routes **every tool call a live model emits** through CapGuard and derives
provenance from the source boundary (not ground truth). Validated against real
AgentDojo environments in `tests/test_live_agentdojo.py` (no key). Deterministic
replay also ships (`run_agentdojo`, ASR 0% @ 100% utility). Next:
- Run `run_live` with GPT-4o / Claude (API key) and publish end-to-end ASR/utility.
- Add ASB / InjecAgent / AgentDyn behind the same `Scenario`/runtime interface.
- Citable comparison table vs Progent / CaMeL / LlamaFirewall / AgentArmor.

### 2. Ed25519/SPIFFE identity in production
Signed identity + delegation attenuation ship (HMAC default, Ed25519 optional).
RS256 and EdDSA JWT verification from JWKS ship for external authorization
servers, including OIDC/OAuth metadata discovery and key refresh on rotation.
Next: JWT-SVID/SPIFFE issuance integration, OIDC principal binding, map to the
OWASP Non-Human-Identity Top 10, and an AIP-style verifiable-delegation envelope.

### 3. Streamable-HTTP MCP transport — shipped (JSON mode + OAuth)
`HttpDownstream` + `MCPHttpServer` + OAuth 2.1 resource-server auth ship
(`capguard.mcp_http`, `capguard.mcp_auth`). Next: full server→client **SSE
streaming** (GET stream + resumability) and `Mcp-Session-Id` lifecycle.

### 4. Policy-pack compiler — core shipped
Compiler + `owasp-baseline` / `finance` / `data-exfil` packs ship (`capguard.packs`).
Next: more packs (healthcare, coding-agent, browser-agent), a `capguard packs lint`
CLI, and signed/pinned pack distribution.

### 5. Packaging & docs
- Publish the renamed PyPI distribution, `capguard-runtime` (imports and CLI remain `capguard`), via Trusted Publishing.
- Quickstart + recipe docs per framework (LangGraph, CrewAI, OpenAI Agents, raw MCP).

---

## 🔭 Later

### Stronger isolation
- gVisor (`runtime=runsc`) and Firecracker/microVM execution backends for hostile code at scale.
- eBPF-based egress and filesystem enforcement for the subprocess tier (true network isolation without a container).

### Rogue-agent detection *(ASI10)* — core shipped
Deterministic anomaly detection + circuit breaker ship (`capguard.monitor`). Next:
- Richer sequence models (n-gram / order-aware tool-call patterns, privilege-drift scoring) as *advisory* signals feeding the deterministic breaker.
- Cumulative budgets ship (`capguard.budget`, trips the breaker). Next: surface live spend in the audit stream + a per-tool sub-budget `BUDGET` DSL effect.

### Full provenance / taint
- Move from tool-boundary tagging to propagation across tool I/O (toward CaMeL-style soundness), while keeping it a library hook, not a forked interpreter.
- Advisory detector hooks ship (`capguard.detectors`, deterministic-first). Next: ready-made adapters for PromptGuard2 / AlignmentCheck / Llama as `CallableDetector`s.

### Framework adapters (first-class)
- LangGraph node/tool wrappers, CrewAI tool wrapper, OpenAI Agents SDK tool shim, LlamaIndex — each routing through the runtime with zero ceremony.
- A Cedar/OPA predicate backend so teams can bring their existing policy engine and use CapGuard purely as the enforcement point.

### Inter-agent (A2A) security *(ASI07)* — core shipped
Signed messages + per-message capability attenuation ship (`capguard.a2a`). Next:
native A2A AgentCard verification, an A2A transport adapter that routes envelopes
through the runtime automatically, and full multi-hop delegation-chain propagation.

### Control plane (commercial)
- Hosted multi-tenant policy management, central tamper-evident audit, dashboards, and replay/digital-twin testing for cascading-failure analysis.

---

## Guiding principles

1. **Deterministic-first.** Enforcement never depends on a model guessing intent; classifiers are optional advisory inputs, never the gate.
2. **Least privilege by construction.** Capabilities only narrow; unknown is denied or escalated.
3. **Composability over lock-in.** Bring your framework, your policy engine, your classifier — CapGuard is the enforcement point underneath.
4. **Prove it.** Every security claim has a test and a benchmark number; security regressions fail CI.
