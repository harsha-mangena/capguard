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
- ✅ **Streamable-HTTP MCP transport** — guard remote/hosted MCP servers (`HttpDownstream`) and serve the guarded proxy over HTTP (`MCPHttpServer`), stdlib-only. *(ASI04, ASI07)*
- ✅ **Unified `capguard` CLI** — `bench` / `agentdojo` / `audit verify` / `packs list|show|lint` / `mcp-scan` / `proxy --check`, each with a CI-meaningful exit code.

> **Every one of the ten OWASP ASI risks now has a deterministic shipped mechanism (all ✓).** 143 tests passing, 1 skipped (Docker).

---

## 🔜 Next (target: v0.1)

### 1. Live-LLM AgentDojo (build on the shipped deterministic adapter)
The deterministic ground-truth replay ships (`capguard.bench.run_agentdojo`,
ASR 0% @ 100% utility on all four suites). Next:
- Drive `agentdojo.agent_pipeline` with a real model (API key) through the same
  enforcement loop; publish end-to-end ASR with CapGuard as the action backstop.
- Auto-assign provenance from the tracker during the live run (instead of from
  the known ground-truth source), and add ASB / InjecAgent / AgentDyn.
- Citable comparison table vs Progent / CaMeL / LlamaFirewall / AgentArmor.

### 2. Ed25519/SPIFFE identity in production
Signed identity + delegation attenuation ship (HMAC default, Ed25519 optional).
Next: JWT-SVID/SPIFFE issuance integration, OIDC principal binding, map to the
OWASP Non-Human-Identity Top 10, and an AIP-style verifiable-delegation envelope.

### 3. Streamable-HTTP MCP transport — shipped (JSON mode)
`HttpDownstream` + `MCPHttpServer` ship (`capguard.mcp_http`). Next: full
server→client **SSE streaming** (GET stream + resumability), `Mcp-Session-Id`
lifecycle, and OAuth bearer-token auth on the HTTP boundary.

### 4. Policy-pack compiler — core shipped
Compiler + `owasp-baseline` / `finance` / `data-exfil` packs ship (`capguard.packs`).
Next: more packs (healthcare, coding-agent, browser-agent), a `capguard packs lint`
CLI, and signed/pinned pack distribution.

### 5. Packaging & docs
- Finalize `pyproject` (console scripts: `capguard-proxy`, `capguard-bench`), CI workflow (lint + test + benchmark gate), publish to PyPI.
- Quickstart + recipe docs per framework (LangGraph, CrewAI, OpenAI Agents, raw MCP).

---

## 🔭 Later

### Stronger isolation
- gVisor (`runtime=runsc`) and Firecracker/microVM execution backends for hostile code at scale.
- eBPF-based egress and filesystem enforcement for the subprocess tier (true network isolation without a container).

### Rogue-agent detection *(ASI10)* — core shipped
Deterministic anomaly detection + circuit breaker ship (`capguard.monitor`). Next:
- Richer sequence models (n-gram / order-aware tool-call patterns, privilege-drift scoring) as *advisory* signals feeding the deterministic breaker.
- Per-agent/session token & $ budgets feeding back into the DSL as a `RATE_LIMIT`/`DENY` effect.

### Full provenance / taint
- Move from tool-boundary tagging to propagation across tool I/O (toward CaMeL-style soundness), while keeping it a library hook, not a forked interpreter.
- Optional advisory detectors (PromptGuard2 / AlignmentCheck) as predicates — deterministic-first, probabilistic-assist.

### Framework adapters (first-class)
- LangGraph node/tool wrappers, CrewAI tool wrapper, OpenAI Agents SDK tool shim, LlamaIndex — each routing through the runtime with zero ceremony.
- A Cedar/OPA predicate backend so teams can bring their existing policy engine and use CapGuard purely as the enforcement point.

### Inter-agent (A2A) security *(ASI07)*
- Signed inter-agent messages, identity propagation across hops, and capability attenuation along delegation chains.

### Control plane (commercial)
- Hosted multi-tenant policy management, central tamper-evident audit, dashboards, and replay/digital-twin testing for cascading-failure analysis.

---

## Guiding principles

1. **Deterministic-first.** Enforcement never depends on a model guessing intent; classifiers are optional advisory inputs, never the gate.
2. **Least privilege by construction.** Capabilities only narrow; unknown is denied or escalated.
3. **Composability over lock-in.** Bring your framework, your policy engine, your classifier — CapGuard is the enforcement point underneath.
4. **Prove it.** Every security claim has a test and a benchmark number; security regressions fail CI.
