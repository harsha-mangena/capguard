# CapGuard Enhancement Plan — 2026 H1

*Co-founder/CTO memo. Reasoned with Atom-of-Thoughts (decompose every "best SDK" claim into an atomic, checkable unit) and Tree-of-Thoughts (branch the strategy, prune against June-2026 market + research evidence). Supersedes the framing in `STRATEGY.md` where the field has moved.*

> Historical planning memo. For the current install name, release status, and
> validation count, use `README.md` as the source of truth.

---

## 0. Where we stand (revalidated)

- **Tests:** the current tree contains 272 test functions; optional integrations
  self-skip when their dependencies or Docker are unavailable.
- **Benchmark:** ASR 0% / utility 100% / **0.027 ms** per guarded call. Holds.
- **Architecture:** the seven planes from `STRATEGY.md` are largely *shipped* — attenuable capabilities with real argument enforcement, argument-level policy DSL, per-call provenance predicates, replay-safe approvals, hash-chained audit, MCP guard (pin/rug-pull/shadow/poison) + runnable proxy with `tools/list` stripping, and tiered sandbox backends.

CapGuard is no longer "a declarative layer that doesn't enforce." It enforces. The question for 2026 H1 is **not** "is it real?" but **"is it the best, and is it defensible?"** The market answered the first question for us by shipping a competitor with our exact tagline.

---

## 1. What changed since `STRATEGY.md` (June 2026 intel)

| Event | So what |
|-------|---------|
| **Microsoft Agent Governance Toolkit** (Apr 2, 2026, MIT). "First toolkit to address all 10 OWASP agentic risks with **deterministic, sub-millisecond** policy enforcement." Py/Rust/TS/Go/.NET. Hooks LangChain callbacks, CrewAI decorators, ADK plugins, OpenAI Agents, LangGraph, PydanticAI. | **Existential + validating.** Our exact positioning ("deterministic sub-ms runtime enforcement, all 10 ASI") is now occupied by a hyperscaler with multi-language reach and a marketplace. We cannot out-*breadth* them. We must out-*depth* them and be **embeddable underneath** them. |
| **Snyk acquired Invariant Labs** (closed; "Evo by Snyk" GA early 2026). They coined "tool poisoning" & "MCP rug pull," own mcp-scan + Guardrails. | MCP *scanning* is becoming a commercial, well-funded category. Our MCP edge has to be **enforcement + list-strip at the proxy**, not just detection. |
| **Oso for Agents / Permit.io (SPIFFE + OAuth token-exchange) / WorkOS FGA / Cerbos** stretch AuthZ to agents. Oso publicly states *"deterministic governance alone won't catch intent drift, prompt injection, or unauthorized combinations of permitted actions."* | The AuthZ incumbents concede the exact gap we fill (the post-decision, data-aware, runtime layer). Position as **complementary**, ride their adoption (Cedar/OPA predicate backend). |
| **Research frontier moved from per-call checks → trace-level information-flow.** AgentArmor (trace-as-program: CFG/DFG/PDG + type system; 95.75% TPR/3.66% FPR on AgentDojo). RTBAS, **Ghost-in-the-Agent** (redefining IFT for agents), **NeuroTaint** (semantic+causal taint reconstructed from execution traces), CaMeL "computer-use" extension (single-shot plan, provable CFI). | **Our single biggest technical gap.** CapGuard provenance is **passed in per call**, not **propagated across tool I/O**. The whole frontier is information-flow across the trace. Closing this is our deepest, most defensible moat — and it *reuses our hash-chained audit stream* as the provenance source (NeuroTaint validates exactly this). |
| **Intent / task-scoped authorization.** PAuth (Microsoft Research, "NL task implicitly authorizes only the concrete operations"; NL-slices + value-binding Envelopes). "Intent-to-Execution Integrity." "Authorization Propagation in Multi-Agent Systems." | Capabilities bound to the *agent* are too coarse. Next primitive: capabilities bound to the **task/intent**, JIT and ephemeral, **attenuated along delegation chains**. |
| **Identity standardized.** NIST AI Agent Standards Initiative (Feb 2026). SPIFFE/WIMSE (CNCF-graduated; Block in prod). **AIP — Agent Identity Protocol** for verifiable delegation across MCP **and** A2A. | Don't invent an identity scheme — **plug into SPIFFE/JWT-SVID + AIP**. Self-asserted `agent_id` is our weakest plane; the fix is now a standards-adoption play, not R&D. |
| **Adaptive attacks beat probabilistic defenses: >85% ASR** in a 78-study meta-analysis. OpenAI shipped deterministic "Lockdown Mode." | Strong tailwind. "Deterministic-first, classifiers-advisory" is now the consensus, not a contrarian bet. Our backstop framing is *more* correct than when it was written. |
| **New attack class: Causality Laundering / denial-feedback leakage** (an attack on the *enforcement layer itself* — exfiltration via the observable pattern of allow/deny/feedback). | Almost nobody addresses attacks *on the guard*. Hardening here is a cheap, unique credibility win. |
| New benchmarks: **AgentDyn** (dynamic, open-ended), DoomArena, ASB, InjecAgent; PromptArmor ≈0% ASR; SecAlign (model-side). | "Best SDK" requires **public, reproducible live-LLM numbers** vs the named SoTA. AgentArmor/PromptArmor set the bar. |

---

## 2. Atom-of-Thoughts: the "best SDK" claim, decomposed

Each row is an atomic claim, checked against the code as it exists today.

| # | Atomic claim | Status | Evidence / gap |
|---|--------------|--------|----------------|
| A1 | Enforces argument-level least privilege | ✅ true | `Capability.enforce` on real values; bench blocks shell/url/path/db abuse |
| A2 | Deterministically stops indirect prompt injection | ◑ partial | Works **only** for arguments explicitly tagged at the call. No propagation: a tainted value laundered through a second tool loses its label. |
| A3 | Secures MCP (poisoning/rug-pull/shadow) | ✅ strong | pin + scan + cross-server collision + **strip from `tools/list`** (most competitors only detect) |
| A4 | Verifiable agent identity | ❌ false | `agent_id` self-asserted at the boundary (ASI03 hole) |
| A5 | Provably correct enforcement | ◑ partial | 50 unit tests; **no** property-based/fuzz/adversarial tests; no live-LLM numbers |
| A6 | Composes under any framework in minutes | ◑ partial | MCP proxy ✅; **no** LangGraph/OpenAI-Agents/CrewAI adapter shipped |
| A7 | Resists attacks on the guard itself | ❌ gap | no input normalization before enforce (unicode/encoding); denial-feedback channel unaddressed |
| A8 | Capabilities scoped to the task/intent, attenuated across delegation | ❌ gap | grants are per-agent and static; no delegation attenuation |

**Reading:** the foundation (A1, A3) is genuinely strong. "Best" is blocked by **A2 (propagation), A4 (identity), A5 (proof), A6 (adapters), A7 (self-hardening)**. A2 is both the biggest gap *and* the deepest moat.

---

## 3. Tree-of-Thoughts: strategic branches

- **Branch A — out-platform Microsoft** (marketplace, multi-language, SRE, RL-gov). → **Prune.** Cannot beat a hyperscaler on breadth as a focused project. Fighting on their turf.
- **Branch B — become the AuthZ engine** (compete with Permit/Oso/Cedar). → **Prune.** They own decisioning; they *themselves* say it's insufficient for the agent runtime — which is *our* layer.
- **Branch C — the embeddable deterministic *enforcement core* with the deepest information-flow engine, composable *underneath* everyone.** → **Keep.** The "SQLite/eBPF of agent security": a tiny, dependency-light (pydantic-only), property-tested library you drop into any stack — including under Microsoft's toolkit, LangChain, or Snyk. Win on **depth, correctness, and composability**, not breadth.

**Sharpened positioning:** *CapGuard is the deterministic enforcement kernel for agent actions — argument-level least privilege + propagated data-flow integrity + MCP-native defense, in one embeddable library with published, reproducible numbers. Bring your framework, your policy engine, your identity provider, your classifier; CapGuard is the non-bypassable point underneath all of them.*

Three compounding moats: (1) the **information-flow engine** (hardest to copy, frontier-aligned); (2) the **MCP enforcement proxy** (strip-at-source, not just scan); (3) the **benchmark + property-test corpus** (credibility that's expensive to match).

---

## 4. Prioritized phases (each independently shippable)

> Ordered by leverage = (moat depth) × (frontier alignment) × (closes a "best" blocker) ÷ effort.

### P1 — Provenance Propagation Engine  ★ deepest moat, closes A2
Turn provenance from a per-call **input** into a **propagated taint lattice** across tool I/O.
- A `ProvenanceContext`/`TaintTracker` that labels tool **outputs** and propagates labels to downstream call **arguments** (integrity lattice `TRUSTED > UNTRUSTED_TOOL > UNTRUSTED_WEB`, plus a confidentiality dimension for exfil: `SECRET`/`PII` must not reach an untrusted sink).
- Runtime auto-derives an argument's label from the labels of values it was built from (boundary tagging first; full propagation as the soundness target — explicit threat-model docs, à la CaMeL/RTBAS/Ghost-in-the-Agent).
- New DSL predicates: `Flow(secret) -> untrusted_sink` ⇒ DENY; `Taint(arg).at_least("trusted")`.
- Reuses the **hash-chained audit stream** as the provenance graph (NeuroTaint-style), so we get offline trace reconstruction for free.
- **Why us:** Microsoft's policy-engine and Snyk's scanner approaches don't do propagated IFC; this is CaMeL-grade defense delivered as a library hook, not a forked interpreter.

### P2 — Verifiable identity + delegation attenuation  ★ closes A4 (ASI03)
- Signed `AgentIdentity` assertions (reuse Ed25519): JWT-SVID / SPIFFE-style, bound to **human principal + tenant**, verified at the proxy/gateway boundary; reject unsigned/mismatched.
- **Delegation chains (A2A):** capability attenuation along hops — a sub-agent can only ever hold a *subset* of the delegator's caps; align with the AIP verifiable-delegation model.
- Zero standing permissions; JIT ephemeral grants become the norm.

### P3 — Live-LLM AgentDojo adapter + published numbers  ★ closes A5 ("best" needs proof)
- Wire real AgentDojo (then ASB / InjecAgent / AgentDyn) behind the existing `Scenario` interface.
- Publish end-to-end ASR / utility / latency **with CapGuard as the enforcement layer**, in a reproducible table vs AgentArmor / Progent / CaMeL / LlamaFirewall.

### P4 — Framework adapters + 5-minute story  ★ closes A6 (adoption)
- One-line wrappers: **LangGraph** node/tool, **OpenAI Agents SDK** tool shim, **CrewAI** tool. Each routes through the runtime with provenance defaults.
- Explicitly market "runs **under** Microsoft AGT / LangChain / Snyk as the enforcement kernel."

### P5 — Harden the guard itself  ★ closes A7, cheap credibility
- **Normalize-before-enforce:** NFKC + percent/unicode-decode URLs, resolve+normalize paths, canonicalize shell argv — so encoded payloads can't slip past `enforce`.
- **Denial-feedback / causality-laundering** mitigation: constant-shape denial responses; rate-limit/secret-independent error text on the proxy.
- **Property-based + fuzz tests** (Hypothesis): attenuation is reflexive/transitive/monotone; `enforce` never expands authority; round-trip audit-chain integrity under random edits.

### P6 — Task/intent-scoped capabilities (PAuth-style)  ★ research-grade, later
- Bind grants to a task spec ("transfer ≤ $100 to Bob"), not just the operator ("transfer"); value-binding envelopes tying an operand to its symbolic provenance. Highest ceiling, highest ambiguity risk — sequence after P1–P3.

---

## 5. Recommended immediate build

**P1 (Provenance Propagation Engine) + the P5 property-test harness**, together.

Rationale (connecting the dots): P1 is the deepest moat, is exactly where the research frontier is (AgentArmor/NeuroTaint/RTBAS/Ghost-in-the-Agent), is the one thing Microsoft's and Snyk's approaches structurally don't do, directly closes our biggest atomic gap (A2), and *reuses infrastructure we already have* (the audit chain). Pairing it with property/fuzz tests (P5) converts "we added a feature" into "we added a feature with machine-checked guarantees" — which is the credibility currency for a security kernel. P2/P3/P4 then layer on cleanly.

---

## 5.1 Status — shipped in this build ✅

All five prioritized phases landed and remain covered by the current test suite.

| Phase | Status | Evidence |
|-------|--------|----------|
| **P1** Provenance Propagation Engine | ✅ | `capguard/provenance.py` (label lattice + `ProvenanceTracker`), `Taint`/`Flow` DSL, runtime wiring; `tests/test_provenance.py` (11); two laundering attacks now in the headline bench (**15/15 blocked**) |
| **P5** Harden + property/fuzz tests | ✅ | normalize-before-enforce (NFKC + control/zero-width/NUL) in `core.py`; `tests/test_properties.py` (17, Hypothesis): lattice laws, attenuation monotonicity, audit tamper-evidence, smuggling |
| **P2** Verifiable identity + delegation | ✅ | `capguard/identity.py` (HMAC + optional Ed25519, principal+tenant, delegation-only-attenuates, depth/expiry bounds), proxy signed-identity gate; `tests/test_identity.py` (15) |
| **P4** Framework adapters | ✅ | `capguard/adapters.py` (`CapGuard` facade + `to_langchain`/`to_openai_agents`/`to_crewai`); `tests/test_adapters.py` (8) incl. a **real** LangChain `StructuredTool` routed through the runtime |
| **P3** Real-AgentDojo adapter | ✅ | `capguard/bench/agentdojo_adapter.py` + `run_agentdojo.py`: deterministic ground-truth replay, all four suites → **97 user / 35 injection, utility 100%, ASR 0.0%**; `tests/test_agentdojo_adapter.py` |
| **ASI10** Rogue-agent detection + kill switch | ✅ | `capguard/monitor.py` (sliding-window anomaly detection + per-agent `CircuitBreaker`), runtime fail-close gate; `tests/test_monitor.py` (9) |
| **P6** Task/intent-scoped capability envelopes | ✅ | `capguard/taskscope.py` (signed, expiring, per-arg-constrained JIT grants; issuing only attenuates), runtime task-scope gate; `tests/test_taskscope.py` (11) |
| **ASI06** Provenance-preserving memory | ✅ | `capguard/memory.py` (taint survives write→read; optional deny mode); `tests/test_memory.py` (8) |
| **Policy-pack compiler** | ✅ | `capguard/packs.py` (declarative profiles → `PolicyEngine` + capability templates; builtin owasp-baseline/finance/data-exfil); `tests/test_packs.py` (10) |

**Current tree: 272 test functions.** Both benchmarks hold (scripted 15/15 @ 0% ASR; real AgentDojo 97+35 @ 0% ASR / 100% utility under deterministic ground-truth replay).

**ASI coverage — every one of the ten risks is now ✓ (a deterministic shipped mechanism):** ASI01 (propagated taint), ASI02 (hardened + task-scoped), ASI03 (verifiable identity + delegation), ASI04 (MCP pin/scan), ASI05 (sandbox), ASI06 (provenance-preserving memory), ASI07 (shadowing + delegation attenuation), ASI08 (+ circuit breaker), ASI09 (replay-safe approvals), ASI10 (anomaly detection + kill switch).

**What's next (post-build):** live-LLM AgentDojo (drive `agentdojo.agent_pipeline` with a real model + auto-provenance from the tracker), Ed25519/SPIFFE issuance + OIDC binding, streamable-HTTP MCP transport, a policy-pack compiler (YAML → rules), and richer (advisory) sequence models feeding the deterministic breaker.

---

## 6. Risks & de-risking (reflect)

- **Over-blocking from propagation.** → keep utility in CI; default to boundary-tagging (sound-enough for the high-value exfil cases) before attempting full propagation; offer `corrective`/`sanitize` effects instead of hard DENY where safe.
- **Soundness gaps in taint.** → be explicit in docs about the threat model (we are not a forked interpreter); cover the money/email/HTTP/file exfil paths first; cite CaMeL/RTBAS as the soundness north star.
- **"Another security tool" / Microsoft shadow.** → lean all the way into *embeddable + composable underneath*; never ask the user to adopt a platform; 5-minute decorator story.
- **Latency.** → propagation is pointer/label bookkeeping, µs-level; keep any classifier detectors optional/async.
- **Scope sprawl.** → phases ship independently and are ordered by leverage; P1 alone is a headline release.

---

## 7. References (June 2026 reading list)
- OWASP Top 10 for Agentic Applications 2026 (ASI01–ASI10) — genai.owasp.org
- Microsoft **Agent Governance Toolkit** — opensource.microsoft.com (Apr 2026)
- **AgentArmor** (trace-as-program IFC) — arXiv:2508.01249
- **CaMeL** — arXiv:2503.18813; computer-use extension arXiv:2601.09923
- **RTBAS** arXiv:2502.08966 · **Ghost-in-the-Agent** arXiv:2604.23374 · **NeuroTaint** (semantic/causal taint)
- **PAuth** arXiv:2603.17170 · Intent-to-Execution Integrity arXiv:2605.16976 · Authorization Propagation arXiv:2605.05440
- **AIP — Agent Identity Protocol** arXiv:2603.24775 · SPIFFE/WIMSE (CNCF) · NIST AI Agent Standards Initiative (Feb 2026)
- **Progent** arXiv:2504.11703 · **AgentSpec** arXiv:2503.18666 · **LlamaFirewall** arXiv:2505.03574
- MCP threat modeling arXiv:2603.22489 · MCP CVE wave (40+ Jan–Apr 2026) · Snyk/Invariant Labs
- Benchmarks: AgentDojo (2406.13352), **AgentDyn** (2602.03117), ASB, InjecAgent, DoomArena · Agentic AI attack/defense survey arXiv:2603.11088
