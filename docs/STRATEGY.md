# CapGuard → Agentic Security SDK: Strategy & Implementation Roadmap

*Co-founder strategy memo. Reasoned with Atom-of-Thoughts (decompose each claim to an atomic, checkable unit) and Tree-of-Thoughts (branch options, prune by market + research evidence). Grounded in the current repo and June 2026 state of the field.*

> Historical memo. This document describes an earlier state of the repository;
> many gaps called out below have since been implemented. Use `README.md`,
> `docs/security-model.md`, and `ROADMAP.md` for the current product state.

---

## 0. TL;DR

CapGuard today is a clean, well-structured **capability-declaration + policy + audit + approval-queue** library. But it is a *declarative metadata layer that does not actually enforce its own capabilities*, its core matching function has a latent crash bug, and it misses the two surfaces where the 2026 market actually lives: **MCP** and **data-provenance / prompt-injection defense**.

The winning move is **not** to become another policy engine (Permit.io, Oso, Cerbos, OpenFGA, Cedar already own generic AuthZ). The wedge is to be the **agent-native enforcement runtime**: the thing that sits *inline on every tool call and every MCP message*, enforces least-privilege at the argument level, tracks data taint to stop injected-instruction misuse, and produces a tamper-evident, OWASP-ASI-mapped audit trail. Think **"the eBPF/OPA of agent tool calls,"** packaged as a 5-minute-to-adopt SDK + MCP proxy.

---

## 1. Honest assessment of the repo as-is

### What's genuinely good
- Clean separation: `core` (Capability/ToolSpec/AgentIdentity/Policy) → `registry` → `runtime` → `adapters`/`gateway`/`approvals`.
- Three-decision policy model (ALLOW / DENY / REQUIRE_APPROVAL) is the right primitive.
- Signed plugin bundles (Ed25519) + `PluginLoader` with severity ceiling = correct instinct for ASI04 supply chain.
- Approval queue service (SSE, TTL auto-deny, Slack/webhook notify, inline UI) is a real differentiator vs research prototypes — production HITL is usually missing.
- Policy packs (OWASP / finance / healthcare YAML) = good GTM surface.

### Critical defects (must fix before any "best SDK" claim)

| # | Defect | File | Severity | Why it matters |
|---|--------|------|----------|----------------|
| 1 | `frozenset(c.params.items())` hashes list-valued params (`allowlist`, `domains`, `paths`) → **TypeError at runtime**. Lists are unhashable. | `core.py` `Policy.evaluate` | **Blocker** | Any real capability with a list param crashes policy evaluation. The matching also has *no attenuation semantics* even if it didn't crash. |
| 2 | **Capabilities are decorative — not enforced.** `safe_shell` runs `subprocess.run(cmd, shell=True)`; the `allowlist=["ls"]` never reaches the runtime check or the tool. `safe_shell(cmd="rm -rf /")` passes if the agent holds `shell_exec`. | `runtime.py` + all example tools | **Blocker** | A "capability layer" that does not enforce capabilities is theatre. This is the single biggest gap. |
| 3 | Approval **replay loop is broken**. Gateway has no `approval_handler`, so replaying an approved call re-hits `REQUIRE_APPROVAL`; approvals service then marks it `approved_failed`. No approval token flips the decision. TOCTOU. | `approvals.py` + `gateway.py` | High | The headline HITL feature doesn't actually resume the action. |
| 4 | `CapabilityMiddleware` **mutates `runtime._agent` with try/finally** → not concurrency-safe under FastAPI's threadpool / async. | `adapters.py` | High | Cross-request identity bleed under load = privilege confusion, the worst class of bug for a security tool. |
| 5 | Gateway `/tool-call` is **unauthenticated**, `agent_id` is self-asserted in the body, CORS `*`. | `gateway.py` | High | ASI03 (identity abuse) — anyone can claim any agent identity. |
| 6 | Audit log is plain **append-only JSONL**; README claims "tamper-proof." | `audit.py` | Medium | Not tamper-evident. No hash chaining / signing. |
| 7 | `pub.public_bytes.__defaults__[0]` introspection hack to get encoding/format. | `cli.py` | Medium | Fragile; will break across `cryptography` versions. Use explicit enums. |
| 8 | LangGraph adapter is a stub (`wrap_langgraph_tool` ignores capabilities; `apply_capguard_to_graph` is a no-op). CrewAI adapter is claimed in README but absent. **No MCP adapter at all.** | `adapters/` | High | The integration surface that matters most in 2026 is missing. |

---

## 2. Market landscape (June 2026) — where the puck is

**Standards / threat model.** OWASP published the **Top 10 for Agentic Applications 2026** in Dec 2025: ASI01 Agent Goal/Behavior Hijack, ASI02 Tool Misuse, ASI03 Identity & Privilege Abuse, ASI04 Agentic Supply Chain, ASI05 Unexpected Code Execution, ASI06 Memory & Context Poisoning, ASI07 Insecure Inter-Agent Communication, ASI08 Cascading Failures, ASI09 Human-Agent Trust Exploitation, ASI10 Rogue Agents. It ships cross-maps to the LLM Top 10, AIVSS scoring, CycloneDX/AIBOM, and the **Non-Human Identities Top 10** — those mappings are a ready-made GTM scaffold.

**Adjacent / competing categories.**
- *Generic AuthZ engines being stretched to agents:* Permit.io (OPA/OPAL/Rego; "Four-Perimeter" AI access control; agent identity bound to human identity, zero standing permissions, HITL), Oso (Polar DSL; "automated least privilege" = confine agent to the user's permissions), Cerbos, OpenFGA, AWS Cedar, WorkOS FGA. **They own policy decisioning. They do *not* own the agent-runtime enforcement point, data taint, or MCP.**
- *Runtime guardrail / firewall vendors:* Meta **LlamaFirewall** (open source: PromptGuard2 classifier + AlignmentCheck CoT auditor + CodeShield), NeMo Guardrails, Lakera, Lasso, Protect AI, Palo Alto Prisma AIRS, Invariant Labs (MCP-scan), NeuralTrust. **These are mostly classifiers/gateways that act before/after the model — probabilistic, not deterministic enforcement.**
- *MCP-specific security:* MCP-Guard (proxy, multi-stage defense), ETDI (OAuth-enhanced tool definitions + crypto-pinned tool defs), mcp-scan, OWASP MCP cheat sheet, ARGE of CVEs (MCPoison CVE-2025-54136, CurXecute CVE-2025-54135, mcp-remote CVE-2025-6514). A 2025 study found **5.5% of ~1,899 public MCP servers had tool-poisoning issues.** This is an open, fast-growing surface with no dominant open-source SDK yet.

**Synthesis (connect the dots):** The market has (a) policy engines without an agent-native enforcement runtime, and (b) probabilistic guardrails without deterministic least-privilege. **No open-source SDK convincingly unifies deterministic capability enforcement + data-provenance + MCP-native proxy + signed supply chain + tamper-evident audit, with a Progent-style argument-level policy DSL and AgentSpec-style runtime hooks.** That is the gap CapGuard should own.

---

## 3. Research foundations to build on (and exactly what to borrow)

| Work | Core idea | What CapGuard adopts |
|------|-----------|----------------------|
| **CaMeL** (DeepMind, *Defeating Prompt Injections by Design*, 2025) | Capabilities-as-metadata on *data values*; control/data-flow separation via a custom interpreter; block an action when a value lacks the required trust capability. ~67% IPI mitigation on AgentDojo, by design (not classifier). | **Data-provenance/taint capabilities.** Tag tool *outputs* and inputs with trust labels (trusted-user vs untrusted-tool/web). Policy can require "recipient must be `trusted`" — stops the classic "email forwarded to attacker" exfil. This is CapGuard's ASI01/ASI06 answer and the deepest moat. |
| **Progent** (Shi et al., 2504.11703; validated on AgentDojo/ASB/AgentPoison; integrates LangChain + OpenAI Agents SDK) | A **DSL for privilege control over tool calls**: when a call is permissible, argument-level predicates, fallbacks if not. LLM-generated + dynamically updated policies. | **The policy DSL.** Replace coarse per-tool severity with per-call predicates over arguments (e.g. `transfer.amount <= 1000 and recipient in allowlist`). Add LLM-assisted policy synthesis from the user's task. |
| **AgentSpec** (ICSE'26, 2503.18666) | Lightweight DSL: **trigger → predicate → enforcement** (terminate / user-inspect / corrective-invoke / self-reflect). Framework-agnostic hooks into the decision pipeline; ms overhead; >90% unsafe-execution prevention. | **The enforcement model.** Generalize beyond ALLOW/DENY/APPROVE to: deny, require-approval, **transform/sanitize args**, **corrective re-prompt**, **rate-limit/quota**. Hook pattern for adapters. |
| **LlamaFirewall** (Meta, 2505.03574; AgentDojo ASR 17.6%→1.75% combined) | Layered defense: classifier (PromptGuard2) + semantic alignment auditor + code scanner. | **Optional probabilistic layer behind the deterministic core.** CapGuard stays deterministic-first; expose pluggable "detectors" (PromptGuard2/AlignmentCheck/own) as advisory signals feeding policy predicates. |
| **ETDI / MCP-Guard / mcp-scan** | OAuth-enhanced + crypto-pinned tool definitions; proxy scanning for poisoning/shadowing/rug-pulls; pin tool defs by hash and alert on change. | **MCP proxy + tool-definition pinning.** Reuse CapGuard's existing Ed25519 signing to pin and verify MCP tool schemas; detect rug-pulls by hash diff. ASI02/ASI04/ASI07. |
| **Sandboxing best practice** (E2B/Firecracker/gVisor; ICSE/AugmentCode guides) | Hardware/userspace-kernel isolation, default-deny fs/net, ephemeral containers for code/shell. | **Enforcement backends.** `shell_exec`/`exec_code` capabilities should *dispatch into a sandbox* (subprocess allowlist → Docker → gVisor/Firecracker tiers), not just call `subprocess.run`. This closes defect #2 for the highest-risk capabilities. |

**Evaluation anchor:** AgentDojo (97 tasks, ~949 attack pairs), ASB, InjecAgent, DoomArena. Near-0 ASR is achievable (Task Shield, MELON, ACE, CaMeL, Progent all reported <2% on AgentDojo "important instructions"). CapGuard must publish numbers on these or it cannot credibly claim "best."

---

## 4. The reinvention — CapGuard 2.0 architecture

**Positioning statement:** *CapGuard is the deterministic, agent-native security runtime. It sits inline on every tool call and MCP message, enforces argument-level least privilege and data-provenance policy, sandboxes high-risk execution, and emits a tamper-evident, OWASP-ASI-mapped audit trail — in any framework, in 5 minutes.*

Seven planes:

1. **Identity plane** — verifiable `AgentIdentity` (signed assertions / OIDC-style token bound to a human principal + tenant), not self-asserted strings. Zero standing permissions; capabilities are grants, not properties. (ASI03)
2. **Capability plane** — capabilities as *attenuable grants* with proper **subset/attenuation semantics** (agent `domains=[a,b,c]` ⊇ tool `domains=[a]` → allow). Fixes defect #1 properly. (ASI02/ASI03)
3. **Policy plane** — a Progent/AgentSpec-style **DSL**: `trigger(tool, args) → predicate → effect`. Effects: allow / deny / require_approval / sanitize / rate_limit / corrective. Argument-level. Compiles to a fast evaluator. LLM-assisted synthesis from the task, human-reviewed before activation. (ASI01/ASI02)
4. **Provenance plane** — taint labels on data values flowing through tool I/O (trusted-user / untrusted-tool / untrusted-web). Policies can require trust levels on sensitive arguments. CaMeL-style, but as a library hook, not a forked interpreter. (ASI01/ASI06)
5. **Enforcement plane** — pluggable backends per capability: in-proc check, subprocess allowlist, Docker, gVisor/Firecracker microVM; default-deny egress; quotas/budgets per agent/session. (ASI05/ASI08)
6. **Supply-chain plane** — signed plugins (have it) **extended to MCP**: pin tool schemas by hash, verify signer, detect rug-pulls/shadowing, scan descriptions for poisoning. (ASI04/ASI07)
7. **Observability plane** — **hash-chained, optionally signed** audit (Merkle-style), OpenTelemetry export, AIVSS-scored events, real-time anomaly hooks on call sequences (ASI10 rogue-agent detection), blast-radius caps + kill switch (ASI08).

**Integration surfaces (priority order):** MCP proxy → LangGraph → OpenAI Agents SDK → CrewAI/AutoGen → generic HTTP gateway. MCP first because it is the universal surface and the least-served.

---

## 5. OWASP ASI 2026 coverage map (target state)

| Risk | Today | CapGuard 2.0 mechanism |
|------|-------|------------------------|
| ASI01 Goal Hijack | ✗ | Provenance plane + corrective effect + advisory detectors |
| ASI02 Tool Misuse | ◑ (per-tool only) | Argument-level policy DSL + capability attenuation |
| ASI03 Identity/Privilege | ◑ (self-asserted) | Verifiable identity + zero standing perms + JIT ephemeral caps |
| ASI04 Supply Chain | ◑ (plugin signing) | Extend signing/pinning to MCP tool defs + scan |
| ASI05 Unexpected Code Exec | ✗ (decorative) | Sandbox enforcement backends (Docker→microVM) |
| ASI06 Memory/Context Poisoning | ✗ | Provenance taint on memory/RAG writes; require trusted source |
| ASI07 Insecure Inter-Agent Comms | ✗ | MCP/A2A message signing + identity propagation |
| ASI08 Cascading Failures | ✗ | Quotas, budgets, blast-radius caps, kill switch |
| ASI09 Human-Agent Trust | ◑ (approval UI) | Approval UI shows provenance + risk + diff before approve |
| ASI10 Rogue Agents | ✗ | Sequence anomaly detection on audit stream |

Legend: ✓ done · ◑ partial · ✗ gap.

---

## 6. Implementation plan (phased)

Each phase ships independently and is testable. Effort tags are rough solo-builder estimates.

### Phase 0 — Stop the bleeding (week 1, ~3 days)
- **Fix `Policy.evaluate`**: replace `frozenset(c.params.items())` with a structural, hashable-safe comparator; implement **attenuation** (tool cap must be a *subset/refinement* of an agent cap: timeout ≤, allowlist ⊆, domains ⊆, paths ⊆ by glob containment). Add property-based tests (Hypothesis).
- **Make `shell_exec` actually enforce** the allowlist in the runtime *before* dispatch; reject commands whose argv[0] ∉ allowlist; enforce `timeout`. Same for `network_http` domain and `file_*` path containment — move the check out of each tool and into the runtime.
- **Concurrency-safe context**: stop mutating `runtime._agent`. Pass an immutable per-call `CallContext(agent, caps, provenance)` through `invoke_tool`. Make `AgentRuntime` stateless w.r.t. identity.
- Replace the `cli.py` `__defaults__` hack with explicit `serialization.Encoding.PEM` / `PublicFormat.SubjectPublicKeyInfo`.

### Phase 1 — Real enforcement + DSL core (weeks 2–4)
- **Policy DSL v1** (`trigger → predicate → effect`), argument-aware. Start as typed Python (decorators + expressions); add a YAML/JSON serialization. Compile to a deterministic evaluator. Effects: `allow | deny | require_approval | rate_limit | sanitize | corrective`.
- **Enforcement backends** abstraction: `InProcess`, `SubprocessAllowlist`, `DockerSandbox`. Capabilities declare a backend; runtime dispatches through it. Default-deny egress in the Docker backend.
- **Quotas/budgets**: per-agent/session call counts, token/$ budgets, rate limits → ties to ASI08.
- **Tamper-evident audit**: hash-chain each `AuditEvent` (`prev_hash` + event → `hash`); optional Ed25519 signing of the chain head; keep JSONL + add OpenTelemetry exporter.

### Phase 2 — MCP-native (weeks 5–7) ← biggest market lever
- **CapGuard MCP proxy**: a server that sits between client and downstream MCP servers. It (a) verifies/pins tool schemas by hash (reuse Ed25519), (b) maps each MCP tool to a `ToolSpec` + capabilities, (c) enforces the policy DSL on every `tools/call`, (d) audits, (e) routes `require_approval` to the existing queue.
- **Rug-pull / shadowing detection**: alert on tool-definition hash change; flag near-duplicate tool names across servers; static scan of descriptions for instruction-like payloads (ASI04/ASI07).
- **Per-session isolation**: one sandbox/process per session; non-deterministic session IDs; bind to loopback by default.

### Phase 3 — Provenance / anti-injection (weeks 8–11) ← deepest moat
- **Taint labels** on tool I/O: outputs from untrusted sources (web/tool) carry `untrusted`; user prompt carries `trusted`. A lightweight propagation wrapper (not a forked interpreter) tags values crossing tool boundaries.
- **Provenance predicates** in the DSL: e.g. `send_email` requires `recipient.provenance == trusted`. This is the CaMeL-style deterministic IPI defense.
- **Advisory detectors** (pluggable, off the deterministic critical path): optional PromptGuard2 / AlignmentCheck / classifier hooks whose scores feed predicates. Deterministic-first, probabilistic-assist.

### Phase 4 — Identity, rogue-agent detection, fleet (weeks 12–16)
- **Verifiable identity**: signed agent assertions bound to human principal + tenant; integrate with an IdP / OIDC; map to NHI Top 10. Zero standing permissions; JIT ephemeral capability grants (the `ephemeral_capabilities` hook already exists — make it the norm).
- **Sequence anomaly detection** on the audit stream (ASI10): unusual tool-call sequences, privilege drift, blast-radius breaches → alert / kill switch.
- **Control plane (commercial wedge)**: hosted policy management, multi-tenant audit, dashboards, replay/digital-twin testing (OWASP's cascading-failure mitigation).

### Phase 5 — Prove it (continuous from Phase 1)
- Wire **AgentDojo + ASB + InjecAgent + DoomArena** into CI. Publish ASR / utility / latency vs no-defense and vs Progent/LlamaFirewall/CaMeL. "Best SDK" requires public, reproducible numbers — make the benchmark harness a first-class repo artifact.

---

## 7. Differentiation & moat (connect intra/inter dots)

- **vs Permit.io/Oso/Cedar:** they decide; CapGuard *enforces inline at the agent runtime* + does data taint + MCP + sandbox. Position as complementary: "bring your policy engine; CapGuard is the enforcement point." Offer a Cedar/OPA predicate backend so you ride their adoption instead of fighting it.
- **vs LlamaFirewall/guardrail vendors:** they are probabilistic and model-side; CapGuard is **deterministic and action-side**. Different failure mode, composable. Embed their classifiers as advisory detectors.
- **vs research prototypes (Progent/CaMeL/AgentSpec):** they are papers + research code. CapGuard is **productized**: HITL queue, signed supply chain, OTel audit, MCP proxy, framework adapters, benchmark harness. Productization + MCP-native + deterministic taint = the defensible combination.
- **Moat compounding:** (1) the policy-pack library (OWASP/finance/healthcare/more) becomes a content moat; (2) the MCP tool-definition pinning registry becomes a trust/network-effect moat; (3) the benchmark harness + published numbers become a credibility moat that's expensive for others to match.

---

## 8. Risks & how to de-risk (reflect)

- **Risk: deterministic policy hurts utility (over-blocking).** De-risk: utility metric in CI; LLM-assisted policy synthesis tuned to the task; `corrective` effect (re-prompt) instead of hard deny where possible. Progent showed strong security *with* high utility — replicate.
- **Risk: provenance plane is hard without a custom interpreter.** De-risk: ship a *partial* propagation wrapper (tool-boundary tagging) first; it covers the high-value exfil cases (email/transfer/HTTP) even if not sound across arbitrary Python. Be explicit about the threat model.
- **Risk: scope sprawl (seven planes).** De-risk: phases are independently shippable and ordered by leverage; MCP proxy (Phase 2) is the standalone hero feature even if later phases slip.
- **Risk: latency.** De-risk: deterministic evaluator is µs–ms (AgentSpec confirms ms overhead); keep probabilistic detectors optional/async.
- **Risk: "another security tool" fatigue.** De-risk: 5-minute adoption story (decorator or one-line MCP proxy), great docs, OWASP-ASI mapping that lets buyers check compliance boxes.

---

## 9. Naming / packaging note

README uses "CapGuard a.k.a. AgentCap." Pick one and own it; "CapGuard" reads as security, keep it. Tagline candidates: *"Least privilege for AI agents — enforced."* / *"The runtime firewall for agent tool calls."*

---

## 10. References (for your reading list)

- OWASP **Top 10 for Agentic Applications 2026** — genai.owasp.org (ASI01–ASI10; appendices: NHI Top 10, AIVSS, AIBOM).
- **CaMeL** — *Defeating Prompt Injections by Design*, arXiv:2503.18813 (code: google-research/camel-prompt-injection).
- **Progent** — *Programmable / Securing AI Agents with Privilege Control*, arXiv:2504.11703.
- **AgentSpec** — *Customizable Runtime Enforcement for Safe and Reliable LLM Agents*, arXiv:2503.18666 (ICSE'26).
- **LlamaFirewall** — Meta, arXiv:2505.03574 (PromptGuard2 / AlignmentCheck / CodeShield).
- **ETDI** — arXiv:2506.01333 (OAuth-enhanced MCP tool definitions).
- **MCP-Guard** — arXiv:2508.10991; **MCP threat taxonomy** arXiv:2603.18063; OWASP MCP Security Cheat Sheet.
- IPI defense comparison (Task Shield / MELON / ACE / CaMeL / Progent on AgentDojo/ASB/InjecAgent) — arXiv:2511.15203.
- Sandboxing: E2B / Firecracker / gVisor; secure plan-then-execute, arXiv:2509.08646.
