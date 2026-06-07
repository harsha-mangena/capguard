# CapGuard — the deterministic security runtime for AI agents

> Least privilege for AI agents, **enforced**. A non-bypassable layer that sits inline on every tool call and every MCP message.

CapGuard is an embeddable Python SDK that makes any agent stack (LangGraph, CrewAI, AutoGen, OpenAI Agents, custom loops, or raw MCP) safe by default. It is **not** a prompt classifier and **not** a guardrail that tries to guess intent. It is a deterministic enforcement runtime: it decides — from capabilities, policy, and data provenance — whether a concrete tool call is allowed, denied, or needs human approval, and it backs that decision with hard isolation and a tamper-evident audit trail.

**Status:** active development. Core is implemented and tested. **171 tests passing** (1 skipped: Docker backend); deterministic security benchmark at **0% attack-success rate / 100% utility / ~0.04 ms per-call overhead**. On the **real AgentDojo benchmark** (97 user + 35 injection tasks across all four suites), one general provenance profile holds **ASR 0.0% at 100% utility** under deterministic ground-truth replay. **All ten OWASP ASI risks now carry a shipped mechanism — every row is ✓.**

```bash
pip install -e .                 # or: poetry install
PYTHONPATH=. pytest -q           # 171 passed, 1 skipped

capguard bench                       # scripted security benchmark (exit non-zero on regression)
capguard agentdojo                   # real AgentDojo eval (pip install agentdojo)
capguard packs list                  # builtin policy packs
capguard audit verify audit.jsonl    # check the tamper-evident hash chain
capguard mcp-scan tools.json         # scan MCP tool defs for poisoning
capguard proxy proxy.json --check    # dry-run the guarded MCP proxy (lists exposed tools)
```

---

## Why CapGuard

The 2026 **OWASP Top 10 for Agentic Applications** (ASI01–ASI10) makes clear that the dangerous moments in an agent's life are at the **action boundary**: which tool runs, with which arguments, on whose authority, fed by which data. Prompt filters and classifiers operate *around* the model and are probabilistic — they can be talked past. Generic authorization engines (Permit, Oso, Cedar) decide policy but don't sit on the agent runtime, don't track data provenance, and don't secure MCP.

CapGuard fills that gap. It is the deterministic backstop: even when a model is fooled into *attempting* a malicious call, CapGuard blocks it because the call violates capability, policy, or provenance — not because a classifier flagged it.

---

## What it does

| Layer | Module | What it gives you |
|-------|--------|-------------------|
| **Attenuable capabilities** | `core` | Capabilities are grants that can only be *narrowed*. An agent holding `network_http(domains=[a,b])` cannot reach `c`; `shell_exec(allowlist=[ls])` cannot run `rm`. Authorization is a subset/refinement check, never an expansion. |
| **Real argument enforcement** | `core`, `runtime` | The capability is enforced against the **actual** call value before dispatch: shell metacharacters and non-allow-listed commands are rejected, URLs checked against allowed domains, file paths resolved and contained (defeats `../`), read-only DB grants reject writes. |
| **Programmable policy DSL** | `policy_dsl` | Restrict by specific tool **and** use case: `Arg("amount") > 1000 → REQUIRE_APPROVAL`, rate limits, role checks. Deny-overrides precedence — a rule can only tighten. |
| **Data-flow provenance (propagated)** | `provenance`, `runtime` | A trust/confidentiality **label lattice** propagated across tool I/O: a value pulled from an untrusted source and laundered through another tool stays tainted, so `Taint("recipient").is_untrusted() → DENY` and `Flow.any_secret() → DENY` hold across a whole call chain with no per-call tagging. Deterministic indirect-prompt-injection defense (CaMeL / RTBAS / AgentArmor class) delivered as a library hook — not a forked interpreter. |
| **Verifiable identity + delegation** | `identity` | Signed (HMAC or Ed25519/SPIFFE-style) identity assertions bound to a human **principal + tenant**, verified at the proxy boundary — no more self-asserted `agent_id`. Sub-agent **delegation only attenuates**: a child can never hold authority its parent lacks (A2A-safe), with bounded chain depth and JIT expiry. |
| **Framework adapters** | `adapters` | `CapGuard(rt).tool(...)` guards a plain function in one line; `to_langchain` / `to_openai_agents` / `to_crewai` hand back native tool objects. CapGuard runs **underneath** LangGraph / OpenAI Agents / CrewAI / raw MCP — bring your stack. |
| **Replay-safe approvals** | `approval` | Human-in-the-loop tokens bound to `(agent, tool, exact-args)`, HMAC-signed, single-use. Approving a $10 transfer cannot be replayed as $10,000 (TOCTOU defense). |
| **Tamper-evident audit** | `audit` | Every decision is hash-chained (`prev_hash` + event → `hash`); any retroactive edit breaks the chain. Logs digests, not raw payloads. |
| **MCP security engine** | `mcp_guard` | Pins tool definitions by fingerprint, detects **rug pulls** (changed defs), **shadowing** (cross-server name/description collisions), and **tool poisoning** (instruction-override / concealment / exfiltration / zero-width smuggling in descriptions). |
| **Runnable MCP proxy** | `mcp_proxy`, `mcp_http` | A JSON-RPC proxy any MCP client connects to, over **stdio or Streamable HTTP**. Guards local subprocess *and* remote/hosted MCP servers. Poisoned/rug-pulled/shadowed tools are **stripped from `tools/list`** so the malicious description never reaches the model; every `tools/call` is enforced and audited. |
| **OAuth 2.1 boundary auth** | `mcp_auth` | The HTTP MCP server is an OAuth 2.1 **resource server**: validates bearer tokens (stdlib HS256-JWT or static), pins `alg`, checks **audience** (RFC 8707), returns `401 + WWW-Authenticate` / `403` and serves Protected Resource Metadata (RFC 9728). Composes with the signed-identity gate. |
| **Sandboxed execution** | `sandbox` | Execution backends with isolation tiers: hardened `SubprocessBackend` (POSIX rlimits, no-shell, env scrub, timeout-kill), ephemeral `DockerBackend` (`--network none`, read-only, caps dropped), and `DenyBackend`. |
| **Rogue-agent detection + kill switch** | `monitor` | Deterministic sliding-window anomaly detection over the audit stream — call-rate, denial-rate (probing), blast-radius (distinct sinks), novel-tool — trips a per-agent **circuit breaker**; the runtime then fail-closes that agent. (ASI10/ASI08) |
| **Task-scoped capability envelopes** | `taskscope` | PAuth-style JIT least privilege: a signed, expiring envelope authorizes only the concrete operations a task implies (`transfer ≤ $100 to Bob`), enforced per-call on top of standing capabilities. Issuing can only attenuate. |
| **Memory / RAG poisoning guard** | `memory` | Provenance-preserving memory: taint survives the write→read round-trip so recalled untrusted content is still blocked at sinks; optional deny-untrusted-writes mode. (ASI06) |
| **Policy packs** | `packs` | Declarative YAML/JSON/dict profiles compile to a `PolicyEngine` (and capability templates). Ship `owasp-baseline` / `finance` / `data-exfil`; adopt a strong default in one line. |
| **Benchmark harness** | `bench` | Deterministic scripted suite + **real AgentDojo** adapter measuring ASR / utility / latency, wired as a CI gate. |

---

## The pipeline (every tool call)

```
invoke_tool(name, agent=…, provenance=…, approval_token=…, **args)
  1. capability gate      — agent must hold a capability that covers the tool's need
  2. policy DSL           — argument / use-case / rate / provenance rules (deny-overrides)
  3. argument enforcement — the concrete value is checked against the granted bound  ← the teeth
  4. dispatch             — via the configured execution backend
  5. audit                — hash-chained event at every exit
```

Identity flows through an immutable per-call context, so concurrent calls cannot bleed permissions into one another.

---

## 60-second example

```python
from capguard import (
    AgentIdentity, AgentRuntime, Capability, Policy, Severity, ToolRegistry,
    PolicyEngine, Rule, Arg, tool_is, Effect,
)
from capguard.audit import HashChainedSink

reg = ToolRegistry()

@reg.tool(capabilities=[Capability.custom("transfer")], severity=Severity.LOW)
def transfer(amount: int, recipient: str) -> str:
    return f"sent {amount} to {recipient}"

# Restrict by use case: large transfers need a human; untrusted recipients are denied.
engine = (PolicyEngine()
    .add(Rule("limit", trigger=tool_is("transfer"), when=Arg("amount") > 1000,
              effect=Effect.REQUIRE_APPROVAL))
)

agent = AgentIdentity(id="fin-bot", allowed_capabilities=[Capability.custom("transfer")])
rt = AgentRuntime(registry=reg, engine=engine, audit_sink=HashChainedSink("audit.jsonl"),
                  default_agent=agent)

rt.invoke_tool("transfer", amount=100, recipient="alice")    # ok
rt.invoke_tool("transfer", amount=9999, recipient="alice")   # ApprovalRequired
```

Guard a real MCP server in front of any client:

```bash
python examples/run_proxy.py     # stdio MCP proxy; point Claude Desktop / Cursor at it
```

---

## Security benchmark

**Scripted suite** — one general policy profile, 15 attacks across 7 domains (banking, email, web, files, shell, messaging, destructive ops), including two *laundering* attacks blocked only by propagated provenance:

```
metric                 baseline   CapGuard
attack success rate     100.0%      0.0%
benign utility          100.0%    100.0%
overhead / call          —       ~0.04 ms
```

**Real AgentDojo** (`capguard.bench.run_agentdojo`) — deterministic ground-truth replay of the actual benchmark, one general provenance rule per domain:

```
suite        user  inj   utility    ASR
banking        16    9    100.0%    0.0%
slack          21    5    100.0%    0.0%
travel         20    7    100.0%    0.0%
workspace      40   14    100.0%    0.0%
TOTAL          97   35    100.0%    0.0%
```

CapGuard measures **deterministic enforcement** — does it block the malicious call when attempted — not LLM susceptibility (which adaptive attacks now beat >85% of the time against probabilistic defenses). It composes underneath classifier defenses (LlamaFirewall, CaMeL) as the non-bypassable layer. See [`docs/BENCHMARK_RESULTS.md`](docs/BENCHMARK_RESULTS.md).

---

## OWASP ASI 2026 coverage

| Risk | Status | Mechanism |
|------|--------|-----------|
| ASI01 Goal/behavior hijack | ✓ | provenance **propagated** across tool I/O (taint a laundered value end-to-end) |
| ASI02 Tool misuse | ✓ | attenuation + argument-level DSL + normalize-before-enforce + task-scoped envelopes |
| ASI03 Identity & privilege abuse | ✓ | verifiable signed identity (principal+tenant), delegation-only-attenuates, JIT grants |
| ASI04 Agentic supply chain | ✓ | signed plugins, MCP pinning, poisoning scan |
| ASI05 Unexpected code execution | ✓ | sandbox backends |
| ASI06 Memory/context poisoning | ✓ | provenance-preserving memory/RAG: taint survives write→read; optional deny-untrusted-writes |
| ASI07 Insecure inter-agent comms | ✓ | shadowing detection + list-strip; delegation attenuation across hops |
| ASI08 Cascading failures | ✓ | rate limits, resource caps, blast-radius cap + **circuit-breaker kill switch** |
| ASI09 Human-agent trust | ✓ | replay-safe approvals |
| ASI10 Rogue agents | ✓ | **sequence-anomaly detection** over the audit stream → circuit breaker |

✓ covered · ◑ partial · ✗ planned. **Every row is now ✓** — a deterministic mechanism for all ten ASI risks. See [`ROADMAP.md`](ROADMAP.md).

---

## Repository layout

```
capguard/
  core.py          capabilities, attenuation, argument enforcement, normalize-before-enforce, policy
  registry.py      tool registry (decorator API)
  runtime.py       enforcement pipeline (stateless, concurrency-safe) + provenance wiring
  policy_dsl.py    trigger → predicate → effect rules; Arg / Provenance / Taint / Flow builders
  provenance.py    trust+confidentiality label lattice; ProvenanceTracker (propagated taint)
  identity.py      signed identity assertions, verification, delegation attenuation (ASI03)
  taskscope.py     task/intent-scoped capability envelopes (PAuth-style JIT least privilege)
  monitor.py       rogue-agent anomaly detection + circuit breaker / kill switch (ASI10/ASI08)
  memory.py        provenance-preserving memory/RAG store (anti context-poisoning, ASI06)
  packs.py         policy-pack compiler (declarative profiles -> PolicyEngine) + builtin packs
  adapters.py      one-line guard + LangChain/OpenAI-Agents/CrewAI bindings
  cli.py           `capguard` CLI: bench / agentdojo / audit verify / packs / mcp-scan / proxy
  audit.py         hash-chained tamper-evident audit + sinks
  approval.py      replay-safe, args-bound approval tokens
  mcp_guard.py     MCP pinning, rug-pull / shadowing / poisoning detection
  mcp_proxy.py     runnable JSON-RPC MCP proxy (stdio) + downstream clients; signed-identity gate
  mcp_http.py      Streamable-HTTP MCP transport: guard remote servers + serve the proxy over HTTP
  mcp_auth.py      OAuth 2.1 resource-server auth (bearer/JWT verify, RFC 9728 PRM, RFC 8707 audience)
  sandbox.py       execution backends (subprocess / docker / deny) + tool factories
  bench/           scripted security benchmark + real AgentDojo adapter + CI gate
tests/             171 tests (provenance, identity, adapters, properties, AgentDojo, monitor, taskscope, memory, packs, http, auth, cli, …)
examples/          runnable MCP server + guarded proxy launcher
docs/              strategy memo, enhancement plan, benchmark results
```

---

## Documents

- [`docs/STRATEGY.md`](docs/STRATEGY.md) — market analysis, research grounding (CaMeL, Progent, AgentSpec, MCP-Guard), positioning and moat.
- [`docs/BENCHMARK_RESULTS.md`](docs/BENCHMARK_RESULTS.md) — methodology and numbers.
- [`docs/PR_01..04`](docs/) — change notes for each build phase.
- [`ROADMAP.md`](ROADMAP.md) — what's next.

## License

Apache 2.0 (core library, plugin spec, adapters). Hosted control plane / advanced policy packs may be licensed separately later.
