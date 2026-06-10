# Security model

## The pipeline (every tool call)

```text
invoke_tool(name, agent=…, provenance=…, approval_token=…, task_scope=…, **args)
  0   kill switch        — a tripped circuit breaker halts the agent first
  0.3 budget gate        — cumulative call/token/$ ceiling (ASI08)
  0.5 task scope         — JIT least privilege for this task (PAuth-style)
  1   capability gate    — agent must hold a capability covering the tool's need
  1.5 advisory detectors — optional classifier signals feed the DSL (tighten-only)
  2   policy DSL         — argument / use-case / rate / provenance rules (deny-overrides)
  3   argument enforcement — the concrete value is checked against the grant ← the teeth
  4   dispatch + provenance record
  5   hash-chained audit at every exit
```

Identity flows through an immutable per-call context, so concurrent calls cannot
bleed permissions into one another. Every gate can only **tighten** the decision;
there is no path by which policy, detectors, or scopes *loosen* enforcement.

## Guarantees (machine-checked)

Property tests (`tests/test_properties.py`, Hypothesis) assert the laws a security
kernel lives or dies by:

- the information-flow label lattice is a real join-semilattice
  (commutative / associative / idempotent / identity / monotone);
- capability coverage is exactly the subset/refinement relation, and enforcement
  never permits a value outside the grant (no privilege expansion);
- the audit hash-chain is intact for any sequence and breaks under any single-field
  tamper;
- normalize-before-enforce rejects smuggled control/format characters.

## OWASP ASI-2026 coverage

| Risk | Mechanism |
|------|-----------|
| ASI01 Goal/behavior hijack | propagated provenance + advisory detectors |
| ASI02 Tool misuse | attenuation + argument DSL + normalize-before-enforce + task scopes |
| ASI03 Identity & privilege abuse | verifiable signed identity, delegation only attenuates |
| ASI04 Agentic supply chain | MCP pinning + rug-pull / shadowing / poisoning scan |
| ASI05 Unexpected code execution | sandbox backends (subprocess / docker / deny) |
| ASI06 Memory & context poisoning | provenance-preserving memory (taint survives write→read) |
| ASI07 Insecure inter-agent comms | shadowing strip + signed A2A messages + per-message attenuation |
| ASI08 Cascading failures | rate limits, budgets, blast-radius cap + circuit-breaker kill switch |
| ASI09 Human-agent trust | replay-safe, args-bound approval tokens |
| ASI10 Rogue agents | sequence-anomaly detection over the audit stream → kill switch |

## Threat-model honesty

- **Provenance** is a library hook (boundary tagging + propagation), not a forked
  interpreter. It is sound for the high-value exfil paths (money / email /
  messaging / HTTP / file) — be explicit about that scope.
- **Detectors** are advisory: a probabilistic signal can tighten the deterministic
  decision, never weaken it; a failing detector is ignored.
- **The benchmark** measures *deterministic enforcement* — does the guard block
  the malicious call when attempted — under one general profile with no per-attack
  rules. It composes underneath classifier defenses (LlamaFirewall, CaMeL) as the
  non-bypassable backstop.
