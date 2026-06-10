# CapGuard

**Least privilege for AI agents — enforced.** A deterministic, non-bypassable
layer that sits inline on every tool call and every MCP message.

CapGuard is an embeddable Python SDK that makes any agent stack (LangGraph,
CrewAI, OpenAI Agents, custom loops, or raw MCP) safe by default. It is **not** a
prompt classifier and **not** a guardrail that guesses intent. It is a
deterministic enforcement runtime: from capabilities, policy, and data
provenance it decides whether a concrete tool call is allowed, denied, or needs
human approval — and backs that with hard isolation and a tamper-evident audit
trail.

```bash
pip install capguard
```

## Why it exists

The 2026 OWASP Top 10 for Agentic Applications makes clear that the dangerous
moments are at the **action boundary**: which tool runs, with which arguments, on
whose authority, fed by which data. Classifiers operate *around* the model and
are probabilistic — they can be talked past. Authorization engines decide policy
but don't sit on the agent runtime, don't track data provenance, and don't secure
MCP.

CapGuard is the deterministic backstop: even when a model is fooled into
*attempting* a malicious call, CapGuard blocks it because the call violates
capability, policy, or provenance — not because a classifier flagged it.

## Numbers

- **206 tests** (1 skipped: Docker backend).
- Deterministic security benchmark: **0% attack-success rate / 100% utility /
  ~0.04 ms per call**.
- Real **AgentDojo** (97 user + 35 injection tasks, all four suites): **0% ASR /
  100% utility** under deterministic ground-truth replay.
- A shipped mechanism for **all ten OWASP ASI-2026 risks**.

Start with the [Quickstart](quickstart.md) or guard a real MCP server with the
[MCP proxy](mcp-proxy.md).
