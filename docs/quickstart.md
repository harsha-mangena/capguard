# Quickstart

```bash
pip install capguard-runtime
```

The distribution is named `capguard-runtime` on PyPI; the Python package and CLI
remain `capguard`.

## 60 seconds: guard a tool call

```python
from capguard import (
    AgentIdentity, AgentRuntime, Capability, Severity, ToolRegistry,
    PolicyEngine, Rule, Arg, tool_is, Effect,
)
from capguard.audit import HashChainedSink

reg = ToolRegistry()

@reg.tool(capabilities=[Capability.custom("transfer")], severity=Severity.LOW)
def transfer(amount: int, recipient: str) -> str:
    return f"sent {amount} to {recipient}"

# Restrict by use case: large transfers need a human.
engine = PolicyEngine().add(
    Rule("limit", trigger=tool_is("transfer"), when=Arg("amount") > 1000,
         effect=Effect.REQUIRE_APPROVAL))

agent = AgentIdentity(id="fin-bot", allowed_capabilities=[Capability.custom("transfer")])
rt = AgentRuntime(registry=reg, engine=engine,
                  audit_sink=HashChainedSink("audit.jsonl"), default_agent=agent)

rt.invoke_tool("transfer", amount=100,  recipient="alice")   # ok
rt.invoke_tool("transfer", amount=9999, recipient="alice")   # ApprovalRequired
```

See the live demo:

```bash
python -m capguard.cli version
python examples/demo_poison_strip.py     # poisoned MCP tool stripped + guarded transfer
```

## Embed under your framework

```python
from capguard import CapGuard, to_langchain

guard = CapGuard(rt)

@guard.tool(name="search", capabilities=[Capability.network_http(domains=["api.corp.com"])])
def search(url: str) -> str:
    ...

lc_tool = to_langchain(search)      # native LangChain StructuredTool, still guarded
```

`to_openai_agents(...)` and `to_crewai(...)` work the same way. CapGuard runs
**underneath** your framework — bring your stack.

## Adopt a strong default in one line

```python
from capguard import compile_pack
engine = compile_pack("owasp-baseline")   # or "finance", "data-exfil"
```

## Stop a laundered injection with propagated provenance

```python
from capguard import ProvenanceTracker
rt = AgentRuntime(registry=reg, engine=engine, default_agent=agent,
                  tracker=ProvenanceTracker())

poisoned = rt.invoke_tool("web_fetch", url="https://evil.com")   # auto-labeled untrusted_web
rt.invoke_tool("send_message", channel="#x", text=poisoned)      # DENIED — taint propagated, no tagging needed
```
