"""Tests for the framework adapters (P4)."""

from __future__ import annotations

import pytest

from capguard import (
    AgentIdentity,
    AgentRuntime,
    Capability,
    CapGuard,
    Effect,
    PolicyEngine,
    Provenance,
    Rule,
    Severity,
    ToolRegistry,
    to_crewai,
    to_langchain,
    to_openai_agents,
    tool_is,
)


def _guard_with_echo():
    reg = ToolRegistry()
    agent = AgentIdentity(id="bot", allowed_capabilities=[
        Capability.custom("echo"),
        Capability.network_http(domains=["a.com"], arg="url"),
    ])
    rt = AgentRuntime(registry=reg, default_agent=agent)
    guard = CapGuard(rt)

    @guard.tool(name="echo", capabilities=[Capability.custom("echo")], severity=Severity.LOW)
    def echo(text):
        """Echo text back."""
        return f"echo:{text}"

    return guard, rt, echo


# --------------------------------------------------------------------------- #
# universal facade
# --------------------------------------------------------------------------- #
def test_facade_registers_and_guards():
    guard, rt, echo = _guard_with_echo()
    assert echo(text="hi") == "echo:hi"          # GuardedTool routes through runtime
    assert echo.name == "echo"
    assert "Echo text" in echo.description
    assert rt.registry.has("echo")


def test_facade_enforces_capabilities_through_runtime():
    guard, rt, _ = _guard_with_echo()

    @guard.tool(name="fetch",
                capabilities=[Capability.network_http(domains=["a.com"], arg="url")],
                severity=Severity.LOW)
    def fetch(url):
        return f"got {url}"

    assert fetch(url="https://a.com/x") == "got https://a.com/x"
    with pytest.raises(PermissionError):
        fetch(url="https://evil.com/x")  # capability enforcement still applies


def test_wrap_passes_default_provenance():
    reg = ToolRegistry()
    agent = AgentIdentity(id="bot", allowed_capabilities=[Capability.custom("slack")])
    engine = PolicyEngine().add(
        Rule(name="prov", trigger=tool_is("send_message"),
             when=(Provenance("text") != "trusted"), effect=Effect.DENY))
    rt = AgentRuntime(registry=reg, engine=engine, default_agent=agent)
    guard = CapGuard(rt)

    @guard.tool(name="send_message", capabilities=[Capability.custom("slack")],
                severity=Severity.LOW)
    def send_message(channel, text):
        return f"posted to {channel}"

    # a guarded handle that injects an untrusted provenance default is blocked
    tainted = guard.wrap("send_message", provenance={"text": "untrusted_web"})
    with pytest.raises(PermissionError):
        tainted(channel="#x", text="anything")
    # the plain handle (trusted by default) goes through
    assert send_message(channel="#x", text="ok")


# --------------------------------------------------------------------------- #
# native bindings (framework class/decorator injected so we test the wiring)
# --------------------------------------------------------------------------- #
class _FakeStructuredTool:
    def __init__(self, func, name, description, args_schema):
        self.func, self.name, self.description, self.args_schema = func, name, description, args_schema

    @classmethod
    def from_function(cls, func, name, description, args_schema=None):
        return cls(func, name, description, args_schema)


def test_to_langchain_wraps_and_routes():
    guard, rt, echo = _guard_with_echo()
    lc = to_langchain(echo, structured_tool_cls=_FakeStructuredTool)
    assert lc.name == "echo"
    assert "Echo text" in lc.description
    assert lc.func(text="hi") == "echo:hi"          # still routed through the runtime


def test_to_openai_agents_wraps_and_routes():
    guard, rt, echo = _guard_with_echo()
    captured = {}

    def fake_function_tool(fn):
        captured["name"] = fn.__name__
        return fn

    ot = to_openai_agents(echo, function_tool=fake_function_tool)
    assert captured["name"] == "echo"
    assert ot(text="yo") == "echo:yo"


def test_to_crewai_wraps_and_routes():
    guard, rt, echo = _guard_with_echo()
    captured = {}

    def fake_tool_decorator(name):
        captured["name"] = name
        def deco(fn):
            return fn
        return deco

    ct = to_crewai(echo, tool_decorator=fake_tool_decorator)
    assert captured["name"] == "echo"
    assert ct(text="yo") == "echo:yo"


def _importable(mod: str) -> bool:
    try:
        __import__(mod)
        return True
    except Exception:  # noqa: BLE001
        return False


def test_bindings_behave_per_framework_availability():
    """Present framework => native wrap; absent framework => loud ImportError."""
    guard, rt, echo = _guard_with_echo()
    if _importable("langchain_core.tools"):
        assert to_langchain(echo).name == "echo"
    else:
        with pytest.raises(ImportError):
            to_langchain(echo)
    if _importable("agents"):
        assert to_openai_agents(echo) is not None
    else:
        with pytest.raises(ImportError):
            to_openai_agents(echo)
    if _importable("crewai.tools"):
        assert to_crewai(echo) is not None
    else:
        with pytest.raises(ImportError):
            to_crewai(echo)


@pytest.mark.skipif(not _importable("langchain_core.tools"), reason="langchain-core not installed")
def test_to_langchain_builds_real_structured_tool_that_routes_through_capguard():
    guard, rt, echo = _guard_with_echo()
    lc = to_langchain(echo)               # a real langchain_core StructuredTool
    assert lc.name == "echo"
    # the native tool's callable still goes through the CapGuard runtime
    assert "echo:hi" in str(lc.func(text="hi"))
