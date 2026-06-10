"""Tests for the provenance-preserving memory guard (ASI06)."""

from __future__ import annotations

import pytest

from capguard import (
    SECRET,
    UNTRUSTED_WEB,
    AgentIdentity,
    AgentRuntime,
    Capability,
    Effect,
    MemoryPoisoningError,
    PolicyEngine,
    ProvenanceMemory,
    ProvenanceTracker,
    Rule,
    Severity,
    Taint,
    ToolRegistry,
    Trust,
    tool_is,
)


def _runtime_and_memory(mode="label"):
    tracker = ProvenanceTracker()
    reg = ToolRegistry()

    @reg.tool(name="web_fetch",
              capabilities=[Capability.network_http(domains=["*"], arg="url")],
              severity=Severity.LOW, output_label=UNTRUSTED_WEB)
    def web_fetch(url: str) -> str:
        return f"ATTACKER_NOTE::{url}"

    @reg.tool(name="send_message", capabilities=[Capability.custom("slack")],
              severity=Severity.LOW)
    def send_message(channel: str, text: str) -> str:
        return f"posted to {channel}"

    engine = PolicyEngine().add(
        Rule(name="msg-integrity", trigger=tool_is("send_message"),
             when=Taint("text").is_untrusted(), effect=Effect.DENY))
    agent = AgentIdentity(id="bot", allowed_capabilities=[
        Capability.network_http(domains=["*"], arg="url"), Capability.custom("slack")])
    rt = AgentRuntime(registry=reg, engine=engine, default_agent=agent, tracker=tracker)
    mem = ProvenanceMemory(tracker, mode=mode)
    return rt, mem, tracker


# --------------------------------------------------------------------------- #
# the laundering-via-memory hole is closed
# --------------------------------------------------------------------------- #
def test_memory_does_not_launder_taint_kv():
    rt, mem, _ = _runtime_and_memory()
    poisoned = rt.invoke_tool("web_fetch", url="https://evil.com")  # UNTRUSTED_WEB
    mem.write("note", poisoned)                                     # stored with taint
    recalled = mem.read("note")                                     # taint re-applied
    with pytest.raises(PermissionError):
        rt.invoke_tool("send_message", channel="#x", text=recalled)


def test_memory_namespace_recall_preserves_taint():
    rt, mem, _ = _runtime_and_memory()
    poisoned = rt.invoke_tool("web_fetch", url="https://evil.com")
    mem.append("inbox", poisoned)
    (recalled,) = mem.recall("inbox")
    with pytest.raises(PermissionError):
        rt.invoke_tool("send_message", channel="#x", text=recalled)


def test_memory_search_preserves_taint():
    rt, mem, _ = _runtime_and_memory()
    poisoned = rt.invoke_tool("web_fetch", url="https://evil.com/secret-plan")
    mem.append("docs", poisoned)
    hits = mem.search("docs", "ATTACKER")
    assert hits
    with pytest.raises(PermissionError):
        rt.invoke_tool("send_message", channel="#x", text=hits[0])


def test_trusted_memory_round_trips_and_is_allowed():
    rt, mem, _ = _runtime_and_memory()
    mem.write("greeting", "hello team")          # trusted (first-party literal)
    recalled = mem.read("greeting")
    assert rt.invoke_tool("send_message", channel="#x", text=recalled)  # allowed


# --------------------------------------------------------------------------- #
# deny mode + labels
# --------------------------------------------------------------------------- #
def test_deny_mode_refuses_untrusted_writes():
    rt, mem, _ = _runtime_and_memory(mode="deny")
    poisoned = rt.invoke_tool("web_fetch", url="https://evil.com")
    with pytest.raises(MemoryPoisoningError):
        mem.write("note", poisoned)
    with pytest.raises(MemoryPoisoningError):
        mem.append("ns", poisoned)


def test_deny_mode_allows_trusted_writes():
    rt, mem, _ = _runtime_and_memory(mode="deny")
    assert mem.write("ok", "first-party text").trust is Trust.TRUSTED


def test_label_of_records_provenance():
    rt, mem, _ = _runtime_and_memory()
    poisoned = rt.invoke_tool("web_fetch", url="https://evil.com")
    mem.write("n", poisoned)
    assert mem.label_of("n").trust is Trust.UNTRUSTED_WEB


def test_explicit_label_overrides():
    _, mem, tracker = _runtime_and_memory()
    mem.write("secret-doc", "board minutes", label=SECRET)
    assert mem.label_of("secret-doc").is_secret
    # reading re-applies the SECRET label to the value in the tracker
    mem.read("secret-doc")
    assert tracker.label_for("board minutes").is_secret
