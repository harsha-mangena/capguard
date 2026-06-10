"""Tests for the provenance propagation engine (P1) — the information-flow moat.

Two things are proven here:
  1. The label lattice is a well-formed algebra (commutative/associative/
     idempotent join; trust takes the min, confidentiality the max).
  2. Taint *propagates across tool boundaries*: a value pulled from an untrusted
     source and laundered through a tool is still blocked at a downstream sink,
     with NO manual tagging at the sink call site. This is the capability the
     old per-call provenance could not provide.
"""

from __future__ import annotations

import pytest

from capguard import (
    SECRET,
    UNTRUSTED_WEB,
    AgentIdentity,
    AgentRuntime,
    Capability,
    Confidentiality,
    Effect,
    Flow,
    Label,
    Policy,
    PolicyEngine,
    Provenance,
    ProvenanceTracker,
    Rule,
    Severity,
    Taint,
    ToolRegistry,
    Trust,
    combine_all,
    tool_is,
)
from capguard.audit import MemorySink


# --------------------------------------------------------------------------- #
# 1. Lattice algebra
# --------------------------------------------------------------------------- #
def test_combine_takes_min_trust_max_confidentiality():
    a = Label(Trust.TRUSTED, Confidentiality.SECRET)
    b = Label(Trust.UNTRUSTED_WEB, Confidentiality.PUBLIC)
    c = a.combine(b)
    assert c.trust is Trust.UNTRUSTED_WEB          # tainted wins (integrity)
    assert c.confidentiality is Confidentiality.SECRET  # secret wins (confidentiality)


def test_combine_is_commutative_associative_idempotent():
    a = Label(Trust.UNTRUSTED_TOOL, Confidentiality.INTERNAL, frozenset({"x"}))
    b = Label(Trust.TRUSTED, Confidentiality.SECRET, frozenset({"y"}))
    d = Label(Trust.UNTRUSTED_WEB, Confidentiality.PUBLIC, frozenset({"z"}))
    assert a.combine(b) == b.combine(a)                       # commutative
    assert a.combine(b).combine(d) == a.combine(b.combine(d)) # associative
    assert a.combine(a) == a                                   # idempotent


def test_default_label_is_identity_element():
    a = Label(Trust.UNTRUSTED_WEB, Confidentiality.SECRET)
    assert Label().combine(a) == a
    assert combine_all([]) == Label()
    assert combine_all([a, Label(), Label()]) == a


def test_source_cannot_launder_a_tainted_input_clean():
    tainted = Label(Trust.UNTRUSTED_WEB)
    # even a 'trusted' source label can only narrow, never raise trust
    assert tainted.downgrade_to(Label(Trust.TRUSTED)).trust is Trust.UNTRUSTED_WEB


# --------------------------------------------------------------------------- #
# 2. Tracker propagation
# --------------------------------------------------------------------------- #
def test_tracker_propagates_source_label_to_output():
    t = ProvenanceTracker()
    out = t.record_output("CONTENT", inputs=["https://evil.com"], source=UNTRUSTED_WEB)
    assert out.trust is Trust.UNTRUSTED_WEB
    assert t.label_for("CONTENT").trust is Trust.UNTRUSTED_WEB


def test_tracker_merges_to_most_restrictive_on_collision():
    t = ProvenanceTracker()
    t.observe("dup", Label(Trust.TRUSTED, Confidentiality.SECRET))
    t.observe("dup", Label(Trust.UNTRUSTED_WEB, Confidentiality.PUBLIC))
    lbl = t.label_for("dup")
    assert lbl.trust is Trust.UNTRUSTED_WEB
    assert lbl.confidentiality is Confidentiality.SECRET


# --------------------------------------------------------------------------- #
# helpers for the end-to-end runtime tests
# --------------------------------------------------------------------------- #
def _build_runtime(tracker):
    reg = ToolRegistry()

    @reg.tool(name="web_fetch",
              capabilities=[Capability.network_http(domains=["*"], arg="url")],
              severity=Severity.LOW, output_label=UNTRUSTED_WEB)
    def web_fetch(url: str) -> str:
        return f"ATTACKER_CONTENT::{url}"

    @reg.tool(name="read_secret",
              capabilities=[Capability.custom("read_secret")],
              severity=Severity.LOW, output_label=SECRET)
    def read_secret(name: str) -> str:
        return "sk-LIVE-DEADBEEF"

    @reg.tool(name="send_message",
              capabilities=[Capability.custom("slack")], severity=Severity.LOW)
    def send_message(channel: str, text: str) -> str:
        return f"posted to {channel}: {text}"

    engine = PolicyEngine()
    # integrity rule: a message body derived from non-trusted data is denied
    engine.add(Rule(name="msg-integrity", trigger=tool_is("send_message"),
                    when=Taint("text").is_untrusted(), effect=Effect.DENY,
                    reason="message body derived from untrusted data"))
    # confidentiality rule: no secret may flow into the messaging sink
    engine.add(Rule(name="msg-confidentiality", trigger=tool_is("send_message"),
                    when=Flow.any_secret(), effect=Effect.DENY,
                    reason="secret data must not reach a messaging sink"))

    agent = AgentIdentity(id="bot", allowed_capabilities=[
        Capability.network_http(domains=["*"], arg="url"),
        Capability.custom("read_secret"),
        Capability.custom("slack"),
    ])
    rt = AgentRuntime(registry=reg, policy=Policy(max_auto_allow_severity=Severity.MEDIUM),
                      engine=engine, audit_sink=MemorySink(), default_agent=agent,
                      tracker=tracker)
    return rt


def test_laundered_untrusted_value_is_blocked_at_downstream_sink():
    """The headline result: taint survives a hop with no tagging at the sink."""
    tracker = ProvenanceTracker()
    rt = _build_runtime(tracker)

    # 1. benign: a trusted, first-party message goes through
    assert rt.invoke_tool("send_message", channel="#team", text="deploy done")

    # 2. attacker content is fetched from the web (auto-labeled UNTRUSTED_WEB)
    poisoned = rt.invoke_tool("web_fetch", url="https://evil.com/payload")

    # 3. the agent is tricked into forwarding it — note: NO provenance tagging here
    with pytest.raises(PermissionError):
        rt.invoke_tool("send_message", channel="#public", text=poisoned)


def test_secret_cannot_flow_to_sink_via_confidentiality_label():
    tracker = ProvenanceTracker()
    rt = _build_runtime(tracker)
    secret = rt.invoke_tool("read_secret", name="OPENAI_API_KEY")  # labeled SECRET
    with pytest.raises(PermissionError):
        rt.invoke_tool("send_message", channel="#public", text=secret)


def test_taint_predicate_reads_propagated_label():
    tracker = ProvenanceTracker()
    rt = _build_runtime(tracker)
    poisoned = rt.invoke_tool("web_fetch", url="https://evil.com")
    # a clean, trusted literal still passes the integrity rule
    assert rt.invoke_tool("send_message", channel="#team", text="hello")
    # the laundered value does not
    with pytest.raises(PermissionError):
        rt.invoke_tool("send_message", channel="#team", text=poisoned)


# --------------------------------------------------------------------------- #
# 3. Backward compatibility
# --------------------------------------------------------------------------- #
def test_runtime_without_tracker_is_unchanged():
    """No tracker => behaves exactly like pre-P1: explicit provenance still works."""
    reg = ToolRegistry()

    @reg.tool(name="send_message", capabilities=[Capability.custom("slack")],
              severity=Severity.LOW)
    def send_message(channel: str, text: str) -> str:
        return f"posted to {channel}"

    engine = PolicyEngine().add(
        Rule(name="prov", trigger=tool_is("send_message"),
             when=(Provenance("text") != "trusted"), effect=Effect.DENY))
    agent = AgentIdentity(id="bot", allowed_capabilities=[Capability.custom("slack")])
    rt = AgentRuntime(registry=reg, engine=engine, default_agent=agent)  # no tracker

    assert rt.invoke_tool("send_message", channel="#t", text="ok",
                          provenance={"text": "trusted"})
    with pytest.raises(PermissionError):
        rt.invoke_tool("send_message", channel="#t", text="evil",
                       provenance={"text": "untrusted_web"})


def test_explicit_call_site_label_cannot_relabel_tracked_taint_clean():
    """A call site claiming 'trusted' cannot override a value the tracker tainted."""
    tracker = ProvenanceTracker()
    rt = _build_runtime(tracker)
    poisoned = rt.invoke_tool("web_fetch", url="https://evil.com")
    with pytest.raises(PermissionError):
        rt.invoke_tool("send_message", channel="#x", text=poisoned,
                       provenance={"text": "trusted"})  # attempt to launder
