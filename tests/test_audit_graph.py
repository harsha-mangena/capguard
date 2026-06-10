"""Tests for forensic provenance reconstruction from the audit chain."""

from __future__ import annotations

from capguard import (
    UNTRUSTED_WEB,
    AgentIdentity,
    AgentRuntime,
    Capability,
    ProvenanceTracker,
    Severity,
    ToolRegistry,
    build_flow_graph,
    flow_graph_from_file,
    tainted_sink_calls,
)
from capguard.audit import HashChainedSink, MemorySink
from capguard.cli import main as cli_main


def _laundering_runtime(sink):
    tracker = ProvenanceTracker()
    reg = ToolRegistry()

    @reg.tool(name="web_fetch",
              capabilities=[Capability.network_http(domains=["*"], arg="url")],
              severity=Severity.LOW, output_label=UNTRUSTED_WEB)
    def web_fetch(url):
        return f"ATTACKER::{url}"

    @reg.tool(name="summarize", capabilities=[Capability.custom("nlp")], severity=Severity.LOW)
    def summarize(text):
        return f"SUMMARY[{text}]"

    @reg.tool(name="send_message", capabilities=[Capability.custom("slack")], severity=Severity.LOW)
    def send_message(channel, text):
        return f"posted to {channel}"

    agent = AgentIdentity(id="bot", allowed_capabilities=[
        Capability.network_http(domains=["*"], arg="url"),
        Capability.custom("nlp"), Capability.custom("slack")])
    return AgentRuntime(registry=reg, default_agent=agent, audit_sink=sink, tracker=tracker)


def test_reconstructs_untrusted_to_sink_flow():
    sink = MemorySink()
    rt = _laundering_runtime(sink)
    poisoned = rt.invoke_tool("web_fetch", url="https://evil.com")     # event 0 (untrusted output)
    rt.invoke_tool("send_message", channel="#x", text=poisoned)        # event 1 (sink)
    g = build_flow_graph(sink.events)
    # an edge links the fetch output to the message argument by content digest
    assert any(e.src == 0 and e.dst == 1 and e.arg == "text" for e in g.edges)
    flagged = tainted_sink_calls(g, ["send_message"])
    assert [n.tool for n in flagged] == ["send_message"]


def test_transitive_taint_through_a_transform():
    sink = MemorySink()
    rt = _laundering_runtime(sink)
    raw = rt.invoke_tool("web_fetch", url="https://evil.com")          # 0
    summ = rt.invoke_tool("summarize", text=raw)                       # 1 (taint propagates)
    rt.invoke_tool("send_message", channel="#x", text=summ)            # 2 (sink)
    g = build_flow_graph(sink.events)
    flagged = tainted_sink_calls(g, ["send_*"])
    assert any(n.index == 2 for n in flagged)


def test_clean_flow_has_no_tainted_sink():
    sink = MemorySink()
    rt = _laundering_runtime(sink)
    rt.invoke_tool("send_message", channel="#x", text="deploy done")   # trusted literal
    g = build_flow_graph(sink.events)
    assert tainted_sink_calls(g, ["send_message"]) == []


def test_file_roundtrip_and_cli(tmp_path, capsys):
    path = tmp_path / "audit.jsonl"
    rt = _laundering_runtime(HashChainedSink(path))
    poisoned = rt.invoke_tool("web_fetch", url="https://evil.com")
    rt.invoke_tool("send_message", channel="#public", text=poisoned)

    g = flow_graph_from_file(path)
    assert tainted_sink_calls(g, ["send_message"])

    # CLI: non-zero exit because an untrusted->sink path exists
    rc = cli_main(["audit", "flows", str(path), "--sinks", "send_message"])
    out = capsys.readouterr().out
    assert rc == 1
    assert "send_message" in out and "tainted sink calls: 1" in out
