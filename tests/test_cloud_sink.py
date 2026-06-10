"""Tests for cloud audit ingest: MultiSink + HttpSink (Phase 2, slice 1).

Proves the control-plane principle: events stream to the cloud and verify
server-side, but the local gate is the source of truth — if the cloud is down,
enforcement is unaffected (HttpSink is fail-open).
"""

from __future__ import annotations

import threading
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

from capguard import (
    AgentIdentity,
    AgentRuntime,
    AuditEvent,
    Capability,
    HashChainedSink,
    HttpSink,
    MemorySink,
    MultiSink,
    Severity,
    ToolRegistry,
    ToolSpec,
    verify_chain,
)
from capguard.core import PolicyDecision

_RECEIVED = []


class _IngestHandler(BaseHTTPRequestHandler):
    def log_message(self, *a):
        pass

    def do_POST(self):
        n = int(self.headers.get("Content-Length", 0) or 0)
        body = self.rfile.read(n)
        _RECEIVED.append((self.headers.get("Authorization"), AuditEvent.model_validate_json(body)))
        self.send_response(202)
        self.send_header("Content-Length", "0")
        self.end_headers()


def _server():
    _RECEIVED.clear()
    httpd = ThreadingHTTPServer(("127.0.0.1", 0), _IngestHandler)
    threading.Thread(target=httpd.serve_forever, daemon=True).start()
    return httpd, f"http://127.0.0.1:{httpd.server_address[1]}/v1/audit"


def test_httpsink_streams_and_verifies_server_side():
    httpd, url = _server()
    try:
        sink = HttpSink(url, token="tenant-key")
        for i in range(5):
            sink(AuditEvent(agent_id="a", tool_name=f"t{i}", decision=PolicyDecision.ALLOW))
        # server received all events, with the bearer token, and the chain verifies
        assert len(_RECEIVED) == 5
        assert all(auth == "Bearer tenant-key" for auth, _ in _RECEIVED)
        assert verify_chain([ev for _, ev in _RECEIVED])
        assert sink.dropped == 0
    finally:
        httpd.shutdown(); httpd.server_close()


def test_multisink_local_and_cloud_both_verify_independently():
    httpd, url = _server()
    try:
        local = MemorySink()
        sink = MultiSink(local, HttpSink(url))
        for i in range(4):
            sink(AuditEvent(agent_id="a", tool_name=f"t{i}", decision=PolicyDecision.ALLOW))
        assert len(local.events) == 4 and verify_chain(local.events)        # local chain
        assert len(_RECEIVED) == 4 and verify_chain([e for _, e in _RECEIVED])  # cloud chain
    finally:
        httpd.shutdown(); httpd.server_close()


def test_cloud_down_does_not_break_enforcement():
    """HttpSink is fail-open: a dead cloud endpoint never blocks the local guard."""
    local = MemorySink()
    dead = HttpSink("http://127.0.0.1:9/v1/audit", timeout=0.2)  # nothing listening
    reg = ToolRegistry()
    reg.register(ToolSpec(name="echo", capabilities=[Capability.custom("echo")],
                          severity=Severity.LOW), lambda **k: "ok")
    agent = AgentIdentity(id="bot", allowed_capabilities=[Capability.custom("echo")])
    rt = AgentRuntime(registry=reg, default_agent=agent, audit_sink=MultiSink(local, dead))

    assert rt.invoke_tool("echo", text="hi") == "ok"     # enforcement unaffected
    assert len(local.events) == 1 and verify_chain(local.events)
    assert dead.dropped == 1                              # cloud post failed, swallowed


def test_local_sink_remains_source_of_truth_with_file(tmp_path):
    httpd, url = _server()
    try:
        path = tmp_path / "audit.jsonl"
        sink = MultiSink(HashChainedSink(path), HttpSink(url))
        for i in range(3):
            sink(AuditEvent(agent_id="a", tool_name=f"t{i}", decision=PolicyDecision.ALLOW))
        from capguard import verify_file
        assert verify_file(path)                          # local file chain intact
        assert len(_RECEIVED) == 3                         # cloud mirror received them
    finally:
        httpd.shutdown(); httpd.server_close()
