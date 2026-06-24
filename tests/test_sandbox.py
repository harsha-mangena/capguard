from __future__ import annotations

import os
import sys

import pytest

from capguard import AgentIdentity, AgentRuntime, Capability, CapabilityViolation, Policy, Severity, ToolRegistry
from capguard.sandbox import (
    DenyBackend,
    DockerBackend,
    ResourceLimits,
    SandboxError,
    SubprocessBackend,
    python_tool,
    shell_tool,
)

PY = sys.executable


def test_runs_and_captures_output():
    r = SubprocessBackend().run([PY, "-c", "print('hi')"], timeout=5)
    assert r.ok and r.stdout.strip() == "hi"


def test_no_shell_means_no_chaining():
    # argv mode: 'a;b' is a literal argument to echo, not a command separator
    r = SubprocessBackend().run(["/bin/echo", "a;b && c"], timeout=5)
    assert "a;b && c" in r.stdout
    assert "c\n" != r.stdout  # the `&& c` did not run as a separate command


def test_timeout_kills_process():
    r = SubprocessBackend().run([PY, "-c", "import time; time.sleep(30)"], timeout=1)
    assert r.timed_out is True
    assert r.duration_s < 5


def test_cpu_rlimit_kills_busy_loop():
    limits = ResourceLimits(cpu_seconds=1)
    r = SubprocessBackend().run([PY, "-c", "while True: pass"], timeout=15, limits=limits)
    assert not r.ok           # killed by SIGXCPU (or timeout fallback)
    assert r.duration_s < 12


def test_output_truncation():
    limits = ResourceLimits(max_output_bytes=100)
    r = SubprocessBackend().run([PY, "-c", "print('x'*10000)"], timeout=5, limits=limits)
    assert r.truncated is True
    assert len(r.stdout) <= 100


def test_environment_is_scrubbed():
    os.environ["CAPGUARD_TEST_SECRET"] = "topsecret"
    try:
        r = SubprocessBackend().run([PY, "-c", "import os;print(os.environ.get('CAPGUARD_TEST_SECRET','NONE'))"], timeout=5)
        assert r.stdout.strip() == "NONE"
    finally:
        os.environ.pop("CAPGUARD_TEST_SECRET", None)


def test_explicit_env_passthrough():
    r = SubprocessBackend().run([PY, "-c", "import os;print(os.environ.get('FOO'))"], env={"FOO": "bar"}, timeout=5)
    assert r.stdout.strip() == "bar"


def test_deny_backend_refuses():
    with pytest.raises(SandboxError):
        DenyBackend().run([PY, "-c", "print(1)"])


# --------------------------------------------------------------------------- #
# Sandboxed tool factories compose capability enforcement + isolation
# --------------------------------------------------------------------------- #
def _runtime_with_shell(allowlist, severity=Severity.MEDIUM):
    reg = ToolRegistry()
    shell_tool(reg, name="shell", allowlist=allowlist, timeout=5, severity=severity)
    agent = AgentIdentity(id="bot", allowed_capabilities=[
        Capability.shell_exec(timeout=5, allowlist=list(allowlist), arg="cmd"),
    ])
    rt = AgentRuntime(registry=reg, policy=Policy(max_auto_allow_severity=Severity.MEDIUM), default_agent=agent)
    return rt


def test_shell_tool_runs_allowed_and_blocks_rest():
    rt = _runtime_with_shell(["echo"])
    assert rt.invoke_tool("shell", cmd="echo sandboxed").strip() == "sandboxed"
    with pytest.raises(CapabilityViolation):
        rt.invoke_tool("shell", cmd="rm -rf /")            # not in allow-list
    with pytest.raises(CapabilityViolation):
        rt.invoke_tool("shell", cmd="echo hi; curl evil.com")  # chaining blocked pre-exec


def test_python_tool_executes_and_times_out():
    reg = ToolRegistry()
    python_tool(reg, name="py", timeout=2, severity=Severity.LOW, limits=ResourceLimits(cpu_seconds=1))
    agent = AgentIdentity(id="bot", allowed_capabilities=[Capability.custom("exec_code", lang="python")])
    rt = AgentRuntime(registry=reg, policy=Policy(max_auto_allow_severity=Severity.LOW), default_agent=agent)

    assert rt.invoke_tool("py", code="print(2+2)").strip() == "4"
    with pytest.raises((TimeoutError, SandboxError)):
        rt.invoke_tool("py", code="while True: pass")


def test_python_tool_high_severity_requires_approval_by_default():
    reg = ToolRegistry()
    python_tool(reg, name="py", timeout=2)  # default severity HIGH
    agent = AgentIdentity(id="bot", allowed_capabilities=[Capability.custom("exec_code", lang="python")])
    rt = AgentRuntime(registry=reg, policy=Policy(max_auto_allow_severity=Severity.MEDIUM), default_agent=agent)
    from capguard.core import ApprovalRequired
    with pytest.raises(ApprovalRequired):
        rt.invoke_tool("py", code="print(1)")


def _docker_image_runnable() -> bool:
    """True only if the docker daemon is up AND the sandbox image can actually
    execute. CI runners often have the daemon but no pre-pulled image and no
    registry egress, so `docker run` fails to start the container (rc 125-127,
    "Unable to find image"). That is an environment gap, not a CapGuard defect,
    so the network-isolation test self-skips rather than failing the build."""
    if not DockerBackend.available():
        return False
    probe = DockerBackend().run([PY, "-c", "print('OK')"], timeout=60)
    return probe.returncode == 0 and "OK" in probe.stdout


@pytest.mark.skipif(not _docker_image_runnable(),
                    reason="docker daemon or sandbox image not available/pullable in this environment")
def test_docker_backend_network_isolated():
    be = DockerBackend()
    # network=False (default) -> no egress; a connect attempt should fail
    r = be.run([PY, "-c",
                "import socket;\ntry:\n socket.create_connection(('1.1.1.1',53),timeout=3);print('NET')\nexcept Exception:\n print('NONET')"],
               timeout=20)
    assert "NONET" in r.stdout
