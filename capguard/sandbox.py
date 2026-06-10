"""Sandboxed execution backends (ASI05: Unexpected Code Execution).

The capability layer validates *which* command/argv an agent may run; this
module controls *how* it runs. Even an allow-listed command can hang the host,
fork-bomb it, fill the disk, or phone home — so execution is delegated to a
backend that imposes resource, filesystem and (where supported) network limits.

Tiers, weakest to strongest isolation:

  * ``SubprocessBackend`` — no shell, scrubbed env, working-dir jail, POSIX
    rlimits (CPU, address space, file size, processes, no core), closed fds,
    timeout with process-group kill, output truncation. Single host, no daemon.
  * ``DockerBackend`` — ephemeral container, ``--network none`` by default,
    read-only rootfs, dropped capabilities, non-root, memory/cpu/pid limits,
    tmpfs work dir. Adds network + filesystem isolation. (gVisor/Firecracker
    would slot in here as `runtime=runsc` / a microVM variant.)
  * ``DenyBackend`` — refuses all execution (useful as a default for untrusted
    agents).

Tool authors call a backend instead of ``subprocess.run`` directly; the
``shell_tool`` / ``python_tool`` factories wire a hardened tool that ALSO
declares the matching capability, so attenuation + argument enforcement +
isolation all compose.
"""

from __future__ import annotations

import os
import shlex
import shutil
import signal
import subprocess
import sys
import time
from dataclasses import dataclass
from typing import List, Mapping, Optional, Sequence

from .core import Capability, Severity


@dataclass
class ResourceLimits:
    cpu_seconds: int = 5          # RLIMIT_CPU (wall-clock guarded separately by timeout)
    memory_mb: int = 512          # RLIMIT_AS
    max_file_mb: int = 16         # RLIMIT_FSIZE
    max_processes: int = 64       # RLIMIT_NPROC
    max_output_bytes: int = 1_000_000


@dataclass
class ExecResult:
    stdout: str = ""
    stderr: str = ""
    returncode: int = 0
    timed_out: bool = False
    killed: bool = False
    truncated: bool = False
    duration_s: float = 0.0

    @property
    def ok(self) -> bool:
        return self.returncode == 0 and not self.timed_out and not self.killed


class SandboxError(RuntimeError):
    pass


class ExecutionBackend:
    name = "abstract"

    def run(
        self,
        argv: Sequence[str],
        *,
        timeout: float = 10.0,
        cwd: Optional[str] = None,
        env: Optional[Mapping[str, str]] = None,
        stdin: Optional[str] = None,
        limits: Optional[ResourceLimits] = None,
        network: bool = False,
    ) -> ExecResult:
        raise NotImplementedError


class DenyBackend(ExecutionBackend):
    name = "deny"

    def run(self, argv, **kw) -> ExecResult:  # type: ignore[override]
        raise SandboxError("execution is disabled by policy (DenyBackend)")


def _minimal_env(extra: Optional[Mapping[str, str]]) -> dict:
    env = {"PATH": "/usr/local/bin:/usr/bin:/bin", "LC_ALL": "C", "LANG": "C"}
    if extra:
        env.update(extra)
    return env


class SubprocessBackend(ExecutionBackend):
    """Hardened single-host backend. POSIX-only rlimits; degrades gracefully
    elsewhere (still no shell, scrubbed env, timeout)."""

    name = "subprocess"

    def __init__(self, default_limits: Optional[ResourceLimits] = None) -> None:
        self._limits = default_limits or ResourceLimits()

    def _preexec(self, limits: ResourceLimits):
        if sys.platform == "win32":
            return None
        import resource

        def _apply():
            os.setsid()  # own process group, so we can kill the whole tree
            resource.setrlimit(resource.RLIMIT_CPU, (limits.cpu_seconds, limits.cpu_seconds))
            mem = limits.memory_mb * 1024 * 1024
            try:
                resource.setrlimit(resource.RLIMIT_AS, (mem, mem))
            except (ValueError, OSError):
                pass  # some platforms reject AS limits
            fsize = limits.max_file_mb * 1024 * 1024
            resource.setrlimit(resource.RLIMIT_FSIZE, (fsize, fsize))
            try:
                resource.setrlimit(resource.RLIMIT_NPROC, (limits.max_processes, limits.max_processes))
            except (ValueError, OSError):
                pass
            resource.setrlimit(resource.RLIMIT_CORE, (0, 0))

        return _apply

    def run(self, argv, *, timeout=10.0, cwd=None, env=None, stdin=None,
            limits=None, network=False) -> ExecResult:  # type: ignore[override]
        argv = list(argv)
        if not argv:
            raise SandboxError("empty argv")
        limits = limits or self._limits
        # SubprocessBackend cannot enforce network isolation on a shared host.
        # Be honest: callers needing egress control must use DockerBackend.
        t0 = time.perf_counter()
        try:
            proc = subprocess.Popen(
                argv,
                stdin=subprocess.PIPE if stdin is not None else subprocess.DEVNULL,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                text=True,
                cwd=cwd,
                env=_minimal_env(env),
                close_fds=True,
                preexec_fn=self._preexec(limits),
                start_new_session=False,  # we call setsid in preexec
            )
        except FileNotFoundError as exc:
            raise SandboxError(f"command not found: {argv[0]!r}") from exc

        res = ExecResult()
        try:
            out, err = proc.communicate(input=stdin, timeout=timeout)
        except subprocess.TimeoutExpired:
            res.timed_out = True
            self._kill_tree(proc)
            out, err = proc.communicate()
        res.returncode = proc.returncode if proc.returncode is not None else -1
        res.killed = res.returncode < 0
        res.duration_s = time.perf_counter() - t0

        cap = limits.max_output_bytes
        if out and len(out) > cap:
            out, res.truncated = out[:cap], True
        if err and len(err) > cap:
            err = err[:cap]
            res.truncated = True
        res.stdout, res.stderr = out or "", err or ""
        return res

    @staticmethod
    def _kill_tree(proc: subprocess.Popen) -> None:
        if sys.platform == "win32":
            proc.kill()
            return
        try:
            os.killpg(os.getpgid(proc.pid), signal.SIGKILL)
        except (ProcessLookupError, PermissionError):
            try:
                proc.kill()
            except Exception:  # noqa: BLE001
                pass


class DockerBackend(ExecutionBackend):
    """Ephemeral, network-isolated container per execution."""

    name = "docker"

    def __init__(self, image: str = "python:3.12-slim", user: str = "65534:65534") -> None:
        self._image = image
        self._user = user

    @staticmethod
    def available() -> bool:
        if not shutil.which("docker"):
            return False
        try:
            return subprocess.run(["docker", "info"], capture_output=True, timeout=5).returncode == 0
        except Exception:  # noqa: BLE001
            return False

    def run(self, argv, *, timeout=10.0, cwd=None, env=None, stdin=None,
            limits=None, network=False) -> ExecResult:  # type: ignore[override]
        limits = limits or ResourceLimits()
        docker_argv: List[str] = [
            "docker", "run", "--rm", "-i",
            "--network", ("bridge" if network else "none"),
            "--read-only",
            "--cap-drop", "ALL",
            "--security-opt", "no-new-privileges",
            "--pids-limit", str(limits.max_processes),
            "--memory", f"{limits.memory_mb}m",
            "--cpus", "1",
            "--user", self._user,
            "--tmpfs", "/work:rw,size=64m,mode=1777",
            "-w", "/work",
        ]
        for k, v in _minimal_env(env).items():
            docker_argv += ["-e", f"{k}={v}"]
        docker_argv += [self._image, *list(argv)]

        t0 = time.perf_counter()
        try:
            cp = subprocess.run(
                docker_argv,
                input=stdin,
                capture_output=True,
                text=True,
                timeout=timeout,
            )
        except subprocess.TimeoutExpired:
            return ExecResult(timed_out=True, duration_s=time.perf_counter() - t0)
        res = ExecResult(
            stdout=(cp.stdout or "")[: limits.max_output_bytes],
            stderr=(cp.stderr or "")[: limits.max_output_bytes],
            returncode=cp.returncode,
            killed=cp.returncode < 0,
            duration_s=time.perf_counter() - t0,
        )
        return res


# --------------------------------------------------------------------------- #
# Sandboxed tool factories — capability + isolation in one call.
# --------------------------------------------------------------------------- #
def shell_tool(
    registry,
    *,
    name: str = "shell",
    allowlist: Sequence[str],
    timeout: int = 10,
    backend: Optional[ExecutionBackend] = None,
    severity: Severity = Severity.HIGH,
    limits: Optional[ResourceLimits] = None,
):
    """Register a shell tool that is BOTH capability-gated and sandboxed."""
    be = backend or SubprocessBackend()

    @registry.tool(
        name=name,
        capabilities=[Capability.shell_exec(timeout=timeout, allowlist=list(allowlist), arg="cmd")],
        severity=severity,
        description=f"Run an allow-listed shell command ({', '.join(allowlist)}) in a sandbox.",
    )
    def _shell(cmd: str) -> str:
        # capability.enforce has already blocked metachars + non-allowlisted argv0
        res = be.run(shlex.split(cmd), timeout=timeout, limits=limits)
        if res.timed_out:
            raise TimeoutError(f"command timed out after {timeout}s")
        if not res.ok:
            raise SandboxError(f"command failed (rc={res.returncode}): {res.stderr[:200]}")
        return res.stdout

    return _shell


def python_tool(
    registry,
    *,
    name: str = "run_python",
    timeout: int = 10,
    backend: Optional[ExecutionBackend] = None,
    severity: Severity = Severity.HIGH,
    limits: Optional[ResourceLimits] = None,
):
    """Register a code-execution tool that runs inside a sandbox.

    Defaults to HIGH severity so it requires human approval unless the deploying
    policy explicitly raises the auto-allow ceiling — code execution should be
    reviewed by default.
    """
    be = backend or SubprocessBackend()

    @registry.tool(
        name=name,
        capabilities=[Capability.custom("exec_code", lang="python")],
        severity=severity,
        description="Execute a short Python snippet inside a resource-limited sandbox.",
    )
    def _py(code: str) -> str:
        res = be.run([sys.executable, "-I", "-c", code], timeout=timeout, limits=limits)
        if res.timed_out:
            raise TimeoutError(f"code timed out after {timeout}s")
        if not res.ok:
            raise SandboxError(f"code failed (rc={res.returncode}): {res.stderr[:200]}")
        return res.stdout

    return _py
