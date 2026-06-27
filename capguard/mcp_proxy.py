"""Runnable MCP security proxy.

The proxy speaks MCP (JSON-RPC 2.0) to a client on one side and to one or more
downstream MCP servers on the other. Every tool the downstreams expose is run
through :class:`MCPGuard` (scan + pin), and every ``tools/call`` is routed
through the enforcement runtime (capabilities + policy DSL + provenance +
approval + hash-chained audit).

Two defenses operate at different points:

  * ``tools/list`` — quarantined tools (poisoned descriptions, rug-pulled,
    shadowed) are **stripped from the list before it reaches the client/model**.
    The model never sees the malicious description, so it cannot be injected by
    it. This is prevention at the source, not just at call time.
  * ``tools/call`` — even for a listed tool, the call is enforced; a blocked or
    approval-gated call returns an MCP tool error (fail-closed), never executes.

The protocol layer is implemented directly (no heavy SDK dependency) and kept
transport-agnostic: an in-process downstream backs tests/demos, a stdio
downstream spawns a real subprocess MCP server, and ``StdioServer`` exposes the
proxy itself over stdio so a client like Claude Desktop can connect to it.
"""

from __future__ import annotations

import json
import subprocess
import sys
import threading
from typing import Any, Callable, Dict, List, Mapping, Optional, Protocol, Sequence, TextIO

from .core import AgentIdentity, ApprovalRequired, CapabilityViolation
from .identity import IdentityError, IdentityVerifier, SignedIdentity
from .mcp_guard import MCPGuard, MCPSecurityError, MCPToolDef

PROTOCOL_VERSION = "2025-11-25"


# --------------------------------------------------------------------------- #
# JSON-RPC 2.0 helpers
# --------------------------------------------------------------------------- #
def jrpc_result(req_id: Any, result: Any) -> Dict[str, Any]:
    return {"jsonrpc": "2.0", "id": req_id, "result": result}


def jrpc_error(req_id: Any, code: int, message: str, data: Any = None) -> Dict[str, Any]:
    err: Dict[str, Any] = {"code": code, "message": message}
    if data is not None:
        err["data"] = data
    return {"jsonrpc": "2.0", "id": req_id, "error": err}


def jrpc_request(req_id: Any, method: str, params: Optional[Mapping[str, Any]] = None) -> Dict[str, Any]:
    msg: Dict[str, Any] = {"jsonrpc": "2.0", "id": req_id, "method": method}
    if params is not None:
        msg["params"] = dict(params)
    return msg


# --------------------------------------------------------------------------- #
# Downstream clients
# --------------------------------------------------------------------------- #
class Downstream(Protocol):
    server_id: str

    def list_tools(self) -> List[MCPToolDef]: ...
    def call_tool(self, name: str, arguments: Mapping[str, Any]) -> Any: ...


class InProcessDownstream:
    """Downstream backed by in-process tool defs + Python handlers (tests/demos)."""

    def __init__(
        self,
        server_id: str,
        tools: Sequence[MCPToolDef],
        handlers: Mapping[str, Callable[..., Any]],
    ) -> None:
        self.server_id = server_id
        self._tools = list(tools)
        self._handlers = dict(handlers)

    def set_tools(self, tools: Sequence[MCPToolDef]) -> None:  # simulate a rug pull
        self._tools = list(tools)

    def list_tools(self) -> List[MCPToolDef]:
        return list(self._tools)

    def call_tool(self, name: str, arguments: Mapping[str, Any]) -> Any:
        return self._handlers[name](**dict(arguments))


class StdioDownstream:
    """Downstream that spawns a real subprocess MCP server and speaks JSON-RPC
    over its stdin/stdout (newline-delimited)."""

    def __init__(self, server_id: str, command: Sequence[str]) -> None:
        self.server_id = server_id
        self._proc = subprocess.Popen(
            list(command),
            stdin=subprocess.PIPE,
            stdout=subprocess.PIPE,
            text=True,
            bufsize=1,
        )
        self._id = 0
        self._lock = threading.Lock()
        self._initialize()

    def _next_id(self) -> int:
        self._id += 1
        return self._id

    def _send(self, msg: Mapping[str, Any]) -> None:
        assert self._proc.stdin is not None
        self._proc.stdin.write(json.dumps(msg) + "\n")
        self._proc.stdin.flush()

    def _recv_for(self, req_id: Any) -> Dict[str, Any]:
        assert self._proc.stdout is not None
        for _ in range(1000):
            line = self._proc.stdout.readline()
            if not line:
                raise RuntimeError("downstream closed the connection")
            msg = json.loads(line)
            if msg.get("id") == req_id:
                return msg
        raise RuntimeError("no matching response from downstream")

    def _rpc(self, method: str, params: Optional[Mapping[str, Any]] = None) -> Any:
        with self._lock:
            rid = self._next_id()
            self._send(jrpc_request(rid, method, params))
            msg = self._recv_for(rid)
        if "error" in msg:
            raise RuntimeError(f"downstream error: {msg['error']}")
        return msg.get("result")

    def _initialize(self) -> None:
        self._rpc("initialize", {"protocolVersion": PROTOCOL_VERSION,
                                 "clientInfo": {"name": "capguard-proxy", "version": "0.1"},
                                 "capabilities": {}})
        self._send({"jsonrpc": "2.0", "method": "notifications/initialized"})

    def list_tools(self) -> List[MCPToolDef]:
        result = self._rpc("tools/list") or {}
        out: List[MCPToolDef] = []
        for t in result.get("tools", []):
            out.append(MCPToolDef(
                server_id=self.server_id,
                name=t["name"],
                description=t.get("description", ""),
                input_schema=t.get("inputSchema", {}),
            ))
        return out

    def call_tool(self, name: str, arguments: Mapping[str, Any]) -> Any:
        return self._rpc("tools/call", {"name": name, "arguments": dict(arguments)})

    def close(self) -> None:
        try:
            if self._proc.stdin:
                self._proc.stdin.close()
            self._proc.terminate()
        except Exception:  # noqa: BLE001
            pass


# --------------------------------------------------------------------------- #
# The proxy
# --------------------------------------------------------------------------- #
def _expose_name(server_id: str, name: str) -> str:
    return f"{server_id}__{name}"


class MCPProxy:
    def __init__(
        self,
        *,
        guard: MCPGuard,
        agent: AgentIdentity,
        downstreams: Sequence[Downstream],
        server_name: str = "capguard-proxy",
        default_provenance: Optional[Dict[str, Dict[str, str]]] = None,
        identity_verifier: Optional[IdentityVerifier] = None,
        require_signed_identity: bool = False,
    ) -> None:
        self._guard = guard
        self._agent = agent
        self._downstreams = {d.server_id: d for d in downstreams}
        self._server_name = server_name
        self._default_provenance = default_provenance or {}
        # ASI03: when a verifier is configured, the caller's identity is taken
        # from a signed assertion in the call params, not the (self-asserted)
        # default agent. With require_signed_identity, an unsigned call is denied.
        self._identity_verifier = identity_verifier
        self._require_signed_identity = require_signed_identity
        # exposed_name -> (server_id, original_name)
        self._name_map: Dict[str, tuple[str, str]] = {}
        self.refresh()

    # -- discovery --------------------------------------------------------- #
    def refresh(self) -> None:
        """(Re)discover downstream tools and re-run scan/pin. Catches rug pulls
        that happen after the initial connection."""
        self._name_map.clear()
        for server_id, ds in self._downstreams.items():
            tools = ds.list_tools()
            self._guard.register_server(server_id, tools, lambda n, a, _d=ds: _d.call_tool(n, a))
            for td in tools:
                if self._guard.is_callable(server_id, td.name):
                    self._name_map[_expose_name(server_id, td.name)] = (server_id, td.name)

    def _exposed_tools(self) -> List[Dict[str, Any]]:
        tools: List[Dict[str, Any]] = []
        for exposed, (server_id, name) in self._name_map.items():
            td = self._guard._defs.get(f"{server_id}::{name}")  # internal read, deliberate
            tools.append({
                "name": exposed,
                "description": (td.description if td else ""),
                "inputSchema": (dict(td.input_schema) if td else {}),
            })
        return tools

    # -- JSON-RPC dispatch ------------------------------------------------- #
    def handle(self, message: Mapping[str, Any]) -> Optional[Dict[str, Any]]:
        method = message.get("method")
        req_id = message.get("id")

        # notifications carry no id and expect no response
        if req_id is None and method and method.startswith("notifications/"):
            return None

        if method == "initialize":
            return jrpc_result(req_id, {
                "protocolVersion": PROTOCOL_VERSION,
                "serverInfo": {"name": self._server_name, "version": "0.1.0"},
                "capabilities": {"tools": {"listChanged": True}},
            })

        if method == "tools/list":
            return jrpc_result(req_id, {"tools": self._exposed_tools()})

        if method == "tools/call":
            return self._handle_call(req_id, message.get("params") or {})

        if method in ("ping",):
            return jrpc_result(req_id, {})

        return jrpc_error(req_id, -32601, f"method not found: {method}")

    def _tool_error(self, req_id: Any, text: str) -> Dict[str, Any]:
        # MCP convention: tool-level failures come back as a result with isError
        return jrpc_result(req_id, {"content": [{"type": "text", "text": text}], "isError": True})

    def _handle_call(self, req_id: Any, params: Mapping[str, Any]) -> Dict[str, Any]:
        exposed = params.get("name", "")
        arguments = params.get("arguments", {}) or {}
        approval_token = params.get("_capguard_approval_token")

        mapping = self._name_map.get(exposed)
        if mapping is None:
            # not listed -> either unknown or quarantined; fail closed
            return self._tool_error(req_id, f"tool {exposed!r} is not available (unknown or quarantined by CapGuard)")
        server_id, name = mapping
        provenance = self._default_provenance.get(exposed, {})

        # resolve the caller identity (signed assertion overrides the default)
        agent = self._agent
        if self._identity_verifier is not None:
            ident = params.get("_capguard_identity")
            if ident is None:
                if self._require_signed_identity:
                    return self._tool_error(req_id, "BLOCKED by CapGuard: a signed identity is required")
            else:
                try:
                    agent = self._identity_verifier.verify(SignedIdentity.from_dict(ident))
                except (IdentityError, KeyError, ValueError, TypeError) as exc:
                    return self._tool_error(req_id, f"BLOCKED by CapGuard: identity verification failed ({exc})")

        try:
            result = self._guard.guard_call(
                server_id, name, arguments,
                agent=agent, provenance=provenance, approval_token=approval_token,
            )
        except ApprovalRequired as exc:
            return self._tool_error(
                req_id, f"BLOCKED: human approval required for {exposed!r} (approval id: {exc.token_id}). {exc.reason}"
            )
        except (MCPSecurityError, CapabilityViolation, PermissionError) as exc:
            return self._tool_error(req_id, f"BLOCKED by CapGuard policy: {exc}")

        # normalize a downstream result into MCP content
        if isinstance(result, dict) and "content" in result:
            return jrpc_result(req_id, result)
        return jrpc_result(req_id, {"content": [{"type": "text", "text": str(result)}], "isError": False})


# --------------------------------------------------------------------------- #
# Stdio server loop (the proxy as something a client connects to)
# --------------------------------------------------------------------------- #
class StdioServer:
    def __init__(self, proxy: MCPProxy) -> None:
        self._proxy = proxy

    def serve(self, stdin: TextIO | None = None, stdout: TextIO | None = None) -> None:
        stdin = stdin or sys.stdin
        stdout = stdout or sys.stdout
        for line in stdin:
            line = line.strip()
            if not line:
                continue
            try:
                message = json.loads(line)
            except json.JSONDecodeError:
                stdout.write(json.dumps(jrpc_error(None, -32700, "parse error")) + "\n")
                stdout.flush()
                continue
            response = self._proxy.handle(message)
            if response is not None:
                stdout.write(json.dumps(response) + "\n")
                stdout.flush()
