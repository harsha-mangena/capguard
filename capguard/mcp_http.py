"""Streamable-HTTP MCP transport — guard *remote* MCP servers, not just stdio.

The 2026 MCP CVE wave (40+ disclosures) lives mostly on the **remote** surface:
hosted MCP servers reached over HTTP, where auth gaps, path traversal and tool
poisoning compound. CapGuard's stdio proxy guarded only local subprocess
servers; this module extends the exact same enforcement to HTTP:

  * :class:`HttpDownstream` — a downstream client speaking MCP JSON-RPC over
    Streamable HTTP, so a hosted MCP server can sit *behind* the guard (its tools
    are scanned/pinned, every call enforced + audited, poisoned tools stripped).
  * :class:`MCPHttpServer` — serves the guarded :class:`~capguard.mcp_proxy.MCPProxy`
    over Streamable HTTP, so a remote MCP client (Claude Desktop, Cursor, an
    agent) connects to the guard instead of straight to the raw servers.

It is stdlib-only (``urllib`` client, ``http.server`` server) — no new
dependency — and reuses the transport-agnostic ``MCPProxy.handle`` /
``MCPGuard`` core unchanged. This implements the single-JSON-response mode of
Streamable HTTP (the common request/response path for ``tools/call``); an
``text/event-stream`` body is also parsed if a server replies with SSE.
"""

from __future__ import annotations

import json
import secrets
import threading
import urllib.request
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from typing import Any, Dict, List, Mapping, Optional, Sequence

from .mcp_proxy import MCPProxy, PROTOCOL_VERSION, jrpc_request
from .mcp_guard import MCPToolDef
from .mcp_auth import (
    ProtectedResourceMetadata,
    TokenError,
    TokenVerifier,
    WELL_KNOWN_PRM_PATH,
    extract_bearer,
    www_authenticate,
)


# --------------------------------------------------------------------------- #
# SSE helper
# --------------------------------------------------------------------------- #
def _parse_sse(body: str) -> Dict[str, Any]:
    """Pull the first JSON-RPC message out of an SSE stream body."""
    data_lines: List[str] = []
    for line in body.splitlines():
        if line.startswith("data:"):
            data_lines.append(line[len("data:"):].strip())
    payload = "\n".join(data_lines).strip()
    return json.loads(payload) if payload else {}


# --------------------------------------------------------------------------- #
# Client: guard a remote MCP server
# --------------------------------------------------------------------------- #
class HttpDownstream:
    """Downstream that speaks MCP JSON-RPC to a remote server over Streamable HTTP."""

    def __init__(
        self,
        server_id: str,
        url: str,
        *,
        headers: Optional[Mapping[str, str]] = None,
        timeout: float = 30.0,
    ) -> None:
        self.server_id = server_id
        self._url = url
        self._headers = dict(headers or {})
        self._timeout = timeout
        self._id = 0
        self._session_id: Optional[str] = None
        self._lock = threading.Lock()
        self._initialize()

    # -- low-level HTTP ---------------------------------------------------- #
    def _post(self, message: Mapping[str, Any], expect_response: bool = True) -> Dict[str, Any]:
        data = json.dumps(message).encode()
        headers = {
            "Content-Type": "application/json",
            "Accept": "application/json, text/event-stream",
            **self._headers,
        }
        if self._session_id:
            headers["Mcp-Session-Id"] = self._session_id
        req = urllib.request.Request(self._url, data=data, method="POST", headers=headers)
        with urllib.request.urlopen(req, timeout=self._timeout) as resp:
            sid = resp.headers.get("Mcp-Session-Id")
            if sid:
                self._session_id = sid
            ctype = (resp.headers.get("Content-Type") or "").lower()
            raw = resp.read().decode("utf-8")
        if not expect_response or not raw.strip():
            return {}
        if "text/event-stream" in ctype:
            return _parse_sse(raw)
        return json.loads(raw)

    def _next_id(self) -> int:
        self._id += 1
        return self._id

    def _rpc(self, method: str, params: Optional[Mapping[str, Any]] = None) -> Any:
        with self._lock:
            rid = self._next_id()
            msg = self._post(jrpc_request(rid, method, params))
        if "error" in msg:
            raise RuntimeError(f"remote MCP error: {msg['error']}")
        return msg.get("result")

    def _initialize(self) -> None:
        self._rpc("initialize", {"protocolVersion": PROTOCOL_VERSION,
                                 "clientInfo": {"name": "capguard-proxy", "version": "0.1"},
                                 "capabilities": {}})
        # initialized notification (no response expected)
        self._post({"jsonrpc": "2.0", "method": "notifications/initialized"}, expect_response=False)

    # -- Downstream protocol ---------------------------------------------- #
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


# --------------------------------------------------------------------------- #
# Server: expose the guarded proxy over HTTP
# --------------------------------------------------------------------------- #
class _ProxyHTTPRequestHandler(BaseHTTPRequestHandler):
    server_version = "CapGuardMCP/0.1"

    def log_message(self, *args: Any) -> None:  # silence default stderr logging
        pass

    def _write_json(self, code: int, payload: Optional[Dict[str, Any]], *,
                    session_id: Optional[str] = None,
                    extra_headers: Optional[Dict[str, str]] = None) -> None:
        body = json.dumps(payload).encode() if payload is not None else b""
        self.send_response(code)
        if payload is not None:
            self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(body)))
        if session_id:
            self.send_header("Mcp-Session-Id", session_id)
        for k, v in (extra_headers or {}).items():
            self.send_header(k, v)
        self.end_headers()
        if body:
            self.wfile.write(body)

    def _authorized(self) -> bool:
        """Enforce OAuth resource-server auth if a verifier is configured.

        Returns True to proceed; otherwise writes the proper 401/403 challenge
        (RFC 9728 WWW-Authenticate) and returns False.
        """
        verifier: Optional[TokenVerifier] = getattr(self.server, "auth_verifier", None)
        if verifier is None:
            return True  # auth disabled
        prm_url = getattr(self.server, "auth_prm_url", None)
        token = extract_bearer(self.headers.get("Authorization"))
        if token is None:
            self._write_json(401, {"jsonrpc": "2.0", "id": None,
                                   "error": {"code": -32001, "message": "authentication required"}},
                             extra_headers={"WWW-Authenticate": www_authenticate(resource_metadata_url=prm_url)})
            return False
        try:
            claims = verifier.verify(token)
        except TokenError as exc:
            self._write_json(401, {"jsonrpc": "2.0", "id": None,
                                   "error": {"code": -32001, "message": f"invalid token: {exc}"}},
                             extra_headers={"WWW-Authenticate": www_authenticate(
                                 resource_metadata_url=prm_url, error="invalid_token")})
            return False
        required = getattr(self.server, "auth_required_scopes", frozenset())
        if required and not required.issubset(claims.scopes):
            self._write_json(403, {"jsonrpc": "2.0", "id": None,
                                   "error": {"code": -32002, "message": "insufficient scope"}},
                             extra_headers={"WWW-Authenticate": www_authenticate(
                                 resource_metadata_url=prm_url, error="insufficient_scope",
                                 scope=" ".join(sorted(required)))})
            return False
        return True

    def do_POST(self) -> None:
        if not self._authorized():
            return
        length = int(self.headers.get("Content-Length", 0) or 0)
        raw = self.rfile.read(length) if length else b""
        try:
            message = json.loads(raw.decode("utf-8"))
        except Exception:  # noqa: BLE001
            self._write_json(400, {"jsonrpc": "2.0", "id": None,
                                   "error": {"code": -32700, "message": "parse error"}})
            return
        proxy: MCPProxy = self.server.proxy  # type: ignore[attr-defined]
        # issue a session id on initialize, for spec-friendly clients
        session_id = None
        if message.get("method") == "initialize":
            session_id = secrets.token_urlsafe(16)
        response = proxy.handle(message)
        if response is None:
            self._write_json(202, None)          # notification: accepted, no body
            return
        self._write_json(200, response, session_id=session_id)

    def do_GET(self) -> None:
        # Protected Resource Metadata (RFC 9728) is public so clients can discover auth.
        prm = getattr(self.server, "auth_prm", None)
        if prm is not None and self.path.split("?", 1)[0] == WELL_KNOWN_PRM_PATH:
            self._write_json(200, prm.to_dict())
            return
        # optional server->client SSE stream; not used in JSON-response mode
        self._write_json(405, {"jsonrpc": "2.0", "id": None,
                               "error": {"code": -32000, "message": "GET stream not supported"}})


class MCPHttpServer:
    """Serve a guarded :class:`MCPProxy` over Streamable HTTP (JSON-response mode)."""

    def __init__(self, proxy: MCPProxy, host: str = "127.0.0.1", port: int = 0, *,
                 token_verifier: Optional[TokenVerifier] = None,
                 required_scopes=(),
                 resource_metadata: Optional[ProtectedResourceMetadata] = None) -> None:
        self._httpd = ThreadingHTTPServer((host, port), _ProxyHTTPRequestHandler)
        self._httpd.proxy = proxy  # type: ignore[attr-defined]
        # OAuth resource-server config (None verifier => auth disabled)
        self._httpd.auth_verifier = token_verifier            # type: ignore[attr-defined]
        self._httpd.auth_required_scopes = frozenset(required_scopes)  # type: ignore[attr-defined]
        self._httpd.auth_prm = resource_metadata              # type: ignore[attr-defined]
        self._httpd.auth_prm_url = (                          # type: ignore[attr-defined]
            resource_metadata.resource.rstrip("/") + WELL_KNOWN_PRM_PATH
            if resource_metadata else None
        )
        self._thread: Optional[threading.Thread] = None

    @property
    def host(self) -> str:
        return self._httpd.server_address[0]

    @property
    def port(self) -> int:
        return self._httpd.server_address[1]

    @property
    def url(self) -> str:
        return f"http://{self.host}:{self.port}/"

    def start(self) -> "MCPHttpServer":
        self._thread = threading.Thread(target=self._httpd.serve_forever, daemon=True)
        self._thread.start()
        return self

    def stop(self) -> None:
        self._httpd.shutdown()
        self._httpd.server_close()

    def __enter__(self) -> "MCPHttpServer":
        return self.start()

    def __exit__(self, *exc: Any) -> None:
        self.stop()
