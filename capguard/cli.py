"""``capguard`` command-line interface.

The "5-minute adoption" surface: every shipped capability is usable without
writing Python, and every command returns a CI-meaningful exit code (0 = good,
non-zero = a security regression / failure), so the same binary drops into a
pipeline gate.

    capguard version
    capguard bench                      # scripted security benchmark (CI gate)
    capguard agentdojo                  # real AgentDojo eval (needs `pip install agentdojo`)
    capguard audit verify <file.jsonl>  # check the tamper-evident hash chain
    capguard packs list|show|lint ...   # inspect / validate policy packs
    capguard mcp-scan <tooldefs.json>   # scan MCP tool definitions for poisoning
    capguard proxy <config.json> [--check]   # run / dry-check the guarded MCP proxy
"""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path
from typing import Any, Dict, List, Optional

from . import __version__


# --------------------------------------------------------------------------- #
# helpers
# --------------------------------------------------------------------------- #
def _load_doc(path: str) -> Any:
    p = Path(path)
    text = p.read_text(encoding="utf-8")
    if p.suffix in (".yaml", ".yml"):
        import yaml  # optional
        return yaml.safe_load(text)
    return json.loads(text)


def _build_auth(auth_cfg: Optional[Dict[str, Any]], http_cfg: Dict[str, Any]):
    """Build (token_verifier, required_scopes, resource_metadata) from config."""
    if not auth_cfg:
        return None, (), None
    from .mcp_auth import HMACJWTVerifier, ProtectedResourceMetadata, StaticTokenVerifier

    audience = auth_cfg.get("audience")
    kind = auth_cfg.get("type", "jwt-hs256")
    if kind == "static":
        verifier = StaticTokenVerifier(auth_cfg.get("tokens", {}), audience=audience)
    elif kind == "jwt-hs256":
        secret = auth_cfg["secret"]
        verifier = HMACJWTVerifier(secret.encode() if isinstance(secret, str) else secret,
                                   audience=audience)
    else:
        raise ValueError(f"unknown auth type {kind!r} (use 'jwt-hs256' or 'static')")

    prm = None
    resource = auth_cfg.get("resource")
    if resource is None and http_cfg:
        resource = f"http://{http_cfg.get('host', '127.0.0.1')}:{int(http_cfg.get('port', 8080))}/"
    if resource:
        prm = ProtectedResourceMetadata(
            resource=resource,
            authorization_servers=auth_cfg.get("authorization_servers", []),
            scopes_supported=auth_cfg.get("required_scopes", []),
        )
    return verifier, tuple(auth_cfg.get("required_scopes", [])), prm


def _build_proxy_from_config(cfg: Dict[str, Any]):
    from .core import AgentIdentity
    from .mcp_guard import MCPGuard
    from .mcp_http import HttpDownstream
    from .mcp_proxy import MCPProxy, StdioDownstream
    from .packs import _compile_capability, compile_pack

    engine = compile_pack(cfg["pack"]) if cfg.get("pack") else None
    agent_cfg = cfg.get("agent", {})
    caps = [_compile_capability(c) for c in agent_cfg.get("capabilities", [])]
    agent = AgentIdentity(id=agent_cfg.get("id", "agent"), roles=agent_cfg.get("roles", []),
                          allowed_capabilities=caps)
    guard = MCPGuard(engine=engine)

    downstreams = []
    for d in cfg.get("downstreams", []):
        if "stdio" in d:
            downstreams.append(StdioDownstream(d["server_id"], d["stdio"]))
        elif "http" in d:
            downstreams.append(HttpDownstream(d["server_id"], d["http"], headers=d.get("headers")))
        else:
            raise ValueError(f"downstream {d.get('server_id')!r} needs 'stdio' or 'http'")
    return MCPProxy(guard=guard, agent=agent, downstreams=downstreams)


# --------------------------------------------------------------------------- #
# command handlers (each returns an exit code)
# --------------------------------------------------------------------------- #
def _cmd_version(_args) -> int:
    print(f"capguard {__version__}")
    return 0


def _cmd_bench(_args) -> int:
    from .bench.run_bench import main as bench_main
    return bench_main()


def _cmd_agentdojo(_args) -> int:
    from .bench.run_agentdojo import main as ad_main
    return ad_main()


def _cmd_audit_verify(args) -> int:
    from .audit import verify_file
    try:
        ok = verify_file(args.path)
    except FileNotFoundError:
        print(f"error: no such file: {args.path}", file=sys.stderr)
        return 2
    print("OK: audit chain intact" if ok else "FAIL: audit chain broken or tampered")
    return 0 if ok else 1


def _cmd_packs(args) -> int:
    from .packs import builtin_pack_names, compile_pack, load_pack
    if args.packs_cmd == "list":
        for name in builtin_pack_names():
            print(name)
        return 0
    if args.packs_cmd == "show":
        try:
            print(json.dumps(load_pack(args.name), indent=2, default=str))
        except Exception as exc:  # noqa: BLE001
            print(f"error: {exc}", file=sys.stderr)
            return 2
        return 0
    if args.packs_cmd == "lint":
        try:
            engine = compile_pack(args.name)
        except Exception as exc:  # noqa: BLE001
            print(f"FAIL: {exc}", file=sys.stderr)
            return 1
        print(f"OK: {args.name} compiled to {len(engine.rules)} rule(s)")
        return 0
    print("error: packs subcommand required (list|show|lint)", file=sys.stderr)
    return 2


def _cmd_mcp_scan(args) -> int:
    from .mcp_guard import MCPToolDef, scan_poisoning
    try:
        data = _load_doc(args.path)
    except Exception as exc:  # noqa: BLE001
        print(f"error: cannot read {args.path}: {exc}", file=sys.stderr)
        return 2
    tools = data.get("tools", data) if isinstance(data, dict) else data
    findings = []
    for t in tools:
        td = MCPToolDef(
            server_id=t.get("server_id", "?"),
            name=t["name"],
            description=t.get("description", ""),
            input_schema=t.get("inputSchema") or t.get("input_schema") or {},
        )
        for f in scan_poisoning(td):
            findings.append((td.name, f))
    if not findings:
        print(f"OK: scanned {len(tools)} tool(s), no poisoning detected")
        return 0
    for name, f in findings:
        print(f"FINDING [{f.severity.value}] {name}: {f.detail}")
    return 1


def _cmd_proxy(args) -> int:
    try:
        cfg = _load_doc(args.config)
    except FileNotFoundError:
        print(f"error: no such config: {args.config}", file=sys.stderr)
        return 2
    except Exception as exc:  # noqa: BLE001
        print(f"error: invalid config: {exc}", file=sys.stderr)
        return 2
    try:
        proxy = _build_proxy_from_config(cfg)
    except Exception as exc:  # noqa: BLE001
        print(f"error: {exc}", file=sys.stderr)
        return 2

    if args.check:
        listing = proxy.handle({"jsonrpc": "2.0", "id": 1, "method": "tools/list"})
        tools = listing["result"]["tools"]
        print(f"exposed tools ({len(tools)}):")
        for t in tools:
            print(f"  - {t['name']}")
        return 0

    transport = cfg.get("transport", "stdio")
    if transport == "http":
        from .mcp_http import MCPHttpServer
        http_cfg = cfg.get("http", {})
        verifier, scopes, prm = _build_auth(cfg.get("auth"), http_cfg)
        srv = MCPHttpServer(proxy, host=http_cfg.get("host", "127.0.0.1"),
                            port=int(http_cfg.get("port", 8080)),
                            token_verifier=verifier, required_scopes=scopes,
                            resource_metadata=prm).start()
        print(f"CapGuard MCP proxy serving on {srv.url}", file=sys.stderr)
        import time
        try:
            while True:
                time.sleep(3600)
        except KeyboardInterrupt:
            srv.stop()
        return 0
    from .mcp_proxy import StdioServer
    StdioServer(proxy).serve()
    return 0


# --------------------------------------------------------------------------- #
# parser
# --------------------------------------------------------------------------- #
def build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(prog="capguard",
                                description="Deterministic security runtime for AI agents.")
    sub = p.add_subparsers(dest="cmd")

    sub.add_parser("version", help="print the version").set_defaults(func=_cmd_version)
    sub.add_parser("bench", help="run the scripted security benchmark (CI gate)").set_defaults(func=_cmd_bench)
    sub.add_parser("agentdojo", help="run the real AgentDojo eval").set_defaults(func=_cmd_agentdojo)

    a = sub.add_parser("audit", help="audit-log tools")
    asub = a.add_subparsers(dest="audit_cmd")
    av = asub.add_parser("verify", help="verify a hash-chained audit JSONL")
    av.add_argument("path")
    av.set_defaults(func=_cmd_audit_verify)

    pk = sub.add_parser("packs", help="inspect / validate policy packs")
    pksub = pk.add_subparsers(dest="packs_cmd")
    pksub.add_parser("list", help="list builtin packs").set_defaults(func=_cmd_packs)
    sh = pksub.add_parser("show", help="print a pack (builtin name or path)")
    sh.add_argument("name")
    sh.set_defaults(func=_cmd_packs)
    ln = pksub.add_parser("lint", help="compile a pack and report rule count/errors")
    ln.add_argument("name")
    ln.set_defaults(func=_cmd_packs)

    ms = sub.add_parser("mcp-scan", help="scan MCP tool definitions for poisoning")
    ms.add_argument("path", help="JSON/YAML file: a list of tool defs or {\"tools\": [...]}")
    ms.set_defaults(func=_cmd_mcp_scan)

    px = sub.add_parser("proxy", help="run the guarded MCP proxy from a config")
    px.add_argument("config", help="JSON/YAML proxy config")
    px.add_argument("--check", action="store_true",
                    help="dry run: connect, list exposed tools, and exit")
    px.set_defaults(func=_cmd_proxy)
    return p


def main(argv: Optional[List[str]] = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)
    func = getattr(args, "func", None)
    if func is None:  # no (sub)command chosen
        parser.print_help()
        return 0
    return func(args)


if __name__ == "__main__":
    sys.exit(main())
