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
    from .mcp_auth import (
        HMACJWTVerifier,
        JWKSVerifier,
        ProtectedResourceMetadata,
        StaticTokenVerifier,
        fetch_authorization_server_metadata,
    )

    audience = auth_cfg.get("audience")
    kind = auth_cfg.get("type")
    discovered_issuer = None
    if kind is None:
        if any(k in auth_cfg for k in (
            "jwks_url", "jwks", "public_jwk", "issuer", "issuer_url",
            "authorization_server", "metadata_url",
            "authorization_server_metadata_url", "oidc_metadata_url",
        )):
            kind = "jwt-jwks"
        elif "tokens" in auth_cfg:
            kind = "static"
        else:
            kind = "jwt-hs256"
    if kind == "static":
        verifier = StaticTokenVerifier(auth_cfg.get("tokens", {}), audience=audience)
    elif kind == "jwt-hs256":
        secret = auth_cfg["secret"]
        verifier = HMACJWTVerifier(secret.encode() if isinstance(secret, str) else secret,
                                   audience=audience)
    elif kind in ("jwt-eddsa-jwks", "jwt-rs256-jwks", "jwks", "jwt-jwks"):
        configured_algs = auth_cfg.get("algorithms")
        cache_ttl = auth_cfg.get("jwks_cache_ttl_seconds", auth_cfg.get("jwks_cache_ttl"))
        cache_ttl_seconds = None if cache_ttl is None else float(cache_ttl)
        refresh_on_kid_miss = bool(auth_cfg.get("jwks_refresh_on_kid_miss", True))
        if configured_algs is None:
            if kind == "jwt-eddsa-jwks":
                algorithms = ["EdDSA"]
            elif kind == "jwt-rs256-jwks":
                algorithms = ["RS256"]
            else:
                algorithms = ["EdDSA", "RS256"]
        elif isinstance(configured_algs, str):
            algorithms = [configured_algs]
        else:
            algorithms = list(configured_algs)
        metadata_url = (
            auth_cfg.get("metadata_url")
            or auth_cfg.get("authorization_server_metadata_url")
            or auth_cfg.get("oidc_metadata_url")
        )
        issuer = (
            auth_cfg.get("issuer")
            or auth_cfg.get("issuer_url")
            or auth_cfg.get("authorization_server")
        )
        discovery = auth_cfg.get("discovery", "auto")
        metadata = None
        if "jwks_url" in auth_cfg:
            verifier = JWKSVerifier.from_url(
                auth_cfg["jwks_url"], audience=audience,
                timeout=float(auth_cfg.get("jwks_timeout", 5.0)),
                algorithms=algorithms, cache_ttl_seconds=cache_ttl_seconds,
                refresh_on_kid_miss=refresh_on_kid_miss)
        elif metadata_url or issuer:
            metadata = fetch_authorization_server_metadata(
                issuer=issuer, metadata_url=metadata_url,
                timeout=float(auth_cfg.get("metadata_timeout", auth_cfg.get("jwks_timeout", 5.0))),
                discovery=discovery)
            verifier = JWKSVerifier.from_url(
                metadata["jwks_uri"], audience=audience,
                timeout=float(auth_cfg.get("jwks_timeout", 5.0)),
                algorithms=algorithms, cache_ttl_seconds=cache_ttl_seconds,
                refresh_on_kid_miss=refresh_on_kid_miss)
        else:
            jwks = auth_cfg.get("jwks")
            if jwks is None and "public_jwk" in auth_cfg:
                jwks = {"keys": [auth_cfg["public_jwk"]]}
            if jwks is None:
                raise ValueError("JWT JWKS auth needs 'issuer_url', 'metadata_url', 'jwks_url', 'jwks', "
                                 "or 'public_jwk'")
            verifier = JWKSVerifier(jwks, audience=audience, algorithms=algorithms)
        discovered_issuer = metadata.get("issuer") if metadata else None
    else:
        raise ValueError(
            f"unknown auth type {kind!r} (use 'jwt-jwks', 'jwt-rs256-jwks', 'jwt-eddsa-jwks', "
            "'jwt-hs256', or 'static')"
        )

    prm = None
    resource = auth_cfg.get("resource")
    if resource is None and http_cfg:
        resource = f"http://{http_cfg.get('host', '127.0.0.1')}:{int(http_cfg.get('port', 8080))}/"
    if resource:
        authorization_servers = auth_cfg.get("authorization_servers")
        if authorization_servers is None:
            issuer = auth_cfg.get("issuer") or auth_cfg.get("issuer_url") or auth_cfg.get("authorization_server")
            authorization_servers = [discovered_issuer or issuer] if (discovered_issuer or issuer) else []
        prm = ProtectedResourceMetadata(
            resource=resource,
            authorization_servers=authorization_servers,
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

    # optional: stream the audit trail to a control plane (fail-open, observe-only)
    audit_sink = None
    cloud = cfg.get("cloud")
    if cloud and cloud.get("url"):
        from .audit import HashChainedSink, HttpSink, MultiSink
        sinks = [HttpSink(
            cloud["url"], token=cloud.get("token"),
            timeout=float(cloud.get("timeout", 5.0)),
            allow_private_network=bool(cloud.get("allow_private_network", False)),
            allow_insecure_http=bool(cloud.get("allow_insecure_http", False)),
        )]
        if cloud.get("local_log"):
            sinks.insert(0, HashChainedSink(cloud["local_log"]))
        audit_sink = MultiSink(*sinks) if len(sinks) > 1 else sinks[0]

    guard = MCPGuard(engine=engine, audit_sink=audit_sink)

    downstreams = []
    for d in cfg.get("downstreams", []):
        if "stdio" in d:
            downstreams.append(StdioDownstream(d["server_id"], d["stdio"]))
        elif "http" in d:
            downstreams.append(HttpDownstream(
                d["server_id"], d["http"], headers=d.get("headers"),
                timeout=float(d.get("timeout", 30.0)),
                allow_private_network=bool(d.get("allow_private_network", False)),
                allow_insecure_http=bool(d.get("allow_insecure_http", False)),
            ))
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


def _cmd_audit_flows(args) -> int:
    from .audit_graph import _DEFAULT_SINKS, flow_graph_from_file, format_flows, tainted_sink_calls
    try:
        graph = flow_graph_from_file(args.path)
    except FileNotFoundError:
        print(f"error: no such file: {args.path}", file=sys.stderr)
        return 2
    sinks = [s.strip() for s in (args.sinks or "").split(",") if s.strip()] or _DEFAULT_SINKS
    print(format_flows(graph, sinks))
    return 1 if tainted_sink_calls(graph, sinks) else 0   # non-zero if an exfil path exists


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
        if cfg.get("transport", "stdio") == "http":
            try:
                _build_auth(cfg.get("auth"), cfg.get("http", {}))
            except Exception as exc:  # noqa: BLE001
                print(f"error: auth: {exc}", file=sys.stderr)
                return 2
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
_INIT_TEMPLATE: Dict[str, Any] = {
    "transport": "stdio",
    "pack": "owasp-baseline",
    "agent": {
        "id": "my-agent",
        "capabilities": [
            {"type": "custom", "name": "example_tool"},
            {"type": "network_http", "domains": ["api.example.com"]},
        ],
    },
    "downstreams": [{"server_id": "local", "stdio": ["python", "your_mcp_server.py"]}],
}


def _cmd_init(args) -> int:
    cfg = json.loads(json.dumps(_INIT_TEMPLATE))  # deep copy
    if args.http:
        cfg["transport"] = "http"
        cfg["http"] = {"host": "127.0.0.1", "port": 8080}
        cfg["auth"] = {
            "type": "jwt-jwks",
            "algorithms": ["RS256", "EdDSA"],
            "audience": "https://your-guard.example/mcp",
            "issuer_url": "https://your-idp.example",
            "discovery": "auto",
            "jwks_cache_ttl_seconds": 300,
            "required_scopes": ["mcp:call"],
            "authorization_servers": ["https://your-idp.example"],
        }
    if args.cloud:
        cfg["cloud"] = {"url": args.cloud, "token": "YOUR_TENANT_KEY",
                        "local_log": "capguard_audit.jsonl"}
    out = Path(args.out)
    if out.exists() and not args.force:
        print(f"refusing to overwrite {out} (use --force)", file=sys.stderr)
        return 1
    out.write_text(json.dumps(cfg, indent=2) + "\n", encoding="utf-8")
    print(f"wrote {out}\n  1. edit the downstreams / agent capabilities\n"
          f"  2. capguard proxy {out} --check     # connect, validate auth & list tools\n"
          f"  3. capguard proxy {out}             # serve")
    return 0


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
    af = asub.add_parser("flows", help="reconstruct data-flow; list untrusted->sink paths")
    af.add_argument("path")
    af.add_argument("--sinks", default="", help="comma-separated tool globs (default: common sinks)")
    af.set_defaults(func=_cmd_audit_flows)

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

    ini = sub.add_parser("init", help="scaffold a guarded-proxy config (stdio/http, optional cloud)")
    ini.add_argument("--out", default="capguard.proxy.json")
    ini.add_argument("--http", action="store_true", help="serve over HTTP + OAuth instead of stdio")
    ini.add_argument("--cloud", default="", help="control-plane audit ingest URL to stream to")
    ini.add_argument("--force", action="store_true", help="overwrite an existing file")
    ini.set_defaults(func=_cmd_init)

    px = sub.add_parser("proxy", help="run the guarded MCP proxy from a config")
    px.add_argument("config", help="JSON/YAML proxy config")
    px.add_argument("--check", action="store_true",
                    help="dry run: connect, validate HTTP auth, list exposed tools, and exit")
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
