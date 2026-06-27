"""Tests for `capguard init` scaffolding."""

from __future__ import annotations

import json

from capguard import compile_pack, pack_capabilities
from capguard.cli import main


def test_init_writes_valid_stdio_config(tmp_path):
    out = tmp_path / "capguard.proxy.json"
    assert main(["init", "--out", str(out)]) == 0
    cfg = json.loads(out.read_text())
    assert cfg["transport"] == "stdio"
    assert cfg["pack"] == "owasp-baseline"
    assert cfg["agent"]["capabilities"] and cfg["downstreams"]
    # the scaffolded pack + capabilities actually compile
    assert compile_pack(cfg["pack"]).rules
    assert pack_capabilities({"capabilities": cfg["agent"]["capabilities"]})


def test_init_http_and_cloud(tmp_path):
    out = tmp_path / "c.json"
    assert main(["init", "--out", str(out), "--http",
                 "--cloud", "https://cp.example/v1/audit"]) == 0
    cfg = json.loads(out.read_text())
    assert cfg["transport"] == "http" and cfg["http"]["port"] == 8080
    assert cfg["auth"]["type"] == "jwt-jwks"
    assert cfg["auth"]["algorithms"] == ["RS256", "EdDSA"]
    assert cfg["auth"]["issuer_url"] == "https://your-idp.example"
    assert cfg["auth"]["discovery"] == "auto"
    assert cfg["auth"]["jwks_cache_ttl_seconds"] == 300
    assert cfg["cloud"]["url"].endswith("/v1/audit") and "local_log" in cfg["cloud"]


def test_init_refuses_overwrite_without_force(tmp_path):
    out = tmp_path / "c.json"
    out.write_text("{}")
    assert main(["init", "--out", str(out)]) == 1          # refuse
    assert main(["init", "--out", str(out), "--force"]) == 0  # ok with --force
