"""Tests for signed policy push (Phase 2, slice 3)."""

from __future__ import annotations

import pytest

from capguard import (
    AgentIdentity,
    AgentRuntime,
    Capability,
    Effect,
    HMACSigner,
    PolicyClient,
    PolicySyncError,
    ProvenanceTracker,
    Severity,
    ToolRegistry,
    ToolSpec,
    sign_pack,
)
from capguard.policy_dsl import CallContext

FINANCE_PACK = {
    "rules": [
        {"name": "untrusted-recipient", "tools": ["transfer"],
         "when": {"provenance": "recipient", "is": "untrusted"}, "effect": "deny"},
    ]
}


def test_sign_and_client_fetch_compiles_engine():
    signer = HMACSigner(b"tenant-secret")
    sp = sign_pack(signer, FINANCE_PACK, version=3)

    # injected transport returns exactly what the cloud would serve
    client = PolicyClient("https://cloud.example/v1/policy", "tok", signer,
                          _get=lambda u, h: sp.to_dict())
    engine, version = client.fetch()
    assert version == 3
    # the compiled engine actually enforces the pushed rule
    ctx = CallContext(agent_id="a", tool_name="transfer", args={"recipient": "x"},
                      extra={"labels": {}}, provenance={"recipient": "untrusted_web"})
    assert engine.evaluate(ctx).effect is Effect.DENY


def test_tampered_pushed_policy_is_rejected():
    signer = HMACSigner(b"tenant-secret")
    sp = sign_pack(signer, FINANCE_PACK, version=1)
    d = sp.to_dict()
    d["pack"]["rules"].append({"name": "evil-allow", "tools": ["*"], "effect": "allow"})  # tamper
    client = PolicyClient("https://cloud.example/v1/policy", "tok", signer, _get=lambda u, h: d)
    with pytest.raises(PolicySyncError):
        client.fetch()


def test_wrong_key_rejected():
    sp = sign_pack(HMACSigner(b"real"), FINANCE_PACK, version=1)
    client = PolicyClient("https://cloud.example", "tok", HMACSigner(b"attacker"),
                          _get=lambda u, h: sp.to_dict())
    with pytest.raises(PolicySyncError):
        client.fetch()


def test_pushed_policy_cannot_widen_local_capability_gate():
    """Even a fully-permissive pushed pack can't grant authority the agent lacks."""
    signer = HMACSigner(b"k")
    permissive = {"rules": [{"name": "allow-all", "tools": ["*"], "effect": "allow"}]}
    engine, _ = PolicyClient("https://policy.example/v1/policy", "t", signer,
                             _get=lambda u, h: sign_pack(signer, permissive, 1).to_dict()).fetch()

    reg = ToolRegistry()
    reg.register(ToolSpec(name="danger", capabilities=[Capability.custom("danger")],
                          severity=Severity.LOW), lambda **k: "boom")
    agent = AgentIdentity(id="bot", allowed_capabilities=[])  # holds NOTHING
    rt = AgentRuntime(registry=reg, engine=engine, default_agent=agent,
                      tracker=ProvenanceTracker())
    # the pushed "allow-all" DSL can't override the local capability gate
    with pytest.raises(PermissionError):
        rt.invoke_tool("danger")


# --------------------------------------------------------------------------- #
# end-to-end via the control plane (TestClient bridged into PolicyClient)
# --------------------------------------------------------------------------- #
def test_cloud_policy_roundtrip():
    pytest.importorskip("fastapi")
    from fastapi.testclient import TestClient

    from capguard_cloud import create_app

    signer = HMACSigner(b"cloud-policy-secret")
    app = create_app(api_keys={"kA": "tenantA"}, policy_signer=signer)
    tc = TestClient(app)

    # no policy yet
    assert tc.get("/v1/policy", headers={"Authorization": "Bearer kA"}).status_code == 404
    # push one
    r = tc.put("/v1/policy", headers={"Authorization": "Bearer kA"}, json=FINANCE_PACK)
    assert r.status_code == 200 and r.json()["version"] == 1

    # a guard pulls it, verifying the signature locally, and compiles a working engine
    client = PolicyClient("https://cloud.example/v1/policy", "kA", signer,
                          _get=lambda u, h: tc.get("/v1/policy", headers=h).json())
    engine, version = client.fetch()
    assert version == 1
    ctx = CallContext(agent_id="a", tool_name="transfer", args={"recipient": "x"},
                      extra={"labels": {}}, provenance={"recipient": "untrusted_web"})
    assert engine.evaluate(ctx).effect is Effect.DENY

    # versions increment on re-push
    assert tc.put("/v1/policy", headers={"Authorization": "Bearer kA"}, json=FINANCE_PACK).json()["version"] == 2


def test_policy_client_rejects_unsafe_default_urls():
    signer = HMACSigner(b"k")
    with pytest.raises(ValueError, match="requires https outside loopback"):
        PolicyClient("http://cloud.example/v1/policy", "tok", signer)
    with pytest.raises(ValueError, match="non-public IP literal"):
        PolicyClient("https://169.254.169.254/v1/policy", "tok", signer)


def test_policy_client_allows_explicit_internal_escape_hatches():
    signer = HMACSigner(b"k")
    sp = sign_pack(signer, FINANCE_PACK, version=7)
    internal = PolicyClient(
        "https://10.0.0.5/v1/policy", "tok", signer,
        allow_private_network=True, _get=lambda u, h: sp.to_dict())
    assert internal.fetch()[1] == 7
    dev = PolicyClient(
        "http://policy.internal/v1/policy", "tok", signer,
        allow_insecure_http=True, _get=lambda u, h: sp.to_dict())
    assert dev.fetch()[1] == 7
