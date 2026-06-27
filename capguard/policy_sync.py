"""Signed policy push — the control plane delivers policy; the guard verifies it.

The control plane stores a versioned policy *pack* per tenant and signs it. A
guard pulls the pack and **verifies the signature locally before applying it**.
Two safety properties make this safe even against a compromised control plane:

  1. **Authenticated** — an unsigned or tampered pack is rejected (fail-closed:
     the guard keeps its current policy). Reuses the identity ``Signer`` (HMAC or
     Ed25519).
  2. **Can only tighten** — a pushed pack compiles to ``PolicyEngine`` DSL rules,
     which under deny-overrides can only *add* restriction. It does **not** touch
     the local capability gate or argument enforcement, so the cloud can never
     widen what an agent is allowed to do — only narrow it. The local guard stays
     the source of truth (the same principle as the fail-open audit sink).
"""

from __future__ import annotations

import json
import urllib.request
from dataclasses import dataclass, field
from typing import Any, Callable, Dict, Mapping, Optional, Tuple

from .identity import Signer
from .net_safety import validate_http_url
from .packs import compile_pack
from .policy_dsl import PolicyEngine


class PolicySyncError(PermissionError):
    """Raised when a pushed policy is unsigned, tampered, or otherwise untrusted."""


@dataclass
class SignedPack:
    version: int
    pack: Dict[str, Any] = field(default_factory=dict)
    signature: str = ""
    alg: str = ""

    def canonical(self) -> bytes:
        body = {"version": self.version, "pack": self.pack}
        return json.dumps(body, sort_keys=True, separators=(",", ":"), default=str).encode()

    def to_dict(self) -> Dict[str, Any]:
        return {"version": self.version, "pack": self.pack,
                "signature": self.signature, "alg": self.alg}

    @classmethod
    def from_dict(cls, d: Mapping[str, Any]) -> "SignedPack":
        return cls(version=int(d["version"]), pack=dict(d.get("pack", {})),
                   signature=d.get("signature", ""), alg=d.get("alg", ""))


def sign_pack(signer: Signer, pack: Mapping[str, Any], version: int) -> SignedPack:
    sp = SignedPack(version=version, pack=dict(pack))
    sp.signature = signer.sign(sp.canonical())
    sp.alg = signer.alg
    return sp


def _default_get(url: str, headers: Mapping[str, str], timeout: float) -> Dict[str, Any]:
    req = urllib.request.Request(url, headers=dict(headers), method="GET")
    with urllib.request.urlopen(req, timeout=timeout) as resp:
        return json.loads(resp.read().decode("utf-8"))


class PolicyClient:
    """Pulls a signed policy pack from the control plane and compiles it locally
    after verifying the signature. ``_get`` is injectable for testing."""

    def __init__(self, url: str, token: str, signer: Signer, *, timeout: float = 5.0,
                 allow_private_network: bool = False,
                 allow_insecure_http: bool = False,
                 _get: Optional[Callable[..., Dict[str, Any]]] = None) -> None:
        self._url = validate_http_url(
            url,
            label="policy sync URL",
            allow_private_network=allow_private_network,
            allow_insecure_http=allow_insecure_http,
        )
        self._token = token
        self._signer = signer
        self._timeout = timeout
        self._get = _get or (lambda u, h: _default_get(u, h, timeout))

    def fetch(self) -> Tuple[PolicyEngine, int]:
        data = self._get(self._url, {"Authorization": f"Bearer {self._token}"})
        sp = SignedPack.from_dict(data)
        if sp.alg != self._signer.alg or not self._signer.verify(sp.canonical(), sp.signature):
            raise PolicySyncError("pushed policy signature invalid — refusing to apply")
        return compile_pack(sp.pack), sp.version
