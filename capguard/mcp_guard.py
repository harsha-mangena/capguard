"""CapGuard MCP security engine.

The Model Context Protocol is the dominant tool surface for agents in 2026 and
also its softest target: tool *descriptions are executable context*, so a
server can poison the agent via its metadata, silently redefine a tool after
approval (rug pull), or shadow a trusted tool's name (squatting). Empirical
studies found a non-trivial fraction of public MCP servers carrying
tool-poisoning issues.

This module is the deterministic security core that sits between an MCP client
and downstream servers. It is transport-agnostic on purpose: it operates on
tool *definitions* and *calls*, so it can back a stdio/HTTP MCP proxy, an
in-process client wrapper, or a gateway. Threat → control mapping:

  * Tool poisoning (ASI04)      -> static description/schema scan, quarantine.
  * Rug pull / redefinition     -> cryptographic pinning of tool fingerprints;
    (ASI04)                        any change quarantines until re-approved.
  * Tool shadowing/squatting    -> cross-server name/description collision check.
    (ASI07)
  * Tool misuse (ASI02)         -> every call routed through AgentRuntime, so
                                   capabilities + the policy DSL still apply.
  * Confused deputy / injection -> unknown/unpinned tools are not callable;
    (ASI01)                        argument provenance flows into the DSL.
"""

from __future__ import annotations

import hashlib
import json
import re
import unicodedata
from dataclasses import dataclass, field
from enum import Enum
from typing import Any, Callable, Dict, List, Mapping, Optional, Sequence, Tuple

from .audit import AuditSink
from .core import Capability, Policy, Severity, ToolSpec
from .policy_dsl import PolicyEngine
from .registry import ToolRegistry
from .runtime import AgentIdentity, AgentRuntime


class MCPThreat(str, Enum):
    POISONING = "tool_poisoning"
    RUG_PULL = "rug_pull"
    SHADOWING = "tool_shadowing"
    UNPINNED = "unpinned_tool"


class MCPSecurityError(PermissionError):
    """Raised when a call targets a quarantined or unknown MCP tool."""


@dataclass(frozen=True)
class MCPToolDef:
    server_id: str
    name: str
    description: str = ""
    input_schema: Mapping[str, Any] = field(default_factory=dict)

    @property
    def key(self) -> str:
        return f"{self.server_id}::{self.name}"

    def fingerprint(self) -> str:
        body = {
            "name": self.name,
            "description": self.description,
            "input_schema": self.input_schema,
        }
        canonical = json.dumps(body, sort_keys=True, separators=(",", ":"), default=str)
        return hashlib.sha256(canonical.encode()).hexdigest()


@dataclass
class SecurityFinding:
    threat: MCPThreat
    server_id: str
    tool_name: str
    detail: str
    severity: Severity = Severity.HIGH


@dataclass
class ScanReport:
    pinned: List[str] = field(default_factory=list)
    findings: List[SecurityFinding] = field(default_factory=list)

    @property
    def ok(self) -> bool:
        return not self.findings

    @property
    def quarantined(self) -> List[str]:
        return [f"{f.server_id}::{f.tool_name}" for f in self.findings]


# --------------------------------------------------------------------------- #
# Deterministic tool-poisoning scanner (mcp-scan style, stage-1 static).
# --------------------------------------------------------------------------- #
_POISON_PATTERNS: List[Tuple[re.Pattern, str, Severity]] = [
    (re.compile(r"ignore\s+(all\s+|the\s+|any\s+)?(previous|prior|above|earlier)\s+(instruction|prompt|context|rule)", re.I),
     "instruction_override", Severity.HIGH),
    (re.compile(r"disregard\s+(all\s+|the\s+|your\s+)?(previous|prior|above|safety|system)", re.I),
     "instruction_override", Severity.HIGH),
    (re.compile(r"<\s*(important|secret|system|hidden|admin|instructions?)\s*>", re.I),
     "hidden_directive_tag", Severity.HIGH),
    (re.compile(r"do\s+not\s+(tell|inform|mention|reveal|notify).{0,40}(user|human|operator)", re.I),
     "concealment", Severity.HIGH),
    (re.compile(r"without\s+(telling|informing|notifying|alerting).{0,30}(the\s+)?(user|human)", re.I),
     "concealment", Severity.HIGH),
    (re.compile(r"(read|exfiltrate|send|leak|upload|forward|copy).{0,40}(\.env|\.ssh|id_rsa|/etc/passwd|api[_\- ]?keys?|credential|secret|token)", re.I),
     "exfiltration", Severity.CRITICAL),
    (re.compile(r"(curl|wget|fetch|https?://)\S{0,80}(token|key|secret|password|cookie)", re.I),
     "exfiltration", Severity.CRITICAL),
    (re.compile(r"you\s+must\s+(also\s+)?(call|invoke|use|run|execute)", re.I),
     "coerced_tool_use", Severity.HIGH),
]

_ZERO_WIDTH = {"\u200b", "\u200c", "\u200d", "\u2060", "\ufeff", "\u00ad"}


def _walk_schema_strings(schema: Mapping[str, Any]):
    if not isinstance(schema, Mapping):
        return
    for k, v in schema.items():
        if k == "description" and isinstance(v, str):
            yield v
        if isinstance(v, Mapping):
            yield from _walk_schema_strings(v)
        elif isinstance(v, list):
            for item in v:
                if isinstance(item, Mapping):
                    yield from _walk_schema_strings(item)


def scan_poisoning(td: MCPToolDef) -> List[SecurityFinding]:
    findings: List[SecurityFinding] = []
    texts = [td.description, *list(_walk_schema_strings(td.input_schema))]
    blob = "\n".join(t for t in texts if t)

    # hidden / invisible unicode is a classic smuggling vector
    if any(ch in _ZERO_WIDTH for ch in blob):
        findings.append(SecurityFinding(MCPThreat.POISONING, td.server_id, td.name,
                                        "invisible/zero-width characters in tool metadata", Severity.HIGH))
    # control characters (other than tab/newline) hiding content
    if any(unicodedata.category(ch) == "Cf" for ch in blob if ch not in "\t\n"):
        findings.append(SecurityFinding(MCPThreat.POISONING, td.server_id, td.name,
                                        "format-control characters in tool metadata", Severity.MEDIUM))
    for pattern, label, sev in _POISON_PATTERNS:
        if pattern.search(blob):
            findings.append(SecurityFinding(MCPThreat.POISONING, td.server_id, td.name,
                                            f"poisoning pattern: {label}", sev))
    return findings


def _normalize(s: str) -> str:
    return re.sub(r"\s+", " ", s.strip().lower())


# --------------------------------------------------------------------------- #
# Capability mapping
# --------------------------------------------------------------------------- #
CapabilityMapper = Callable[[MCPToolDef], Tuple[List[Capability], Severity]]


def deny_by_default_mapper(td: MCPToolDef) -> Tuple[List[Capability], Severity]:
    """Unknown MCP tools get a custom capability at HIGH severity, which forces
    human approval under the baseline policy. Least privilege for the unknown."""
    return [Capability.custom(td.name)], Severity.HIGH


def explicit_mapper(mapping: Mapping[str, Tuple[List[Capability], Severity]]) -> CapabilityMapper:
    """Map known tool names to concrete capabilities; everything else is denied."""
    def _m(td: MCPToolDef) -> Tuple[List[Capability], Severity]:
        if td.name in mapping:
            return mapping[td.name]
        return deny_by_default_mapper(td)
    return _m


# --------------------------------------------------------------------------- #
# The guard
# --------------------------------------------------------------------------- #
class MCPGuard:
    def __init__(
        self,
        *,
        policy: Optional[Policy] = None,
        engine: Optional[PolicyEngine] = None,
        audit_sink: Optional[AuditSink] = None,
        approval_store: Optional[Any] = None,
        capability_mapper: Optional[CapabilityMapper] = None,
        block_severity: Severity = Severity.HIGH,
    ) -> None:
        self._registry = ToolRegistry()
        self._runtime = AgentRuntime(
            registry=self._registry,
            policy=policy or Policy(),
            engine=engine or PolicyEngine(),
            audit_sink=audit_sink,
            approval_store=approval_store,
        )
        self._mapper = capability_mapper or deny_by_default_mapper
        self._block_at = block_severity.rank
        self._pins: Dict[str, str] = {}                 # key -> fingerprint
        self._defs: Dict[str, MCPToolDef] = {}          # key -> def
        self._invokers: Dict[str, Callable[[str, Mapping[str, Any]], Any]] = {}
        self._quarantine: Dict[str, SecurityFinding] = {}

    # -- discovery / pinning ------------------------------------------------ #
    def register_server(
        self,
        server_id: str,
        tools: Sequence[MCPToolDef],
        invoker: Callable[[str, Mapping[str, Any]], Any],
    ) -> ScanReport:
        """Scan, pin and (if clean) make callable the tools of one MCP server."""
        report = ScanReport()
        self._invokers[server_id] = invoker

        for td in tools:
            key = td.key
            findings: List[SecurityFinding] = []

            # 1. poisoning scan
            findings += scan_poisoning(td)

            # 2. rug-pull: changed fingerprint vs an existing pin
            fp = td.fingerprint()
            if key in self._pins and self._pins[key] != fp:
                findings.append(SecurityFinding(
                    MCPThreat.RUG_PULL, server_id, td.name,
                    "tool definition changed since it was pinned", Severity.CRITICAL))

            # 3. shadowing: same tool name or identical description on another server
            for _other_key, other in self._defs.items():
                if other.server_id == server_id:
                    continue
                if _normalize(other.name) == _normalize(td.name):
                    findings.append(SecurityFinding(
                        MCPThreat.SHADOWING, server_id, td.name,
                        f"name collides with {other.key!r} on another server", Severity.HIGH))
                elif td.description and _normalize(other.description) == _normalize(td.description):
                    findings.append(SecurityFinding(
                        MCPThreat.SHADOWING, server_id, td.name,
                        f"description identical to {other.key!r} on another server", Severity.MEDIUM))

            self._defs[key] = td
            blocking = [f for f in findings if f.severity.rank >= self._block_at]
            report.findings += findings

            if blocking:
                # quarantine: not callable until explicitly re-approved
                self._quarantine[key] = blocking[0]
                if self._registry.has(key):
                    self._registry.unregister(key)
                continue

            # clean: pin + (re)register a guarded shim
            self._pins[key] = fp
            self._quarantine.pop(key, None)
            self._register_shim(server_id, td)
            report.pinned.append(key)

        return report

    def _register_shim(self, server_id: str, td: MCPToolDef) -> None:
        caps, severity = self._mapper(td)
        if self._registry.has(td.key):
            self._registry.unregister(td.key)
        invoker = self._invokers[server_id]
        original = td.name

        def shim(**kwargs: Any) -> Any:
            return invoker(original, kwargs)

        self._registry.register(
            ToolSpec(name=td.key, description=td.description, capabilities=caps, severity=severity),
            shim,
        )

    def approve_change(self, server_id: str, tool_name: str) -> None:
        """Human re-approval of a rug-pulled/quarantined tool: re-pin to current."""
        key = f"{server_id}::{tool_name}"
        td = self._defs.get(key)
        if td is None:
            raise KeyError(key)
        # only re-pin if the remaining findings were rug-pull/shadowing, not active poisoning
        residual = scan_poisoning(td)
        if any(f.severity.rank >= self._block_at for f in residual):
            raise MCPSecurityError(f"{key!r} still fails poisoning scan; refusing to re-pin")
        self._pins[key] = td.fingerprint()
        self._quarantine.pop(key, None)
        self._register_shim(server_id, td)

    # -- calls -------------------------------------------------------------- #
    def guard_call(
        self,
        server_id: str,
        tool_name: str,
        args: Mapping[str, Any],
        *,
        agent: AgentIdentity,
        provenance: Optional[Dict[str, str]] = None,
        approval_token: Optional[str] = None,
        request_id: Optional[str] = None,
    ) -> Any:
        key = f"{server_id}::{tool_name}"
        if key in self._quarantine:
            raise MCPSecurityError(
                f"tool {key!r} is quarantined: {self._quarantine[key].detail}"
            )
        if key not in self._pins:
            raise MCPSecurityError(f"tool {key!r} is unknown/unpinned; refusing to call")
        # integrity re-check: current def must still match the pin
        if self._defs[key].fingerprint() != self._pins[key]:
            raise MCPSecurityError(f"tool {key!r} fingerprint drifted since pinning")

        return self._runtime.invoke_tool(
            key,
            agent=agent,
            provenance=provenance,
            approval_token=approval_token,
            request_id=request_id,
            **dict(args),
        )

    # -- introspection ------------------------------------------------------ #
    @property
    def runtime(self) -> AgentRuntime:
        return self._runtime

    def is_callable(self, server_id: str, tool_name: str) -> bool:
        key = f"{server_id}::{tool_name}"
        return key in self._pins and key not in self._quarantine
