__version__ = "0.1.0.dev0"

from .core import (
    AgentIdentity,
    ApprovalRequired,
    Capability,
    CapabilityType,
    CapabilityViolation,
    Policy,
    PolicyDecision,
    Severity,
    ToolSpec,
)
from .registry import ToolRegistry
from .runtime import AgentRuntime
from .policy_dsl import (
    ANY_TOOL,
    AND,
    Arg,
    CallContext,
    Decision,
    Effect,
    Flow,
    NOT,
    OR,
    PolicyEngine,
    Provenance,
    Rule,
    Taint,
    role_in,
    tool_is,
)
from .provenance import (
    Confidentiality,
    Label,
    ProvenanceTracker,
    Trust,
    SECRET,
    TRUSTED,
    UNTRUSTED_TOOL,
    UNTRUSTED_WEB,
    combine_all,
)

__all__ = [
    "AgentIdentity",
    "ApprovalRequired",
    "Capability",
    "CapabilityType",
    "CapabilityViolation",
    "Policy",
    "PolicyDecision",
    "Severity",
    "ToolSpec",
    "ToolRegistry",
    "AgentRuntime",
    "PolicyEngine",
    "Rule",
    "Effect",
    "Decision",
    "CallContext",
    "Arg",
    "Provenance",
    "Taint",
    "Flow",
    "AND",
    "OR",
    "NOT",
    "role_in",
    "tool_is",
    "ANY_TOOL",
    # provenance / information-flow engine
    "Label",
    "Trust",
    "Confidentiality",
    "ProvenanceTracker",
    "TRUSTED",
    "UNTRUSTED_TOOL",
    "UNTRUSTED_WEB",
    "SECRET",
    "combine_all",
]

# MCP security engine
from .mcp_guard import (  # noqa: E402
    MCPGuard,
    MCPSecurityError,
    MCPThreat,
    MCPToolDef,
    ScanReport,
    SecurityFinding,
    deny_by_default_mapper,
    explicit_mapper,
    scan_poisoning,
)

# Replay-safe approvals
from .approval import (  # noqa: E402
    ApprovalStatus,
    ApprovalStore,
    ApprovalToken,
    args_digest,
)

__all__ += [
    "MCPGuard",
    "MCPSecurityError",
    "MCPThreat",
    "MCPToolDef",
    "ScanReport",
    "SecurityFinding",
    "deny_by_default_mapper",
    "explicit_mapper",
    "scan_poisoning",
    "ApprovalStatus",
    "ApprovalStore",
    "ApprovalToken",
    "args_digest",
]

# Verifiable identity + delegation attenuation (ASI03)
from .identity import (  # noqa: E402
    Ed25519Signer,
    HMACSigner,
    IdentityClaims,
    IdentityError,
    IdentityIssuer,
    IdentityVerifier,
    SignedIdentity,
)

__all__ += [
    "Ed25519Signer",
    "HMACSigner",
    "IdentityClaims",
    "IdentityError",
    "IdentityIssuer",
    "IdentityVerifier",
    "SignedIdentity",
]

# Framework adapters (embed under LangGraph / OpenAI Agents / CrewAI / raw)
from .adapters import (  # noqa: E402
    CapGuard,
    GuardedTool,
    to_crewai,
    to_langchain,
    to_openai_agents,
)

__all__ += [
    "CapGuard",
    "GuardedTool",
    "to_langchain",
    "to_openai_agents",
    "to_crewai",
]

# Rogue-agent detection + circuit breaker (ASI10 / ASI08)
from .monitor import (  # noqa: E402
    Anomaly,
    AnomalyKind,
    AnomalyPolicy,
    BehaviorMonitor,
    CircuitBreaker,
)

__all__ += [
    "Anomaly",
    "AnomalyKind",
    "AnomalyPolicy",
    "BehaviorMonitor",
    "CircuitBreaker",
]

# Task / intent-scoped capability envelopes (P6)
from .taskscope import (  # noqa: E402
    ArgConstraint,
    ConstraintOp,
    TaskScope,
    TaskScopeError,
    TaskScopeIssuer,
    ToolScope,
)

__all__ += [
    "ArgConstraint",
    "ConstraintOp",
    "TaskScope",
    "TaskScopeError",
    "TaskScopeIssuer",
    "ToolScope",
]

# Provenance-preserving memory / RAG guard (ASI06)
from .memory import MemoryPoisoningError, ProvenanceMemory  # noqa: E402

__all__ += [
    "MemoryPoisoningError",
    "ProvenanceMemory",
]

# Policy packs (declarative profiles -> PolicyEngine)
from .packs import (  # noqa: E402
    BUILTIN_PACKS,
    PackError,
    builtin_pack_names,
    compile_pack,
    load_pack,
    pack_capabilities,
)

__all__ += [
    "BUILTIN_PACKS",
    "PackError",
    "builtin_pack_names",
    "compile_pack",
    "load_pack",
    "pack_capabilities",
]

# MCP proxy (runnable)
from .mcp_proxy import (  # noqa: E402
    InProcessDownstream,
    MCPProxy,
    StdioDownstream,
    StdioServer,
)

__all__ += [
    "InProcessDownstream",
    "MCPProxy",
    "StdioDownstream",
    "StdioServer",
]

# Streamable-HTTP MCP transport (guard remote MCP servers / serve the proxy over HTTP)
from .mcp_http import HttpDownstream, MCPHttpServer  # noqa: E402

__all__ += [
    "HttpDownstream",
    "MCPHttpServer",
]

# Sandboxed execution (ASI05)
from .sandbox import (  # noqa: E402
    DenyBackend,
    DockerBackend,
    ExecResult,
    ExecutionBackend,
    ResourceLimits,
    SandboxError,
    SubprocessBackend,
    python_tool,
    shell_tool,
)

__all__ += [
    "DenyBackend",
    "DockerBackend",
    "ExecResult",
    "ExecutionBackend",
    "ResourceLimits",
    "SandboxError",
    "SubprocessBackend",
    "python_tool",
    "shell_tool",
]
