__version__ = "0.1.0"

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
from .policy_dsl import (
    AND,
    ANY_TOOL,
    NOT,
    OR,
    Arg,
    CallContext,
    Decision,
    Effect,
    Flow,
    PolicyEngine,
    Provenance,
    Rule,
    Signal,
    Taint,
    role_in,
    tool_is,
)
from .provenance import (
    SECRET,
    TRUSTED,
    UNTRUSTED_TOOL,
    UNTRUSTED_WEB,
    Confidentiality,
    Label,
    ProvenanceTracker,
    Trust,
    combine_all,
)
from .registry import ToolRegistry
from .runtime import AgentRuntime

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
    "Signal",
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
# Replay-safe approvals
from .approval import (  # noqa: E402
    ApprovalStatus,
    ApprovalStore,
    ApprovalToken,
    args_digest,
)
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

# OAuth 2.1 resource-server auth for the HTTP MCP boundary (RFC 9728 / RFC 8707)
from .mcp_auth import (  # noqa: E402
    Ed25519JWTVerifier,
    HMACJWTVerifier,
    JWKSVerifier,
    ProtectedResourceMetadata,
    StaticTokenVerifier,
    TokenClaims,
    TokenError,
)

__all__ += [
    "Ed25519JWTVerifier",
    "HMACJWTVerifier",
    "JWKSVerifier",
    "ProtectedResourceMetadata",
    "StaticTokenVerifier",
    "TokenClaims",
    "TokenError",
]

# Advisory detectors (deterministic-first, probabilistic-assist)
from .detectors import (  # noqa: E402
    CallableDetector,
    Detector,
    DetectorSignal,
    PIIDetector,
    RegexInjectionDetector,
)

__all__ += [
    "CallableDetector",
    "Detector",
    "DetectorSignal",
    "PIIDetector",
    "RegexInjectionDetector",
]

# Budgets & quotas (ASI08 / unbounded consumption)
from .budget import Budget, BudgetExceeded, BudgetLedger, Spend  # noqa: E402

__all__ += [
    "Budget",
    "BudgetExceeded",
    "BudgetLedger",
    "Spend",
]

# Signed inter-agent (A2A) messages (ASI07)
from .a2a import A2AChannel, A2AError, AgentMessage  # noqa: E402

__all__ += [
    "A2AChannel",
    "A2AError",
    "AgentMessage",
]

# Forensic provenance reconstruction from the audit chain
from .audit_graph import (  # noqa: E402
    FlowEdge,
    FlowGraph,
    FlowNode,
    build_flow_graph,
    flow_graph_from_file,
    tainted_sink_calls,
)

__all__ += [
    "FlowEdge",
    "FlowGraph",
    "FlowNode",
    "build_flow_graph",
    "flow_graph_from_file",
    "tainted_sink_calls",
]

# Audit sinks (incl. cloud ingest)
from .audit import (  # noqa: E402
    AuditEvent,
    HashChainedSink,
    HttpSink,
    MemorySink,
    MultiSink,
    verify_chain,
    verify_file,
)

__all__ += [
    "AuditEvent",
    "HashChainedSink",
    "HttpSink",
    "MemorySink",
    "MultiSink",
    "verify_chain",
    "verify_file",
]

# Signed policy push (cloud -> guard)
from .policy_sync import (  # noqa: E402
    PolicyClient,
    PolicySyncError,
    SignedPack,
    sign_pack,
)

__all__ += [
    "PolicyClient",
    "PolicySyncError",
    "SignedPack",
    "sign_pack",
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
