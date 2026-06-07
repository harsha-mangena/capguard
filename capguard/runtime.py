"""AgentRuntime — the inline enforcement point for every tool call.

Pipeline (deterministic, defense in depth):

  1. Baseline capability gate   (Policy.evaluate: attenuation + severity)
  2. Programmable policy DSL     (argument/use-case/rate/provenance rules)
  3. Capability ARGUMENT enforcement on the concrete call values  ← the teeth
  4. Dispatch
  5. Hash-chained audit at every exit

The runtime holds NO mutable per-call identity. Identity flows through an
immutable CallContext, so concurrent calls cannot bleed permissions into each
other (the previous version mutated ``self._agent`` under a try/finally, which
was unsafe under FastAPI's threadpool).
"""

from __future__ import annotations

from typing import Any, Callable, Dict, List, Optional

from .audit import AuditEvent, AuditSink, digest
from .core import (
    AgentIdentity,
    ApprovalRequired,
    Capability,
    CapabilityViolation,
    Policy,
    PolicyDecision,
    ToolSpec,
)
from .budget import BudgetExceeded, BudgetLedger
from .detectors import Detector
from .identity import Signer
from .monitor import CIRCUIT_OPEN_ERROR, CircuitBreaker
from .policy_dsl import CallContext, Decision, Effect, PolicyEngine
from .provenance import Label, ProvenanceTracker
from .registry import ToolRegistry
from .taskscope import TaskScope

ApprovalHandler = Callable[[AuditEvent, ToolSpec], bool]


class AgentRuntime:
    def __init__(
        self,
        *,
        registry: ToolRegistry,
        policy: Optional[Policy] = None,
        engine: Optional[PolicyEngine] = None,
        audit_sink: Optional[AuditSink] = None,
        approval_handler: Optional[ApprovalHandler] = None,
        approval_store: Optional[Any] = None,
        default_agent: Optional[AgentIdentity] = None,
        tracker: Optional[ProvenanceTracker] = None,
        circuit_breaker: Optional[CircuitBreaker] = None,
        task_scope_signer: Optional[Signer] = None,
        detectors: Optional[List[Detector]] = None,
        budget_ledger: Optional[BudgetLedger] = None,
        budget_key_fn: Optional[Callable[[AgentIdentity, Optional[str]], str]] = None,
        trip_breaker_on_budget: bool = False,
    ) -> None:
        self._registry = registry
        self._policy = policy or Policy()
        self._engine = engine or PolicyEngine()
        self._audit_sink = audit_sink
        self._approval_handler = approval_handler
        self._approval_store = approval_store
        self._default_agent = default_agent
        # Optional kill switch (ASI10/ASI08): when an agent's breaker is open,
        # every call fails closed until it is reset or its cooldown elapses.
        self._circuit_breaker = circuit_breaker
        # Optional signer used to verify signed task scopes (P6) at this boundary.
        self._task_scope_signer = task_scope_signer
        # Optional advisory detectors (probabilistic-assist). Their signals feed
        # DSL predicates but never gate directly — the deterministic layer rules.
        self._detectors: List[Detector] = list(detectors or [])
        # Optional cumulative budget (ASI08 unbounded consumption). Checked before
        # dispatch; one call charged after; overspend can trip the breaker.
        self._budget = budget_ledger
        self._budget_key_fn = budget_key_fn
        self._trip_breaker_on_budget = trip_breaker_on_budget
        # Optional information-flow tracker. When present, every argument's
        # propagated label is computed before policy evaluation and every result
        # is labeled after dispatch, so taint flows across the whole call chain.
        self._tracker = tracker

    # ------------------------------------------------------------------ #
    @property
    def registry(self) -> ToolRegistry:
        return self._registry

    @property
    def default_agent(self) -> Optional[AgentIdentity]:
        return self._default_agent

    # ------------------------------------------------------------------ #
    def _emit(self, event: AuditEvent) -> None:
        if self._audit_sink is not None:
            self._audit_sink(event)

    def _enforce_arguments(
        self, agent: AgentIdentity, tool: ToolSpec, kwargs: Dict[str, Any]
    ) -> None:
        """Validate each concrete argument against the effective capability.

        Uses the agent's *granted* capability (the one that covers the tool's
        requirement), so the enforced bound is the agent's, not merely the
        tool's declaration. Raises CapabilityViolation on the first breach.
        """
        for required in tool.capabilities:
            granted = agent.effective_capability(required)
            enforcer: Capability = granted or required
            arg_name = required.arg
            if not arg_name or arg_name not in kwargs:
                continue
            enforcer.enforce(kwargs[arg_name])

    def _run_detectors(self, ctx: CallContext) -> Dict[str, Any]:
        """Run advisory detectors over the call; collect signals by name.

        Each detector is fail-open: if it raises, its signal is simply absent —
        the deterministic gates are unaffected. Detectors never decide; they only
        feed DSL predicates (which, under deny-overrides, can only tighten).
        """
        signals: Dict[str, Any] = {}
        for det in self._detectors:
            try:
                sig = det.inspect(ctx)
            except Exception:  # noqa: BLE001
                sig = None
            if sig is not None:
                signals[sig.name] = sig
        return signals

    def _budget_key(self, agent: AgentIdentity, request_id: Optional[str]) -> str:
        return self._budget_key_fn(agent, request_id) if self._budget_key_fn else agent.id

    def report_usage(self, agent: "AgentIdentity | str", *, tokens: int = 0, cost: float = 0.0,
                     request_id: Optional[str] = None) -> None:
        """Report measured token / dollar usage so cumulative budgets can enforce.

        Call this after an LLM/tool invocation whose cost you measured (only the
        application knows token counts). Raises ``BudgetExceeded`` — and trips the
        circuit breaker if configured — when a ceiling is breached.
        """
        if self._budget is None:
            return
        if isinstance(agent, str):
            key = agent
        else:
            key = self._budget_key(agent, request_id)
        try:
            self._budget.charge(key, tokens=tokens, cost=cost)
        except BudgetExceeded as exc:
            if self._trip_breaker_on_budget and self._circuit_breaker is not None:
                self._circuit_breaker.trip(key, str(exc))
            raise

    # ------------------------------------------------------------------ #
    def invoke_tool(
        self,
        name: str,
        /,
        *,
        agent: Optional[AgentIdentity] = None,
        request_id: Optional[str] = None,
        provenance: Optional[Dict[str, str]] = None,
        approval_token: Optional[str] = None,
        task_scope: Optional[TaskScope] = None,
        **kwargs: Any,
    ) -> Any:
        agent = agent or self._default_agent
        if agent is None:
            raise ValueError("no agent identity supplied (pass agent= or set default_agent)")

        registered = self._registry.get(name)
        tool: ToolSpec = registered.spec

        # Information-flow labels for each argument. Start from what the tracker
        # propagated (empty if no tracker), then fold in any explicit call-site
        # labels. ``combine`` takes the most-restrictive trust, so an explicit
        # "trusted" can never launder a value the tracker already tainted.
        arg_labels: Dict[str, Label] = (
            self._tracker.labels_for_args(kwargs) if self._tracker is not None else {}
        )
        for arg_name, trust_str in (provenance or {}).items():
            arg_labels[arg_name] = arg_labels.get(arg_name, Label()).combine(
                Label.from_trust_str(trust_str)
            )
        # String view consumed by the back-compat Provenance(...) predicate.
        prov_strs = {k: lbl.trust_str for k, lbl in arg_labels.items()}

        ctx = CallContext(
            agent_id=agent.id,
            tool_name=tool.name,
            args=dict(kwargs),
            roles=tuple(agent.roles),
            request_id=request_id,
            provenance=prov_strs,
            extra={"labels": arg_labels},
        )

        event = AuditEvent(
            agent_id=agent.id,
            tool_name=tool.name,
            decision=PolicyDecision.DENY,
            params={k: digest(v) for k, v in kwargs.items()},  # store digests, not raw payloads
            request_id=request_id,
        )

        # 0. kill switch — a tripped breaker halts the agent before anything else.
        if self._circuit_breaker is not None and self._circuit_breaker.is_open(agent.id):
            event.error = CIRCUIT_OPEN_ERROR
            self._emit(event)
            raise PermissionError(
                f"agent {agent.id!r} is halted by the circuit breaker: "
                f"{self._circuit_breaker.reason(agent.id)}"
            )

        # 0.3 budget pre-gate (ASI08): refuse once a cumulative ceiling is reached.
        if self._budget is not None:
            try:
                self._budget.check(self._budget_key(agent, request_id))
            except BudgetExceeded as exc:
                event.error = f"budget_exceeded: {exc.dimension}"
                self._emit(event)
                if self._trip_breaker_on_budget and self._circuit_breaker is not None:
                    self._circuit_breaker.trip(agent.id, str(exc))
                raise

        # 0.5 task/intent scope — JIT least privilege for one specific task (P6).
        # Enforced on top of standing capabilities; it can only tighten.
        if task_scope is not None:
            if task_scope.signature and self._task_scope_signer is not None and not task_scope.verify(self._task_scope_signer):
                event.error = "invalid_task_scope_signature"
                self._emit(event)
                raise PermissionError(f"task scope signature invalid for tool {name!r}")
            if task_scope.agent_id != agent.id:
                event.error = "task_scope_agent_mismatch"
                self._emit(event)
                raise PermissionError(f"task scope is bound to a different agent for tool {name!r}")
            ok, reason = task_scope.check_call(tool.name, kwargs, required_caps=tool.capabilities)
            if not ok:
                event.error = f"denied_by_task_scope: {reason}"
                self._emit(event)
                raise PermissionError(f"denied by task scope ({reason}) for tool {name!r}")

        # 1. baseline capability gate
        base = self._policy.evaluate(agent=agent, tool=tool)
        if base is PolicyDecision.DENY:
            event.decision = PolicyDecision.DENY
            event.error = "denied_by_capability_policy"
            self._emit(event)
            raise PermissionError(
                f"agent {agent.id!r} lacks capabilities for tool {name!r}"
            )

        # 1.5 advisory detectors → ctx (probabilistic-assist). Their signals feed
        # the DSL; deny-overrides guarantees they can only tighten, never loosen.
        if self._detectors:
            ctx.extra["detectors"] = self._run_detectors(ctx)

        # 2. programmable DSL (deny-overrides). It can only tighten.
        dsl: Decision = self._engine.evaluate(ctx)
        event.effect = dsl.effect.value

        effective = base
        if dsl.effect is Effect.DENY:
            effective = PolicyDecision.DENY
        elif dsl.effect is Effect.REQUIRE_APPROVAL and base is PolicyDecision.ALLOW:
            effective = PolicyDecision.REQUIRE_APPROVAL

        if effective is PolicyDecision.DENY:
            event.decision = PolicyDecision.DENY
            event.error = f"denied_by_policy_dsl: {dsl.reason}"
            self._emit(event)
            raise PermissionError(f"denied by policy ({dsl.reason}) for tool {name!r}")

        if effective is PolicyDecision.REQUIRE_APPROVAL:
            event.decision = PolicyDecision.REQUIRE_APPROVAL

            # (a) replay path: a valid, approved, args-matching token.
            if approval_token is not None and self._approval_store is not None:
                ok = self._approval_store.verify_and_consume(
                    token_id=approval_token, agent_id=agent.id, tool_name=tool.name, args=kwargs
                )
                if not ok:
                    event.error = "invalid_or_mismatched_approval_token"
                    self._emit(event)
                    raise PermissionError(
                        f"approval token invalid/expired/mismatched for tool {name!r}"
                    )
                event.decision = PolicyDecision.ALLOW

            # (b) inline synchronous human approval.
            elif self._approval_handler is not None:
                if not self._approval_handler(event, tool):
                    event.error = "denied_by_approval_handler"
                    self._emit(event)
                    raise PermissionError(f"approval denied for tool {name!r}")
                event.decision = PolicyDecision.ALLOW

            # (c) pause: issue a pending token bound to these exact args.
            else:
                token_id = None
                if self._approval_store is not None:
                    tok = self._approval_store.issue(
                        agent_id=agent.id, tool_name=tool.name, args=kwargs, reason=dsl.reason
                    )
                    token_id = tok.id
                event.error = "require_approval_pending"
                self._emit(event)
                raise ApprovalRequired(tool=tool, agent=agent, reason=dsl.reason, token_id=token_id)

        # 3. ARGUMENT enforcement (the teeth) — independent of the gate above.
        try:
            self._enforce_arguments(agent, tool, kwargs)
        except CapabilityViolation as exc:
            event.decision = PolicyDecision.DENY
            event.error = f"capability_violation: {exc}"
            self._emit(event)
            raise

        # 4. dispatch + 5. audit
        try:
            result = registered.func(**kwargs)
            # charge one call against the budget (check() already admitted it).
            if self._budget is not None:
                self._budget.charge(self._budget_key(agent, request_id), calls=1)
            # Propagate taint onto the result so the next call inherits it.
            if self._tracker is not None:
                out_label = self._tracker.record_output(
                    result, list(kwargs.values()), source=tool.output_label
                )
                if out_label != Label():
                    event.effect = (event.effect or "") + f"|out_trust={out_label.trust_str}"
            event.result_digest = digest(result)
            self._emit(event)
            return result
        except Exception as exc:  # noqa: BLE001
            event.error = f"{type(exc).__name__}: {exc}"
            self._emit(event)
            raise
