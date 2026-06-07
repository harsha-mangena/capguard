"""Programmable, argument-level policy DSL.

Inspired by Progent (programmable privilege control) and AgentSpec
(trigger -> predicate -> enforcement). A rule fires when its *trigger* matches
the tool, its *predicate* holds over the concrete call arguments, and it then
applies an *effect*. This is what lets a user restrict an agent by a specific
tool call AND by a specific use case (argument values, data provenance,
call rate), not merely "may call tool X".

Precedence is deny-overrides: the most restrictive matching effect wins, so
adding a rule can only tighten, never loosen, the baseline capability gate.
"""

from __future__ import annotations

import fnmatch
import threading
import time
from dataclasses import dataclass, field
from enum import Enum
from typing import Any, Callable, Dict, List, Optional, Sequence

from .provenance import Confidentiality, Label, Trust


class Effect(str, Enum):
    ALLOW = "allow"
    DENY = "deny"
    REQUIRE_APPROVAL = "require_approval"
    RATE_LIMIT = "rate_limit"   # exceeding the limit escalates to DENY

    @property
    def restrictiveness(self) -> int:
        return {"allow": 0, "rate_limit": 1, "require_approval": 2, "deny": 3}[self.value]


@dataclass
class CallContext:
    """Everything a predicate may reason about for a single tool call."""

    agent_id: str
    tool_name: str
    args: Dict[str, Any] = field(default_factory=dict)
    roles: Sequence[str] = field(default_factory=tuple)
    request_id: Optional[str] = None
    # provenance: arg-name -> trust label ("trusted" | "untrusted_tool" | "untrusted_web")
    provenance: Dict[str, str] = field(default_factory=dict)
    extra: Dict[str, Any] = field(default_factory=dict)


Predicate = Callable[[CallContext], bool]
Trigger = Callable[[CallContext], bool]


# --------------------------------------------------------------------------- #
# Fluent predicate builders — keep policies readable.
# --------------------------------------------------------------------------- #
class Arg:
    """Reference an argument value, e.g. ``Arg("amount") <= 1000``."""

    def __init__(self, name: str) -> None:
        self._name = name

    def _val(self, ctx: CallContext) -> Any:
        return ctx.args.get(self._name)

    def __le__(self, other: Any) -> Predicate:
        return lambda c: (self._val(c) is not None) and self._val(c) <= other

    def __lt__(self, other: Any) -> Predicate:
        return lambda c: (self._val(c) is not None) and self._val(c) < other

    def __ge__(self, other: Any) -> Predicate:
        return lambda c: (self._val(c) is not None) and self._val(c) >= other

    def __gt__(self, other: Any) -> Predicate:
        return lambda c: (self._val(c) is not None) and self._val(c) > other

    def __eq__(self, other: Any) -> Predicate:  # type: ignore[override]
        return lambda c: self._val(c) == other

    def __ne__(self, other: Any) -> Predicate:  # type: ignore[override]
        return lambda c: self._val(c) != other

    def in_(self, allowed: Sequence[Any]) -> Predicate:
        allowed_set = set(allowed)
        return lambda c: self._val(c) in allowed_set

    def matches(self, pattern: str) -> Predicate:
        return lambda c: isinstance(self._val(c), str) and fnmatch.fnmatch(self._val(c), pattern)


class Provenance:
    """Reason about data provenance, e.g. ``Provenance("recipient") == "trusted"``."""

    def __init__(self, arg: str) -> None:
        self._arg = arg

    def __eq__(self, label: Any) -> Predicate:  # type: ignore[override]
        return lambda c: c.provenance.get(self._arg, "trusted") == label

    def __ne__(self, label: Any) -> Predicate:  # type: ignore[override]
        return lambda c: c.provenance.get(self._arg, "trusted") != label

    def is_trusted(self) -> Predicate:
        return lambda c: c.provenance.get(self._arg, "trusted") == "trusted"


class Taint:
    """Reason about a value's *propagated* information-flow label.

    Unlike :class:`Provenance` (which reads a label supplied at the call site),
    ``Taint`` reads the label the :class:`~capguard.provenance.ProvenanceTracker`
    carried forward through prior tool calls. A rule written with ``Taint`` holds
    across a whole laundering chain without the agent annotating anything:

        ``Rule(trigger=tool_is("send_email"), when=Taint("to").below("trusted"),
               effect=Effect.DENY)``

    blocks an email whose recipient was derived from web/tool output, even if the
    call site never tagged it.
    """

    def __init__(self, arg: str) -> None:
        self._arg = arg

    def _label(self, c: "CallContext") -> Label:
        return c.extra.get("labels", {}).get(self._arg, Label())

    def at_least(self, trust: str | Trust) -> Predicate:
        t = trust if isinstance(trust, Trust) else Trust.from_str(str(trust))
        return lambda c: self._label(c).trust >= t

    def below(self, trust: str | Trust) -> Predicate:
        t = trust if isinstance(trust, Trust) else Trust.from_str(str(trust))
        return lambda c: self._label(c).trust < t

    def is_untrusted(self) -> Predicate:
        return self.below(Trust.TRUSTED)

    def is_secret(self) -> Predicate:
        return lambda c: self._label(c).confidentiality >= Confidentiality.SECRET


class Flow:
    """Predicates over the data flowing into *any* argument of a call.

    The confidentiality companion to integrity checks: ``Flow.any_secret()`` is
    the deterministic "a secret must not reach this sink" rule — attach it as the
    trigger's ``when`` on exfiltration sinks (email/messaging/HTTP).
    """

    @staticmethod
    def _labels(c: "CallContext") -> Sequence[Label]:
        return list(c.extra.get("labels", {}).values())

    @staticmethod
    def any_secret() -> Predicate:
        return lambda c: any(l.confidentiality >= Confidentiality.SECRET for l in Flow._labels(c))

    @staticmethod
    def any_untrusted() -> Predicate:
        return lambda c: any(l.trust < Trust.TRUSTED for l in Flow._labels(c))

    @staticmethod
    def secret_present_and_untrusted_present() -> Predicate:
        """Secret data AND attacker-influenced data in the same call → exfil shape."""
        def _p(c: "CallContext") -> bool:
            labels = Flow._labels(c)
            return (any(l.confidentiality >= Confidentiality.SECRET for l in labels)
                    and any(l.trust < Trust.TRUSTED for l in labels))
        return _p


class Signal:
    """Read an advisory detector's signal in a policy predicate.

    Detectors (see ``capguard.detectors``) attach scored signals to the call
    context; ``Signal`` lets a rule act on them while the deterministic core
    stays the gate (deny-overrides means this can only tighten):

        ``Rule(when=Signal("prompt_injection").above(0.8), effect=Effect.REQUIRE_APPROVAL)``

    Reads ``ctx.extra['detectors']`` duck-typed (objects with ``.score`` / ``.label``),
    so the DSL has no dependency on the detector module.
    """

    def __init__(self, name: str) -> None:
        self._name = name

    def _sig(self, c: "CallContext") -> Any:
        return c.extra.get("detectors", {}).get(self._name)

    def above(self, threshold: float) -> Predicate:
        def _p(c: "CallContext") -> bool:
            s = self._sig(c)
            return s is not None and getattr(s, "score", 0.0) >= threshold
        return _p

    def at_or_below(self, threshold: float) -> Predicate:
        def _p(c: "CallContext") -> bool:
            s = self._sig(c)
            return s is not None and getattr(s, "score", 0.0) <= threshold
        return _p

    def flagged(self, threshold: float = 0.5) -> Predicate:
        def _p(c: "CallContext") -> bool:
            s = self._sig(c)
            return s is not None and (getattr(s, "score", 0.0) >= threshold or bool(getattr(s, "label", "")))
        return _p

    def label_is(self, label: str) -> Predicate:
        def _p(c: "CallContext") -> bool:
            s = self._sig(c)
            return s is not None and getattr(s, "label", "") == label
        return _p


def AND(*ps: Predicate) -> Predicate:
    return lambda c: all(p(c) for p in ps)


def OR(*ps: Predicate) -> Predicate:
    return lambda c: any(p(c) for p in ps)


def NOT(p: Predicate) -> Predicate:
    return lambda c: not p(c)


def role_in(*roles: str) -> Predicate:
    rs = set(roles)
    return lambda c: bool(rs.intersection(c.roles))


# --------------------------------------------------------------------------- #
# Triggers
# --------------------------------------------------------------------------- #
def tool_is(*names: str) -> Trigger:
    pats = list(names)
    return lambda c: any(fnmatch.fnmatch(c.tool_name, p) for p in pats)


ANY_TOOL: Trigger = lambda c: True  # noqa: E731


# --------------------------------------------------------------------------- #
# Rules + engine
# --------------------------------------------------------------------------- #
@dataclass
class Rule:
    name: str
    trigger: Trigger = ANY_TOOL
    when: Predicate = lambda c: True
    effect: Effect = Effect.DENY
    reason: str = ""
    # rate-limit params (only used when effect is RATE_LIMIT)
    max_calls: int = 0
    per_seconds: int = 60

    def fires(self, ctx: CallContext) -> bool:
        return self.trigger(ctx) and self.when(ctx)


@dataclass
class Decision:
    effect: Effect
    rule: Optional[str] = None
    reason: str = ""


class _RateLimiter:
    def __init__(self) -> None:
        self._hits: Dict[str, List[float]] = {}
        self._lock = threading.Lock()

    def over_limit(self, key: str, max_calls: int, per_seconds: int) -> bool:
        now = time.monotonic()
        with self._lock:
            window = [t for t in self._hits.get(key, []) if now - t < per_seconds]
            if len(window) >= max_calls:
                self._hits[key] = window
                return True
            window.append(now)
            self._hits[key] = window
            return False


class PolicyEngine:
    """Evaluates DSL rules with deny-overrides precedence."""

    def __init__(self, rules: Optional[List[Rule]] = None, default: Effect = Effect.ALLOW) -> None:
        self.rules = rules or []
        self.default = default
        self._rl = _RateLimiter()

    def add(self, rule: Rule) -> "PolicyEngine":
        self.rules.append(rule)
        return self

    def evaluate(self, ctx: CallContext) -> Decision:
        winner = Decision(effect=self.default, rule=None, reason="default")
        for rule in self.rules:
            if not rule.fires(ctx):
                continue
            effect = rule.effect
            if effect is Effect.RATE_LIMIT:
                key = f"{ctx.agent_id}:{rule.name}"
                if self._rl.over_limit(key, rule.max_calls, rule.per_seconds):
                    effect = Effect.DENY  # exceeding the budget hard-denies
                    reason = rule.reason or f"rate limit exceeded ({rule.max_calls}/{rule.per_seconds}s)"
                else:
                    continue  # within budget: this rule imposes no restriction
            else:
                reason = rule.reason or f"matched rule {rule.name!r}"
            if effect.restrictiveness > winner.effect.restrictiveness:
                winner = Decision(effect=effect, rule=rule.name, reason=reason)
        return winner
