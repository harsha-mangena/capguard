"""Budgets & quotas — cumulative resource caps (ASI08 / unbounded consumption).

Rate limits cap *frequency* (calls per window); a circuit breaker reacts to
*anomalies*. Neither caps **cumulative cost**. The 2026 failure mode this closes
is the doom spiral: an agent loops, each step cheap and individually allowed,
and the *total* — calls, tokens, dollars — runs away until a pipeline has burned
hundreds of thousands of tokens before anyone notices (OWASP ASI08 cascading
failures; LLM10 unbounded consumption; LLM06 excessive agency).

A :class:`Budget` sets ceilings on calls / tokens / cost (cumulative for a
session, or over a rolling window). A :class:`BudgetLedger` tracks spend per key
(agent, or agent:session) and refuses once a ceiling is hit. Wired into the
runtime it (a) **checks** before dispatch, (b) auto-charges one call after, and
(c) on overspend can **trip the circuit breaker** so the whole agent fails closed
— stopping the cascade at the source, exactly as the guidance prescribes.

Deterministic and thread-safe. Token/cost are reported by the application via
``AgentRuntime.report_usage`` (only the app knows a model's token count); call
count the runtime tracks itself.
"""

from __future__ import annotations

import threading
import time
from collections import deque
from dataclasses import dataclass
from typing import Callable, Deque, Dict, Optional, Tuple


@dataclass(frozen=True)
class Budget:
    max_calls: Optional[int] = None
    max_tokens: Optional[int] = None
    max_cost: Optional[float] = None
    window_seconds: Optional[float] = None   # None = cumulative for the ledger key's life

    def __post_init__(self) -> None:
        if all(v is None for v in (self.max_calls, self.max_tokens, self.max_cost)):
            raise ValueError("a Budget must cap at least one of calls/tokens/cost")


@dataclass
class Spend:
    calls: int = 0
    tokens: int = 0
    cost: float = 0.0

    def __add__(self, other: "Spend") -> "Spend":
        return Spend(self.calls + other.calls, self.tokens + other.tokens, self.cost + other.cost)


class BudgetExceeded(PermissionError):
    """Raised when a charge would exceed (or a check finds already-exceeded) a ceiling."""

    def __init__(self, key: str, dimension: str, used: float, limit: float) -> None:
        self.key = key
        self.dimension = dimension
        self.used = used
        self.limit = limit
        super().__init__(f"budget exceeded for {key!r}: {dimension} {used} > limit {limit}")


class BudgetLedger:
    """Tracks spend per key and enforces a :class:`Budget`. Thread-safe."""

    def __init__(self, budget: Budget, *, clock: Callable[[], float] = time.monotonic) -> None:
        self._budget = budget
        self._clock = clock
        self._lock = threading.Lock()
        # cumulative totals (window is None)
        self._totals: Dict[str, Spend] = {}
        # windowed events: key -> deque[(ts, Spend)]
        self._events: Dict[str, Deque[Tuple[float, Spend]]] = {}

    # ------------------------------------------------------------------ #
    def _windowed_spend(self, key: str) -> Spend:
        now = self._clock()
        cutoff = now - (self._budget.window_seconds or 0)
        dq = self._events.get(key)
        if dq is None:
            return Spend()
        while dq and dq[0][0] < cutoff:
            dq.popleft()
        total = Spend()
        for _, s in dq:
            total = total + s
        return total

    def spend(self, key: str) -> Spend:
        with self._lock:
            if self._budget.window_seconds is not None:
                return self._windowed_spend(key)
            t = self._totals.get(key)
            return Spend(t.calls, t.tokens, t.cost) if t else Spend()

    def _violation(self, key: str, s: Spend) -> Optional[BudgetExceeded]:
        b = self._budget
        if b.max_calls is not None and s.calls > b.max_calls:
            return BudgetExceeded(key, "calls", s.calls, b.max_calls)
        if b.max_tokens is not None and s.tokens > b.max_tokens:
            return BudgetExceeded(key, "tokens", s.tokens, b.max_tokens)
        if b.max_cost is not None and s.cost > b.max_cost:
            return BudgetExceeded(key, "cost", s.cost, b.max_cost)
        return None

    def check(self, key: str) -> None:
        """Pre-gate: raise if the key has *already* reached a ceiling.

        Uses a +1-call probe so that the call about to happen is admitted only if
        it stays within the call ceiling.
        """
        with self._lock:
            current = self._current_locked(key)
            probe = Spend(current.calls + 1, current.tokens, current.cost)
            exc = self._violation(key, probe)
            if exc is not None:
                raise exc

    def charge(self, key: str, *, calls: int = 0, tokens: int = 0, cost: float = 0.0) -> Spend:
        """Record spend; raise BudgetExceeded if the new total breaches a ceiling."""
        delta = Spend(calls, tokens, cost)
        with self._lock:
            if self._budget.window_seconds is not None:
                self._events.setdefault(key, deque()).append((self._clock(), delta))
                total = self._windowed_spend(key)
            else:
                total = self._totals.get(key, Spend()) + delta
                self._totals[key] = total
            exc = self._violation(key, total)
        if exc is not None:
            raise exc
        return total

    def _current_locked(self, key: str) -> Spend:
        if self._budget.window_seconds is not None:
            return self._windowed_spend(key)
        return self._totals.get(key, Spend())

    def reset(self, key: str) -> None:
        with self._lock:
            self._totals.pop(key, None)
            self._events.pop(key, None)
