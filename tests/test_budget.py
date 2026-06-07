"""Tests for budgets & quotas (ASI08 / unbounded consumption)."""

from __future__ import annotations

import pytest

from capguard import (
    AgentIdentity,
    AgentRuntime,
    Budget,
    BudgetExceeded,
    BudgetLedger,
    Capability,
    CircuitBreaker,
    Severity,
    ToolRegistry,
    ToolSpec,
)


# --------------------------------------------------------------------------- #
# ledger units
# --------------------------------------------------------------------------- #
def test_budget_requires_a_ceiling():
    with pytest.raises(ValueError):
        Budget()


def test_cumulative_calls_cap():
    led = BudgetLedger(Budget(max_calls=3))
    for _ in range(3):
        led.check("a")          # admitted
        led.charge("a", calls=1)
    with pytest.raises(BudgetExceeded) as ei:
        led.check("a")          # 4th probe exceeds
    assert ei.value.dimension == "calls"


def test_token_and_cost_charge_raise_when_over():
    led = BudgetLedger(Budget(max_tokens=100, max_cost=1.0))
    led.charge("a", tokens=80, cost=0.5)
    with pytest.raises(BudgetExceeded) as ei:
        led.charge("a", tokens=50)   # 130 > 100
    assert ei.value.dimension == "tokens"
    led2 = BudgetLedger(Budget(max_cost=1.0))
    led2.charge("a", cost=0.9)
    with pytest.raises(BudgetExceeded) as ei2:
        led2.charge("a", cost=0.2)
    assert ei2.value.dimension == "cost"


def test_keys_are_isolated_and_resettable():
    led = BudgetLedger(Budget(max_calls=1))
    led.check("a"); led.charge("a", calls=1)
    led.check("b"); led.charge("b", calls=1)   # different key, own budget
    with pytest.raises(BudgetExceeded):
        led.check("a")
    led.reset("a")
    led.check("a")                              # fresh again


def test_rolling_window_with_injected_clock():
    now = [1000.0]
    led = BudgetLedger(Budget(max_calls=2, window_seconds=60), clock=lambda: now[0])
    led.charge("a", calls=1); led.charge("a", calls=1)
    with pytest.raises(BudgetExceeded):
        led.check("a")            # 2 in window -> next exceeds
    now[0] += 61                  # window slides past both events
    led.check("a")                # allowed again


# --------------------------------------------------------------------------- #
# runtime integration
# --------------------------------------------------------------------------- #
def _rt(budget, *, breaker=None, trip=False):
    reg = ToolRegistry()
    reg.register(ToolSpec(name="work", capabilities=[Capability.custom("work")],
                          severity=Severity.LOW), lambda **k: "done")
    agent = AgentIdentity(id="bot", allowed_capabilities=[Capability.custom("work")])
    return AgentRuntime(registry=reg, default_agent=agent,
                        budget_ledger=BudgetLedger(budget), circuit_breaker=breaker,
                        trip_breaker_on_budget=trip), agent


def test_runtime_denies_over_call_budget():
    rt, _ = _rt(Budget(max_calls=2))
    assert rt.invoke_tool("work") == "done"
    assert rt.invoke_tool("work") == "done"
    with pytest.raises(BudgetExceeded):
        rt.invoke_tool("work")          # 3rd call blocked


def test_report_usage_enforces_token_budget():
    rt, agent = _rt(Budget(max_tokens=1000))
    rt.invoke_tool("work")
    rt.report_usage(agent, tokens=600)
    with pytest.raises(BudgetExceeded):
        rt.report_usage(agent, tokens=500)   # 1100 > 1000


def test_overspend_trips_breaker_and_halts_agent():
    breaker = CircuitBreaker()
    rt, agent = _rt(Budget(max_tokens=100), breaker=breaker, trip=True)
    rt.invoke_tool("work")
    with pytest.raises(BudgetExceeded):
        rt.report_usage(agent, tokens=200)    # blows token budget -> trips breaker
    assert breaker.is_open("bot")
    with pytest.raises(PermissionError):
        rt.invoke_tool("work")                # now halted by the kill switch


def test_budget_exceeded_is_permission_error():
    # so existing _BLOCKED handling / bench treats it as a block
    assert issubclass(BudgetExceeded, PermissionError)
