"""Advisory detectors — the optional probabilistic layer behind the deterministic core.

CapGuard's gate is deterministic and that is non-negotiable: enforcement never
depends on a model guessing intent. But the deterministic layer composes *with*
probabilistic signals — this is the "deterministic-first, probabilistic-assist"
design from the strategy. A **detector** inspects a call and emits a
:class:`DetectorSignal` (a 0–1 score + optional label); the runtime attaches the
signals to the call context, and policy-DSL predicates (:class:`Signal`) can read
them — e.g. *"if the prompt-injection detector scores ≥ 0.8, require approval."*

The safety property is structural, not a promise: the policy engine is
**deny-overrides**, so a detector-driven rule can only ever *tighten* the
decision (deny / require-approval / rate-limit). There is no code path by which a
detector can loosen what the deterministic layer (capabilities, argument
enforcement, provenance, task scope) already decided. Detectors are also
**fail-open as detectors**: if one raises, its signal is simply absent — the
deterministic gates still run. This is exactly where a real PromptGuard2 /
AlignmentCheck / Llama classifier plugs in via :class:`CallableDetector`; the two
shipped detectors are dependency-free heuristics so the mechanism is useful and
testable out of the box.
"""

from __future__ import annotations

import re
from dataclasses import dataclass
from typing import Any, Callable, List, Optional, Protocol

from .policy_dsl import CallContext


@dataclass
class DetectorSignal:
    name: str
    score: float = 0.0           # 0.0 (clean) .. 1.0 (certain)
    label: str = ""              # optional category, e.g. "instruction_override"
    detail: str = ""

    def __post_init__(self) -> None:
        # keep scores in range so predicate thresholds behave
        self.score = max(0.0, min(1.0, float(self.score)))


class Detector(Protocol):
    name: str
    def inspect(self, ctx: CallContext) -> Optional[DetectorSignal]: ...


def _string_args(ctx: CallContext) -> List[str]:
    return [v for v in ctx.args.values() if isinstance(v, str)]


# --------------------------------------------------------------------------- #
# CallableDetector — wrap any function / model in one line
# --------------------------------------------------------------------------- #
class CallableDetector:
    """Adapt any ``fn(ctx) -> (score|DetectorSignal|None)`` into a Detector.

    This is the integration point for a real classifier::

        guard_detector = CallableDetector("prompt_injection",
            lambda ctx: promptguard2.score(" ".join(ctx.args.values())))
    """

    def __init__(self, name: str, fn: Callable[[CallContext], Any]) -> None:
        self.name = name
        self._fn = fn

    def inspect(self, ctx: CallContext) -> Optional[DetectorSignal]:
        out = self._fn(ctx)
        if out is None:
            return None
        if isinstance(out, DetectorSignal):
            return out
        if isinstance(out, (int, float)):
            return DetectorSignal(self.name, float(out))
        if isinstance(out, dict):
            return DetectorSignal(self.name, float(out.get("score", 0.0)),
                                  label=out.get("label", ""), detail=out.get("detail", ""))
        raise TypeError(f"detector {self.name!r} returned unsupported type {type(out)!r}")


# --------------------------------------------------------------------------- #
# Built-in heuristic detectors (no model dependency)
# --------------------------------------------------------------------------- #
_INJECTION_PATTERNS = [
    (re.compile(r"ignore\s+(all\s+|the\s+|any\s+)?(previous|prior|above|earlier)\s+(instruction|prompt|rule)", re.I), "instruction_override"),
    (re.compile(r"disregard\s+(all\s+|the\s+|your\s+)?(previous|prior|above|safety|system)", re.I), "instruction_override"),
    (re.compile(r"do\s+not\s+(tell|inform|mention|reveal|notify).{0,40}(user|human|operator)", re.I), "concealment"),
    (re.compile(r"(exfiltrate|leak|send|forward|upload).{0,40}(\.env|\.ssh|id_rsa|/etc/passwd|api[_\- ]?keys?|credential|secret|token)", re.I), "exfiltration"),
    (re.compile(r"you\s+must\s+(also\s+)?(call|invoke|use|run|execute)", re.I), "coerced_tool_use"),
]


class RegexInjectionDetector:
    """Heuristic prompt-injection detector over string arguments."""

    def __init__(self, name: str = "prompt_injection") -> None:
        self.name = name

    def inspect(self, ctx: CallContext) -> Optional[DetectorSignal]:
        blob = "\n".join(_string_args(ctx))
        if not blob:
            return None
        hits = [label for pat, label in _INJECTION_PATTERNS if pat.search(blob)]
        if not hits:
            return DetectorSignal(self.name, 0.0)
        score = min(1.0, 0.5 * len(hits) + 0.4)   # 1 hit -> 0.9, 2+ -> 1.0
        return DetectorSignal(self.name, score, label=hits[0],
                              detail=f"matched: {', '.join(sorted(set(hits)))}")


_PII_PATTERNS = [
    (re.compile(r"[A-Za-z0-9._%+\-]+@[A-Za-z0-9.\-]+\.[A-Za-z]{2,}"), "email"),
    (re.compile(r"\b\d{3}-\d{2}-\d{4}\b"), "ssn"),
    (re.compile(r"\b(?:\d[ \-]?){13,16}\b"), "card"),
    (re.compile(r"\b(?:sk-[A-Za-z0-9]{16,}|AKIA[0-9A-Z]{16}|ghp_[A-Za-z0-9]{20,})\b"), "api_key"),
]


class PIIDetector:
    """Heuristic detector for emails / SSNs / cards / API keys in arguments."""

    def __init__(self, name: str = "pii") -> None:
        self.name = name

    def inspect(self, ctx: CallContext) -> Optional[DetectorSignal]:
        blob = "\n".join(_string_args(ctx))
        if not blob:
            return None
        kinds = sorted({label for pat, label in _PII_PATTERNS if pat.search(blob)})
        if not kinds:
            return DetectorSignal(self.name, 0.0)
        return DetectorSignal(self.name, 0.8, label=kinds[0], detail=f"detected: {', '.join(kinds)}")
