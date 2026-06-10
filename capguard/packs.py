"""Policy-pack compiler — declarative security profiles as data, not code.

A pack is a small YAML/JSON/dict document that compiles to a ready
:class:`~capguard.policy_dsl.PolicyEngine` (and, optionally, a set of capability
templates for the agent). It is the GTM/content surface from the strategy memo:
ship vetted profiles (OWASP baseline, finance, data-exfil, coding-agent, browser-
agent) so adopting a strong default is a one-line import rather than a DSL
tutorial.

The compiler is a thin, total mapping onto the existing predicate builders
(``Arg`` / ``Provenance`` / ``Taint`` / ``Flow`` / ``role_in`` and ``AND/OR/NOT``)
— packs cannot express anything the typed DSL can't, so there is no second, less-
audited evaluation path. Deny-overrides precedence is inherited from the engine:
a pack can only tighten.

Pack schema (all sections optional except ``rules``)::

    name: finance-baseline
    description: ...
    capabilities:                 # optional agent capability templates
      - {type: custom, name: transfer}
      - {type: network_http, domains: ["api.corp.com"]}
    rules:
      - name: large-transfer
        tools: ["transfer", "send_money"]      # fnmatch globs; omit => any tool
        when: {arg: amount, op: ">", value: 1000}
        effect: require_approval
        reason: large money movement
      - name: untrusted-recipient
        tools: ["transfer", "send_email"]
        when: {taint: recipient, is: untrusted}
        effect: deny
      - name: secret-to-sink
        tools: ["send_*", "post_*"]
        when: {flow: any_secret}
        effect: deny
      - name: global-rate
        effect: rate_limit
        max_calls: 100
        per_seconds: 60

Predicate forms accepted in ``when``:
  * ``{arg, op, value}``  op ∈ < <= > >= == != in matches
  * ``{provenance, is: trusted|untrusted}`` | ``{provenance, equals|not_equals: <label>}``
  * ``{taint, is: untrusted|secret}`` | ``{taint, at_least: trusted|untrusted_tool|untrusted_web}``
  * ``{flow: any_secret|any_untrusted|secret_and_untrusted}``
  * ``{role_in: [...]}``
  * ``{all: [...]}`` / ``{any: [...]}`` / ``{not: {...}}``
"""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any, Dict, List, Mapping, Optional, Union

from .core import Capability
from .policy_dsl import (
    AND,
    ANY_TOOL,
    NOT,
    OR,
    Arg,
    Effect,
    Flow,
    PolicyEngine,
    Predicate,
    Provenance,
    Rule,
    Taint,
    role_in,
    tool_is,
)

PackSource = Union[str, Path, Mapping[str, Any]]


class PackError(ValueError):
    pass


# --------------------------------------------------------------------------- #
# predicate compilation
# --------------------------------------------------------------------------- #
_ARG_OPS = {
    "<": lambda a, v: a < v,
    "<=": lambda a, v: a <= v,
    ">": lambda a, v: a > v,
    ">=": lambda a, v: a >= v,
    "==": lambda a, v: a == v,
    "!=": lambda a, v: a != v,
    "in": lambda a, v: a.in_(v),
    "matches": lambda a, v: a.matches(v),
}
_FLOWS = {
    "any_secret": Flow.any_secret,
    "any_untrusted": Flow.any_untrusted,
    "secret_and_untrusted": Flow.secret_present_and_untrusted_present,
}


def _compile_predicate(spec: Optional[Mapping[str, Any]]) -> Predicate:
    if not spec:
        return lambda c: True
    if "all" in spec:
        return AND(*[_compile_predicate(s) for s in spec["all"]])
    if "any" in spec:
        return OR(*[_compile_predicate(s) for s in spec["any"]])
    if "not" in spec:
        return NOT(_compile_predicate(spec["not"]))
    if "role_in" in spec:
        return role_in(*spec["role_in"])
    if "flow" in spec:
        try:
            return _FLOWS[spec["flow"]]()
        except KeyError as exc:
            raise PackError(f"unknown flow predicate {spec['flow']!r}") from exc
    if "provenance" in spec:
        arg = spec["provenance"]
        if spec.get("is") == "trusted":
            return Provenance(arg).is_trusted()
        if spec.get("is") == "untrusted":
            return NOT(Provenance(arg).is_trusted())
        if "equals" in spec:
            return Provenance(arg) == spec["equals"]
        if "not_equals" in spec:
            return Provenance(arg) != spec["not_equals"]
        raise PackError(f"provenance predicate needs is/equals/not_equals: {spec}")
    if "taint" in spec:
        arg = spec["taint"]
        if spec.get("is") == "untrusted":
            return Taint(arg).is_untrusted()
        if spec.get("is") == "secret":
            return Taint(arg).is_secret()
        if "at_least" in spec:
            return Taint(arg).at_least(spec["at_least"])
        raise PackError(f"taint predicate needs is/at_least: {spec}")
    if "arg" in spec:
        try:
            builder = _ARG_OPS[spec["op"]]
        except KeyError as exc:
            raise PackError(f"unknown arg op {spec.get('op')!r}") from exc
        return builder(Arg(spec["arg"]), spec["value"])
    raise PackError(f"unrecognized predicate spec: {spec!r}")


def _compile_rule(spec: Mapping[str, Any]) -> Rule:
    if "name" not in spec:
        raise PackError(f"rule is missing a name: {spec!r}")
    tools = spec.get("tools")
    trigger = tool_is(*tools) if tools else ANY_TOOL
    try:
        effect = Effect(spec.get("effect", "deny"))
    except ValueError as exc:
        raise PackError(f"unknown effect {spec.get('effect')!r}") from exc
    return Rule(
        name=spec["name"],
        trigger=trigger,
        when=_compile_predicate(spec.get("when")),
        effect=effect,
        reason=spec.get("reason", ""),
        max_calls=int(spec.get("max_calls", 0)),
        per_seconds=int(spec.get("per_seconds", 60)),
    )


# --------------------------------------------------------------------------- #
# capability templates
# --------------------------------------------------------------------------- #
def _compile_capability(spec: Mapping[str, Any]) -> Capability:
    t = spec.get("type")
    if t == "network_http":
        return Capability.network_http(domains=spec.get("domains", []), arg=spec.get("arg", "url"))
    if t == "file_read":
        return Capability.file_read(paths=spec.get("paths", []), arg=spec.get("arg", "path"))
    if t == "file_write":
        return Capability.file_write(paths=spec.get("paths", []), arg=spec.get("arg", "path"))
    if t == "shell_exec":
        return Capability.shell_exec(timeout=int(spec.get("timeout", 30)),
                                     allowlist=spec.get("allowlist", []), arg=spec.get("arg", "cmd"))
    if t == "db_query":
        return Capability.db_query(read_only=bool(spec.get("read_only", True)), arg=spec.get("arg", "query"))
    if t == "custom":
        params = {k: v for k, v in spec.items() if k not in ("type", "name")}
        return Capability.custom(spec["name"], **params)
    raise PackError(f"unknown capability type {t!r}")


# --------------------------------------------------------------------------- #
# loading + compiling
# --------------------------------------------------------------------------- #
def load_pack(src: PackSource) -> Dict[str, Any]:
    """Resolve a pack source (dict, builtin name, or path) to a pack dict."""
    if isinstance(src, Mapping):
        return dict(src)
    name = str(src)
    if name in BUILTIN_PACKS:
        return dict(BUILTIN_PACKS[name])
    path = Path(name)
    if not path.exists():
        raise PackError(f"unknown pack {name!r}: not a builtin and not a file. "
                        f"Builtins: {sorted(BUILTIN_PACKS)}")
    text = path.read_text(encoding="utf-8")
    if path.suffix in (".yaml", ".yml"):
        try:
            import yaml
        except Exception as exc:  # noqa: BLE001
            raise PackError("PyYAML is required for YAML packs (pip install pyyaml)") from exc
        return yaml.safe_load(text)
    return json.loads(text)


def compile_pack(src: PackSource) -> PolicyEngine:
    """Compile a pack into a ready PolicyEngine (rules only)."""
    pack = load_pack(src)
    engine = PolicyEngine()
    for r in pack.get("rules", []):
        engine.add(_compile_rule(r))
    return engine


def pack_capabilities(src: PackSource) -> List[Capability]:
    """Compile a pack's optional capability templates."""
    pack = load_pack(src)
    return [_compile_capability(c) for c in pack.get("capabilities", [])]


# --------------------------------------------------------------------------- #
# Built-in packs (shipped as data — no file dependency)
# --------------------------------------------------------------------------- #
_SINKS = ["send_*", "post_*", "reserve_*", "transfer", "send_money", "delete_*", "share_*"]

BUILTIN_PACKS: Dict[str, Dict[str, Any]] = {
    "owasp-baseline": {
        "name": "owasp-baseline",
        "description": "General ASI defense: no untrusted data or secrets into sinks; global rate cap.",
        "rules": [
            {"name": "no-untrusted-into-sink", "tools": _SINKS,
             "when": {"flow": "any_untrusted"}, "effect": "deny",
             "reason": "a sink fed by untrusted/injected data"},
            {"name": "no-secret-into-sink", "tools": _SINKS,
             "when": {"flow": "any_secret"}, "effect": "deny",
             "reason": "a secret must not reach a sink"},
            {"name": "global-rate", "effect": "rate_limit", "max_calls": 300, "per_seconds": 60,
             "reason": "global per-agent call budget"},
        ],
    },
    "finance": {
        "name": "finance",
        "description": "Money movement: cap amounts, require human review over a limit, block untrusted payees.",
        "rules": [
            {"name": "large-transfer", "tools": ["transfer", "send_money", "schedule_transaction"],
             "when": {"arg": "amount", "op": ">", "value": 1000},
             "effect": "require_approval", "reason": "transfer over limit"},
            {"name": "untrusted-recipient",
             "tools": ["transfer", "send_money", "schedule_transaction"],
             "when": {"taint": "recipient", "is": "untrusted"}, "effect": "deny",
             "reason": "payee derived from untrusted/injected data"},
            {"name": "money-rate", "tools": ["transfer", "send_money"],
             "effect": "rate_limit", "max_calls": 10, "per_seconds": 60,
             "reason": "money-movement velocity cap"},
        ],
    },
    "data-exfil": {
        "name": "data-exfil",
        "description": "Block the classic exfiltration shape: secret data flowing to an outbound sink.",
        "rules": [
            {"name": "secret-to-sink", "tools": _SINKS,
             "when": {"flow": "any_secret"}, "effect": "deny",
             "reason": "secret data to an outbound sink"},
            {"name": "secret-and-untrusted", "tools": ["*"],
             "when": {"flow": "secret_and_untrusted"}, "effect": "deny",
             "reason": "secret + attacker-influenced data in the same call"},
        ],
    },
}


def builtin_pack_names() -> List[str]:
    return sorted(BUILTIN_PACKS)
