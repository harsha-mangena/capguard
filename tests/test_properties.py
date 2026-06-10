"""Property-based + fuzz tests (P5) — machine-checked security invariants.

Unit tests prove specific cases; these prove *laws* over a large random input
space with Hypothesis. For a security kernel the laws are the product:

  * the information-flow lattice is a real join-semilattice (commutative,
    associative, idempotent, identity, monotone);
  * capability coverage is exactly the subset/refinement relation, and
    enforcement never permits a value outside the grant (no privilege
    expansion);
  * the audit hash-chain is intact for any well-formed sequence and breaks under
    any single-field tamper;
  * normalize-before-enforce rejects smuggled control/format characters.
"""

from __future__ import annotations

import pytest
from hypothesis import given
from hypothesis import strategies as st

from capguard import Confidentiality, Label, Trust
from capguard.audit import AuditEvent, MemorySink, verify_chain
from capguard.core import Capability, CapabilityViolation, PolicyDecision

# --------------------------------------------------------------------------- #
# strategies
# --------------------------------------------------------------------------- #
trusts = st.sampled_from(list(Trust))
confs = st.sampled_from(list(Confidentiality))
labels = st.builds(Label, trust=trusts, confidentiality=confs)

DOMAINS = ["a.com", "b.com", "c.com", "api.x.io", "evil.com"]
domain_sets = st.lists(st.sampled_from(DOMAINS), max_size=5)
CMDS = ["ls", "cat", "echo", "rm", "curl", "git"]
cmd_sets = st.lists(st.sampled_from(CMDS), max_size=5)


# --------------------------------------------------------------------------- #
# 1. lattice laws
# --------------------------------------------------------------------------- #
@given(labels, labels)
def test_combine_commutative(a, b):
    assert a.combine(b) == b.combine(a)


@given(labels, labels, labels)
def test_combine_associative(a, b, c):
    assert a.combine(b).combine(c) == a.combine(b.combine(c))


@given(labels)
def test_combine_idempotent(a):
    assert a.combine(a) == a


@given(labels)
def test_default_is_identity(a):
    assert Label().combine(a) == a


@given(labels, labels)
def test_combine_is_monotone(a, b):
    c = a.combine(b)
    # integrity only ever drops; confidentiality only ever rises
    assert c.trust <= a.trust and c.trust <= b.trust
    assert c.confidentiality >= a.confidentiality and c.confidentiality >= b.confidentiality


# --------------------------------------------------------------------------- #
# 2. capability coverage == subset, and enforcement never expands authority
# --------------------------------------------------------------------------- #
@given(domain_sets, domain_sets)
def test_network_covers_iff_subset(granted, req):
    g = Capability.network_http(domains=granted)
    r = Capability.network_http(domains=req)
    assert g.covers(r) == set(req).issubset(set(granted))


@given(domain_sets, st.sampled_from(DOMAINS))
def test_network_enforce_stays_within_grant(granted, host):
    cap = Capability.network_http(domains=granted)
    url = f"https://{host}/p"
    if host in set(granted):
        cap.enforce(url)  # must not raise
    else:
        with pytest.raises(CapabilityViolation):
            cap.enforce(url)


@given(domain_sets, domain_sets, st.sampled_from(DOMAINS))
def test_network_no_expansion_under_attenuation(small, extra, host):
    """If a narrow grant permits a host, any broader grant also permits it."""
    narrow = Capability.network_http(domains=small)
    broad = Capability.network_http(domains=list(set(small) | set(extra)))
    assert broad.covers(narrow)  # broad ⊇ narrow
    try:
        narrow.enforce(f"https://{host}/p")
    except CapabilityViolation:
        return  # narrow rejected it; nothing to compare
    broad.enforce(f"https://{host}/p")  # broader must also accept


@given(cmd_sets, cmd_sets)
def test_shell_covers_iff_subset(granted, req):
    g = Capability.shell_exec(allowlist=granted, timeout=30)
    r = Capability.shell_exec(allowlist=req, timeout=10)
    assert g.covers(r) == set(req).issubset(set(granted))


@given(cmd_sets, st.sampled_from(CMDS))
def test_shell_enforce_stays_within_allowlist(allow, prog):
    cap = Capability.shell_exec(allowlist=allow, timeout=30)
    if prog in set(allow):
        cap.enforce(f"{prog} -x")
    else:
        with pytest.raises(CapabilityViolation):
            cap.enforce(f"{prog} -x")


# --------------------------------------------------------------------------- #
# 3. audit hash-chain integrity
# --------------------------------------------------------------------------- #
def _seal_n(n):
    sink = MemorySink()
    for i in range(n):
        sink(AuditEvent(agent_id="a", tool_name=f"t{i}", decision=PolicyDecision.ALLOW))
    return sink


@given(st.integers(min_value=1, max_value=25))
def test_audit_chain_intact_for_any_length(n):
    assert verify_chain(_seal_n(n).events)


@given(st.integers(min_value=1, max_value=15), st.integers(min_value=0))
def test_audit_single_field_tamper_is_detected(n, idx):
    sink = _seal_n(n)
    i = idx % n
    sink.events[i].tool_name = sink.events[i].tool_name + "_TAMPERED"
    assert not verify_chain(sink.events)


# --------------------------------------------------------------------------- #
# 4. normalize-before-enforce: smuggling is rejected
# --------------------------------------------------------------------------- #
SMUGGLE = ["\u200b", "\u200c", "\u200d", "\ufeff", "\u202e", "\x00", "\u0007", "\u00ad"]


@given(st.sampled_from(SMUGGLE))
def test_url_smuggling_rejected(ch):
    cap = Capability.network_http(domains=["a.com"])
    with pytest.raises(CapabilityViolation):
        cap.enforce(f"https://a.com/{ch}x")


@given(st.sampled_from(SMUGGLE))
def test_path_smuggling_rejected(ch):
    cap = Capability.file_read(paths=["/tmp/*"])
    with pytest.raises(CapabilityViolation):
        cap.enforce(f"/tmp/{ch}file")


@given(st.sampled_from(SMUGGLE))
def test_shell_smuggling_rejected(ch):
    cap = Capability.shell_exec(allowlist=["ls"], timeout=30)
    with pytest.raises(CapabilityViolation):
        cap.enforce(f"ls{ch} -l")


def test_fullwidth_metachar_is_normalized_then_blocked():
    """A fullwidth semicolon (U+FF1B) folds to ';' under NFKC → metachar block."""
    cap = Capability.shell_exec(allowlist=["ls"], timeout=30)
    with pytest.raises(CapabilityViolation):
        cap.enforce("ls ； rm -rf /")


def test_trailing_dot_host_does_not_bypass_domain_check():
    """`evil.com.` must not slip past an `a.com` allow-list."""
    cap = Capability.network_http(domains=["a.com"])
    with pytest.raises(CapabilityViolation):
        cap.enforce("https://evil.com./x")
    cap.enforce("https://a.com./ok")  # trusted host with trailing dot still ok
