# Contributing to CapGuard

Thanks for helping make least-privilege for AI agents real and enforced.

## Dev setup

```bash
git clone https://github.com/harsha-mangena/capguard
cd capguard
pip install -e ".[dev,yaml]"
pytest -q                 # full suite; optional integrations may self-skip
ruff check capguard tests examples
capguard bench            # security benchmark gate (must stay ASR 0 / utility 100)
```

## The bar for a PR

CapGuard is a security kernel, so every change keeps these invariants:

1. **Deterministic-first.** Enforcement never depends on a model guessing intent.
   Classifiers are advisory detectors only; they can tighten, never loosen.
2. **Least privilege by construction.** Capabilities only narrow. Attenuation and
   delegation must never expand authority.
3. **Prove it.** Every security claim has a test. New mechanisms add tests; the
   benchmark (`capguard bench`) must still report **ASR 0% / utility 100%**, and
   the property tests (`tests/test_properties.py`) must hold.
4. **Fail closed.** When in doubt, deny. A guard that fails open is a bug.

## Checklist

- [ ] `ruff check` clean
- [ ] `pytest -q` green (add tests for your change)
- [ ] `capguard bench` still 0% ASR / 100% utility
- [ ] Docs / README updated if behavior changed
- [ ] No raw payloads written to the audit log (digests only)

## Releases

The PyPI distribution is `capguard-runtime`; imports and the CLI remain
`capguard`. Use [`RELEASE.md`](RELEASE.md) for the release checklist. The
release workflow publishes only from version tags through PyPI Trusted
Publishing.

## Commit style

Conventional-ish: `feat:`, `fix:`, `docs:`, `chore:`, `test:`. Keep the subject
imperative and scoped.
