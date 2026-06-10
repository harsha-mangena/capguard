## What & why

<!-- One or two sentences. Link the issue if any. -->

## Security invariants (CapGuard is a security kernel)

- [ ] Deterministic-first preserved (no new probabilistic gate)
- [ ] Capabilities only narrow (no authority expansion via attenuation/delegation)
- [ ] `ruff check` clean and `pytest -q` green (tests added for the change)
- [ ] `capguard bench` still **ASR 0% / utility 100%**
- [ ] Fails closed on error; no raw payloads in the audit log

## Notes for reviewers

<!-- Anything subtle: threat model, crypto, tenant isolation, perf. -->
