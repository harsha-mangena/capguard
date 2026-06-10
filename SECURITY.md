# Security Policy

CapGuard is a security tool, so we take vulnerabilities in it seriously.

## Reporting a vulnerability

**Please do not open a public issue for security bugs.**

Report privately via GitHub Security Advisories
("Security" tab → "Report a vulnerability") on
<https://github.com/harsha-mangena/capguard>, or email the maintainer listed in
`pyproject.toml`.

Include: affected version/commit, a minimal reproduction, and the impact (e.g.
"a capability-denied call is permitted", "the audit chain verifies after a
tamper", "a poisoned MCP tool reaches `tools/list`").

We aim to acknowledge within 72 hours and to ship a fix or mitigation for
confirmed high-severity issues promptly. We will credit reporters unless you ask
us not to.

## What counts as a vulnerability

Because CapGuard is an enforcement layer, the highest-severity classes are
**bypasses of the deterministic guarantees**, e.g.:

- a call that exceeds a granted capability is allowed (argument-enforcement bypass);
- attenuation expands authority (a delegated/attenuated grant gains power);
- a tampered audit chain passes `verify_chain`;
- a poisoned / rug-pulled / shadowed MCP tool reaches the client or executes;
- a signed identity / approval / task-scope / A2A message is forged, replayed, or
  over-claims authority;
- normalize-before-enforce is defeated (encoded payload slips past `enforce`).

## Supported versions

Pre-1.0: only the latest `main` / latest release is supported. Pin a version in
production and watch releases.
