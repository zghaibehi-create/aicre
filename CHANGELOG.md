# Changelog

## 0.2.1

- Accept semantic patch versions and new lowercase profile names in the v2
  report schema while retaining schema version `2.0`.
- Require at least one finding in a readiness report; generated reports are
  covered by tests confirming they always contain findings.
- Add the `laptop-dev`, `agent-workstation`, and `ci-runner` profiles while
  retaining `standard` and `agent-development`.
- Evaluate Software readiness against the selected profile; retain host-facing
  resource observations without using them to pass or fail Resource readiness.
- Document every emitted finding ID and its value contract in
  `docs/finding-ids.md`.
- Keep runtime dependencies empty and preserve local-only, read-only,
  no-network, no-secrets, and no-execution collection boundaries.
