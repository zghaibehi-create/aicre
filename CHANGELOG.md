# Changelog

## 0.2.1

- Accept semantic patch versions and new lowercase profile names in the v2
  report schema while retaining schema version `2.0`.
- Require at least one finding in a readiness report; generated reports are
  covered by tests confirming they always contain findings.
- Add the `laptop-dev`, `agent-workstation`, and `ci-runner` profiles while
  retaining `standard` and `agent-development`.
- Evaluate Resource and Software readiness against the selected profile,
  including fail, warning, pass, and unknown outcomes.
- Add opt-in `aicre report --composite` output to write a separate
  `report.summary.json` beside the main report.
- Document every emitted finding ID and its value contract in
  `docs/finding-ids.md`.
- Keep runtime dependencies empty and preserve local-only, read-only,
  no-network, no-secrets, and no-execution collection boundaries.
