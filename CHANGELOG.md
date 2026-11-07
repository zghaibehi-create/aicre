# Changelog

## 0.3.0 (unreleased candidate — not approved for publication)

This section is a release-note draft. The package version remains 0.2.1 until the
mandatory release gates in [RELEASE_READINESS.md](docs/RELEASE_READINESS.md)
are complete and the project owner gives an explicit go decision.

- Add workload-profile foundations for `standard`, `agent-development`,
  `laptop-dev`, `agent-workstation`, and `ci-runner`, with five independent
  readiness dimensions and no composite score.
- Preserve host-facing CPU, memory, and storage observations without treating
  them as effective process/container capacity; Resource readiness remains
  `unknown` when effective limits cannot be established.
- Bound directory enumeration by default to 25,000 included items and 5,000
  entries buffered per directory; report incomplete scans explicitly and
  return a nonzero CLI status for incomplete directory scans.
- Add/align directory-scan report schema v2 and document finding identifiers,
  collection boundaries, limitations, and residual risks.
- Expand automated Linux validation and clean wheel-install smoke coverage to
  Ubuntu 22.04 and 24.04 with Python 3.11, 3.12, and 3.13.
- Keep runtime dependencies empty and preserve local-first, metadata-only,
  no-network, no-telemetry, no-secret-content-read, and no-program-execution
  boundaries.

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
