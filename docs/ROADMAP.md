# AICRE Roadmap and Scope

AICRE's feature scope is frozen and complete as a Linux-first, local environment inventory and readiness CLI. Version 0.4.0 was published as the final scoped release on 2026-11-09; no additional feature roadmap is planned.

## Completed product scope

- Local Linux system metadata inventory and fixed allowlist PATH discovery; discovered programs are identified, never executed.
- Five separate readiness dimensions and named workload profiles. No composite score is produced, and unknown remains distinct from fail.
- Metadata-only directory inventory with bounded cardinality, explicit incomplete-scan reporting, and schema-versioned JSON.
- Versioned readiness reports, canonical report identities, strict JSON import validation, JSON/Markdown/offline HTML and optional PDF output, and snapshot comparison.
- Local report publication with private POSIX permissions, atomic writes, overwrite consent, and symlink/special-file protections.
- Linux/Python compatibility evidence for Ubuntu 22.04 and 24.04 with Python 3.11, 3.12, and 3.13 in CI.

The scope is intentionally narrow. AICRE does not establish effective container/cgroup resource limits, host security posture, safe agent execution, or complete secret detection. These limitations remain documented rather than being treated as unfinished feature requirements.

## Explicitly out of scope; no features planned

The following are not release gates, planned phases, or work items for AICRE:

- Security Intelligence or broader agent/tool configuration, MCP trust/permission, or dependency-provenance assessment.
- Compatibility Catalogs or version-aware vendor/runtime support matrices.
- Guided Remediation, automatic changes, or remediation previews.
- Windows or macOS support.
- A graphical interface.
- New MCP or agent integrations. The existing agent skill is usage documentation, not an integration.
- Architectural redesign for its own sake.

PR [#39](https://github.com/zghaibehi-create/aicre/pull/39), which proposed a future Security Intelligence specification, was closed unmerged on 2026-11-09 under this scope decision. Its history remains available for reference; it is not a requirement for project completion.

## Maintenance policy

After the scoped release, accept only necessary, evidence-backed fixes for confirmed security, privacy, correctness, backward-compatibility, reliability, or packaging defects. Every behavior change must have a regression test and preserve the documented privacy boundaries. Do not use maintenance work to introduce the out-of-scope capabilities above.

## Release state

- `v0.3.0` remains the historical experimental GitHub pre-release published on 2026-11-07. Its tag is immutable and does not contain the later reporting/diff implementation.
- `v0.4.0` is the final scoped release, published at [GitHub Release v0.4.0](https://github.com/zghaibehi-create/aicre/releases/tag/v0.4.0) from merge commit `9a2300e3bddd7badc9dd25b3d493bc5481e79027`. PR #40 is merged; the release includes the reporting/diff implementation, import-safety fix, and verified wheel/sdist/checksum assets.
- The project has no future feature phases. The roadmap is maintenance-only: accept only necessary, evidence-backed fixes for confirmed security, privacy, correctness, compatibility, reliability, or packaging defects.

See [RELEASE_READINESS.md](RELEASE_READINESS.md), [SECURITY_MODEL.md](SECURITY_MODEL.md), and [LINUX_ACCEPTANCE.md](LINUX_ACCEPTANCE.md) for the release gates, privacy boundaries, residual risks, and test evidence.
