# AICRE Roadmap

This roadmap separates implemented behavior from planned work and release approval.

## Implemented on main
- **0.1 security hardening:** descriptor-relative directory scanning, conservative sensitive-path policy, private atomic reports, locked CI, and regression coverage.
- **0.2 Linux inventory preview:** local system metadata, allowlisted PATH-only tool discovery without execution, explicit Linux/Python compatibility checks, five separate readiness dimensions, versioned JSON Schema, cooperative timeouts, and CLI reporting.
- **0.3 bounded directory scanning (implemented on main):** per-directory and total-item limits, deterministic completed output, explicit partial-report semantics, and a versioned directory-scan JSON Schema. These cardinality bounds do not constitute a hard byte-level memory ceiling.

## Current work
- **0.3 workload-profile foundation (implemented on main):** host-facing resource observations and required-tool PATH checks for workload profiles; Resource readiness remains `unknown` until effective limits are established. The `standard` profile remains inventory-only. This does not audit agent configuration, MCP permissions, sandboxing, or host security posture.
- **0.3.0 release preparation:** residual risks and their engineering dispositions are recorded in [the release-readiness register](RELEASE_READINESS.md). Release preparation is not publication approval; publication requires the owner's recorded go/no-go decision. For this release the owner chose an AI-assisted internal security review in place of an external review (not an independent audit or certification) and accepted the Ubuntu 22.04/24.04 CI matrix as Linux acceptance evidence. See RELEASE_READINESS.md and LINUX_ACCEPTANCE.md.
- **Known limitation:** the initial resource baseline is host-observation-only. It does not yet account for cgroup CPU/memory limits or CPU affinity, so it must not be marketed as container-aware readiness.

## Next engineering phases
- **0.3 security intelligence:** threat model and narrowly scoped metadata-only checks for agent/tool configuration, MCP trust and permission exposure, execution boundaries, and dependency provenance. No configuration is executed or changed.
- **0.4 compatibility catalog:** evidence-backed, version-aware requirements for selected agent runtimes; unknown states are explicit.
- **0.5 guided remediation plans:** recommendations and preview-only diffs; any system-changing action requires explicit per-action approval and rollback design.
- **1.x broader platforms:** Windows/macOS only after separate implementations and target-environment CI; GUI after core contracts stabilize.

## Release gates
A green CI run is necessary but insufficient. Each phase requires code review, privacy and threat-model review, regression tests, target-environment integration tests, documented residual risks, and a release decision. Planned features are not implemented merely because they appear here.

## Permanent non-goals unless explicitly redesigned
No telemetry, cloud upload of machine inventories, undisclosed network activity, automatic installation/remediation, autonomous agent execution, vendor lock-in, or silent weakening of exclusions.
