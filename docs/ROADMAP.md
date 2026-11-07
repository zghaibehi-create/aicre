# AICRE Roadmap

This roadmap separates implemented behavior from planned work and release approval.

## Implemented on main
- **0.1 security hardening:** descriptor-relative directory scanning, conservative sensitive-path policy, private atomic reports, locked CI, and regression coverage.
- **0.2 Linux inventory preview:** local system metadata, allowlisted PATH-only tool discovery without execution, explicit Linux/Python compatibility checks, five separate readiness dimensions, versioned JSON Schema, cooperative timeouts, and CLI reporting.

## Current work
- **0.3 workload-profile foundation (under review):** host-facing resource observations and PATH-presence checks for required tools in the documented `agent-development` baseline. Resource readiness remains `unknown` until effective process/container limits can be established; software readiness reflects PATH presence only. The `standard` profile remains inventory-only. This does not audit agent configuration, MCP permissions, sandboxing, or host security posture.
- **Known limitation:** CPU, RAM, and root-storage observations are host-facing and do not establish effective process/container limits, cgroup quotas, CPU affinity, orchestrator reservations, or filesystem quotas. Resource readiness therefore remains `unknown`; the reference thresholds are not used to claim a resource pass or fail. Effective-resource assessment is deferred until its evidence can be measured safely and tested.

## Next engineering phases
- **0.3 security intelligence:** threat model and narrowly scoped metadata-only checks for agent/tool configuration, MCP trust and permission exposure, execution boundaries, and dependency provenance. No configuration is executed or changed.
- **0.4 compatibility catalog:** evidence-backed, version-aware requirements for selected agent runtimes; unknown states are explicit.
- **0.5 guided remediation plans:** recommendations and preview-only diffs; any system-changing action requires explicit per-action approval and rollback design.
- **1.x broader platforms:** Windows/macOS only after separate implementations and target-environment CI; GUI after core contracts stabilize.

## Release gates
A green CI run is necessary but insufficient. Each phase requires code review, privacy and threat-model review, regression tests, target-environment integration tests, documented residual risks, and a release decision. Planned features are not implemented merely because they appear here.

## Permanent non-goals unless explicitly redesigned
No telemetry, cloud upload of machine inventories, undisclosed network activity, automatic installation/remediation, autonomous agent execution, vendor lock-in, or silent weakening of exclusions.
