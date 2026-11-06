# AICRE Roadmap

This roadmap distinguishes implemented work from release approval; a passing build is not a production-readiness claim.

- **AICRE 0.1 Linux preview and security hardening — merged:** descriptor-relative scanner hardening, conservative path policy, private atomic reports, locked CI, and regression coverage. This remains an experimental tool.
- **AICRE 0.2 Linux inventory/readiness — implementation in progress:** local system metadata, allowlisted non-executing tool discovery, explicit Linux/Python compatibility checks, five independent readiness dimensions, and a versioned JSON Schema. Resource and software baselines remain unknown until workload requirements are defined; no composite score is planned.
- **0.2 release gate — pending:** Linux CI on the supported Python matrix, verified read-only behavior, privacy/exclusion and schema tests, updated limitations, and independent review. Do not describe 0.2 as release-ready until each criterion is verified.
- **Future scope:** a configurable workload requirements profile, additional reviewed local metadata sources, packaging/signing, and broader platform feasibility work.
- **Non-goals:** no Windows/macOS support claim, GUI, autonomous agent execution, automatic repairs, cloud analytics, telemetry, or vendor lock-in.

A phase is complete only after its acceptance criteria pass on its target environment and required independent review is complete. Future roadmap items are not implemented merely because they appear here.
