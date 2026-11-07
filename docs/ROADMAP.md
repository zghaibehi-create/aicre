# AICRE Roadmap

This roadmap distinguishes implemented work from release approval; a passing build is not a production-readiness claim.

- **AICRE 0.1 Linux preview and security hardening — merged:** descriptor-relative scanner hardening, conservative path policy, private atomic reports, locked CI, and regression coverage. This remains an experimental tool.
- **AICRE 0.2 Linux inventory/readiness — implemented, merged, and CI-validated:** local system metadata, allowlisted non-executing tool discovery, explicit Linux/Python compatibility checks, five independent readiness dimensions, and a versioned JSON Schema. The Ubuntu 24.04 CI matrix passes on Python 3.11, 3.12, and 3.13. Resource and software baselines remain unknown until workload requirements are defined; no composite score is planned.
- **0.2 formal release approval — pending:** the implementation is a validated preview, not a production-readiness claim. No `v0.2.0` tag or GitHub release has been published; independent review remains required before tagging or describing 0.2 as release-ready.
- **Future scope:** a configurable workload requirements profile, additional reviewed local metadata sources, packaging/signing, and broader platform feasibility work.
- **Non-goals:** no Windows/macOS support claim, GUI, autonomous agent execution, automatic repairs, cloud analytics, telemetry, or vendor lock-in.

A phase is complete only after its acceptance criteria pass on its target environment and required independent review is complete. Future roadmap items are not implemented merely because they appear here.
