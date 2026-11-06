# AICRE Roadmap

The roadmap is a plan, not a statement that these capabilities already exist.

- **L0 — Linux Preview (current):** metadata-only inventory, conservative path exclusions, JSON report, Linux-focused documentation, automated tests, and Ubuntu CI.
- **L1 — Linux Hardening:** review filesystem race conditions, permission and mount behavior, add adversarial tests, gather community feedback, and publish only after the Linux acceptance gate is met.
- **W0 — Windows Feasibility:** separately validate Windows 11 filesystem semantics, junctions/reparse points, permissions, and packaging before claiming support.
- **M1 — Privacy Policy:** explicit policy files and reviewable exclusion decisions.
- **M2 — Windows Isolation:** design and validate a separate standard Windows account; no administrator privileges or ACL changes without explicit approval and test evidence.
- **M3 — Knowledge Index:** local index of approved metadata and, only after separate approval, permitted content.
- **M4 — Agent Workspace:** constrained workspace and integrations for Codex, Claude Code, and other agents.
- **M5 — Production:** threat-model review, platform-specific acceptance tests, packaging, documentation, and signed releases.

A phase is complete only after its acceptance criteria pass on its target environment. Later phases must not be treated as implemented by this roadmap.
