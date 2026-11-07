# AICRE 0.3.0 — Release Readiness and Residual-Risk Decision

**Status:** release preparation; not yet a 0.3.0 publication approval.  
**Current package version:** 0.2.1.  
**Target:** 0.3.0.  
**Release rule:** do not tag, publish, or announce 0.3.0 until the final candidate has been validated and the project owner records a go decision.

## 1. Scope of the 0.3.0 candidate

The 0.3.0 candidate is a consolidation release of behavior already implemented on `main`, not a promise that planned security-intelligence features exist.

Included:
- Linux-first local inventory and workload-profile foundation.
- Five independent readiness dimensions; no composite score.
- Resource readiness remains `unknown` unless effective process/container limits can be established.
- Metadata-only directory scanning with default limits of 25,000 included items and 5,000 entries buffered per directory.
- Explicit partial-report semantics and directory-scan report schema v2.
- No runtime third-party dependencies; Python >=3.11.
- Expanded CI coverage on Ubuntu 22.04 and 24.04 with Python 3.11, 3.12, and 3.13.

Not included and must not be implied:
- Agent execution, sandboxing, remediation, malware scanning, or complete secret detection.
- Host-wide security auditing or security certification.
- Effective cgroup/container resource accounting.
- Agent configuration, MCP permission, or dependency-provenance assessment.
- Windows or macOS support.

## 2. Residual-risk register and engineering disposition

The following dispositions are scoped to an experimental, local-first metadata tool. They are not claims that the risks are eliminated. Any future reviewer finding that contradicts these dispositions reopens the relevant item.

| ID | Residual risk | Impact and existing controls | 0.3.0 engineering disposition |
|---|---|---|---|
| RR-01 | No hard byte-level memory ceiling | Item count and per-directory entry count are bounded by default. The report still consumes memory proportional to path lengths, Python object overhead, and serialization; callers can raise limits. | **Accept with constraints.** Keep conservative defaults, retain explicit override flags, document that cardinality limits are not a byte budget, and do not market the scanner as an OOM-proof sandbox. A hard byte budget is deferred. |
| RR-02 | Resource observations are host-facing | CPU count, host memory, and root filesystem capacity may differ from resources available to the process/container. cgroup limits, CPU affinity, reservations, and quotas are not established. | **Accept as unknown, never as pass/fail.** Keep Resource readiness `unknown` until effective limits are reliably measured. This is a deliberate honesty constraint, not a release defect to conceal. |
| RR-03 | Same-device bind mounts may be traversed | Cross-device entries are excluded and traversal is descriptor-relative, but a bind mount on the same device can evade the device-ID boundary. Metadata beneath it may be inventoried. | **Accept with explicit user-scope warning for 0.3.0.** The scan root is user-selected and collection remains metadata-only. Users must exclude sensitive mount paths and avoid scanning roots containing untrusted bind mounts. Mount-ID-aware containment is deferred; do not claim mount-boundary isolation. |
| RR-04 | Filesystem scans are not snapshots | Concurrent rename, replacement, permission, and metadata changes can make results inconsistent. Descriptor-relative operations and identity checks reduce some races; errors/limits/timeouts produce incomplete reports. | **Accept with explicit completeness semantics.** Do not claim point-in-time consistency. Keep partial-result reporting and nonzero CLI status for incomplete scans. Snapshot support is deferred. |
| RR-05 | Cooperative deadlines cannot interrupt an in-flight OS call | Deadline checks occur between observations/filesystem operations; a blocked kernel or filesystem call may exceed the requested budget. | **Accept with clear wording.** Describe timeouts as cooperative, not hard real-time guarantees. |
| RR-06 | Path/name exclusions are not a complete secret detector | Built-in and user exclusions reduce accidental disclosure but cannot identify every secret or sensitive-looking path. Reports can contain paths and system metadata. | **Accept with privacy warnings.** Keep source-content reads prohibited, require report review before sharing, and never describe exclusions as a complete secret scanner. |
| RR-07 | Tool discovery checks PATH presence only | A discovered executable is not launched; its version, configuration, safety, or functionality is not verified. | **Accept with narrow semantics.** Preserve PATH-only wording and do not infer a tool is safe or ready merely because it is detected. |
| RR-08 | AICRE does not establish host security posture | Non-root execution and the limited checks do not establish host-wide controls or safe agent execution. | **Accept only as a non-security-product boundary.** Keep security readiness unknown unless a specific supported observation justifies a narrower result. Never call AICRE a security audit or agent sandbox. |

### Risk decision

For 0.3.0, RR-01 through RR-08 are accepted as documented limitations only within the product scope and constraints above. No item is represented as mitigated or eliminated where it is not.

## 3. Release gates and evidence

- [x] **Owner ownership attestation and public notice:** owner confirmed rights necessary to distribute current AICRE content under MIT and selected **AICRE Project** as the public-facing copyright designation. Recorded in PR #30. This is an owner representation, not an independent legal audit.
- [ ] **Third-party source/license provenance audit:** deferred by explicit project-owner instruction for this release-preparation pass. It is not represented as complete. Runtime dependencies remain empty; see `THIRD_PARTY_NOTICES.md` for the bounded prior inventory.
- [x] **AI-assisted internal security review:** performed on 2026-11-07 against commit `d9ee4977f6057a79c9f1fec2289f2de05ec33c12`. No new Critical/High finding was identified in the scoped review. See [INTERNAL_SECURITY_REVIEW.md](INTERNAL_SECURITY_REVIEW.md). This is not an independent third-party audit, penetration test, or security certification.
- [ ] **Independent external code/security review:** not obtained. This remains distinct from the AI-assisted internal review. The project owner must explicitly decide whether to require it or accept the documented internal-review limitation for an experimental release.
- [x] **Automated Linux support-matrix validation:** final main Tests workflow and Install smoke workflow passed 6/6 jobs each on commit `d9ee4977f6057a79c9f1fec2289f2de05ec33c12`, covering Ubuntu 22.04/24.04 and Python 3.11/3.12/3.13. See [LINUX_ACCEPTANCE.md](LINUX_ACCEPTANCE.md). This does not claim the owner's own machine was tested.
- [ ] **Owner-machine-specific Linux acceptance:** not supplied. Decide whether this is required for the intended audience; do not represent hosted CI as a test of the owner's device.
- [x] GitHub Private Vulnerability Reporting visually verified enabled by the repository owner on 2026-11-07.
- [x] Public repository description corrected and verified.
- [x] Residual risks RR-01 through RR-08 documented with explicit dispositions.
- [x] **Final main test workflow after PR #33:** run [42386187695](https://github.com/zghaibehi-create/aicre/actions/runs/42386187695), all six matrix jobs passed on commit `d9ee4977f6057a79c9f1fec2289f2de05ec33c12`.
- [x] **Final main install/artifact inspection workflow after PR #33:** run [42386187780](https://github.com/zghaibehi-create/aicre/actions/runs/42386187780), all six matrix jobs passed on the same commit. It built wheel and sdist, inspected archive contents and metadata, checked version consistency and absence of runtime dependencies, installed both artifacts into clean virtual environments, and exercised CLI/report commands.
- [ ] **0.3.0 release-candidate validation:** current CI artifact checks are for package version 0.2.1. After the owner decides the review/provenance/target-Linux gates, create the exact 0.3.0 candidate and rerun the complete matrix and artifact inspection against that candidate.
- [ ] **Final consistency and approval:** align version metadata, `aicre.__version__`, CLI/report tests, README, changelog, security model, schemas, finding IDs, and release notes; then record the project owner's explicit go/no-go decision.

## 4. Release execution checklist

1. Resolve the open gate decisions above without misrepresenting deferred work as completed.
2. Freeze the release-candidate commit; do not add unrelated features.
3. Apply the 0.3.0 version consistently in package metadata, `aicre.__version__`, CLI/report tests, documentation, and issue templates. Keep the report schema version unchanged unless the JSON contract itself changes.
4. Finalize the 0.3.0 changelog from merged behavior only; distinguish implemented behavior from deferred roadmap items.
5. Run the complete CI matrix and build both wheel and source distribution from the candidate.
6. Install each artifact in a clean Python 3.11+ Linux virtual environment; verify `aicre --version`, CLI smoke commands, report schema validation, and absence of runtime dependencies.
7. Inspect artifact contents and metadata; confirm license, README, package files, schemas, and third-party notices are present where required; record canonical release artifact SHA-256 hashes.
8. Create a GitHub Release only after explicit go/no-go approval. Mark it as a pre-release if the project remains experimental.
9. Preserve the exact tag, commit SHA, artifact filenames, hashes, and CI run links in the release record.

## 5. Current engineering recommendation

**GO for technical validation of the current main snapshot; NO-GO for publishing 0.3.0 at this point.** The 0.2.1 main snapshot passed the latest Linux test and artifact-inspection matrix. The 0.3.0 candidate has not yet been versioned or built. The third-party provenance audit is deferred by owner instruction; the internal AI review is documented but is not an external independent review. Resolve those release-policy decisions, then validate the actual 0.3.0 candidate before publication.
