# AICRE 0.3.0 — Release Readiness and Residual-Risk Decision

**Status:** Published as an experimental GitHub pre-release on 2026-11-07.  
**Current package version:** 0.3.0.  
**Release tag:** [`v0.3.0`](https://github.com/zghaibehi-create/aicre/releases/tag/v0.3.0).  
**Tagged commit:** `530920cfa4a5fb7a3619f4e624157772230b157d`.  
**Post-release documentation:** PR #37 merged documentation-only clarifications to `main` on 2026-11-08; the published tag remains an immutable snapshot of the validated release commit.
**Follow-on work:** open PR #4 is not included in the tagged source or GitHub release; its canonical reporting and snapshot-diff changes require separate review, merge, validation, and a later release.

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
- [x] **Third-party source/license provenance audit deferral:** explicitly deferred by the project owner for this release. This is a scope decision, not a completed audit. Runtime dependencies remain empty; see `THIRD_PARTY_NOTICES.md` for the bounded prior inventory.
- [x] **AI-assisted internal security review:** performed on 2026-11-07 against commit `d9ee4977f6057a79c9f1fec2289f2de05ec33c12`. No new Critical/High finding was identified in the scoped review. See [INTERNAL_SECURITY_REVIEW.md](INTERNAL_SECURITY_REVIEW.md). This is not an independent third-party audit, penetration test, or security certification.
- [x] **Owner-directed security-review substitution:** the owner directed the assistant to perform an AI-assisted internal review in place of an external review. The internal review is documented in `INTERNAL_SECURITY_REVIEW.md`; no external reviewer was engaged. This is not represented as an independent third-party audit or certification.
- [x] **Automated Linux support-matrix validation:** final main Tests workflow and Install smoke workflow passed 6/6 jobs each on commit `d9ee4977f6057a79c9f1fec2289f2de05ec33c12`, covering Ubuntu 22.04/24.04 and Python 3.11/3.12/3.13. See [LINUX_ACCEPTANCE.md](LINUX_ACCEPTANCE.md). This does not claim the owner's own machine was tested.
- [x] **Linux acceptance scope:** the owner accepts the Ubuntu 22.04/24.04 CI matrix as the Linux support evidence for this release. The owner's personal machine was not tested; no claim is made that it was.
- [x] GitHub Private Vulnerability Reporting visually verified enabled by the repository owner on 2026-11-07.
- [x] Public repository description corrected and verified.
- [x] Residual risks RR-01 through RR-08 documented with explicit dispositions.
- [x] **Final main test workflow after PR #33:** run [42386187695](https://github.com/zghaibehi-create/aicre/actions/runs/42386187695), all six matrix jobs passed on commit `d9ee4977f6057a79c9f1fec2289f2de05ec33c12`.
- [x] **Final main install/artifact inspection workflow after PR #33:** run [42386187780](https://github.com/zghaibehi-create/aicre/actions/runs/42386187780), all six matrix jobs passed on the same commit. It built wheel and sdist, inspected archive contents and metadata, checked version consistency and absence of runtime dependencies, installed both artifacts into clean virtual environments, and exercised CLI/report commands.
- [x] **0.3.0 release-candidate validation:** PR #35 merge validation passed on the exact integrated candidate tree: Tests run #566 (6/6), Install smoke run #38 (6/6), and Sample report run #19 (passed). The install-smoke run built and inspected wheel/sdist, checked metadata and zero runtime dependencies, installed both artifacts in clean virtual environments, and exercised CLI/report behavior. Evidence is recorded in `LINUX_ACCEPTANCE.md`.
- [x] **Final consistency:** package metadata, `aicre.__version__`, CLI/report tests, README, changelog, security model, schemas, finding-ID reference, and issue template are aligned at 0.3.0; the CI artifact-inspection workflow confirmed version metadata consistency.
- [x] **Publication and tag:** GitHub pre-release [`v0.3.0`](https://github.com/zghaibehi-create/aicre/releases/tag/v0.3.0) published on 2026-11-07; tag resolves to validated commit `530920cfa4a5fb7a3619f4e624157772230b157d`. The release is marked as a pre-release. No wheel or source-distribution assets are attached; GitHub provides the source archives for the tag.

## 4. Release execution record

The following checklist describes the procedure used for 0.3.0. Publication is complete; it is retained as an auditable record rather than a list of pending actions.

1. Resolve the open gate decisions above without misrepresenting deferred work as completed.
2. Freeze the release-candidate commit; do not add unrelated features.
3. Apply the 0.3.0 version consistently in package metadata, `aicre.__version__`, CLI/report tests, documentation, and issue templates. Keep the report schema version unchanged unless the JSON contract itself changes.
4. Finalize the 0.3.0 changelog from merged behavior only; distinguish implemented behavior from deferred roadmap items.
5. Run the complete CI matrix and build both wheel and source distribution from the candidate.
6. Install each artifact in a clean Python 3.11+ Linux virtual environment; verify `aicre --version`, CLI smoke commands, report schema validation, and absence of runtime dependencies.
7. Inspect artifact contents and metadata; confirm license, README, package files, schemas, and third-party notices are present where required; record canonical release artifact SHA-256 hashes.
8. Create a GitHub Release only after explicit go/no-go approval. Mark it as a pre-release if the project remains experimental.
9. Preserve the exact tag, commit SHA, artifact filenames, hashes, and CI run links in the release record.

## 5. Post-publication status

**0.3.0 experimental pre-release publication is complete.** The candidate passed the documented test, install/artifact-inspection, and sample-report workflows before publication. The owner deferred the third-party provenance audit and accepted the AI-assisted internal review in place of an external review for this experimental release. The Ubuntu CI matrix is accepted as Linux support evidence; the owner's personal machine was not tested. No external audit or host-security certification is claimed. No binary distribution assets were attached to the GitHub Release; the published tag and GitHub-generated source archives remain the release source of record.
