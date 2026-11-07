# AICRE 0.3.0 — Release Readiness and Residual-Risk Decision

**Status:** preparation only; not release approval.  
**Current package version:** 0.2.1.  
**Target:** 0.3.0.  
**Release rule:** do not tag, publish, or announce 0.3.0 until every mandatory gate in this document is closed.

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

The following dispositions are scoped to an experimental, local-first metadata tool. They are not claims that the risks are eliminated. Any external reviewer finding that contradicts these dispositions reopens the relevant item.

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

For 0.3.0, RR-01 through RR-08 are accepted as documented limitations **only within the product scope and constraints above**. No item is represented as mitigated or eliminated where it is not. If independent review identifies a concrete exploitable issue, privacy leak, incorrect completeness claim, or unsafe traversal behavior, the release is blocked until fixed and retested.

## 3. Mandatory release gates

- [ ] **Copyright and provenance confirmation:** project owner verifies that the project has the necessary rights to distribute all existing project-authored code, documentation, examples, and assets under MIT; checks that the copyright notice is not misleading; and identifies and preserves any third-party notices or license obligations. Resolve employer/client ownership or other contributor restrictions before release.
- [ ] **Independent external code/security review** completed; findings triaged and blocking findings resolved.
- [ ] **Target Linux acceptance evidence** recorded by the project owner: distribution/version, kernel, Python version, filesystem, installation method, commands, outputs, and deviations. Do not place private machine details in public issues.
- [x] GitHub Private Vulnerability Reporting visually verified enabled by the repository owner on 2026-11-07.
- [x] Public repository description corrected and verified on 2026-11-07.
- [x] Residual risks RR-01 through RR-08 documented with explicit 0.3.0 dispositions and usage constraints.
- [ ] All required GitHub Actions checks green on the final release candidate commit.
- [ ] Final source distribution and wheel built; clean-environment install, metadata, entry point, and version checks pass.
- [ ] Release notes, version metadata, README, security model, schemas, and finding-ID reference are cross-checked for consistency.
- [ ] Project owner makes the final go/no-go decision.

## 4. Release execution checklist (after the gates)

1. Freeze the release-candidate commit; do not add unrelated features.
2. Apply the 0.3.0 version consistently in package metadata, `aicre.__version__`, CLI/report tests, documentation, and issue templates. Keep the report schema version unchanged unless the JSON contract itself changes.
3. Finalize the 0.3.0 changelog from merged behavior only; distinguish implemented behavior from deferred roadmap items.
4. Run the complete CI matrix and build both wheel and source distribution.
5. Install each artifact in a clean Python 3.11+ Linux virtual environment; verify `aicre --version`, CLI smoke commands, report schema validation, and absence of runtime dependencies.
6. Inspect artifact contents and metadata; confirm license, README, package files, and schemas are present.
7. Create a GitHub Release only after explicit go/no-go approval. Mark it as a pre-release if the project remains experimental.
8. Preserve the exact tag, commit SHA, artifact filenames, hashes, and CI run links in the release record.

## 5. Current engineering recommendation

**Conditional GO for release preparation; NO-GO for publishing.** The implemented feature set is coherent enough to prepare as 0.3.0, subject to the mandatory external review and target-Linux evidence. Do not bump the package version or create a public tag until those two owner-managed gates are supplied and the final candidate has passed CI.
