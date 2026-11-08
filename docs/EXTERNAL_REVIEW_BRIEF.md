# AICRE — External Review Request Brief

**Document status:** reusable request template. Not a 0.3.0 release gate; see [RELEASE_READINESS.md](RELEASE_READINESS.md).  
**Review target:** To be set to the commit under review when this brief is sent.  
**Product:** AICRE — local-first Linux environment inventory and workload-readiness CLI.

## 1. Purpose

Request an independent reviewer to assess the security and correctness boundaries of AICRE before a release. This brief is a preparation aid; it is not itself an audit, certification, penetration test, or independent review.

The reviewer should be independent of the implementation and should state their relevant experience, review scope, commit inspected, tools used, limitations, and any conflicts of interest.

## 2. Review scope

Prioritize these areas:

1. **Filesystem traversal and containment**
   - Descriptor-relative traversal, symlink handling, hard links, mount boundaries, same-device bind mounts, path normalization, race conditions, rename/replacement behavior.
   - Confirm the documented limitation that same-device bind mounts may be traversed is accurate.
2. **Resource bounds and denial of service**
   - Item and per-directory-entry bounds, memory growth from long paths/object overhead, cooperative timeout behavior, very large directories, deep trees, and error handling.
   - Confirm no claim implies a hard byte-level memory ceiling or hard real-time deadline.
3. **Privacy and data disclosure**
   - Sources read by system inventory and directory scanning, path filtering, exclusions, report contents, output permissions, symlink/hard-link destinations, atomic publication, and accidental disclosure.
   - Confirm that no file contents, credentials, API keys, chat histories, or user documents are read.
4. **Execution and network boundaries**
   - Confirm discovered executables are not launched and that application code makes no network requests, telemetry calls, subprocess launches, privilege elevation, or remediation operations.
5. **Readiness semantics**
   - Five independent dimensions, no composite score, evidence mapping, unknown vs pass/fail behavior, host-facing resource observations, and limits of PATH-only software detection.
6. **CLI and report contracts**
   - Argument validation, JSON serialization, schema conformance, partial-report behavior, exit codes, malformed inputs, and compatibility behavior.
7. **Packaging and supply-chain boundaries**
   - Runtime dependency metadata, wheel/sdist contents, build configuration, locked CI dependencies, GitHub Actions pinned by full commit SHA, and release metadata.

## 3. Non-goals and safe handling

- Do not run AICRE as root or with elevated privileges.
- Do not scan personal, customer, production, or otherwise sensitive directories.
- Use disposable test fixtures and synthetic files only.
- Do not submit real credentials, secrets, private paths, or user inventories as test inputs.
- This review does not certify the host machine, AI agents, operating system, dependencies, or GitHub platform.
- Legal ownership and license review are separate from the technical security review.

## 4. Expected deliverable

Provide a written report containing:

- Reviewer name or organization and relevant qualifications.
- Exact commit SHA and date reviewed.
- Scope and methodology, including commands/tools and any files not inspected.
- Findings with unique IDs, severity (Critical/High/Medium/Low/Informational), affected file/function, preconditions, reproducible steps, impact, and recommended remediation.
- Explicit statement if no findings were identified; absence of findings must not be described as proof of security.
- Retest evidence for fixes and a final residual-risk statement.
- Reviewer independence/conflict statement.

## 5. Acceptance criteria if an external review is commissioned

The review gate may be closed only when:
- The report is received and tied to the exact release-candidate commit or an explicitly compared commit.
- Every Critical/High finding is fixed and independently retested.
- Medium findings are fixed or receive a documented, owner-approved disposition.
- Low/Informational findings are recorded with rationale and follow-up status.
- Any finding that changes product claims, privacy boundaries, or residual-risk dispositions is reflected in the docs and tests.
- The project owner records the review date, reviewer, report location, and final disposition without publishing sensitive exploit details.

## 6. Reviewer checklist

- [ ] Reviewer independence and qualifications recorded.
- [ ] Exact commit SHA confirmed.
- [ ] Filesystem traversal and race conditions reviewed.
- [ ] Resource bounds and timeout behavior reviewed.
- [ ] Privacy and report disclosure reviewed.
- [ ] Execution/network boundaries reviewed.
- [ ] Readiness semantics and JSON contract reviewed.
- [ ] Packaging and dependency boundaries reviewed.
- [ ] Findings triaged and blocking findings retested.
- [ ] Final signed or attributable review report received.

## 7. Current status

No external review has been commissioned or performed. For 0.3.0 the owner chose an AI-assisted internal review ([INTERNAL_SECURITY_REVIEW.md](INTERNAL_SECURITY_REVIEW.md)), which is not independent. This brief remains available for a future external review and does not block 0.3.0.
