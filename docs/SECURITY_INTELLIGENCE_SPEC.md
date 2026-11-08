# AICRE 0.3 Security Intelligence — Design Proposal

**Status:** Draft for review; not implemented  
**Target:** Post-0.3.0 experimental engineering phase  
**Branch:** `docs/aicre-0.3-security-intelligence-spec`

## 1. Purpose

Define a narrowly scoped, evidence-backed way for AICRE to report selected security-relevant observations about local AI-agent and developer-tool configuration. The feature must help users see *what AICRE can verify*, while preserving explicit unknown states for anything it cannot safely or reliably establish.

This proposal does not change the published 0.3.0 release and does not authorize a security-product claim.

## 2. Product boundary

AICRE remains a local-first Linux CLI. Security Intelligence must:

- Run with the invoking user's privileges; never request elevation.
- Make no network requests and perform no telemetry or cloud upload.
- Never execute, import, launch, or probe discovered tools, servers, package managers, or configured commands.
- Never modify configuration, install packages, change permissions, or remediate findings.
- Read only explicitly allowlisted configuration/metadata sources after a source-specific privacy review.
- Never recursively search a user's home directory or scan arbitrary project trees by default.
- Keep the five readiness dimensions separate; do not introduce a composite score.
- Report `unknown` when the source, schema, version, or meaning is unsupported or ambiguous.

The feature is advisory inventory, not a sandbox, access-control enforcement system, malware scanner, vulnerability scanner, complete secret detector, or host-security audit.

## 3. Proposed collection model

### 3.1 Two-stage source policy

**Stage A — fixed-path filesystem metadata only (proposed first implementation):**
- Inspect only the exact per-user settings paths listed below; do not search for them.
- Use metadata-only operations. Do not open file contents, parse settings, resolve symlink targets, or inspect sibling files.
- Record only whether the exact candidate is present, its file type, whether the candidate itself is a symlink, permission bits, and owner/group IDs where supported. Do not report absolute paths, file contents, size, timestamps, or arbitrary filenames.
- Reject symlinked parent components and symlink candidates; do not follow them.
- Do not traverse project directories, enumerate home directories, inspect environment variables, or infer active configuration.
- A missing candidate is only “not present at this exact path”; it is not proof that the tool is absent or that no other configuration source exists.

**Initial exact candidate paths (Linux, per-user only):**

| Product | Candidate path relative to the invoking user's home | Metadata-only interpretation |
|---|---|---|
| Codex | `.codex/config.toml` | User-level Codex configuration file may be present |
| Claude Code | `.claude/settings.json` | User-level Claude Code settings file may be present |
| Gemini CLI | `.gemini/settings.json` | User-level Gemini CLI settings file may be present |

These paths are grounded in the products' current official configuration documentation. They are candidate paths for AICRE's own metadata inventory, not a complete enumeration of each product's configuration precedence or active settings. Project-scoped and system-managed configuration locations are deliberately excluded from the first implementation.

**Explicitly excluded paths and data:**
- Claude Code `.claude.json`: contains account details, MCP server configuration, and per-project state.
- Codex `.codex/auth.json`, history, logs, caches, and all files other than the exact `config.toml` candidate.
- Any `.env*`, credentials, tokens, private keys, shell startup files, prompts, chat/session history, project-local settings, or managed configuration.
- All other files in the candidate directories.

**Stage B — structured configuration metadata (not approved):**
- May be considered only for individually named, versioned formats and exact allowlisted paths.
- Must have a documented field allowlist, strict parser, size/depth/item limits, duplicate-key rejection, and explicit behavior for malformed or unknown versions.
- Extract only normalized security-relevant fields. Never place raw configuration documents, credentials, tokens, environment values, prompts, or arbitrary argument strings in reports or logs.
- Do not enable until a threat-model/privacy review and adversarial parser tests pass.

Stage B is not approved by this proposal. It is a design gate, not an implementation commitment.

### 3.2 Initial candidate observations

The initial implementation, if approved, should be limited to the three Stage A user-level settings candidates above:

| Area | Candidate observation | What it may establish | What remains unknown |
|---|---|---|---|
| Agent/tool configuration | Presence, file type, symlink status, mode bits, and owner/group IDs for the three exact candidate files | Whether a documented user-level settings file exists at that exact path and what its basic filesystem metadata indicates | Whether the tool is installed/running, which configuration layer is active, actual settings, secrets, effective runtime behavior |
| MCP exposure | No MCP server configuration is read or enumerated in Stage A | Nothing about configured MCP servers | Server list, transport, authentication, tools, scopes, effective permissions, remote trust |
| Execution boundaries | No approval, sandbox, hook, or command setting is read in Stage A | Nothing about effective execution boundaries | Whether commands are sandboxed, constrained, approved, or safe |
| Dependency provenance | No manifests or lockfiles are inspected in Stage A | Nothing about dependency integrity or origin | Dependency graph, integrity, origin, vulnerability status, reproducibility |

A file's presence is not proof that a tool is installed, active, configured securely, or used by a running process. File permissions alone do not prove effective access controls. Stage A must not emit “secure”, “insecure”, “safe”, or a security pass/fail from these observations.

### 3.3 Source allowlist requirements

Before any path is added, record:
- Tool/product and supported configuration format/version.
- Exact candidate paths and platform assumptions.
- Whether paths can contain credentials or personal data.
- Whether symlinked paths are rejected.
- The exact metadata fields collected.
- Exclusion-policy behavior and failure/timeout semantics.
- Tests proving no content reads occur in Stage A.

No generic globbing, recursive home-directory discovery, shell expansion, or environment-variable expansion is permitted.

## 4. Finding and readiness semantics

- Every observation must identify its source, collection status, confidence, timestamp, and limitations using existing report conventions.
- Use existing statuses where semantically correct; do not overload `not_detected` to mean unsupported, excluded, unreadable, or not queried.
- A missing candidate path means only that the path was not present at collection time.
- Permission denied, excluded, malformed, timed out, unsupported format, and unavailable source must remain distinguishable.
- Security readiness must remain `unknown` unless a narrowly defined check supports a narrower conclusion. A collection of metadata-presence checks must not produce a general security pass.
- No weighted score, risk score, safety percentage, or implied ranking.

## 5. Privacy and safety controls

- Fixed allowlist; no arbitrary path input in the initial feature.
- No file-content reads in Stage A.
- No network, subprocess, executable discovery beyond existing PATH-only behavior, imports of discovered packages, or active endpoint checks.
- No raw config values, command arguments, environment variables, credentials, tokens, prompts, or server URLs in reports.
- Respect existing exclusions before metadata access and disclosure.
- Keep output private using existing atomic-write and permission behavior.
- Treat reports as sensitive because even paths, usernames/UIDs, tool names, and timestamps can disclose environment details.
- Fail closed: unexpected file types, symlinks, oversized metadata, parser ambiguity, or unsupported layouts produce a bounded warning/unknown result rather than a guessed conclusion.

## 6. Threat model

The implementation must assume:
- Configuration paths and their contents may be attacker-controlled.
- Files can change between discovery and observation.
- Symlinks, hard links, special files, malformed data, duplicate keys, deeply nested structures, and oversized inputs may be present.
- A report may be shared with a third party and therefore must not contain secrets or unnecessary identifiers.
- A malicious local process may race filesystem operations; AICRE is not a security boundary against such a process.

The feature must not claim race-free snapshots or protection against a hostile process with the same user's privileges.

## 7. Explicit non-goals

- No attempt to determine whether an MCP server is trustworthy by contacting it.
- No authentication test, permission probe, exploit test, vulnerability scan, malware scan, or secret-content scan.
- No inference that a configured command is safe because its path exists.
- No dependency vulnerability or license verdict without a separate, reviewed source of authoritative data; no network lookup.
- No agent execution, automatic repair, policy enforcement, or system configuration changes.
- No Windows/macOS support claim.

## 8. Acceptance gates before implementation

1. Review and freeze the candidate source allowlist.
2. Decide explicitly whether the first release is Stage A only. Stage B requires a separate approval.
3. Update the threat model and privacy model before code changes.
4. Define finding IDs, statuses, evidence, and exact unknown semantics.
5. Add tests proving no subprocess/network calls, no content reads in Stage A, exclusion-before-access, and no symlink following.
6. Add adversarial filesystem tests for symlinks, hard links, special files, races, permission errors, oversized files, and path disclosure.
7. Verify deterministic output and compatibility with the existing report-v2 contract.
8. Run the full Ubuntu/Python CI matrix and relevant integration tests.
9. Obtain code review and a separate security/privacy review; record residual risks honestly.
10. Only then decide whether to merge and whether a new version is warranted.

## 9. Relationship to PR #4

PR #4 is not a safe implementation base for this phase as-is. It is substantially divergent from current `main`, and its report-import/render/diff surface has unresolved validation and untrusted-output concerns. Any salvage must be isolated, re-reviewed against current contracts, and covered by adversarial tests. This proposal does not authorize merging PR #4 or importing its code.

## 10. Decision requested

Review this proposal's product boundary and Stage A/Stage B separation. No implementation should begin until the source allowlist and privacy boundary are approved.


## 11. Source references

The exact candidate locations above are based on the following official documentation, consulted on 2026-11-09:

- OpenAI Codex configuration basics: https://learn.chatgpt.com/docs/config-file/config-basic
- Claude Code settings files and precedence: https://code.claude.com/docs/en/settings
- Gemini CLI configuration: https://github.com/google-gemini/gemini-cli/blob/main/docs/reference/configuration.md

These references establish documented configuration locations only. They do not establish that a candidate file is active, secure, or authoritative on a particular machine.
