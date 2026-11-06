# AICRE 0.2.0 — Security and Privacy Model

## Purpose and non-goals

AICRE 0.2 collects a bounded set of Linux environment and directory metadata and reports five independent readiness dimensions. It is not an agent sandbox, access-control manager, malware scanner, complete secret detector, backup tool, security certification, or authorization to run an autonomous agent. It does not install software, modify machine settings, or remediate findings. Windows and macOS support are not claimed.

## Trust boundary

AICRE runs with the invoking user's privileges. It does not request elevation or alter accounts, ACLs, or configuration. The CLI inventory profile observes the local system; the legacy `scan SOURCE` command separately inventories a user-selected directory. Reports are generated locally. A user-specified report file is the only intended output write and is created with the atomic, private publication behavior described below.

## Approved discovery sources

System inventory uses:

- `platform.freedesktop_os_release()` for a small allowlist of distribution fields (`ID`, `NAME`, `VERSION_ID`, `PRETTY_NAME`), after checking both standard os-release paths against exclusions;
- `platform.uname()` and `os.cpu_count()` for kernel identity and logical CPU count;
- only `MemTotal` and `MemAvailable` from `/proc/meminfo`;
- `shutil.disk_usage("/")` for root filesystem capacity;
- `sys`, `sysconfig`, and `platform` for the current Python runtime, ABI, and interpreter paths;
- `os.geteuid()` where available;
- only vendor/device IDs for Linux DRM card entries under `/sys/class/drm` as optional GPU metadata.

Tool discovery checks a fixed allowlist (`git`, `python3`, `pip`, `uv`, `pipx`, `node`, `npm`, `docker`, `podman`, `codex`, `claude`, `aider`, `ollama`) with `shutil.which`. Excluded PATH directories and candidate executable paths are removed before lookup. AICRE never launches, imports, or otherwise executes a discovered tool.

Only the allowlisted system-metadata sources above are read. AICRE does not inspect user-document contents, credentials, API keys, `.env` contents, private keys, or chat histories. No telemetry or network calls are made by the application. Tests patch process and network entry points to fail if called. These implementation properties do not monitor unrelated processes on the host.

## Privacy policy and exclusions

The built-in policy excludes selected credential directories, filenames, extensions, and known configuration locations. It is a path/name policy, not a complete secret detector. Sensitive paths are not opened for discovery and are not emitted in report values when excluded. User patterns are applied to filesystem metadata sources and executable paths before opening or disclosing them. A withheld observation is `not_checked`; it is never described as absent. Patterns are per invocation and are not persisted. `aicre exclusions show` lists the built-in rules.

For legacy directory scans, patterns are relative to the chosen scan root. For system inventory and tool lookup, patterns are tested against root-relative paths and, where relevant, paths relative to the current home directory. A report destination matching an exclusion is refused by the report/profile CLI. Exclusions do not act as system-wide access controls.

Reports may reveal system versions, hardware identifiers, storage totals, tool names, interpreter paths, and filesystem metadata. Treat them as private; inspect them before sharing. Reports can still contain sensitive facts not recognized by path rules.

## Finding and readiness semantics

Each finding contains a stable ID, category, one of `detected`, `not_detected`, `unsupported`, `permission_denied`, `error`, or `not_checked`, a JSON value and optional unit, named source, confidence, UTC collection time, and limitations. `not_detected` means the approved observation found no matching item; it does not replace `not_checked` when a source was excluded, unavailable, timed out, or not queried.

The report schema is `schemas/report-v2.schema.json`. Each readiness dimension has `pass`, `warning`, `fail`, or `unknown`, an explanation, and supporting finding IDs. There is no composite score. Resource readiness is `unknown` without a workload resource baseline; Software readiness is `unknown` without a mandatory software manifest. Compatibility explicitly checks Linux and Python `>=3.11` for the `standard` profile. Privacy readiness describes AICRE's local collection and exclusion behavior only. Security readiness warns if AICRE is run with effective UID 0; otherwise it remains unknown because the host's broader controls are not assessed.

## Read-only behavior, reporting, and timeouts

Inventory code reads only the allowlisted metadata sources. Tool discovery uses `shutil.which` and does not run candidates. Directory scanning remains metadata-only and does not open source files. User exclusions are checked before path-based reads and before reportable executable paths are returned.

Report files are written through a same-directory temporary file and atomically published. On POSIX, they have owner-only `0600` permissions. Without `--force`, an existing destination is not replaced; with `--force`, only a single-link regular file may be replaced. Symlinks and special files are rejected.

System inventory checks a cooperative deadline between observations. Directory scans check it between filesystem operations and emit a partial report with non-zero `scan_errors` if the time budget expires. A deadline cannot interrupt a filesystem or kernel call already in progress; it is not a hard real-time bound.

## Residual risks and unsupported cases

- Path/name rules cannot find every secret. An ordinary-looking path may still appear in a directory inventory.
- This is not a filesystem snapshot. Concurrent changes can produce incomplete or inconsistent results.
- The directory scanner refuses cross-device traversal but cannot reliably distinguish same-device bind mounts.
- Very large directory scans can consume substantial time and memory; there is no configurable item or memory ceiling.
- Scan errors are aggregated rather than identifying every failed path.
- DRM metadata covers only the Linux DRM sysfs interface. Other GPU providers and driver readiness may not be detected.
- Resource/software readiness cannot be meaningfully passed or failed until workload requirements are supplied. Security readiness is not a host audit.
- Filesystem, permission, mount, and metadata behavior vary across Linux distributions. CI targets Ubuntu 24.04; no Windows/macOS compatibility claim is made.
- AICRE is not a security boundary against a hostile process with access to the host or scanned directory.

## Safe-use guidance

- Run as a normal user; do not use `sudo`.
- Use explicit exclusions and review reports before sharing.
- Stop if behavior differs from this document and report issues privately without attaching sensitive inventories.
- Do not treat `pass` in one dimension as a certification of overall agent safety.

## Verification and release status

CI runs Ruff, JSON Schema validation, and tests on Ubuntu 24.04 with Python 3.11, 3.12, and 3.13. A successful run verifies only those checks. Independent review is required before any release; this document alone does not constitute that review.


## Workload profile limitation

The `agent-development` profile uses explicit project-defined thresholds only: >=2 logical CPUs, >=8 GiB total RAM, >=10 GiB free space on the root filesystem, and PATH presence of Git and Python 3. A missing, excluded, malformed, or timed-out observation remains unknown. These thresholds are not vendor requirements or performance guarantees. This profile does not inspect agent configuration, MCP servers, tool permissions, isolation, dependency provenance, or model inference capability.
