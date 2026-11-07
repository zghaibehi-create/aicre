# AICRE 0.2.1 — Linux-first inventory and readiness preview

**Independent AI Computer Readiness Engine (AICRE)** is a local-first Linux CLI for collecting a narrow set of environment metadata and presenting separate, evidence-backed readiness dimensions. It does not run AI agents, install software, change system settings, or send machine information anywhere.

> **Preview status:** AICRE is an experimental inventory tool, not a security product, agent sandbox, malware scanner, secret scanner, or guarantee that a computer is safe for autonomous agents. The 0.2 implementation is not a release approval; independent review remains required.

## Quick start

AICRE runs on Linux with Python 3.11 or newer and is installed from source.

1. Get the source: `git clone https://github.com/zghaibehi-create/aicre.git && cd aicre`.
2. Create and activate a virtual environment: `python3 -m venv .venv && source .venv/bin/activate`.
3. Install AICRE: `python -m pip install -e '.[dev]'`.
4. Assess the agent-development profile: `aicre readiness --profile agent-development`.

## Sample output

The following output was captured by the [GitHub Actions sample-report workflow](https://github.com/zghaibehi-create/aicre/actions/runs/42371048090) on a GitHub-hosted Ubuntu 24.04 runner, using AICRE 0.2.1 from the merge commit for PR #16:

```text
AICRE 0.2.1 — profile: agent-development
Observed values (host-facing; resource comparisons are not performed):
  CPU: 4 (min 2 logical CPUs)
  RAM: 15.6 GiB (min 8.0 GiB)
  Free disk: 85.7 GiB (min 10.0 GiB)
  git: detected
  python3: detected
[unknown] resource_readiness: Host-facing CPU, RAM, and root-storage observations are retained for context, but effective process/container limits are not established; resource thresholds are not evaluated and readiness remains unknown.
  evidence: profile.resource.cpu, profile.resource.memory, profile.resource.storage
[pass] software_readiness: Compared PATH presence for required tools. Presence does not verify versions, configuration, security, or functionality.
  evidence: profile.software.git, profile.software.python3
[pass] compatibility_readiness: Linux platform and minimum Python compatibility are assessed from explicit runtime checks only.
  evidence: compatibility.platform.linux, compatibility.python.minimum
[pass] privacy_readiness: Describes AICRE's local collection and exclusion behavior only; it is not a host-wide privacy guarantee.
  evidence: privacy.local_collection, privacy.user_exclusions
[unknown] security_readiness: The process effective UID is nonzero; other host security controls were not assessed.
  evidence: security.effective_uid
Note: unknown means not assessed, not failed.
```

This sample describes a GitHub-hosted virtual runner, not a personal computer. Resource readiness remains `unknown` because the report does not establish effective process/container limits.

## Privacy and collection boundaries

AICRE uses only narrowly scoped local sources: Python's `platform`, `os`, `sys`, and `sysconfig` interfaces; Linux `/etc/os-release`/`/usr/lib/os-release`, `/proc/meminfo`, `/sys/class/drm` vendor/device identifiers; `shutil.disk_usage("/")`; and `shutil.which` for a fixed allowlist of executable names. The allowlist is `git`, `python3`, `pip`, `uv`, `pipx`, `node`, `npm`, `docker`, `podman`, `codex`, `claude`, `aider`, and `ollama`. Tool detection searches permitted `PATH` entries only: `detected` does not verify version or functionality, and `not_detected` does not prove the tool is absent elsewhere.

AICRE does not execute discovered programs, read credentials, API keys, `.env` contents, private keys, chat histories, or user documents. It makes no network requests or telemetry calls and does not perform remediation. Filesystem sources and executable paths are filtered through built-in sensitive-path policy and any `--exclude` patterns before reading or disclosing them. An excluded result is reported as `not_checked`, not as absent. Exclusion patterns are not persisted.

Reports can contain hardware details, software availability, and executable paths. Review a report before sharing it. Built-in path rules are conservative and cannot discover every secret.

## Findings and readiness

Each finding has a stable ID, category, collection status, value and optional unit, named source, confidence, UTC collection timestamp, and limitations. Finding statuses are `detected`, `not_detected`, `unsupported`, `permission_denied`, `error`, and `not_checked`.

Each report contains five separate readiness dimensions: Resource, Software, Compatibility, Privacy, and Security. Each dimension returns `pass`, `warning`, `fail`, or `unknown`, an explanation, and finding IDs used as evidence. Resource and Software readiness are evaluated independently. The default `standard` profile remains inventory-only and leaves both dimensions `unknown`. Workload profiles may assess PATH presence for required tools, but host-facing CPU, RAM, and storage observations are never used to pass or fail Resource readiness; it remains `unknown` until effective process/container limits can be established. The standard Compatibility profile explicitly checks Linux and Python `>=3.11`; it has no GPU requirement. Security readiness is deliberately limited: root execution produces a warning, while non-root execution does not imply that other host security controls passed. Privacy findings describe AICRE behavior, not host-wide privacy.

The full JSON report conforms to [`schemas/report-v2.schema.json`](schemas/report-v2.schema.json). Reports are written locally; when saved to a file, the existing atomic publication rules apply, with owner-only `0600` mode on POSIX. Existing reports are not replaced without explicit `--force`.

## Requirements and installation

- Linux-first. Windows and macOS support are not claimed.
- Python 3.11 or newer.
- No runtime third-party dependencies. `pytest`, Ruff, and `fastjsonschema` are development/test-only dependencies.
- GitHub Actions checks Ubuntu 22.04 and 24.04 with Python 3.11, 3.12, and 3.13; CI tools are version- and hash-locked in `.github/requirements-ci.txt`.

```bash
python3 -m venv .venv
source .venv/bin/activate
python -m pip install -e '.[dev]'
```

## CLI

Run a system profile, human-readable by default:

```bash
aicre --version
aicre system
aicre inventory
aicre readiness
aicre scan --profile standard
```

Emit the complete versioned JSON report to stdout or save it securely to a new file:

```bash
aicre report --format json
aicre report --format json --output "$HOME/aicre-report.json"
```

Set exclusions and a cooperative time budget for system inventory:

```bash
aicre inventory --exclude '**/.local/bin/private-tool' --timeout 10
```

Show built-in exclusions:

```bash
aicre exclusions show
```

The original directory metadata scanner is retained. Its default cardinality limits can be overridden deliberately:

```bash
aicre scan "$HOME/Documents" --output "$HOME/aicre-directory-report.json" \
  --exclude 'Projects/Client-A/**' --exclude '**/Personal/**'

# Example: increase both bounds for a large, trusted directory
aicre scan "$HOME/Documents" --output "$HOME/aicre-directory-report.json" \
  --max-items 50000 --max-directory-entries 10000
```

For directory scans, exclusions are matched against paths relative to the selected scan root. For system inventory and tool discovery, they are matched against root-relative paths and, when applicable, home-relative paths. Directory scans use two cardinality limits by default: `--max-items 25000` caps included files and directories in the report, and `--max-directory-entries 5000` caps the temporary entry buffer used to sort any one directory. Both values can be lowered or raised explicitly. The per-directory limit counts all directory entries, including entries later excluded by policy.

A directory scan that reaches either limit stops and writes the records collected so far as an explicitly incomplete report. It does not silently skip entries and continue as if the scan were complete. The report uses schema version `2`, with `summary.complete` and `summary.termination_reason` (`item_limit`, `directory_entry_limit`, `timeout`, or `filesystem_errors`). Timeout is cooperative; it cannot interrupt a filesystem call already in progress. `scan_errors` counts filesystem/metadata errors only; timeout and configured limits are reported separately. The CLI returns exit code `1` for any incomplete directory scan. The system/inventory/report commands represent observations not reached before their deadline as `not_checked`.

To intentionally replace an existing regular report file, supply `--force`. Symlinks, hard-linked destinations, directories, FIFOs, sockets, devices, and other non-regular destinations are rejected. A directory scan must still write its report outside the scan root.

## Development and verification

```bash
python -m pip install -e '.[dev]'
ruff check src tests
pytest -v
```

The automated tests cover system source filtering, executable discovery without execution, explicit compatibility requirements, readiness evidence, report-schema validation, path exclusions, CLI behavior, scanner races, and previous security regressions. A green CI run verifies only those checks; it does not establish production readiness.

## Use with AI agents

See the [AICRE agent skill](skills/aicre/SKILL.md) for instructions an AI agent can follow when running AICRE and interpreting its output. AICRE is Linux-only for now.

## Project documents

- [Security model](docs/SECURITY_MODEL.md)
- [Roadmap](docs/ROADMAP.md)
- [Security reporting](SECURITY.md)
- [Legal notices](docs/LEGAL_NOTICES.md)
- [Contributing](CONTRIBUTING.md)
- [JSON readiness report schema](schemas/report-v2.schema.json)
- [JSON directory scan report schema](schemas/directory-scan-report-v2.schema.json)

## License

MIT. See [LICENSE](LICENSE).

## Workload profiles

The default `standard` profile is inventory-only. The `agent-development`
profile is retained for compatibility. Additional profiles are listed below.
The CPU, RAM, and storage values are project reference thresholds only; they are
not compared into Resource readiness because effective process/container limits
are not established.

| Profile | Reference CPU | Reference RAM | Reference free storage | Required tools |
|---|---:|---:|---:|---|
| `agent-development` | 2 | 8 GiB | 10 GiB | git, python3 |
| `laptop-dev` | 4 | 16 GiB | 20 GiB | git, python3, node |
| `agent-workstation` | 8 | 32 GiB | 50 GiB | git, python3, docker, ollama |
| `ci-runner` | 2 | 8 GiB | 10 GiB | git, python3, pip |

Resource observations are retained for context only. AICRE does not establish effective process/container limits, cgroup quotas, CPU affinity, orchestrator reservations, or filesystem quotas. Therefore profile thresholds are not compared into Resource `pass` or `fail`; Resource readiness remains `unknown`. Software readiness assesses PATH presence only; it does not verify versions, configuration, security, or functionality.

```bash
aicre readiness --profile agent-development
aicre report --profile agent-development --format json
```

These are project-defined minimums, not vendor specifications or performance
or safety guarantees. No profile currently requires a GPU. AICRE does not
assess local model inference performance, drivers, concurrency, agent
configuration, MCP permissions, sandboxing, or dependency provenance.

**Container and constrained-environment limitation:** resource observations
remain host-facing and do not account for cgroup CPU/memory quotas or
CPU-affinity restrictions. Treat the result as a host-observation-only
assessment.

