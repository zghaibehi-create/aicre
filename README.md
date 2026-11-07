# AICRE 0.2.0 — Linux-first inventory and readiness preview

**Independent AI Computer Readiness Engine (AICRE)** is a local-first Linux CLI for collecting a narrow set of environment metadata and presenting separate, evidence-backed readiness dimensions. It does not run AI agents, install software, change system settings, or send machine information anywhere.

> **Preview status:** AICRE is an experimental inventory tool, not a security product, agent sandbox, malware scanner, secret scanner, or guarantee that a computer is safe for autonomous agents. The 0.2 implementation is not a release approval; independent review remains required.

## Quick start

AICRE runs on Linux with Python 3.11 or newer and is installed from source.

1. Get the source: `git clone https://github.com/zghaibehi-create/aicre.git && cd aicre`.
2. Create and activate a virtual environment: `python3 -m venv .venv && source .venv/bin/activate`.
3. Install AICRE: `python -m pip install -e '.[dev]'`.
4. Assess the agent-development profile: `aicre readiness --profile agent-development`.

## Privacy and collection boundaries

AICRE uses only narrowly scoped local sources: Python's `platform`, `os`, `sys`, and `sysconfig` interfaces; Linux `/etc/os-release`/`/usr/lib/os-release`, `/proc/meminfo`, `/sys/class/drm` vendor/device identifiers; `shutil.disk_usage("/")`; and `shutil.which` for a fixed allowlist of executable names. The allowlist is `git`, `python3`, `pip`, `uv`, `pipx`, `node`, `npm`, `docker`, `podman`, `codex`, `claude`, `aider`, and `ollama`. Tool detection searches permitted `PATH` entries only: `detected` does not verify version or functionality, and `not_detected` does not prove the tool is absent elsewhere.

AICRE does not execute discovered programs, read credentials, API keys, `.env` contents, private keys, chat histories, or user documents. It makes no network requests or telemetry calls and does not perform remediation. Filesystem sources and executable paths are filtered through built-in sensitive-path policy and any `--exclude` patterns before reading or disclosing them. An excluded result is reported as `not_checked`, not as absent. Exclusion patterns are not persisted.

Reports can contain hardware details, software availability, and executable paths. Review a report before sharing it. Built-in path rules are conservative and cannot discover every secret.

## Findings and readiness

Each finding has a stable ID, category, collection status, value and optional unit, named source, confidence, UTC collection timestamp, and limitations. Finding statuses are `detected`, `not_detected`, `unsupported`, `permission_denied`, `error`, and `not_checked`.

Each report contains five separate readiness dimensions: Resource, Software, Compatibility, Privacy, and Security. Each dimension returns `pass`, `warning`, `fail`, or `unknown`, an explanation, and finding IDs used as evidence. AICRE does not calculate a composite score. In the inventory-only `standard` profile, Resource and Software readiness remain `unknown` because no workload resource baseline or required software manifest is applied. The optional `agent-development` profile checks only PATH presence for its required tools; its Resource readiness remains `unknown` because host-facing measurements do not establish effective process/container limits. The standard Compatibility profile explicitly checks Linux and Python `>=3.11`; it has no GPU requirement. Security readiness is deliberately limited: root execution produces a warning, while non-root execution does not imply that other host security controls passed. Privacy findings describe AICRE behavior, not host-wide privacy.

The full JSON report conforms to [`schemas/report-v2.schema.json`](schemas/report-v2.schema.json). Reports are written locally; when saved to a file, the existing atomic publication rules apply, with owner-only `0600` mode on POSIX. Existing reports are not replaced without explicit `--force`.

## Requirements and installation

- Linux-first. Windows and macOS support are not claimed.
- Python 3.11 or newer.
- No runtime third-party dependencies. `pytest`, Ruff, and `fastjsonschema` are development/test-only dependencies.
- GitHub Actions checks Ubuntu 24.04 with Python 3.11, 3.12, and 3.13; CI tools are version- and hash-locked in `.github/requirements-ci.txt`.

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

The original directory metadata scanner is retained:

```bash
aicre scan "$HOME/Documents" --output "$HOME/aicre-directory-report.json" \
  --exclude 'Projects/Client-A/**' --exclude '**/Personal/**'
```

For directory scans, exclusions are matched against paths relative to the selected scan root. For system inventory and tool discovery, they are matched against root-relative paths and, when applicable, home-relative paths. `--timeout` is cooperative between observations; it cannot interrupt a filesystem call already in progress. A timed-out directory scan writes a partial report with a non-zero `scan_errors` count. The system/inventory/report commands represent observations not reached before the deadline as `not_checked`.

To intentionally replace an existing regular report file, supply `--force`. Symlinks, hard-linked destinations, directories, FIFOs, sockets, devices, and other non-regular destinations are rejected. A directory scan must still write its report outside the scan root. A non-zero `scan_errors` count means the directory inventory is incomplete.

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
- [Contributing](CONTRIBUTING.md)
- [JSON report schema](schemas/report-v2.schema.json)

## License

MIT. See [LICENSE](LICENSE).

## Workload profiles

The default `standard` profile is inventory-only and deliberately leaves Resource and Software readiness unknown. The optional `agent-development` profile records host-facing CPU count, total RAM, and free root-filesystem storage alongside project-defined reference thresholds (>=2 CPUs, >=8 GiB RAM, >=10 GiB free storage). Because effective process/container, cgroup, CPU-affinity, and filesystem-quota limits are not established, these observations are not used to pass or fail Resource readiness; that dimension remains `unknown`. Software readiness can assess only PATH presence of Git and Python 3, not their versions, configuration, security, or functionality.

```bash
aicre readiness --profile agent-development
aicre report --profile agent-development --format json
```

This is an advisory project-defined minimum, not a vendor specification or performance/safety guarantee. It does not assess local model inference, GPU drivers, concurrency, agent configuration, MCP permissions, sandboxing, or dependency provenance. Tool presence does not verify version or functionality.

**Resource limitation:** `os.cpu_count()`, `/proc/meminfo`, and `shutil.disk_usage("/")` provide host-facing observations, not a portable measurement of effective resources available to the process. AICRE does not establish cgroup v1/v2 limits, CPU affinity, orchestrator reservations, or filesystem quotas. Consequently, the `agent-development` profile preserves these observations for context but does not compare them into a Resource `pass` or `fail`; Resource readiness remains `unknown`. Container-aware assessment is deferred until it can be implemented and independently tested without overstating effective capacity.
