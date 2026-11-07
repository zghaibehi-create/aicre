# AICRE 0.2.1 — Linux-first inventory and readiness preview

**Independent AI Computer Readiness Engine (AICRE)** is a local-first Linux CLI for collecting a narrow set of environment metadata and presenting separate, evidence-backed readiness dimensions. It does not run AI agents, install software, change system settings, or send machine information anywhere.

> **Preview status:** AICRE is an experimental inventory tool, not a security product, agent sandbox, malware scanner, secret scanner, or guarantee that a computer is safe for autonomous agents. The 0.2 implementation is not a release approval; independent review remains required.

## Privacy and collection boundaries

AICRE uses only narrowly scoped local sources: Python's `platform`, `os`, `sys`, and `sysconfig` interfaces; Linux `/etc/os-release`/`/usr/lib/os-release`, `/proc/meminfo`, `/sys/class/drm` vendor/device identifiers; `shutil.disk_usage("/")`; and `shutil.which` for a fixed allowlist of executable names. The allowlist is `git`, `python3`, `pip`, `uv`, `pipx`, `node`, `npm`, `docker`, `podman`, `codex`, `claude`, `aider`, and `ollama`. Tool detection searches permitted `PATH` entries only: `detected` does not verify version or functionality, and `not_detected` does not prove the tool is absent elsewhere.

AICRE does not execute discovered programs, read credentials, API keys, `.env` contents, private keys, chat histories, or user documents. It makes no network requests or telemetry calls and does not perform remediation. Filesystem sources and executable paths are filtered through built-in sensitive-path policy and any `--exclude` patterns before reading or disclosing them. An excluded result is reported as `not_checked`, not as absent. Exclusion patterns are not persisted.

Reports can contain hardware details, software availability, and executable paths. Review a report before sharing it. Built-in path rules are conservative and cannot discover every secret.

## Findings and readiness

Each finding has a stable ID, category, collection status, value and optional unit, named source, confidence, UTC collection timestamp, and limitations. Finding statuses are `detected`, `not_detected`, `unsupported`, `permission_denied`, `error`, and `not_checked`.

Each report contains five separate readiness dimensions: Resource, Software, Compatibility, Privacy, and Security. Each dimension returns `pass`, `warning`, `fail`, or `unknown`, an explanation, and finding IDs used as evidence. Resource and Software readiness are evaluated against the selected workload profile. The default `standard` profile remains inventory-only and leaves both dimensions `unknown`. The opt-in `--composite` report summary provides a weighted overview; it does not replace the five separate readiness dimensions. The standard Compatibility profile explicitly checks Linux and Python `>=3.11`; it has no GPU requirement. Security readiness is deliberately limited: root execution produces a warning, while non-root execution does not imply that other host security controls passed. Privacy findings describe AICRE behavior, not host-wide privacy.

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
aicre report --profile laptop-dev --output "$HOME/aicre-report-composite.json" --composite
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

## Project documents

- [Security model](docs/SECURITY_MODEL.md)
- [Roadmap](docs/ROADMAP.md)
- [Security reporting](SECURITY.md)
- [Contributing](CONTRIBUTING.md)
- [JSON report schema](schemas/report-v2.schema.json)

## License

MIT. See [LICENSE](LICENSE).

## Workload profiles

The default `standard` profile is inventory-only. The `agent-development`
profile is retained for compatibility. Additional profiles are:

| Profile | CPU cores | RAM | Free root storage | Required tools |
|---|---:|---:|---:|---|
| `laptop-dev` | 4 | 16 GiB | 20 GiB | git, python3, node |
| `agent-workstation` | 8 | 32 GiB | 50 GiB | git, python3, docker, ollama |
| `ci-runner` | 2 | 8 GiB | 10 GiB | git, python3, pip |

Resource values below 50% of a profile threshold fail, values from 50% to
below 100% warn, and values at or above the threshold pass. Missing observations
remain unknown. Software readiness passes when all required tools are found,
warns for one missing tool, and fails for two or more missing tools; when all
tool observations are unavailable, it remains unknown. Tool presence is based
on permitted PATH entries only; programs are never executed.

The optional composite output is written beside the main report as
`report.summary.json`. It uses Resource 40%, Software 30%, Compatibility 15%,
Privacy 10%, and Security 5%; unknown dimensions are excluded from the average.
The summary is advisory and does not replace the full report.

```bash
aicre readiness --profile agent-development
aicre report --profile laptop-dev --format json --output "$HOME/aicre-report.json" --composite
```

These are project-defined minimums, not vendor specifications or performance
or safety guarantees. No profile currently requires a GPU. AICRE does not
assess local model inference performance, drivers, concurrency, agent
configuration, MCP permissions, sandboxing, or dependency provenance.

**Container and constrained-environment limitation:** resource observations
remain host-facing and do not account for cgroup CPU/memory quotas or
CPU-affinity restrictions. Treat the result as a host-observation-only
assessment.
