# AICRE 0.2.0 — Linux-first inventory and readiness preview

**Independent AI Computer Readiness Engine (AICRE)** is a local-first Linux CLI for collecting a narrow set of environment metadata and presenting separate, evidence-backed readiness dimensions. It does not run AI agents, install software, change system settings, or send machine information anywhere.

> **Preview status:** AICRE is an experimental inventory tool, not a security product, agent sandbox, malware scanner, secret scanner, or guarantee that a computer is safe for autonomous agents. The 0.2 implementation is not a release approval; independent review remains required.

## Privacy and collection boundaries

AICRE uses only narrowly scoped local sources: Python's `platform`, `os`, `sys`, and `sysconfig` interfaces; Linux `/etc/os-release`/`/usr/lib/os-release`, `/proc/meminfo`, `/sys/class/drm` vendor/device identifiers; `shutil.disk_usage("/")`; and `shutil.which` for a fixed allowlist of executable names. The allowlist is `git`, `python3`, `pip`, `uv`, `pipx`, `node`, `npm`, `docker`, `podman`, `codex`, `claude`, `aider`, and `ollama`. Tool detection searches permitted `PATH` entries only: `detected` does not verify version or functionality, and `not_detected` does not prove the tool is absent elsewhere.

AICRE does not execute discovered programs, read credentials, API keys, `.env` contents, private keys, chat histories, or user documents. It makes no network requests or telemetry calls and does not perform remediation. Filesystem sources and executable paths are filtered through built-in sensitive-path policy and any `--exclude` patterns before reading or disclosing them. An excluded result is reported as `not_checked`, not as absent. Exclusion patterns are not persisted.

Reports can contain hardware details, software availability, and executable paths. Review a report before sharing it. Built-in path rules are conservative and cannot discover every secret.

## Findings and readiness

Each finding has a stable ID, category, collection status, value and optional unit, named source, confidence, UTC collection timestamp, and limitations. Finding statuses are `detected`, `not_detected`, `unsupported`, `permission_denied`, `error`, and `not_checked`.

Each report contains five separate readiness dimensions: Resource, Software, Compatibility, Privacy, and Security. Each dimension returns `pass`, `warning`, `fail`, or `unknown`, an explanation, and finding IDs used as evidence. AICRE does not calculate a composite score. Resource and Software readiness remain `unknown` until workload resource thresholds and a required software manifest are defined. The standard Compatibility profile explicitly checks Linux and Python `>=3.11`; it has no GPU requirement. Security readiness is deliberately limited: root execution produces a warning, while non-root execution does not imply that other host security controls passed. Privacy findings describe AICRE behavior, not host-wide privacy.

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

## Project documents

- [Security model](docs/SECURITY_MODEL.md)
- [Roadmap](docs/ROADMAP.md)
- [Security reporting](SECURITY.md)
- [Canonical report schema](schemas/report-v1.schema.json)
- [Report schema and identity design](docs/schema.md)
- [Contributing](CONTRIBUTING.md)
- [JSON report schema](schemas/report-v2.schema.json)

## Report formats and comparisons

Render a canonical report as plain text, JSON, Markdown, HTML, or PDF:

```bash
aicre report --format text
aicre report --format json
aicre report --format markdown --output "$HOME/reports/aicre.md"
aicre report --format html --output "$HOME/reports/aicre.html"
aicre scan --profile standard --format html --output "$HOME/reports/system.html"
```

PDF is optional: install it with `python -m pip install -e '.[pdf]'`, then use `--format pdf`. The PDF renderer rejects characters outside its built-in WinAnsi font set rather than silently misrendering Arabic or other unsupported scripts. HTML has no scripts, remote assets, CDN dependencies, or external fonts. POSIX output files are created with mode `0600`; parent directories are created and existing regular files are atomically replaced.

Render a previously saved JSON report, or compare two snapshots:

```bash
aicre report --input "$HOME/aicre-report.json" --format html --output "$HOME/aicre.html"
aicre report --diff before.json after.json --format json
aicre report --diff before.json after.json --format markdown --output changes.md
```

The diff classifies checks as `new`, `resolved`, `unchanged`, or `changed`. `--open` opens a completed output with `xdg-open` on Linux only. Exit code `3` indicates an unsupported output format or missing optional PDF support; `6` indicates that opening is unsupported on the current platform; `7` indicates that `xdg-open` could not be launched.

## License

MIT. See [LICENSE](LICENSE).

## Workload profiles

The default `standard` profile is inventory-only and deliberately leaves Resource and Software readiness unknown. The optional `agent-development` profile compares CPU count (>=2), total RAM (>=8 GiB), free root-filesystem storage (>=10 GiB), and PATH presence of Git and Python 3.

```bash
aicre readiness --profile agent-development
aicre report --profile agent-development --format json
```

This is an advisory project-defined minimum, not a vendor specification or performance/safety guarantee. It does not assess local model inference, GPU drivers, concurrency, agent configuration, MCP permissions, sandboxing, or dependency provenance. Tool presence does not verify version or functionality.

**Container and constrained-environment limitation:** this profile currently uses host-facing observations (`os.cpu_count()` and `/proc/meminfo`) and does not account for cgroup CPU/memory quotas or CPU-affinity restrictions. In containers or restricted execution environments, reported CPU/RAM may exceed what the process can actually use. Treat the resource result as host-observation-only until container-aware limits are implemented and independently tested.
