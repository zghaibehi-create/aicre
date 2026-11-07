# AICRE Linux Acceptance Evidence

**Purpose:** distinguish automated Linux CI evidence from acceptance on the project owner's intended Linux environment.  
**Current package version:** 0.3.0 (release candidate).  
**Release target:** 0.3.0.

## 1. Automated Linux CI evidence

The following evidence is available from GitHub Actions:

| Evidence | Commit | Environment | Result | Scope |
|---|---|---|---|---|
| Tests run #533 (post-merge on main) | `1d0145752952a0a39e6ffa65510690e57cca1452` | Ubuntu 22.04 and 24.04 × Python 3.11, 3.12, 3.13 | 6/6 jobs passed | Lint, full test suite, CLI entry point |
| Install smoke run #29 (post-merge on main) | `1d0145752952a0a39e6ffa65510690e57cca1452` | Ubuntu 22.04 and 24.04 × Python 3.11, 3.12, 3.13 | 6/6 jobs passed | Wheel and sdist build, clean-venv installs, pip check, CLI/report smoke checks |
| **Final main Tests workflow after PR #33** | `d9ee4977f6057a79c9f1fec2289f2de05ec33c12` | Ubuntu 22.04 and 24.04 × Python 3.11, 3.12, 3.13 | **6/6 jobs passed** | Ruff, full pytest suite, CLI entry point |
| **Final main Install smoke workflow after PR #33** | `d9ee4977f6057a79c9f1fec2289f2de05ec33c12` | Ubuntu 22.04 and 24.04 × Python 3.11, 3.12, 3.13 | **6/6 jobs passed** | Wheel/sdist build, archive inventory, version/metadata/runtime-dependency checks, clean installs, CLI/report smoke checks |
| Tests run #532 (PR #31) | `5ae2128a85de2ece87fb1373ad9c180c00cc6c58` | Ubuntu 22.04 and 24.04 × Python 3.11, 3.12, 3.13 | 6/6 jobs passed | Lint, full test suite, CLI entry point |
| Install smoke run #28 (PR #31) | `5ae2128a85de2ece87fb1373ad9c180c00cc6c58` | Ubuntu 22.04 and 24.04 × Python 3.11, 3.12, 3.13 | 6/6 jobs passed | Wheel and sdist build, clean-venv installs, pip check, CLI/report smoke checks |
| Sample report run #18 (PR #31) | `5ae2128a85de2ece87fb1373ad9c180c00cc6c58` | Ubuntu 24.04 × Python 3.12 | Passed | Sample report generation and conservative Resource readiness check |

Latest main run links:
- [Final main Tests workflow](https://github.com/zghaibehi-create/aicre/actions/runs/42386187695)
- [Final main Install smoke workflow](https://github.com/zghaibehi-create/aicre/actions/runs/42386187780)
- [PR #33 artifact-inspection change](https://github.com/zghaibehi-create/aicre/commit/d9ee4977f6057a79c9f1fec2289f2de05ec33c12)

Earlier evidence:
- [Tests run #533](https://github.com/zghaibehi-create/aicre/actions/runs/42385655762)
- [Install smoke run #29](https://github.com/zghaibehi-create/aicre/actions/runs/42385655772)
- [Tests run #532](https://github.com/zghaibehi-create/aicre/actions/runs/42385579698)
- [Install smoke run #28](https://github.com/zghaibehi-create/aicre/actions/runs/42385579695)
- [Sample report run #18](https://github.com/zghaibehi-create/aicre/actions/runs/42385579678)

The final workflow logs confirm that both workflows checked out the exact main commit above. The install-smoke logs show successful wheel and source-distribution builds, archive inspection, clean virtual-environment installs, `pip check`, CLI execution, and JSON report contract checks. Example artifact hashes are emitted per matrix job; they are build outputs for those CI jobs, not a single canonical release artifact hash.

These are GitHub-hosted Ubuntu runner results. They do not identify or prove acceptance on the project owner's own target machine, filesystem, distribution configuration, or deployment environment. The install-smoke workflow validates CI-built artifacts, not an artifact uploaded to a public release.

## 2. Project-owner target Linux acceptance record

**Status: not supplied.** No claim is made that the owner's own Linux machine was tested.

| Field | Recorded value |
|---|---|
| Distribution and version | Not supplied |
| Kernel and architecture | Not supplied |
| Python version | Not supplied |
| Filesystem type for working directory | Not supplied |
| Installation method | Not supplied |
| AICRE version / commit | Not supplied |
| Test date (UTC) | Not supplied |
| Deviations or failures | Not supplied |

Do not publish private hostnames, usernames, private directory paths, serial numbers, or full inventory reports. AICRE reports may disclose machine and path metadata.

## 3. Reproducible acceptance commands

Run from a clean checkout of the intended release candidate on Linux with Python 3.11 or newer:

```bash
cat /etc/os-release
uname -srmo
python3 --version
stat -f -c '%T' .

python3 -m venv .venv
. .venv/bin/activate
python -m pip install --require-hashes -r .github/requirements-ci.txt
python -m pip install --no-build-isolation --no-deps -e '.[dev]'
python -m pip check

python -m ruff check src tests
python -m pytest -v
aicre --version
aicre readiness --profile agent-development
aicre report --format json | python -c 'import json,sys; r=json.load(sys.stdin); assert r["schema_version"] == "2.0"; assert len(r["readiness"]) == 5; print("JSON report contract: OK")'
```

Record command exit codes and any environment-specific deviations. Do not run as root. Do not use a sensitive directory as a scan fixture. If validating the directory scanner, create a disposable temporary directory with synthetic files and remove it afterward.

## 4. Acceptance criteria

- All commands above complete successfully, except any explicitly documented environment-specific limitation.
- The CLI version matches the candidate under test.
- The JSON report parses and has schema version `2.0` with five independent readiness dimensions.
- Resource readiness remains `unknown` where effective process/container limits are not established.
- No unexpected network, telemetry, source-content reads, program execution, privilege elevation, or system modifications are observed.
- Any failure is triaged, fixed if blocking, and retested on the candidate commit.

## 5. Release gate

Automated CI acceptance for the declared Ubuntu support matrix is complete on the recorded main commit. Owner-machine-specific acceptance remains untested and is not implied by the CI results. The release decision must state whether that additional machine-specific check is required for the intended audience.
