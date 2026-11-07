# AICRE Linux Acceptance Evidence

**Purpose:** distinguish automated Linux CI evidence from acceptance on the project owner's intended Linux environment.  
**Current package version:** 0.2.1.  
**Release target:** 0.3.0.

## 1. Automated Linux CI evidence

The following evidence is available from GitHub Actions:

| Evidence | Environment | Result | Scope |
|---|---|---|---|
| Tests run #522 on the ownership-notice merge commit `16b6bee59422d97a8686d2b973c23342010225a8` | Ubuntu 22.04 and 24.04 × Python 3.11, 3.12, 3.13 | 6/6 jobs passed | Lint, test suite, CLI entry point |
| Install smoke run #25 (PR #27) | Ubuntu 22.04 and 24.04 × Python 3.11, 3.12, 3.13 | 6/6 jobs passed | Wheel and sdist build, clean-venv installs, pip check, CLI/report smoke checks |
| Tests run #506 (PR #27) | Ubuntu 22.04 and 24.04 × Python 3.11, 3.12, 3.13 | 6/6 jobs passed | Test suite and CI checks |

Links:
- [Tests run #522](https://github.com/zghaibehi-create/aicre/actions/runs/42385122338)
- [Install smoke run #25](https://github.com/zghaibehi-create/aicre/actions/runs/42382558680)
- [Tests run #506](https://github.com/zghaibehi-create/aicre/actions/runs/42382558691)

These are GitHub-hosted Ubuntu runner results. They do not identify or prove acceptance on the project owner's own target machine, filesystem, distribution configuration, or deployment environment.

## 2. Project-owner target Linux acceptance record

**Status: awaiting owner-supplied environment evidence.**

Fill this section only after running the commands below on the intended target Linux machine.

| Field | Recorded value |
|---|---|
| Distribution and version | Not yet supplied |
| Kernel and architecture | Not yet supplied |
| Python version | Not yet supplied |
| Filesystem type for working directory | Not yet supplied |
| Installation method | Not yet supplied |
| AICRE version / commit | Not yet supplied |
| Test date (UTC) | Not yet supplied |
| Deviations or failures | Not yet supplied |

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

Automated CI is useful Linux evidence but is not a substitute for the project-owner target-environment record above. Do not mark the owner acceptance gate complete until the table in Section 2 is populated and reviewed.
