# AICRE Linux Acceptance Evidence

**Purpose:** distinguish automated Linux CI and package-artifact evidence from acceptance on the project owner's own Linux machine. No owner-machine acceptance is claimed.

## Current candidate: 0.4.0 (not yet published)

PR [#40](https://github.com/zghaibehi-create/aicre/pull/40) is open against `main`; implementation commit `f28c837e1dab81f556fcd8bfcc3a62d1ee5eb35d` passed the listed checks. The candidate branch now also records final release evidence and broadens install-smoke triggers to package inputs; those follow-up changes are being revalidated. No 0.4.0 commit has been merged, tagged, or published. The currently published version remains the historical experimental pre-release `v0.3.0`.

| Evidence | Result | Scope |
|---|---:|---|
| [Tests workflow run 42587555664](https://github.com/zghaibehi-create/aicre/actions/runs/42587555664) | 6/6 passed | Ubuntu 22.04 and 24.04 × Python 3.11, 3.12, 3.13; Ruff, full test suite, CLI entry point |
| [Install smoke run 42587555636](https://github.com/zghaibehi-create/aicre/actions/runs/42587555636) | 6/6 passed | Wheel/sdist build and archive inspection, clean installs, `pip check`, legacy/canonical report, import, Markdown render, and diff commands |
| [Sample report run 42587555625](https://github.com/zghaibehi-create/aicre/actions/runs/42587555625) | Passed | GitHub-hosted Ubuntu 24.04 × Python 3.12; readiness sample |
| Local candidate validation | Passed | `ruff check src tests`; `pytest -v` (218 passed with optional ReportLab); hostile-markup PDF smoke |
| Local wheel/sdist acceptance | Passed | Both artifacts inspected and installed in clean virtual environments; `pip check` and installed report/import/render/diff checks passed |

Local candidate artifact hashes (the artifacts are not yet attached to a GitHub release):

- `aicre-0.4.0-py3-none-any.whl` — SHA-256 `5b6e5461d66d1a62424fc57a258c54b7de5bc4442c37c79cb803ffebdd969182`
- `aicre-0.4.0.tar.gz` — SHA-256 `f9a9afc3103d90f6c467c4ddc5abfba8942bfacbfcd77d0b2d578a09aba23c6c`

These values are verified by the repository's [0.4.0 checksum manifest](release-assets/SHA256SUMS-v0.4.0.txt), prepared for attachment as `SHA256SUMS.txt`. The package contains no runtime dependencies. Final publication remains gated on PR review/merge and explicit owner approval.

## Historical release: 0.3.0

`v0.3.0` is an experimental GitHub pre-release published on 2026-11-07 from tagged commit `530920cfa4a5fb7a3619f4e624157772230b157d`. It predates the canonical multi-format reporting and snapshot-diff changes in PR #4 and the current 0.4.0 candidate. Historical candidate CI evidence:

- [Tests run #566 — 6/6](https://github.com/zghaibehi-create/aicre/actions/runs/42386970651) and [install smoke run #38 — 6/6](https://github.com/zghaibehi-create/aicre/actions/runs/42386970639), on the Ubuntu 22.04/24.04 × Python 3.11/3.12/3.13 matrix.
- [Sample report run #19](https://github.com/zghaibehi-create/aicre/actions/runs/42386970661) passed on Ubuntu 24.04 × Python 3.12.
- 0.3.0 artifacts from the Ubuntu 24.04/Python 3.12 job were `aicre-0.3.0-py3-none-any.whl` (SHA-256 `133c0ed5cbc56b040e53766c1aeb16b47ee18640f86ad805907eb187387d0c9c`) and `aicre-0.3.0.tar.gz` (SHA-256 `47de24dce9d59927d86c0c441ca8eda22a92d73b606c627599c32037396f0a71`). Those hashes identify that historical CI job only.

Earlier main/PR matrix evidence remains available in the [GitHub Actions history](https://github.com/zghaibehi-create/aicre/actions). It must not be presented as evidence for the 0.4.0 candidate.

## Project-owner target Linux acceptance

**Status: not supplied.** These are GitHub-hosted runner results, not proof of acceptance on the owner's machine, filesystem, distribution configuration, or deployment environment. Do not publish private hostnames, usernames, private directory paths, serial numbers, or full inventory reports; AICRE reports may disclose machine and path metadata.

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

## Reproducible acceptance commands

Run from a clean checkout of the intended release candidate on Linux with Python 3.11 or newer. Do not run as root or scan a sensitive directory; use disposable synthetic fixtures for directory-scan checks.

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
aicre report | python -c 'import json,sys; r=json.load(sys.stdin); assert r["schema_version"] == "2.0"; assert len(r["readiness"]) == 5'
aicre report --format json | python -c 'import json,sys; r=json.load(sys.stdin); assert r["schema_version"] == "1.0.0"; assert len(r["readiness"]) == 5'
```

Record command exit codes and environment-specific deviations. Confirm that unknown Resource readiness remains unknown where effective process/container limits are not established, and that no unexpected network, telemetry, source-content reads, program execution, privilege elevation, or system modifications occur.

## Release gate

Automated Linux acceptance for the 0.4.0 candidate is complete only after the final matrix for the current PR head passes; the implementation commit listed above already passed its matrix. The outstanding steps are current-head revalidation, final PR review/merge, and owner authorization to publish the final release and attach the verified artifacts plus `SHA256SUMS.txt`. The 0.3.0 owner decision accepting CI evidence is historical and does not constitute publication approval for 0.4.0.
