# AICRE Linux Acceptance Evidence

**Purpose:** distinguish automated Linux CI and package-artifact evidence from acceptance on the project owner's own Linux machine. No owner-machine acceptance is claimed.

## Current release: 0.4.0 (published)

The final release [`v0.4.0`](https://github.com/zghaibehi-create/aicre/releases/tag/v0.4.0) was published on 2026-11-09 from main merge commit `9a2300e3bddd7badc9dd25b3d493bc5481e79027`. PR [#40](https://github.com/zghaibehi-create/aicre/pull/40) is merged. The tag is a final release, not a draft or prerelease.

| Evidence | Result | Scope |
|---|---:|---|
| [Post-merge Tests run 42589858188](https://github.com/zghaibehi-create/aicre/actions/runs/42589858188) | 6/6 passed | Ubuntu 22.04 and 24.04 × Python 3.11, 3.12, 3.13; Ruff, full test suite, CLI entry point |
| [Post-merge Install smoke run 42589858166](https://github.com/zghaibehi-create/aicre/actions/runs/42589858166) | 6/6 passed | Wheel/sdist build and archive inspection, clean installs, `pip check`, legacy/canonical report, import, Markdown render, and diff commands |
| [Sample report run 42588959452](https://github.com/zghaibehi-create/aicre/actions/runs/42588959452) | Passed | GitHub-hosted Ubuntu 24.04 × Python 3.12; readiness sample on the final PR candidate |
| Local candidate validation | Passed | `ruff check src tests`; `pytest -v` (218 passed with optional ReportLab); hostile-markup PDF smoke |
| Local wheel/sdist acceptance | Passed | Both artifacts inspected and installed in clean virtual environments; `pip check` and installed report/import/render/diff checks passed |

Published release artifacts and hashes:

- [`aicre-0.4.0-py3-none-any.whl`](https://github.com/zghaibehi-create/aicre/releases/download/v0.4.0/aicre-0.4.0-py3-none-any.whl) — SHA-256 `5b6e5461d66d1a62424fc57a258c54b7de5bc4442c37c79cb803ffebdd969182`
- [`aicre-0.4.0.tar.gz`](https://github.com/zghaibehi-create/aicre/releases/download/v0.4.0/aicre-0.4.0.tar.gz) — SHA-256 `f9a9afc3103d90f6c467c4ddc5abfba8942bfacbfcd77d0b2d578a09aba23c6c`
- [`SHA256SUMS.txt`](https://github.com/zghaibehi-create/aicre/releases/download/v0.4.0/SHA256SUMS.txt) — downloaded release manifest.

These values match the repository's [0.4.0 checksum manifest](release-assets/SHA256SUMS-v0.4.0.txt); the published GitHub assets were downloaded and verified with `sha256sum -c`. Both distributions were installed and exercised in clean environments. The package has no runtime dependencies.

## Historical release: 0.3.0

`v0.3.0` is an experimental GitHub pre-release published on 2026-11-07 from tagged commit `530920cfa4a5fb7a3619f4e624157772230b157d`. It predates the canonical multi-format reporting and snapshot-diff changes in PR #4, which are included in the later 0.4.0 release. Historical candidate CI evidence:

- [Tests run #566 — 6/6](https://github.com/zghaibehi-create/aicre/actions/runs/42386970651) and [install smoke run #38 — 6/6](https://github.com/zghaibehi-create/aicre/actions/runs/42386970639), on the Ubuntu 22.04/24.04 × Python 3.11/3.12/3.13 matrix.
- [Sample report run #19](https://github.com/zghaibehi-create/aicre/actions/runs/42386970661) passed on Ubuntu 24.04 × Python 3.12.
- 0.3.0 artifacts from the Ubuntu 24.04/Python 3.12 job were `aicre-0.3.0-py3-none-any.whl` (SHA-256 `133c0ed5cbc56b040e53766c1aeb16b47ee18640f86ad805907eb187387d0c9c`) and `aicre-0.3.0.tar.gz` (SHA-256 `47de24dce9d59927d86c0c441ca8eda22a92d73b606c627599c32037396f0a71`). Those hashes identify that historical CI job only.

Earlier main/PR matrix evidence remains available in the [GitHub Actions history](https://github.com/zghaibehi-create/aicre/actions). Historical 0.3.0 runs are not evidence for the 0.4.0 release.

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

Run from a clean checkout of the tagged release on Linux with Python 3.11 or newer. Do not run as root or scan a sensitive directory; use disposable synthetic fixtures for directory-scan checks.

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

Automated Linux and artifact acceptance is complete for release tag `v0.4.0` at commit `9a2300e3bddd7badc9dd25b3d493bc5481e79027`; PR #40 is merged and the verified wheel, sdist, and checksum manifest are published. No acceptance test on the owner's personal Linux machine is supplied; the CI matrix describes GitHub-hosted runner evidence only. The 0.3.0 owner decision is historical.
