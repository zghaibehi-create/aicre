# Third-Party Notices and Dependency Inventory

**Audit snapshot:** 2026-11-07  
**Reviewed repository commit:** `16b6bee59422d97a8686d2b973c23342010225a8`  
**Purpose:** record third-party software used by development/build automation and distinguish it from the AICRE runtime distribution.

## 1. Project-authored content and repository inventory

The tracked repository tree at the audit snapshot contains the AICRE application, tests, documentation, JSON schemas, agent skill, GitHub workflows, and project metadata.

A static review of the tracked application source, test suite, documentation, schemas, and CI configuration found:
- No vendored third-party source tree or bundled third-party application asset.
- No embedded third-party license headers, SPDX identifiers, or copied external code blocks identified in the reviewed files.
- No declared runtime dependencies in `pyproject.toml`.
- The JSON schemas identify the JSON Schema Draft 2020-12 meta-schema by its standard URI; the meta-schema itself is not copied into this repository.
- The GitHub Actions workflows use upstream `actions/checkout` and `actions/setup-python`, pinned to full commit SHAs. These actions are hosted automation dependencies, not source files included in the AICRE wheel.

This is a bounded repository inspection, not proof of authorship by forensic analysis or a legal opinion. The project owner separately confirmed on 2026-11-07 that they hold the rights necessary to distribute all current AICRE content under MIT. That representation remains the basis for the project's ownership claim.

## 2. Runtime and build dependencies

| Component | Version / source | Role | Declared license | Distributed in AICRE runtime? |
|---|---|---|---|---|
| AICRE application | 0.2.1 at audit snapshot | Application | MIT | Yes |
| Runtime dependencies | None declared | Runtime | Not applicable | No |
| setuptools | 84.1.0 | PEP 517 build backend | MIT | No |
| pytest | 9.2.0 | Tests | MIT | No |
| Ruff | 0.17.4 | Linting | MIT | No |
| fastjsonschema | 2.21.2 | Test-time JSON Schema validation | BSD (upstream PyPI metadata) | No |

## 3. Locked CI toolchain and transitive packages

The CI lock file `.github/requirements-ci.txt` pins package versions and SHA-256 hashes. The following packages are installed for build, test, or lint jobs; they are not AICRE runtime dependencies.

| Package | Locked version | Upstream license metadata |
|---|---:|---|
| pip | 26.3 | MIT |
| setuptools | 84.1.0 | MIT |
| pytest | 9.2.0 | MIT |
| iniconfig | 2.3.1 | MIT |
| packaging | 26.3 | Apache-2.0 OR BSD-2-Clause |
| pluggy | 1.7.0 | MIT |
| Pygments | 2.21.0 | BSD-2-Clause |
| Ruff | 0.17.4 | MIT |
| fastjsonschema | 2.21.2 | BSD (upstream metadata uses the generic BSD label) |

License metadata was checked against the corresponding upstream PyPI project/release records on 2026-11-07. For fastjsonschema, the PyPI record identifies an OSI-approved BSD license but does not provide a precise SPDX expression in the surfaced release metadata. Do not invent a BSD variant. If this package or its source is ever copied into a distributed AICRE artifact, inspect the exact upstream LICENSE file and preserve all required notices first.

## 4. GitHub Actions and hosted services

The repository's workflows currently pin:
- `actions/checkout` to `3d3c42e5aac5ba805825da76410c181273ba90b1`
- `actions/setup-python` to `6d4fd22b20465ccc0f7354476588e8df7c9ca0e0`

The upstream projects publish these actions under the MIT License. Their source is fetched and executed by GitHub Actions; it is not bundled into AICRE's Python package. GitHub-hosted runners, repository hosting, issue tracking, and artifact storage are third-party services governed by their own terms.

## 5. Distribution and notice policy

- Keep `dependencies = []` unless a reviewed product decision explicitly changes the runtime dependency model.
- Keep development/test dependencies separate from runtime dependencies.
- Continue pinning CI dependencies and verifying hashes.
- Before copying, vendoring, or redistributing any third-party code, data, documentation, icon, image, font, or generated artifact, record its exact origin, version, license, required notices, and intended distribution scope.
- Recheck the actual wheel and source distribution at release time. This source-tree audit does not replace artifact inspection.
- Do not treat the AICRE MIT License as a license for GitHub Actions, PyPI packages, JSON Schema specifications, or other third-party services and components.

## 6. Audit disposition

**Repository source inventory:** no vendored third-party code or assets were identified in the reviewed tracked files at the audit snapshot.

**Dependency license inventory:** development/build dependencies and the two GitHub Actions are identified above; none is declared as an AICRE runtime dependency.

**Remaining limitations:** upstream metadata is not a substitute for checking the exact license file if any dependency is ever redistributed; future contributions and release artifacts must be reviewed; owner attestation is not a forensic authorship audit.

Review this file whenever dependencies, workflows, vendored files, assets, or distribution contents change.
