# Contributing to AICRE

Thank you for considering a contribution.

## Before you start

- Read `README.md`, `SECURITY.md`, and `docs/SECURITY_MODEL.md`.
- Keep changes small and explain the security or usability reason for each change.
- Do not add telemetry, network calls, content-reading behavior, privilege elevation, or source-file modifications without a separately reviewed design and explicit approval.
- Never include real credentials, private inventories, personal paths, or customer data in issues, tests, or pull requests.

## Development

```bash
python3 -m venv .venv
source .venv/bin/activate
python -m pip install -e '.[dev]'
ruff check src tests
pytest -v
```

## Pull requests

- Describe the behavior change and its threat-model implications.
- Add tests for normal behavior and relevant failure/abuse cases.
- Keep the JSON report aligned with `schemas/report-v2.schema.json`; schema validation runs as part of the tests.
- Confirm that source files are not opened or modified by scanner code.
- Update documentation when behavior, supported platforms, or limitations change.
- Do not claim a platform is supported unless its CI and acceptance checks have passed.
