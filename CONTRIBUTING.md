# Contributing to AICRE

Thank you for considering a contribution.

## Before you start

- Read `README.md`, `SECURITY.md`, and `docs/SECURITY_MODEL.md`.
- Keep changes small and explain the security or usability reason for each change.
- Do not add telemetry, network calls, content-reading behavior, privilege elevation, or source-file modifications without a separately reviewed design and explicit approval.
- Never include real credentials, private inventories, personal paths, or customer data in issues, tests, or pull requests.

## Copyright and licensing

AICRE is distributed under the MIT License; see `LICENSE`. Contributions accepted into this repository are made available under that same MIT License.

By submitting a contribution, you confirm that you have the right and any necessary permissions to submit it, and you agree that the contribution may be distributed under the repository's MIT License. You retain any copyright you hold in your original contribution; submission does not assign that copyright to the project or repository owner. No separate Contributor License Agreement (CLA) or Developer Certificate of Origin (DCO) is currently required.

Do not submit code, documentation, datasets, images, or other material unless you created it or have permission to contribute it under the MIT License. Preserve third-party notices and disclose material third-party origins in the pull request. If your employer, client, or another agreement may own or restrict the work, resolve that issue before submitting it.

See [Legal Notices](docs/LEGAL_NOTICES.md) for the project's current copyright, privacy, third-party, and international-use notices.

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
