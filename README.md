# AICRE 0.1.0 — Linux Preview

**AI Computer Readiness Engine** is a local, metadata-only inventory prototype intended to help users understand the contents of a directory before preparing a computer for AI-agent workflows.

> **Preview status:** This is an experimental Linux-first preview, not a security product, agent sandbox, malware scanner, or guarantee that a computer is safe for autonomous agents. Use it only on directories you own or are authorized to inspect. Review the report before sharing it.

## What this version does

- Scans a directory selected by the user.
- Records relative paths, item type, extension, file size, and last-modified UTC timestamp.
- Does **not** open or read source-file contents.
- Does **not** modify, move, rename, or delete source items.
- Skips symbolic links and Windows reparse points detected by the current implementation.
- Excludes known sensitive names and locations, plus user-specified path patterns.
- Writes a JSON report outside the scan root.
- Refuses to overwrite an existing report unless `--force` is explicitly supplied.

The scanner is not a filesystem snapshot. Concurrent changes to the scanned tree can affect results. See [SECURITY.md](SECURITY.md) and [docs/SECURITY_MODEL.md](docs/SECURITY_MODEL.md) before use.

## Platform and requirements

- **Initial target:** Linux (Ubuntu 24.04 LTS is the intended first community test target).
- Python 3.11 or newer.
- No runtime third-party dependencies.
- The current test suite has been run in the project development environment; a clean Ubuntu release-matrix run is pending the first GitHub Actions run.

Windows support is planned, but this preview is not being advertised as Windows-validated.

## Install from a local clone

```bash
python3 --version
python3 -m venv .venv
source .venv/bin/activate
python -m pip install --upgrade pip
python -m pip install -e '.[dev]'
```

## Usage

Choose a source directory and a report destination **outside** it:

```bash
aicre --version
aicre scan "$HOME/Documents" --output "$HOME/aicre-inventory.json"
```

Exclude private paths. Patterns are matched against relative POSIX-style paths:

```bash
aicre scan "$HOME/Documents" \
  --output "$HOME/aicre-inventory.json" \
  --exclude 'Projects/Client-A/**' \
  --exclude '**/Personal/**'
```

To intentionally replace an existing report:

```bash
aicre scan "$HOME/Documents" --output "$HOME/aicre-inventory.json" --force
```

The JSON report includes a summary of included items, excluded items, and scan errors. Inaccessible entries are skipped and counted as errors rather than guessed.

## Safety recommendations

1. Run as your ordinary user; do not use `sudo`.
2. Start with a small, non-sensitive test directory.
3. Set explicit `--exclude` patterns for private projects and folders.
4. Keep the JSON report private. Filenames and metadata can themselves reveal sensitive information.
5. Do not interpret a successful scan as proof that every secret was excluded.

## Development and tests

```bash
python -m pip install -e '.[dev]'
pytest -v
```

GitHub Actions runs the test suite on the configured Ubuntu/Python matrix after the repository is published. A green CI run is required before calling the Linux preview validated.

## Project documents

- [Security model](docs/SECURITY_MODEL.md)
- [Roadmap](docs/ROADMAP.md)
- [Security reporting](SECURITY.md)
- [Contributing](CONTRIBUTING.md)

## License

MIT. See [LICENSE](LICENSE).
