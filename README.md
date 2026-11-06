# AICRE 0.1.0 — Linux Preview

**AI Computer Readiness Engine** is an experimental local, metadata-only inventory prototype intended to help users understand a directory before preparing a computer for AI-agent workflows.

> **Preview status:** This is an experimental Linux-first preview, not a security product, agent sandbox, malware scanner, or guarantee that a computer is safe for autonomous agents. Use it only on directories you own or are authorized to inspect. Review the report before sharing it.

## What this version does

- Scans a directory selected by the user.
- Records relative paths, item type, extension, file size, and last-modified UTC timestamp.
- Counts path names, not unique underlying files; hard-linked source paths appear as separate entries.
- Does **not** open or read source-file contents.
- Does **not** modify, move, rename, or delete source items.
- Skips symbolic links and, on supported POSIX systems, opens directories relative to the selected root without following path-component symlinks.
- Does not descend into entries whose filesystem device differs from the scan root; same-device bind mounts are not reliably detected.
- Excludes selected credential directories and names, plus user-specified path patterns. The path-based policy is conservative but cannot identify every secret.
- Writes a JSON report outside the scan root using a temporary file and atomic publication. Existing symlink, hard-link, directory, device, FIFO, and other non-regular report destinations are rejected.
- Creates report files with owner-only `0600` permissions on POSIX systems. `--force` replaces an existing regular report atomically; it does not truncate an existing file in place.

The scanner is not a filesystem snapshot. Concurrent changes can make results incomplete or inconsistent. It reports an aggregate scan-error count, not a diagnostic path for each error. See [SECURITY.md](SECURITY.md) and [docs/SECURITY_MODEL.md](docs/SECURITY_MODEL.md) before use.

## Platform and requirements

- **Initial target:** Linux (Ubuntu 24.04 LTS is the CI target).
- Python 3.11 or newer is declared; the automated test matrix covers Python 3.11, 3.12, and 3.13.
- No runtime third-party dependencies.
- CI installs hash-locked build, test, and lint tools from `.github/requirements-ci.txt`.

Windows support is planned, but this preview is not being advertised as Windows-validated. The descriptor-relative no-follow scan implementation requires platform support for those filesystem operations and refuses to scan where they are unavailable.

## Install from a local clone

```bash
python3 --version
python3 -m venv .venv
source .venv/bin/activate
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

To intentionally replace an existing regular report:

```bash
aicre scan "$HOME/Documents" --output "$HOME/aicre-inventory.json" --force
```

A hard-linked report destination is refused even with `--force`; choose a new, ordinary file path instead. Reports include a summary of included items, excluded items, and scan errors. Inaccessible entries are skipped and counted as errors rather than guessed.

## Safety recommendations

1. Run as your ordinary user; do not use `sudo`.
2. Start with a small, non-sensitive test directory.
3. Set explicit `--exclude` patterns for private projects and folders.
4. Keep the JSON report private. Filenames and metadata can themselves reveal sensitive information.
5. Do not interpret a successful scan as proof that every secret was excluded.
6. A non-zero `scan_errors` count means the inventory is incomplete.

## Development and tests

```bash
python -m pip install -e '.[dev]'
pytest -v
```

GitHub Actions runs Ruff and the test suite on Ubuntu 24.04 with Python 3.11, 3.12, and 3.13. Check the repository's Actions tab for the result on the commit or pull request you are reviewing. A green workflow verifies only the checks it runs; it does not establish production readiness or remove the limitations in the security model.

## Project documents

- [Security model](docs/SECURITY_MODEL.md)
- [Roadmap](docs/ROADMAP.md)
- [Security reporting](SECURITY.md)
- [Contributing](CONTRIBUTING.md)

## License

MIT. See [LICENSE](LICENSE).
