# Changelog

All notable changes to AICRE are documented here.

## [0.3.0] - Unreleased

### Added
- Canonical report schema 1.0.0 adapter with SHA-256 finding identifiers and deterministic UUIDv5 scan IDs.
- Markdown and self-contained offline HTML report rendering.
- Optional PDF rendering through ReportLab's built-in fonts.
- Saved-report input rendering and JSON/Markdown/HTML/PDF comparison output.
- Linux-only `--open` support through `xdg-open`.
- Atomic output publication, automatic parent-directory creation, and private POSIX file permissions.

### Compatibility
- Legacy `aicre scan --profile standard` without `--format` retains the 0.2 human-readable output path.
- The package version remains 0.2.0 on this implementation branch until the release candidate is approved; the 0.3.0 changelog entry is unreleased.
