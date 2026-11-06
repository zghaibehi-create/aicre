# AICRE report contract

## Legacy and canonical reports

AICRE 0.2's existing JSON report remains schema version `2.0` and retains the existing `Finding` dataclass. The Phase 1 report pipeline maps that model into the canonical `1.0.0` document rather than replacing collector models or duplicating their responsibilities.

The adapter maps `Finding.id` to `check_id`, `Finding.source` to `collector_id`, and preserves category, status, value, confidence, unit, collection time, and limitations. Canonical `id` is the lowercase SHA-256 hex digest of the collector ID, check ID, and normalized evidence (status, value, unit). `check_id` remains available as the semantic comparison key.

## Scan identity and determinism

The specification's random UUIDv4 requirement conflicts with its requirement that identical observations produce deterministic report identity. Canonical reports therefore use an RFC 4122 UUIDv5 derived from a stable serialization of profile and finding evidence. Timestamps are excluded from the scan identity. This is deliberately not described as UUIDv4.

`generated_at` and per-finding `collected_at` remain wall-clock timestamps and therefore vary between separate scans. Ordering, finding IDs, and scan identity are deterministic for equivalent normalized observations. Consumers requiring byte-identical artifacts should normalize or omit timestamps before comparing complete documents.

## Diff semantics

Diffs match findings by `check_id`, not evidence-derived hash ID. This is necessary because an evidence change changes the SHA-256 ID. The classifications are:

- `new`: check exists only in the later report.
- `resolved`: check exists only in the earlier report.
- `unchanged`: stable observation fields match.
- `changed`: the check remains but one or more observation fields differ.

Collection timestamps do not alone count as a changed finding.

## Security and privacy

The HTML renderer is self-contained: inline CSS only, no JavaScript, remote assets, external fonts, or network fetches. It sets a restrictive Content Security Policy and escapes all report-controlled text. PDF generation uses ReportLab's built-in Helvetica/Courier fonts; no third-party font files are bundled. Install PDF support with `pip install '.[pdf]'`.

Report output paths create missing parent directories and replace existing regular files atomically. POSIX output files are mode `0600`. Symlinks, special files, and hard-linked destinations are rejected. The explicit `--open` option invokes `xdg-open` only on Linux.


ReportLab's built-in Type 1 fonts avoid redistributing third-party fonts and their licenses. They do not guarantee correct rendering of every Unicode script (including Arabic); users requiring full multilingual glyph coverage need a separately licensed, explicitly configured font in a future phase.
