"""Command-line interface for AICRE."""
from __future__ import annotations

import argparse
import json
import math
import os
import platform
import subprocess
import sys
import tempfile
from pathlib import Path
from typing import Any

from . import __version__
from .diff import compare_reports
from .policy import (
    SENSITIVE_CONFIG_DIR_PAIRS,
    SENSITIVE_DIRS,
    SENSITIVE_NAMES,
    SENSITIVE_SUFFIXES,
)
from .privacy import path_exclusion_reason
from .report import DEFAULT_TIMEOUT_SECONDS, build_report, serialize_report
from .renderers import render_html, render_markdown, render_pdf
from .scanner import ScanError, scan_directory, write_json_report
from .schema import canonical_report
from .workload_profiles import supported_profiles


EXIT_UNSUPPORTED_FORMAT = 3
EXIT_OPEN_UNSUPPORTED = 6
EXIT_OPEN_FAILED = 7
FORMATS = ("text", "json", "markdown", "html", "pdf")


def _timeout_value(raw: str) -> float:
    try:
        value = float(raw)
    except ValueError as exc:
        raise argparse.ArgumentTypeError("timeout must be a number of seconds") from exc
    if not math.isfinite(value) or value < 0:
        raise argparse.ArgumentTypeError("timeout must be finite and non-negative")
    return value


def _add_inventory_options(parser: argparse.ArgumentParser, *, default_timeout: float) -> None:
    parser.add_argument("--profile", choices=supported_profiles(), default="standard", help="workload baseline")
    parser.add_argument("--format", choices=("text", "json"), default="text")
    parser.add_argument("--exclude", action="append", default=[], help="relative path pattern to omit; repeatable")
    parser.add_argument("--timeout", type=_timeout_value, default=default_timeout,
                        help="cooperative collection time budget in seconds")


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(prog="aicre",
        description="Local Linux environment inventory and readiness assessment")
    parser.add_argument("--version", action="version", version=f"%(prog)s {__version__}")
    subparsers = parser.add_subparsers(dest="command", required=True)

    scan = subparsers.add_parser("scan", help="inventory a directory or run a system profile")
    scan.add_argument("source", nargs="?", help="directory to scan (omit for a system profile)")
    scan.add_argument("--profile", choices=supported_profiles(), help="system/workload profile")
    scan.add_argument("--format", default=None, help="one of text, json, markdown, html, pdf; omitted preserves legacy output")
    scan.add_argument("--output", help="report destination")
    scan.add_argument("--open", action="store_true", help="open the completed report with xdg-open (Linux only)")
    scan.add_argument("--exclude", action="append", default=[], help="private relative path/glob to exclude; repeatable")
    scan.add_argument("--force", action="store_true", help="legacy mode: explicitly replace an existing report")
    scan.add_argument("--timeout", type=_timeout_value, default=None,
                      help="cooperative time budget; directory scans are unlimited unless set")

    system = subparsers.add_parser("system", help="show local OS and resource metadata")
    _add_inventory_options(system, default_timeout=DEFAULT_TIMEOUT_SECONDS)
    inventory = subparsers.add_parser("inventory", help="show system metadata and allowlisted tools")
    _add_inventory_options(inventory, default_timeout=DEFAULT_TIMEOUT_SECONDS)
    readiness = subparsers.add_parser("readiness", help="assess five separate readiness dimensions")
    _add_inventory_options(readiness, default_timeout=DEFAULT_TIMEOUT_SECONDS)

    report = subparsers.add_parser("report", help="render, inspect, or compare saved reports")
    report.add_argument("--profile", choices=supported_profiles(), default="standard", help="workload baseline")
    report.add_argument("--format", default="json", help="one of text, json, markdown, html, pdf")
    report.add_argument("--output", help="destination; parent directories are created and existing files replaced")
    report.add_argument("--open", action="store_true", help="open the completed report with xdg-open (Linux only)")
    report.add_argument("--input", help="render an existing JSON report instead of scanning")
    report.add_argument("--diff", nargs=2, metavar=("BEFORE", "AFTER"), help="compare two saved JSON reports")
    report.add_argument("--force", action="store_true", help="accepted for compatibility; new output formats replace files")
    report.add_argument("--exclude", action="append", default=[], help="filesystem source or executable path pattern to omit; repeatable")
    report.add_argument("--timeout", type=_timeout_value, default=DEFAULT_TIMEOUT_SECONDS)

    exclusions = subparsers.add_parser("exclusions", help="show AICRE's built-in path policy")
    exclusions_subparsers = exclusions.add_subparsers(dest="exclusions_command", required=True)
    exclusions_subparsers.add_parser("show", help="show built-in sensitive path rules")
    return parser


def _format_value(value: Any) -> str:
    return "not available" if value is None else json.dumps(value, ensure_ascii=False, sort_keys=True)


def _print_findings(findings: list[dict[str, Any]]) -> None:
    for item in findings:
        print(f"[{item['status']}] {item['id']}: {_format_value(item['value'])}")
        print(f"  source: {item['source']}; confidence: {item['confidence']}")
        if item.get("unit"):
            print(f"  unit: {item['unit']}")
        for limitation in item.get("limitations", []):
            print(f"  limitation: {limitation}")


def _print_readiness(readiness: dict[str, dict[str, Any]]) -> None:
    for name, result in readiness.items():
        print(f"[{result['status']}] {name}: {result['explanation']}")
        if result["evidence"]:
            print(f"  evidence: {', '.join(result['evidence'])}")


def _print_human_report(report: dict[str, Any], *, command: str) -> None:
    print(f"AICRE {report['aicre_version']} — profile: {report['profile']}")
    if command == "readiness":
        _print_readiness(report["readiness"])
        return
    categories = {"system", "resource", "runtime", "security"} if command == "system" else None
    findings = report["findings"]
    if categories is not None:
        findings = [item for item in findings if item["category"] in categories]
    _print_findings(findings)
    if command in {"inventory", "report", "scan-profile"}:
        print("Readiness (separate dimensions; no composite score):")
        _print_readiness(report["readiness"])


def _show_exclusions() -> None:
    print("Built-in sensitive directory names:")
    print("  " + ", ".join(sorted(SENSITIVE_DIRS)))
    print("Built-in paired config locations:")
    for parent, child in sorted(SENSITIVE_CONFIG_DIR_PAIRS):
        print(f"  {parent}/{child}")
    print("Built-in sensitive filenames:")
    print("  " + ", ".join(sorted(SENSITIVE_NAMES)))
    print("Built-in sensitive extensions:")
    print("  " + ", ".join(sorted(SENSITIVE_SUFFIXES)))
    print("User patterns are supplied per command with --exclude and are not persisted.")


def _load_json(path: str) -> dict[str, Any]:
    try:
        value = json.loads(Path(path).expanduser().read_text(encoding="utf-8"))
    except (OSError, UnicodeError, json.JSONDecodeError) as exc:
        raise ScanError(f"cannot read JSON report {path!r}: {exc}") from exc
    required = {"schema_version", "aicre_version", "profile", "generated_at", "findings", "readiness"}
    if (not isinstance(value, dict)
            or not required.issubset(value)
            or value.get("schema_version") not in {"2.0", "1.0.0"}
            or not isinstance(value.get("findings"), list)
            or any(not isinstance(item, dict) for item in value.get("findings", []))
            or not isinstance(value.get("readiness"), dict)):
        raise ScanError(f"invalid AICRE report structure in {path!r}")
    for item in value["findings"]:
        if not {"category", "status", "value", "source", "confidence", "unit", "limitations"}.issubset(item):
            raise ScanError(f"invalid finding structure in {path!r}")
        if "id" not in item and "check_id" not in item:
            raise ScanError(f"finding is missing an identifier in {path!r}")
    if value["schema_version"] == "1.0.0" and not isinstance(value.get("scan_id"), str):
        raise ScanError(f"canonical report is missing scan_id in {path!r}")
    return value


def _diff_as_report(diff: dict[str, Any]) -> dict[str, Any]:
    findings = []
    for change in diff["changes"]:
        findings.append({
            "id": change["check_id"], "category": "diff", "status": change["change"],
            "value": {"before": change["before"], "after": change["after"]},
            "source": "AICRE report comparison", "confidence": "high", "unit": None,
            "collected_at": diff.get("after_scan_id") or "unknown", "limitations": [],
        })
    return {"schema_version": diff["schema_version"], "aicre_version": __version__,
            "scan_id": diff.get("after_scan_id"), "generated_at": "comparison",
            "profile": "diff", "findings": findings, "readiness": {},
            "diff_counts": diff["counts"]}


def _render(report_data: dict[str, Any], fmt: str) -> tuple[str | bytes, str]:
    if fmt == "json":
        return json.dumps(report_data, ensure_ascii=False, indent=2, sort_keys=False) + "\n", ".json"
    if fmt == "text":
        return render_markdown(report_data), ".txt"
    if fmt == "markdown":
        return render_markdown(report_data), ".md"
    if fmt == "html":
        return render_html(report_data), ".html"
    if fmt == "pdf":
        return render_pdf(report_data), ".pdf"
    raise ScanError(f"unsupported report format: {fmt}")


def _write_output(path: str, data: str | bytes) -> Path:
    target = Path(path).expanduser()
    target.parent.mkdir(parents=True, exist_ok=True)
    if target.is_symlink() or (target.exists() and not target.is_file()):
        raise ScanError("report destination must be a regular file, not a symlink or special file")
    if target.exists() and target.stat().st_nlink > 1:
        raise ScanError("refusing to replace a hard-linked report destination")
    fd, temporary = tempfile.mkstemp(prefix=".aicre-", suffix=".tmp", dir=target.parent)
    try:
        if os.name == "posix":
            os.fchmod(fd, 0o600)
        mode = "wb"
        with os.fdopen(fd, mode) as stream:
            payload = data.encode("utf-8") if isinstance(data, str) else data
            stream.write(payload)
            stream.flush()
            os.fsync(stream.fileno())
        os.replace(temporary, target)
    except Exception:
        try:
            os.unlink(temporary)
        except OSError:
            pass
        raise
    return target.absolute()


def _open_report(path: Path) -> int:
    if platform.system() != "Linux":
        print("AICRE: --open is supported only on Linux (xdg-open).", file=sys.stderr)
        return EXIT_OPEN_UNSUPPORTED
    try:
        subprocess.Popen(["xdg-open", str(path)], stdin=subprocess.DEVNULL,
                         stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, close_fds=True)
    except OSError as exc:
        print(f"AICRE: unable to launch xdg-open: {exc}", file=sys.stderr)
        return EXIT_OPEN_FAILED
    return 0


def _handle_report_command(args: argparse.Namespace) -> int:
    if args.input and args.diff:
        raise ScanError("--input and --diff cannot be used together")
    diff_result = None
    if args.diff:
        before, after = (_load_json(path) for path in args.diff)
        diff_result = compare_reports(before, after)
        data = _diff_as_report(diff_result)
    elif args.input:
        data = canonical_report(_load_json(args.input))
    else:
        data = canonical_report(build_report(profile=args.profile, excludes=args.exclude, timeout=args.timeout))
    if diff_result is not None and args.format == "json":
        rendered, _extension = json.dumps(diff_result, ensure_ascii=False, indent=2) + "\n", ".json"
    else:
        rendered, _extension = _render(data, args.format)
    if args.output:
        reason = path_exclusion_reason(args.output, args.exclude)
        if reason:
            raise ScanError("Report destination is excluded by the privacy policy; choose another path.")
        path = _write_output(args.output, rendered)
        print(f"AICRE report written to {path}")
        return _open_report(path) if args.open else 0
    if args.open:
        raise ScanError("--open requires --output")
    if isinstance(rendered, bytes):
        sys.stdout.buffer.write(rendered)
    else:
        sys.stdout.write(rendered)
    return 0


def main(argv: list[str] | None = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)
    try:
        if args.command in {"scan", "report"} and args.format is not None and args.format not in FORMATS:
            raise ScanError(f"unsupported report format: {args.format}")
        if args.command == "scan":
            if args.source is not None:
                if args.format not in (None, "json"):
                    raise ScanError("directory metadata scans currently support JSON output only")
                if args.output is None:
                    parser.error("scan SOURCE requires --output")
                report = scan_directory(args.source, args.output, excludes=args.exclude,
                                        force=args.force, timeout=args.timeout)
                summary = report["summary"]
                print(f"Inventory written. Included: {summary['included_items']}; excluded: {summary['excluded_items']}; errors: {summary['scan_errors']}.")
                return _open_report(Path(args.output).expanduser().absolute()) if args.open else 0
            if args.profile not in supported_profiles():
                parser.error("unsupported workload profile")
            timeout = DEFAULT_TIMEOUT_SECONDS if args.timeout is None else args.timeout
            if args.format is None:
                # Preserve 0.2.0 output and path-safety behavior byte-for-byte for legacy invocations.
                if args.output is not None:
                    reason = path_exclusion_reason(args.output, args.exclude)
                    if reason:
                        raise ScanError("Report destination is excluded by the privacy policy; choose another path.")
                    old_report = build_report(profile=args.profile, excludes=args.exclude, timeout=timeout)
                    write_json_report(args.output, old_report, force=args.force)
                    print(f"AICRE report written to {Path(args.output).expanduser().absolute()}")
                    return 0
                old_report = build_report(profile=args.profile, excludes=args.exclude, timeout=timeout)
                _print_human_report(old_report, command="scan-profile")
                return 0
            old_report = build_report(profile=args.profile, excludes=args.exclude, timeout=timeout)
            data = canonical_report(old_report)
            rendered, _extension = _render(data, args.format)
            if args.output:
                reason = path_exclusion_reason(args.output, args.exclude)
                if reason:
                    raise ScanError("Report destination is excluded by the privacy policy; choose another path.")
                path = _write_output(args.output, rendered)
                print(f"AICRE report written to {path}")
                return _open_report(path) if args.open else 0
            if args.open:
                raise ScanError("--open requires --output")
            if isinstance(rendered, bytes):
                sys.stdout.buffer.write(rendered)
            else:
                sys.stdout.write(rendered)
            return 0

        if args.command in {"system", "inventory", "readiness"}:
            report = build_report(profile=args.profile, excludes=args.exclude, timeout=args.timeout,
                                  include_tools=args.command != "system")
            if args.format == "json":
                sys.stdout.write(serialize_report(report))
            else:
                _print_human_report(report, command=args.command)
            return 0
        if args.command == "report":
            return _handle_report_command(args)
        if args.command == "exclusions" and args.exclusions_command == "show":
            _show_exclusions()
            return 0
    except (ScanError, ValueError, OSError, RuntimeError) as exc:
        print(f"AICRE: {exc}", file=sys.stderr)
        if "unsupported report format" in str(exc) or "requires the optional ReportLab dependency" in str(exc):
            return EXIT_UNSUPPORTED_FORMAT
        return 2
    return 2


if __name__ == "__main__":
    raise SystemExit(main())
