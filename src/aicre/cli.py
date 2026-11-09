"""Command-line interface for AICRE."""
from __future__ import annotations

import argparse
import json
import math
import os
import platform
import stat
import subprocess
import sys
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
from .renderers import render_html, render_markdown, render_pdf
from .report import DEFAULT_TIMEOUT_SECONDS, build_report, serialize_report
from .scanner import (
    DEFAULT_MAX_DIRECTORY_ENTRIES,
    DEFAULT_MAX_ITEMS,
    ScanError,
    scan_directory,
    write_json_report,
)
from .schema import ReportValidationError, canonical_report
from .workload_profiles import supported_profiles

EXIT_UNSUPPORTED_FORMAT = 3
EXIT_OPEN_UNSUPPORTED = 6
EXIT_OPEN_FAILED = 7
FORMATS = ("text", "json", "markdown", "html", "pdf")
MAX_REPORT_INPUT_BYTES = 16 * 1024 * 1024


def _timeout_value(raw: str) -> float:
    try:
        value = float(raw)
    except ValueError as exc:
        raise argparse.ArgumentTypeError("timeout must be a number of seconds") from exc
    if not math.isfinite(value) or value < 0:
        raise argparse.ArgumentTypeError("timeout must be finite and non-negative")
    return value


def _positive_int(raw: str) -> int:
    try:
        value = int(raw)
    except ValueError as exc:
        raise argparse.ArgumentTypeError("value must be a positive integer") from exc
    if value < 1:
        raise argparse.ArgumentTypeError("value must be a positive integer")
    return value


def _add_inventory_options(parser: argparse.ArgumentParser, *, default_timeout: float) -> None:
    parser.add_argument("--profile", choices=supported_profiles(), default=None, help="workload baseline (default: standard)")
    parser.add_argument("--format", choices=("text", "json"), default="text")
    parser.add_argument("--exclude", action="append", default=[], help="relative path pattern to omit; repeatable")
    parser.add_argument("--timeout", type=_timeout_value, default=default_timeout,
                        help="cooperative collection time budget in seconds")


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(prog="aicre",
        description="Local Linux environment inventory and readiness assessment")
    parser.add_argument("--version", action="version", version=f"%(prog)s {__version__}")
    subparsers = parser.add_subparsers(dest="command", required=True)

    scan = subparsers.add_parser("scan", help="inventory a directory or run a selected system profile")
    scan.add_argument("source", nargs="?", help="directory to scan (omit only when --profile is supplied)")
    scan.add_argument("--profile", choices=supported_profiles(), default=None,
                      help="system inventory/workload profile (required when SOURCE is omitted)")
    scan.add_argument("--format", default=None,
                      help="one of text, json, markdown, html, pdf; omitted preserves legacy output")
    scan.add_argument("--output", help="report destination")
    scan.add_argument("--open", action="store_true", help="open the completed report with xdg-open (Linux only)")
    scan.add_argument("--exclude", action="append", default=[], help="private relative path/glob to exclude; repeatable")
    scan.add_argument("--force", action="store_true", help="explicitly replace an existing report")
    scan.add_argument("--timeout", type=_timeout_value, default=None,
                      help="cooperative time budget; directory scans are unlimited unless set")
    scan.add_argument("--max-items", type=_positive_int, default=DEFAULT_MAX_ITEMS,
                      help=f"maximum included files and directories (default: {DEFAULT_MAX_ITEMS})")
    scan.add_argument("--max-directory-entries", type=_positive_int,
                      default=DEFAULT_MAX_DIRECTORY_ENTRIES,
                      help=f"maximum entries buffered per directory, including excluded entries (default: {DEFAULT_MAX_DIRECTORY_ENTRIES})")

    system = subparsers.add_parser("system", help="show local OS and resource metadata")
    _add_inventory_options(system, default_timeout=DEFAULT_TIMEOUT_SECONDS)
    inventory = subparsers.add_parser("inventory", help="show system metadata and allowlisted tools")
    _add_inventory_options(inventory, default_timeout=DEFAULT_TIMEOUT_SECONDS)
    readiness = subparsers.add_parser("readiness", help="assess five separate readiness dimensions")
    _add_inventory_options(readiness, default_timeout=DEFAULT_TIMEOUT_SECONDS)

    report = subparsers.add_parser("report", help="render, inspect, or compare saved reports")
    report.add_argument("--profile", choices=supported_profiles(), default=None, help="workload baseline (default: standard)")
    report.add_argument("--format", default=None, help="explicit format: text, json, markdown, html, pdf; omitted preserves schema 2.0 JSON")
    report.add_argument("--output", help="destination; missing parent directories are created")
    report.add_argument("--open", action="store_true", help="open the completed report with xdg-open (Linux only)")
    report.add_argument("--input", help="render an existing JSON report instead of scanning")
    report.add_argument("--diff", nargs=2, metavar=("BEFORE", "AFTER"), help="compare two saved JSON reports")
    report.add_argument("--force", action="store_true", help="explicitly replace an existing regular report file")
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


def _format_gib(value: Any) -> str:
    if not isinstance(value, (int, float)) or isinstance(value, bool):
        return "not available"
    return f"{value / (1024 ** 3):.1f} GiB"


def _print_profile_observations(report: dict[str, Any]) -> None:
    """Display existing host observations without implying resource readiness."""
    findings = {
        item["id"]: item
        for item in report["findings"]
        if isinstance(item, dict) and isinstance(item.get("id"), str)
    }
    print("Observed values (host-facing; resource comparisons are not performed):")

    cpu = findings.get("profile.resource.cpu", {}).get("value", {})
    cpu_actual = cpu.get("actual") if isinstance(cpu, dict) else None
    cpu_minimum = cpu.get("minimum") if isinstance(cpu, dict) else None
    cpu_text = str(cpu_actual) if isinstance(cpu_actual, int) else "not available"
    print(f"  CPU: {cpu_text} (min {cpu_minimum} logical CPUs)")

    memory = findings.get("profile.resource.memory", {}).get("value", {})
    memory_actual = memory.get("actual") if isinstance(memory, dict) else None
    memory_minimum = memory.get("minimum") if isinstance(memory, dict) else None
    print(
        f"  RAM: {_format_gib(memory_actual)} "
        f"(min {_format_gib(memory_minimum)})"
    )

    storage = findings.get("profile.resource.storage", {}).get("value", {})
    storage_actual = storage.get("actual") if isinstance(storage, dict) else None
    storage_minimum = storage.get("minimum") if isinstance(storage, dict) else None
    print(
        f"  Free disk: {_format_gib(storage_actual)} "
        f"(min {_format_gib(storage_minimum)})"
    )

    for tool in ("git", "python3"):
        item = findings.get(f"profile.software.{tool}")
        status = item.get("status", "not_checked") if isinstance(item, dict) else "not_checked"
        label = "detected" if status == "detected" else status.replace("_", " ")
        print(f"  {tool}: {label}")


def _print_human_report(report: dict[str, Any], *, command: str) -> None:
    print(f"AICRE {report['aicre_version']} — profile: {report['profile']}")
    if command == "readiness":
        if report["profile"] == "agent-development":
            _print_profile_observations(report)
        _print_readiness(report["readiness"])
        print("Note: unknown means not assessed, not failed.")
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


def _unique_object(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    result: dict[str, Any] = {}
    for key, value in pairs:
        if key in result:
            raise ValueError(f"duplicate JSON object key: {key!r}")
        result[key] = value
    return result


def _reject_nonfinite(value: str) -> None:
    raise ValueError(f"non-finite JSON number is not permitted: {value}")


def _read_report_input(path: str, excludes: tuple[str, ...] | list[str]) -> str:
    requested = Path(path).expanduser()
    absolute = Path(os.path.abspath(requested))
    if path_exclusion_reason(absolute, excludes):
        raise ScanError("refusing to read a report input blocked by the privacy policy")
    if any(absolute == root or root in absolute.parents for root in map(Path, ("/proc", "/sys", "/dev"))):
        raise ScanError("report input must not be read from a virtual filesystem")

    directory_flags = (
        os.O_RDONLY | getattr(os, "O_DIRECTORY", 0) | getattr(os, "O_NOFOLLOW", 0)
    )
    if (
        os.open not in os.supports_dir_fd
        or not hasattr(os, "O_DIRECTORY")
        or not hasattr(os, "O_NOFOLLOW")
    ):
        raise ScanError("safe report input is unavailable on this platform")

    directory_fd = os.open(os.path.sep, directory_flags)
    file_fd: int | None = None
    try:
        for component in absolute.parent.parts[1:]:
            child_fd = os.open(component, directory_flags, dir_fd=directory_fd)
            os.close(directory_fd)
            directory_fd = child_fd
        file_flags = os.O_RDONLY | os.O_NOFOLLOW | getattr(os, "O_CLOEXEC", 0)
        file_flags |= getattr(os, "O_NONBLOCK", 0)
        file_fd = os.open(absolute.name, file_flags, dir_fd=directory_fd)
        metadata = os.fstat(file_fd)
        if not stat.S_ISREG(metadata.st_mode):
            raise ScanError("report input must be a regular file")
        if metadata.st_nlink > 1:
            raise ScanError("report input with multiple hard links is not accepted")
        if metadata.st_size > MAX_REPORT_INPUT_BYTES:
            raise ScanError(f"report input exceeds the {MAX_REPORT_INPUT_BYTES}-byte limit")

        content = bytearray()
        while len(content) <= MAX_REPORT_INPUT_BYTES:
            chunk = os.read(file_fd, min(65_536, MAX_REPORT_INPUT_BYTES + 1 - len(content)))
            if not chunk:
                break
            content.extend(chunk)
        if len(content) > MAX_REPORT_INPUT_BYTES:
            raise ScanError(f"report input exceeds the {MAX_REPORT_INPUT_BYTES}-byte limit")
        return content.decode("utf-8")
    finally:
        if file_fd is not None:
            os.close(file_fd)
        os.close(directory_fd)


def _load_json(path: str, *, excludes: tuple[str, ...] | list[str] = ()) -> dict[str, Any]:
    try:
        text = _read_report_input(path, excludes)
        value = json.loads(
            text,
            object_pairs_hook=_unique_object,
            parse_constant=_reject_nonfinite,
        )
        if not isinstance(value, dict):
            raise ReportValidationError("top-level JSON value must be an object")
        canonical_report(value)  # strict, version-aware validation of all nested fields
    except (OSError, UnicodeError, json.JSONDecodeError, ReportValidationError, ValueError, RecursionError) as exc:
        raise ScanError(f"cannot load valid AICRE JSON report {path!r}: {exc}") from exc
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
    if fmt in {"text", "markdown"}:
        return render_markdown(report_data), ".txt" if fmt == "text" else ".md"
    if fmt == "html":
        return render_html(report_data), ".html"
    if fmt == "pdf":
        return render_pdf(report_data), ".pdf"
    raise ScanError(f"unsupported report format: {fmt}")


def _write_output(path: str, data: str | bytes, *, force: bool = False) -> Path:
    requested = Path(path).expanduser()
    if requested.name in {"", ".", ".."}:
        raise ScanError("report destination must name a file")
    absolute = Path(os.path.abspath(requested))
    flags = os.O_RDONLY | getattr(os, "O_DIRECTORY", 0) | getattr(os, "O_NOFOLLOW", 0)
    directory_fd = os.open(os.path.sep, flags)
    try:
        for part in absolute.parent.parts[1:]:
            try:
                child_fd = os.open(part, flags, dir_fd=directory_fd)
            except FileNotFoundError:
                os.mkdir(part, 0o700, dir_fd=directory_fd)
                child_fd = os.open(part, flags, dir_fd=directory_fd)
            os.close(directory_fd)
            directory_fd = child_fd

        try:
            existing = os.stat(absolute.name, dir_fd=directory_fd, follow_symlinks=False)
        except FileNotFoundError:
            existing = None
        if existing is not None:
            if not stat.S_ISREG(existing.st_mode):
                raise ScanError("report destination must be a regular file, not a symlink or special file")
            if existing.st_nlink > 1:
                raise ScanError("refusing to replace a hard-linked report destination")
            if not force:
                raise ScanError("report destination already exists; use --force to replace it")

        temporary_name = f".aicre-{os.getpid()}-{os.urandom(12).hex()}.tmp"
        create_flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL | getattr(os, "O_NOFOLLOW", 0)
        file_fd = os.open(temporary_name, create_flags, 0o600, dir_fd=directory_fd)
        try:
            if os.name == "posix":
                os.fchmod(file_fd, 0o600)
            with os.fdopen(file_fd, "wb") as stream:
                file_fd = -1
                payload = data.encode("utf-8") if isinstance(data, str) else data
                stream.write(payload)
                stream.flush()
                os.fsync(stream.fileno())
            if force:
                os.replace(temporary_name, absolute.name,
                           src_dir_fd=directory_fd, dst_dir_fd=directory_fd)
            else:
                # link() publishes only if the destination is still absent.
                os.link(temporary_name, absolute.name, src_dir_fd=directory_fd,
                        dst_dir_fd=directory_fd, follow_symlinks=False)
                os.unlink(temporary_name, dir_fd=directory_fd)
            if os.name == "posix":
                os.fsync(directory_fd)
        except Exception:
            if file_fd >= 0:
                os.close(file_fd)
            try:
                os.unlink(temporary_name, dir_fd=directory_fd)
            except OSError:
                pass
            raise
    finally:
        os.close(directory_fd)
    return absolute


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
    legacy_default = args.format is None and not args.input and not args.diff
    if args.diff:
        before, after = (_load_json(path, excludes=args.exclude) for path in args.diff)
        diff_result = compare_reports(before, after)
        data = _diff_as_report(diff_result)
    elif args.input:
        data = canonical_report(_load_json(args.input, excludes=args.exclude))
    else:
        raw_report = build_report(profile=args.profile, excludes=args.exclude, timeout=args.timeout)
        data = raw_report if legacy_default else canonical_report(raw_report)
    if legacy_default:
        rendered, _extension = serialize_report(data), ".json"
    elif diff_result is not None and args.format == "json":
        rendered, _extension = json.dumps(diff_result, ensure_ascii=False, indent=2) + "\n", ".json"
    else:
        rendered, _extension = _render(data, args.format or "json")
    if args.output:
        reason = path_exclusion_reason(args.output, args.exclude)
        if reason:
            raise ScanError("Report destination is excluded by the privacy policy; choose another path.")
        path = _write_output(args.output, rendered, force=args.force)
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
    if getattr(args, "force", False) and not getattr(args, "output", None):
        parser.error("--force requires --output; it cannot be used with standard output.")

    try:
        if args.command in {"scan", "report"} and args.format is not None and args.format not in FORMATS:
            raise ScanError(f"unsupported report format: {args.format}")
        if args.command == "scan":
            if args.source is not None:
                if args.format not in (None, "json"):
                    raise ScanError("directory metadata scans currently support JSON output only")
                if args.output is None:
                    parser.error("scan SOURCE requires --output")
                report = scan_directory(
                    args.source, args.output, excludes=args.exclude,
                    force=args.force, timeout=args.timeout,
                    max_items=args.max_items,
                    max_directory_entries=args.max_directory_entries,
                )
                summary = report["summary"]
                print(
                    "Inventory written. "
                    f"Included: {summary['included_items']}; "
                    f"excluded: {summary['excluded_items']}; "
                    f"errors: {summary['scan_errors']}; "
                    f"complete: {'yes' if summary['complete'] else 'no'}; "
                    f"termination: {summary['termination_reason'] or 'none'}."
                )
                open_status = _open_report(Path(args.output).expanduser().absolute()) if args.open else 0
                complete = summary.get("complete", summary["scan_errors"] == 0)
                return 1 if not complete else open_status
            if args.profile is None:
                parser.error("scan without SOURCE requires --profile")
            timeout = DEFAULT_TIMEOUT_SECONDS if args.timeout is None else args.timeout
            if args.format is None:
                # Preserve the legacy 0.2 JSON schema, output, and destination checks.
                if args.output is not None:
                    reason = path_exclusion_reason(args.output, args.exclude)
                    if reason:
                        raise ScanError("Report destination is excluded by the privacy policy; choose another path.")
                    old_report = build_report(profile=args.profile, excludes=args.exclude, timeout=timeout)
                    write_json_report(args.output, old_report, force=args.force)
                    path = Path(args.output).expanduser().absolute()
                    print(f"AICRE report written to {path}")
                    return _open_report(path) if args.open else 0
                if args.open:
                    raise ScanError("--open requires --output")
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
                path = _write_output(args.output, rendered, force=args.force)
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
