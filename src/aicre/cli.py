"""Command-line interface for AICRE 0.2.1."""
from __future__ import annotations

import argparse
import json
import math
import sys
from pathlib import Path
from typing import Any

from . import __version__
from .policy import (
    SENSITIVE_CONFIG_DIR_PAIRS,
    SENSITIVE_DIRS,
    SENSITIVE_NAMES,
    SENSITIVE_SUFFIXES,
)
from .privacy import path_exclusion_reason
from .report import DEFAULT_TIMEOUT_SECONDS, build_report, serialize_report
from .scanner import (
    DEFAULT_MAX_DIRECTORY_ENTRIES,
    DEFAULT_MAX_ITEMS,
    ScanError,
    scan_directory,
    write_json_report,
)
from .workload_profiles import supported_profiles


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
    parser.add_argument("--exclude", action="append", default=[],
                        help="relative path pattern to omit; repeatable")
    parser.add_argument("--timeout", type=_timeout_value, default=default_timeout,
                        help="cooperative collection time budget in seconds")



def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="aicre",
        description="Local Linux environment inventory and readiness assessment",
    )
    parser.add_argument("--version", action="version", version=f"%(prog)s {__version__}")
    subparsers = parser.add_subparsers(dest="command", required=True)

    scan = subparsers.add_parser("scan", help="inventory a directory or run a selected system profile")
    scan.add_argument("source", nargs="?", help="directory to scan (omit only when --profile is supplied)")
    scan.add_argument("--profile", choices=supported_profiles(), default=None,
                      help="system inventory/workload profile (required when SOURCE is omitted)")
    scan.add_argument("--output", help="JSON report path")
    scan.add_argument("--exclude", action="append", default=[],
                      help="private relative path/glob to exclude; repeatable")
    scan.add_argument("--force", action="store_true", help="explicitly replace an existing report")
    scan.add_argument("--timeout", type=_timeout_value, default=None,
                      help="cooperative time budget; directory scans are unlimited unless set")
    scan.add_argument("--max-items", type=_positive_int, default=DEFAULT_MAX_ITEMS,
                      help=f"maximum included directory entries (default: {DEFAULT_MAX_ITEMS})")
    scan.add_argument("--max-directory-entries", type=_positive_int,
                      default=DEFAULT_MAX_DIRECTORY_ENTRIES,
                      help=f"maximum entries buffered per directory (default: {DEFAULT_MAX_DIRECTORY_ENTRIES})")

    system = subparsers.add_parser("system", help="show local OS and resource metadata")
    _add_inventory_options(system, default_timeout=DEFAULT_TIMEOUT_SECONDS)

    inventory = subparsers.add_parser("inventory", help="show system metadata and allowlisted tools")
    _add_inventory_options(inventory, default_timeout=DEFAULT_TIMEOUT_SECONDS)

    readiness = subparsers.add_parser("readiness", help="assess five separate readiness dimensions")
    _add_inventory_options(readiness, default_timeout=DEFAULT_TIMEOUT_SECONDS)

    report = subparsers.add_parser("report", help="emit the full versioned JSON report")
    report.add_argument("--profile", choices=supported_profiles(), default=None, help="workload baseline (default: standard)")
    report.add_argument("--format", choices=("json",), default="json")
    report.add_argument("--output", help="optional report destination; stdout if omitted")
    report.add_argument("--force", action="store_true", help="explicitly replace an existing report")
    report.add_argument("--exclude", action="append", default=[],
                        help="filesystem source or executable path pattern to omit; repeatable")
    report.add_argument("--timeout", type=_timeout_value, default=DEFAULT_TIMEOUT_SECONDS,
                        help="cooperative collection time budget in seconds")

    exclusions = subparsers.add_parser("exclusions", help="show AICRE's built-in path policy")
    exclusions_subparsers = exclusions.add_subparsers(dest="exclusions_command", required=True)
    exclusions_subparsers.add_parser("show", help="show built-in sensitive path rules")
    return parser


def _format_value(value: Any) -> str:
    if value is None:
        return "not available"
    return json.dumps(value, ensure_ascii=False, sort_keys=True)


def _print_findings(findings: list[dict[str, Any]]) -> None:
    for item in findings:
        print(f"[{item['status']}] {item['id']}: {_format_value(item['value'])}")
        print(f"  source: {item['source']}; confidence: {item['confidence']}")
        if item["unit"]:
            print(f"  unit: {item['unit']}")
        for limitation in item["limitations"]:
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

    categories = None
    if command == "system":
        categories = {"system", "resource", "runtime", "security"}
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


def _build_and_emit_report(args: argparse.Namespace, *, command: str, include_tools: bool = True) -> int:
    report = build_report(
        profile=args.profile,
        excludes=args.exclude,
        timeout=args.timeout,
        include_tools=include_tools,
    )
    if args.format == "json":
        print(serialize_report(report), end="")
    else:
        _print_human_report(report, command=command)
    return 0


def main(argv: list[str] | None = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)
    if getattr(args, "force", False) and not getattr(args, "output", None):
        parser.error("--force requires --output; it cannot be used with standard output.")

    try:
        if args.command == "scan":
            if args.source is not None:
                if args.output is None:
                    parser.error("scan SOURCE requires --output")
                report = scan_directory(
                    args.source,
                    args.output,
                    excludes=args.exclude,
                    force=args.force,
                    timeout=args.timeout,
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
                return 0 if summary["complete"] else 1
            if args.profile is None:
                parser.error("scan without SOURCE requires --profile")
            if args.output is not None:
                reason = path_exclusion_reason(args.output, args.exclude)
                if reason:
                    raise ScanError("Report destination is excluded by the privacy policy; choose another path.")
                report = build_report(
                    profile=args.profile,
                    excludes=args.exclude,
                    timeout=DEFAULT_TIMEOUT_SECONDS if args.timeout is None else args.timeout,
                )
                write_json_report(args.output, report, force=args.force)
                print(f"AICRE report written to {Path(args.output).expanduser().absolute()}")
                return 0
            report = build_report(
                profile=args.profile,
                excludes=args.exclude,
                timeout=DEFAULT_TIMEOUT_SECONDS if args.timeout is None else args.timeout,
            )
            _print_human_report(report, command="scan-profile")
            return 0

        if args.command == "system":
            return _build_and_emit_report(args, command="system", include_tools=False)

        if args.command == "inventory":
            return _build_and_emit_report(args, command="inventory")

        if args.command == "readiness":
            return _build_and_emit_report(args, command="readiness")

        if args.command == "report":
            report = build_report(
                profile=args.profile,
                excludes=args.exclude,
                timeout=args.timeout,
            )
            if args.output:
                reason = path_exclusion_reason(args.output, args.exclude)
                if reason:
                    raise ScanError("Report destination is excluded by the privacy policy; choose another path.")
                output_path = Path(args.output).expanduser().absolute()
                write_json_report(output_path, report, force=args.force)
                print(f"AICRE report written to {output_path}")
            else:
                print(serialize_report(report), end="")
            return 0

        if args.command == "exclusions" and args.exclusions_command == "show":
            _show_exclusions()
            return 0
    except (ScanError, ValueError) as exc:
        print(f"AICRE: {exc}", file=sys.stderr)
        return 2

    return 2


if __name__ == "__main__":
    raise SystemExit(main())
