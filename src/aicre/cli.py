"""Command-line interface."""
from __future__ import annotations

import argparse
import sys

from . import __version__
from .scanner import ScanError, scan_directory


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(prog="aicre", description="Local metadata-only inventory (AICRE 0.1.0)")
    parser.add_argument("--version", action="version", version=f"%(prog)s {__version__}")
    subparsers = parser.add_subparsers(dest="command", required=True)
    scan = subparsers.add_parser("scan", help="inventory a directory without reading file contents")
    scan.add_argument("source", help="directory to scan")
    scan.add_argument("--output", required=True, help="JSON report path, outside the source directory")
    scan.add_argument("--exclude", action="append", default=[], help="private relative path/glob to exclude; repeatable")
    scan.add_argument("--force", action="store_true", help="explicitly replace an existing report")
    return parser


def main(argv: list[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    if args.command == "scan":
        try:
            report = scan_directory(args.source, args.output, excludes=args.exclude, force=args.force)
        except ScanError as exc:
            print(f"AICRE: {exc}", file=sys.stderr)
            return 2
        summary = report["summary"]
        print(f"Inventory written. Included: {summary['included_items']}; excluded: {summary['excluded_items']}; errors: {summary['scan_errors']}.")
        return 0
    return 2


if __name__ == "__main__":
    raise SystemExit(main())
