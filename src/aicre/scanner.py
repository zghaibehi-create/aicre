"""Metadata-only scanner. File contents are never opened."""
from __future__ import annotations

import json
import os
import stat
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from .policy import is_sensitive_relative_path, is_user_excluded


class ScanError(RuntimeError):
    """Raised when a scan cannot safely be started or its report cannot be written."""


def _is_reparse_point(st: os.stat_result) -> bool:
    # Windows: FILE_ATTRIBUTE_REPARSE_POINT (junctions, symlinks, mount points).
    attributes = getattr(st, "st_file_attributes", 0)
    return bool(attributes & getattr(stat, "FILE_ATTRIBUTE_REPARSE_POINT", 0x400))


def _is_within(path: Path, parent: Path) -> bool:
    try:
        path.relative_to(parent)
        return True
    except ValueError:
        return False


def _utc_timestamp(timestamp: float) -> str:
    return datetime.fromtimestamp(timestamp, tz=timezone.utc).isoformat(timespec="seconds").replace("+00:00", "Z")


def scan_directory(source: str | Path, output: str | Path, *,
                   excludes: tuple[str, ...] | list[str] = (),
                   force: bool = False) -> dict[str, Any]:
    """Inventory metadata below source and write JSON outside source.

    The scanner uses lstat/scandir metadata only and never opens source files.
    """
    source_path = Path(source).expanduser().absolute()
    output_path = Path(output).expanduser().absolute()

    try:
        source_stat = source_path.lstat()
    except OSError as exc:
        raise ScanError(f"Cannot inspect source directory: {exc}") from exc
    if stat.S_ISLNK(source_stat.st_mode) or _is_reparse_point(source_stat):
        raise ScanError("Source must not be a symbolic link or reparse point.")
    if not stat.S_ISDIR(source_stat.st_mode):
        raise ScanError("Source must be an existing directory.")

    source_real = source_path.resolve(strict=True)
    output_parent = output_path.parent.resolve(strict=True) if output_path.parent.exists() else output_path.parent.resolve()
    normalized_output = output_parent / output_path.name
    if _is_within(normalized_output, source_real):
        raise ScanError("Report destination must be outside the scan directory.")

    try:
        output_stat = normalized_output.lstat()
    except FileNotFoundError:
        output_stat = None
    except OSError as exc:
        raise ScanError(f"Cannot inspect report destination: {exc}") from exc
    if output_stat is not None and (
        stat.S_ISLNK(output_stat.st_mode) or _is_reparse_point(output_stat)
    ):
        raise ScanError("Report destination must not be a symbolic link or reparse point.")
    if output_stat is not None and not force:
        raise ScanError("Report already exists; pass --force to replace it.")
    if output_stat is not None and stat.S_ISDIR(output_stat.st_mode):
        raise ScanError("Report destination is a directory.")
    if not normalized_output.parent.is_dir():
        raise ScanError("Report parent directory does not exist.")

    records: list[dict[str, Any]] = []
    errors = 0
    excluded = 0
    stack: list[Path] = [source_path]

    while stack:
        current = stack.pop()
        try:
            with os.scandir(current) as iterator:
                entries = sorted(iterator, key=lambda item: item.name.casefold(), reverse=True)
        except OSError:
            errors += 1
            continue

        for entry in entries:
            path = Path(entry.path)
            try:
                relative = path.relative_to(source_path).as_posix()
                # lstat semantics: do not follow symlinks or Windows reparse points.
                item_stat = entry.stat(follow_symlinks=False)
            except (OSError, ValueError):
                errors += 1
                continue

            if stat.S_ISLNK(item_stat.st_mode) or _is_reparse_point(item_stat):
                excluded += 1
                continue

            is_dir = stat.S_ISDIR(item_stat.st_mode)
            if is_sensitive_relative_path(relative) or is_user_excluded(relative, excludes):
                excluded += 1
                continue

            if is_dir:
                item_type = "directory"
                extension = ""
                size = None
                stack.append(path)
            elif stat.S_ISREG(item_stat.st_mode):
                item_type = "file"
                extension = path.suffix.lower()
                size = item_stat.st_size
            else:
                excluded += 1
                continue

            records.append({
                "relative_path": relative,
                "type": item_type,
                "extension": extension,
                "size_bytes": size,
                "modified_utc": _utc_timestamp(item_stat.st_mtime),
            })

    records.sort(key=lambda record: record["relative_path"].casefold())
    report = {
        "schema_version": "1",
        "aicre_version": "0.1.0",
        "source_name": source_path.name,
        "generated_utc": datetime.now(timezone.utc).isoformat(timespec="seconds").replace("+00:00", "Z"),
        "summary": {
            "included_items": len(records),
            "excluded_items": excluded,
            "scan_errors": errors,
        },
        "items": records,
    }

    # Exclusive creation prevents a race from silently replacing a report.
    mode = "w" if force else "x"
    try:
        with normalized_output.open(mode, encoding="utf-8", newline="\n") as report_file:
            json.dump(report, report_file, ensure_ascii=False, indent=2)
            report_file.write("\n")
    except FileExistsError as exc:
        raise ScanError("Report already exists; pass --force to replace it.") from exc
    except OSError as exc:
        raise ScanError(f"Could not write report: {exc}") from exc

    return report
