"""Metadata-only scanner. File contents are never opened."""
from __future__ import annotations

import json
import os
import secrets
import stat
from datetime import UTC, datetime
from pathlib import Path, PurePosixPath
from typing import Any

from .policy import is_sensitive_relative_path, is_sensitive_scan_root, is_user_excluded


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


def _secure_directory_flags() -> int:
    """Return flags needed for descriptor-relative, no-follow directory opens."""
    if (
        os.open not in os.supports_dir_fd
        or os.scandir not in os.supports_fd
        or not hasattr(os, "O_NOFOLLOW")
        or not hasattr(os, "O_DIRECTORY")
    ):
        raise ScanError("Secure descriptor-relative scanning is unavailable on this platform.")
    return os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | getattr(os, "O_CLOEXEC", 0)


def _open_directory_beneath(root_fd: int, relative: PurePosixPath, flags: int) -> int:
    """Open a directory below root without following any path-component symlink."""
    current_fd = os.dup(root_fd)
    try:
        for component in relative.parts:
            next_fd = os.open(component, flags, dir_fd=current_fd)
            os.close(current_fd)
            current_fd = next_fd
        return current_fd
    except OSError:
        os.close(current_fd)
        raise


def _utc_timestamp(timestamp: float) -> str:
    return datetime.fromtimestamp(timestamp, tz=UTC).isoformat(timespec="seconds").replace("+00:00", "Z")


def _validate_output_destination(path: Path, *, force: bool, parent_fd: int | None = None) -> None:
    """Reject unsafe destination types before creating or replacing a report."""
    try:
        if parent_fd is None:
            output_stat = path.lstat()
        else:
            output_stat = os.stat(path.name, dir_fd=parent_fd, follow_symlinks=False)
    except FileNotFoundError:
        return
    except OSError as exc:
        raise ScanError(f"Cannot inspect report destination: {exc}") from exc

    if stat.S_ISLNK(output_stat.st_mode) or _is_reparse_point(output_stat):
        raise ScanError("Report destination must not be a symbolic link or reparse point.")
    if not stat.S_ISREG(output_stat.st_mode):
        raise ScanError("Report destination must be a regular file; special files are not allowed.")
    if not force:
        raise ScanError("Report already exists; pass --force to replace it.")
    if getattr(output_stat, "st_nlink", 1) > 1:
        raise ScanError("Report destination has multiple hard links and cannot be safely replaced.")


def _write_report(path: Path, report: dict[str, Any], *, force: bool) -> None:
    """Write a complete private report before atomically publishing its pathname."""
    flags = _secure_directory_flags()
    try:
        parent_fd = os.open(path.parent, flags)
    except OSError as exc:
        raise ScanError(f"Could not safely open report directory: {exc}") from exc
    fd: int | None = None
    temporary_name: str | None = None
    try:
        _validate_output_destination(path, force=force, parent_fd=parent_fd)
        temp_flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL | getattr(os, "O_NOFOLLOW", 0)
        temp_flags |= getattr(os, "O_CLOEXEC", 0)
        for _ in range(10):
            temporary_name = f".aicre-report-{secrets.token_hex(16)}"
            try:
                fd = os.open(temporary_name, temp_flags, 0o600, dir_fd=parent_fd)
                break
            except FileExistsError:
                temporary_name = None
        if fd is None or temporary_name is None:
            raise OSError("Could not allocate a unique temporary report file")
        if os.name == "posix":
            os.fchmod(fd, 0o600)

        with os.fdopen(fd, "w", encoding="utf-8", newline="\n") as report_file:
            fd = None  # The context manager now owns and closes the descriptor.
            json.dump(report, report_file, ensure_ascii=False, indent=2)
            report_file.write("\n")
            report_file.flush()
            os.fsync(report_file.fileno())

        if force:
            # Replacing a directory entry does not follow a symlink installed at
            # the destination after validation, and does not truncate hard-link peers.
            os.replace(temporary_name, path.name, src_dir_fd=parent_fd, dst_dir_fd=parent_fd)
            temporary_name = None
        else:
            # link() publishes only if the destination is still absent; unlike a
            # second open, it cannot overwrite a concurrently created file.
            os.link(
                temporary_name, path.name,
                src_dir_fd=parent_fd, dst_dir_fd=parent_fd,
                follow_symlinks=False,
            )
            os.unlink(temporary_name, dir_fd=parent_fd)
            temporary_name = None
    except FileExistsError as exc:
        raise ScanError("Report already exists; pass --force to replace it.") from exc
    except OSError as exc:
        raise ScanError(f"Could not write report: {exc}") from exc
    finally:
        if fd is not None:
            os.close(fd)
        if temporary_name is not None:
            try:
                os.unlink(temporary_name, dir_fd=parent_fd)
            except FileNotFoundError:
                pass
            except OSError:
                pass
        os.close(parent_fd)


def scan_directory(source: str | Path, output: str | Path, *,
                   excludes: tuple[str, ...] | list[str] = (),
                   force: bool = False) -> dict[str, Any]:
    """Inventory metadata below source and write JSON outside source.

    On POSIX systems with descriptor-relative no-follow operations, directory
    traversal is anchored to the opened scan root and refuses symlink swaps.
    It is not an atomic filesystem snapshot and does not prevent concurrent
    changes to file metadata or mount topology.
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
    if is_sensitive_scan_root(source_path):
        raise ScanError("Scan root is a protected sensitive path; choose a different root.")

    source_real = source_path.resolve(strict=True)
    output_parent = output_path.parent.resolve(strict=True) if output_path.parent.exists() else output_path.parent.resolve()
    normalized_output = output_parent / output_path.name
    if _is_within(normalized_output, source_real):
        raise ScanError("Report destination must be outside the scan directory.")
    if not normalized_output.parent.is_dir():
        raise ScanError("Report parent directory does not exist.")
    _validate_output_destination(normalized_output, force=force)

    flags = _secure_directory_flags()
    try:
        root_fd = os.open(source_path, flags)
    except OSError as exc:
        raise ScanError(f"Cannot safely open source directory: {exc}") from exc
    try:
        opened_root_stat = os.fstat(root_fd)
        if (
            not stat.S_ISDIR(opened_root_stat.st_mode)
            or (opened_root_stat.st_dev, opened_root_stat.st_ino)
            != (source_stat.st_dev, source_stat.st_ino)
        ):
            raise ScanError("Source directory changed during validation; retry the scan.")

        records: list[dict[str, Any]] = []
        errors = 0
        excluded = 0
        stack: list[tuple[PurePosixPath, int, int]] = [
            (PurePosixPath(), opened_root_stat.st_dev, opened_root_stat.st_ino)
        ]

        while stack:
            current_relative, expected_dev, expected_ino = stack.pop()
            current_fd: int | None = None
            try:
                current_fd = _open_directory_beneath(root_fd, current_relative, flags)
                current_stat = os.fstat(current_fd)
                if (current_stat.st_dev, current_stat.st_ino) != (expected_dev, expected_ino):
                    errors += 1
                    continue

                with os.scandir(current_fd) as iterator:
                    entries = sorted(iterator, key=lambda item: item.name.casefold(), reverse=True)
                    for entry in entries:
                        try:
                            item_stat = entry.stat(follow_symlinks=False)
                        except OSError:
                            errors += 1
                            continue

                        if stat.S_ISLNK(item_stat.st_mode) or _is_reparse_point(item_stat):
                            excluded += 1
                            continue
                        if item_stat.st_dev != opened_root_stat.st_dev:
                            # Do not cross into a different filesystem mounted
                            # beneath the selected root.
                            excluded += 1
                            continue

                        relative_path = current_relative / entry.name
                        relative = relative_path.as_posix()
                        if is_sensitive_relative_path(relative) or is_user_excluded(relative, excludes):
                            excluded += 1
                            continue

                        if stat.S_ISDIR(item_stat.st_mode):
                            item_type = "directory"
                            extension = ""
                            size = None
                            try:
                                child_fd = os.open(entry.name, flags, dir_fd=current_fd)
                                try:
                                    child_stat = os.fstat(child_fd)
                                finally:
                                    os.close(child_fd)
                                if (
                                    not stat.S_ISDIR(child_stat.st_mode)
                                    or _is_reparse_point(child_stat)
                                    or (child_stat.st_dev, child_stat.st_ino)
                                    != (item_stat.st_dev, item_stat.st_ino)
                                ):
                                    errors += 1
                                else:
                                    stack.append((relative_path, child_stat.st_dev, child_stat.st_ino))
                            except OSError:
                                # The entry may have changed since lstat; never
                                # descend through a path that no longer matches.
                                errors += 1
                        elif stat.S_ISREG(item_stat.st_mode):
                            item_type = "file"
                            extension = Path(entry.name).suffix.lower()
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
            except OSError:
                errors += 1
            finally:
                if current_fd is not None:
                    os.close(current_fd)

        records.sort(key=lambda record: record["relative_path"].casefold())
        report = {
            "schema_version": "1",
            "aicre_version": "0.1.0",
            "source_name": source_path.name,
            "generated_utc": datetime.now(UTC).isoformat(timespec="seconds").replace("+00:00", "Z"),
            "summary": {
                "included_items": len(records),
                "excluded_items": excluded,
                "scan_errors": errors,
            },
            "items": records,
        }
    finally:
        os.close(root_fd)

    _write_report(normalized_output, report, force=force)
    return report
