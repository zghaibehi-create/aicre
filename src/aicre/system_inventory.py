"""Privacy-conscious Linux system metadata inventory."""
from __future__ import annotations

import os
import platform
import re
import shutil
import sys
import sysconfig
import time
from pathlib import Path
from typing import Any

from .models import Finding
from .privacy import path_exclusion_reason

_PROC_MEMINFO = "/proc/meminfo"
_OS_RELEASE = "/etc/os-release"


def _finding(
    identifier: str,
    category: str,
    status: str,
    value: Any,
    source: str,
    *,
    confidence: str = "high",
    unit: str | None = None,
    limitations: tuple[str, ...] = (),
) -> Finding:
    return Finding(
        id=identifier,
        category=category,
        status=status,
        value=value,
        source=source,
        confidence=confidence,
        unit=unit,
        limitations=limitations,
    )


def _skip(identifier: str, category: str, source: str, reason: str) -> Finding:
    return _finding(identifier, category, "not_checked", None, source,
                    limitations=(reason,))


def _unavailable(identifier: str, category: str, source: str, exc: Exception) -> Finding:
    status = "permission_denied" if isinstance(exc, PermissionError) else "error"
    return _finding(identifier, category, status, None, source,
                    limitations=(f"Source unavailable ({type(exc).__name__}).",))


def _meminfo(path: str) -> dict[str, int]:
    """Read only the two approved numeric fields from procfs metadata."""
    values: dict[str, int] = {}
    with open(path, encoding="ascii") as handle:
        for line in handle:
            key, separator, raw = line.partition(":")
            if separator and key in {"MemTotal", "MemAvailable"}:
                fields = raw.split()
                if len(fields) >= 2 and fields[1] == "kB":
                    try:
                        values[key] = int(fields[0]) * 1024
                    except ValueError:
                        continue
    return values


def _drm_names() -> list[str]:
    """List DRM card entry names only; callers read only vendor/device IDs."""
    with os.scandir("/sys/class/drm") as entries:
        return sorted(
            entry.name for entry in entries
            if re.fullmatch(r"card\d+", entry.name)
        )


def _gpu_finding(excludes: tuple[str, ...] | list[str], deadline: float | None) -> Finding:
    source = "Linux DRM sysfs metadata"
    drm_root = "/sys/class/drm"
    if deadline is not None and time.monotonic() >= deadline:
        return _skip("resource.gpu", "resource", source,
                     "Collection deadline reached before this observation was collected.")
    reason = path_exclusion_reason(drm_root, excludes)
    if reason:
        return _skip("resource.gpu", "resource", "excluded GPU metadata source", reason)
    try:
        names = _drm_names()
    except (FileNotFoundError, NotADirectoryError):
        return _finding("resource.gpu", "resource", "not_detected", None, source,
                        limitations=("No Linux DRM card metadata was available; other GPU providers may use different interfaces.",))
    except OSError as exc:
        return _unavailable("resource.gpu", "resource", source, exc)

    devices: list[dict[str, str]] = []
    excluded_device = False
    for name in names:
        if deadline is not None and time.monotonic() >= deadline:
            if devices:
                return _finding(
                    "resource.gpu", "resource", "detected", {"devices": devices}, source,
                    confidence="medium",
                    limitations=("GPU enumeration stopped at the cooperative collection deadline; results may be partial.",),
                )
            return _skip("resource.gpu", "resource", source,
                         "Collection deadline reached before this observation was collected.")
        vendor_path = f"{drm_root}/{name}/device/vendor"
        device_path = f"{drm_root}/{name}/device/device"
        vendor_reason = path_exclusion_reason(vendor_path, excludes)
        device_reason = path_exclusion_reason(device_path, excludes)
        if vendor_reason or device_reason:
            excluded_device = True
            continue
        try:
            vendor_id = Path(vendor_path).read_text(encoding="ascii").strip()
            device_id = Path(device_path).read_text(encoding="ascii").strip()
        except FileNotFoundError:
            continue
        except UnicodeError as exc:
            return _unavailable("resource.gpu", "resource", source, exc)
        except PermissionError as exc:
            return _unavailable("resource.gpu", "resource", source, exc)
        except OSError as exc:
            return _unavailable("resource.gpu", "resource", source, exc)
        if re.fullmatch(r"0x[0-9a-fA-F]{4}", vendor_id) and re.fullmatch(
            r"0x[0-9a-fA-F]{4}", device_id
        ):
            devices.append({"vendor_id": vendor_id, "device_id": device_id})

    if devices:
        return _finding("resource.gpu", "resource", "detected", {"devices": devices}, source,
                        confidence="medium",
                        limitations=("Only Linux DRM vendor/device identifiers are collected; other GPU metadata and driver readiness are not assessed.",))
    if excluded_device:
        return _skip("resource.gpu", "resource", "excluded GPU metadata source",
                     "One or more GPU metadata paths were excluded by policy.")
    return _finding("resource.gpu", "resource", "not_detected", None, source,
                    confidence="medium",
                    limitations=("No readable Linux DRM card metadata was found; other GPU providers may use different interfaces.",))


def collect_system_findings(
    excludes: tuple[str, ...] | list[str] = (), deadline: float | None = None
) -> list[Finding]:
    """Collect local system metadata without executing programs or inspecting user data."""
    linux = sys.platform.startswith("linux")
    findings: list[Finding] = []

    def timed_out() -> bool:
        return deadline is not None and time.monotonic() >= deadline

    def timeout_finding(identifier: str, category: str, source: str) -> Finding:
        return _skip(identifier, category, source, "Collection deadline reached before this observation was collected.")

    # Distro data is provided by the standard library's documented os-release reader.
    if not linux:
        findings.append(_finding("system.os_release", "system", "unsupported", None,
                                 "platform.freedesktop_os_release", limitations=("Linux-only observation.",)))
    elif timed_out():
        findings.append(timeout_finding("system.os_release", "system", "platform.freedesktop_os_release"))
    else:
        release_sources = (_OS_RELEASE, "/usr/lib/os-release")
        reason = next(
            (blocked for candidate in release_sources
             if (blocked := path_exclusion_reason(candidate, excludes))),
            None,
        )
        if reason:
            findings.append(_skip("system.os_release", "system", "excluded os-release source", reason))
        else:
            try:
                release = platform.freedesktop_os_release()
                # Retain only distro identification fields; omit arbitrary release data.
                value = {key: release[key] for key in ("ID", "NAME", "VERSION_ID", "PRETTY_NAME") if key in release}
                findings.append(_finding("system.os_release", "system", "detected" if value else "not_detected", value or None,
                                         "platform.freedesktop_os_release"))
            except OSError as exc:
                findings.append(_unavailable("system.os_release", "system", "platform.freedesktop_os_release", exc))
            except (AttributeError, ValueError) as exc:
                findings.append(_finding("system.os_release", "system", "error", None,
                                         "platform.freedesktop_os_release", limitations=(f"Source unavailable ({type(exc).__name__}).",)))

    # Kernel/system/machine use platform APIs and require no filesystem traversal by this module.
    if not linux:
        findings.append(_finding("system.kernel", "system", "unsupported", None, "platform",
                                 limitations=("Linux-only observation.",)))
    elif timed_out():
        findings.append(timeout_finding("system.kernel", "system", "platform"))
    else:
        try:
            uname = platform.uname()
            value = {"system": uname.system, "kernel": uname.release, "machine": uname.machine}
            findings.append(_finding("system.kernel", "system", "detected", value, "platform.uname"))
        except OSError as exc:
            findings.append(_unavailable("system.kernel", "system", "platform.uname", exc))

    if not linux:
        findings.append(_finding("resource.cpu.logical_count", "resource", "unsupported", None, "os.cpu_count",
                                 limitations=("Linux-only observation.",)))
    elif timed_out():
        findings.append(timeout_finding("resource.cpu.logical_count", "resource", "os.cpu_count"))
    else:
        try:
            count = os.cpu_count()
            findings.append(_finding("resource.cpu.logical_count", "resource", "detected" if count is not None else "not_detected",
                                     count, "os.cpu_count", unit="logical CPUs"))
        except OSError as exc:
            findings.append(_unavailable("resource.cpu.logical_count", "resource", "os.cpu_count", exc))

    memory_values: dict[str, int] = {}
    meminfo_read = False
    meminfo_error: Exception | None = None
    mem_reason = path_exclusion_reason(_PROC_MEMINFO, excludes) if linux else None
    for identifier, key in (("resource.memory.total_bytes", "MemTotal"),
                             ("resource.memory.available_bytes", "MemAvailable")):
        source = "/proc/meminfo"
        if not linux:
            result = _finding(identifier, "resource", "unsupported", None, source,
                              unit="bytes", limitations=("Linux-only observation.",))
        elif timed_out():
            result = timeout_finding(identifier, "resource", source)
        elif mem_reason:
            result = _skip(identifier, "resource", "excluded memory metadata source", mem_reason)
        else:
            if not meminfo_read:
                meminfo_read = True
                try:
                    memory_values = _meminfo(_PROC_MEMINFO)
                except (OSError, UnicodeError) as exc:
                    meminfo_error = exc
            if meminfo_error is not None:
                result = _unavailable(identifier, "resource", source, meminfo_error)
            else:
                result = _finding(
                    identifier, "resource",
                    "detected" if key in memory_values else "not_detected",
                    memory_values.get(key), source, unit="bytes",
                    limitations=() if key in memory_values
                    else (f"{key} is absent or malformed in /proc/meminfo.",),
                )
        findings.append(result)

    storage_source = "shutil.disk_usage('/')"
    if not linux:
        findings.append(_finding("resource.storage.root", "resource", "unsupported", None, storage_source,
                                 unit="bytes", limitations=("Linux-only observation.",)))
    elif timed_out():
        findings.append(timeout_finding("resource.storage.root", "resource", storage_source))
    elif (storage_reason := path_exclusion_reason("/", excludes)) is not None:
        findings.append(_skip(
            "resource.storage.root", "resource", "excluded root filesystem source", storage_reason
        ))
    else:
        try:
            usage = shutil.disk_usage("/")
            findings.append(_finding("resource.storage.root", "resource", "detected",
                                     {"total_bytes": usage.total, "used_bytes": usage.used,
                                      "free_bytes": usage.free}, storage_source, unit="bytes"))
        except OSError as exc:
            findings.append(_unavailable("resource.storage.root", "resource", storage_source, exc))

    python_source = "sys / sysconfig"
    if timed_out():
        findings.append(timeout_finding("python.environment", "runtime", python_source))
    else:
        paths = {"executable": sys.executable, "prefix": sys.prefix}
        excluded_names = [name for name, path in paths.items() if path_exclusion_reason(path, excludes)]
        for name in excluded_names:
            paths.pop(name)
        value = {"version": platform.python_version(), "implementation": sys.implementation.name,
                 "platform": sysconfig.get_platform(),
                 "abi": sysconfig.get_config_var("SOABI"),
                 **paths, "venv": sys.prefix != getattr(sys, "base_prefix", sys.prefix)}
        limitation = ("One or more Python paths were omitted by path privacy policy.",) if excluded_names else ()
        findings.append(_finding("python.environment", "runtime", "detected", value, python_source,
                                 limitations=limitation))

    uid_source = "os.geteuid"
    if timed_out():
        findings.append(timeout_finding("security.effective_uid", "security", uid_source))
    elif not hasattr(os, "geteuid"):
        findings.append(_finding("security.effective_uid", "security", "unsupported", None, uid_source,
                                 limitations=("Effective UID is unavailable on this platform.",)))
    else:
        try:
            findings.append(_finding("security.effective_uid", "security", "detected", os.geteuid(), uid_source))
        except OSError as exc:
            findings.append(_unavailable("security.effective_uid", "security", uid_source, exc))

    if not linux:
        findings.append(_finding("resource.gpu", "resource", "unsupported", None,
                                 "Linux DRM sysfs metadata",
                                 limitations=("Linux-only observation.",)))
    else:
        findings.append(_gpu_finding(excludes, deadline))
    return findings
