"""Discover allowlisted executable locations without executing tools."""
from __future__ import annotations

import os
import shutil
import sys
import time
from pathlib import Path

from .models import Finding
from .privacy import path_exclusion_reason

TOOL_NAMES = (
    "git",
    "python3",
    "pip",
    "uv",
    "pipx",
    "node",
    "npm",
    "docker",
    "podman",
    "codex",
    "claude",
    "aider",
    "ollama",
)


def _search_path_for_tool(
    name: str, path_entries: list[str], excludes: tuple[str, ...] | list[str]
) -> tuple[str, bool, bool]:
    """Filter excluded directories/candidate paths before ``shutil.which`` stats them."""
    permitted: list[str] = []
    excluded_candidate = False
    for entry in path_entries:
        search_dir = entry or os.curdir
        candidate = Path(search_dir) / name
        reason = path_exclusion_reason(search_dir, excludes)
        if reason is None:
            reason = path_exclusion_reason(candidate, excludes)
        if reason is not None:
            excluded_candidate = True
            continue
        permitted.append(entry)
    return os.pathsep.join(permitted), excluded_candidate, bool(permitted)


def discover_tools(
    excludes: tuple[str, ...] | list[str] = (), deadline: float | None = None
) -> list[Finding]:
    """Return one privacy-filtered availability finding for each allowlisted tool.

    ``deadline`` is an absolute timestamp from :func:`time.monotonic`; checks
    are cooperative and performed before each lookup. PATH entries and each
    potential executable path are filtered before ``shutil.which`` examines
    them, so excluded directories are not searched.
    """
    if not sys.platform.startswith("linux"):
        return [
            Finding(
                id=f"tool.{name}",
                category="software",
                status="unsupported",
                value=None,
                source="shutil.which",
                limitations=(
                    "Tool discovery is supported only on Linux in this preview.",
                ),
            )
            for name in TOOL_NAMES
        ]

    path_entries = os.environ.get("PATH", os.defpath).split(os.pathsep)
    findings: list[Finding] = []
    for name in TOOL_NAMES:
        source = f"shutil.which({name})"
        if deadline is not None and time.monotonic() >= deadline:
            findings.append(
                Finding(
                    id=f"tool.{name}",
                    category="software",
                    status="not_checked",
                    value=None,
                    source=source,
                    limitations=("discovery deadline expired",),
                )
            )
            continue

        search_path, excluded_candidate, has_permitted_paths = _search_path_for_tool(
            name, path_entries, excludes
        )
        if not has_permitted_paths:
            found_path = None
        else:
            try:
                found_path = shutil.which(name, path=search_path)
            except OSError as exc:
                findings.append(
                    Finding(
                        id=f"tool.{name}",
                        category="software",
                        status="permission_denied" if isinstance(exc, PermissionError) else "error",
                        value=None,
                        source="shutil.which (path withheld)",
                        limitations=(f"Executable lookup unavailable ({type(exc).__name__}).",),
                    )
                )
                continue

        if found_path is None:
            if excluded_candidate:
                findings.append(
                    Finding(
                        id=f"tool.{name}",
                        category="software",
                        status="not_checked",
                        value=None,
                        source="shutil.which (path withheld)",
                        limitations=("one or more candidate paths were excluded by policy",),
                    )
                )
            else:
                findings.append(
                    Finding(
                        id=f"tool.{name}",
                        category="software",
                        status="not_detected",
                        value=None,
                        source=source,
                        limitations=(
                            "Only permitted PATH entries are checked; the tool may be installed elsewhere.",
                        ),
                    )
                )
            continue

        absolute_path = os.path.abspath(found_path)
        exclusion = path_exclusion_reason(absolute_path, excludes)
        if exclusion is not None:
            findings.append(
                Finding(
                    id=f"tool.{name}",
                    category="software",
                    status="not_checked",
                    value=None,
                    source="shutil.which (path withheld)",
                    limitations=(exclusion,),
                )
            )
            continue

        findings.append(
            Finding(
                id=f"tool.{name}",
                category="software",
                status="detected",
                value=absolute_path,
                source=source,
                limitations=(
                    "PATH lookup only; the executable is not run and its version or functionality is not verified.",
                ),
            )
        )
    return findings
