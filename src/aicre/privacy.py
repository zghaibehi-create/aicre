"""Shared path filtering for discovery sources and reportable executable paths."""
from __future__ import annotations

from os import PathLike, fspath
from pathlib import Path, PurePosixPath

from .policy import is_sensitive_relative_path, is_user_excluded


def _relative_candidates(path: str | PathLike[str]) -> tuple[str, ...]:
    """Return root-relative and, when applicable, home-relative path spellings."""
    candidate = Path(fspath(path)).expanduser()
    if not candidate.is_absolute():
        candidate = candidate.absolute()
    candidate = Path(PurePosixPath(candidate.as_posix()))
    result = [candidate.as_posix().lstrip("/")]
    try:
        home_relative = candidate.relative_to(Path.home()).as_posix()
    except ValueError:
        pass
    else:
        if home_relative and home_relative not in result:
            result.append(home_relative)
    return tuple(result)


def path_exclusion_reason(
    path: str | PathLike[str], patterns: tuple[str, ...] | list[str] = ()
) -> str | None:
    """Return a non-sensitive reason when a path must not be read or disclosed.

    User patterns match paths relative to the filesystem root and, for paths
    below the current home directory, relative to that home directory. This
    makes the same exclusion useful for system inventory and discovered tools.
    The legacy directory scanner continues to match paths relative to its
    selected scan root.
    """
    candidates = _relative_candidates(path)
    if any(is_sensitive_relative_path(candidate) for candidate in candidates):
        return "protected by the built-in sensitive-path policy"
    if any(is_user_excluded(candidate, patterns) for candidate in candidates):
        return "excluded by a user-supplied path pattern"
    return None


def path_is_excluded(
    path: str | PathLike[str], patterns: tuple[str, ...] | list[str] = ()
) -> bool:
    """Whether a source or path value must be omitted under current policy."""
    return path_exclusion_reason(path, patterns) is not None
