"""Conservative path-based privacy policy. No file contents are inspected."""
from __future__ import annotations

import fnmatch
import re
from pathlib import PurePosixPath

SENSITIVE_DIRS = {
    ".ssh", ".gnupg", ".aws", ".azure", ".docker",
    "credentials", "credential", "secrets", "secret",
    "passwords", "password", "wallets", "wallet",
}
SENSITIVE_NAMES = {
    ".env", ".env.local", ".env.production", ".netrc",
    "id_rsa", "id_dsa", "id_ecdsa", "id_ed25519",
    "known_hosts", "authorized_keys",
    "credentials", "credentials.json", "secrets.json",
    "secrets.yaml", "secrets.yml", "token", "tokens",
    "passwords.txt", "master.key",
}
SENSITIVE_SUFFIXES = {".pem", ".key", ".p12", ".pfx", ".kdbx", ".keystore"}
SENSITIVE_WORD = re.compile(r"(^|[._-])(secret|secrets|password|passwd|credential|credentials|token|private[-_]?key)([._-]|$)", re.I)


def is_sensitive_relative_path(relative_path: str) -> bool:
    """Return True for well-known credential locations/names, by path only."""
    path = PurePosixPath(relative_path.replace("\\", "/"))
    parts = [part.lower() for part in path.parts]
    if any(part in SENSITIVE_DIRS for part in parts):
        return True
    name = parts[-1] if parts else ""
    suffix = PurePosixPath(name).suffix.lower()
    return (
        name in SENSITIVE_NAMES
        or suffix in SENSITIVE_SUFFIXES
        or bool(SENSITIVE_WORD.search(name))
    )


def is_user_excluded(relative_path: str, patterns: tuple[str, ...] | list[str]) -> bool:
    """Match user exclusions against normalized relative POSIX paths."""
    candidate = relative_path.replace("\\", "/")
    for raw in patterns:
        pattern = raw.replace("\\", "/").strip("/")
        if not pattern:
            continue
        if pattern.endswith("/**"):
            base = pattern[:-3].rstrip("/")
            if candidate == base or candidate.startswith(base + "/"):
                return True
        if fnmatch.fnmatchcase(candidate, pattern):
            return True
        # A literal directory pattern also excludes all descendants.
        if not any(char in pattern for char in "*?[") and (
            candidate == pattern or candidate.startswith(pattern + "/")
        ):
            return True
    return False
