"""Conservative path-based privacy policy. No file contents are inspected."""
from __future__ import annotations

import fnmatch
import re
from os import PathLike, fspath
from pathlib import PurePosixPath

SENSITIVE_DIRS = {
    ".ssh", ".gnupg", ".aws", ".azure", ".kube", ".docker",
    "credentials", "credential", "secrets", "secret",
    "passwords", "password", "wallets", "wallet",
}
SENSITIVE_CONFIG_DIR_PAIRS = {
    (".config", "gcloud"),
    (".config", "gh"),
}
SENSITIVE_NAMES = {
    ".env", ".env.local", ".env.development", ".env.production", ".env.staging",
    ".env.test", ".env.development.local", ".env.production.local",
    ".env.staging.local", ".env.test.local", ".envrc",
    ".netrc", ".npmrc", ".pypirc", ".authinfo", "auth.json",
    "id_rsa", "id_dsa", "id_ecdsa", "id_ed25519", "id_xmss",
    "id_ecdsa_sk", "id_ed25519_sk", "known_hosts", "authorized_keys",
    "credentials", "credentials.json", "secrets.json", "secrets.yaml",
    "secrets.yml", "token", "tokens", "token.txt", "tokens.txt",
    "token.json", "tokens.json", "passwords.txt", "master.key",
}
SENSITIVE_SUFFIXES = {".pem", ".key", ".p12", ".pfx", ".kdbx", ".keystore"}
SENSITIVE_WORD = re.compile(
    r"(^|[._-])(secret|secrets|password|passwd|credential|credentials|private[-_]?key)([._-]|$)",
    re.IGNORECASE,
)
SENSITIVE_TOKEN_FIELD = re.compile(
    r"(^|[._-])(access|refresh|auth|oauth|api)[_-]?tokens?([._-]|$)", re.IGNORECASE
)


def _normalized_parts(path: str) -> list[str]:
    return [part.lower() for part in PurePosixPath(path.replace("\\", "/")).parts]


def is_sensitive_relative_path(relative_path: str) -> bool:
    """Return True for known credential locations/names, based on path only."""
    parts = _normalized_parts(relative_path)
    if any(part in SENSITIVE_DIRS for part in parts):
        return True
    if any(tuple(parts[index:index + 2]) in SENSITIVE_CONFIG_DIR_PAIRS
           for index in range(len(parts) - 1)):
        return True

    name = parts[-1] if parts else ""
    suffix = PurePosixPath(name).suffix.lower()
    return (
        name in SENSITIVE_NAMES
        or suffix in SENSITIVE_SUFFIXES
        or bool(SENSITIVE_WORD.search(name))
        or bool(SENSITIVE_TOKEN_FIELD.search(name))
    )


def is_sensitive_scan_root(root: str | PathLike[str]) -> bool:
    """Return True if any selected-root component is a protected sensitive path."""
    parts = _normalized_parts(fspath(root))
    if any(tuple(parts[index:index + 2]) in SENSITIVE_CONFIG_DIR_PAIRS
           for index in range(len(parts) - 1)):
        return True
    return any(is_sensitive_relative_path(part) for part in parts if part not in {"/", "\\"})


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
