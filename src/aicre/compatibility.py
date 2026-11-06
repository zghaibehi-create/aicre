"""Explicit runtime compatibility checks for AICRE 0.2.

The ``standard`` profile requires Linux and Python 3.11 or newer, matching
AICRE's ``pyproject.toml``. It has no GPU requirement. Checks are local,
read-only observations of ``platform.system()`` and ``sys.version_info``.
"""
from __future__ import annotations

import platform
import sys
import time

from aicre.models import Finding

_PROFILE_REQUIREMENTS = {
    "standard": ("Linux", (3, 11, 0)),
}


def evaluate_compatibility(
    profile: str = "standard",
    *,
    system: str | None = None,
    python_version: tuple[int, int, int] | None = None,
    deadline: float | None = None,
) -> list[Finding]:
    """Evaluate explicit runtime requirements and return two stable findings.

    ``deadline`` is an absolute ``time.monotonic()`` deadline. If it has
    expired, neither runtime property is checked and both values are null.
    """
    if profile not in _PROFILE_REQUIREMENTS:
        raise ValueError(f"unsupported compatibility profile: {profile}")

    required_platform, required_python = _PROFILE_REQUIREMENTS[profile]
    if deadline is not None and time.monotonic() >= deadline:
        limitation = ("Deadline expired before runtime compatibility checks.",)
        return [
            Finding(
                id="compatibility.platform.linux",
                category="compatibility",
                status="not_checked",
                value=None,
                source="platform.system()",
                confidence="high",
                limitations=limitation,
            ),
            Finding(
                id="compatibility.python.minimum",
                category="compatibility",
                status="not_checked",
                value=None,
                source="sys.version_info",
                confidence="high",
                limitations=limitation,
            ),
        ]

    actual_system = platform.system() if system is None else system
    actual_python = sys.version_info[:3] if python_version is None else python_version
    platform_satisfied = actual_system == required_platform
    python_satisfied = actual_python >= required_python

    return [
        Finding(
            id="compatibility.platform.linux",
            category="compatibility",
            status="detected" if platform_satisfied else "unsupported",
            value={
                "actual": actual_system,
                "required": required_platform,
                "satisfied": platform_satisfied,
            },
            source="platform.system()",
            confidence="high",
        ),
        Finding(
            id="compatibility.python.minimum",
            category="compatibility",
            status="detected" if python_satisfied else "not_detected",
            value={
                "actual": ".".join(map(str, actual_python)),
                "required": ">=3.11",
                "satisfied": python_satisfied,
            },
            source="sys.version_info",
            confidence="high",
        ),
    ]
