"""Deterministic workload baselines; comparisons use existing observations only."""

from __future__ import annotations

from collections.abc import Sequence

from .models import Finding
from .profiles import PROFILES, list_profiles, resolve_profile

GIB = 1024 ** 3

__all__ = ["GIB", "PROFILES", "evaluate_workload_profile", "supported_profiles"]


def supported_profiles() -> tuple[str, ...]:
    """Return profile names in their documented order."""
    return tuple(list_profiles())


def evaluate_workload_profile(findings: Sequence[Finding], profile: str) -> list[Finding]:
    """Create derived comparisons without collecting or executing anything."""
    requirements = resolve_profile(profile)
    if profile == "standard":
        return []

    by_id = {item.id: item for item in findings if isinstance(item, Finding)}
    checks: list[Finding] = []
    specs = (
        ("cpu", "resource.cpu.logical_count", requirements["cores_min"], "logical CPUs", 1),
        ("memory", "resource.memory.total_bytes", requirements["ram_gb_min"] * GIB, "bytes", GIB),
        ("storage", "resource.storage.root", requirements["disk_gb_min"] * GIB, "bytes", GIB),
    )

    for name, source_id, minimum, unit, divisor in specs:
        source = by_id.get(source_id)
        actual = None
        if source is not None and source.status == "detected":
            if name == "storage" and isinstance(source.value, dict):
                actual = source.value.get("free_bytes")
            elif isinstance(source.value, int) and not isinstance(source.value, bool):
                actual = source.value

        valid = isinstance(actual, int) and not isinstance(actual, bool) and actual >= 0
        checks.append(Finding(
            id=f"profile.resource.{name}",
            category="profile",
            status="detected" if valid else "not_checked",
            value={
                "satisfied": None,
                "actual": actual,
                "minimum": minimum,
                "ratio": None,
                "unit": unit,
                "display_unit": "GiB" if divisor == GIB else unit,
                "source_finding": source_id,
                "comparison": "not_performed",
                "observation_scope": "host_facing",
            },
            source=f"AICRE {profile} profile",
            confidence="medium" if valid else "low",
            unit=unit,
            limitations=(
                "Host-facing observation only; effective process, container, cgroup, affinity, or filesystem quota limits are not established. Resource readiness remains unknown.",
            ) if valid else (
                "Required host observation unavailable, excluded, malformed, or timed out.",
            ),
        ))

    for tool in requirements["required_tools"]:
        source = by_id.get(f"tool.{tool}")
        status = source.status if source is not None else "not_checked"
        if status not in {
            "detected", "not_detected", "unsupported",
            "permission_denied", "error", "not_checked",
        }:
            status = "not_checked"
        checks.append(Finding(
            id=f"profile.software.{tool}",
            category="profile",
            status=status,
            value={
                "satisfied": status == "detected" if status in {"detected", "not_detected"} else None,
                "required_tool": tool,
                "source_finding": f"tool.{tool}",
            },
            source=f"AICRE {profile} profile",
            confidence="high" if status in {"detected", "not_detected"} else "low",
            limitations=(
                "PATH presence only; version, configuration, security, and functionality are not verified.",
            ),
        ))
    return checks
