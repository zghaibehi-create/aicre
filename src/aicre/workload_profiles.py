"""Deterministic workload baselines; comparisons use existing observations only."""
from __future__ import annotations

from collections.abc import Sequence
from .models import Finding


GIB = 1024 ** 3
PROFILES = {
    "standard": {"description": "Inventory only; no workload assumptions.", "required_tools": ()},
    "agent-development": {
        "description": "Conservative local agent-development baseline; not a model-inference profile.",
        "cpu_min": 2, "memory_min": 8 * GIB, "storage_min": 10 * GIB,
        "required_tools": ("git", "python3"),
    },
}

def supported_profiles() -> tuple[str, ...]:
    return tuple(PROFILES)

def evaluate_workload_profile(findings: Sequence[Finding], profile: str) -> list[Finding]:
    """Compare inventory findings with an explicit baseline without executing tools."""
    if profile not in PROFILES:
        raise ValueError(f"unsupported profile: {profile}")
    if profile == "standard":
        return []
    by_id = {f.id: f for f in findings if isinstance(f, Finding)}
    checks: list[Finding] = []
    specs = (
        ("cpu", "resource.cpu.logical_count", PROFILES[profile]["cpu_min"], "logical CPUs"),
        ("memory", "resource.memory.total_bytes", PROFILES[profile]["memory_min"], "bytes"),
        ("storage", "resource.storage.root", PROFILES[profile]["storage_min"], "bytes"),
    )
    for name, source_id, minimum, unit in specs:
        source = by_id.get(source_id)
        actual = None
        if source is not None and source.status == "detected":
            if name == "storage" and isinstance(source.value, dict):
                actual = source.value.get("free_bytes")
            elif isinstance(source.value, int) and not isinstance(source.value, bool):
                actual = source.value
        valid = isinstance(actual, int) and not isinstance(actual, bool) and actual >= 0
        checks.append(Finding(
            id=f"profile.resource.{name}", category="profile",
            status="detected" if valid else "not_checked",
            value={"satisfied": actual >= minimum if valid else None, "actual": actual,
                   "minimum": minimum, "unit": unit, "source_finding": source_id},
            source="AICRE agent-development baseline",
            confidence="high" if valid else "low", unit=unit,
            limitations=() if valid else ("Required observation unavailable, excluded, malformed, or timed out.",),
        ))
    for tool in PROFILES[profile]["required_tools"]:
        source = by_id.get(f"tool.{tool}")
        if source is not None and source.status == "detected":
            status, satisfied = "detected", True
        elif source is not None and source.status == "not_detected":
            status, satisfied = "not_detected", False
        else:
            status, satisfied = "not_checked", None
        checks.append(Finding(
            id=f"profile.software.{tool}", category="profile", status=status,
            value={"satisfied": satisfied, "required_tool": tool, "source_finding": f"tool.{tool}"},
            source="AICRE agent-development baseline",
            confidence="high" if satisfied is not None else "low",
            limitations=("PATH presence only; version, configuration, security, and functionality are not verified.",),
        ))
    return checks
