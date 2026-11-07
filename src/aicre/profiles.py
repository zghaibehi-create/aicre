"""Named workload requirements used by readiness evaluation."""

from __future__ import annotations

from typing import Any

PROFILES: dict[str, dict[str, Any]] = {
    "standard": {
        "description": "Inventory only; no workload assumptions.",
        "cores_min": None,
        "ram_gb_min": None,
        "disk_gb_min": None,
        "required_tools": [],
        "gpu_required": False,
    },
    "agent-development": {
        "description": "Conservative local agent-development baseline; not a model-inference profile.",
        "cores_min": 2,
        "ram_gb_min": 8,
        "disk_gb_min": 10,
        "required_tools": ["git", "python3"],
        "gpu_required": False,
    },
    "laptop-dev": {
        "description": "General-purpose laptop development baseline.",
        "cores_min": 4,
        "ram_gb_min": 16,
        "disk_gb_min": 20,
        "required_tools": ["git", "python3", "node"],
        "gpu_required": False,
    },
    "agent-workstation": {
        "description": "Local AI-agent development workstation baseline.",
        "cores_min": 8,
        "ram_gb_min": 32,
        "disk_gb_min": 50,
        "required_tools": ["git", "python3", "docker", "ollama"],
        "gpu_required": False,
    },
    "ci-runner": {
        "description": "Lightweight continuous-integration runner baseline.",
        "cores_min": 2,
        "ram_gb_min": 8,
        "disk_gb_min": 10,
        "required_tools": ["git", "python3", "pip"],
        "gpu_required": False,
    },
}


def list_profiles() -> list[str]:
    """Return supported profile names in their documented order."""
    return list(PROFILES)


def resolve_profile(name: str) -> dict[str, Any]:
    """Return a defensive copy of a profile or raise an actionable error."""
    try:
        profile = PROFILES[name]
    except KeyError as exc:
        available = ", ".join(list_profiles())
        raise ValueError(
            f"unknown profile {name!r}; available profiles: {available}"
        ) from exc
    return {**profile, "required_tools": list(profile["required_tools"])}
