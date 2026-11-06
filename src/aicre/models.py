"""Shared, validated data contracts for AICRE 0.2 findings and readiness."""
from __future__ import annotations

from dataclasses import dataclass, field
from datetime import UTC, datetime
from typing import Any

FINDING_STATUSES = frozenset({
    "detected",
    "not_detected",
    "unsupported",
    "permission_denied",
    "error",
    "not_checked",
})
READINESS_STATUSES = frozenset({"pass", "warning", "fail", "unknown"})
CONFIDENCE_LEVELS = frozenset({"high", "medium", "low"})


def utc_now() -> str:
    """Return a timezone-aware ISO 8601 UTC timestamp with a Z suffix."""
    return datetime.now(UTC).isoformat(timespec="seconds").replace("+00:00", "Z")


@dataclass(frozen=True)
class Finding:
    """One evidence-backed observation collected from an explicitly named source."""

    id: str
    category: str
    status: str
    value: Any
    source: str
    confidence: str = "high"
    unit: str | None = None
    collected_at: str = field(default_factory=utc_now)
    limitations: tuple[str, ...] = ()

    def __post_init__(self) -> None:
        if not self.id or not self.category or not self.source:
            raise ValueError("finding id, category, and source must be non-empty")
        if self.status not in FINDING_STATUSES:
            raise ValueError(f"unsupported finding status: {self.status}")
        if self.confidence not in CONFIDENCE_LEVELS:
            raise ValueError(f"unsupported confidence level: {self.confidence}")
        if not self.collected_at.endswith("Z"):
            raise ValueError("collected_at must be a UTC timestamp ending in Z")
        if not isinstance(self.limitations, tuple) or any(
            not isinstance(item, str) for item in self.limitations
        ):
            raise ValueError("limitations must be a tuple of strings")

    def to_dict(self) -> dict[str, Any]:
        """Convert to the stable JSON finding shape."""
        return {
            "id": self.id,
            "category": self.category,
            "status": self.status,
            "value": self.value,
            "unit": self.unit,
            "source": self.source,
            "confidence": self.confidence,
            "collected_at": self.collected_at,
            "limitations": list(self.limitations),
        }


@dataclass(frozen=True)
class ReadinessDimension:
    """A separately explained dimension; no composite score is implied."""

    name: str
    status: str
    explanation: str
    evidence: tuple[str, ...] = ()

    def __post_init__(self) -> None:
        if not self.name or not self.explanation:
            raise ValueError("readiness name and explanation must be non-empty")
        if self.status not in READINESS_STATUSES:
            raise ValueError(f"unsupported readiness status: {self.status}")
        if any(not isinstance(item, str) or not item for item in self.evidence):
            raise ValueError("evidence must contain non-empty finding IDs")

    def to_dict(self) -> dict[str, Any]:
        return {
            "status": self.status,
            "explanation": self.explanation,
            "evidence": list(self.evidence),
        }
