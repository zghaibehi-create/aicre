"""Evidence-backed readiness assessments for AICRE."""

from __future__ import annotations

from collections.abc import Sequence
from typing import Any

from aicre.models import Finding, ReadinessDimension
from aicre.profiles import resolve_profile


def _dimension(
    name: str,
    status: str,
    explanation: str,
    evidence: Sequence[str] = (),
) -> ReadinessDimension:
    return ReadinessDimension(name, status, explanation, tuple(evidence))


def _resource_evidence(findings: Sequence[Finding]) -> tuple[str, ...]:
    terms = ("cpu", "ram", "memory", "storage", "disk")
    return tuple(
        item.id
        for item in findings
        if isinstance(item, Finding)
        and any(term in f"{item.id} {item.category}".lower() for term in terms)
    )


def _uid_value(value: Any) -> int | None:
    if isinstance(value, int) and not isinstance(value, bool):
        return value
    if isinstance(value, dict):
        uid = value.get("effective_uid")
        if isinstance(uid, int) and not isinstance(uid, bool):
            return uid
    return None


def _resource_status(by_id: dict[str, Finding]) -> tuple[str, tuple[str, ...]]:
    """Host-facing observations cannot establish effective resource capacity."""
    evidence = tuple(
        identifier
        for identifier in (
            "profile.resource.cpu",
            "profile.resource.memory",
            "profile.resource.storage",
        )
        if identifier in by_id
    )
    return "unknown", evidence


def _software_status(
    by_id: dict[str, Finding], required_tools: Sequence[str]
) -> tuple[str, tuple[str, ...]]:
    selected = [by_id.get(f"profile.software.{tool}") for tool in required_tools]
    evidence = tuple(item.id for item in selected if item is not None)
    if not selected or any(item is None for item in selected):
        return "unknown", evidence

    statuses = [item.status for item in selected if item is not None]
    unavailable = {"not_detected", "permission_denied", "error", "unsupported", "not_checked"}
    if all(status in unavailable for status in statuses):
        return "unknown", evidence

    missing = statuses.count("not_detected")
    if missing >= 2:
        return "fail", evidence
    if missing == 1:
        return "warning", evidence
    if all(status == "detected" for status in statuses):
        return "pass", evidence
    return "unknown", evidence


def evaluate_readiness(
    findings: Sequence[Finding], profile: str | None = None
) -> dict[str, ReadinessDimension]:
    """Evaluate five independent dimensions for an optional named profile.

    Passing None means no profile was specified and leaves Resource and
    Software readiness unknown.
    """
    by_id = {item.id: item for item in findings if isinstance(item, Finding)}

    if profile is None:
        resource = _dimension(
            "resource_readiness", "unknown", "No profile specified.", _resource_evidence(findings)
        )
        software = _dimension(
            "software_readiness",
            "unknown",
            "No profile specified.",
            tuple(sorted(key for key in by_id if key.startswith("tool."))),
        )
    else:
        requirements = resolve_profile(profile)
        if profile == "standard":
            resource = _dimension(
                "resource_readiness",
                "unknown",
                "No workload resource baseline is defined, so CPU, RAM, and storage capacity cannot be assessed against requirements.",
                _resource_evidence(findings),
            )
            software = _dimension(
                "software_readiness",
                "unknown",
                "No mandatory software manifest is defined for the inventory-only profile.",
                tuple(sorted(key for key in by_id if key.startswith("tool."))),
            )
        else:
            status, evidence = _resource_status(by_id)
            resource = _dimension(
                "resource_readiness",
                status,
                (
                    "Host-facing CPU, RAM, and root-storage observations are retained for context, but effective process/container limits are not established; resource thresholds are not evaluated and readiness remains unknown."
                ),
                evidence or tuple(
                    key for key in by_id if key.startswith("profile.resource.")
                ),
            )
            status, evidence = _software_status(
                by_id, requirements["required_tools"]
            )
            software = _dimension(
                "software_readiness",
                status,
                "Compared PATH presence for required tools. Presence does not verify versions, configuration, security, or functionality.",
                evidence,
            )

    platform = by_id.get("compatibility.platform.linux")
    python = by_id.get("compatibility.python.minimum")
    compatibility_findings = (platform, python)
    compatibility_evidence = tuple(
        item.id for item in compatibility_findings if item is not None
    )
    explicit_failure = any(
        item is not None
        and (
            item.status in {"unsupported", "not_detected"}
            or (
                item.status == "detected"
                and isinstance(item.value, dict)
                and item.value.get("satisfied") is False
            )
        )
        for item in compatibility_findings
    )
    both_satisfied = all(
        item is not None
        and item.status == "detected"
        and isinstance(item.value, dict)
        and item.value.get("satisfied") is True
        for item in compatibility_findings
    )
    status = "fail" if explicit_failure else "pass" if both_satisfied else "unknown"
    compatibility = _dimension(
        "compatibility_readiness",
        status,
        "Linux platform and minimum Python compatibility are assessed from explicit runtime checks only.",
        compatibility_evidence,
    )

    privacy_ids = ("privacy.local_collection", "privacy.user_exclusions")
    privacy_evidence = tuple(key for key in privacy_ids if key in by_id)
    privacy_pass = all(
        key in by_id and by_id[key].status == "detected" for key in privacy_ids
    )
    privacy = _dimension(
        "privacy_readiness",
        "pass" if privacy_pass else "unknown",
        (
            "Describes AICRE's local collection and exclusion behavior only; it is not a host-wide privacy guarantee."
            if privacy_pass
            else "AICRE privacy-policy observations are incomplete; no host-wide privacy guarantee is inferred."
        ),
        privacy_evidence,
    )

    security_finding = by_id.get("security.effective_uid")
    security_evidence = (security_finding.id,) if security_finding else ()
    uid = _uid_value(security_finding.value) if security_finding else None
    if security_finding and security_finding.status == "detected" and uid == 0:
        security_status = "warning"
        explanation = (
            "AICRE is running as root (effective UID 0); other host security controls were not assessed."
        )
    elif security_finding and security_finding.status == "detected" and uid is not None:
        security_status = "unknown"
        explanation = (
            "The process effective UID is nonzero; other host security controls were not assessed."
        )
    else:
        security_status = "unknown"
        explanation = (
            "Effective UID is unavailable or malformed, and broader host security controls were not assessed."
        )
    security = _dimension(
        "security_readiness", security_status, explanation, security_evidence
    )

    return {
        "resource_readiness": resource,
        "software_readiness": software,
        "compatibility_readiness": compatibility,
        "privacy_readiness": privacy,
        "security_readiness": security,
    }
