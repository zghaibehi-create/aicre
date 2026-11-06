"""Evidence-backed readiness assessments for AICRE 0.2."""
from __future__ import annotations

from collections.abc import Sequence
from typing import Any

from aicre.models import Finding, ReadinessDimension


def _dimension(
    name: str, status: str, explanation: str, evidence: Sequence[str] = ()
) -> ReadinessDimension:
    return ReadinessDimension(name, status, explanation, tuple(evidence))


def _resource_evidence(findings: Sequence[Finding]) -> tuple[str, ...]:
    terms = ("cpu", "ram", "memory", "storage", "disk")
    return tuple(
        finding.id
        for finding in findings
        if isinstance(finding, Finding)
        and any(term in f"{finding.id} {finding.category}".lower() for term in terms)
    )


def _uid_value(value: Any) -> int | None:
    if isinstance(value, int) and not isinstance(value, bool):
        return value
    if isinstance(value, dict):
        uid = value.get("effective_uid")
        if isinstance(uid, int) and not isinstance(uid, bool):
            return uid
    return None


def evaluate_readiness(findings: Sequence[Finding]) -> dict[str, ReadinessDimension]:
    """Evaluate five independent dimensions; no composite score is calculated."""
    by_id = {
        finding.id: finding
        for finding in findings
        if isinstance(finding, Finding)
    }

    resource_ids = _resource_evidence(findings)
    resource = _dimension(
        "resource_readiness",
        "unknown",
        "No workload resource baseline is defined, so CPU, RAM, and storage capacity cannot be assessed against requirements.",
        resource_ids,
    )

    tool_ids = tuple(sorted(key for key in by_id if key.startswith("tool.")))
    software = _dimension(
        "software_readiness",
        "unknown",
        "No mandatory software manifest is defined, so detected tools cannot be judged against required software.",
        tool_ids,
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
    compatibility_status = (
        "fail" if explicit_failure else "pass" if both_satisfied else "unknown"
    )
    compatibility = _dimension(
        "compatibility_readiness",
        compatibility_status,
        "Linux platform and minimum Python compatibility are assessed only from explicit detected requirement results.",
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
        "AICRE's local-only collection and path-exclusion policy are AICRE properties, not a host-wide privacy guarantee."
        if privacy_pass
        else "Local-only collection and path-exclusion findings are incomplete; these AICRE properties do not establish a host-wide privacy guarantee.",
        privacy_evidence,
    )

    security_finding = by_id.get("security.effective_uid")
    security_evidence = (security_finding.id,) if security_finding else ()
    uid = _uid_value(security_finding.value) if security_finding else None
    if security_finding and security_finding.status == "detected" and uid == 0:
        security_status = "warning"
        security_explanation = "The process is running as root (effective UID 0); other host security controls were not assessed."
    elif security_finding and security_finding.status == "detected" and uid is not None:
        security_status = "unknown"
        security_explanation = "The process effective UID is nonzero; other host security controls were not assessed."
    else:
        security_status = "unknown"
        security_explanation = "Effective UID is unavailable or malformed, and other host security controls were not assessed; no security guarantee is inferred."
    security = _dimension(
        "security_readiness", security_status, security_explanation, security_evidence
    )

    return {
        "resource_readiness": resource,
        "software_readiness": software,
        "compatibility_readiness": compatibility,
        "privacy_readiness": privacy,
        "security_readiness": security,
    }
