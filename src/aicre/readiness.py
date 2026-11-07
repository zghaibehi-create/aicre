"""Evidence-backed readiness assessments for AICRE."""
from __future__ import annotations

from collections.abc import Sequence
from typing import Any

from aicre.models import Finding, ReadinessDimension
from aicre.workload_profiles import PROFILES

def _dimension(name: str, status: str, explanation: str, evidence: Sequence[str] = ()) -> ReadinessDimension:
    return ReadinessDimension(name, status, explanation, tuple(evidence))

def _uid_value(value: Any) -> int | None:
    if isinstance(value, int) and not isinstance(value, bool):
        return value
    if isinstance(value, dict):
        uid = value.get("effective_uid")
        if isinstance(uid, int) and not isinstance(uid, bool):
            return uid
    return None

def _profile_status(by_id: dict[str, Finding], prefix: str, expected: Sequence[str]) -> tuple[str, tuple[str, ...]]:
    selected = [by_id.get(f"{prefix}.{name}") for name in expected]
    evidence = tuple(item.id for item in selected if item is not None)
    if any(item is not None and isinstance(item.value, dict) and item.value.get("satisfied") is False for item in selected):
        return "fail", evidence
    if all(item is not None and item.status == "detected" and isinstance(item.value, dict)
           and item.value.get("satisfied") is True for item in selected):
        return "pass", evidence
    return "unknown", evidence

def evaluate_readiness(findings: Sequence[Finding], profile: str = "standard") -> dict[str, ReadinessDimension]:
    """Evaluate five independent readiness dimensions for a named profile."""
    if profile not in PROFILES:
        raise ValueError(f"unsupported profile: {profile}")
    by_id = {item.id: item for item in findings if isinstance(item, Finding)}
    resource_ids = tuple(key for key in by_id if key.startswith(("resource.", "profile.resource.")))
    if profile == "standard":
        resource = _dimension("resource_readiness", "unknown",
            "No workload baseline is defined; CPU, RAM, and storage observations are informational only.", resource_ids)
        software = _dimension("software_readiness", "unknown",
            "No mandatory software manifest is defined for the inventory-only profile.",
            tuple(sorted(key for key in by_id if key.startswith("tool."))))
    else:
        status, evidence = _profile_status(by_id, "profile.resource", ("cpu", "memory", "storage"))
        resource = _dimension("resource_readiness", status,
            "Compared CPU count, total RAM, and free root-filesystem storage with documented agent-development minimums. This is not a performance guarantee.",
            evidence or resource_ids)
        status, evidence = _profile_status(by_id, "profile.software", tuple(PROFILES[profile]["required_tools"]))
        software = _dimension("software_readiness", status,
            "Compared allowlisted PATH presence for required tools. Presence does not verify versions, configuration, security, or functionality.", evidence)

    platform = by_id.get("compatibility.platform.linux")
    python = by_id.get("compatibility.python.minimum")
    compatibility_findings = (platform, python)
    compatibility_evidence = tuple(item.id for item in compatibility_findings if item is not None)
    explicit_failure = any(item is not None and (
        item.status in {"unsupported", "not_detected"} or
        (item.status == "detected" and isinstance(item.value, dict) and item.value.get("satisfied") is False)
    ) for item in compatibility_findings)
    both_satisfied = all(item is not None and item.status == "detected" and
        isinstance(item.value, dict) and item.value.get("satisfied") is True for item in compatibility_findings)
    status = "fail" if explicit_failure else "pass" if both_satisfied else "unknown"
    compatibility = _dimension("compatibility_readiness", status,
        "Linux platform and minimum Python compatibility are assessed from explicit runtime checks only.", compatibility_evidence)

    privacy_ids = ("privacy.local_collection", "privacy.user_exclusions")
    privacy_evidence = tuple(key for key in privacy_ids if key in by_id)
    privacy_pass = all(key in by_id and by_id[key].status == "detected" for key in privacy_ids)
    privacy = _dimension("privacy_readiness", "pass" if privacy_pass else "unknown",
        "Describes AICRE's local collection and exclusion behavior only; it is not a host-wide privacy guarantee."
        if privacy_pass else "AICRE privacy-policy observations are incomplete; no host-wide privacy guarantee is inferred.", privacy_evidence)

    security_finding = by_id.get("security.effective_uid")
    security_evidence = (security_finding.id,) if security_finding else ()
    uid = _uid_value(security_finding.value) if security_finding else None
    if security_finding and security_finding.status == "detected" and uid == 0:
        security_status, explanation = "warning", "AICRE is running as root (effective UID 0); other host security controls were not assessed."
    elif security_finding and security_finding.status == "detected" and uid is not None:
        security_status, explanation = "unknown", "The process effective UID is nonzero; other host security controls were not assessed."
    else:
        security_status, explanation = "unknown", "Effective UID is unavailable or malformed, and broader host security controls were not assessed."
    security = _dimension("security_readiness", security_status, explanation, security_evidence)
    return {"resource_readiness": resource, "software_readiness": software,
            "compatibility_readiness": compatibility, "privacy_readiness": privacy,
            "security_readiness": security}
