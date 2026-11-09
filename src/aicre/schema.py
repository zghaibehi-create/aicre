from __future__ import annotations

import hashlib
import json
import re
import uuid
from datetime import datetime
from typing import Any

FINDING_STATUSES = {"detected", "not_detected", "unsupported", "permission_denied", "error", "not_checked"}
CONFIDENCE_LEVELS = {"high", "medium", "low"}
READINESS_STATUSES = {"pass", "warning", "fail", "unknown"}
READINESS_KEYS = {
    "resource_readiness", "software_readiness", "compatibility_readiness",
    "privacy_readiness", "security_readiness",
}
V1_TOP_LEVEL = {"schema_version", "aicre_version", "scan_id", "generated_at", "profile", "findings", "readiness"}
V1_FINDING_KEYS = {"id", "check_id", "category", "status", "value", "source", "confidence", "unit", "collected_at", "limitations"}
V2_TOP_LEVEL = {"schema_version", "aicre_version", "profile", "generated_at", "findings", "readiness"}
V2_FINDING_KEYS = {"id", "category", "status", "value", "unit", "source", "confidence", "collected_at", "limitations"}
DIMENSION_KEYS = {"status", "explanation", "evidence"}


class ReportValidationError(ValueError):
    """Raised when an imported or generated report violates its contract."""


def _canonical(value: Any) -> str:
    return json.dumps(value, ensure_ascii=False, sort_keys=True, separators=(",", ":"), allow_nan=False)


def stable_finding_id(collector_id: str, check_id: str, evidence: Any) -> str:
    material = "\\0".join((collector_id, check_id, _canonical(evidence)))
    return hashlib.sha256(material.encode("utf-8")).hexdigest()


def _timestamp(value: Any, field: str) -> None:
    if not isinstance(value, str) or not value:
        raise ReportValidationError(f"{field} must be an ISO-8601 timestamp")
    try:
        parsed = datetime.fromisoformat(value)
    except ValueError as exc:
        raise ReportValidationError(f"{field} must be an ISO-8601 timestamp") from exc
    if parsed.tzinfo is None or parsed.utcoffset() is None:
        raise ReportValidationError(f"{field} must include a timezone")


def _string(value: Any, field: str) -> None:
    if not isinstance(value, str) or not value.strip():
        raise ReportValidationError(f"{field} must be a non-empty string")


def _json_value(value: Any, field: str) -> None:
    try:
        json.dumps(value, ensure_ascii=False, allow_nan=False)
    except (TypeError, ValueError) as exc:
        raise ReportValidationError(f"{field} must be a finite JSON value") from exc


def _validate_readiness(value: Any, finding_ids: set[str]) -> None:
    if not isinstance(value, dict) or set(value) != READINESS_KEYS:
        raise ReportValidationError("readiness must contain exactly the five documented dimensions")
    for name, dimension in value.items():
        if not isinstance(dimension, dict) or set(dimension) != DIMENSION_KEYS:
            raise ReportValidationError(f"readiness.{name} has an invalid structure")
        if not isinstance(dimension["status"], str) or dimension["status"] not in READINESS_STATUSES:
            raise ReportValidationError(f"readiness.{name}.status is invalid")
        _string(dimension["explanation"], f"readiness.{name}.explanation")
        evidence = dimension["evidence"]
        if not isinstance(evidence, list) or any(not isinstance(item, str) or not item for item in evidence):
            raise ReportValidationError(f"readiness.{name}.evidence must be an array of non-empty finding IDs")
        if len(evidence) != len(set(evidence)) or any(item not in finding_ids for item in evidence):
            raise ReportValidationError(f"readiness.{name}.evidence contains duplicate or unknown finding IDs")


def validate_v1_report(report: Any) -> dict[str, Any]:
    if not isinstance(report, dict) or set(report) != V1_TOP_LEVEL:
        raise ReportValidationError("canonical report has missing or unknown top-level fields")
    if report["schema_version"] != "1.0.0":
        raise ReportValidationError("unsupported canonical report schema version")
    _string(report["aicre_version"], "aicre_version")
    _string(report["profile"], "profile")
    _timestamp(report["generated_at"], "generated_at")
    try:
        parsed_uuid = uuid.UUID(report["scan_id"])
    except (ValueError, TypeError, AttributeError) as exc:
        raise ReportValidationError("scan_id must be a UUIDv5") from exc
    if parsed_uuid.version != 5 or str(parsed_uuid) != report["scan_id"]:
        raise ReportValidationError("scan_id must be a canonical lowercase UUIDv5")
    findings = report["findings"]
    if not isinstance(findings, list):
        raise ReportValidationError("findings must be an array")
    finding_ids: set[str] = set()
    check_ids: set[str] = set()
    for index, item in enumerate(findings):
        prefix = f"findings[{index}]"
        if not isinstance(item, dict) or set(item) != V1_FINDING_KEYS:
            raise ReportValidationError(f"{prefix} has missing or unknown fields")
        for field in ("id", "check_id", "category", "source"):
            _string(item[field], f"{prefix}.{field}")
        if not re.fullmatch(r"[a-z0-9][a-z0-9._-]*", item["check_id"]):
            raise ReportValidationError(f"{prefix}.check_id is invalid")
        if any(ord(char) < 32 or ord(char) == 127 for char in item["source"]):
            raise ReportValidationError(f"{prefix}.source contains control characters")
        if not re.fullmatch(r"[a-f0-9]{64}", item["id"]):
            raise ReportValidationError(f"{prefix}.id must be a lowercase SHA-256 digest")
        if item["id"] in finding_ids:
            raise ReportValidationError(f"duplicate finding id: {item['id']}")
        if item["check_id"] in check_ids:
            raise ReportValidationError(f"duplicate check_id: {item['check_id']}")
        finding_ids.add(item["id"])
        check_ids.add(item["check_id"])
        if not isinstance(item["status"], str) or item["status"] not in FINDING_STATUSES:
            raise ReportValidationError(f"{prefix}.status is invalid")
        if not isinstance(item["confidence"], str) or item["confidence"] not in CONFIDENCE_LEVELS:
            raise ReportValidationError(f"{prefix}.confidence is invalid")
        if item["unit"] is not None and not isinstance(item["unit"], str):
            raise ReportValidationError(f"{prefix}.unit must be a string or null")
        _timestamp(item["collected_at"], f"{prefix}.collected_at")
        if not isinstance(item["limitations"], list) or any(not isinstance(x, str) for x in item["limitations"]):
            raise ReportValidationError(f"{prefix}.limitations must be an array of strings")
        _json_value(item["value"], f"{prefix}.value")
        expected_id = stable_finding_id(
            item["source"], item["check_id"],
            {"status": item["status"], "value": item["value"], "unit": item["unit"]},
        )
        if item["id"] != expected_id:
            raise ReportValidationError(f"{prefix}.id does not match its evidence")
    _validate_readiness(report["readiness"], finding_ids)
    return report


def validate_v2_report(report: Any) -> dict[str, Any]:
    if not isinstance(report, dict) or set(report) != V2_TOP_LEVEL:
        raise ReportValidationError("legacy report has missing or unknown top-level fields")
    if report["schema_version"] != "2.0":
        raise ReportValidationError("unsupported legacy report version")
    _string(report["aicre_version"], "aicre_version")
    _string(report["profile"], "profile")
    _timestamp(report["generated_at"], "generated_at")
    findings = report["findings"]
    if not isinstance(findings, list):
        raise ReportValidationError("findings must be an array")
    ids: set[str] = set()
    for index, item in enumerate(findings):
        prefix = f"findings[{index}]"
        if not isinstance(item, dict) or set(item) != V2_FINDING_KEYS:
            raise ReportValidationError(f"{prefix} has missing or unknown fields")
        for field in ("id", "category", "source"):
            _string(item[field], f"{prefix}.{field}")
        if not re.fullmatch(r"[a-z0-9][a-z0-9._-]*", item["id"]):
            raise ReportValidationError(f"{prefix}.id is invalid")
        if item["id"] in ids:
            raise ReportValidationError(f"duplicate finding id: {item['id']}")
        ids.add(item["id"])
        if not isinstance(item["status"], str) or item["status"] not in FINDING_STATUSES:
            raise ReportValidationError(f"{prefix}.status is invalid")
        if not isinstance(item["confidence"], str) or item["confidence"] not in CONFIDENCE_LEVELS:
            raise ReportValidationError(f"{prefix}.confidence is invalid")
        if item["unit"] is not None and not isinstance(item["unit"], str):
            raise ReportValidationError(f"{prefix}.unit must be a string or null")
        _timestamp(item["collected_at"], f"{prefix}.collected_at")
        if not isinstance(item["limitations"], list) or any(not isinstance(x, str) for x in item["limitations"]):
            raise ReportValidationError(f"{prefix}.limitations must be an array of strings")
        _json_value(item["value"], f"{prefix}.value")
    _validate_readiness(report["readiness"], ids)
    return report


def canonical_report(report: dict[str, Any]) -> dict[str, Any]:
    if not isinstance(report, dict):
        raise ReportValidationError("report must be a JSON object")
    version = report.get("schema_version")
    if version == "1.0.0":
        return validate_v1_report(report)
    if version != "2.0":
        raise ReportValidationError(f"unsupported report schema version: {version!r}")
    validate_v2_report(report)
    findings = []
    for item in report["findings"]:
        check_id = item["id"]
        collector_id = item["source"]
        evidence = {"status": item["status"], "value": item["value"], "unit": item["unit"]}
        findings.append({
            "id": stable_finding_id(collector_id, check_id, evidence),
            "check_id": check_id, "category": item["category"], "status": item["status"],
            "value": item["value"], "source": collector_id, "confidence": item["confidence"],
            "unit": item["unit"], "collected_at": item["collected_at"],
            "limitations": list(item["limitations"]),
        })
    findings.sort(key=lambda item: item["check_id"])
    stable_rows = sorted(
        ({key: item.get(key) for key in (
            "id", "check_id", "category", "status", "value", "source", "confidence", "unit", "limitations"
        )} for item in findings),
        key=lambda item: item["check_id"],
    )
    seed = _canonical({"profile": report["profile"], "findings": stable_rows})
    scan_id = str(uuid.uuid5(uuid.NAMESPACE_URL, "urn:aicre:scan:" + seed))
    id_map = {item["check_id"]: item["id"] for item in findings}
    readiness = {
        name: {
            "status": dimension["status"],
            "explanation": dimension["explanation"],
            "evidence": [id_map[item] for item in dimension["evidence"]],
        }
        for name, dimension in report["readiness"].items()
    }
    result = {
        "schema_version": "1.0.0", "aicre_version": report["aicre_version"],
        "scan_id": scan_id, "generated_at": report["generated_at"],
        "profile": report["profile"], "findings": findings, "readiness": readiness,
    }
    return validate_v1_report(result)
