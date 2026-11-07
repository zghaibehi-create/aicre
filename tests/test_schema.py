import copy
import json
from pathlib import Path
import uuid

import fastjsonschema
import pytest

from aicre.schema import (
    ReportValidationError,
    canonical_report,
    stable_finding_id,
    validate_v1_report,
)


READINESS_KEYS = (
    "resource_readiness", "software_readiness", "compatibility_readiness",
    "privacy_readiness", "security_readiness",
)


def readiness(evidence=()):
    return {
        name: {"status": "unknown", "explanation": "Not assessed.", "evidence": list(evidence)}
        for name in READINESS_KEYS
    }


def source_report(timestamp):
    return {
        "schema_version": "2.0", "aicre_version": "0.2.0", "profile": "standard",
        "generated_at": timestamp,
        "findings": [{
            "id": "resource.cpu.logical_count", "category": "resource",
            "status": "detected", "value": 4, "unit": "count",
            "source": "cpu-collector", "confidence": "high",
            "collected_at": timestamp, "limitations": [],
        }],
        "readiness": readiness(["resource.cpu.logical_count"]),
    }


def test_finding_id_is_sha256_of_normalized_evidence():
    value = stable_finding_id("collector", "check", {"b": 2, "a": 1})
    assert len(value) == 64
    assert value == stable_finding_id("collector", "check", {"a": 1, "b": 2})


def test_scan_id_is_deterministic_and_ignores_timestamps():
    first = canonical_report(source_report("2026-01-01T00:00:00Z"))
    second = canonical_report(source_report("2026-01-02T00:00:00Z"))
    assert first["scan_id"] == second["scan_id"]
    assert uuid.UUID(first["scan_id"]).version == 5
    assert first["findings"][0]["id"] == second["findings"][0]["id"]


def test_canonical_report_validates_against_v1_schema():
    schema = json.loads(Path("schemas/report-v1.schema.json").read_text(encoding="utf-8"))
    validate = fastjsonschema.compile(schema)
    report = canonical_report(source_report("2026-01-01T00:00:00Z"))
    assert validate(report) == report


def test_v1_passthrough_is_deeply_validated():
    report = canonical_report(source_report("2026-01-01T00:00:00Z"))
    report["findings"][0]["status"] = "totally-safe"
    with pytest.raises(ReportValidationError):
        canonical_report(report)


def test_v1_rejects_duplicate_semantic_check_ids():
    report = canonical_report(source_report("2026-01-01T00:00:00Z"))
    duplicate = copy.deepcopy(report["findings"][0])
    duplicate["source"] = "another-collector"
    duplicate["id"] = stable_finding_id(
        duplicate["source"], duplicate["check_id"],
        {"status": duplicate["status"], "value": duplicate["value"], "unit": duplicate["unit"]},
    )
    report["findings"].append(duplicate)
    with pytest.raises(ReportValidationError, match="duplicate check_id"):
        validate_v1_report(report)


def test_v1_rejects_unknown_readiness_evidence():
    report = canonical_report(source_report("2026-01-01T00:00:00Z"))
    report["readiness"]["resource_readiness"]["evidence"] = ["not-a-finding"]
    with pytest.raises(ReportValidationError, match="unknown finding"):
        validate_v1_report(report)


def test_v1_rejects_malformed_uuid_and_forged_finding_digest():
    report = canonical_report(source_report("2026-01-01T00:00:00Z"))
    report["scan_id"] = str(uuid.uuid4())
    with pytest.raises(ReportValidationError, match="UUIDv5"):
        validate_v1_report(report)
    report = canonical_report(source_report("2026-01-01T00:00:00Z"))
    report["findings"][0]["id"] = "0" * 64
    with pytest.raises(ReportValidationError, match="does not match"):
        validate_v1_report(report)
