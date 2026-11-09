import copy

import pytest

from aicre.diff import compare_reports
from aicre.schema import canonical_report, stable_finding_id


def readiness():
    return {
        name: {"status": "unknown", "explanation": "Not assessed.", "evidence": []}
        for name in (
            "resource_readiness", "software_readiness", "compatibility_readiness",
            "privacy_readiness", "security_readiness",
        )
    }


def legacy_report(findings, timestamp="2026-01-01T00:00:00Z"):
    return {
        "schema_version": "2.0", "aicre_version": "0.2.0", "profile": "standard",
        "generated_at": timestamp, "findings": findings, "readiness": readiness(),
    }


def finding(identifier, value, status="detected"):
    return {
        "id": identifier, "category": "resource", "status": status, "value": value,
        "unit": "count", "source": "collector", "confidence": "high",
        "collected_at": "2026-01-01T00:00:00Z", "limitations": [],
    }


def test_diff_classifies_new_resolved_unchanged_and_changed():
    before = legacy_report([finding("cpu", 2), finding("old", 1)])
    after = legacy_report([finding("cpu", 4), finding("new", 3)])
    result = compare_reports(before, after)
    assert result["counts"] == {"new": 1, "resolved": 1, "unchanged": 0, "changed": 1}
    assert {item["change"] for item in result["changes"]} == {"new", "resolved", "changed"}


def test_diff_ignores_collection_timestamp():
    left, right = finding("cpu", 2), finding("cpu", 2)
    right["collected_at"] = "2026-01-02T00:00:00Z"
    result = compare_reports(legacy_report([left]), legacy_report([right]))
    assert result["changes"][0]["change"] == "unchanged"


def test_diff_rejects_duplicate_legacy_finding_ids():
    report = legacy_report([finding("cpu", 2), finding("cpu", 4)])
    with pytest.raises(ValueError, match="duplicate finding id"):
        compare_reports(report, report)


def test_diff_rejects_duplicate_canonical_check_ids():
    report = canonical_report(legacy_report([finding("cpu", 2)]))
    duplicate = copy.deepcopy(report["findings"][0])
    duplicate["source"] = "second-collector"
    duplicate["id"] = stable_finding_id(
        duplicate["source"], duplicate["check_id"],
        {"status": duplicate["status"], "value": duplicate["value"], "unit": duplicate["unit"]},
    )
    report["findings"].append(duplicate)
    with pytest.raises(ValueError, match="duplicate check_id"):
        compare_reports(report, report)
