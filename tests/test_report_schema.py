from __future__ import annotations

import json
from pathlib import Path

import fastjsonschema
import pytest

from aicre.report import build_report, serialize_report

SCHEMA_PATH = Path(__file__).resolve().parents[1] / "schemas" / "report-v2.schema.json"
SCHEMA = json.loads(SCHEMA_PATH.read_text(encoding="utf-8"))
VALIDATE_REPORT = fastjsonschema.compile(SCHEMA)


def test_generated_and_serialized_reports_validate_against_json_schema():
    report = build_report(timeout=5)

    assert VALIDATE_REPORT(report) == report
    decoded = json.loads(serialize_report(report))
    assert VALIDATE_REPORT(decoded) == decoded


def test_schema_rejects_missing_finding_fields_and_invalid_status():
    report = build_report(timeout=0)
    invalid = json.loads(serialize_report(report))
    invalid["findings"][0].pop("source")

    with pytest.raises(fastjsonschema.JsonSchemaException):
        VALIDATE_REPORT(invalid)

    invalid = json.loads(serialize_report(report))
    invalid["findings"][0]["status"] = "safe"
    with pytest.raises(fastjsonschema.JsonSchemaException):
        VALIDATE_REPORT(invalid)


def test_agent_development_report_validates_against_schema():
    report = build_report(profile="agent-development", timeout=0)
    assert VALIDATE_REPORT(report) == report



def test_every_emitted_report_has_findings_for_the_nonempty_schema_contract():
    for profile in ("standard", "agent-development", "laptop-dev", "agent-workstation", "ci-runner"):
        report = build_report(profile=profile, timeout=0)
        assert report["findings"]
        assert VALIDATE_REPORT(report) == report


def test_schema_accepts_patch_versions_and_new_profile_names():
    report = build_report(profile="laptop-dev", timeout=0)
    report["aicre_version"] = "0.2.1"
    report["profile"] = "future-profile-2"
    assert VALIDATE_REPORT(report) == report


def test_schema_rejects_empty_findings_array():
    report = build_report(timeout=0)
    report["findings"] = []
    with pytest.raises(fastjsonschema.JsonSchemaException):
        VALIDATE_REPORT(report)


def test_summary_document_is_an_unversioned_separate_contract():
    summary = {
        "derived_from": "report.json",
        "generated_at": "2026-11-07T00:00:00Z",
        "profile": "standard",
        "composite_score": None,
        "dimensions": {
            "resource": "unknown", "software": "unknown",
            "compatibility": "unknown", "privacy": "unknown", "security": "unknown",
        },
        "recommendations": [],
    }
    assert "schema_version" not in summary
    assert set(summary) == {
        "derived_from", "generated_at", "profile", "composite_score",
        "dimensions", "recommendations",
    }
