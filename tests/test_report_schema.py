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
