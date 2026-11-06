import json
import uuid
from pathlib import Path
import fastjsonschema
from aicre.schema import canonical_report, stable_finding_id

def source_report(timestamp):
    return {"schema_version":"2.0", "aicre_version":"0.2.0", "profile":"standard",
            "generated_at":timestamp, "findings":[{"id":"resource.cpu", "category":"resource",
            "status":"detected", "value":4, "unit":"count", "source":"cpu-collector",
            "confidence":"high", "collected_at":timestamp, "limitations":[]}], "readiness":{}}

def test_finding_id_is_sha256_of_normalized_evidence():
    value = stable_finding_id("collector", "check", {"b":2,"a":1})
    assert len(value) == 64
    assert value == stable_finding_id("collector", "check", {"a":1,"b":2})

def test_scan_id_is_deterministic_and_ignores_timestamps():
    first = canonical_report(source_report("2026-01-01T00:00:00Z"))
    second = canonical_report(source_report("2026-01-02T00:00:00Z"))
    assert first["scan_id"] == second["scan_id"]
    assert uuid.UUID(first["scan_id"]).version == 5
    assert first["findings"][0]["id"] == second["findings"][0]["id"]


def test_canonical_report_validates_against_v1_schema():
    schema = json.loads(Path('schemas/report-v1.schema.json').read_text(encoding='utf-8'))
    validate = fastjsonschema.compile(schema)
    report = canonical_report(source_report('2026-01-01T00:00:00Z'))
    assert validate(report) == report
