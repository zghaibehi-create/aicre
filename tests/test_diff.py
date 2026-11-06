from aicre.diff import compare_reports


def finding(value, status="detected"):
    return {"id": "sha", "check_id": "cpu.logical", "category": "resource", "status": status,
            "value": value, "unit": "count", "source": "collector", "confidence": "high", "limitations": []}

def test_diff_classifies_new_resolved_unchanged_and_changed():
    before = {"scan_id": "before", "findings": [finding(2), {"id":"gone","check_id":"old","value":1}]}
    after = {"scan_id": "after", "findings": [finding(4), {"id":"new","check_id":"new","value":3}]}
    result = compare_reports(before, after)
    assert result["counts"] == {"new": 1, "resolved": 1, "unchanged": 0, "changed": 1}
    assert {item["change"] for item in result["changes"]} == {"new", "resolved", "changed"}

def test_diff_ignores_collection_timestamp():
    left, right = finding(2), finding(2)
    left["collected_at"], right["collected_at"] = "2026-01-01T00:00:00Z", "2026-01-02T00:00:00Z"
    result = compare_reports({"findings":[left]}, {"findings":[right]})
    assert result["changes"][0]["change"] == "unchanged"
