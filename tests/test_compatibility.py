from __future__ import annotations

import time

import pytest

from aicre.compatibility import evaluate_compatibility


def test_linux_and_supported_python_are_detected() -> None:
    findings = evaluate_compatibility(system="Linux", python_version=(3, 11, 0))

    assert [finding.id for finding in findings] == [
        "compatibility.platform.linux",
        "compatibility.python.minimum",
    ]
    assert [finding.status for finding in findings] == ["detected", "detected"]
    assert findings[0].value == {"actual": "Linux", "required": "Linux", "satisfied": True}
    assert findings[1].value == {"actual": "3.11.0", "required": ">=3.11", "satisfied": True}


def test_incompatible_os_is_unsupported() -> None:
    findings = evaluate_compatibility(system="Darwin", python_version=(3, 12, 1))

    assert findings[0].status == "unsupported"
    assert findings[0].value == {"actual": "Darwin", "required": "Linux", "satisfied": False}


def test_python_below_minimum_is_not_detected() -> None:
    findings = evaluate_compatibility(system="Linux", python_version=(3, 10, 9))

    assert findings[1].status == "not_detected"
    assert findings[1].value == {"actual": "3.10.9", "required": ">=3.11", "satisfied": False}


def test_invalid_profile_raises_value_error() -> None:
    with pytest.raises(ValueError, match="unsupported compatibility profile"):
        evaluate_compatibility("gpu")


def test_expired_deadline_returns_two_unchecked_findings() -> None:
    findings = evaluate_compatibility(
        system="Linux", python_version=(3, 12, 0), deadline=time.monotonic() - 1
    )

    assert len(findings) == 2
    assert [finding.status for finding in findings] == ["not_checked", "not_checked"]
    assert [finding.value for finding in findings] == [None, None]
    assert all(finding.limitations for finding in findings)


def test_stable_json_shapes_and_named_sources() -> None:
    findings = evaluate_compatibility(system="Linux", python_version=(3, 12, 2))
    serialized = [finding.to_dict() for finding in findings]

    assert set(serialized[0]) == {
        "id", "category", "status", "value", "unit", "source", "confidence",
        "collected_at", "limitations",
    }
    assert set(serialized[0]["value"]) == {"actual", "required", "satisfied"}
    assert set(serialized[1]["value"]) == {"actual", "required", "satisfied"}
    assert [item["source"] for item in serialized] == ["platform.system()", "sys.version_info"]
    assert all(item["confidence"] == "high" for item in serialized)
