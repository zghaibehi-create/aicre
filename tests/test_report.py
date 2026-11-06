from __future__ import annotations

import json
import socket
import subprocess

import pytest

from aicre import report
from aicre.models import Finding


def _sample_finding(identifier: str, category: str = "system") -> Finding:
    return Finding(
        id=identifier,
        category=category,
        status="detected",
        value={"observed": True},
        source="unit-test fixture",
    )


def test_build_report_has_stable_top_level_shape_and_separate_dimensions(monkeypatch):
    monkeypatch.setattr(
        report, "collect_system_findings", lambda excludes, deadline: [_sample_finding("system.fixture")]
    )
    monkeypatch.setattr(
        report, "discover_tools", lambda excludes, deadline: [_sample_finding("tool.git", "software")]
    )
    monkeypatch.setattr(
        report,
        "evaluate_compatibility",
        lambda profile, deadline: [
            _sample_finding("compatibility.platform.linux", "compatibility"),
            _sample_finding("compatibility.python.minimum", "compatibility"),
        ],
    )

    result = report.build_report(excludes=("private/**",), timeout=10)

    assert set(result) == {
        "schema_version", "aicre_version", "profile", "generated_at", "findings", "readiness"
    }
    assert result["schema_version"] == "2.0"
    assert result["aicre_version"] == "0.2.0"
    assert result["profile"] == "standard"
    assert result["generated_at"].endswith("Z")
    assert set(result["readiness"]) == {
        "resource_readiness", "software_readiness", "compatibility_readiness",
        "privacy_readiness", "security_readiness",
    }
    assert "score" not in result
    by_id = {finding["id"]: finding for finding in result["findings"]}
    assert by_id["privacy.user_exclusions"]["value"]["patterns_supplied"] == 1
    privacy_values = by_id["privacy.local_collection"]["value"]
    assert privacy_values["user_document_contents_read"] is False
    assert privacy_values["credential_contents_read"] is False
    assert privacy_values["approved_metadata_sources_only"] is True
    assert result["readiness"]["privacy_readiness"]["status"] == "pass"
    assert result["readiness"]["resource_readiness"]["status"] == "unknown"


def test_timeout_zero_returns_valid_partial_findings_without_claiming_absence():
    result = report.build_report(timeout=0)
    findings = {item["id"]: item for item in result["findings"]}

    assert findings["system.os_release"]["status"] == "not_checked"
    assert findings["system.os_release"]["value"] is None
    assert findings["tool.git"]["status"] == "not_checked"
    assert findings["compatibility.platform.linux"]["status"] == "not_checked"
    assert result["readiness"]["compatibility_readiness"]["status"] == "unknown"


def test_report_collector_does_not_start_programs_or_network(monkeypatch):
    def forbidden(*_args, **_kwargs):
        raise AssertionError("external process/network activity is forbidden")

    monkeypatch.setattr(subprocess, "Popen", forbidden)
    monkeypatch.setattr(subprocess, "run", forbidden)
    monkeypatch.setattr(socket, "create_connection", forbidden)
    result = report.build_report(timeout=2, include_tools=False)

    assert result["schema_version"] == "2.0"
    assert all(item["id"].startswith("tool.") is False for item in result["findings"])


def test_invalid_profile_and_timeout_rejected():
    with pytest.raises(ValueError, match="unsupported profile"):
        report.build_report(profile="gpu")
    with pytest.raises(ValueError, match="finite"):
        report.build_report(timeout=float("nan"))
    with pytest.raises(ValueError, match="finite"):
        report.build_report(timeout=-1)


def test_serialized_report_is_json_with_newline():
    result = report.build_report(timeout=0)
    serialized = report.serialize_report(result)

    assert serialized.endswith("\n")
    assert json.loads(serialized) == result
