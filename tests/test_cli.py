from __future__ import annotations

import json
import os
import stat

import pytest

from aicre.cli import main


def test_version_argument(capsys):
    with pytest.raises(SystemExit) as exit_info:
        main(["--version"])
    assert exit_info.value.code == 0
    assert capsys.readouterr().out.strip() == "aicre 0.2.1"


def test_scan_requires_output_argument(tmp_path):
    source = tmp_path / "source"
    source.mkdir()
    with pytest.raises(SystemExit) as exit_info:
        main(["scan", str(source)])
    assert exit_info.value.code == 2


def test_scan_requires_profile_when_source_is_omitted(capsys):
    with pytest.raises(SystemExit) as exit_info:
        main(["scan"])
    assert exit_info.value.code == 2
    assert "scan without SOURCE requires --profile" in capsys.readouterr().err


def test_legacy_directory_scan_success_and_user_exclusion(tmp_path, capsys):
    source = tmp_path / "source"
    (source / "private").mkdir(parents=True)
    (source / "private" / "item.txt").write_text("fixture", encoding="utf-8")
    (source / "public.txt").write_text("fixture", encoding="utf-8")
    output = tmp_path / "directory-report.json"

    result = main(["scan", str(source), "--output", str(output), "--exclude", "private/**"])

    assert result == 0
    assert "Inventory written" in capsys.readouterr().out
    paths = {item["relative_path"] for item in json.loads(output.read_text(encoding="utf-8"))["items"]}
    assert "public.txt" in paths
    assert "private/item.txt" not in paths


def test_partial_directory_scan_writes_report_and_returns_status_1(tmp_path, capsys):
    source = tmp_path / "source"
    source.mkdir()
    output = tmp_path / "partial-report.json"

    result = main([
        "scan", str(source), "--output", str(output), "--timeout", "0",
    ])

    assert result == 1
    assert "errors: 1" in capsys.readouterr().out
    report = json.loads(output.read_text(encoding="utf-8"))
    assert report["summary"]["scan_errors"] == 1


def test_cli_reports_scan_error_with_exit_code_2(tmp_path, capsys):
    source = tmp_path / "missing"
    output = tmp_path / "report.json"

    result = main(["scan", str(source), "--output", str(output)])

    assert result == 2
    assert "AICRE:" in capsys.readouterr().err
    assert not output.exists()


def test_cli_refuses_existing_scan_report_without_force(tmp_path, capsys):
    source = tmp_path / "source"
    source.mkdir()
    output = tmp_path / "report.json"
    output.write_text("KEEP", encoding="utf-8")

    result = main(["scan", str(source), "--output", str(output)])

    assert result == 2
    assert "already exists" in capsys.readouterr().err
    assert output.read_text(encoding="utf-8") == "KEEP"


def test_scan_standard_profile_command(capsys):
    result = main(["scan", "--profile", "standard", "--timeout", "0"])

    assert result == 0
    output = capsys.readouterr().out
    assert "AICRE 0.2.1" in output
    assert "Readiness (separate dimensions" in output


def test_system_json_command_emits_full_valid_report(capsys):
    result = main(["system", "--format", "json", "--timeout", "0"])

    assert result == 0
    data = json.loads(capsys.readouterr().out)
    assert data["schema_version"] == "2.0"
    assert data["aicre_version"] == "0.2.1"
    assert "resource.cpu.logical_count" in {item["id"] for item in data["findings"]}
    assert not any(item["id"].startswith("tool.") for item in data["findings"])


def test_inventory_and_readiness_commands(capsys, monkeypatch):
    report = {
        "aicre_version": "0.2.1",
        "profile": "standard",
        "findings": [{
            "id": "tool.git", "category": "software", "status": "detected",
            "value": "fixture", "source": "test", "confidence": "high",
            "unit": "", "limitations": [],
        }],
        "readiness": {
            name: {"status": "unknown", "explanation": "fixture", "evidence": []}
            for name in (
                "resource_readiness", "software_readiness", "compatibility_readiness",
                "privacy_readiness", "security_readiness",
            )
        },
    }

    def fake_build_report(*, profile, excludes, timeout, include_tools=True):
        assert profile == "standard"
        assert include_tools
        return report

    monkeypatch.setattr("aicre.cli.build_report", fake_build_report)
    assert main(["inventory", "--timeout", "0"]) == 0
    inventory_text = capsys.readouterr().out
    assert "tool.git" in inventory_text
    assert "Readiness" in inventory_text

    assert main(["readiness", "--timeout", "0"]) == 0
    readiness_text = capsys.readouterr().out
    assert "resource_readiness" in readiness_text
    assert "compatibility_readiness" in readiness_text


def test_report_json_stdout_and_schema_shape(capsys):
    result = main(["report", "--format", "json", "--timeout", "0"])

    assert result == 0
    data = json.loads(capsys.readouterr().out)
    assert set(data["readiness"]) == {
        "resource_readiness", "software_readiness", "compatibility_readiness",
        "privacy_readiness", "security_readiness",
    }


def test_report_file_uses_private_permissions_and_refuses_overwrite(tmp_path, capsys):
    output = tmp_path / "aicre-report.json"
    assert main(["report", "--output", str(output), "--timeout", "0"]) == 0
    capsys.readouterr()
    data = json.loads(output.read_text(encoding="utf-8"))
    assert data["schema_version"] == "2.0"
    if os.name == "posix":
        assert stat.S_IMODE(output.stat().st_mode) == 0o600

    assert main(["report", "--output", str(output), "--timeout", "0"]) == 2
    assert "already exists" in capsys.readouterr().err


def test_report_respects_user_exclusion_for_destination(tmp_path, capsys):
    private_dir = tmp_path / "private"
    private_dir.mkdir()
    output = private_dir / "report.json"
    result = main([
        "report", "--output", str(output), "--exclude", str(output.relative_to("/")),
        "--timeout", "0",
    ])

    assert result == 2
    assert "excluded by the privacy policy" in capsys.readouterr().err
    assert not output.exists()


def test_report_force_replaces_only_explicitly(tmp_path, capsys):
    output = tmp_path / "report.json"
    output.write_text("OLD", encoding="utf-8")

    assert main(["report", "--output", str(output), "--force", "--timeout", "0"]) == 0
    capsys.readouterr()
    assert json.loads(output.read_text(encoding="utf-8"))["schema_version"] == "2.0"


def test_exclusions_show_policy_and_non_persistence(capsys):
    assert main(["exclusions", "show"]) == 0
    text = capsys.readouterr().out
    assert ".ssh" in text
    assert ".env" in text
    assert "not persisted" in text


def test_invalid_timeout_has_usage_error():
    with pytest.raises(SystemExit) as exit_info:
        main(["inventory", "--timeout", "nan"])
    assert exit_info.value.code == 2


def test_agent_development_profile_cli_is_selectable(capsys):
    result = main(["readiness", "--profile", "agent-development", "--timeout", "0"])
    assert result == 0
    assert "agent-development" in capsys.readouterr().out


def test_report_accepts_agent_development_profile(capsys):
    result = main(["report", "--profile", "agent-development", "--timeout", "0"])
    assert result == 0
    data = json.loads(capsys.readouterr().out)
    assert data["profile"] == "agent-development"
    assert "profile.resource.cpu" in {item["id"] for item in data["findings"]}



@pytest.mark.parametrize("arguments", [
    ["scan", "--profile", "standard", "--force"],
    ["scan", "source", "--force"],
    ["report", "--force"],
])
def test_force_requires_an_output_destination(arguments, capsys):
    with pytest.raises(SystemExit) as exit_info:
        main(arguments)

    assert exit_info.value.code == 2
    assert "--force requires --output" in capsys.readouterr().err



def test_unknown_profile_is_a_usage_error_listing_available_profiles(capsys):
    with pytest.raises(SystemExit) as exit_info:
        main(["report", "--profile", "unknown"])
    assert exit_info.value.code == 2
    error = capsys.readouterr().err
    assert "laptop-dev" in error
    assert "agent-workstation" in error


def test_composite_requires_a_report_output_path():
    with pytest.raises(SystemExit) as exit_info:
        main(["report", "--composite"])
    assert exit_info.value.code == 2


def test_composite_writes_separate_summary_without_mutating_main_report(
    tmp_path, monkeypatch, capsys
):
    from aicre.report import serialize_report

    gib = 1024 ** 3
    report = {
        "schema_version": "2.0",
        "aicre_version": "0.2.1",
        "profile": "laptop-dev",
        "generated_at": "2026-11-07T00:00:00Z",
        "findings": [
            {
                "id": "profile.resource.cpu", "status": "detected",
                "value": {"actual": 1, "minimum": 4, "ratio": 0.25},
            },
            {
                "id": "profile.resource.memory", "status": "detected",
                "value": {"actual": 8 * gib, "minimum": 16 * gib, "ratio": 0.5},
            },
            {
                "id": "profile.resource.storage", "status": "detected",
                "value": {"actual": 30 * gib, "minimum": 20 * gib, "ratio": 1.5},
            },
            {
                "id": "profile.software.node", "status": "not_detected",
                "value": {"required_tool": "node"},
            },
            {
                "id": "compatibility.platform.linux", "status": "detected",
                "value": {"satisfied": True},
            },
            {
                "id": "compatibility.python.minimum", "status": "detected",
                "value": {"satisfied": True},
            },
            {"id": "security.effective_uid", "status": "detected", "value": 0},
        ],
        "readiness": {
            "resource_readiness": {"status": "fail", "explanation": "fixture", "evidence": []},
            "software_readiness": {"status": "warning", "explanation": "fixture", "evidence": []},
            "compatibility_readiness": {"status": "pass", "explanation": "fixture", "evidence": []},
            "privacy_readiness": {"status": "pass", "explanation": "fixture", "evidence": []},
            "security_readiness": {"status": "warning", "explanation": "fixture", "evidence": []},
        },
    }
    original = serialize_report(report)
    monkeypatch.setattr(
        "aicre.cli.build_report",
        lambda **kwargs: report,
    )
    output = tmp_path / "report.json"

    assert main([
        "report", "--profile", "laptop-dev", "--output", str(output), "--composite",
    ]) == 0
    capsys.readouterr()

    summary_path = tmp_path / "report.summary.json"
    saved_report = output.read_text(encoding="utf-8")
    summary = json.loads(summary_path.read_text(encoding="utf-8"))
    assert saved_report == original
    assert report == json.loads(original)
    assert summary["derived_from"] == "report.json"
    assert summary["profile"] == "laptop-dev"
    assert summary["composite_score"] == 46
    assert summary["dimensions"] == {
        "resource": "fail",
        "software": "warning",
        "compatibility": "pass",
        "privacy": "pass",
        "security": "warning",
    }
    assert len(summary["recommendations"]) == 3
    assert any("node" in item and "PATH" in item for item in summary["recommendations"])
    assert not any("Free at least" in item for item in summary["recommendations"])
    assert "schema_version" not in summary


def test_composite_summary_does_not_overwrite_existing_summary_without_force(
    tmp_path, monkeypatch, capsys
):
    monkeypatch.setattr(
        "aicre.cli.build_report",
        lambda **kwargs: {
            "schema_version": "2.0",
            "aicre_version": "0.2.1",
            "profile": "standard",
            "generated_at": "2026-11-07T00:00:00Z",
            "findings": [],
            "readiness": {
                name: {"status": "unknown", "explanation": "fixture", "evidence": []}
                for name in (
                    "resource_readiness", "software_readiness", "compatibility_readiness",
                    "privacy_readiness", "security_readiness",
                )
            },
        },
    )
    output = tmp_path / "report.json"
    summary = tmp_path / "report.summary.json"
    summary.write_text("KEEP", encoding="utf-8")

    assert main([
        "report", "--output", str(output), "--composite",
    ]) == 2
    assert summary.read_text(encoding="utf-8") == "KEEP"
    assert not output.exists()
    assert "Summary report already exists" in capsys.readouterr().err



def test_composite_score_is_null_when_every_dimension_is_unknown(
    tmp_path, monkeypatch, capsys
):
    report = {
        "schema_version": "2.0",
        "aicre_version": "0.2.1",
        "profile": "standard",
        "generated_at": "2026-11-07T00:00:00Z",
        "findings": [],
        "readiness": {
            name: {"status": "unknown", "explanation": "fixture", "evidence": []}
            for name in (
                "resource_readiness", "software_readiness", "compatibility_readiness",
                "privacy_readiness", "security_readiness",
            )
        },
    }
    monkeypatch.setattr("aicre.cli.build_report", lambda **kwargs: report)
    output = tmp_path / "report.json"
    assert main(["report", "--output", str(output), "--composite"]) == 0
    capsys.readouterr()
    summary = json.loads((tmp_path / "report.summary.json").read_text(encoding="utf-8"))
    assert summary["composite_score"] is None
    assert summary["recommendations"] == []
