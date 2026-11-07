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
    assert capsys.readouterr().out.strip() == "aicre 0.3.0"


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
    output_text = capsys.readouterr().out
    assert "complete: no" in output_text
    assert "termination: timeout" in output_text
    report = json.loads(output.read_text(encoding="utf-8"))
    assert report["summary"]["scan_errors"] == 0
    assert report["summary"]["termination_reason"] == "timeout"


def test_cli_exposes_item_and_directory_entry_limits(tmp_path, capsys):
    source = tmp_path / "source"
    source.mkdir()
    for name in ("a.txt", "b.txt", "c.txt"):
        (source / name).write_text("fixture", encoding="utf-8")
    output = tmp_path / "limited-report.json"

    result = main([
        "scan", str(source), "--output", str(output),
        "--max-items", "2", "--max-directory-entries", "10",
    ])

    assert result == 1
    output_text = capsys.readouterr().out
    assert "complete: no" in output_text
    assert "termination: item_limit" in output_text
    report = json.loads(output.read_text(encoding="utf-8"))
    assert report["summary"]["included_items"] == 2
    assert report["summary"]["termination_reason"] == "item_limit"


def test_cli_reports_directory_entry_limit_separately(tmp_path, capsys):
    source = tmp_path / "source"
    source.mkdir()
    for name in ("a.txt", "b.txt", "c.txt"):
        (source / name).write_text("fixture", encoding="utf-8")
    output = tmp_path / "directory-limited-report.json"

    result = main([
        "scan", str(source), "--output", str(output),
        "--max-items", "10", "--max-directory-entries", "2",
    ])

    assert result == 1
    output_text = capsys.readouterr().out
    assert "termination: directory_entry_limit" in output_text
    report = json.loads(output.read_text(encoding="utf-8"))
    assert report["summary"]["complete"] is False
    assert report["summary"]["scan_errors"] == 0


def test_cli_rejects_non_positive_scan_limits():
    with pytest.raises(SystemExit) as exit_info:
        main(["scan", "source", "--output", "report.json", "--max-items", "0"])
    assert exit_info.value.code == 2


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
    assert "AICRE 0.3.0" in output
    assert "Readiness (separate dimensions" in output


def test_system_json_command_emits_full_valid_report(capsys):
    result = main(["system", "--format", "json", "--timeout", "0"])

    assert result == 0
    data = json.loads(capsys.readouterr().out)
    assert data["schema_version"] == "2.0"
    assert data["aicre_version"] == "0.3.0"
    assert "resource.cpu.logical_count" in {item["id"] for item in data["findings"]}
    assert not any(item["id"].startswith("tool.") for item in data["findings"])


def test_inventory_and_readiness_commands(capsys, monkeypatch):
    report = {
        "aicre_version": "0.3.0",
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
        assert profile is None
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

def test_cli_without_profile_uses_standard_label_but_explains_unknown_readiness(capsys):
    assert main(["readiness", "--timeout", "0"]) == 0
    output = capsys.readouterr().out
    assert "AICRE 0.3.0 — profile: standard" in output
    assert output.count("No profile specified.") == 2


def test_agent_development_readiness_shows_existing_values_and_unknown_footer(capsys, monkeypatch):
    gib = 1024 ** 3
    report = {
        "aicre_version": "0.3.0",
        "profile": "agent-development",
        "findings": [
            {"id": "profile.resource.cpu", "value": {"actual": 4, "minimum": 2}},
            {"id": "profile.resource.memory", "value": {"actual": int(15.6 * gib), "minimum": 8 * gib}},
            {"id": "profile.resource.storage", "value": {"actual": 80 * gib, "minimum": 10 * gib}},
            {"id": "profile.software.git", "status": "detected"},
            {"id": "profile.software.python3", "status": "detected"},
        ],
        "readiness": {
            name: {"status": "unknown", "explanation": "fixture", "evidence": []}
            for name in (
                "resource_readiness", "software_readiness", "compatibility_readiness",
                "privacy_readiness", "security_readiness",
            )
        },
    }

    def fake_build_report(*, profile, excludes, timeout, include_tools=True):
        assert profile == "agent-development"
        return report

    monkeypatch.setattr("aicre.cli.build_report", fake_build_report)

    assert main(["readiness", "--profile", "agent-development"]) == 0
    output = capsys.readouterr().out
    assert "CPU: 4 (min 2 logical CPUs)" in output
    assert "RAM: 15.6 GiB (min 8.0 GiB)" in output
    assert "Free disk: 80.0 GiB (min 10.0 GiB)" in output
    assert "git: detected" in output
    assert "python3: detected" in output
    assert "unknown means not assessed, not failed" in output


def test_agent_development_readiness_handles_missing_observations(capsys, monkeypatch):
    report = {
        "aicre_version": "0.3.0",
        "profile": "agent-development",
        "findings": [],
        "readiness": {
            name: {"status": "unknown", "explanation": "fixture", "evidence": []}
            for name in (
                "resource_readiness", "software_readiness", "compatibility_readiness",
                "privacy_readiness", "security_readiness",
            )
        },
    }

    monkeypatch.setattr(
        "aicre.cli.build_report",
        lambda **kwargs: report,
    )

    assert main(["readiness", "--profile", "agent-development"]) == 0
    output = capsys.readouterr().out
    assert "CPU: not available (min None logical CPUs)" in output
    assert "RAM: not available (min not available)" in output
    assert "git: not checked" in output
