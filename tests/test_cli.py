import json

import pytest

from aicre.cli import main


def test_version_argument(capsys):
    with pytest.raises(SystemExit) as exit_info:
        main(["--version"])
    assert exit_info.value.code == 0
    assert capsys.readouterr().out.strip() == "aicre 0.1.0"


def test_scan_requires_output_argument(tmp_path):
    source = tmp_path / "source"
    source.mkdir()
    with pytest.raises(SystemExit) as exit_info:
        main(["scan", str(source)])
    assert exit_info.value.code == 2


def test_cli_success_and_user_exclusion(tmp_path, capsys):
    source = tmp_path / "source"
    (source / "private").mkdir(parents=True)
    (source / "private" / "item.txt").write_text("fixture", encoding="utf-8")
    (source / "public.txt").write_text("fixture", encoding="utf-8")
    output = tmp_path / "report.json"

    result = main(["scan", str(source), "--output", str(output), "--exclude", "private/**"])

    assert result == 0
    assert "Inventory written" in capsys.readouterr().out
    paths = {item["relative_path"] for item in json.loads(output.read_text(encoding="utf-8"))["items"]}
    assert "public.txt" in paths
    assert "private/item.txt" not in paths


def test_cli_reports_scan_error_with_exit_code_2(tmp_path, capsys):
    source = tmp_path / "missing"
    output = tmp_path / "report.json"

    result = main(["scan", str(source), "--output", str(output)])

    assert result == 2
    assert "AICRE:" in capsys.readouterr().err
    assert not output.exists()


def test_cli_refuses_existing_report_without_force(tmp_path, capsys):
    source = tmp_path / "source"
    source.mkdir()
    output = tmp_path / "report.json"
    output.write_text("KEEP", encoding="utf-8")

    result = main(["scan", str(source), "--output", str(output)])

    assert result == 2
    assert "already exists" in capsys.readouterr().err
    assert output.read_text(encoding="utf-8") == "KEEP"
