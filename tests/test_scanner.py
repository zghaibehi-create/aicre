import hashlib
import json
import os
import stat
from types import SimpleNamespace
from pathlib import Path

import pytest

from aicre.scanner import ScanError, _is_reparse_point, scan_directory


def digest(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def test_inventory_metadata_and_source_unchanged(tmp_path):
    source = tmp_path / "source"
    source.mkdir()
    nested = source / "nested"
    nested.mkdir()
    secret_text = "NEVER-EXPOSE-THIS-CONTENT"
    target = nested / "sample.txt"
    target.write_text(secret_text, encoding="utf-8")
    before_hash = digest(target)
    before_stat = target.stat()

    output = tmp_path / "report.json"
    result = scan_directory(source, output)

    assert result["summary"]["included_items"] == 2
    data = json.loads(output.read_text(encoding="utf-8"))
    file_record = next(item for item in data["items"] if item["relative_path"] == "nested/sample.txt")
    assert file_record["type"] == "file"
    assert file_record["extension"] == ".txt"
    assert file_record["size_bytes"] == len(secret_text.encode())
    assert file_record["modified_utc"].endswith("Z")
    assert secret_text not in output.read_text(encoding="utf-8")
    assert digest(target) == before_hash
    after_stat = target.stat()
    assert (after_stat.st_mtime_ns, after_stat.st_size) == (before_stat.st_mtime_ns, before_stat.st_size)


def test_sensitive_and_user_private_paths_excluded(tmp_path):
    source = tmp_path / "source"
    (source / ".ssh").mkdir(parents=True)
    (source / "Private").mkdir()
    (source / "ordinary").mkdir()
    (source / ".env").write_text("secret", encoding="utf-8")
    (source / ".ssh" / "id_ed25519").write_text("private", encoding="utf-8")
    (source / "Private" / "diary.txt").write_text("private", encoding="utf-8")
    (source / "ordinary" / "ok.txt").write_text("ok", encoding="utf-8")

    report = scan_directory(source, tmp_path / "report.json", excludes=("Private/**",))
    paths = {item["relative_path"] for item in report["items"]}
    assert "ordinary/ok.txt" in paths
    assert ".env" not in paths
    assert ".ssh" not in paths
    assert "Private" not in paths
    assert "Private/diary.txt" not in paths


def test_refuses_report_inside_source(tmp_path):
    source = tmp_path / "source"
    source.mkdir()
    with pytest.raises(ScanError, match="outside"):
        scan_directory(source, source / "report.json")


def test_refuses_overwrite_without_force(tmp_path):
    source = tmp_path / "source"
    source.mkdir()
    output = tmp_path / "report.json"
    output.write_text("KEEP", encoding="utf-8")
    with pytest.raises(ScanError, match="already exists"):
        scan_directory(source, output)
    assert output.read_text(encoding="utf-8") == "KEEP"


def test_force_replaces_existing_report(tmp_path):
    source = tmp_path / "source"
    source.mkdir()
    output = tmp_path / "report.json"
    output.write_text("OLD", encoding="utf-8")
    scan_directory(source, output, force=True)
    assert json.loads(output.read_text(encoding="utf-8"))["items"] == []


def test_symlink_is_not_followed(tmp_path):
    source = tmp_path / "source"
    outside = tmp_path / "outside"
    source.mkdir()
    outside.mkdir()
    (outside / "do-not-index.txt").write_text("outside", encoding="utf-8")
    link = source / "linked"
    try:
        link.symlink_to(outside, target_is_directory=True)
    except (OSError, NotImplementedError):
        pytest.skip("Symlink creation is unavailable in this environment")
    report = scan_directory(source, tmp_path / "report.json")
    assert all("do-not-index" not in item["relative_path"] for item in report["items"])
    assert report["summary"]["excluded_items"] == 1


def test_rejects_symlink_source(tmp_path):
    source = tmp_path / "source"
    source.mkdir()
    link = tmp_path / "source-link"
    try:
        link.symlink_to(source, target_is_directory=True)
    except (OSError, NotImplementedError):
        pytest.skip("Symlink creation is unavailable in this environment")
    with pytest.raises(ScanError, match="symbolic link"):
        scan_directory(link, tmp_path / "report.json")


def test_refuses_symlink_report_destination(tmp_path):
    source = tmp_path / "source"
    source.mkdir()
    target = tmp_path / "target.json"
    target.write_text("DO NOT TOUCH", encoding="utf-8")
    link = tmp_path / "report.json"
    try:
        link.symlink_to(target)
    except (OSError, NotImplementedError):
        pytest.skip("Symlink creation is unavailable in this environment")
    with pytest.raises(ScanError, match="must not be a symbolic link"):
        scan_directory(source, link, force=True)
    assert target.read_text(encoding="utf-8") == "DO NOT TOUCH"


def test_scanner_opens_only_the_report_for_writing(tmp_path, monkeypatch):
    source = tmp_path / "source"
    source.mkdir()
    source_file = source / "opaque.bin"
    source_file.write_bytes(b"CONTENTS-MUST-NEVER-BE-OPENED")
    report_path = tmp_path / "report.json"
    opened_paths = []
    original_open = Path.open

    def tracked_open(path, *args, **kwargs):
        opened_paths.append(path)
        return original_open(path, *args, **kwargs)

    monkeypatch.setattr(Path, "open", tracked_open)
    scan_directory(source, report_path)
    assert opened_paths == [report_path]


def test_detects_windows_reparse_point_attribute():
    assert _is_reparse_point(SimpleNamespace(st_file_attributes=0x400))
    assert not _is_reparse_point(SimpleNamespace(st_file_attributes=0))


def test_rejects_reparse_point_scan_root(tmp_path, monkeypatch):
    source = tmp_path / "source"
    source.mkdir()
    real_lstat = Path.lstat

    def fake_lstat(path):
        if path == source:
            return SimpleNamespace(st_mode=stat.S_IFDIR, st_file_attributes=0x400)
        return real_lstat(path)

    monkeypatch.setattr(Path, "lstat", fake_lstat)
    with pytest.raises(ScanError, match="reparse point"):
        scan_directory(source, tmp_path / "report.json")
