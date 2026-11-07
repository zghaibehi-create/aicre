import hashlib
import json
import os
import socket
import stat
import subprocess
import sys
from pathlib import Path
from types import SimpleNamespace

import pytest

from aicre import scanner
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
    assert result["summary"]["complete"] is True
    assert result["summary"]["termination_reason"] is None
    data = json.loads(output.read_text(encoding="utf-8"))
    assert data["schema_version"] == "2"
    assert set(data) == {"schema_version", "aicre_version", "source_name", "generated_utc", "summary", "items"}
    file_record = next(item for item in data["items"] if item["relative_path"] == "nested/sample.txt")
    assert file_record["type"] == "file"
    assert file_record["extension"] == ".txt"
    assert file_record["size_bytes"] == len(secret_text.encode())
    assert file_record["modified_utc"].endswith("Z")
    assert secret_text not in output.read_text(encoding="utf-8")
    assert digest(target) == before_hash
    after_stat = target.stat()
    assert (after_stat.st_mtime_ns, after_stat.st_size, after_stat.st_mode, after_stat.st_ino) == (
        before_stat.st_mtime_ns, before_stat.st_size, before_stat.st_mode, before_stat.st_ino
    )


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


def test_sensitive_scan_root_is_rejected_before_traversal(tmp_path):
    source = tmp_path / ".ssh"
    source.mkdir()
    (source / "config").write_text("temporary fixture", encoding="utf-8")
    output = tmp_path / "report.json"

    with pytest.raises(ScanError, match="protected sensitive path"):
        scan_directory(source, output)
    assert not output.exists()


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


def test_force_atomically_replaces_regular_report_with_private_permissions(tmp_path):
    if os.name != "posix":
        pytest.skip("POSIX permission bits are only asserted on POSIX")
    source = tmp_path / "source"
    source.mkdir()
    output = tmp_path / "report.json"
    output.write_text("OLD", encoding="utf-8")
    output.chmod(0o644)

    scan_directory(source, output, force=True)

    assert json.loads(output.read_text(encoding="utf-8"))["items"] == []
    assert stat.S_IMODE(output.stat().st_mode) == 0o600
    assert not list(tmp_path.glob(".aicre-report-*"))


def test_new_report_uses_owner_only_posix_permissions(tmp_path):
    if os.name != "posix":
        pytest.skip("POSIX permission bits are only asserted on POSIX")
    source = tmp_path / "source"
    source.mkdir()
    output = tmp_path / "report.json"

    scan_directory(source, output)

    assert stat.S_IMODE(output.stat().st_mode) == 0o600


def test_force_refuses_hard_link_destination_without_modifying_peer(tmp_path):
    source = tmp_path / "source"
    source.mkdir()
    victim = tmp_path / "original.txt"
    victim.write_text("ORIGINAL-SENTINEL", encoding="utf-8")
    output = tmp_path / "report.json"
    try:
        os.link(victim, output)
    except (OSError, NotImplementedError):
        pytest.skip("Hard links are unavailable on this filesystem")
    before_inode = victim.stat().st_ino

    with pytest.raises(ScanError, match="multiple hard links"):
        scan_directory(source, output, force=True)

    assert victim.read_text(encoding="utf-8") == "ORIGINAL-SENTINEL"
    assert output.read_text(encoding="utf-8") == "ORIGINAL-SENTINEL"
    assert victim.stat().st_ino == before_inode == output.stat().st_ino


def test_hard_linked_source_names_are_inventory_paths_not_content_reads(tmp_path):
    source = tmp_path / "source"
    source.mkdir()
    first = source / "first.txt"
    second = source / "second.txt"
    first.write_text("SOURCE-SENTINEL", encoding="utf-8")
    try:
        os.link(first, second)
    except (OSError, NotImplementedError):
        pytest.skip("Hard links are unavailable on this filesystem")
    before = digest(first)

    report = scan_directory(source, tmp_path / "report.json")

    assert {item["relative_path"] for item in report["items"]} == {"first.txt", "second.txt"}
    assert "SOURCE-SENTINEL" not in (tmp_path / "report.json").read_text(encoding="utf-8")
    assert digest(first) == digest(second) == before


def test_force_report_write_failure_preserves_old_file_and_cleans_temporary(tmp_path, monkeypatch):
    source = tmp_path / "source"
    source.mkdir()
    output = tmp_path / "report.json"
    output.write_text("KEEP-OLD-REPORT", encoding="utf-8")

    def fail_after_partial_write(report, report_file, **kwargs):
        report_file.write("PARTIAL")
        raise OSError("injected write failure")

    monkeypatch.setattr(scanner.json, "dump", fail_after_partial_write)
    with pytest.raises(ScanError, match="injected write failure"):
        scan_directory(source, output, force=True)

    assert output.read_text(encoding="utf-8") == "KEEP-OLD-REPORT"
    assert not list(tmp_path.glob(".aicre-report-*"))


def test_failed_new_report_write_leaves_no_destination_or_temp(tmp_path, monkeypatch):
    source = tmp_path / "source"
    source.mkdir()
    output = tmp_path / "report.json"

    def fail_dump(report, report_file, **kwargs):
        report_file.write("PARTIAL")
        raise OSError("injected write failure")

    monkeypatch.setattr(scanner.json, "dump", fail_dump)
    with pytest.raises(ScanError, match="injected write failure"):
        scan_directory(source, output)

    assert not output.exists()
    assert not list(tmp_path.glob(".aicre-report-*"))


def test_racing_new_destination_is_not_overwritten(tmp_path, monkeypatch):
    source = tmp_path / "source"
    source.mkdir()
    output = tmp_path / "report.json"
    original_link = os.link

    def create_destination_then_link(src, dst, **kwargs):
        output.write_text("RACE-SENTINEL", encoding="utf-8")
        return original_link(src, dst, **kwargs)

    monkeypatch.setattr(scanner.os, "link", create_destination_then_link)
    with pytest.raises(ScanError, match="already exists"):
        scan_directory(source, output)
    assert output.read_text(encoding="utf-8") == "RACE-SENTINEL"
    assert not list(tmp_path.glob(".aicre-report-*"))


def test_force_replaces_symlink_race_without_touching_target(tmp_path, monkeypatch):
    source = tmp_path / "source"
    source.mkdir()
    output = tmp_path / "report.json"
    output.write_text("OLD-REPORT", encoding="utf-8")
    victim = tmp_path / "victim.txt"
    victim.write_text("KEEP-OUTSIDE-TARGET", encoding="utf-8")
    original_replace = os.replace
    installed = False

    def install_symlink_then_replace(src, dst, **kwargs):
        nonlocal installed
        if dst == output.name and not installed:
            installed = True
            output.unlink()
            output.symlink_to(victim)
        return original_replace(src, dst, **kwargs)

    monkeypatch.setattr(scanner.os, "replace", install_symlink_then_replace)
    scan_directory(source, output, force=True)

    assert installed
    assert not output.is_symlink()
    assert json.loads(output.read_text(encoding="utf-8"))["items"] == []
    assert victim.read_text(encoding="utf-8") == "KEEP-OUTSIDE-TARGET"


def test_report_parent_swap_does_not_redirect_atomic_replace(tmp_path, monkeypatch):
    source = tmp_path / "source"
    source.mkdir()
    report_dir = tmp_path / "reports"
    outside_dir = tmp_path / "outside"
    report_dir.mkdir()
    outside_dir.mkdir()
    output = report_dir / "report.json"
    output.write_text("OLD-REPORT", encoding="utf-8")
    outside_target = outside_dir / "report.json"
    outside_target.write_text("KEEP-OUTSIDE-TARGET", encoding="utf-8")
    original_replace = os.replace
    swapped = False

    def swap_parent_then_replace(src, dst, **kwargs):
        nonlocal swapped
        if dst == output.name and not swapped:
            swapped = True
            report_dir.rename(tmp_path / "reports-saved")
            report_dir.symlink_to(outside_dir, target_is_directory=True)
        return original_replace(src, dst, **kwargs)

    monkeypatch.setattr(scanner.os, "replace", swap_parent_then_replace)
    scan_directory(source, output, force=True)

    assert swapped
    assert outside_target.read_text(encoding="utf-8") == "KEEP-OUTSIDE-TARGET"
    saved_report = tmp_path / "reports-saved" / "report.json"
    assert json.loads(saved_report.read_text(encoding="utf-8"))["items"] == []


def test_refuses_special_report_destinations(tmp_path):
    source = tmp_path / "source"
    source.mkdir()
    directory = tmp_path / "report-dir"
    directory.mkdir()
    with pytest.raises(ScanError, match="regular file"):
        scan_directory(source, directory, force=True)

    socket_path = tmp_path / "report.sock"
    sock = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
    try:
        sock.bind(str(socket_path))
        with pytest.raises(ScanError, match="regular file"):
            scan_directory(source, socket_path, force=True)
    finally:
        sock.close()

    device = Path("/dev/null")
    if device.exists() and stat.S_ISCHR(device.stat().st_mode):
        with pytest.raises(ScanError, match="regular file"):
            scan_directory(source, device, force=True)


def test_block_device_report_destination_is_rejected(tmp_path, monkeypatch):
    source = tmp_path / "source"
    source.mkdir()
    destination = tmp_path / "simulated-block-device"
    block_stat = SimpleNamespace(
        st_mode=stat.S_IFBLK | 0o600, st_nlink=1, st_file_attributes=0
    )
    real_lstat = Path.lstat
    real_stat = os.stat

    def simulated_lstat(path):
        if path == destination:
            return block_stat
        return real_lstat(path)

    def simulated_stat(path, *args, **kwargs):
        if path == destination.name and kwargs.get("dir_fd") is not None:
            return block_stat
        return real_stat(path, *args, **kwargs)

    monkeypatch.setattr(Path, "lstat", simulated_lstat)
    monkeypatch.setattr(scanner.os, "stat", simulated_stat)
    with pytest.raises(ScanError, match="regular file"):
        scan_directory(source, destination, force=True)
    assert not destination.exists()


@pytest.mark.skipif(not hasattr(os, "mkfifo"), reason="FIFO creation requires POSIX")
def test_fifo_report_destination_is_rejected_without_blocking(tmp_path):
    source = tmp_path / "source"
    source.mkdir()
    fifo = tmp_path / "report.fifo"
    os.mkfifo(fifo)
    project_src = str(Path(__file__).resolve().parents[1] / "src")
    code = (
        "import sys\n"
        "from aicre.scanner import scan_directory, ScanError\n"
        "try:\n"
        "    scan_directory(sys.argv[1], sys.argv[2], force=True)\n"
        "except ScanError as exc:\n"
        "    print(exc)\n"
        "else:\n"
        "    raise SystemExit(1)\n"
    )
    env = os.environ.copy()
    env["PYTHONPATH"] = project_src + os.pathsep + env.get("PYTHONPATH", "")

    result = subprocess.run(
        [sys.executable, "-c", code, str(source), str(fifo)],
        capture_output=True, text=True, timeout=5, env=env, check=False,
    )
    assert result.returncode == 0
    assert "regular file" in result.stdout


def test_special_source_entries_are_excluded_without_opening(tmp_path):
    if not hasattr(os, "mkfifo"):
        pytest.skip("FIFO creation requires POSIX")
    source = tmp_path / "source"
    source.mkdir()
    os.mkfifo(source / "pipe")

    report = scan_directory(source, tmp_path / "report.json")

    assert report["items"] == []
    assert report["summary"]["excluded_items"] == 1


def test_entries_on_a_different_filesystem_are_excluded(tmp_path, monkeypatch):
    source = tmp_path / "source"
    source.mkdir()
    root_device = source.stat().st_dev
    real_scandir = os.scandir

    class FakeEntry:
        name = "mounted-volume"

        def stat(self, *, follow_symlinks=True):
            assert follow_symlinks is False
            return SimpleNamespace(
                st_mode=stat.S_IFDIR | 0o755,
                st_dev=root_device + 1,
                st_ino=123,
                st_mtime=0.0,
                st_file_attributes=0,
            )

    class FakeIterator:
        def __enter__(self):
            return self

        def __exit__(self, exc_type, exc, traceback):
            return False

        def __iter__(self):
            return iter([FakeEntry()])

    def fake_scandir(path):
        if isinstance(path, int):
            return FakeIterator()
        return real_scandir(path)

    monkeypatch.setattr(scanner.os, "scandir", fake_scandir)
    monkeypatch.setattr(scanner.os, "supports_fd", scanner.os.supports_fd | {fake_scandir})
    report = scan_directory(source, tmp_path / "report.json")

    assert report["items"] == []
    assert report["summary"]["excluded_items"] == 1


def test_permission_error_in_nested_directory_is_counted_and_scan_continues(tmp_path, monkeypatch):
    source = tmp_path / "source"
    blocked = source / "blocked"
    ordinary = source / "ordinary"
    blocked.mkdir(parents=True)
    ordinary.mkdir()
    (blocked / "hidden.txt").write_text("fixture", encoding="utf-8")
    (ordinary / "visible.txt").write_text("fixture", encoding="utf-8")
    real_open_directory = scanner._open_directory_beneath

    def controlled_open_directory(root_fd, relative, flags):
        if relative.as_posix() == "blocked":
            raise PermissionError("injected permission denial")
        return real_open_directory(root_fd, relative, flags)

    monkeypatch.setattr(scanner, "_open_directory_beneath", controlled_open_directory)
    report = scan_directory(source, tmp_path / "report.json")
    paths = {item["relative_path"] for item in report["items"]}

    assert report["summary"]["scan_errors"] == 1
    assert report["summary"]["complete"] is False
    assert report["summary"]["termination_reason"] == "filesystem_errors"
    assert "ordinary/visible.txt" in paths
    assert "blocked/hidden.txt" not in paths


def test_empty_tree_and_many_files_produce_valid_complete_json(tmp_path):
    source = tmp_path / "source"
    source.mkdir()
    for index in range(250):
        (source / f"item-{index:03}.txt").write_text("x", encoding="utf-8")

    report = scan_directory(source, tmp_path / "report.json")

    assert report["summary"]["included_items"] == 250
    assert len(json.loads((tmp_path / "report.json").read_text(encoding="utf-8"))["items"]) == 250
    names = [item["relative_path"] for item in report["items"]]
    assert names == sorted(names, key=str.casefold)


def test_cooperative_scan_timeout_marks_partial_inventory(tmp_path):
    source = tmp_path / "source"
    source.mkdir()
    (source / "not-yet-scanned.txt").write_text("fixture", encoding="utf-8")
    output = tmp_path / "report.json"

    report = scan_directory(source, output, timeout=0)

    assert report["aicre_version"] == "0.2.1"
    assert report["summary"]["included_items"] == 0
    assert report["summary"]["scan_errors"] == 0
    assert report["summary"]["complete"] is False
    assert report["summary"]["termination_reason"] == "timeout"
    saved = json.loads(output.read_text(encoding="utf-8"))
    assert saved["summary"]["complete"] is False
    assert saved["summary"]["termination_reason"] == "timeout"


def test_scan_rejects_invalid_timeout(tmp_path):
    source = tmp_path / "source"
    source.mkdir()
    with pytest.raises(ScanError, match="finite, non-negative"):
        scan_directory(source, tmp_path / "report.json", timeout=float("nan"))


def test_invalid_source_and_missing_output_parent_are_rejected(tmp_path):
    regular_file = tmp_path / "not-a-directory"
    regular_file.write_text("x", encoding="utf-8")
    with pytest.raises(ScanError, match="existing directory"):
        scan_directory(regular_file, tmp_path / "report.json")

    source = tmp_path / "source"
    source.mkdir()
    with pytest.raises(ScanError, match="parent directory does not exist"):
        scan_directory(source, tmp_path / "missing" / "report.json")


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


def test_directory_replaced_with_symlink_before_descent_is_not_followed(tmp_path, monkeypatch):
    source = tmp_path / "source"
    child = source / "child"
    outside = tmp_path / "outside"
    child.mkdir(parents=True)
    outside.mkdir()
    (child / "inside.txt").write_text("inside fixture", encoding="utf-8")
    (outside / "outside-secret.txt").write_text("outside fixture", encoding="utf-8")
    original_open = os.open
    swapped = False

    def replace_before_open(path, flags, *args, **kwargs):
        nonlocal swapped
        if path == "child" and "dir_fd" in kwargs and not swapped:
            swapped = True
            child.rename(source / "child.saved")
            child.symlink_to(outside, target_is_directory=True)
        return original_open(path, flags, *args, **kwargs)

    monkeypatch.setattr(scanner.os, "open", replace_before_open)
    monkeypatch.setattr(scanner.os, "supports_dir_fd", scanner.os.supports_dir_fd | {replace_before_open})
    report = scan_directory(source, tmp_path / "report.json")
    paths = {item["relative_path"] for item in report["items"]}

    assert swapped
    assert "child/outside-secret.txt" not in paths
    assert report["summary"]["scan_errors"] >= 1


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


def test_scanner_never_opens_source_files(tmp_path, monkeypatch):
    source = tmp_path / "source"
    source.mkdir()
    source_file = source / "opaque.bin"
    source_file.write_bytes(b"CONTENTS-MUST-NEVER-BE-OPENED")
    report_path = tmp_path / "report.json"
    opened_paths = []
    original_open = os.open

    def tracked_open(path, flags, *args, **kwargs):
        opened_paths.append((path, kwargs.get("dir_fd")))
        return original_open(path, flags, *args, **kwargs)

    monkeypatch.setattr(scanner.os, "open", tracked_open)
    monkeypatch.setattr(scanner.os, "supports_dir_fd", scanner.os.supports_dir_fd | {tracked_open})
    scan_directory(source, report_path)
    assert all(path != source_file and path != source_file.name for path, _ in opened_paths)
    assert report_path.exists()


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



def test_item_limit_writes_explicit_partial_report(tmp_path):
    source = tmp_path / "source"
    source.mkdir()
    for name in ("a.txt", "b.txt", "c.txt"):
        (source / name).write_text("fixture", encoding="utf-8")
    output = tmp_path / "report.json"

    report = scan_directory(source, output, max_items=2)

    assert report["schema_version"] == "2"
    assert report["summary"]["included_items"] == 2
    assert report["summary"]["complete"] is False
    assert report["summary"]["termination_reason"] == "item_limit"
    assert report["summary"]["scan_errors"] == 0
    assert len(report["items"]) == 2
    assert json.loads(output.read_text(encoding="utf-8")) == report


def test_item_limit_exact_boundary_can_still_be_complete(tmp_path):
    source = tmp_path / "source"
    source.mkdir()
    for name in ("a.txt", "b.txt"):
        (source / name).write_text("fixture", encoding="utf-8")

    report = scan_directory(source, tmp_path / "report.json", max_items=2)

    assert report["summary"]["included_items"] == 2
    assert report["summary"]["complete"] is True
    assert report["summary"]["termination_reason"] is None


def test_per_directory_entry_limit_bounds_sort_buffer_and_marks_partial(tmp_path):
    source = tmp_path / "source"
    source.mkdir()
    for name in ("a.txt", "b.txt", "c.txt"):
        (source / name).write_text("fixture", encoding="utf-8")
    output = tmp_path / "report.json"

    report = scan_directory(source, output, max_directory_entries=2)

    assert report["summary"]["included_items"] == 0
    assert report["summary"]["complete"] is False
    assert report["summary"]["termination_reason"] == "directory_entry_limit"
    assert report["summary"]["scan_errors"] == 0
    assert json.loads(output.read_text(encoding="utf-8")) == report


def test_per_directory_entry_limit_exact_boundary_can_complete(tmp_path):
    source = tmp_path / "source"
    source.mkdir()
    for name in ("a.txt", "b.txt"):
        (source / name).write_text("fixture", encoding="utf-8")

    report = scan_directory(source, tmp_path / "report.json", max_directory_entries=2)

    assert report["summary"]["included_items"] == 2
    assert report["summary"]["complete"] is True
    assert report["summary"]["termination_reason"] is None


@pytest.mark.parametrize(
    ("kwargs", "message"),
    [
        ({"max_items": 0}, "Maximum item count"),
        ({"max_items": True}, "Maximum item count"),
        ({"max_directory_entries": 0}, "Maximum directory entry count"),
        ({"max_directory_entries": False}, "Maximum directory entry count"),
    ],
)
def test_scan_rejects_invalid_cardinality_limits(tmp_path, kwargs, message):
    source = tmp_path / "source"
    source.mkdir()
    with pytest.raises(ScanError, match=message):
        scan_directory(source, tmp_path / "report.json", **kwargs)


def test_directory_scan_report_matches_published_schema(tmp_path):
    import fastjsonschema

    source = tmp_path / "source"
    source.mkdir()
    (source / "item.txt").write_text("fixture", encoding="utf-8")
    report = scan_directory(source, tmp_path / "report.json")
    schema_path = Path(__file__).resolve().parents[1] / "schemas" / "directory-scan-report-v2.schema.json"
    schema = json.loads(schema_path.read_text(encoding="utf-8"))

    fastjsonschema.validate(schema, report)
