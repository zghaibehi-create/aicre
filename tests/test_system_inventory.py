from __future__ import annotations

import errno
from pathlib import Path
from types import SimpleNamespace

import pytest

from aicre import system_inventory as inventory
from aicre.models import FINDING_STATUSES, Finding

EXPECTED_IDS = {
    "system.os_release",
    "system.kernel",
    "resource.cpu.logical_count",
    "resource.memory.total_bytes",
    "resource.memory.available_bytes",
    "resource.storage.root",
    "python.environment",
    "security.effective_uid",
    "resource.gpu",
}


def patch_normal(monkeypatch):
    monkeypatch.setattr(inventory.sys, "platform", "linux")
    monkeypatch.setattr(inventory.platform, "freedesktop_os_release",
                        lambda: {"ID": "testos", "NAME": "Test OS", "SECRET": "omit"})
    monkeypatch.setattr(inventory.platform, "uname",
                        lambda: SimpleNamespace(system="Linux", release="6.1", machine="x86_64"))
    monkeypatch.setattr(inventory.os, "cpu_count", lambda: 8)
    monkeypatch.setattr(inventory.shutil, "disk_usage",
                        lambda path: SimpleNamespace(total=1000, used=400, free=600))
    monkeypatch.setattr(inventory.os, "geteuid", lambda: 1234, raising=False)
    monkeypatch.setattr(inventory.time, "monotonic", lambda: 1.0)
    monkeypatch.setattr(inventory, "_drm_names", list)
    monkeypatch.setattr(inventory, "_meminfo", lambda path: {
        "MemTotal": 8 * 1024**3, "MemAvailable": 3 * 1024**3
    })


def by_id(findings):
    return {finding.id: finding for finding in findings}


def test_normal_inventory_model_shape_and_values(monkeypatch):
    patch_normal(monkeypatch)
    findings = inventory.collect_system_findings()
    mapped = by_id(findings)
    assert set(mapped) == EXPECTED_IDS
    assert all(isinstance(item, Finding) and item.status in FINDING_STATUSES for item in findings)
    assert mapped["system.os_release"].value == {"ID": "testos", "NAME": "Test OS"}
    assert mapped["system.kernel"].value == {"system": "Linux", "kernel": "6.1", "machine": "x86_64"}
    assert mapped["resource.cpu.logical_count"].value == 8
    assert mapped["resource.memory.total_bytes"].value == 8 * 1024**3
    assert mapped["resource.memory.available_bytes"].value == 3 * 1024**3
    assert mapped["resource.storage.root"].value == {
        "total_bytes": 1000, "used_bytes": 400, "free_bytes": 600
    }
    assert mapped["python.environment"].value["version"]
    assert "SECRET" not in repr(findings)
    for item in findings:
        assert item.collected_at.endswith("Z")
        item.to_dict()


@pytest.mark.parametrize(("exception", "status"), [
    (FileNotFoundError(errno.ENOENT, "missing"), "error"),
    (PermissionError(errno.EACCES, "denied"), "permission_denied"),
    (UnicodeDecodeError("ascii", b"\xff", 0, 1, "invalid"), "error"),
])
def test_proc_source_missing_or_permission_denied(monkeypatch, exception, status):
    patch_normal(monkeypatch)
    monkeypatch.setattr(inventory, "_meminfo", lambda path: (_ for _ in ()).throw(exception))
    mapped = by_id(inventory.collect_system_findings())
    assert mapped["resource.memory.total_bytes"].status == status
    assert mapped["resource.memory.total_bytes"].value is None
    assert mapped["resource.memory.available_bytes"].status == status


def test_exclusion_prevents_proc_read_and_path_disclosure(monkeypatch):
    patch_normal(monkeypatch)
    calls = []
    monkeypatch.setattr(inventory, "_meminfo", lambda path: calls.append(path) or {})
    findings = inventory.collect_system_findings(excludes=["proc/meminfo", "etc/os-release"])
    mapped = by_id(findings)
    assert calls == []
    for identifier in ("system.os_release", "resource.memory.total_bytes", "resource.memory.available_bytes"):
        item = mapped[identifier]
        assert item.status == "not_checked" and item.value is None
        assert "/etc/os-release" not in repr(item)
        assert "/proc/meminfo" not in repr(item)


def test_exclusion_prevents_root_storage_probe(monkeypatch):
    patch_normal(monkeypatch)
    calls = []
    monkeypatch.setattr(inventory.shutil, "disk_usage", lambda path: calls.append(path))

    item = by_id(inventory.collect_system_findings(excludes=["*"]))["resource.storage.root"]

    assert calls == []
    assert item.status == "not_checked"
    assert item.value is None
    assert "excluded root filesystem source" == item.source


def test_builtin_sensitive_exclusion_blocks_reads(monkeypatch):
    patch_normal(monkeypatch)
    monkeypatch.setattr(inventory, "_OS_RELEASE", "/home/private/.ssh/id_rsa")
    calls = []
    monkeypatch.setattr(inventory.platform, "freedesktop_os_release", lambda: calls.append(True) or {"ID": "x"})
    finding = by_id(inventory.collect_system_findings())["system.os_release"]
    assert calls == []
    assert finding.status == "not_checked" and finding.value is None
    assert "/home/private/.ssh/id_rsa" not in repr(finding)


def test_python_paths_filtered_by_policy(monkeypatch):
    patch_normal(monkeypatch)
    monkeypatch.setattr(inventory.sys, "executable", "/home/u/secret/python")
    monkeypatch.setattr(inventory.sys, "prefix", "/usr/local")
    monkeypatch.setattr(inventory.sys, "base_prefix", "/usr")
    item = by_id(inventory.collect_system_findings(excludes=["home/u/secret"]))["python.environment"]
    assert "executable" not in item.value
    assert item.value["prefix"] == "/usr/local"
    assert "/home/u/secret/python" not in repr(item)


def test_non_linux_marks_linux_observations_unsupported(monkeypatch):
    patch_normal(monkeypatch)
    monkeypatch.setattr(inventory.sys, "platform", "darwin")
    findings = by_id(inventory.collect_system_findings())
    for identifier in EXPECTED_IDS - {"python.environment", "security.effective_uid", "resource.gpu"}:
        assert findings[identifier].status == "unsupported"
        assert findings[identifier].value is None


def test_deadline_marks_uncollected_observations_not_checked(monkeypatch):
    patch_normal(monkeypatch)
    monkeypatch.setattr(inventory.time, "monotonic", lambda: 2.0)
    findings = inventory.collect_system_findings(deadline=1.0)
    mapped = by_id(findings)
    assert set(mapped) == EXPECTED_IDS
    for item in findings:
        if item.id != "resource.gpu":
            assert item.status == "not_checked"
            assert item.value is None
            assert any("deadline" in message.lower() for message in item.limitations)


def test_no_content_overreach_or_unapproved_file_reads(monkeypatch):
    patch_normal(monkeypatch)
    opened = []
    real_open = open

    def guarded_open(path, *args, **kwargs):
        opened.append(str(path))
        raise AssertionError("inventory must not read arbitrary paths")

    monkeypatch.setattr("builtins.open", guarded_open)
    monkeypatch.setattr(inventory, "_drm_names", list)
    monkeypatch.setattr(inventory, "_meminfo", lambda path: {
        "MemTotal": 4096, "MemAvailable": 2048
    })
    findings = inventory.collect_system_findings()
    assert opened == []
    assert "cpuinfo" not in repr(findings)
    assert "SECRET" not in repr(findings)
    assert real_open  # retained only to make explicit that tests do not alter real files


def test_optional_gpu_metadata_reads_only_two_sysfs_identifier_fields(monkeypatch):
    patch_normal(monkeypatch)
    monkeypatch.setattr(inventory, "_drm_names", lambda: ["card0", "card1"])
    reads = []

    def fake_read_text(path, *, encoding=None):
        reads.append(str(path))
        return {"vendor": "0x1234", "device": "0xabcd"}[Path(path).name]

    monkeypatch.setattr(Path, "read_text", fake_read_text)
    item = by_id(inventory.collect_system_findings())["resource.gpu"]

    assert item.status == "detected"
    assert item.value == {
        "devices": [
            {"vendor_id": "0x1234", "device_id": "0xabcd"},
            {"vendor_id": "0x1234", "device_id": "0xabcd"},
        ]
    }
    assert all(path.endswith(("/vendor", "/device")) for path in reads)
    assert len(reads) == 4


def test_gpu_user_exclusion_prevents_sysfs_read_and_path_disclosure(monkeypatch):
    patch_normal(monkeypatch)
    monkeypatch.setattr(inventory, "_drm_names", lambda: ["card0"])
    monkeypatch.setattr(
        "pathlib.Path.read_text",
        lambda *_args, **_kwargs: (_ for _ in ()).throw(AssertionError("excluded sysfs path was read")),
    )

    item = by_id(
        inventory.collect_system_findings(excludes=["sys/class/drm/card0/device/vendor"])
    )["resource.gpu"]

    assert item.status == "not_checked"
    assert item.value is None
    assert "/sys/class/drm" not in repr(item)
