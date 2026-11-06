from __future__ import annotations

import time

import pytest

from aicre import tool_discovery
from aicre.models import Finding


def test_emits_one_finding_per_allowlisted_tool_and_only_looks_up_allowlist(monkeypatch):
    calls = []

    def fake_which(name, *, path):
        calls.append((name, path))
        return f"/usr/bin/{name}"

    monkeypatch.setenv("PATH", "/usr/bin")
    monkeypatch.setattr(tool_discovery.shutil, "which", fake_which)
    findings = tool_discovery.discover_tools()

    assert [name for name, _ in calls] == list(tool_discovery.TOOL_NAMES)
    assert all(path == "/usr/bin" for _, path in calls)
    assert len(findings) == len(tool_discovery.TOOL_NAMES)
    assert {finding.id for finding in findings} == {
        f"tool.{name}" for name in tool_discovery.TOOL_NAMES
    }
    assert all(isinstance(finding, Finding) for finding in findings)
    for finding, name in zip(findings, tool_discovery.TOOL_NAMES):
        assert finding.category == "software"
        assert finding.status == "detected"
        assert finding.value == f"/usr/bin/{name}"
        assert finding.source == f"shutil.which({name})"
        assert "not verified" in finding.limitations[0]


def test_missing_tools_are_not_detected(monkeypatch):
    monkeypatch.setenv("PATH", "/usr/bin")
    monkeypatch.setattr(tool_discovery.shutil, "which", lambda _name, *, path: None)

    findings = tool_discovery.discover_tools()

    assert len(findings) == len(tool_discovery.TOOL_NAMES)
    assert all(finding.status == "not_detected" for finding in findings)
    assert all(finding.value is None for finding in findings)
    assert all("may be installed elsewhere" in finding.limitations[0] for finding in findings)


def test_non_linux_marks_tools_unsupported_without_path_lookup(monkeypatch):
    calls = []
    monkeypatch.setattr(tool_discovery.sys, "platform", "darwin")
    monkeypatch.setattr(
        tool_discovery.shutil, "which", lambda *_args, **_kwargs: calls.append(True)
    )

    findings = tool_discovery.discover_tools()

    assert calls == []
    assert len(findings) == len(tool_discovery.TOOL_NAMES)
    assert all(finding.status == "unsupported" for finding in findings)
    assert all(finding.value is None for finding in findings)


def test_sensitive_executable_paths_are_withheld(monkeypatch):
    sensitive_path = "/home/testuser/.ssh/secret-tool"
    monkeypatch.setenv("PATH", "/usr/bin")
    monkeypatch.setattr(
        tool_discovery.shutil, "which", lambda _name, *, path: sensitive_path
    )

    findings = tool_discovery.discover_tools()

    assert all(finding.status == "not_checked" for finding in findings)
    assert all(finding.value is None for finding in findings)
    assert all(finding.source == "shutil.which (path withheld)" for finding in findings)
    assert all(
        finding.limitations == ("protected by the built-in sensitive-path policy",)
        for finding in findings
    )
    assert all(sensitive_path not in repr(finding.to_dict()) for finding in findings)


def test_user_excluded_executable_paths_are_withheld(monkeypatch, tmp_path):
    executable = tmp_path / "private-bin" / "custom-tool"
    monkeypatch.setenv("PATH", "/usr/bin")
    monkeypatch.setattr(
        tool_discovery.shutil, "which", lambda _name, *, path: str(executable)
    )
    pattern = str(executable.relative_to("/"))

    findings = tool_discovery.discover_tools(excludes=(pattern,))

    assert all(finding.status == "not_checked" for finding in findings)
    assert all(finding.value is None for finding in findings)
    assert all(finding.source == "shutil.which (path withheld)" for finding in findings)
    assert all(
        finding.limitations == ("excluded by a user-supplied path pattern",)
        for finding in findings
    )
    assert all(str(executable) not in repr(finding.to_dict()) for finding in findings)


def test_excluded_path_entries_are_removed_before_which(monkeypatch):
    calls = []
    monkeypatch.setenv("PATH", "/home/testuser/.ssh:/usr/bin")

    def fake_which(name, *, path):
        calls.append(path)
        assert "/home/testuser/.ssh" not in path

    monkeypatch.setattr(tool_discovery.shutil, "which", fake_which)
    findings = tool_discovery.discover_tools()

    assert calls and all(path == "/usr/bin" for path in calls)
    assert all(finding.status == "not_checked" for finding in findings)
    assert all(finding.value is None for finding in findings)
    assert all(".ssh" not in repr(finding.to_dict()) for finding in findings)


def test_fully_excluded_path_is_never_searched(monkeypatch):
    calls = []
    monkeypatch.setenv("PATH", "/home/testuser/.ssh")
    monkeypatch.setattr(
        tool_discovery.shutil,
        "which",
        lambda name, *, path: calls.append((name, path)),
    )

    findings = tool_discovery.discover_tools()

    assert calls == []
    assert all(finding.status == "not_checked" for finding in findings)
    assert all(finding.value is None for finding in findings)


@pytest.mark.parametrize(
    ("exception", "expected_status"),
    [(PermissionError("denied"), "permission_denied"), (OSError("failed"), "error")],
)
def test_lookup_os_errors_become_findings_without_path_disclosure(
    monkeypatch, exception, expected_status
):
    monkeypatch.setenv("PATH", "/private/path")

    def fail_lookup(_name, *, path):
        raise exception

    monkeypatch.setattr(tool_discovery.shutil, "which", fail_lookup)
    findings = tool_discovery.discover_tools()

    assert all(finding.status == expected_status for finding in findings)
    assert all(finding.value is None for finding in findings)
    assert all("/private/path" not in repr(finding.to_dict()) for finding in findings)


def test_expired_deadline_skips_all_lookups(monkeypatch):
    calls = []

    def fake_which(name, *, path):
        calls.append(name)
        return f"/usr/bin/{name}"

    monkeypatch.setenv("PATH", "/usr/bin")
    monkeypatch.setattr(tool_discovery.shutil, "which", fake_which)
    findings = tool_discovery.discover_tools(deadline=time.monotonic() - 1)

    assert calls == []
    assert len(findings) == len(tool_discovery.TOOL_NAMES)
    assert all(finding.status == "not_checked" for finding in findings)
    assert all(finding.value is None for finding in findings)


def test_deadline_expiring_during_discovery_skips_remaining_lookups(monkeypatch):
    calls = []

    def fake_which(name, *, path):
        calls.append(name)
        return f"/usr/bin/{name}"

    ticks = iter((10.0, 11.0))
    monkeypatch.setenv("PATH", "/usr/bin")
    monkeypatch.setattr(tool_discovery.shutil, "which", fake_which)
    monkeypatch.setattr(tool_discovery.time, "monotonic", lambda: next(ticks, 11.0))

    findings = tool_discovery.discover_tools(deadline=10.5)

    assert calls == [tool_discovery.TOOL_NAMES[0]]
    assert findings[0].status == "detected"
    assert all(finding.status == "not_checked" for finding in findings[1:])
    assert all(finding.value is None for finding in findings[1:])
