from aicre.models import Finding, ReadinessDimension
from aicre.readiness import evaluate_readiness


def finding(identifier, status="detected", value=None, category="system"):
    return Finding(
        id=identifier,
        category=category,
        status=status,
        value=value,
        source="unit-test",
    )


def test_returns_exactly_five_independent_dimensions_with_no_score():
    result = evaluate_readiness([])
    assert set(result) == {
        "resource_readiness",
        "software_readiness",
        "compatibility_readiness",
        "privacy_readiness",
        "security_readiness",
    }
    assert all(isinstance(value, ReadinessDimension) for value in result.values())
    assert all(value.status == "unknown" for value in result.values())
    assert not any("score" in key.lower() for key in result)


def test_resource_unknown_cites_available_resource_findings():
    findings = [
        finding("host.cpu_count", value=8),
        finding("host.ram_bytes", value=16000),
        finding("host.storage_bytes", value=100000),
        finding("host.hostname", value="example"),
    ]
    dimension = evaluate_readiness(findings)["resource_readiness"]
    assert dimension.status == "unknown"
    assert dimension.evidence == ("host.cpu_count", "host.ram_bytes", "host.storage_bytes")
    assert "no workload resource baseline" in dimension.explanation.lower()


def test_software_unknown_cites_detected_tool_ids():
    findings = [finding("tool.python", value="3.12"), finding("tool.git"), finding("host.os")]
    dimension = evaluate_readiness(findings)["software_readiness"]
    assert dimension.status == "unknown"
    assert dimension.evidence == ("tool.git", "tool.python")
    assert "No mandatory software manifest" in dimension.explanation


def test_compatibility_pass_requires_both_detected_and_satisfied():
    findings = [
        finding("compatibility.platform.linux", value={"satisfied": True}),
        finding("compatibility.python.minimum", value={"satisfied": True}),
    ]
    dimension = evaluate_readiness(findings)["compatibility_readiness"]
    assert dimension.status == "pass"
    assert dimension.evidence == (
        "compatibility.platform.linux",
        "compatibility.python.minimum",
    )


def test_compatibility_fails_on_explicit_requirement_failure():
    for failed in (
        finding("compatibility.platform.linux", "unsupported", {"satisfied": False}),
        finding("compatibility.python.minimum", "not_detected", {}),
        finding("compatibility.python.minimum", "detected", {"satisfied": False}),
    ):
        other_id = (
            "compatibility.python.minimum"
            if failed.id == "compatibility.platform.linux"
            else "compatibility.platform.linux"
        )
        dimension = evaluate_readiness(
            [failed, finding(other_id, value={"satisfied": True})]
        )["compatibility_readiness"]
        assert dimension.status == "fail"


def test_compatibility_unknown_for_missing_or_malformed_results():
    cases = [
        [],
        [finding("compatibility.platform.linux", value={"satisfied": True})],
        [
            finding("compatibility.platform.linux", value="yes"),
            finding("compatibility.python.minimum", value={"satisfied": 1}),
        ],
        [
            finding("compatibility.platform.linux", "error", {"satisfied": False}),
            finding("compatibility.python.minimum", value={"satisfied": True}),
        ],
    ]
    for case in cases:
        assert evaluate_readiness(case)["compatibility_readiness"].status == "unknown"


def test_privacy_pass_only_when_both_policy_findings_detected():
    findings = [
        finding("privacy.local_collection", value=True),
        finding("privacy.user_exclusions", value=True),
    ]
    dimension = evaluate_readiness(findings)["privacy_readiness"]
    assert dimension.status == "pass"
    assert dimension.evidence == ("privacy.local_collection", "privacy.user_exclusions")
    assert "not a host-wide privacy guarantee" in dimension.explanation
    assert evaluate_readiness(findings[:1])["privacy_readiness"].status == "unknown"
    assert evaluate_readiness(
        [findings[0], finding("privacy.user_exclusions", "error")]
    )["privacy_readiness"].status == "unknown"


def test_security_root_warning_and_nonzero_uid_unknown():
    root = evaluate_readiness(
        [finding("security.effective_uid", value=0)]
    )["security_readiness"]
    assert root.status == "warning"
    assert root.evidence == ("security.effective_uid",)
    assert "root" in root.explanation

    root_mapping = evaluate_readiness(
        [finding("security.effective_uid", value={"effective_uid": 0})]
    )["security_readiness"]
    assert root_mapping.status == "warning"

    regular = evaluate_readiness(
        [finding("security.effective_uid", value={"effective_uid": 1000})]
    )["security_readiness"]
    assert regular.status == "unknown"
    assert "not assessed" in regular.explanation
    assert "guarantee" not in regular.explanation.lower()


def test_missing_or_malformed_security_identity_is_unknown():
    assert evaluate_readiness([])["security_readiness"].status == "unknown"
    for status, value in (("error", 0), ("detected", "0"), ("detected", {"uid": 0}), ("detected", True)):
        dimension = evaluate_readiness(
            [finding("security.effective_uid", status, value)]
        )["security_readiness"]
        assert dimension.status == "unknown"
        assert dimension.evidence == ("security.effective_uid",)


def test_ignores_non_finding_entries_without_crashing():
    result = evaluate_readiness([None, {"id": "tool.fake"}])
    assert result["software_readiness"].evidence == ()
    assert result["compatibility_readiness"].status == "unknown"



def profile_findings(*, cpu=4, memory_gib=16, disk_gib=20, tools=None, missing_resource=None):
    from aicre.workload_profiles import GIB, evaluate_workload_profile

    values = [
        finding("resource.cpu.logical_count", value=cpu, category="resource"),
        finding("resource.memory.total_bytes", value=memory_gib * GIB, category="resource"),
        finding(
            "resource.storage.root",
            value={"total_bytes": disk_gib * GIB, "free_bytes": disk_gib * GIB},
            category="resource",
        ),
    ]
    if missing_resource:
        values = [item for item in values if item.id != missing_resource]
    for name, status in (tools or {"git": "detected", "python3": "detected", "node": "detected"}).items():
        values.append(
            finding(
                f"tool.{name}",
                status=status,
                value="/usr/bin/" + name if status == "detected" else None,
                category="software",
            )
        )
    return values + evaluate_workload_profile(values, "laptop-dev")


def test_resource_readiness_pass_warning_fail_and_unknown_fixtures():
    assert evaluate_readiness(profile_findings(), "laptop-dev")["resource_readiness"].status == "pass"
    assert evaluate_readiness(
        profile_findings(cpu=2), "laptop-dev"
    )["resource_readiness"].status == "warning"
    assert evaluate_readiness(
        profile_findings(cpu=1), "laptop-dev"
    )["resource_readiness"].status == "fail"
    assert evaluate_readiness(
        profile_findings(missing_resource="resource.memory.total_bytes"), "laptop-dev"
    )["resource_readiness"].status == "unknown"


def test_software_readiness_pass_warning_fail_and_unknown_fixtures():
    assert evaluate_readiness(
        profile_findings(), "laptop-dev"
    )["software_readiness"].status == "pass"
    assert evaluate_readiness(
        profile_findings(tools={"git": "not_detected", "python3": "detected", "node": "detected"}),
        "laptop-dev",
    )["software_readiness"].status == "warning"
    assert evaluate_readiness(
        profile_findings(tools={"git": "not_detected", "python3": "not_detected", "node": "detected"}),
        "laptop-dev",
    )["software_readiness"].status == "fail"
    assert evaluate_readiness(
        profile_findings(tools={"git": "not_detected", "python3": "permission_denied", "node": "error"}),
        "laptop-dev",
    )["software_readiness"].status == "unknown"


def test_explicitly_unspecified_profile_returns_unknown_explanation():
    result = evaluate_readiness([], profile=None)
    assert result["resource_readiness"].status == "unknown"
    assert result["software_readiness"].status == "unknown"
    assert result["resource_readiness"].explanation == "No profile specified."
