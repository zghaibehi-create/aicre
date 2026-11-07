from aicre.models import Finding
from aicre.readiness import evaluate_readiness
from aicre.workload_profiles import GIB, evaluate_workload_profile


def finding(identifier, value, status="detected", category="resource"):
    return Finding(id=identifier, category=category, status=status, value=value, source="test")


def observations():
    return [finding("resource.cpu.logical_count", 8),
            finding("resource.memory.total_bytes", 16 * GIB),
            finding("resource.storage.root", {"total_bytes": 100 * GIB, "free_bytes": 50 * GIB}),
            finding("tool.git", "/usr/bin/git", category="software"),
            finding("tool.python3", "/usr/bin/python3", category="software")]


def test_resource_readiness_stays_unknown_when_only_host_observations_exist():
    base = observations()
    checks = evaluate_workload_profile(base, "agent-development")
    result = evaluate_readiness(base + checks, "agent-development")

    assert result["resource_readiness"].status == "unknown"
    assert result["resource_readiness"].evidence == (
        "profile.resource.cpu", "profile.resource.memory", "profile.resource.storage"
    )
    for check in checks:
        if check.id.startswith("profile.resource."):
            assert check.status == "detected"
            assert check.value["satisfied"] is None
            assert check.value["comparison"] == "not_performed"
            assert check.value["observation_scope"] == "host_facing"
            assert any("effective process" in item for item in check.limitations)


def test_host_observations_above_or_below_threshold_never_pass_or_fail_resource():
    for cpu_count in (1, 8):
        base = observations()
        base[0] = finding("resource.cpu.logical_count", cpu_count)
        checks = evaluate_workload_profile(base, "agent-development")
        result = evaluate_readiness(base + checks, "agent-development")
        assert result["resource_readiness"].status == "unknown"
        cpu_check = next(item for item in checks if item.id == "profile.resource.cpu")
        assert cpu_check.value["actual"] == cpu_count
        assert cpu_check.value["satisfied"] is None


def test_missing_required_tool_fails():
    base = observations()
    base[3] = finding("tool.git", None, status="not_detected", category="software")
    result = evaluate_readiness(base + evaluate_workload_profile(base, "agent-development"), "agent-development")
    assert result["software_readiness"].status == "fail"

def test_excluded_or_timed_out_sources_remain_unknown():
    base = observations()
    base[1] = finding("resource.memory.total_bytes", None, status="not_checked")
    base[4] = finding("tool.python3", None, status="not_checked", category="software")
    result = evaluate_readiness(base + evaluate_workload_profile(base, "agent-development"), "agent-development")
    assert result["resource_readiness"].status == "unknown"
    assert result["software_readiness"].status == "unknown"

def test_standard_profile_does_not_assume_requirements():
    base = observations()
    assert evaluate_workload_profile(base, "standard") == []
    result = evaluate_readiness(base, "standard")
    assert result["resource_readiness"].status == "unknown"
    assert result["software_readiness"].status == "unknown"
