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

def test_agent_development_profile_passes_baseline():
    base = observations()
    result = evaluate_readiness(base + evaluate_workload_profile(base, "agent-development"), "agent-development")
    assert result["resource_readiness"].status == "pass"
    assert result["software_readiness"].status == "pass"

def test_resource_below_minimum_fails():
    base = observations()
    base[0] = finding("resource.cpu.logical_count", 1)
    result = evaluate_readiness(base + evaluate_workload_profile(base, "agent-development"), "agent-development")
    assert result["resource_readiness"].status == "fail"

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
