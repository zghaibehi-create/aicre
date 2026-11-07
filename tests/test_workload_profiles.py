from aicre.models import Finding
from aicre.profiles import PROFILES, list_profiles, resolve_profile
from aicre.readiness import evaluate_readiness
from aicre.workload_profiles import GIB, evaluate_workload_profile


def finding(identifier, value, status="detected", category="resource"):
    return Finding(id=identifier, category=category, status=status, value=value, source="test")


def observations():
    return [
        finding("resource.cpu.logical_count", 8),
        finding("resource.memory.total_bytes", 16 * GIB),
        finding("resource.storage.root", {"total_bytes": 100 * GIB, "free_bytes": 50 * GIB}),
        finding("tool.git", "/usr/bin/git", category="software"),
        finding("tool.python3", "/usr/bin/python3", category="software"),
    ]


def test_every_profile_resolves_and_has_required_contract_fields():
    assert list_profiles() == list(PROFILES)
    for name in list_profiles():
        profile = resolve_profile(name)
        assert set(profile) >= {
            "cores_min", "ram_gb_min", "disk_gb_min", "required_tools", "gpu_required"
        }
        assert isinstance(profile["required_tools"], list)
        assert isinstance(profile["gpu_required"], bool)


def test_existing_standard_and_agent_development_profiles_are_preserved():
    assert resolve_profile("standard")["required_tools"] == []
    assert resolve_profile("agent-development") == {
        "description": "Conservative local agent-development baseline.",
        "cores_min": 2,
        "ram_gb_min": 8,
        "disk_gb_min": 10,
        "required_tools": ["git", "python3"],
        "gpu_required": False,
    }


def test_new_profile_thresholds_and_required_tools_are_exact():
    assert resolve_profile("laptop-dev") == {
        "description": "General-purpose laptop development baseline.",
        "cores_min": 4, "ram_gb_min": 16, "disk_gb_min": 20,
        "required_tools": ["git", "python3", "node"], "gpu_required": False,
    }
    assert resolve_profile("agent-workstation") == {
        "description": "Local AI-agent development workstation baseline.",
        "cores_min": 8, "ram_gb_min": 32, "disk_gb_min": 50,
        "required_tools": ["git", "python3", "docker", "ollama"], "gpu_required": False,
    }
    assert resolve_profile("ci-runner") == {
        "description": "Lightweight continuous-integration runner baseline.",
        "cores_min": 2, "ram_gb_min": 8, "disk_gb_min": 10,
        "required_tools": ["git", "python3", "pip"], "gpu_required": False,
    }


def test_unknown_profile_error_lists_available_profiles():
    import pytest

    with pytest.raises(ValueError, match="available profiles") as error:
        resolve_profile("unknown")
    assert "standard" in str(error.value)
    assert "ci-runner" in str(error.value)


def test_agent_development_profile_passes_baseline():
    base = observations()
    result = evaluate_readiness(
        base + evaluate_workload_profile(base, "agent-development"),
        "agent-development",
    )
    assert result["resource_readiness"].status == "pass"
    assert result["software_readiness"].status == "pass"


def test_one_missing_required_tool_warns_and_two_missing_tools_fail():
    base = observations()
    base.append(finding("tool.node", "/usr/bin/node", category="software"))
    one_missing = [
        item for item in base if item.id != "tool.git"
    ] + [finding("tool.git", None, status="not_detected", category="software")]
    result = evaluate_readiness(
        one_missing + evaluate_workload_profile(one_missing, "laptop-dev"),
        "laptop-dev",
    )
    assert result["software_readiness"].status == "warning"

    two_missing = [
        item for item in base if item.id not in {"tool.git", "tool.python3"}
    ] + [
        finding("tool.git", None, status="not_detected", category="software"),
        finding("tool.python3", None, status="not_detected", category="software"),
    ]
    result = evaluate_readiness(
        two_missing + evaluate_workload_profile(two_missing, "laptop-dev"),
        "laptop-dev",
    )
    assert result["software_readiness"].status == "fail"

    all_unavailable = [
        finding("tool.git", None, status="not_detected", category="software"),
        finding("tool.python3", None, status="permission_denied", category="software"),
        finding("tool.node", None, status="error", category="software"),
    ]
    result = evaluate_readiness(
        all_unavailable + evaluate_workload_profile(all_unavailable, "laptop-dev"),
        "laptop-dev",
    )
    assert result["software_readiness"].status == "unknown"

def test_resource_profile_thresholds_are_generated_from_shared_profile():
    base = observations()
    result = evaluate_workload_profile(base, "laptop-dev")
    by_id = {item.id: item for item in result}
    assert by_id["profile.resource.cpu"].value["minimum"] == 4
    assert by_id["profile.resource.memory"].value["minimum"] == 16 * GIB
    assert by_id["profile.resource.storage"].value["minimum"] == 20 * GIB


def test_standard_profile_does_not_assume_requirements():
    base = observations()
    assert evaluate_workload_profile(base, "standard") == []
    result = evaluate_readiness(base, "standard")
    assert result["resource_readiness"].status == "unknown"
    assert result["software_readiness"].status == "unknown"
