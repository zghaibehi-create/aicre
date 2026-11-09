"""AICRE local inventory and evidence-backed readiness report."""
from __future__ import annotations

import json
import math
import time
from collections.abc import Sequence
from typing import Any

from . import __version__
from .compatibility import evaluate_compatibility
from .models import Finding, utc_now
from .readiness import evaluate_readiness
from .system_inventory import collect_system_findings
from .tool_discovery import discover_tools
from .workload_profiles import evaluate_workload_profile, supported_profiles

REPORT_SCHEMA_VERSION = "2.0"
DEFAULT_TIMEOUT_SECONDS = 15.0


def build_report(
    *,
    profile: str | None = None,
    excludes: Sequence[str] = (),
    timeout: float = DEFAULT_TIMEOUT_SECONDS,
    include_tools: bool = True,
) -> dict[str, Any]:
    """Collect an inventory locally and produce five separate readiness dimensions.

    Collection uses a cooperative deadline checked between metadata sources;
    it cannot interrupt an operating-system call already in progress. No
    subprocesses, remote connections, remediation, or user-file content reads
    are performed by this orchestrator.
    """
    selected_profile = "standard" if profile is None else profile
    if selected_profile not in supported_profiles():
        raise ValueError(f"unsupported profile: {profile}")
    if not math.isfinite(timeout) or timeout < 0:
        raise ValueError("timeout must be a finite, non-negative number")

    patterns = tuple(excludes)
    deadline = time.monotonic() + timeout
    findings = collect_system_findings(patterns, deadline=deadline)
    if include_tools:
        findings.extend(discover_tools(patterns, deadline=deadline))
    findings.extend(evaluate_compatibility("standard", deadline=deadline))
    if profile is not None:
        findings.extend(evaluate_workload_profile(findings, selected_profile))
    findings.extend([
        Finding(
            id="privacy.local_collection",
            category="privacy",
            status="detected",
            value={
                "network_access": "none",
                "user_document_contents_read": False,
                "credential_contents_read": False,
                "approved_metadata_sources_only": True,
                "discovered_programs_executed": False,
            },
            source=f"AICRE {__version__} collection policy",
            limitations=(
                "Describes AICRE inventory behavior only; it does not monitor other host processes or traffic.",
            ),
        ),
        Finding(
            id="privacy.user_exclusions",
            category="privacy",
            status="detected",
            value={
                "patterns_supplied": len(patterns),
                "applied_to_filesystem_sources_and_tool_paths": True,
            },
            source="AICRE path policy",
            limitations=(
                "Patterns are applied to filesystem metadata sources and executable paths; they are not a host-wide access-control rule.",
            ),
        ),
    ])
    readiness = evaluate_readiness(findings, profile=profile)
    return {
        "schema_version": REPORT_SCHEMA_VERSION,
        "aicre_version": __version__,
        "profile": selected_profile,
        "generated_at": utc_now(),
        "findings": [finding.to_dict() for finding in findings],
        "readiness": {
            name: dimension.to_dict() for name, dimension in readiness.items()
        },
    }


def serialize_report(report: dict[str, Any]) -> str:
    """Serialize a report as stable, human-readable UTF-8 JSON."""
    return json.dumps(report, ensure_ascii=False, indent=2, sort_keys=False) + "\n"
