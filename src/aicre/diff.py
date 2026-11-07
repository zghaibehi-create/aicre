from __future__ import annotations

from typing import Any

from .schema import canonical_report


def compare_reports(before: dict[str, Any], after: dict[str, Any]) -> dict[str, Any]:
    """Compare two validated reports without silently discarding duplicate checks."""
    old_report = canonical_report(before)
    new_report = canonical_report(after)

    def index(report: dict[str, Any], label: str) -> dict[str, dict[str, Any]]:
        result: dict[str, dict[str, Any]] = {}
        for item in report["findings"]:
            identifier = item["check_id"]
            if not isinstance(identifier, str) or not identifier.strip():
                raise ValueError(f"{label} report contains an invalid check_id")
            if identifier in result:
                raise ValueError(f"{label} report contains duplicate check_id: {identifier}")
            result[identifier] = item
        return result

    old = index(old_report, "before")
    new = index(new_report, "after")
    changes = []
    for identifier in sorted(set(old) | set(new)):
        if identifier not in old:
            change, left, right = "new", None, new[identifier]
        elif identifier not in new:
            change, left, right = "resolved", old[identifier], None
        else:
            left, right = old[identifier], new[identifier]
            fields = ("category", "status", "value", "unit", "source", "confidence", "limitations")
            change = "unchanged" if all(left.get(field) == right.get(field) for field in fields) else "changed"
        changes.append({"check_id": identifier, "change": change, "before": left, "after": right})
    counts = {
        name: sum(1 for item in changes if item["change"] == name)
        for name in ("new", "resolved", "unchanged", "changed")
    }
    return {
        "schema_version": "1.0.0",
        "before_scan_id": old_report["scan_id"],
        "after_scan_id": new_report["scan_id"],
        "counts": counts,
        "changes": changes,
    }
