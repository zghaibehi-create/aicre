from __future__ import annotations
from typing import Any

def compare_reports(before: dict[str, Any], after: dict[str, Any]) -> dict[str, Any]:
    def key(item: dict[str, Any]) -> str:
        return str(item.get('check_id') or item.get('id') or '')
    old = {key(item): item for item in before.get('findings', [])}
    new = {key(item): item for item in after.get('findings', [])}
    changes = []
    for identifier in sorted(set(old) | set(new)):
        if identifier not in old:
            change, left, right = 'new', None, new[identifier]
        elif identifier not in new:
            change, left, right = 'resolved', old[identifier], None
        else:
            left, right = old[identifier], new[identifier]
            fields = ('category', 'status', 'value', 'unit', 'source', 'confidence', 'limitations')
            change = 'unchanged' if all(left.get(field) == right.get(field) for field in fields) else 'changed'
        changes.append({'check_id': identifier, 'change': change, 'before': left, 'after': right})
    counts = {name: sum(1 for item in changes if item['change'] == name) for name in ('new', 'resolved', 'unchanged', 'changed')}
    return {'schema_version': '1.0.0', 'before_scan_id': before.get('scan_id'), 'after_scan_id': after.get('scan_id'), 'counts': counts, 'changes': changes}
