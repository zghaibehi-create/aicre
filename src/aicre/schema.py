from __future__ import annotations
import hashlib
import json
import uuid
from typing import Any

def _canonical(value: Any) -> str:
    return json.dumps(value, ensure_ascii=False, sort_keys=True, separators=(',', ':'), default=str)

def stable_finding_id(collector_id: str, check_id: str, evidence: Any) -> str:
    material = '\0'.join((collector_id, check_id, _canonical(evidence)))
    return hashlib.sha256(material.encode('utf-8')).hexdigest()

def canonical_report(report: dict[str, Any]) -> dict[str, Any]:
    if report.get("schema_version") == "1.0.0" and isinstance(report.get("scan_id"), str):
        return report
    findings = []
    for item in report.get('findings', []):
        check_id = str(item.get('id', 'unknown'))
        collector_id = str(item.get('source', 'unknown'))
        evidence = {'status': item.get('status'), 'value': item.get('value'), 'unit': item.get('unit')}
        findings.append({'id': stable_finding_id(collector_id, check_id, evidence), 'check_id': check_id,
            'category': item.get('category', 'unknown'), 'status': item.get('status', 'unknown'),
            'value': item.get('value'), 'source': collector_id, 'confidence': item.get('confidence', 'low'),
            'unit': item.get('unit'), 'collected_at': item.get('collected_at', report.get('generated_at')),
            'limitations': list(item.get('limitations', []))})
    seed = _canonical({'profile': report.get('profile'), 'findings': findings})
    scan_id = str(uuid.uuid5(uuid.NAMESPACE_URL, 'urn:aicre:scan:' + seed))
    return {'schema_version': '1.0.0', 'aicre_version': report.get('aicre_version'), 'scan_id': scan_id,
        'generated_at': report.get('generated_at'), 'profile': report.get('profile'),
        'findings': findings, 'readiness': report.get('readiness', {})}
