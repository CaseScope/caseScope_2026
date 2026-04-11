"""Helpers for building consistent analysis summaries."""

from datetime import datetime
from typing import Any, Dict, List, Optional

from utils.finding_contract import canonicalize_finding, severity_from_confidence


_SEVERITY_ORDER = {
    'critical': 0,
    'high': 1,
    'medium': 2,
    'low': 3,
}
def normalize_finding(finding: Any) -> Optional[Dict[str, Any]]:
    """Normalize gap findings, pattern results, and storyline dicts."""
    if hasattr(finding, 'to_dict'):
        raw = finding.to_dict()
    elif isinstance(finding, dict):
        raw = dict(finding)
    else:
        return None

    canonical = canonicalize_finding(raw)
    severity = canonical['severity']
    confidence = canonical['confidence']
    finding_type = raw.get('type') or raw.get('detail_type') or canonical['rule_pack'] or 'finding'
    name = canonical['name']
    summary = (
        raw.get('summary')
        or raw.get('description')
        or raw.get('finding')
        or raw.get('title')
        or name
    )
    entity_value = (
        raw.get('entity_value')
        or canonical.get('host')
        or canonical.get('user')
        or raw.get('target_value')
        or ''
    )
    entity_type = raw.get('entity_type') or ('system' if canonical.get('host') else '')
    timestamp = (
        raw.get('timestamp')
        or canonical.get('first_seen')
    )

    return {
        'id': raw.get('id') or canonical.get('dedup_key'),
        'type': finding_type,
        'name': name,
        'summary': summary,
        'severity': severity,
        'confidence': confidence,
        'entity': entity_value,
        'entity_type': entity_type,
        'timestamp': timestamp,
        'mitre_techniques': canonical.get('mitre_techniques') or [],
        'suggested_iocs': raw.get('suggested_iocs') or [],
        'rule_id': canonical.get('rule_id'),
        'rule_pack': canonical.get('rule_pack'),
        'dedup_key': canonical.get('dedup_key'),
    }


def summarize_findings(findings: List[Any], top_limit: int = 5) -> Dict[str, Any]:
    """Build reusable summary metrics from a heterogeneous findings list."""
    normalized = [item for item in (normalize_finding(f) for f in findings) if item]

    severity_breakdown = {'critical': 0, 'high': 0, 'medium': 0, 'low': 0}
    for finding in normalized:
        severity = finding['severity']
        if severity in severity_breakdown:
            severity_breakdown[severity] += 1

    high_confidence_findings = sum(1 for finding in normalized if (finding['confidence'] or 0) >= 75)

    def _sort_key(item: Dict[str, Any]):
        timestamp = item.get('timestamp')
        if isinstance(timestamp, datetime):
            timestamp_value = timestamp.isoformat()
        else:
            timestamp_value = str(timestamp or '')
        return (
            _SEVERITY_ORDER.get(item.get('severity', 'low'), 99),
            -(item.get('confidence') or 0),
            timestamp_value,
        )

    top_findings = sorted(normalized, key=_sort_key)[:top_limit]

    return {
        'total_findings': len(normalized),
        'high_confidence_findings': high_confidence_findings,
        'critical_findings': severity_breakdown['critical'],
        'high_findings': severity_breakdown['high'],
        'medium_findings': severity_breakdown['medium'],
        'low_findings': severity_breakdown['low'],
        'severity_breakdown': severity_breakdown,
        'top_findings': top_findings,
        'normalized_findings': normalized,
    }
