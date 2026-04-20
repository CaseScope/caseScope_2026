"""Unified findings reader backed by the ClickHouse mirror."""

from typing import Any, Dict, List

from utils.unified_findings_store import load_case_findings


def get_unified_findings(
    case_id: int,
    min_confidence: int = 0,
    severity: str = None,
    category: str = None,
    limit: int = 200
) -> Dict[str, Any]:
    """Get normalized findings from all three detection systems.
    
    Args:
        case_id: PostgreSQL case ID
        min_confidence: Minimum unified confidence (0-100)
        severity: Filter by severity (critical, high, medium, low)
        category: Filter by MITRE category
        limit: Maximum results to return
        
    Returns:
        {
            'findings': list of normalized finding dicts,
            'summary': {
                'total': int,
                'by_source': {system: count},
                'by_severity': {level: count},
                'by_category': {category: count}
            }
        }
    """
    findings = load_case_findings(case_id) or []
    read_path = 'clickhouse_store'
    
    # Apply filters
    if min_confidence > 0:
        findings = [f for f in findings if f['confidence'] >= min_confidence]
    
    if severity:
        findings = [f for f in findings if f['severity'] == severity.lower()]
    
    if category:
        findings = [f for f in findings if f['category'] == category]
    
    # Sort by confidence descending, then severity
    severity_order = {'critical': 0, 'high': 1, 'medium': 2, 'low': 3}
    findings.sort(key=lambda f: (
        -f['confidence'], 
        severity_order.get(f['severity'], 4)
    ))
    
    # Apply limit
    findings = findings[:limit]
    
    # Build summary
    summary = _build_summary(findings)
    summary['read_path'] = read_path
    summary['legacy_fallback_used'] = False
    summary['store_backed'] = True
    
    return {
        'findings': findings,
        'summary': summary,
    }


def _build_summary(findings: List[Dict]) -> Dict[str, Any]:
    """Build summary statistics from unified findings."""
    by_source = {}
    by_severity = {}
    by_category = {}
    
    for f in findings:
        # By source
        src = f['source_system']
        by_source[src] = by_source.get(src, 0) + 1
        
        # By severity
        sev = f['severity']
        by_severity[sev] = by_severity.get(sev, 0) + 1
        
        # By category
        cat = f['category']
        if cat:
            by_category[cat] = by_category.get(cat, 0) + 1
    
    # Compute confidence stats
    confidences = [f['confidence'] for f in findings]
    
    return {
        'total': len(findings),
        'by_source': by_source,
        'by_severity': by_severity,
        'by_category': by_category,
        'avg_confidence': round(sum(confidences) / len(confidences), 1) if confidences else 0,
        'max_confidence': max(confidences) if confidences else 0,
        'critical_count': by_severity.get('critical', 0),
        'high_count': by_severity.get('high', 0)
    }
