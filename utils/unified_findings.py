"""Unified Findings - Normalizes results from all three detection systems

Combines findings from:
- System 1: AI Correlation (AIAnalysisResult) - confidence 0-100
- System 2: Pattern Rules (PatternRuleMatch) - confidence 0-100  
- System 3: RAG Patterns (PatternMatch) - confidence_score 0-1

Normalizes to a single output format with:
- Unified 0-100 confidence scale
- Consistent severity mapping
- Common fields across all systems
- Source system attribution

Usage:
    findings = get_unified_findings(case_id=123)
    # Returns list of dicts sorted by confidence descending
"""

import logging
from typing import Dict, List, Any, Optional
from datetime import datetime

from models.database import db

logger = logging.getLogger(__name__)


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
    findings = []
    
    # Collect from all three systems
    findings.extend(_get_system1_findings(case_id))
    findings.extend(_get_system2_findings(case_id))
    findings.extend(_get_system3_findings(case_id))
    
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
    
    return {
        'findings': findings,
        'summary': summary
    }


def _get_system1_findings(case_id: int) -> List[Dict]:
    """Get findings from System 1 (AI Correlation Analyzer).
    
    Source: AIAnalysisResult model
    Confidence: final_confidence (0-100, already normalized)
    """
    try:
        from models.rag import AIAnalysisResult
        
        results = AIAnalysisResult.query.filter_by(case_id=case_id).all()
        
        findings = []
        for r in results:
            # Skip incomplete/neutral results
            if r.final_confidence is None or r.final_confidence == 50:
                if not r.ai_reasoning or r.ai_reasoning.startswith('AI analysis incomplete'):
                    continue
            
            findings.append({
                'id': f's1_{r.id}',
                'source_system': 'ai_correlation',
                'source_label': 'AI Pattern Analysis',
                'pattern_id': r.pattern_id or '',
                'pattern_name': r.pattern_name or '',
                'category': r.category or '',
                'severity': (r.severity or 'medium').lower(),
                'confidence': round(r.final_confidence or 0),
                'confidence_raw': r.final_confidence,
                'confidence_components': {
                    'ai_confidence': r.ai_confidence,
                    'rule_based': r.rule_based_confidence,
                    'final_blended': r.final_confidence
                },
                'mitre_techniques': r.mitre_techniques or [],
                'source_host': r.source_host or '',
                'username': r.correlation_key or '',
                'event_count': r.events_analyzed or 0,
                'first_seen': r.window_start.isoformat() if r.window_start else None,
                'last_seen': r.window_end.isoformat() if r.window_end else None,
                'reasoning': r.ai_reasoning or '',
                'iocs': r.ai_iocs or [],
                'indicators': r.ai_indicators_found or [],
                'detail_url': f'/api/rag/ai-correlation/results/{case_id}'
            })
        
        return findings
        
    except Exception as e:
        logger.warning(f"[UnifiedFindings] System 1 query failed: {e}")
        return []


def _get_system2_findings(case_id: int) -> List[Dict]:
    """Get findings from System 2 (Pattern Rules).
    
    Source: PatternRuleMatch model
    Confidence: confidence (0-100, already normalized)
    """
    try:
        from models.rag import PatternRuleMatch
        
        results = PatternRuleMatch.query.filter_by(case_id=case_id).all()
        
        findings = []
        for r in results:
            # Parse confidence factors if stored as JSON
            factors = {}
            if r.confidence_factors:
                if isinstance(r.confidence_factors, dict):
                    factors = r.confidence_factors
                elif isinstance(r.confidence_factors, str):
                    import json
                    try:
                        factors = json.loads(r.confidence_factors)
                    except (json.JSONDecodeError, TypeError):
                        pass
            
            findings.append({
                'id': f's2_{r.id}',
                'source_system': 'pattern_rules',
                'source_label': 'Rule-Based Detection',
                'pattern_id': r.pattern_id or '',
                'pattern_name': r.pattern_name or '',
                'category': r.category or '',
                'severity': (r.severity or 'medium').lower(),
                'confidence': r.confidence or 0,
                'confidence_raw': r.confidence,
                'confidence_components': factors,
                'mitre_techniques': r.mitre_techniques or [],
                'source_host': r.source_host or '',
                'username': r.username or '',
                'event_count': r.event_count or 0,
                'first_seen': r.first_seen.isoformat() if r.first_seen else None,
                'last_seen': r.last_seen.isoformat() if r.last_seen else None,
                'reasoning': '',  # Rule-based, no AI reasoning
                'iocs': [],
                'indicators': r.indicators or [],
                'detail_url': f'/api/rag/pattern-rules/details/{case_id}/{r.pattern_id}'
            })
        
        return findings
        
    except Exception as e:
        logger.warning(f"[UnifiedFindings] System 2 query failed: {e}")
        return []


def _get_system3_findings(case_id: int) -> List[Dict]:
    """Get findings from System 3 (RAG Pattern Discovery).
    
    Source: PatternMatch model
    Confidence: confidence_score (0-1, needs ×100 normalization)
    """
    try:
        from models.rag import PatternMatch, AttackPattern
        
        results = db.session.query(PatternMatch, AttackPattern).join(
            AttackPattern, PatternMatch.pattern_id == AttackPattern.id
        ).filter(
            PatternMatch.case_id == case_id
        ).all()
        
        findings = []
        for match, pattern in results:
            # Normalize confidence from 0-1 to 0-100
            raw_confidence = match.confidence_score or 0
            normalized_confidence = round(raw_confidence * 100)
            
            findings.append({
                'id': f's3_{match.id}',
                'source_system': 'rag_patterns',
                'source_label': 'Pattern Discovery',
                'pattern_id': str(pattern.id) if pattern else '',
                'pattern_name': pattern.name if pattern else '',
                'category': pattern.tactic if pattern else '',
                'severity': (pattern.severity or 'medium').lower() if pattern else 'medium',
                'confidence': normalized_confidence,
                'confidence_raw': raw_confidence,
                'confidence_components': {
                    'raw_score': raw_confidence,
                    'normalized': normalized_confidence,
                    'confidence_weight': pattern.confidence_weight if pattern else None
                },
                'mitre_techniques': [pattern.technique_id] if pattern and pattern.technique_id else [],
                'source_host': match.source_host or '',
                'username': '',
                'event_count': match.matched_event_count or 0,
                'first_seen': match.first_event_time.isoformat() if match.first_event_time else None,
                'last_seen': match.last_event_time.isoformat() if match.last_event_time else None,
                'reasoning': match.ai_summary or '',
                'iocs': [],
                'indicators': [],
                'detail_url': f'/api/rag/matches/{case_id}/details/{pattern.id}' if pattern else ''
            })
        
        return findings
        
    except Exception as e:
        logger.warning(f"[UnifiedFindings] System 3 query failed: {e}")
        return []


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
