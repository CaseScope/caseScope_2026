"""Post-detection TI enrichment helpers."""

from __future__ import annotations

from typing import Any, Dict, Iterable, Optional

from utils.pattern_overlay import PatternOverlayEnhancer, is_opencti_overlay_enabled


def is_ti_overlay_enabled() -> bool:
    """Return whether TI overlay enrichment is available for this run."""
    return is_opencti_overlay_enabled()


def apply_ti_overlay_to_finding(
    finding: Dict[str, Any],
    *,
    overlay_enhancer: Optional[PatternOverlayEnhancer] = None,
) -> Optional[Dict[str, Any]]:
    """Attach additive TI overlay metadata without mutating detector confidence."""
    if not isinstance(finding, dict):
        return None

    pattern_id = str(finding.get('pattern_id') or '').strip()
    if not pattern_id:
        return None

    deterministic_score = finding.get('deterministic_score')
    if deterministic_score is None:
        deterministic_score = finding.get('confidence', 0)

    enhancer = overlay_enhancer or PatternOverlayEnhancer()
    context = enhancer.build_overlay_context(
        pattern_id=pattern_id,
        deterministic_score=float(deterministic_score or 0),
        mitre_techniques=finding.get('mitre_techniques'),
    )
    if not context:
        return None

    applied_boost = float(context.get('applied_boost') or 0.0)
    finding['overlay_score_adjustment'] = applied_boost
    finding['intel_overlay'] = context

    ti_enrichment = finding.get('ti_enrichment')
    if not isinstance(ti_enrichment, dict):
        ti_enrichment = {}
        finding['ti_enrichment'] = ti_enrichment

    ti_enrichment.update({
        'available': True,
        'authority': 'metadata_only',
        'confidence_delta': applied_boost,
        'overlay_sources': context.get('sources', []),
        'freshness_score': context.get('freshness_score'),
        'matched_mitre_techniques': context.get('matched_mitre_techniques', []),
    })

    base_confidence = float(finding.get('confidence') or 0.0)
    ti_enrichment['authoritative_confidence'] = base_confidence
    ti_enrichment['display_confidence_preview'] = min(100.0, base_confidence + applied_boost)
    return context


def apply_ti_overlay_to_findings(
    findings: Iterable[Dict[str, Any]],
    *,
    overlay_enhancer: Optional[PatternOverlayEnhancer] = None,
) -> int:
    """Apply TI overlay enrichment across a finding list."""
    enhancer = overlay_enhancer or PatternOverlayEnhancer()
    updates = 0
    for finding in findings or []:
        context = apply_ti_overlay_to_finding(finding, overlay_enhancer=enhancer)
        if context and context.get('applied_boost', 0) > 0:
            updates += 1
    return updates
