"""Shared threat-intel enrichment stage helpers."""

from __future__ import annotations

import logging
from typing import Any, Callable, Dict, List, Tuple

logger = logging.getLogger(__name__)


def run_opencti_enrichment(
    *,
    case_id: int,
    analysis_id: str,
    findings: List[Dict[str, Any]],
    attack_chains: List[Any],
    progress_callback: Callable[[str, int, str], None],
    record_phase_outcome: Callable[..., None],
) -> Tuple[Dict[str, Any], int]:
    """Attach post-detection threat-intel context to findings and chains."""
    from utils.opencti_context import OpenCTIContextProvider
    from utils.ti.enrichment import apply_ti_overlay_to_finding, is_ti_overlay_enabled

    provider = OpenCTIContextProvider(case_id, analysis_id)

    if not provider.is_available():
        progress_callback('opencti_enrichment', 90, 'OpenCTI not available')
        record_phase_outcome(
            'opencti_enrichment',
            False,
            details={'error': 'OpenCTI context provider unavailable'},
            message='OpenCTI not available',
        )
        return {}, 0

    provider.clear_cache()
    progress_callback('opencti_enrichment', 86, 'Fetching threat intelligence context...')

    context = provider.get_context_for_findings(findings)
    overlay_updates = 0
    if is_ti_overlay_enabled():
        for finding in findings:
            overlay_context = apply_ti_overlay_to_finding(finding)
            if overlay_context and overlay_context.get('applied_boost', 0) > 0:
                overlay_updates += 1
                logger.info(
                    "[CaseAnalyzer] Attached TI overlay to %s:%s (+%s metadata-only)",
                    finding.get('pattern_id', ''),
                    finding.get('correlation_key', ''),
                    overlay_context['applied_boost'],
                )

    for chain in attack_chains:
        chain_dict = chain.to_dict() if hasattr(chain, 'to_dict') else chain
        techniques = chain_dict.get('tactics_observed', []) if isinstance(chain_dict, dict) else []
        if not techniques:
            continue
        chain_context = {}
        for tech in techniques[:5]:
            tech_ctx = provider.get_attack_pattern_context(tech)
            if tech_ctx.get('technique_name'):
                chain_context[tech] = tech_ctx

        if isinstance(chain, dict):
            chain['opencti_context'] = chain_context
        elif hasattr(chain, 'opencti_context'):
            chain.opencti_context = chain_context

    progress_callback('opencti_enrichment', 90, 'Threat intelligence enrichment complete')
    record_phase_outcome(
        'opencti_enrichment',
        True,
        details={
            'threat_actors': len(context.get('threat_actors', [])),
            'campaigns': len(context.get('campaigns', [])),
            'ioc_enrichment': len(context.get('ioc_enrichment', {})),
            'overlay_updates': overlay_updates,
        },
        message='Threat intelligence enrichment complete',
    )
    return context, overlay_updates
