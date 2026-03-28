"""Shared threat intelligence context builder for AI prompts.

Used by AIReportGenerator and AITimelineGenerator to inject OpenCTI
threat actor, campaign, and IOC enrichment data into LLM prompts.

Respects licensing via OpenCTIContextProvider.is_available().
Returns empty string when unavailable, unlicensed, or no relevant data.
"""

import logging
from typing import Optional

logger = logging.getLogger(__name__)


def get_threat_intel_context(case_id: int, max_chars: int = 1500,
                             include_iocs: bool = True) -> str:
    """Build a threat intel context string for LLM prompt injection.

    Args:
        case_id: Case to gather threat intel for.
        max_chars: Maximum characters for the returned context block.
        include_iocs: Whether to enrich case IOCs against OpenCTI.

    Returns:
        A formatted string of threat intel context, or empty string
        if OpenCTI is unavailable or returns no data.
    """
    try:
        from utils.opencti_context import OpenCTIContextProvider
        provider = OpenCTIContextProvider(case_id)
        if not provider.is_available():
            return ""
    except Exception:
        return ""

    techniques = set()
    try:
        from models.rag import AIAnalysisResult, PatternRuleMatch

        ai_results = AIAnalysisResult.query.filter_by(
            case_id=case_id
        ).filter(AIAnalysisResult.final_confidence >= 50).all()
        for r in ai_results:
            config = r.evidence_package or {}
            for t in config.get('mitre_techniques', []):
                techniques.add(t)

        pattern_matches = PatternRuleMatch.query.filter_by(
            case_id=case_id
        ).filter(PatternRuleMatch.confidence >= 50).all()
        for pm in pattern_matches:
            if pm.mitre_techniques:
                techniques.update(pm.mitre_techniques)
    except Exception:
        pass

    sections = []

    if techniques:
        actors = provider.get_threat_actor_context(list(techniques))
        if actors:
            actor_lines = []
            for a in actors[:5]:
                matching = [t['mitre_id'] for t in a.get('attack_patterns', [])
                            if t.get('mitre_id') in techniques]
                if matching:
                    actor_lines.append(f"- {a['name']}: uses {', '.join(matching)}")
            if actor_lines:
                sections.append("Threat Actors:\n" + "\n".join(actor_lines))

        campaigns = provider.get_campaign_context(list(techniques), days_back=180)
        if campaigns:
            camp_lines = [f"- {c['name']} ({c.get('published', 'N/A')})"
                          for c in campaigns[:3]]
            sections.append("Recent Campaigns:\n" + "\n".join(camp_lines))

    if include_iocs:
        try:
            from models.ioc import IOC
            iocs = IOC.query.filter_by(case_id=case_id, hidden=False).limit(10).all()
            enriched_lines = []
            cve_values = []
            for ioc in iocs:
                if not ioc.value:
                    continue
                if ioc.ioc_type == 'CVE':
                    cve_values.append(ioc.value)
                result = provider.enrich_ioc(ioc.value, ioc.ioc_type)
                if result and result.get('found'):
                    connector_names = [
                        connector.get('name')
                        for connector in result.get('available_connectors', [])[:3]
                        if connector.get('name')
                    ]
                    line = (
                        f"- {ioc.value}: score {result.get('score', 'N/A')}, "
                        f"{', '.join(result.get('labels', []))}"
                    )
                    if connector_names:
                        line += f" | connectors: {', '.join(connector_names)}"
                    enriched_lines.append(line)
            if enriched_lines:
                sections.append("IOC Intelligence:\n" + "\n".join(enriched_lines))

            vulnerabilities = provider.get_vulnerability_context(cve_values[:5])
            if vulnerabilities:
                vuln_lines = []
                for vulnerability in vulnerabilities[:5]:
                    ref_names = [
                        ref.get('source_name')
                        for ref in vulnerability.get('external_references', [])[:3]
                        if ref.get('source_name')
                    ]
                    line = f"- {vulnerability.get('name')}"
                    if vulnerability.get('base_score') is not None:
                        line += f": base score {vulnerability.get('base_score')}"
                    if ref_names:
                        line += f" | sources: {', '.join(ref_names)}"
                    vuln_lines.append(line)
                if vuln_lines:
                    sections.append("Vulnerability Intelligence:\n" + "\n".join(vuln_lines))
        except Exception:
            pass

    if not sections:
        return ""

    context = "\n\n".join(sections)
    return context[:max_chars] if len(context) > max_chars else context
