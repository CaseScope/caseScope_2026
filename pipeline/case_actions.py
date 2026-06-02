"""Shared suggested-action stage helpers."""

from __future__ import annotations

import logging
from typing import Any, Dict, List

from models.database import db
from models.behavioral_profiles import SuggestedAction

logger = logging.getLogger(__name__)

MAX_FINDINGS_FOR_ACTIONS = 1000
MAX_SUGGESTED_ACTIONS = 500
MAX_IOC_ACTIONS = 200
SEVERITY_RANK = {
    'critical': 4,
    'high': 3,
    'medium': 2,
    'low': 1,
}


def _finding_value(finding: Any, key: str, default: Any = None) -> Any:
    if hasattr(finding, key):
        return getattr(finding, key)
    if isinstance(finding, dict):
        return finding.get(key, default)
    return default


def _finding_confidence(finding: Any) -> float:
    try:
        return float(_finding_value(finding, 'confidence', 0) or 0)
    except (TypeError, ValueError):
        return 0.0


def _finding_severity(finding: Any) -> str:
    return str(_finding_value(finding, 'severity', 'low') or 'low').lower()


def _rank_findings_for_actions(findings: List[Any]) -> List[Any]:
    return sorted(
        findings or [],
        key=lambda finding: (
            SEVERITY_RANK.get(_finding_severity(finding), 0),
            _finding_confidence(finding),
        ),
        reverse=True,
    )


def _trim_target_value(value: Any) -> str:
    return str(value or '').strip()[:255]


def _generate_actions_for_finding(
    *,
    case_id: int,
    analysis_id: str,
    finding: Any,
) -> List[SuggestedAction]:
    actions: List[SuggestedAction] = []

    if hasattr(finding, 'confidence'):
        confidence = _finding_confidence(finding)
        severity = _finding_severity(finding)
        entity_type = _finding_value(finding, 'entity_type', '')
        entity_value = _trim_target_value(_finding_value(finding, 'entity_value', ''))
        suggested_iocs = _finding_value(finding, 'suggested_iocs', []) or []
        finding_id = _finding_value(finding, 'id', 0)
        source_type = 'gap_finding'
    elif isinstance(finding, dict):
        confidence = _finding_confidence(finding)
        severity = _finding_severity(finding)
        entity_type = finding.get('entity_type', '')
        entity_value = _trim_target_value(finding.get('entity_value', ''))
        suggested_iocs = finding.get('suggested_iocs', [])
        finding_id = finding.get('id', 0)
        source_type = finding.get('type', 'finding')
    else:
        return actions

    if confidence >= 75 and entity_value:
        if entity_type == 'user':
            actions.append(SuggestedAction(
                case_id=case_id,
                analysis_id=analysis_id,
                source_type=source_type,
                source_id=finding_id,
                action_type='mark_user_compromised',
                target_type='user',
                target_value=entity_value,
                reason=f'High confidence finding ({confidence}%) suggests user compromise',
                confidence=confidence,
                status='pending',
            ))
        elif entity_type == 'system':
            actions.append(SuggestedAction(
                case_id=case_id,
                analysis_id=analysis_id,
                source_type=source_type,
                source_id=finding_id,
                action_type='mark_system_compromised',
                target_type='system',
                target_value=entity_value,
                reason=f'High confidence finding ({confidence}%) suggests system compromise',
                confidence=confidence,
                status='pending',
            ))

    for ioc in suggested_iocs[:5]:
        ioc_value = ioc.get('value') if isinstance(ioc, dict) else str(ioc)
        ioc_value = _trim_target_value(ioc_value)
        if not ioc_value or confidence < 60:
            continue
        ioc_reason = ioc.get('reason', 'Discovered during analysis') if isinstance(ioc, dict) else 'Discovered during analysis'
        actions.append(SuggestedAction(
            case_id=case_id,
            analysis_id=analysis_id,
            source_type=source_type,
            source_id=finding_id,
            action_type='add_ioc',
            target_type='ioc',
            target_value=ioc_value,
            reason=ioc_reason,
            confidence=confidence,
            status='pending',
        ))

    if severity in ['high', 'critical']:
        actions.append(SuggestedAction(
            case_id=case_id,
            analysis_id=analysis_id,
            source_type=source_type,
            source_id=finding_id,
            action_type='investigate',
            target_type=entity_type or 'finding',
            target_value=entity_value or 'Finding',
            reason=f'{severity.title()} severity finding requires investigation',
            confidence=confidence,
            status='pending',
        ))

    return actions


def _deduplicate_actions(actions: List[SuggestedAction]) -> List[SuggestedAction]:
    deduped: Dict[Any, SuggestedAction] = {}
    for action in actions:
        key = (
            action.action_type,
            action.target_type,
            str(action.target_value or '').lower(),
        )
        existing = deduped.get(key)
        if existing is None or (action.confidence or 0) > (existing.confidence or 0):
            deduped[key] = action
    return list(deduped.values())


def _cap_actions(actions: List[SuggestedAction]) -> List[SuggestedAction]:
    """Bound persisted suggestions so noisy cases do not flood analyst queues."""
    sorted_actions = sorted(
        actions,
        key=lambda action: (
            action.confidence or 0,
            1 if action.action_type in {'mark_user_compromised', 'mark_system_compromised'} else 0,
        ),
        reverse=True,
    )
    capped: List[SuggestedAction] = []
    ioc_count = 0
    for action in sorted_actions:
        if action.action_type == 'add_ioc':
            if ioc_count >= MAX_IOC_ACTIONS:
                continue
            ioc_count += 1
        capped.append(action)
        if len(capped) >= MAX_SUGGESTED_ACTIONS:
            break
    return capped


def generate_suggested_actions(
    *,
    case_id: int,
    analysis_id: str,
    all_findings: List[Any],
    attack_chains: List[Any],
    opencti_context: Dict[str, Any],
    progress_callback,
) -> List[SuggestedAction]:
    """Generate, deduplicate, and persist suggested analyst actions."""
    actions: List[SuggestedAction] = []
    progress_callback('suggested_actions', 91, 'Generating investigation suggestions...')

    ranked_findings = _rank_findings_for_actions(all_findings)
    for finding in ranked_findings[:MAX_FINDINGS_FOR_ACTIONS]:
        actions.extend(_generate_actions_for_finding(
            case_id=case_id,
            analysis_id=analysis_id,
            finding=finding,
        ))

    if opencti_context and opencti_context.get('available'):
        try:
            detected_techniques = set()
            for finding in all_findings:
                if hasattr(finding, 'mitre_techniques') and finding.mitre_techniques:
                    detected_techniques.update(finding.mitre_techniques)
                elif isinstance(finding, dict) and finding.get('mitre_techniques'):
                    detected_techniques.update(finding['mitre_techniques'])

            for chain in attack_chains:
                chain_dict = chain.to_dict() if hasattr(chain, 'to_dict') else chain
                if isinstance(chain_dict, dict):
                    detected_techniques.update(chain_dict.get('tactics_observed', []))

            for actor in opencti_context.get('threat_actors', [])[:5]:
                actor_techniques = {
                    technique['mitre_id']
                    for technique in actor.get('attack_patterns', [])
                    if technique.get('mitre_id')
                }
                missing = actor_techniques - detected_techniques
                for tech_id in list(missing)[:3]:
                    actions.append(SuggestedAction(
                        case_id=case_id,
                        analysis_id=analysis_id,
                        source_type='opencti',
                        source_id=0,
                        action_type='hunt',
                        target_type='technique',
                        target_value=tech_id,
                        reason=(
                            f"Hunt for {tech_id} — used by {actor['name']} "
                            f"alongside detected techniques"
                        ),
                        confidence=60,
                        status='pending',
                    ))
        except Exception as exc:
            logger.debug("[CaseAnalyzer] OpenCTI hunt suggestions skipped: %s", exc)

    actions = _cap_actions(_deduplicate_actions(actions))
    for action in actions:
        db.session.add(action)

    skipped = max(0, len(ranked_findings) - MAX_FINDINGS_FOR_ACTIONS)
    message = f'Generated {len(actions)} suggested actions'
    if skipped:
        message += f' from top-ranked findings ({skipped} lower-ranked findings skipped)'
    progress_callback('suggested_actions', 95, message)
    return actions
