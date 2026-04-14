"""Shared Phase 7 and 8 narrative stage helpers."""

from __future__ import annotations

from typing import Any, Callable, Dict


def run_ai_triage(
    *,
    case_id: int,
    analysis_id: str,
    context: Dict[str, Any],
    progress_callback: Callable[[str, int, str], None],
    record_phase_outcome: Callable[..., None],
) -> Dict[str, Any]:
    """Run the AI triage checkpoint over the current case-analysis context."""
    from utils.ai_checkpoints import TriageCheckpoint

    checkpoint = TriageCheckpoint(case_id=case_id, analysis_id=analysis_id)
    result = checkpoint.run(context)
    priority_count = len(result.get('priority_findings', []))
    thread_count = len(result.get('investigation_threads', []))
    duration = result.get('triage_duration_ms', 0)
    progress_callback(
        'ai_triage',
        88,
        f'AI triage: {priority_count} priority findings, {thread_count} threads ({duration}ms)',
    )
    record_phase_outcome(
        'ai_triage',
        not result.get('fallback', False),
        details={
            'priority_findings': priority_count,
            'investigation_threads': thread_count,
            'fallback': result.get('fallback', False),
        },
        duration_seconds=duration / 1000 if duration else None,
        message='AI triage complete' if not result.get('fallback') else 'AI triage fallback',
    )
    return result


def run_ai_synthesis(
    *,
    case_id: int,
    analysis_id: str,
    context: Dict[str, Any],
    progress_callback: Callable[[str, int, str], None],
    record_phase_outcome: Callable[..., None],
) -> Dict[str, Any]:
    """Run the AI synthesis checkpoint over the enriched case-analysis context."""
    from utils.ai_checkpoints import SynthesisCheckpoint

    checkpoint = SynthesisCheckpoint(case_id=case_id, analysis_id=analysis_id)
    result = checkpoint.run(context)
    findings_count = len(result.get('key_findings', []))
    actions_count = len(result.get('recommended_actions', []))
    duration = result.get('synthesis_duration_ms', 0)
    progress_callback(
        'ai_synthesis',
        95,
        f'AI synthesis: {findings_count} findings, {actions_count} actions ({duration}ms)',
    )
    record_phase_outcome(
        'ai_synthesis',
        not result.get('fallback', False),
        details={
            'key_findings': findings_count,
            'recommended_actions': actions_count,
            'fallback': result.get('fallback', False),
        },
        duration_seconds=duration / 1000 if duration else None,
        message='AI synthesis complete' if not result.get('fallback') else 'AI synthesis fallback',
    )
    return result
