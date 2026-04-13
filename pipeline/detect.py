"""Shared Phase 7 detection-stage helpers."""

from __future__ import annotations

from typing import Any, Callable, Dict, List, Optional

from utils.attack_chain_builder import AttackChainBuilder
from utils.hayabusa_correlator import HayabusaCorrelator


def run_hayabusa_correlation(
    case_id: int,
    analysis_id: str,
    progress_callback: Optional[Callable[[str, int, str], None]] = None,
) -> Dict[str, Any]:
    """Run Hayabusa correlation and downstream attack-chain building."""
    correlator = HayabusaCorrelator(
        case_id=case_id,
        analysis_id=analysis_id,
        progress_callback=progress_callback,
    )
    detection_groups = correlator.correlate()

    attack_chains: List[Any] = []
    if detection_groups:
        if progress_callback is not None:
            progress_callback("hayabusa_correlation", 48, "Building attack chains...")
        builder = AttackChainBuilder(case_id, analysis_id)
        attack_chains = builder.build_chains(detection_groups)

    return {
        "detection_groups": detection_groups or [],
        "attack_chains": attack_chains,
    }
