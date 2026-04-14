"""Helpers for building Scoring 2.0 baseline artifacts from hunting logs."""

from __future__ import annotations

import json
from collections import Counter, defaultdict
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, Iterable, List, Optional


def parse_scoring_telemetry_line(line: str) -> Optional[Dict[str, Any]]:
    """Parse one hunting-log line into a scoring telemetry payload."""
    json_start = line.find("{")
    if json_start < 0:
        return None
    try:
        payload = json.loads(line[json_start:].strip())
    except json.JSONDecodeError:
        return None
    if payload.get("event") != "scoring_telemetry":
        return None
    return payload


def load_scoring_telemetry_from_log(path: Path) -> List[Dict[str, Any]]:
    """Load all scoring telemetry entries from one hunting log."""
    payloads: List[Dict[str, Any]] = []
    with path.open("r", encoding="utf-8") as handle:
        for line in handle:
            payload = parse_scoring_telemetry_line(line)
            if payload is not None:
                payloads.append(payload)
    return payloads


def build_scoring_baseline_artifact(
    *,
    case_id: int,
    source_logs: List[str],
    telemetry_payloads: Iterable[Dict[str, Any]],
    analyst_verdicts: Optional[Iterable[Dict[str, Any]]] = None,
) -> Dict[str, Any]:
    """Build the structured baseline artifact from scoring telemetry payloads."""
    payloads = list(telemetry_payloads)
    verdict_rows = list(analyst_verdicts or [])
    analysis_ids = sorted(
        {
            str(payload.get("analysis_id"))
            for payload in payloads
            if payload.get("analysis_id")
        }
    )

    verdicts_by_key: Dict[tuple[str, str], str] = {}
    for row in verdict_rows:
        key = (str(row.get("pattern_id") or ""), str(row.get("correlation_key") or ""))
        verdict = str(row.get("verdict") or "").strip()
        if key[0] and key[1] and verdict:
            verdicts_by_key[key] = verdict

    grouped: Dict[tuple[str, str], List[Dict[str, Any]]] = defaultdict(list)
    for payload in payloads:
        grouped[(str(payload.get("pattern_id") or ""), str(payload.get("pattern_name") or ""))].append(payload)

    pattern_rows: List[Dict[str, Any]] = []
    overall_verdict_counts: Counter[str] = Counter()
    for (pattern_id, pattern_name), rows in grouped.items():
        materialized = [row for row in rows if row.get("outcome") == "materialized"]
        suppressed = [row for row in rows if row.get("outcome") == "suppressed"]
        strong_downranks = [
            row for row in materialized
            if row.get("ai_adjustment") is not None and float(row.get("ai_adjustment") or 0) <= -15.0
        ]
        coverage_gap_count = sum(1 for row in materialized if row.get("coverage_gap_present"))
        eligible_emit_count = sum(1 for row in materialized if row.get("eligible_to_emit"))
        legacy_forced_count = sum(1 for row in rows if row.get("legacy_forced"))

        verdict_counts: Counter[str] = Counter()
        for row in materialized:
            verdict = verdicts_by_key.get((pattern_id, str(row.get("correlation_key") or "")))
            if verdict:
                verdict_counts[verdict] += 1
        overall_verdict_counts.update(verdict_counts)

        total_count = len(rows)
        materialized_count = len(materialized)
        reviewed_count = sum(verdict_counts.values())
        pattern_rows.append(
            {
                "pattern_id": pattern_id,
                "pattern_name": pattern_name or pattern_id,
                "volume": total_count,
                "materialized_count": materialized_count,
                "suppressed_count": len(suppressed),
                "suppression_rate": round(len(suppressed) / total_count, 4) if total_count else 0.0,
                "eligible_emit_count": eligible_emit_count,
                "eligible_emit_rate": round(eligible_emit_count / materialized_count, 4) if materialized_count else 0.0,
                "strong_downrank_count": len(strong_downranks),
                "strong_downrank_rate": (
                    round(len(strong_downranks) / materialized_count, 4) if materialized_count else 0.0
                ),
                "coverage_gap_count": coverage_gap_count,
                "coverage_gap_rate": (
                    round(coverage_gap_count / materialized_count, 4) if materialized_count else 0.0
                ),
                "legacy_forced_count": legacy_forced_count,
                "reviewed_count": reviewed_count,
                "verdict_counts": dict(sorted(verdict_counts.items())),
                "confirmed_rate": (
                    round(verdict_counts.get("confirmed", 0) / reviewed_count, 4) if reviewed_count else None
                ),
                "false_positive_rate": (
                    round(verdict_counts.get("false_positive", 0) / reviewed_count, 4) if reviewed_count else None
                ),
            }
        )

    pattern_rows.sort(
        key=lambda row: (
            -int(row["volume"]),
            -int(row["strong_downrank_count"]),
            row["pattern_name"],
        )
    )

    total_payloads = len(payloads)
    total_materialized = sum(1 for row in payloads if row.get("outcome") == "materialized")
    total_suppressed = sum(1 for row in payloads if row.get("outcome") == "suppressed")
    total_strong_downranks = sum(
        1
        for row in payloads
        if row.get("outcome") == "materialized"
        and row.get("ai_adjustment") is not None
        and float(row.get("ai_adjustment") or 0) <= -15.0
    )

    return {
        "artifact_type": "scoring_2_0_baseline",
        "generated_at": datetime.now(timezone.utc).isoformat(),
        "case_id": case_id,
        "analysis_ids": analysis_ids,
        "source_logs": source_logs,
        "overall": {
            "pattern_count": len(pattern_rows),
            "packages_evaluated": total_payloads,
            "materialized_count": total_materialized,
            "suppressed_count": total_suppressed,
            "suppression_rate": round(total_suppressed / total_payloads, 4) if total_payloads else 0.0,
            "strong_downrank_count": total_strong_downranks,
            "strong_downrank_rate": (
                round(total_strong_downranks / total_materialized, 4) if total_materialized else 0.0
            ),
            "reviewed_count": sum(overall_verdict_counts.values()),
            "verdict_counts": dict(sorted(overall_verdict_counts.items())),
        },
        "patterns": pattern_rows,
    }


def render_scoring_baseline_text(artifact: Dict[str, Any], *, top_n: int = 10) -> str:
    """Render the baseline artifact as a readable plain-text report."""
    overall = artifact.get("overall", {})
    lines = [
        f"Scoring 2.0 baseline artifact for case {artifact.get('case_id')}",
        f"Generated at: {artifact.get('generated_at')}",
        f"Analysis IDs: {', '.join(artifact.get('analysis_ids', [])) or 'unknown'}",
        f"Source logs: {', '.join(artifact.get('source_logs', [])) or 'none'}",
        "",
        "Overall metrics:",
        f"  Packages evaluated: {overall.get('packages_evaluated', 0)}",
        f"  Materialized: {overall.get('materialized_count', 0)}",
        f"  Suppressed: {overall.get('suppressed_count', 0)} ({overall.get('suppression_rate', 0.0):.2%})",
        f"  Strong downranks: {overall.get('strong_downrank_count', 0)} ({overall.get('strong_downrank_rate', 0.0):.2%})",
        f"  Reviewed outcomes: {overall.get('reviewed_count', 0)}",
    ]
    verdict_counts = overall.get("verdict_counts", {})
    if verdict_counts:
        lines.append(f"  Verdict counts: {json.dumps(verdict_counts, sort_keys=True)}")
    else:
        lines.append("  Verdict counts: none")

    lines.extend(["", f"Top {min(top_n, len(artifact.get('patterns', [])))} patterns by volume:"])
    for index, pattern in enumerate(artifact.get("patterns", [])[:top_n], start=1):
        verdict_text = (
            json.dumps(pattern["verdict_counts"], sort_keys=True)
            if pattern.get("verdict_counts")
            else "none"
        )
        lines.extend(
            [
                f"{index}. {pattern['pattern_name']} ({pattern['pattern_id']})",
                f"   Volume: {pattern['volume']} | Materialized: {pattern['materialized_count']} | Suppressed: {pattern['suppressed_count']} ({pattern['suppression_rate']:.2%})",
                f"   Strong downranks: {pattern['strong_downrank_count']} ({pattern['strong_downrank_rate']:.2%}) | Coverage gaps: {pattern['coverage_gap_count']} ({pattern['coverage_gap_rate']:.2%})",
                f"   Eligible to emit: {pattern['eligible_emit_count']} ({pattern['eligible_emit_rate']:.2%}) | Reviewed: {pattern['reviewed_count']} | Verdicts: {verdict_text}",
            ]
        )
    return "\n".join(lines) + "\n"
