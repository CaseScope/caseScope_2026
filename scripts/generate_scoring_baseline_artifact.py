#!/usr/bin/env python3
"""Generate a Scoring 2.0 baseline artifact from hunting telemetry."""

from __future__ import annotations

import argparse
import json
from pathlib import Path

from app import create_app
from models.database import db
from models.rag import AIAnalysisResult, AnalystVerdict
from utils.hunting_logger import list_hunting_logs
from utils.scoring_baseline_artifact import (
    build_scoring_baseline_artifact,
    load_scoring_telemetry_from_log,
    render_scoring_baseline_text,
)

REPO_ROOT = Path(__file__).resolve().parents[1]


def resolve_log_path(case_id: int, explicit_path: str | None) -> Path:
    """Resolve the requested hunting log path."""
    if explicit_path:
        return Path(explicit_path).resolve()

    logs = list_hunting_logs(case_id)
    if not logs:
        raise FileNotFoundError(f"No hunting logs found for case {case_id}")
    return Path(logs[0]["path"]).resolve()


def load_latest_verdict_rows(case_id: int, analysis_ids: list[str]) -> list[dict[str, str]]:
    """Load the latest analyst verdict row per AI analysis result for the run."""
    if not analysis_ids:
        return []

    app = create_app()
    with app.app_context():
        rows = (
            db.session.query(AnalystVerdict, AIAnalysisResult)
            .join(AIAnalysisResult, AnalystVerdict.analysis_result_id == AIAnalysisResult.id)
            .filter(AIAnalysisResult.case_id == case_id)
            .filter(AIAnalysisResult.analysis_id.in_(analysis_ids))
            .order_by(AnalystVerdict.analysis_result_id, AnalystVerdict.created_at.desc())
            .all()
        )

        latest: dict[int, dict[str, str]] = {}
        for verdict, analysis_result in rows:
            if verdict.analysis_result_id in latest:
                continue
            latest[verdict.analysis_result_id] = {
                "pattern_id": analysis_result.pattern_id or "",
                "correlation_key": analysis_result.correlation_key or "",
                "verdict": verdict.verdict or "",
            }
        return list(latest.values())


def main() -> None:
    parser = argparse.ArgumentParser(
        description="Generate a Scoring 2.0 baseline artifact from ai_hunting logs."
    )
    parser.add_argument("--case-id", type=int, required=True, help="Internal case ID")
    parser.add_argument("--log-path", help="Explicit hunting log path to parse")
    parser.add_argument(
        "--output-json",
        help="Output JSON path",
    )
    parser.add_argument(
        "--output-txt",
        help="Output text report path",
    )
    args = parser.parse_args()

    log_path = resolve_log_path(args.case_id, args.log_path)
    payloads = load_scoring_telemetry_from_log(log_path)
    if not payloads:
        raise RuntimeError(f"No scoring telemetry found in {log_path}")

    artifact_stub = build_scoring_baseline_artifact(
        case_id=args.case_id,
        source_logs=[str(log_path)],
        telemetry_payloads=payloads,
        analyst_verdicts=[],
    )
    verdict_rows = load_latest_verdict_rows(args.case_id, artifact_stub.get("analysis_ids", []))
    artifact = build_scoring_baseline_artifact(
        case_id=args.case_id,
        source_logs=[str(log_path)],
        telemetry_payloads=payloads,
        analyst_verdicts=verdict_rows,
    )

    output_json = Path(
        args.output_json or REPO_ROOT / "_REFACTOR" / f"scoring_2_0_case_{args.case_id}_baseline_artifact.json"
    )
    output_txt = Path(
        args.output_txt or REPO_ROOT / "_REFACTOR" / f"scoring_2_0_case_{args.case_id}_baseline_artifact.txt"
    )
    output_json.parent.mkdir(parents=True, exist_ok=True)
    output_txt.parent.mkdir(parents=True, exist_ok=True)

    output_json.write_text(json.dumps(artifact, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    output_txt.write_text(render_scoring_baseline_text(artifact), encoding="utf-8")

    print(f"Wrote baseline artifact JSON to {output_json}")
    print(f"Wrote baseline artifact text to {output_txt}")


if __name__ == "__main__":
    main()
