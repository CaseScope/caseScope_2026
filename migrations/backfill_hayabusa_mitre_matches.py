#!/usr/bin/env python3
"""Backfill Hayabusa MITRE matches from legacy event columns.

Usage:
    python migrations/backfill_hayabusa_mitre_matches.py [--case-id CASE_ID]
"""
from __future__ import annotations

import argparse
import json
import os
import re
import sys
from typing import Any, Dict, Iterable, List, Optional, Set

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from app import create_app
from models.mitre_attack import MitreAttackObject
from utils.clickhouse import get_fresh_client
from utils.event_mitre_state import (
    ensure_event_mitre_state_tables,
    insert_hayabusa_matches,
    rebuild_mitre_summary_columns,
)


MITRE_TECHNIQUE_RE = re.compile(r"^T\d{4}(?:\.\d{3})?$", re.IGNORECASE)
HAYABUSA_CONFIDENCE = {
    "informational": 25,
    "info": 25,
    "low": 40,
    "medium": 60,
    "med": 60,
    "high": 75,
    "critical": 90,
    "crit": 90,
}


def _normalize_mitre_technique(value: Any) -> str:
    normalized = str(value or "").strip().upper()
    return normalized if MITRE_TECHNIQUE_RE.match(normalized) else ""


def _confidence_for_level(level: Any) -> int:
    return HAYABUSA_CONFIDENCE.get(str(level or "").strip().lower(), 0)


def _evidence_strength(level: Any) -> str:
    normalized = str(level or "").strip().lower()
    if normalized in {"critical", "crit", "high"}:
        return "high"
    if normalized in {"medium", "med"}:
        return "medium"
    return "low"


def _load_attack_metadata(attack_ids: Iterable[str]) -> Dict[str, Dict[str, str]]:
    clean_ids = sorted({attack_id for attack_id in attack_ids if attack_id})
    if not clean_ids:
        return {}
    rows = MitreAttackObject.query.filter(
        MitreAttackObject.external_id.in_(clean_ids),
        MitreAttackObject.object_type.in_(["technique", "sub_technique"]),
    ).all()
    return {
        row.external_id: {
            "name": row.name,
            "object_type": row.object_type,
            "tactic": row.tactic_name or "",
        }
        for row in rows
        if row.external_id
    }


def _detections_from_event(row: Dict[str, Any]) -> List[Dict[str, Any]]:
    try:
        extra = json.loads(row.get("extra_fields") or "{}")
    except (TypeError, ValueError, json.JSONDecodeError):
        extra = {}
    detections = extra.get("hayabusa_detections")
    if isinstance(detections, list) and detections:
        return [detection for detection in detections if isinstance(detection, dict)]
    return [
        {
            "rule_title": row.get("rule_title"),
            "rule_level": row.get("rule_level"),
            "rule_file": row.get("rule_file"),
            "mitre_tags": row.get("mitre_tags") or [],
        }
    ]


def _build_match_rows(event_rows: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
    attack_ids: Set[str] = set()
    detections_by_selector = {}
    for event_row in event_rows:
        detections = _detections_from_event(event_row)
        detections_by_selector[event_row["selector_key"]] = detections
        for detection in detections:
            for tag in detection.get("mitre_tags") or []:
                attack_id = _normalize_mitre_technique(tag)
                if attack_id:
                    attack_ids.add(attack_id)

    metadata_by_id = _load_attack_metadata(attack_ids)
    rows_by_key = {}
    for event_row in event_rows:
        selector_key = event_row["selector_key"]
        for detection in detections_by_selector.get(selector_key, []):
            level = detection.get("rule_level") or event_row.get("rule_level")
            confidence = _confidence_for_level(level)
            for tag in detection.get("mitre_tags") or []:
                attack_id = _normalize_mitre_technique(tag)
                if not attack_id:
                    continue
                existing = rows_by_key.get((selector_key, attack_id))
                if existing and existing["mapping_confidence"] >= confidence:
                    continue
                metadata = metadata_by_id.get(attack_id, {})
                rows_by_key[(selector_key, attack_id)] = {
                    "selector_key": selector_key,
                    "artifact_type": event_row.get("artifact_type") or "",
                    "source_host": event_row.get("source_host") or "",
                    "timestamp": event_row.get("timestamp"),
                    "attack_id": attack_id,
                    "attack_name": metadata.get("name") or attack_id,
                    "object_type": metadata.get("object_type") or "",
                    "tactic": metadata.get("tactic") or "",
                    "procedure_name": detection.get("rule_title") or event_row.get("rule_title") or "",
                    "mapping_confidence": confidence,
                    "evidence_strength": _evidence_strength(level),
                    "reason": "Hayabusa Sigma detection",
                    "matched_fields_json": "{}",
                    "rule_id": detection.get("rule_file") or event_row.get("rule_file") or "",
                    "scan_version": "hayabusa_backfill",
                }
    return list(rows_by_key.values())


def _case_ids(client, case_id: Optional[int]) -> List[int]:
    if case_id is not None:
        return [int(case_id)]
    result = client.query(
        """
        SELECT DISTINCT case_id
        FROM events
        WHERE length(mitre_tags) > 0
        ORDER BY case_id
        """
    )
    return [int(row[0]) for row in result.result_rows]


def backfill_case(client, case_id: int, *, batch_size: int) -> Dict[str, int]:
    total_result = client.query(
        """
        SELECT count()
        FROM events
        WHERE case_id = {case_id:UInt32}
          AND length(mitre_tags) > 0
        """,
        parameters={"case_id": int(case_id)},
    )
    total_events = int(total_result.result_rows[0][0]) if total_result.result_rows else 0
    print(f"Case {case_id}: {total_events:,} legacy Hayabusa-tagged events")

    stats = {"events_seen": total_events, "events_processed": 0, "rows_inserted": 0}
    while True:
        result = client.query(
            """
            SELECT
                selector_key,
                artifact_type,
                source_host,
                timestamp_utc,
                rule_title,
                rule_level,
                rule_file,
                mitre_tags,
                extra_fields
            FROM events
            WHERE case_id = {case_id:UInt32}
              AND length(mitre_tags) > 0
              AND selector_key NOT IN (
                  SELECT selector_key
                  FROM event_mitre_matches
                  WHERE case_id = {case_id:UInt32}
                    AND source = 'hayabusa'
              )
            ORDER BY timestamp_utc, selector_key
            LIMIT {limit:UInt32}
            """,
            parameters={
                "case_id": int(case_id),
                "limit": int(batch_size),
            },
        )
        if not result.result_rows:
            break

        event_rows = [
            {
                "selector_key": row[0],
                "artifact_type": row[1],
                "source_host": row[2],
                "timestamp": row[3],
                "rule_title": row[4],
                "rule_level": row[5],
                "rule_file": row[6],
                "mitre_tags": list(row[7] or []),
                "extra_fields": row[8],
            }
            for row in result.result_rows
            if row[0]
        ]
        match_rows = _build_match_rows(event_rows)
        if not match_rows:
            stats["events_processed"] += len(event_rows)
            print(
                f"Case {case_id}: stopping after {len(event_rows):,} events with no valid "
                "Hayabusa ATT&CK IDs to insert"
            )
            break
        inserted = insert_hayabusa_matches(case_id, match_rows, client=client)
        stats["events_processed"] += len(event_rows)
        stats["rows_inserted"] += inserted
        if inserted <= 0:
            print(f"Case {case_id}: stopping because no new Hayabusa rows were inserted")
            break
        print(
            f"Case {case_id}: processed {stats['events_processed']:,} events, "
            f"inserted {stats['rows_inserted']:,} rows"
        )

    rebuild_groups = rebuild_mitre_summary_columns(case_id, client=client)
    stats["summary_groups_rebuilt"] = rebuild_groups
    print(f"Case {case_id}: rebuilt {rebuild_groups:,} summary groups")
    return stats


def run_migration(case_id: Optional[int], batch_size: int) -> Dict[str, int]:
    app = create_app(run_startup_bootstrap=False, register_blueprints=False)
    client = get_fresh_client()
    ensure_event_mitre_state_tables(client)

    totals = {"cases": 0, "events_processed": 0, "rows_inserted": 0}
    with app.app_context():
        for current_case_id in _case_ids(client, case_id):
            totals["cases"] += 1
            stats = backfill_case(client, current_case_id, batch_size=batch_size)
            totals["events_processed"] += stats.get("events_processed", 0)
            totals["rows_inserted"] += stats.get("rows_inserted", 0)

    print(
        "Backfill complete: "
        f"{totals['cases']} cases, "
        f"{totals['events_processed']:,} events processed, "
        f"{totals['rows_inserted']:,} rows inserted"
    )
    return totals


def main() -> int:
    parser = argparse.ArgumentParser(description="Backfill Hayabusa MITRE match rows")
    parser.add_argument("--case-id", type=int, default=None, help="Limit backfill to a single case ID")
    parser.add_argument("--batch-size", type=int, default=5000, help="Events to read per batch")
    args = parser.parse_args()

    run_migration(case_id=args.case_id, batch_size=max(1, args.batch_size))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
