"""Recover Hayabusa MITRE metadata for already-ingested EVTX files."""
from __future__ import annotations

import json
import os
from collections import defaultdict
from typing import Any, Dict, Iterable, List, Optional, Sequence, Tuple

from config import Config
from parsers.evtx_parser import EvtxECmdParser
from utils.clickhouse import (
    clickhouse_string_array_literal,
    get_client,
    run_events_update,
)
from utils.event_mitre_state import (
    delete_hayabusa_matches_for_case_file,
    insert_hayabusa_matches,
    rebuild_mitre_summary_columns,
)

SOURCE = "hayabusa"
SCAN_VERSION = "hayabusa-reenrichment-v1"
EVENT_BATCH_SIZE = 10000
MUTATION_RECORD_BATCH_SIZE = 5000


def _chunked(values: Sequence[Any], size: int) -> Iterable[List[Any]]:
    for offset in range(0, len(values), size):
        yield list(values[offset:offset + size])


def _normalize_record_id(value: Any) -> Optional[int]:
    try:
        return int(value)
    except (TypeError, ValueError):
        return None


def _record_id_from_detection_key(key: Any) -> Optional[int]:
    raw_key = str(key or "").strip()
    if not raw_key:
        return None
    return _normalize_record_id(raw_key.rsplit(":", 1)[-1])


def _append_unique(target: List[str], values: Iterable[Any]) -> None:
    for value in values or []:
        clean = str(value or "").strip()
        if clean and clean not in target:
            target.append(clean)


def _collect_record_mitre(detections: Sequence[Dict[str, Any]]) -> Dict[str, Any]:
    tactics: List[str] = []
    tags: List[str] = []
    max_confidence = 0
    for detection in detections or []:
        _append_unique(tactics, detection.get("mitre_tactics") or [])
        for tag in detection.get("mitre_tags") or []:
            attack_id = EvtxECmdParser._normalize_mitre_technique(tag)
            if attack_id and attack_id not in tags:
                tags.append(attack_id)
        max_confidence = max(
            max_confidence,
            EvtxECmdParser._hayabusa_confidence(detection.get("rule_level")),
        )
    return {
        "mitre_tactics": tactics,
        "mitre_tags": tags,
        "mitre_mapping_max_confidence": max_confidence,
    }


def _metadata_for_attack_ids(attack_ids: Iterable[str]) -> Dict[str, Dict[str, str]]:
    from models.mitre_attack import MitreAttackObject

    clean_ids = sorted({str(attack_id or "").strip().upper() for attack_id in attack_ids if attack_id})
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


def _query_existing_events(
    case_id: int,
    case_file_id: int,
    record_ids: Sequence[int],
    *,
    client,
) -> Dict[int, Dict[str, Any]]:
    events_by_record: Dict[int, Dict[str, Any]] = {}
    for batch in _chunked(sorted(set(record_ids)), EVENT_BATCH_SIZE):
        if not batch:
            continue
        result = client.query(
            """
            SELECT
                record_id,
                selector_key,
                artifact_type,
                source_host,
                timestamp_utc
            FROM events
            WHERE case_id = {case_id:UInt32}
              AND case_file_id = {case_file_id:UInt32}
              AND record_id IN {record_ids:Array(UInt64)}
            """,
            parameters={
                "case_id": int(case_id),
                "case_file_id": int(case_file_id),
                "record_ids": [int(record_id) for record_id in batch],
            },
        )
        for record_id, selector_key, artifact_type, source_host, timestamp_utc in result.result_rows:
            normalized = _normalize_record_id(record_id)
            if normalized is None or not selector_key:
                continue
            events_by_record[normalized] = {
                "record_id": normalized,
                "selector_key": selector_key,
                "artifact_type": artifact_type,
                "source_host": source_host,
                "timestamp": timestamp_utc,
            }
    return events_by_record


def _hayabusa_evidence_strength(level: Any) -> str:
    normalized = str(level or "").strip().lower()
    if normalized in {"critical", "crit", "high"}:
        return "high"
    if normalized in {"medium", "med"}:
        return "medium"
    return "low"


def _build_match_rows(
    case_id: int,
    detections_by_record: Dict[int, Sequence[Dict[str, Any]]],
    events_by_record: Dict[int, Dict[str, Any]],
    attack_metadata: Dict[str, Dict[str, str]],
) -> List[Dict[str, Any]]:
    best_rows: Dict[Tuple[str, str], Dict[str, Any]] = {}
    for record_id, detections in detections_by_record.items():
        event = events_by_record.get(record_id)
        if not event:
            continue
        for detection in detections or []:
            tags = [
                EvtxECmdParser._normalize_mitre_technique(tag)
                for tag in detection.get("mitre_tags") or []
            ]
            for attack_id in [tag for tag in tags if tag]:
                metadata = attack_metadata.get(attack_id, {})
                confidence = EvtxECmdParser._hayabusa_confidence(detection.get("rule_level"))
                key = (event["selector_key"], attack_id)
                row = {
                    "case_id": int(case_id),
                    "selector_key": event["selector_key"],
                    "artifact_type": event.get("artifact_type") or "evtx",
                    "source_host": event.get("source_host") or "",
                    "timestamp": event.get("timestamp"),
                    "attack_id": attack_id,
                    "attack_name": metadata.get("name") or attack_id,
                    "object_type": metadata.get("object_type") or "technique",
                    "tactic": metadata.get("tactic") or ", ".join(detection.get("mitre_tactics") or []),
                    "procedure_name": detection.get("rule_title") or "",
                    "mapping_confidence": confidence,
                    "evidence_strength": _hayabusa_evidence_strength(detection.get("rule_level")),
                    "source": SOURCE,
                    "reason": "Recovered by rerunning Hayabusa against retained EVTX original",
                    "matched_fields_json": json.dumps({
                        "record_id": record_id,
                        "rule_title": detection.get("rule_title") or "",
                        "rule_level": detection.get("rule_level") or "",
                        "rule_file": detection.get("rule_file") or "",
                    }, sort_keys=True),
                    "rule_id": detection.get("rule_file") or "",
                    "scan_version": SCAN_VERSION,
                }
                existing = best_rows.get(key)
                if not existing or confidence > int(existing.get("mapping_confidence") or 0):
                    best_rows[key] = row
    return list(best_rows.values())


def _update_legacy_event_mitre_fields(
    case_id: int,
    case_file_id: int,
    detections_by_record: Dict[int, Sequence[Dict[str, Any]]],
    events_by_record: Dict[int, Dict[str, Any]],
    *,
    client,
) -> int:
    grouped_records: Dict[Tuple[Tuple[str, ...], Tuple[str, ...], int], List[int]] = defaultdict(list)
    for record_id, detections in detections_by_record.items():
        if record_id not in events_by_record:
            continue
        summary = _collect_record_mitre(detections)
        if not summary["mitre_tags"]:
            continue
        grouped_records[
            (
                tuple(summary["mitre_tactics"]),
                tuple(summary["mitre_tags"]),
                int(summary["mitre_mapping_max_confidence"] or 0),
            )
        ].append(record_id)

    updated_records = 0
    for (tactics, tags, confidence), record_ids in grouped_records.items():
        for batch in _chunked(record_ids, MUTATION_RECORD_BATCH_SIZE):
            run_events_update(
                f"mitre_tactics = {clickhouse_string_array_literal(tactics)}, "
                f"mitre_tags = {clickhouse_string_array_literal(tags)}, "
                "mitre_attack_ids = arrayDistinct(arrayConcat("
                f"mitre_attack_ids, {clickhouse_string_array_literal(tags)})), "
                "mitre_attack_tactics = arrayDistinct(arrayConcat("
                f"mitre_attack_tactics, {clickhouse_string_array_literal(tactics)})), "
                "mitre_attack_sources = arrayDistinct(arrayConcat("
                f"mitre_attack_sources, {clickhouse_string_array_literal([SOURCE])})), "
                f"mitre_mapping_max_confidence = greatest(mitre_mapping_max_confidence, toUInt8({confidence}))",
                f"case_id = {int(case_id)} "
                f"AND case_file_id = {int(case_file_id)} "
                f"AND record_id IN ({', '.join(str(int(record_id)) for record_id in batch)})",
                client=client,
            )
            updated_records += len(batch)
    return updated_records


def _normalize_detection_keys(
    detections_by_key: Dict[str, Sequence[Dict[str, Any]]]
) -> Dict[int, Sequence[Dict[str, Any]]]:
    detections_by_record: Dict[int, List[Dict[str, Any]]] = defaultdict(list)
    for key, detections in (detections_by_key or {}).items():
        record_id = _record_id_from_detection_key(key)
        if record_id is None:
            continue
        for detection in detections or []:
            detections_by_record[record_id].append(detection)
    return dict(detections_by_record)


def _candidate_path(case_file) -> Optional[str]:
    for path in (case_file.file_path, case_file.source_path):
        if path and os.path.exists(path) and path.lower().endswith(".evtx"):
            return path
    return None


def recover_case_file_hayabusa_mitre(
    *,
    case_id: int,
    case_file,
    client=None,
) -> Dict[str, Any]:
    """Recover Hayabusa MITRE rows for one retained EVTX case file."""
    client = client or get_client()
    file_path = _candidate_path(case_file)
    if not file_path:
        return {
            "case_file_id": case_file.id,
            "status": "skipped_missing_evtx",
            "matches_inserted": 0,
            "events_updated": 0,
        }

    parser = EvtxECmdParser(
        case_id=case_id,
        source_host=case_file.hostname or "",
        case_file_id=case_file.id,
        hayabusa_profile=Config.HAYABUSA_PROFILE,
    )
    detections_by_record = _normalize_detection_keys(parser._get_hayabusa_detections(file_path))
    record_ids = sorted(detections_by_record)
    if not record_ids:
        delete_hayabusa_matches_for_case_file(case_id, case_file.id, client=client)
        return {
            "case_file_id": case_file.id,
            "status": "no_hayabusa_detections",
            "matches_inserted": 0,
            "events_updated": 0,
        }

    events_by_record = _query_existing_events(
        case_id,
        case_file.id,
        record_ids,
        client=client,
    )
    if not events_by_record:
        return {
            "case_file_id": case_file.id,
            "status": "no_existing_events_matched",
            "matches_inserted": 0,
            "events_updated": 0,
        }

    all_attack_ids = {
        attack_id
        for detections in detections_by_record.values()
        for detection in detections
        for attack_id in [
            EvtxECmdParser._normalize_mitre_technique(tag)
            for tag in detection.get("mitre_tags") or []
        ]
        if attack_id
    }
    attack_metadata = _metadata_for_attack_ids(all_attack_ids)
    match_rows = _build_match_rows(case_id, detections_by_record, events_by_record, attack_metadata)
    delete_hayabusa_matches_for_case_file(case_id, case_file.id, client=client)
    matches_inserted = insert_hayabusa_matches(case_id, match_rows, client=client)
    events_updated = _update_legacy_event_mitre_fields(
        case_id,
        case_file.id,
        detections_by_record,
        events_by_record,
        client=client,
    )
    return {
        "case_file_id": case_file.id,
        "status": "recovered",
        "records_with_detections": len(record_ids),
        "records_matched": len(events_by_record),
        "matches_inserted": matches_inserted,
        "events_updated": events_updated,
    }


def recover_case_hayabusa_mitre(
    *,
    case_id: int,
    case_file_ids: Optional[Sequence[int]] = None,
    client=None,
) -> Dict[str, Any]:
    """Recover Hayabusa MITRE metadata for retained EVTX files in one case."""
    from models.case import Case
    from models.case_file import CaseFile

    client = client or get_client()
    case = Case.get_by_id_unchecked(case_id)
    if not case:
        return {"success": False, "error": f"Case {case_id} not found"}

    query = CaseFile.query.filter(
        CaseFile.case_uuid == case.uuid,
        CaseFile.is_archive.is_(False),
    )
    if case_file_ids:
        query = query.filter(CaseFile.id.in_([int(value) for value in case_file_ids]))
    else:
        query = query.filter(
            CaseFile.status == "done",
            CaseFile.ingestion_status.in_(["full", "partial"]),
        ).filter(
            CaseFile.parser_type == "evtx"
        )

    results = []
    for case_file in query.order_by(CaseFile.id.asc()).all():
        results.append(
            recover_case_file_hayabusa_mitre(
                case_id=case_id,
                case_file=case_file,
                client=client,
            )
        )

    rebuild_groups = rebuild_mitre_summary_columns(case_id, client=client)
    return {
        "success": True,
        "case_id": int(case_id),
        "files_scanned": len(results),
        "files_recovered": sum(1 for result in results if result.get("status") == "recovered"),
        "files_missing_evtx": sum(1 for result in results if result.get("status") == "skipped_missing_evtx"),
        "matches_inserted": sum(int(result.get("matches_inserted") or 0) for result in results),
        "events_updated": sum(int(result.get("events_updated") or 0) for result in results),
        "summary_groups_rebuilt": rebuild_groups,
        "results": results,
    }
