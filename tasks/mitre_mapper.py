"""Case-level MITRE procedure mapping task."""
from __future__ import annotations

import logging
from typing import Any, Dict

from tasks.celery_tasks import celery_app, get_flask_app

logger = logging.getLogger(__name__)


def mitre_mapping_marker_name(case_id: int) -> str:
    return f"mitre_mapping_case_{int(case_id)}"


def _load_attack_metadata(attack_ids):
    from models.mitre_attack import MitreAttackObject

    rows = MitreAttackObject.query.filter(
        MitreAttackObject.external_id.in_(list(attack_ids)),
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


@celery_app.task(bind=True, name="tasks.mitre_mapper.map_case_mitre_procedures")
def map_case_mitre_procedures(self, case_id: int, username: str = "system") -> Dict[str, Any]:
    """Map case events to deterministic MITRE procedure candidates."""
    from utils.global_task_markers import clear_global_task_inflight, mark_global_task_inflight

    marker_name = mitre_mapping_marker_name(case_id)
    mark_global_task_inflight(marker_name, task_id=self.request.id)
    app = get_flask_app()

    try:
        with app.app_context():
            from utils.clickhouse import get_fresh_client
            from utils.event_mitre_state import (
                get_mitre_mapping_stats,
                insert_mitre_rule_matches,
                rebuild_mitre_summary_columns,
                start_mitre_mapping_scan,
            )
            from utils.mitre_procedure_rules import get_mitre_procedure_rules

            client = get_fresh_client()
            rules = get_mitre_procedure_rules()

            self.update_state(state="PROGRESS", meta={
                "progress": 0,
                "status": "Loading MITRE procedure rules...",
            })

            total_result = client.query(
                "SELECT count() FROM events WHERE case_id = {case_id:UInt32}",
                parameters={"case_id": int(case_id)},
            )
            total_events = int(total_result.result_rows[0][0]) if total_result.result_rows else 0
            if total_events <= 0:
                return {
                    "success": True,
                    "case_id": int(case_id),
                    "total_events": 0,
                    "mapped_events": 0,
                    "total_matches": 0,
                    "rule_matches": [],
                    "message": "No events in case",
                }

            attack_ids = {
                attack_id
                for rule in rules
                for attack_id in (rule.get("attack_ids") or [])
            }
            attack_metadata = _load_attack_metadata(attack_ids)

            self.update_state(state="PROGRESS", meta={
                "progress": 5,
                "status": f"Preparing MITRE mapping rebuild for {total_events:,} events...",
            })
            scan_version = start_mitre_mapping_scan(case_id, updated_by=username, client=client)

            rule_matches = []
            for idx, rule in enumerate(rules, start=1):
                progress = 5 + int((idx / max(len(rules), 1)) * 90)
                self.update_state(state="PROGRESS", meta={
                    "progress": progress,
                    "status": f"Processing MITRE rule {idx}/{len(rules)}: {rule.get('name')}",
                })

                try:
                    match_count = insert_mitre_rule_matches(
                        case_id,
                        scan_version,
                        rule=rule,
                        attack_metadata=attack_metadata,
                        updated_by=username,
                        client=client,
                    )
                except Exception as exc:
                    logger.exception("MITRE rule failed: %s", rule.get("id"))
                    rule_matches.append({
                        "id": rule.get("id"),
                        "name": rule.get("name"),
                        "attack_ids": rule.get("attack_ids", []),
                        "count": 0,
                        "error": str(exc),
                    })
                    continue

                if match_count > 0:
                    rule_matches.append({
                        "id": rule.get("id"),
                        "name": rule.get("name"),
                        "attack_ids": rule.get("attack_ids", []),
                        "count": match_count,
                        "mapping_confidence": rule.get("mapping_confidence"),
                        "evidence_strength": rule.get("evidence_strength"),
                    })

            self.update_state(state="PROGRESS", meta={
                "progress": 98,
                "status": "Rebuilding MITRE mapping summary cache...",
            })

            rebuild_mitre_summary_columns(case_id, client=client)

            self.update_state(state="PROGRESS", meta={
                "progress": 99,
                "status": "Finalizing MITRE mapping statistics...",
            })

            stats = get_mitre_mapping_stats(case_id, client=client)
            result = {
                "success": True,
                "case_id": int(case_id),
                "total_events": total_events,
                "mapped_events": stats["mapped_events"],
                "total_matches": stats["total_matches"],
                "mapped_percentage": stats["mapped_percentage"],
                "last_scan": stats["last_scan"],
                "top_techniques": stats["top_techniques"],
                "artifact_types": stats["artifact_types"],
                "rule_matches": sorted(rule_matches, key=lambda item: item.get("count", 0), reverse=True),
                "scan_version": scan_version,
            }

            logger.info(
                "MITRE mapping complete for case %s: %s events, %s matches",
                case_id,
                result["mapped_events"],
                result["total_matches"],
            )
            return result
    finally:
        clear_global_task_inflight(marker_name)
