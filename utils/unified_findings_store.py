"""ClickHouse-backed mirror for canonical unified findings."""

from __future__ import annotations

import json
import logging
from datetime import datetime
from typing import Any, Dict, List, Optional, Tuple

from utils.clickhouse import get_client
from utils.finding_contract import canonicalize_finding, normalize_string_list

logger = logging.getLogger(__name__)

UNIFIED_FINDINGS_TABLE = "case_unified_findings"


def _stringify(value: Any) -> str:
    return str(value or "").strip()


def _json_dumps(value: Any) -> str:
    return json.dumps(value or {}, default=str, sort_keys=True)


def ensure_unified_findings_table(client=None) -> None:
    client = client or get_client()
    client.command(
        f"""
        CREATE TABLE IF NOT EXISTS {UNIFIED_FINDINGS_TABLE} (
            case_id UInt32,
            analysis_id String,
            finding_id String,
            source_system LowCardinality(String),
            category String,
            rule_pack LowCardinality(String),
            rule_id String,
            name String,
            severity LowCardinality(String),
            confidence Float64,
            host String,
            user String,
            process String,
            first_seen String,
            last_seen String,
            mitre_techniques Array(String),
            event_ids Array(String),
            dedup_key String,
            canonical_json String,
            legacy_json String,
            synced_at DateTime DEFAULT now()
        )
        ENGINE = MergeTree
        ORDER BY (case_id, analysis_id, source_system, dedup_key, finding_id)
        """
    )


def _prepare_store_row(
    *,
    case_id: int,
    analysis_id: str,
    raw_finding: Any,
) -> Optional[Tuple[Any, ...]]:
    if hasattr(raw_finding, "to_dict"):
        raw = raw_finding.to_dict()
    elif isinstance(raw_finding, dict):
        raw = dict(raw_finding)
    else:
        return None

    canonical = canonicalize_finding(
        raw,
        default_rule_pack="analysis",
        default_rule_id=raw.get("pattern_id") or raw.get("finding_type") or raw.get("type") or "",
    )
    source_system = _stringify(raw.get("source_system") or canonical.get("rule_pack") or raw.get("type") or "analysis")
    category = _stringify(raw.get("category") or raw.get("finding_type") or raw.get("type"))
    finding_id = _stringify(raw.get("id") or canonical.get("dedup_key"))

    combined = {**raw, **canonical}
    return (
        int(case_id),
        _stringify(analysis_id),
        finding_id,
        source_system,
        category,
        _stringify(canonical.get("rule_pack")),
        _stringify(canonical.get("rule_id")),
        _stringify(canonical.get("name")),
        _stringify(canonical.get("severity")),
        float(canonical.get("confidence") or 0.0),
        _stringify(canonical.get("host")),
        _stringify(canonical.get("user")),
        _stringify(canonical.get("process")),
        _stringify(canonical.get("first_seen")),
        _stringify(canonical.get("last_seen")),
        normalize_string_list(canonical.get("mitre_techniques")),
        normalize_string_list(canonical.get("event_ids")),
        _stringify(canonical.get("dedup_key")),
        _json_dumps(canonical),
        _json_dumps(combined),
    )


def sync_case_findings(case_id: int, analysis_id: str, findings: List[Any], client=None) -> int:
    """Mirror the finalized analysis findings into ClickHouse."""
    client = client or get_client()
    ensure_unified_findings_table(client)

    rows: List[Tuple[Any, ...]] = []
    seen = set()
    for finding in findings or []:
        row = _prepare_store_row(case_id=case_id, analysis_id=analysis_id, raw_finding=finding)
        if not row:
            continue
        key = (row[3], row[17], row[2])  # source_system, dedup_key, finding_id
        if key in seen:
            continue
        seen.add(key)
        rows.append(row)

    if not rows:
        return 0

    client.insert(
        UNIFIED_FINDINGS_TABLE,
        rows,
        column_names=[
            "case_id",
            "analysis_id",
            "finding_id",
            "source_system",
            "category",
            "rule_pack",
            "rule_id",
            "name",
            "severity",
            "confidence",
            "host",
            "user",
            "process",
            "first_seen",
            "last_seen",
            "mitre_techniques",
            "event_ids",
            "dedup_key",
            "canonical_json",
            "legacy_json",
        ],
    )
    return len(rows)


def load_case_findings(case_id: int, client=None) -> Optional[List[Dict[str, Any]]]:
    """Load the latest mirrored findings for a case from ClickHouse."""
    client = client or get_client()
    try:
        latest = client.query(
            f"""
            SELECT analysis_id
            FROM {UNIFIED_FINDINGS_TABLE}
            WHERE case_id = {{case_id:UInt32}}
            ORDER BY synced_at DESC
            LIMIT 1
            """,
            parameters={"case_id": int(case_id)},
        )
    except Exception as exc:
        logger.debug("[UnifiedFindingsStore] ClickHouse unified-findings lookup unavailable: %s", exc)
        return None

    if not latest.result_rows:
        return None

    analysis_id = latest.result_rows[0][0]
    result = client.query(
        f"""
        SELECT legacy_json
        FROM {UNIFIED_FINDINGS_TABLE}
        WHERE case_id = {{case_id:UInt32}} AND analysis_id = {{analysis_id:String}}
        ORDER BY confidence DESC, severity ASC
        """,
        parameters={
            "case_id": int(case_id),
            "analysis_id": str(analysis_id),
        },
    )

    findings: List[Dict[str, Any]] = []
    for (legacy_json,) in result.result_rows:
        try:
            findings.append(json.loads(legacy_json or "{}"))
        except json.JSONDecodeError:
            continue
    return findings
