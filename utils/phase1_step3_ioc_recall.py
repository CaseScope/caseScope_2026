"""Phase 1.5 IOC recall comparator (dry-run).

Does not mutate IOC rows, IOCEvidenceMatch rows, or events.ioc_types.
Compares legacy match set A against independently measured candidate paths.
"""
from __future__ import annotations

import hashlib
import json
import logging
import time
from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Any, Dict, Iterable, List, Optional, Sequence, Set, Tuple

from models.ioc import detect_match_type
from parsers.base import ParsedEvent
from utils.ioc_artifact_tagger import build_ioc_match_clause, build_substring_match_clause

logger = logging.getLogger(__name__)

PATH_LEGACY = "legacy"
PATH_NO_LOWER = "no_lower_sensitive"
PATH_ILIKE = "ilike"
PATH_NO_RAW_JSON = "no_raw_json"
PATH_STRUCTURED_BLOB = "structured_plus_search_blob"

MISS_RAW_JSON_ONLY = "RAW_JSON_ONLY_TRUE_MATCH"
MISS_BLOB_OMISSION = "SEARCH_BLOB_BUILDER_OMISSION"
MISS_TYPED_OMISSION = "TYPED_COLUMN_OMISSION"
MISS_NORMALIZATION = "NORMALIZATION_DIFFERENCE"
MISS_LEGACY_FP = "LEGACY_FALSE_POSITIVE"
MISS_OTHER = "OTHER"

STRUCTURED_COLUMNS_BY_TYPE = {
    "Username": ["username"],
    "SID": ["sid"],
    "IP Address (IPv4)": ["toString(src_ip)", "toString(dst_ip)"],
    "Hostname": ["source_host", "workstation_name", "remote_host"],
    "FQDN": ["source_host", "remote_host"],
    "Domain": ["source_host", "remote_host"],
    "File Name": ["process_name", "target_path"],
    "File Path": ["process_path", "target_path", "command_line"],
    "Process Name": ["process_name"],
    "Process Path": ["process_path"],
    "Command Line": ["command_line"],
    "Registry Key": ["reg_key"],
    "Registry Value": ["reg_value", "reg_data"],
    "MD5 Hash": ["file_hash_md5"],
    "SHA1 Hash": ["file_hash_sha1"],
    "SHA256 Hash": ["file_hash_sha256"],
}

CANONICAL_STORED_COLUMNS = {
    # No IOC common-path column is currently stored lowercase. username,
    # search_blob, and raw_json retain source case. Hashes are not proven
    # canonical across parsers in this step.
}


def _clean(value: Any) -> str:
    return str(value or "").strip()


def match_key(case_id: int, erk: str, ioc_uuid: str) -> Tuple[int, str, str]:
    return (int(case_id), _clean(erk), _clean(ioc_uuid))


def columns_for_path(ioc_type: str, path: str) -> Optional[List[str]]:
    """Return explicit columns for a candidate path, or None for production default."""
    if path in (PATH_LEGACY, PATH_NO_LOWER, PATH_ILIKE):
        return None
    structured = list(STRUCTURED_COLUMNS_BY_TYPE.get(ioc_type or "", []))
    if path == PATH_NO_RAW_JSON:
        if ioc_type == "Username":
            return ["username", "search_blob"]
        return ["search_blob"]
    if path == PATH_STRUCTURED_BLOB:
        cols = structured + ["search_blob"]
        if ioc_type == "Username" and "username" not in cols:
            cols.insert(0, "username")
        # Deduplicate preserving order
        seen = set()
        out = []
        for col in cols:
            if col not in seen:
                seen.add(col)
                out.append(col)
        return out or ["search_blob"]
    raise ValueError(f"Unknown IOC query path: {path}")


def case_mode_for_path(path: str) -> str:
    if path == PATH_NO_LOWER:
        return "sensitive"
    if path == PATH_ILIKE:
        return "ilike"
    return "lower"


def build_path_clause(
    ioc_value: str,
    ioc_type: str,
    match_type: str,
    aliases: Optional[List[str]] = None,
    path: str = PATH_LEGACY,
) -> str:
    return build_ioc_match_clause(
        ioc_value,
        ioc_type,
        match_type,
        aliases=aliases,
        columns=columns_for_path(ioc_type, path),
        case_mode=case_mode_for_path(path),
    )


def source_predicates(ioc_value: str, ioc_type: str, match_type: str) -> Dict[str, str]:
    """Independent predicates used to classify which store produced a match."""
    structured_cols = columns_for_path(ioc_type, PATH_STRUCTURED_BLOB) or ["search_blob"]
    structured_only = [c for c in structured_cols if c != "search_blob"]
    preds = {
        "search_blob": build_ioc_match_clause(
            ioc_value, ioc_type, match_type, columns=["search_blob"], case_mode="lower"
        ),
        "raw_json": build_ioc_match_clause(
            ioc_value, ioc_type, match_type, columns=["raw_json"], case_mode="lower"
        ),
        "extra_fields": build_substring_match_clause(
            ioc_value, ["extra_fields"], case_mode="lower"
        ),
    }
    if ioc_type == "Username":
        preds["username"] = build_ioc_match_clause(
            ioc_value, ioc_type, match_type, columns=["username"], case_mode="lower"
        )
    if structured_only:
        preds["structured"] = build_ioc_match_clause(
            ioc_value, ioc_type, match_type, columns=structured_only, case_mode="lower"
        )
    else:
        preds["structured"] = "0"
    return preds


@dataclass
class IocSpec:
    case_id: int
    uuid: str
    ioc_type: str
    value: str
    match_type: Optional[str] = None
    aliases: Optional[List[str]] = None
    label: str = ""

    def effective_match_type(self) -> str:
        return self.match_type or detect_match_type(self.value, self.ioc_type)


@dataclass
class MatchRecord:
    case_id: int
    erk: str
    ioc_uuid: str
    ioc_type: str
    ioc_value: str
    path: str
    artifact_type: str = ""
    hit_search_blob: Optional[bool] = None
    hit_raw_json: Optional[bool] = None
    hit_structured: Optional[bool] = None
    hit_username: Optional[bool] = None
    hit_extra_fields: Optional[bool] = None
    matched_field: str = ""
    matched_value_class: str = ""

    def key(self) -> Tuple[int, str, str]:
        return match_key(self.case_id, self.erk, self.ioc_uuid)


def classify_matched_field(record: MatchRecord) -> str:
    if record.hit_username:
        return "username"
    if record.hit_structured and not record.hit_search_blob and not record.hit_raw_json:
        return "structured"
    if record.hit_search_blob:
        return "search_blob"
    if record.hit_raw_json:
        return "raw_json"
    if record.hit_extra_fields:
        return "extra_fields"
    return "unknown"


def classify_miss(record: MatchRecord) -> str:
    """Classify an A-B miss. A legacy false positive requires contract evidence."""
    if record.hit_raw_json and not record.hit_search_blob and not record.hit_structured and not record.hit_username:
        if record.hit_extra_fields:
            return MISS_OTHER
        return MISS_RAW_JSON_ONLY
    if record.hit_structured and not record.hit_search_blob:
        return MISS_TYPED_OMISSION
    if record.hit_search_blob is False and record.hit_raw_json:
        return MISS_BLOB_OMISSION
    if record.hit_search_blob is False and record.hit_raw_json is False and record.hit_structured is False:
        return MISS_NORMALIZATION
    return MISS_OTHER


class CountingClient:
    """Wrap a ClickHouse client and count statements / wall time."""

    def __init__(self, client):
        self.client = client
        self.statements = 0
        self.query_wall_ms = 0.0
        self.rows_returned = 0
        self.sql: List[str] = []

    def query(self, sql, parameters=None):
        started = time.perf_counter()
        result = self.client.query(sql, parameters=parameters)
        self.query_wall_ms += (time.perf_counter() - started) * 1000.0
        self.statements += 1
        self.sql.append(" ".join(str(sql).split())[:500])
        rows = getattr(result, "result_rows", None) or []
        self.rows_returned += len(rows)
        return result

    def command(self, sql, parameters=None):
        started = time.perf_counter()
        result = self.client.command(sql, parameters=parameters)
        self.query_wall_ms += (time.perf_counter() - started) * 1000.0
        self.statements += 1
        return result

    def insert(self, *args, **kwargs):
        return self.client.insert(*args, **kwargs)


def stream_matches(
    client,
    spec: IocSpec,
    path: str,
    *,
    batch_size: int = 5000,
    classify_sources: bool = False,
    max_rows: Optional[int] = None,
) -> List[MatchRecord]:
    """Dry-run stream of matching ERKs for one IOC on one path."""
    where_clause = build_path_clause(
        spec.value,
        spec.ioc_type,
        spec.effective_match_type(),
        aliases=spec.aliases,
        path=path,
    )
    preds = source_predicates(spec.value, spec.ioc_type, spec.effective_match_type()) if classify_sources else {}
    select_flags = ""
    if classify_sources:
        select_flags = f""",
            ({preds['search_blob']}) AS hit_search_blob,
            ({preds['raw_json']}) AS hit_raw_json,
            ({preds.get('structured', '0')}) AS hit_structured,
            ({preds.get('username', '0')}) AS hit_username,
            ({preds['extra_fields']}) AS hit_extra_fields
        """
    records: List[MatchRecord] = []
    offset = 0
    batch_size = max(1, int(batch_size))
    while True:
        limit = batch_size
        if max_rows is not None:
            remaining = max_rows - len(records)
            if remaining <= 0:
                break
            limit = min(batch_size, remaining)
        query = f"""
            SELECT evidence_record_key, artifact_type {select_flags}
            FROM events
            WHERE case_id = {int(spec.case_id)}
              AND evidence_record_key != ''
              AND ({where_clause})
            ORDER BY evidence_record_key
            LIMIT {limit} OFFSET {offset}
        """
        result = client.query(query)
        rows = result.result_rows or []
        if not rows:
            break
        for row in rows:
            rec = MatchRecord(
                case_id=spec.case_id,
                erk=_clean(row[0]),
                ioc_uuid=spec.uuid,
                ioc_type=spec.ioc_type,
                ioc_value=spec.value,
                path=path,
                artifact_type=_clean(row[1]) if len(row) > 1 else "",
            )
            if classify_sources and len(row) >= 7:
                rec.hit_search_blob = bool(row[2])
                rec.hit_raw_json = bool(row[3])
                rec.hit_structured = bool(row[4])
                rec.hit_username = bool(row[5])
                rec.hit_extra_fields = bool(row[6])
                rec.matched_field = classify_matched_field(rec)
                rec.matched_value_class = rec.matched_field
            records.append(rec)
        if len(rows) < limit:
            break
        offset += limit
    return records


def compare_sets(
    set_a: Iterable[Tuple[int, str, str]],
    set_b: Iterable[Tuple[int, str, str]],
) -> Dict[str, Any]:
    a = set(set_a)
    b = set(set_b)
    return {
        "a_count": len(a),
        "b_count": len(b),
        "a_minus_b": sorted(a - b),
        "b_minus_a": sorted(b - a),
        "intersection": len(a & b),
        "a_minus_b_count": len(a - b),
        "b_minus_a_count": len(b - a),
        "recall_gate_pass": len(a - b) == 0,
    }


def classify_a_minus_b(
    client,
    misses: Sequence[Tuple[int, str, str]],
    specs_by_uuid: Dict[str, IocSpec],
    a_records: Sequence[MatchRecord],
) -> List[Dict[str, Any]]:
    classified = []
    by_key = {rec.key(): rec for rec in a_records}
    for key in misses:
        rec = by_key.get(key)
        spec = specs_by_uuid.get(key[2])
        if rec is None and spec is not None:
            # Re-fetch source flags for this ERK only.
            preds = source_predicates(spec.value, spec.ioc_type, spec.effective_match_type())
            sql = f"""
                SELECT
                    ({preds['search_blob']}) AS hit_search_blob,
                    ({preds['raw_json']}) AS hit_raw_json,
                    ({preds.get('structured', '0')}) AS hit_structured,
                    ({preds.get('username', '0')}) AS hit_username,
                    ({preds['extra_fields']}) AS hit_extra_fields,
                    artifact_type,
                    substring(search_blob, 1, 200),
                    substring(raw_json, 1, 200)
                FROM events
                WHERE case_id = {int(key[0])}
                  AND evidence_record_key = '{key[1].replace("'", "''")}'
                LIMIT 1
            """
            result = client.query(sql)
            row = result.result_rows[0] if result.result_rows else None
            rec = MatchRecord(
                case_id=key[0],
                erk=key[1],
                ioc_uuid=key[2],
                ioc_type=spec.ioc_type,
                ioc_value=spec.value,
                path=PATH_LEGACY,
            )
            if row:
                rec.hit_search_blob = bool(row[0])
                rec.hit_raw_json = bool(row[1])
                rec.hit_structured = bool(row[2])
                rec.hit_username = bool(row[3])
                rec.hit_extra_fields = bool(row[4])
                rec.artifact_type = _clean(row[5])
        reason = classify_miss(rec) if rec else MISS_OTHER
        classified.append({
            "case_id": key[0],
            "erk": key[1],
            "ioc_uuid": key[2],
            "ioc_type": rec.ioc_type if rec else "",
            "ioc_value": rec.ioc_value if rec else "",
            "artifact_type": rec.artifact_type if rec else "",
            "hit_search_blob": rec.hit_search_blob if rec else None,
            "hit_raw_json": rec.hit_raw_json if rec else None,
            "hit_structured": rec.hit_structured if rec else None,
            "hit_username": rec.hit_username if rec else None,
            "hit_extra_fields": rec.hit_extra_fields if rec else None,
            "classification": reason,
            "legacy_false_positive_evidence": None,
        })
    return classified


def parse_explain_indexes(text: str) -> Dict[str, Any]:
    parts = None
    granules = None
    indexes = []
    pruned = False
    blob = str(text or "")
    for line in blob.splitlines():
        stripped = line.strip()
        if stripped.startswith("Parts:"):
            try:
                parts = int(stripped.split(":", 1)[1].strip().split()[0])
            except (TypeError, ValueError, IndexError):
                pass
        if stripped.startswith("Granules:"):
            try:
                granules = int(stripped.split(":", 1)[1].strip().split()[0])
            except (TypeError, ValueError, IndexError):
                pass
        if "idx_search" in stripped or "Skip" in stripped or "Name:" in stripped:
            indexes.append(stripped)
            if "idx_search" in stripped:
                pruned = True
    return {
        "parts": parts,
        "granules": granules,
        "index_lines": indexes[:20],
        "search_index_mentioned": pruned,
        "raw": blob[:4000],
    }


def explain_clause(client, case_id: int, where_clause: str) -> Dict[str, Any]:
    sql = f"""
        EXPLAIN indexes = 1
        SELECT count()
        FROM events
        WHERE case_id = {int(case_id)}
          AND ({where_clause})
    """
    started = time.perf_counter()
    result = client.query(sql)
    wall_ms = (time.perf_counter() - started) * 1000.0
    lines = []
    for row in result.result_rows or []:
        lines.append(" ".join(str(part) for part in row if part is not None))
    parsed = parse_explain_indexes("\n".join(lines))
    parsed["explain_wall_ms"] = round(wall_ms, 3)
    return parsed


def _erk(label: str) -> str:
    return "erk:v2:" + hashlib.sha256(f"phase1-step3-ioc-fixture:{label}".encode("utf-8")).hexdigest()


def fixture_timestamp() -> datetime:
    return datetime(2024, 6, 15, 12, 0, 0)


def build_fixture_event(
    *,
    label: str,
    case_id: int = 900001,
    artifact_type: str = "evtx",
    username: str = "",
    search_blob: str = "",
    raw_json: Optional[dict] = None,
    extra_fields: Optional[dict] = None,
    **kwargs,
) -> ParsedEvent:
    ts = fixture_timestamp()
    event = ParsedEvent(
        case_id=case_id,
        artifact_type=artifact_type,
        timestamp=ts,
        timestamp_utc=ts,
        source_file=f"{label}.json",
        source_path=f"/fixtures/{label}.json",
        source_host=kwargs.pop("source_host", "FIXTURE-HOST"),
        case_file_id=1,
        event_id=kwargs.pop("event_id", "1"),
        username=username,
        search_blob=search_blob,
        raw_json=json.dumps(raw_json if raw_json is not None else {}, separators=(",", ":")),
        extra_fields=json.dumps(extra_fields or {}, separators=(",", ":")),
        evidence_record_key=_erk(label),
        evidence_identity_version="2",
        evidence_identity_quality="native",
        parser_version="phase1-step3-fixture",
        **kwargs,
    )
    return event


def fixture_specs(case_id: int = 900001) -> List[IocSpec]:
    """Deterministic IOC needles covering the required recall shapes."""
    def spec(suffix, ioc_type, value, match_type=None):
        digest = hashlib.sha256(f"ioc:{suffix}".encode()).hexdigest()
        uuid = f"{digest[:8]}-{digest[8:12]}-{digest[12:16]}-{digest[16:20]}-{digest[20:32]}"
        return IocSpec(
            case_id=case_id,
            uuid=uuid,
            ioc_type=ioc_type,
            value=value,
            match_type=match_type,
            label=suffix,
        )

    return [
        spec("typed_username", "Username", "fixture.user", "substring"),
        spec("blob_only_token", "MD5 Hash", "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa", "token"),
        spec("raw_json_only_domain", "Domain", "rawjson-only.example", "substring"),
        spec("nested_json_domain", "Domain", "nested-json.example", "substring"),
        spec("mixed_case_domain", "Domain", "MixedCase.Example", "substring"),
        spec("ipv4", "IP Address (IPv4)", "203.0.113.77", "substring"),
        spec("ipv6", "IP Address (IPv6)", "2001:db8::77", "substring"),
        spec("sha256", "SHA256 Hash", "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb", "token"),
        spec("url", "URL", "https://evil.example/payload", "substring"),
        spec("filename", "File Name", "payload.exe", "substring"),
        spec("path", "File Path", r"C:\Windows\Temp\payload.exe", "substring"),
        spec("punct_adjacent", "File Name", "ltsvc", "token"),
        spec("substring_fp", "File Name", "d.bat", "substring"),
    ]


def fixture_events(case_id: int = 900001) -> List[ParsedEvent]:
    """Events that isolate each required IOC location / edge case."""
    events = [
        build_fixture_event(
            label="typed_only_username",
            case_id=case_id,
            username="fixture.user",
            search_blob="unrelated blob",
            raw_json={"EventID": "4624", "note": "username not copied"},
        ),
        build_fixture_event(
            label="blob_only_md5",
            case_id=case_id,
            search_blob="md5 aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa extra",
            raw_json={"EventID": "1", "note": "hash omitted from json"},
            file_hash_md5="",
        ),
        build_fixture_event(
            label="raw_json_only_domain",
            case_id=case_id,
            search_blob="no domain here",
            raw_json={"EventData": {"Unmapped": "rawjson-only.example"}},
        ),
        build_fixture_event(
            label="nested_json",
            case_id=case_id,
            search_blob="outer only",
            raw_json={"EventData": {"Network": {"Dest": "nested-json.example"}}},
        ),
        build_fixture_event(
            label="mixed_case_domain",
            case_id=case_id,
            search_blob="visited MixedCase.Example path",
            raw_json={"host": "MixedCase.Example"},
        ),
        build_fixture_event(
            label="ipv4_blob",
            case_id=case_id,
            search_blob="src 203.0.113.77 dst 10.0.0.1",
            raw_json={"IpAddress": "203.0.113.77"},
            src_ip="203.0.113.77",
        ),
        build_fixture_event(
            label="ipv6_blob",
            case_id=case_id,
            search_blob="src 2001:db8::77",
            raw_json={"IpAddress": "2001:db8::77"},
        ),
        build_fixture_event(
            label="sha256_blob",
            case_id=case_id,
            search_blob="sha256 bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb",
            raw_json={"Hashes": "SHA256=BBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBB"},
            file_hash_sha256="bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb",
        ),
        build_fixture_event(
            label="url_blob",
            case_id=case_id,
            search_blob="https://evil.example/payload dropped",
            raw_json={"url": "https://evil.example/payload"},
        ),
        build_fixture_event(
            label="filename_blob",
            case_id=case_id,
            search_blob=r"c:\temp\payload.exe ran",
            raw_json={"Image": r"c:\temp\payload.exe"},
            process_name="payload.exe",
            process_path=r"c:\temp\payload.exe",
        ),
        build_fixture_event(
            label="path_blob",
            case_id=case_id,
            search_blob=r"C:\Windows\Temp\payload.exe",
            raw_json={"TargetFilename": r"C:\Windows\Temp\payload.exe"},
            target_path=r"C:\Windows\Temp\payload.exe",
        ),
        build_fixture_event(
            label="punct_ltsvc",
            case_id=case_id,
            search_blob=r"c:\ltsvc\agent.exe",
            raw_json={"Image": r"c:\ltsvc\agent.exe"},
        ),
        build_fixture_event(
            label="substring_fp_build_bat",
            case_id=case_id,
            search_blob=r"c:\tools\build.bat",
            raw_json={"Image": r"c:\tools\build.bat"},
            process_name="build.bat",
        ),
        build_fixture_event(
            label="d_bat_true",
            case_id=case_id,
            search_blob=r"c:\tools\d.bat",
            raw_json={"Image": r"c:\tools\d.bat"},
            process_name="d.bat",
        ),
    ]
    return events


def insert_fixture_events(client, events: Sequence[ParsedEvent]) -> int:
    columns = ParsedEvent.clickhouse_columns()
    rows = [event.to_clickhouse_row() for event in events]
    client.insert("events", rows, column_names=columns)
    return len(rows)


def run_path_scan(
    client,
    specs: Sequence[IocSpec],
    path: str,
    *,
    classify_sources: bool = False,
    max_rows_per_ioc: Optional[int] = None,
) -> Tuple[List[MatchRecord], Dict[str, Any]]:
    started = time.perf_counter()
    records: List[MatchRecord] = []
    for spec in specs:
        records.extend(
            stream_matches(
                client,
                spec,
                path,
                classify_sources=classify_sources,
                max_rows=max_rows_per_ioc,
            )
        )
    return records, {
        "path": path,
        "wall_ms": round((time.perf_counter() - started) * 1000.0, 3),
        "match_count": len(records),
        "ioc_count": len(specs),
    }


def summarize_scan(
    specs: Sequence[IocSpec],
    a_records: Sequence[MatchRecord],
    b_records: Sequence[MatchRecord],
    b_path: str,
    classified_misses: Sequence[Dict[str, Any]],
) -> Dict[str, Any]:
    a_keys = [rec.key() for rec in a_records]
    b_keys = [rec.key() for rec in b_records]
    compared = compare_sets(a_keys, b_keys)
    raw_json_only = sum(1 for rec in a_records if rec.hit_raw_json and not rec.hit_search_blob and not rec.hit_structured and not rec.hit_username)
    return {
        "candidate_path": b_path,
        "specs": len(specs),
        **compared,
        "raw_json_only_in_a": raw_json_only,
        "miss_classifications": classified_misses,
        "miss_classification_counts": _count_by(classified_misses, "classification"),
        "ioc_verdict": "IOC_PASS" if compared["recall_gate_pass"] else "IOC_FAIL",
    }


def _count_by(rows: Sequence[Dict[str, Any]], key: str) -> Dict[str, int]:
    counts: Dict[str, int] = {}
    for row in rows:
        counts[str(row.get(key))] = counts.get(str(row.get(key)), 0) + 1
    return counts
