#!/usr/bin/env python3
"""Phase 1 Step 1 full-corpus semantic parity harness.

Disposable only. Refuses to run unless PostgreSQL and ClickHouse database names
start with ``phase1_step1_parity_``. Does not write retained/production evidence.

Subcommands:
  ingest   Parse the approved 8-EVTX corpus, flush events_buffer, dump rows/aliases
  compare  Compare two ingest dumps (baseline vs step1)
"""
from __future__ import annotations

import argparse
import hashlib
import inspect
import ipaddress
import json
import os
import sys
import time
import uuid
from collections import defaultdict
from datetime import date, datetime, timezone
from decimal import Decimal
from pathlib import Path
from typing import Any, Dict, Iterable, List, Sequence
from urllib.parse import urlparse

APPROVED_CORPUS_DIR = Path("/opt/casescope-benchmark/phase0a_evtx")
APPROVED_SHA256 = {
    "Application.evtx": "a9a10f634fb4409e765791c6eedc73346bbed6244a583f8f694c651c6931cbb1",
    "Microsoft-Windows-PowerShell-Operational.evtx": "a0deb6a8e4c97a563e487fa2c96e0a2711566654ef77a28a4e7c7952bcb29a69",
    "Microsoft-Windows-TaskScheduler-Operational.evtx": "915c2c1ef94a010885c882cda0b52cfc26a1512d22f9133c1295e26087dcf499",
    "Microsoft-Windows-TerminalServices-LocalSessionManager.evtx": "eba5bea0102201e553ad004ac1d9fb575067d270a6a2dce3e96740dad64593b8",
    "Microsoft-Windows-WMI-Activity-Operational.evtx": "184b17c902cdaa684da76bb7b256a39a89a5cdb8438ff307714b2a767785f8e0",
    "Microsoft-Windows-Windows-Defender-Operational.evtx": "b52d925a12d38422c6373416a11fe28565ffb4a872dc6318900e1756f8ef9ed0",
    "Security.evtx": "f720ce8362f7f9c5b8ec7068f916026efb04e78499fd30859e3e6e172265244a",
    "System.evtx": "1f4cef929100fc1398f440afc583222ef2e228e1a577c33c19f5a3a82b88699a",
}

# Execution-specific / independently allocated identifiers. Do not add a field
# here merely because a comparison differed.
EXCLUDED_EVENT_FIELDS = {
    "indexed_at",
    "case_id",
    "case_file_id",
}
JSON_SEMANTIC_FIELDS = {"raw_json", "extra_fields"}
DISPOSABLE_PREFIXES = ("phase1_step1_parity_", "phase1_step2_parity_")
DEFAULT_PRIVACY_LEVEL = "cmmc_cui"
ALIAS_EXTRACT_COLUMNS = [
    "timestamp_utc",
    "username",
    "domain",
    "source_host",
    "remote_host",
    "workstation_name",
    "src_ip",
    "dst_ip",
    "command_line",
    "process_path",
    "parent_process",
    "target_path",
    "source_path",
    "reg_data",
    "payload_data1",
    "payload_data2",
    "payload_data3",
    "payload_data4",
    "payload_data5",
    "payload_data6",
    "raw_json",
    "source_file",
    "channel",
    "case_file_id",
]


def _utc_now() -> str:
    return datetime.now(timezone.utc).isoformat()


def _sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def _database_name_from_url(url: str) -> str:
    return urlparse(url).path.rsplit("/", 1)[-1]


def assert_disposable_env() -> None:
    pg_name = _database_name_from_url(os.environ.get("DATABASE_URL", ""))
    ch_name = os.environ.get("CLICKHOUSE_DATABASE", "")
    failures = []
    if not any(pg_name.startswith(prefix) for prefix in DISPOSABLE_PREFIXES):
        failures.append(f"PostgreSQL database is not disposable: {pg_name or '<unset>'}")
    if not any(ch_name.startswith(prefix) for prefix in DISPOSABLE_PREFIXES):
        failures.append(f"ClickHouse database is not disposable: {ch_name or '<unset>'}")
    if failures:
        raise SystemExit("Refusing Step 1 semantic parity run:\n- " + "\n- ".join(failures))
    os.environ["INGEST_FENCE_KEY_PREFIX"] = f"casescope:ingest_fence:disposable:{ch_name}"


def verify_approved_corpus(corpus_dir: Path) -> List[Dict[str, Any]]:
    files = sorted(corpus_dir.glob("*.evtx"))
    if len(files) != 8:
        raise SystemExit(f"Approved corpus must contain 8 EVTX files, found {len(files)} in {corpus_dir}")
    records = []
    mismatches = []
    for path in files:
        digest = _sha256_file(path)
        expected = APPROVED_SHA256.get(path.name)
        records.append(
            {
                "path": str(path),
                "name": path.name,
                "size_bytes": path.stat().st_size,
                "sha256": digest,
                "expected_sha256": expected,
                "sha256_match": digest == expected,
            }
        )
        if digest != expected:
            mismatches.append(path.name)
    if mismatches:
        raise SystemExit(f"Corpus SHA256 mismatch: {mismatches}")
    return records


def cell_to_jsonable(value: Any) -> Any:
    if value is None:
        return None
    if isinstance(value, bool):
        return value
    if isinstance(value, (str, int, float)):
        return value
    if isinstance(value, datetime):
        if value.tzinfo is not None:
            value = value.astimezone(timezone.utc).replace(tzinfo=None)
        return value.isoformat(sep=" ", timespec="milliseconds")
    if isinstance(value, date):
        return value.isoformat()
    if isinstance(value, Decimal):
        return str(value)
    if isinstance(value, bytes):
        return value.decode("utf-8", errors="replace")
    if isinstance(value, (ipaddress.IPv4Address, ipaddress.IPv6Address)):
        return str(value)
    if isinstance(value, (list, tuple)):
        return [cell_to_jsonable(item) for item in value]
    if isinstance(value, dict):
        return {str(key): cell_to_jsonable(item) for key, item in value.items()}
    return str(value)


def parse_json_object(raw: Any) -> Any:
    if raw is None or raw == "":
        return None
    if isinstance(raw, (dict, list)):
        return raw
    if not isinstance(raw, str):
        return raw
    try:
        return json.loads(raw)
    except (TypeError, ValueError, json.JSONDecodeError):
        return raw


def json_semantic_equal(left: Any, right: Any) -> bool:
    return parse_json_object(left) == parse_json_object(right)


def canonical_event_row(row: Dict[str, Any], *, exclude: Iterable[str] = EXCLUDED_EVENT_FIELDS) -> Dict[str, Any]:
    skipped = set(exclude)
    canonical = {}
    for key, value in row.items():
        if key in skipped:
            continue
        if key in JSON_SEMANTIC_FIELDS:
            canonical[key] = parse_json_object(value)
        else:
            canonical[key] = cell_to_jsonable(value)
    return canonical


def alias_identity_key(entity_type: Any, normalized_value: Any) -> tuple[str, str]:
    return (str(entity_type), str(normalized_value))


def detect_alias_path(add_event) -> str:
    source = inspect.getsource(add_event)
    if "extract_alias_candidates_from_event_rows" in source:
        return "per_event_extract"
    return "scoped_populate"


def _ch_client(database: str | None = None, *, timeout: int = 600):
    import clickhouse_connect

    return clickhouse_connect.get_client(
        host=os.environ.get("CLICKHOUSE_HOST", "localhost"),
        port=int(os.environ.get("CLICKHOUSE_PORT", "8123")),
        database=database or os.environ.get("CLICKHOUSE_DATABASE", "default"),
        username=os.environ.get("CLICKHOUSE_USER", "default"),
        password=os.environ.get("CLICKHOUSE_PASSWORD", ""),
        connect_timeout=10,
        send_receive_timeout=timeout,
    )


def _buffer_pending_rows(client) -> int:
    events_rows = int(client.query("SELECT count() FROM events").result_rows[0][0] or 0)
    try:
        buffer_visible = int(client.query("SELECT count() FROM events_buffer").result_rows[0][0] or 0)
    except Exception:
        return 0
    return max(buffer_visible - events_rows, 0)


def flush_events_buffer(client) -> Dict[str, Any]:
    """Explicit Buffer drain when present. OPTIMIZE TABLE events FINAL is not a Buffer flush."""
    events_before = int(client.query("SELECT count() FROM events").result_rows[0][0] or 0)
    exists = False
    try:
        exists = bool(
            client.query(
                """
                SELECT count()
                FROM system.tables
                WHERE database = currentDatabase()
                  AND name = 'events_buffer'
                """
            ).result_rows[0][0]
        )
    except Exception:
        exists = False
    if not exists:
        return {
            "method": "events_buffer_absent",
            "events_before": events_before,
            "events_after": events_before,
            "buffer_visible_before": 0,
            "buffer_visible_after": 0,
            "pending_before": 0,
            "pending_after": 0,
            "flush_ms": 0.0,
            "flushed": True,
        }
    buffer_visible_before = int(client.query("SELECT count() FROM events_buffer").result_rows[0][0] or 0)
    pending_before = max(buffer_visible_before - events_before, 0)
    started = time.perf_counter()
    client.command("OPTIMIZE TABLE events_buffer")
    flush_ms = round((time.perf_counter() - started) * 1000.0, 3)
    events_after = int(client.query("SELECT count() FROM events").result_rows[0][0] or 0)
    buffer_visible_after = int(client.query("SELECT count() FROM events_buffer").result_rows[0][0] or 0)
    pending_after = max(buffer_visible_after - events_after, 0)
    return {
        "method": "OPTIMIZE TABLE events_buffer",
        "events_before": events_before,
        "events_after": events_after,
        "buffer_visible_before": buffer_visible_before,
        "buffer_visible_after": buffer_visible_after,
        "pending_before": pending_before,
        "pending_after": pending_after,
        "flush_ms": flush_ms,
        "flushed": pending_after == 0,
    }


def _prepare_clickhouse() -> Dict[str, Any]:
    from migrations.add_events_table import EVENTS_SCHEMA

    database = os.environ["CLICKHOUSE_DATABASE"]
    admin = _ch_client("default")
    admin.command(f"CREATE DATABASE IF NOT EXISTS `{database}`")
    client = _ch_client(database)
    client.command(EVENTS_SCHEMA)
    engine_full = client.query(
        "SELECT engine_full FROM system.tables WHERE database = currentDatabase() AND name = 'events'"
    ).result_rows[0][0]
    return {"events_engine_full": engine_full, "clickhouse_database": database, "events_buffer_created": False}


def _create_app_context(storage_root: Path):
    os.environ.setdefault("SECRET_KEY", "phase1-step1-parity-secret")
    os.environ.setdefault("DEFAULT_ADMIN_PASSWORD", "phase1-step1-parity-not-used")
    storage_root.mkdir(parents=True, exist_ok=True)
    from config import Config

    Config.STORAGE_FOLDER = str(storage_root)
    Config.STAGING_FOLDER = str(storage_root / "staging")
    Config.UPLOAD_FOLDER = str(storage_root / "uploads")
    from app import create_app
    from models.database import db

    app = create_app(run_startup_bootstrap=False, register_blueprints=False)
    with app.app_context():
        from models.audit_log import AuditLog  # noqa: F401
        from models.case import Case  # noqa: F401
        from models.case_file import CaseFile  # noqa: F401
        import models.graph  # noqa: F401
        import models.privacy_alias  # noqa: F401
        import models.system_settings  # noqa: F401
        import models.user  # noqa: F401

        db.create_all()
    return app, db


def _set_privacy_level(app, db, level: str) -> str:
    from models.system_settings import SettingKeys, SystemSettings

    with app.app_context():
        SystemSettings.set(SettingKeys.AI_PRIVACY_OBFUSCATION_LEVEL, level, value_type="string", updated_by="phase1_step1_parity")
        stored = SystemSettings.get(SettingKeys.AI_PRIVACY_OBFUSCATION_LEVEL, None)
    return str(stored)


def _prepare_case(app, db, files: Sequence[Path]) -> tuple[int, str, Dict[str, int]]:
    from models.case import Case
    from models.case_file import CaseFile, ExtractionStatus, FileStatus

    case_uuid = str(uuid.uuid4())
    case_file_ids: Dict[str, int] = {}
    with app.app_context():
        case = Case(
            uuid=case_uuid,
            name="Phase 1 Step 1 semantic parity",
            company="PHASE1STEP1",
            description="Disposable Step 1 semantic parity case",
            created_by="phase1_step1_parity",
            timezone="UTC",
        )
        db.session.add(case)
        db.session.flush()
        for path in files:
            case_file = CaseFile(
                case_uuid=case_uuid,
                filename=path.name,
                original_filename=path.name,
                file_path=str(path),
                source_path=str(path),
                file_size=path.stat().st_size,
                sha256_hash=_sha256_file(path),
                hostname="",
                file_type="EVTX",
                upload_source="phase1_step1_parity",
                is_archive=False,
                is_extracted=True,
                extraction_status=ExtractionStatus.NA,
                status=FileStatus.NEW,
                retention_state="phase1_step1_disposable",
                uploaded_by="phase1_step1_parity",
            )
            db.session.add(case_file)
            db.session.flush()
            case_file_ids[str(path)] = int(case_file.id)
        db.session.commit()
        return int(case.id), case_uuid, case_file_ids


def _event_column_names(client) -> List[str]:
    rows = client.query(
        """
        SELECT name
        FROM system.columns
        WHERE database = currentDatabase() AND table = 'events'
        ORDER BY position
        """
    ).result_rows
    return [str(row[0]) for row in rows]


def _dump_events(client, output_path: Path) -> Dict[str, Any]:
    columns = _event_column_names(client)
    quoted = ", ".join(f"`{name}`" for name in columns)
    result = client.query(f"SELECT {quoted} FROM events")
    erks = []
    with output_path.open("w", encoding="utf-8") as handle:
        for values in result.result_rows:
            row = {name: cell_to_jsonable(value) for name, value in zip(columns, values)}
            erks.append(str(row.get("evidence_record_key") or ""))
            handle.write(json.dumps(row, ensure_ascii=False, default=str) + "\n")
    unique = set(erks)
    digest = hashlib.sha256("\n".join(sorted(unique)).encode("utf-8")).hexdigest()
    return {
        "row_count": len(erks),
        "unique_erk_count": len(unique),
        "erk_set_sha256": digest,
        "columns": columns,
        "path": str(output_path),
    }


def _alias_identities_from_candidates(candidates: Any, allowed_types: set[str] | None) -> List[List[str]]:
    identities = set()
    values = candidates.values() if isinstance(candidates, dict) else candidates
    for candidate in values:
        entity_type = getattr(candidate, "entity_type", None)
        normalized_value = getattr(candidate, "normalized_value", None)
        original_value = getattr(candidate, "original_value", None)
        if entity_type is None:
            continue
        if allowed_types is not None and entity_type not in allowed_types:
            continue
        identities.add((str(entity_type), str(normalized_value or ""), str(original_value or "")))
    return [list(item) for item in sorted(identities)]


def _vault_snapshot(app, case_id: int, allowed_types: set[str] | None) -> Dict[str, Any]:
    from models.privacy_alias import PrivacyAlias

    with app.app_context():
        rows = PrivacyAlias.query.filter_by(case_id=case_id).all()
        records = []
        for row in rows:
            records.append(
                {
                    "entity_type": row.entity_type,
                    "original_value": row.original_value,
                    "normalized_value": row.normalized_value,
                    "alias_value": row.alias_value,
                    "source": row.source,
                    "seen_count": int(row.seen_count or 0),
                    "sample_fields": list(row.sample_fields or []),
                }
            )
    all_identities = sorted({(row["entity_type"], row["normalized_value"]) for row in records})
    protected = [
        (entity_type, normalized)
        for entity_type, normalized in all_identities
        if allowed_types is None or entity_type in allowed_types
    ]
    by_type: Dict[str, int] = defaultdict(int)
    for entity_type, _normalized in protected:
        by_type[entity_type] += 1
    return {
        "vault_row_count": len(records),
        "unique_identities_all_types": len(all_identities),
        "unique_protected_identities": len(protected),
        "by_type": dict(sorted(by_type.items())),
        "identities": [{"entity_type": t, "normalized_value": v} for t, v in protected],
        "identities_all_types": [{"entity_type": t, "normalized_value": v} for t, v in all_identities],
        "rows": records,
    }


def _extract_rows_for_aliases(client, columns: Sequence[str]) -> List[Dict[str, Any]]:
    present = [name for name in columns if name]
    quoted = ", ".join(f"`{name}`" for name in present)
    result = client.query(f"SELECT {quoted} FROM events")
    rows = []
    for values in result.result_rows:
        row = {}
        for name, value in zip(present, values):
            if name in {"src_ip", "dst_ip"}:
                row[name] = None if value is None else str(value)
            else:
                row[name] = value
        rows.append(row)
    return rows


def _per_source_alias_identities(rows: List[Dict[str, Any]], *, allowed_types: set[str], include_raw_json: bool) -> Dict[str, Any]:
    from utils.privacy_aliases import extract_alias_candidates_from_event_rows

    grouped: Dict[str, List[Dict[str, Any]]] = defaultdict(list)
    for row in rows:
        key = str(row.get("source_file") or "") or str(row.get("channel") or "unknown")
        grouped[key].append(row)
    by_source = {}
    for source_file, source_rows in sorted(grouped.items()):
        scanned = []
        for row in source_rows:
            item = dict(row)
            if not include_raw_json:
                item["raw_json"] = ""
            scanned.append(item)
        candidates = extract_alias_candidates_from_event_rows(scanned)
        identities = _alias_identities_from_candidates(candidates, allowed_types)
        channels = sorted({str(row.get("channel") or "") for row in source_rows})
        by_source[source_file] = {
            "row_count": len(source_rows),
            "channels": channels,
            "candidate_count": len(candidates),
            "protected_identity_count": len(identities),
            "identities": [{"entity_type": t, "normalized_value": n, "original_value": o} for t, n, o in identities],
        }
    return by_source


def cmd_ingest(args: argparse.Namespace) -> int:
    code_root = Path(args.code_root).resolve()
    sys.path.insert(0, str(code_root))
    os.chdir(code_root)
    assert_disposable_env()
    corpus = verify_approved_corpus(Path(args.corpus_dir))
    files = [Path(item["path"]) for item in corpus]
    output_dir = Path(args.output_dir)
    output_dir.mkdir(parents=True, exist_ok=True)

    started = time.perf_counter()
    clickhouse_setup = _prepare_clickhouse()
    app, db = _create_app_context(Path(args.storage_root))
    stored_privacy = _set_privacy_level(app, db, args.privacy_level)
    case_id, case_uuid, case_file_ids = _prepare_case(app, db, files)

    from parsers.registry import BatchProcessor, process_file
    from utils.clickhouse import delete_file_events, get_fresh_client
    from utils.privacy_aliases import PRIVACY_ENTITY_TYPES_BY_LEVEL, get_configured_privacy_level

    alias_path = detect_alias_path(BatchProcessor.add_event)
    ch = get_fresh_client()
    per_file = []
    candidate_counts = []
    with app.app_context():
        configured_level = get_configured_privacy_level()
        allowed_types = set(PRIVACY_ENTITY_TYPES_BY_LEVEL.get(configured_level, set()))
        for path in files:
            case_file_id = case_file_ids[str(path)]
            file_started = time.perf_counter()
            delete_file_events(case_file_id, wait=True, client=ch)
            parsed = process_file(
                file_path=str(path),
                case_id=case_id,
                source_host=path.stem,
                case_file_id=case_file_id,
                clickhouse_client=ch,
                case_tz="UTC",
                parser_hints=["evtx"],
                force_parser=True,
            )
            from models.privacy_alias import PrivacyAlias

            vault_after_file = PrivacyAlias.query.filter_by(case_id=case_id).count()
            per_file.append(
                {
                    "path": str(path),
                    "name": path.name,
                    "case_file_id": case_file_id,
                    "events_parsed": parsed.events_count,
                    "success": parsed.success,
                    "duration_seconds": round(time.perf_counter() - file_started, 3),
                    "errors": parsed.errors,
                    "warnings": parsed.warnings,
                    "vault_rows_after_file": vault_after_file,
                }
            )
            candidate_counts.append(vault_after_file)

    events_before_flush = int(ch.query("SELECT count() FROM events").result_rows[0][0] or 0)
    buffer_flush = flush_events_buffer(ch)
    if not buffer_flush["flushed"]:
        raise SystemExit(
            "events_buffer still has pending rows after OPTIMIZE TABLE events_buffer; "
            "refusing semantic dump. "
            f"pending_after={buffer_flush['pending_after']}"
        )

    events_dump = _dump_events(ch, output_dir / "events.jsonl")
    alias_rows = _extract_rows_for_aliases(ch, ALIAS_EXTRACT_COLUMNS)
    scanned_candidate_count = None
    step1_scan_identities: List[List[str]] = []
    step1_per_file_scans: Dict[str, Any] = {}
    with app.app_context():
        if alias_path == "scoped_populate":
            from utils.privacy_aliases import scan_clickhouse_case_alias_candidates

            scan = scan_clickhouse_case_alias_candidates(
                case_id,
                case_file_id=None,
                generation=None,
                privacy_level=configured_level,
                client=ch,
            )
            scanned_candidate_count = scan.get("candidate_count")
            step1_scan_identities = _alias_identities_from_candidates(scan["candidates"], allowed_types)
            for path in files:
                file_scan = scan_clickhouse_case_alias_candidates(
                    case_id,
                    case_file_id=case_file_ids[str(path)],
                    generation=None,
                    privacy_level=configured_level,
                    client=ch,
                )
                identities = _alias_identities_from_candidates(file_scan["candidates"], allowed_types)
                step1_per_file_scans[path.name] = {
                    "case_file_id": case_file_ids[str(path)],
                    "event_count": file_scan.get("event_count"),
                    "candidate_count": file_scan.get("candidate_count"),
                    "protected_identity_count": len(identities),
                    "identities": [
                        {"entity_type": t, "normalized_value": n, "original_value": o}
                        for t, n, o in identities
                    ],
                }

    vault = _vault_snapshot(app, case_id, allowed_types)
    # Contracted per-source identities from flushed rows, raw_json excluded (Phase 1.1).
    per_source_contracted = _per_source_alias_identities(
        alias_rows, allowed_types=allowed_types, include_raw_json=False
    )

    result = {
        "started_at": _utc_now(),
        "label": args.label,
        "code_root": str(code_root),
        "python_executable": sys.executable,
        "postgres_database": _database_name_from_url(os.environ.get("DATABASE_URL", "")),
        "clickhouse_database": os.environ.get("CLICKHOUSE_DATABASE"),
        "privacy_level_requested": args.privacy_level,
        "privacy_level_stored": stored_privacy,
        "privacy_level_effective": configured_level,
        "alias_path": alias_path,
        "corpus": corpus,
        "case_id": case_id,
        "case_uuid": case_uuid,
        "case_file_ids": case_file_ids,
        "clickhouse_setup": clickhouse_setup,
        "per_file": per_file,
        "events_count_before_buffer_flush": events_before_flush,
        "buffer_flush": buffer_flush,
        "events_dump": events_dump,
        "alias_extract": {
            "baseline_candidate_count": vault["vault_row_count"] if alias_path == "per_event_extract" else None,
            "baseline_style_candidate_count_with_raw_json": None,
            "baseline_style_candidate_count_raw_json_excluded": sum(
                int(payload["candidate_count"]) for payload in per_source_contracted.values()
            ),
            "step1_scanned_candidate_count": scanned_candidate_count,
            "allowed_types": sorted(allowed_types),
            "protected_identities_from_step1_scan": [
                {"entity_type": t, "normalized_value": n, "original_value": o}
                for t, n, o in step1_scan_identities
            ],
            "step1_per_file_scans": step1_per_file_scans,
        },
        "vault": {
            "vault_row_count": vault["vault_row_count"],
            "unique_identities_all_types": vault["unique_identities_all_types"],
            "unique_protected_identities": vault["unique_protected_identities"],
            "by_type": vault["by_type"],
            "identities": vault["identities"],
            "identities_all_types": vault["identities_all_types"],
        },
        "per_source_contracted_raw_json_excluded": {
            name: {
                "row_count": payload["row_count"],
                "channels": payload["channels"],
                "candidate_count": payload["candidate_count"],
                "protected_identity_count": payload["protected_identity_count"],
                "identities": payload["identities"],
            }
            for name, payload in per_source_contracted.items()
        },
        "completed_at": _utc_now(),
        "wall_time_seconds": round(time.perf_counter() - started, 3),
        "errors": [err for item in per_file for err in (item.get("errors") or [])],
    }
    (output_dir / "aliases.json").write_text(json.dumps(vault, indent=2, default=str) + "\n")
    (output_dir / "run.json").write_text(json.dumps(result, indent=2, default=str) + "\n")
    print(
        json.dumps(
            {
                "label": args.label,
                "alias_path": alias_path,
                "privacy_level": configured_level,
                "events": events_dump["row_count"],
                "unique_erks": events_dump["unique_erk_count"],
                "buffer_pending_after": buffer_flush["pending_after"],
                "vault_protected": vault["unique_protected_identities"],
                "wall_time_seconds": result["wall_time_seconds"],
            },
            indent=2,
        )
    )
    return 0 if not result["errors"] else 2


def _load_event_map(path: Path) -> Dict[str, Dict[str, Any]]:
    rows: Dict[str, Dict[str, Any]] = {}
    with path.open("r", encoding="utf-8") as handle:
        for line in handle:
            if not line.strip():
                continue
            row = json.loads(line)
            erk = str(row.get("evidence_record_key") or "")
            rows[erk] = row
    return rows


def _identity_set(items: Iterable[Dict[str, Any]]) -> set[tuple[str, str]]:
    return {(str(item["entity_type"]), str(item["normalized_value"])) for item in items}


def compare_event_dumps(baseline_events: Path, step1_events: Path, *, sample_limit: int = 8) -> Dict[str, Any]:
    baseline = _load_event_map(baseline_events)
    step1 = _load_event_map(step1_events)
    base_erks = set(baseline)
    step_erks = set(step1)
    missing = sorted(base_erks - step_erks)
    extra = sorted(step_erks - base_erks)
    field_counts: Dict[str, int] = defaultdict(int)
    json_representation_only: Dict[str, int] = defaultdict(int)
    mismatches = []
    compared = 0
    mismatched_rows = 0
    for erk in sorted(base_erks & step_erks):
        left = canonical_event_row(baseline[erk])
        right = canonical_event_row(step1[erk])
        compared += 1
        keys = sorted(set(left) | set(right))
        differing = []
        json_only = []
        for key in keys:
            lv = left.get(key)
            rv = right.get(key)
            if lv == rv:
                if key in JSON_SEMANTIC_FIELDS and baseline[erk].get(key) != step1[erk].get(key):
                    json_only.append(key)
                    json_representation_only[key] += 1
                continue
            differing.append(key)
            field_counts[key] += 1
        if differing:
            mismatched_rows += 1
            sample = {}
            for key in differing[:12]:
                if key in JSON_SEMANTIC_FIELDS:
                    sample[key] = {
                        "baseline_preview": str(baseline[erk].get(key))[:500],
                        "step1_preview": str(step1[erk].get(key))[:500],
                    }
                else:
                    sample[key] = {"baseline": left.get(key), "step1": right.get(key)}
            if len(mismatches) < sample_limit:
                mismatches.append(
                    {
                        "evidence_record_key": erk,
                        "source_file": baseline[erk].get("source_file"),
                        "event_id": baseline[erk].get("event_id"),
                        "record_id": baseline[erk].get("record_id"),
                        "fields": differing,
                        "json_representation_only": json_only,
                        "sample": sample,
                    }
                )
    return {
        "baseline_rows": len(baseline),
        "step1_rows": len(step1),
        "baseline_unique_erks": len(base_erks),
        "step1_unique_erks": len(step_erks),
        "erk_set_difference_A_minus_B": len(missing),
        "erk_set_difference_B_minus_A": len(extra),
        "missing_erks_sample": missing[:sample_limit],
        "extra_erks_sample": extra[:sample_limit],
        "rows_compared": compared,
        "rows_with_deterministic_field_difference": mismatched_rows,
        "fields_differing": dict(sorted(field_counts.items(), key=lambda item: (-item[1], item[0]))),
        "json_representation_only_counts": dict(sorted(json_representation_only.items())),
        "representative_mismatches": mismatches,
        "excluded_fields": sorted(EXCLUDED_EVENT_FIELDS),
    }


def compare_alias_dumps(baseline_run: Dict[str, Any], step1_run: Dict[str, Any]) -> Dict[str, Any]:
    base_ids = _identity_set(baseline_run["vault"]["identities"])
    step_ids = _identity_set(step1_run["vault"]["identities"])
    base_only = sorted(base_ids - step_ids)
    step_only = sorted(step_ids - base_ids)
    base_all = _identity_set(baseline_run["vault"]["identities_all_types"])
    step_all = _identity_set(step1_run["vault"]["identities_all_types"])

    def _norm_map(run: Dict[str, Any]) -> Dict[tuple[str, str], str]:
        mapping = {}
        for row in run.get("aliases_rows") or []:
            mapping[(row["entity_type"], row["normalized_value"])] = str(row.get("original_value") or "")
        return mapping

    aliases_base = { (r["entity_type"], r["normalized_value"]): r for r in (baseline_run.get("aliases_rows") or []) }
    aliases_step = { (r["entity_type"], r["normalized_value"]): r for r in (step1_run.get("aliases_rows") or []) }
    normalization_mismatches = []
    for key in sorted(base_ids & step_ids):
        left = aliases_base.get(key)
        right = aliases_step.get(key)
        if not left or not right:
            continue
        if str(left.get("original_value") or "") != str(right.get("original_value") or ""):
            if len(normalization_mismatches) < 12:
                normalization_mismatches.append(
                    {
                        "entity_type": key[0],
                        "normalized_value": key[1],
                        "baseline_original": left.get("original_value"),
                        "step1_original": right.get("original_value"),
                    }
                )

    per_source = {}
    base_sources = baseline_run.get("per_source_contracted_raw_json_excluded") or {}
    step_sources = step1_run.get("per_source_contracted_raw_json_excluded") or {}
    for name in sorted(set(base_sources) | set(step_sources)):
        b = _identity_set((base_sources.get(name) or {}).get("identities") or [])
        s = _identity_set((step_sources.get(name) or {}).get("identities") or [])
        per_source[name] = {
            "baseline_protected_identities": len(b),
            "step1_protected_identities": len(s),
            "baseline_only": [{"entity_type": t, "normalized_value": v} for t, v in sorted(b - s)[:12]],
            "step1_only": [{"entity_type": t, "normalized_value": v} for t, v in sorted(s - b)[:12]],
            "baseline_only_count": len(b - s),
            "step1_only_count": len(s - b),
            "channels": (base_sources.get(name) or step_sources.get(name) or {}).get("channels") or [],
            "parity": b == s,
        }

    return {
        "privacy_level_baseline": baseline_run.get("privacy_level_effective"),
        "privacy_level_step1": step1_run.get("privacy_level_effective"),
        "alias_path_baseline": baseline_run.get("alias_path"),
        "alias_path_step1": step1_run.get("alias_path"),
        "baseline_candidate_count": baseline_run.get("alias_extract", {}).get("baseline_candidate_count")
        or baseline_run.get("vault", {}).get("vault_row_count"),
        "baseline_candidate_count_raw_json_excluded": baseline_run.get("alias_extract", {}).get(
            "baseline_style_candidate_count_raw_json_excluded"
        ),
        "step1_scanned_candidate_count": step1_run.get("alias_extract", {}).get("step1_scanned_candidate_count"),
        "baseline_unique_protected_identities": len(base_ids),
        "step1_unique_protected_identities": len(step_ids),
        "baseline_only_identities": [{"entity_type": t, "normalized_value": v} for t, v in base_only[:25]],
        "step1_only_identities": [{"entity_type": t, "normalized_value": v} for t, v in step_only[:25]],
        "baseline_only_count": len(base_only),
        "step1_only_count": len(step_only),
        "baseline_all_type_identities": len(base_all),
        "step1_all_type_identities": len(step_all),
        "all_type_baseline_only_count": len(base_all - step_all),
        "all_type_step1_only_count": len(step_all - base_all),
        "normalization_mismatches": normalization_mismatches,
        "normalization_mismatch_count": len(normalization_mismatches),
        "per_source_contracted": per_source,
        "protected_identity_set_parity": base_ids == step_ids,
    }


def cmd_compare(args: argparse.Namespace) -> int:
    baseline_dir = Path(args.baseline_dir)
    step1_dir = Path(args.step1_dir)
    baseline_run = json.loads((baseline_dir / "run.json").read_text())
    step1_run = json.loads((step1_dir / "run.json").read_text())
    baseline_aliases = json.loads((baseline_dir / "aliases.json").read_text())
    step1_aliases = json.loads((step1_dir / "aliases.json").read_text())
    baseline_run["aliases_rows"] = baseline_aliases.get("rows") or []
    step1_run["aliases_rows"] = step1_aliases.get("rows") or []

    event_cmp = compare_event_dumps(baseline_dir / "events.jsonl", step1_dir / "events.jsonl")
    alias_cmp = compare_alias_dumps(baseline_run, step1_run)

    event_pass = (
        event_cmp["baseline_rows"] == event_cmp["step1_rows"]
        and event_cmp["erk_set_difference_A_minus_B"] == 0
        and event_cmp["erk_set_difference_B_minus_A"] == 0
        and event_cmp["rows_with_deterministic_field_difference"] == 0
    )
    alias_pass = alias_cmp["protected_identity_set_parity"] is True
    result = {
        "compared_at": _utc_now(),
        "baseline_dir": str(baseline_dir),
        "step1_dir": str(step1_dir),
        "corpus_baseline": baseline_run.get("corpus"),
        "corpus_step1": step1_run.get("corpus"),
        "buffer_flush_baseline": baseline_run.get("buffer_flush"),
        "buffer_flush_step1": step1_run.get("buffer_flush"),
        "event_parity": event_cmp,
        "alias_parity": alias_cmp,
        "event_parity_pass": event_pass,
        "alias_parity_pass": alias_pass,
    }
    output = Path(args.output_json)
    output.parent.mkdir(parents=True, exist_ok=True)
    output.write_text(json.dumps(result, indent=2, default=str) + "\n")
    print(
        json.dumps(
            {
                "event_parity_pass": event_pass,
                "alias_parity_pass": alias_pass,
                "baseline_rows": event_cmp["baseline_rows"],
                "step1_rows": event_cmp["step1_rows"],
                "erk_A_minus_B": event_cmp["erk_set_difference_A_minus_B"],
                "erk_B_minus_A": event_cmp["erk_set_difference_B_minus_A"],
                "rows_with_deterministic_field_difference": event_cmp["rows_with_deterministic_field_difference"],
                "fields_differing": event_cmp["fields_differing"],
                "baseline_protected": alias_cmp["baseline_unique_protected_identities"],
                "step1_protected": alias_cmp["step1_unique_protected_identities"],
                "alias_baseline_only": alias_cmp["baseline_only_count"],
                "alias_step1_only": alias_cmp["step1_only_count"],
            },
            indent=2,
        )
    )
    return 0 if event_pass and alias_pass else 1


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description=__doc__)
    sub = parser.add_subparsers(dest="command", required=True)
    ingest = sub.add_parser("ingest")
    ingest.add_argument("--code-root", required=True)
    ingest.add_argument("--corpus-dir", default=str(APPROVED_CORPUS_DIR))
    ingest.add_argument("--output-dir", required=True)
    ingest.add_argument("--storage-root", required=True)
    ingest.add_argument("--label", required=True)
    ingest.add_argument("--privacy-level", default=DEFAULT_PRIVACY_LEVEL)
    ingest.set_defaults(func=cmd_ingest)
    compare = sub.add_parser("compare")
    compare.add_argument("--baseline-dir", required=True)
    compare.add_argument("--step1-dir", required=True)
    compare.add_argument("--output-json", required=True)
    compare.set_defaults(func=cmd_compare)
    return parser


def main() -> int:
    parser = build_parser()
    args = parser.parse_args()
    return int(args.func(args))


if __name__ == "__main__":
    raise SystemExit(main())
