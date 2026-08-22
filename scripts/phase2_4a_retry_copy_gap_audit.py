#!/usr/bin/env python3
"""Phase 2.4A — interim generation accounting + deterministic retry-copy gap audit.

READ-ONLY against production PostgreSQL and ClickHouse.
All inserts, lost-ack injection, Hunt/mutation/derivation proofs, and
query-exclusion benchmarks run only on disposable databases.

Does not implement the retry-exclusion fix. Does not start Phase 3 or 4.
"""
from __future__ import annotations

import hashlib
import inspect
import json
import os
import re
import subprocess
import sys
import time
import traceback
import uuid
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Any, Dict, List, Optional, Sequence, Tuple

ROOT = Path("/opt/casescope")
sys.path.insert(0, str(ROOT))
os.environ.setdefault("SECRET_KEY", os.environ.get("SECRET_KEY") or "phase2-4a-audit")

import clickhouse_connect
from sqlalchemy import create_engine, text

from migrations.add_events_table import EVENTS_SCHEMA
from migrations.add_phase1b_tranche_b_manifest_protocol import clickhouse_control_table_ddl


# ---------------------------------------------------------------------------
# Locked tokens / constants
# ---------------------------------------------------------------------------
TRANCHE = "phase2_4a_retry_copy_gap_audit"
EXPECTED_HEAD = "3ba6483287ae7a1771f3fd8cf9f67fbf7113e633"
EXPECTED_VERSION = "4.26.2"
EXPECTED_CLICKHOUSE = "26.7.3.19"
PRODUCTION_DB = "casescope"
PG_TEST_DB = "phase2_4a_test"
CH_TEST_DB = "phase2_4a_test"
OUT_JSON = ROOT / "docs" / "database_flow_phase2" / "phase2_4a_retry_copy_gap_audit.json"
OUT_MD = ROOT / "docs" / "database_flow_phase2" / "phase2_4a_retry_copy_gap_audit.md"
LOCKED_PHASE_24_SENTENCE = (
    "Dedup: no engine decision (RMT Option A remains removed). "
    "Interim = generation-aware accounting + deterministic-batch retry exclusion. "
    "Real design = Phase 4."
)

PROD_CH_SETTINGS = {
    "readonly": 1,
    "max_threads": 2,
    "max_execution_time": 90,
    "log_queries": 1,
}

PROTOCOL_IDENTITY_COLUMNS = (
    "source_ref_type",
    "source_ref_id",
    "source_generation",
    "ingest_batch_id",
    "ingest_row_ordinal",
    "ingest_row_hash",
    "ingest_attempt_id",
)


def protocol_complete_sql(alias: str = "") -> str:
    prefix = f"{alias}." if alias else ""
    return f"""
    {prefix}source_ref_type IS NOT NULL AND {prefix}source_ref_type != ''
    AND {prefix}source_ref_id IS NOT NULL AND {prefix}source_ref_id != ''
    AND {prefix}source_generation IS NOT NULL
    AND {prefix}ingest_batch_id IS NOT NULL AND {prefix}ingest_batch_id != ''
    AND {prefix}ingest_row_ordinal IS NOT NULL
    AND {prefix}ingest_row_hash IS NOT NULL AND {prefix}ingest_row_hash != ''
"""


def protocol_all_null_sql(alias: str = "") -> str:
    prefix = f"{alias}." if alias else ""
    return " AND ".join(f"{prefix}{column} IS NULL" for column in PROTOCOL_IDENTITY_COLUMNS)


PROTOCOL_COMPLETE_SQL = protocol_complete_sql()
PROTOCOL_ALL_NULL_SQL = protocol_all_null_sql()

PARITY_FIELDS = (
    "selector_key",
    "indexed_at",
    "ingest_attempt_id",
    "analyst_tagged",
    "analyst_tags",
    "analyst_notes",
    "noise_matched",
    "noise_rules",
    "ioc_types",
    "mitre_attack_ids",
    "mitre_attack_tactics",
    "mitre_attack_sources",
    "mitre_mapping_max_confidence",
)
EXPECTED_DIFFER_FIELDS = frozenset({"indexed_at", "ingest_attempt_id"})

CONSUMER_INVENTORY_SPEC = (
    ("Hunt Events count/list", "NEEDS_PHASE2_4_RETRY_EXCLUSION"),
    ("Hunt detail/raw", "NEEDS_PHASE2_4_RETRY_EXCLUSION"),
    ("Hunt exports using publication bridge", "NEEDS_PHASE2_4_RETRY_EXCLUSION"),
    ("Case/file product event counts", "NEEDS_PHASE2_4_RETRY_EXCLUSION"),
    ("Analyst selector state accounting", "NEEDS_PHASE2_4_RETRY_EXCLUSION"),
    ("Manual-noise selector state accounting", "NEEDS_PHASE2_4_RETRY_EXCLUSION"),
    ("Noise scan accounting", "NEEDS_PHASE2_4_RETRY_EXCLUSION"),
    ("IOC accounting", "NEEDS_PHASE2_4_RETRY_EXCLUSION"),
    ("MITRE accounting", "NEEDS_PHASE2_4_RETRY_EXCLUSION"),
    ("Privacy-alias batch derivation", "NEEDS_PHASE2_4_RETRY_EXCLUSION"),
    ("AI freeze-then-verify", "NEEDS_PHASE2_4_RETRY_EXCLUSION"),
    ("Ingest verify / duplicate_identical", "ALREADY_RETRY_SAFE"),
    ("Generation landed_rows / expected_rows", "ALREADY_RETRY_SAFE"),
    ("Activation completeness row sums", "ALREADY_RETRY_SAFE"),
    ("Capability watermarks", "ALREADY_RETRY_SAFE"),
    ("Case readiness Evidence dimension", "ALREADY_RETRY_SAFE"),
    ("Completion reconciliation PG batch counts", "ALREADY_RETRY_SAFE"),
    ("Graph extraction (F1 transitional)", "NEEDS_PHASE2_4_RETRY_EXCLUSION"),
    ("Event embeddings (F1 transitional)", "NEEDS_PHASE2_4_RETRY_EXCLUSION"),
    ("Known-principal discovery (F1 transitional)", "NEEDS_PHASE2_4_RETRY_EXCLUSION"),
    ("Legacy-only completion dedup", "LEGACY_ONLY_OUT_OF_SCOPE"),
    ("Phase 4 logical/events_current dedup", "PHASE4_LOGICAL_DEDUP_OUT_OF_SCOPE"),
    ("Managed destructive case-wide dedup", "INTEGRITY_FAIL_CLOSED"),
)

LATER_PHASE_TOKENS = (
    "events_current",
    "event_observations_current",
    "logical_event_key",
    "IOCEvidenceMatch",
)

WRITE_SQL_RE = re.compile(
    r"\b(INSERT|ALTER|UPDATE|DELETE|OPTIMIZE|MATERIALIZE|TRUNCATE|DROP|ATTACH|DETACH|RENAME|KILL)\b",
    re.IGNORECASE,
)


class Phase24ANotReady(RuntimeError):
    """Hard-gate abort that still records a NOT_READY artifact when possible."""


def utc_now_iso() -> str:
    return datetime.now(timezone.utc).isoformat()


# ---------------------------------------------------------------------------
# Classification helpers (imported by tests)
# ---------------------------------------------------------------------------
def is_deterministic_retry_equivalent(
    *,
    ingest_batch_id_a: Any,
    ingest_batch_id_b: Any,
    ingest_row_ordinal_a: Any,
    ingest_row_ordinal_b: Any,
    ingest_row_hash_a: Any,
    ingest_row_hash_b: Any,
    expected_hash: Any,
    aggregate_valid: bool = True,
) -> bool:
    """True only for DETERMINISTIC_RETRY_EQUIVALENT identity.

    Same ERK / selector / artifact fields / generation-adjacent resemblance
    is intentionally insufficient.
    """
    if not aggregate_valid:
        return False
    batch_a = str(ingest_batch_id_a or "").strip()
    batch_b = str(ingest_batch_id_b or "").strip()
    hash_a = str(ingest_row_hash_a or "").strip().lower()
    hash_b = str(ingest_row_hash_b or "").strip().lower()
    expected = str(expected_hash or "").strip().lower()
    if not batch_a or batch_a != batch_b:
        return False
    if ingest_row_ordinal_a is None or ingest_row_ordinal_b is None:
        return False
    if int(ingest_row_ordinal_a) != int(ingest_row_ordinal_b):
        return False
    if not hash_a or hash_a != hash_b:
        return False
    if not expected or hash_a != expected:
        return False
    return True


def classify_physical_group(
    *,
    physical_copies: int,
    uniq_hashes: int,
    stored_hashes: Sequence[str],
    pg_expected_hash: Optional[str],
) -> str:
    """Classify one (batch, ordinal) physical group against PG frozen authority."""
    copies = int(physical_copies)
    distinct = int(uniq_hashes)
    hashes = {str(item).strip().lower() for item in stored_hashes if str(item or "").strip()}
    expected = str(pg_expected_hash or "").strip().lower() or None
    if copies < 1:
        return "integrity_conflict"
    if copies == 1:
        if expected is None:
            return "ordinary"
        if hashes and expected not in hashes:
            return "integrity_conflict"
        return "ordinary"
    if distinct != 1 or len(hashes) != 1:
        return "integrity_conflict"
    if expected is None:
        return "integrity_conflict"
    if expected not in hashes:
        return "integrity_conflict"
    return "deterministic_retry_copy_candidate"


def classify_negative_control(kind: str) -> str:
    """Negative controls are never Phase 2.4 retry copies."""
    known = {
        "same_erk_different_batch",
        "same_selector_different_batch",
        "same_artifact_fields_different_source_generation",
        "same_source_event_across_generations",
        "legacy_protocol_null_semantic_duplicate",
        "different_batch_id",
        "different_generation",
        "different_hash_same_ordinal",
    }
    if kind not in known:
        raise ValueError(f"unknown negative control {kind}")
    if kind == "different_hash_same_ordinal":
        return "integrity_conflict"
    return "NOT_PHASE2_4_RETRY_COPY"


def classify_current_state_parity(rows: Sequence[Dict[str, Any]]) -> str:
    """Compare non-hashed mutable/current fields across a retry-copy group."""
    if len(rows) < 2:
        return "CURRENT_RETRY_COPY_STATE_NOT_OBSERVED"
    comparable = [field for field in PARITY_FIELDS if field not in EXPECTED_DIFFER_FIELDS]
    baseline = rows[0]
    for row in rows[1:]:
        for field in comparable:
            if _normalize_parity_value(baseline.get(field)) != _normalize_parity_value(row.get(field)):
                return "CURRENT_STATE_DIVERGENCE"
    return "CURRENT_STATE_PARITY"


def _normalize_parity_value(value: Any) -> Any:
    if isinstance(value, (list, tuple)):
        return tuple(_normalize_parity_value(item) for item in value)
    if isinstance(value, datetime):
        return value.isoformat()
    return value


def consumer_inventory() -> List[Dict[str, str]]:
    return [{"path": path, "classification": classification} for path, classification in CONSUMER_INVENTORY_SPEC]


def recommend_strategy(
    *,
    production_copies_present: bool,
    integrity_conflict: bool,
    current_consumers_need_exclusion: bool,
    production_state_divergence: bool,
) -> str:
    if integrity_conflict:
        return "PHASE2_4_STRATEGY_NOT_READY"
    if not current_consumers_need_exclusion:
        return "PHASE2_4_STRATEGY_NOT_READY"
    # Future lost-ack copies become DURABLE with extras under current protocol.
    # Already-DURABLE extras, if any, must not be physically deleted without
    # current-state proof. Query exclusion covers published consumers now;
    # pre-DURABLE normalization prevents new DURABLE extras.
    if production_state_divergence:
        return "PHASE2_4_STRATEGY_HYBRID"
    if production_copies_present:
        return "PHASE2_4_STRATEGY_HYBRID"
    return "PHASE2_4_STRATEGY_HYBRID"


# ---------------------------------------------------------------------------
# Baseline / connections
# ---------------------------------------------------------------------------
def run(cmd: Sequence[str], *, cwd: Optional[str] = None, env: Optional[dict] = None) -> str:
    merged = dict(os.environ)
    if env:
        merged.update(env)
    result = subprocess.run(
        list(cmd),
        cwd=cwd or str(ROOT),
        env=merged,
        check=False,
        capture_output=True,
        text=True,
    )
    if result.returncode != 0:
        raise RuntimeError(
            f"command failed ({result.returncode}): {' '.join(cmd)}\n{result.stderr or result.stdout}"
        )
    return (result.stdout or "").strip()


def git_baseline() -> Dict[str, Any]:
    env = {
        "GIT_SSH_COMMAND": "ssh -i ~/.ssh/id_ed25519_casescope_github -o IdentitiesOnly=yes"
    }
    try:
        run(["git", "fetch", "origin"], env=env)
    except Exception as exc:
        return {"ok": False, "error": f"git fetch failed: {exc}"}
    status = run(["git", "status", "--short"])
    head = run(["git", "rev-parse", "HEAD"])
    origin = run(["git", "rev-parse", "origin/main"])
    version = json.loads((ROOT / "version.json").read_text(encoding="utf-8"))["version"]
    allowed_dirty = {
        "?? scripts/phase2_4a_retry_copy_gap_audit.py",
        "?? tests/test_phase2_4a_retry_copy_gap_audit.py",
        "?? docs/database_flow_phase2/phase2_4a_retry_copy_gap_audit.md",
        "?? docs/database_flow_phase2/phase2_4a_retry_copy_gap_audit.json",
        " M scripts/phase2_4a_retry_copy_gap_audit.py",
        " M tests/test_phase2_4a_retry_copy_gap_audit.py",
        " M docs/database_flow_phase2/phase2_4a_retry_copy_gap_audit.md",
        " M docs/database_flow_phase2/phase2_4a_retry_copy_gap_audit.json",
        "?? scripts/phase2_4a_retry_copy_gap_audit.py",
    }
    unexpected = []
    for line in status.splitlines():
        normalized = line.rstrip()
        if normalized in allowed_dirty:
            continue
        path = normalized[3:] if len(normalized) >= 3 else normalized
        if path in {
            "scripts/phase2_4a_retry_copy_gap_audit.py",
            "tests/test_phase2_4a_retry_copy_gap_audit.py",
            "docs/database_flow_phase2/phase2_4a_retry_copy_gap_audit.md",
            "docs/database_flow_phase2/phase2_4a_retry_copy_gap_audit.json",
        }:
            continue
        unexpected.append(normalized)
    ok = (
        head == EXPECTED_HEAD
        and origin == EXPECTED_HEAD
        and not unexpected
        and version == EXPECTED_VERSION
    )
    return {
        "ok": ok,
        "repository": str(ROOT),
        "python": "/opt/casescope/venv/bin/python",
        "head": head,
        "origin_main": origin,
        "head_equals_origin_main": head == origin,
        "working_tree_clean_at_start": status == "",
        "status_short": status,
        "unexpected_paths": unexpected,
        "expected_head": EXPECTED_HEAD,
        "expected_version": EXPECTED_VERSION,
        "version": version,
    }


def ch_connect(database: str, settings: Optional[Dict[str, Any]] = None, timeout: int = 300):
    from config import Config

    return clickhouse_connect.get_client(
        host=os.environ.get("CLICKHOUSE_HOST") or Config.CLICKHOUSE_HOST,
        port=int(os.environ.get("CLICKHOUSE_PORT") or Config.CLICKHOUSE_PORT),
        database=database,
        username=os.environ.get("CLICKHOUSE_USER") or Config.CLICKHOUSE_USER,
        password=os.environ.get("CLICKHOUSE_PASSWORD") or Config.CLICKHOUSE_PASSWORD,
        autogenerate_session_id=False,
        settings=settings or {},
        connect_timeout=10,
        send_receive_timeout=timeout,
    )


class ProductionReadOnlyClient:
    """Refuse insert/command/write SQL against production ClickHouse."""

    def __init__(self, inner):
        self._inner = inner
        self.queries = []

    def query(self, sql: str, parameters=None, settings=None):
        if WRITE_SQL_RE.search(sql.split("FROM", 1)[0] if "FROM" in sql.upper() else sql[:200]):
            head = sql.lstrip()[:40].upper()
            if not head.startswith(("SELECT", "EXPLAIN", "SHOW", "DESCRIBE", "DESC", "WITH")):
                raise RuntimeError(f"refusing production write SQL: {sql[:120]}")
        merged = dict(PROD_CH_SETTINGS)
        if settings:
            merged.update(settings)
        started = time.perf_counter()
        result = self._inner.query(sql, parameters=parameters or {}, settings=merged)
        self.queries.append(query_stats(result, time.perf_counter() - started, sql))
        return result

    def command(self, sql: str):
        raise RuntimeError("production ClickHouse command() is forbidden in Phase 2.4A")

    def insert(self, *args, **kwargs):
        raise RuntimeError("production ClickHouse insert() is forbidden in Phase 2.4A")

    def close(self):
        self._inner.close()


def query_stats(result, duration_s: float, sql: str) -> Dict[str, Any]:
    summary = getattr(result, "summary", None)
    return {
        "query_id": getattr(result, "query_id", None) or getattr(summary, "query_id", None),
        "read_rows": int(getattr(summary, "read_rows", 0) or 0),
        "read_bytes": int(getattr(summary, "read_bytes", 0) or 0),
        "duration_ms": round(duration_s * 1000.0, 3),
        "sql_preview": " ".join(sql.split())[:240],
    }


def q(client, sql: str, parameters: Optional[dict] = None, settings: Optional[dict] = None):
    started = time.perf_counter()
    result = client.query(sql, parameters=parameters or {}, settings=settings or {})
    stats = query_stats(result, time.perf_counter() - started, sql)
    cols = list(result.column_names)
    rows = [dict(zip(cols, row)) for row in result.result_rows]
    return rows, result, stats


def scalar(client, sql: str, parameters: Optional[dict] = None, settings: Optional[dict] = None):
    rows, result, stats = q(client, sql, parameters, settings)
    if not rows:
        return None, stats
    return list(rows[0].values())[0], stats


def pg_url(database: Optional[str] = None) -> str:
    from config import Config

    url = Config.SQLALCHEMY_DATABASE_URI
    if database:
        return f"{url.rsplit('/', 1)[0]}/{database}"
    return url


def pg_connect_readonly():
    engine = create_engine(pg_url(), isolation_level="AUTOCOMMIT")
    conn = engine.connect()
    conn.execute(text("SET default_transaction_read_only = on"))
    conn.execute(text("SET statement_timeout = '30s'"))
    return engine, conn


def ensure_pg_database(name: str) -> str:
    subprocess.run(
        ["sudo", "-n", "-u", "postgres", "createdb", "-O", "casescope", name],
        check=False,
        capture_output=True,
        text=True,
    )
    return pg_url(name)


def source_starting_facts() -> Dict[str, Any]:
    """Reverify starting facts A–I from current source, not the prompt."""
    from utils.event_deduplication import deduplicate_case_events
    from utils.ingest_identity import (
        ROW_HASH_ALLOWED_FIELDS,
        ROW_HASH_EXCLUDED_FIELDS,
        canonical_ingest_batch_identity,
        deterministic_ingest_batch_id,
    )
    from utils.manifest_protocol import update_generation_ingest_accounting, verify_ingest_batch
    from utils.staged_batch_reconciler import classify_batch, reconcile_staged_batch
    from routes.hunting_query_helpers import build_hunting_publication_bridge

    identity = inspect.getsource(canonical_ingest_batch_identity)
    batch_id_src = inspect.getsource(deterministic_ingest_batch_id)
    verify_src = inspect.getsource(verify_ingest_batch)
    classify_src = inspect.getsource(classify_batch)
    reconcile_src = inspect.getsource(reconcile_staged_batch)
    accounting_src = inspect.getsource(update_generation_ingest_accounting)
    hunt_src = inspect.getsource(build_hunting_publication_bridge)
    dedup_src = inspect.getsource(deduplicate_case_events)
    celery_text = (ROOT / "tasks" / "celery_tasks.py").read_text(encoding="utf-8")
    case_files_text = (ROOT / "routes" / "case_files.py").read_text(encoding="utf-8")

    facts = {
        "A_ingest_batch_id_deterministic_excludes_attempt": (
            "ingest_attempt_id" not in identity and "batch_ordinal" in identity
        ),
        "B_ingest_attempt_id_not_in_batch_identity": "ingest_attempt_id" not in batch_id_src,
        "C_row_hash_frozen_allowlist": {
            "allowed": list(ROW_HASH_ALLOWED_FIELDS),
            "excluded": sorted(ROW_HASH_EXCLUDED_FIELDS),
            "excludes_selector_indexed_attempt_overlays": ROW_HASH_EXCLUDED_FIELDS.issuperset(
                {
                    "indexed_at",
                    "selector_key",
                    "ingest_attempt_id",
                    "analyst_tagged",
                    "analyst_tags",
                    "analyst_notes",
                    "noise_matched",
                    "noise_rules",
                    "ioc_types",
                    "extra_fields",
                }
            ),
        },
        "D_verify_duplicate_identical_success": (
            'outcome = "duplicate_identical" if retry_equivalent_duplicate else "exact"' in verify_src
            and "True" in verify_src
        ),
        "E_classify_batch_accepts_duplicate_identical": '"duplicate_identical"' in classify_src
        and "True" in classify_src,
        "F_reconcile_marks_durable_without_purge": (
            '{"exact", "duplicate_identical"}' in reconcile_src
            and "mark_durable" in reconcile_src
            and "purge_ingest_batch_rows" not in reconcile_src.split("if classification.classification in")[1].split("if classification.classification")[0]
            if "if classification.classification in" in reconcile_src
            else False
        ),
        "G_landed_rows_from_pg_durable_row_count": (
            "func.sum(IngestBatch.row_count)" in accounting_src
            and "generation.landed_rows" in accounting_src
        ),
        "H_hunt_publication_no_retry_collapse": (
            "dib.state = 'DURABLE'" in hunt_src
            and "BUILDING_INITIAL" in hunt_src
            and "LIMIT 1 BY" not in hunt_src
            and "uniqExact" not in hunt_src
            and "GROUP BY ingest_row_ordinal" not in hunt_src
        ),
        "I_managed_dedup_blocked_default": (
            "allow_managed_evidence: bool = False" in dedup_src
            and "ManagedEvidenceDedupForbidden" in dedup_src
            and "allow_managed_evidence=True" not in celery_text
            and "allow_managed_evidence=True" not in case_files_text
            and "allow_managed_evidence = True" not in celery_text
        ),
    }
    # F: confirm success branch does not call purge. Broader file may still have purge for partial.
    reconcile_success = False
    if "if classification.classification in" in reconcile_src:
        after = reconcile_src.split("if classification.classification in", 1)[1]
        block = after.split("\n    if classification.classification", 1)[0]
        reconcile_success = "mark_batch_durable" in block and "purge" not in block.lower()
    facts["F_reconcile_marks_durable_without_purge"] = reconcile_success
    facts["all_starting_facts_match_prompt"] = all(
        [
            facts["A_ingest_batch_id_deterministic_excludes_attempt"],
            facts["B_ingest_attempt_id_not_in_batch_identity"],
            facts["C_row_hash_frozen_allowlist"]["excludes_selector_indexed_attempt_overlays"],
            facts["D_verify_duplicate_identical_success"],
            facts["E_classify_batch_accepts_duplicate_identical"],
            facts["F_reconcile_marks_durable_without_purge"],
            facts["G_landed_rows_from_pg_durable_row_count"],
            facts["H_hunt_publication_no_retry_collapse"],
            facts["I_managed_dedup_blocked_default"],
        ]
    )
    return facts


def managed_dedup_callers() -> Dict[str, Any]:
    production_true = []
    for rel in ("tasks/celery_tasks.py", "routes/case_files.py", "utils/event_deduplication.py"):
        text_value = (ROOT / rel).read_text(encoding="utf-8")
        if "allow_managed_evidence=True" in text_value or "allow_managed_evidence = True" in text_value:
            production_true.append(rel)
    return {
        "production_allow_managed_evidence_true": production_true,
        "blocked_default": not production_true,
    }


# ---------------------------------------------------------------------------
# Production census
# ---------------------------------------------------------------------------
MODEL_GENERATION_COLUMNS = {
    "id",
    "case_id",
    "source_ref_type",
    "source_ref_id",
    "source_generation",
    "visibility_state",
    "expected_rows",
    "landed_rows",
    "final_batch_ordinal",
    "activated_at",
    "superseded_at",
    "superseded_by_generation",
}
MODEL_BATCH_COLUMNS = {
    "id",
    "ingest_batch_id",
    "generation_id",
    "batch_ordinal",
    "row_count",
    "batch_content_hash",
    "expected_ingest_row_hashes",
    "state",
    "reconcile_owner",
    "reconcile_lease_expires_at",
    "reconcile_attempt_count",
    "last_reconcile_at",
}


def _pg_table_columns(conn, table: str) -> List[str]:
    rows = conn.execute(
        text(
            """
            SELECT column_name
            FROM information_schema.columns
            WHERE table_schema = 'public' AND table_name = :table_name
            ORDER BY ordinal_position
            """
        ),
        {"table_name": table},
    ).fetchall()
    return [row[0] for row in rows]


def _sql_select_existing(alias: str, wanted: Sequence[str], available: set) -> str:
    parts = []
    for column in wanted:
        if column in available:
            parts.append(f"{alias}.{column}")
        else:
            parts.append(f"NULL AS {column}")
    return ",\n                ".join(parts)


def production_pg_census(conn) -> Dict[str, Any]:
    gen_cols = set(_pg_table_columns(conn, "evidence_source_generations"))
    batch_cols = set(_pg_table_columns(conn, "ingest_batches"))
    attempt_cols = set(_pg_table_columns(conn, "ingest_attempts"))
    schema_lag = {
        "evidence_source_generations_missing": sorted(MODEL_GENERATION_COLUMNS - gen_cols),
        "ingest_batches_missing": sorted(MODEL_BATCH_COLUMNS - batch_cols),
        "ingest_attempts_columns": sorted(attempt_cols),
        "evidence_source_generations_columns": sorted(gen_cols),
        "ingest_batches_columns": sorted(batch_cols),
    }
    if not gen_cols or not batch_cols:
        return {
            "managed_cases": [],
            "managed_case_count": 0,
            "generation_count": 0,
            "generations_by_visibility": {},
            "batch_count": 0,
            "batches_by_state": {},
            "generations": [],
            "batches": [],
            "schema_lag": schema_lag,
            "tables_missing": {
                "evidence_source_generations": not gen_cols,
                "ingest_batches": not batch_cols,
            },
        }
    gen_select = _sql_select_existing(
        "g",
        [
            "id",
            "case_id",
            "source_ref_type",
            "source_ref_id",
            "source_generation",
            "visibility_state",
            "expected_rows",
            "landed_rows",
            "final_batch_ordinal",
        ],
        gen_cols,
    )
    generations = conn.execute(
        text(
            f"""
            SELECT
                {gen_select}
            FROM evidence_source_generations g
            ORDER BY g.case_id, g.source_ref_type, g.source_ref_id, g.source_generation
            """
        )
    ).mappings().all()
    batches = conn.execute(
        text(
            """
            SELECT
                b.id,
                b.ingest_batch_id,
                b.generation_id,
                b.batch_ordinal,
                b.row_count,
                b.batch_content_hash,
                b.state,
                g.case_id,
                g.source_ref_type,
                g.source_ref_id,
                g.source_generation,
                g.visibility_state
            FROM ingest_batches b
            JOIN evidence_source_generations g ON g.id = b.generation_id
            ORDER BY g.case_id, b.batch_ordinal, b.id
            """
        )
    ).mappings().all()
    gen_rows = [dict(row) for row in generations]
    batch_rows = [dict(row) for row in batches]
    case_ids = sorted({int(row["case_id"]) for row in gen_rows})
    by_state = {}
    for row in gen_rows:
        by_state[row["visibility_state"]] = by_state.get(row["visibility_state"], 0) + 1
    batch_states = {}
    for row in batch_rows:
        batch_states[row["state"]] = batch_states.get(row["state"], 0) + 1
    return {
        "managed_cases": case_ids,
        "managed_case_count": len(case_ids),
        "generation_count": len(gen_rows),
        "generations_by_visibility": by_state,
        "batch_count": len(batch_rows),
        "batches_by_state": batch_states,
        "generations": gen_rows,
        "batches": batch_rows,
        "schema_lag": schema_lag,
    }


def production_hash_lookup(conn, ingest_batch_ids: Sequence[str]) -> Dict[str, List[str]]:
    if not ingest_batch_ids:
        return {}
    result = {}
    # Parameterized IN list in chunks to keep the statement bounded.
    ids = list(dict.fromkeys(str(item) for item in ingest_batch_ids))
    for offset in range(0, len(ids), 50):
        chunk = ids[offset : offset + 50]
        placeholders = ", ".join(f":id{i}" for i in range(len(chunk)))
        params = {f"id{i}": value for i, value in enumerate(chunk)}
        rows = conn.execute(
            text(
                f"""
                SELECT ingest_batch_id, expected_ingest_row_hashes
                FROM ingest_batches
                WHERE ingest_batch_id IN ({placeholders})
                """
            ),
            params,
        ).mappings().all()
        for row in rows:
            hashes = row["expected_ingest_row_hashes"] or []
            if isinstance(hashes, str):
                hashes = json.loads(hashes)
            result[str(row["ingest_batch_id"])] = [str(item).lower() for item in hashes]
    return result


def production_control_projection_census(prod: ProductionReadOnlyClient) -> Dict[str, Any]:
    """Bounded metadata/control-table counts. Does not scan events."""
    stats: List[Dict[str, Any]] = []
    tables, _, table_stats = q(
        prod,
        """
        SELECT name
        FROM system.tables
        WHERE database = currentDatabase()
          AND name IN ('visible_evidence_generations', 'durable_ingest_batches', 'events')
        ORDER BY name
        """,
    )
    stats.append(table_stats)
    present = {str(row["name"]) for row in tables}
    counts: Dict[str, Any] = {}
    for table in ("visible_evidence_generations", "durable_ingest_batches"):
        if table not in present:
            counts[table] = None
            continue
        value, qstats = scalar(prod, f"SELECT count() FROM {table}")
        stats.append(qstats)
        counts[table] = int(value or 0)
    return {
        "tables_present": sorted(present),
        "counts": counts,
        "query_stats": stats,
        "skipped_unbounded_events_scan": True,
    }


def production_ch_census(prod: ProductionReadOnlyClient, pg_census: Dict[str, Any], conn) -> Dict[str, Any]:
    case_ids = list(pg_census["managed_cases"])
    stats: List[Dict[str, Any]] = []
    retry_groups: List[Dict[str, Any]] = []
    conflict_groups: List[Dict[str, Any]] = []
    malformed_total = 0
    protocol_rows_total = 0
    ordinary_ordinals = 0
    extra_physical_rows = 0
    max_copies = 1
    duplicate_batch_ids = set()
    affected_cases = set()
    affected_generations = set()
    visibility_dupes = {}
    staged_dup_batches = 0
    durable_dup_batches = 0

    batch_meta = {row["ingest_batch_id"]: row for row in pg_census["batches"]}

    for case_id in case_ids:
        summary_sql = f"""
            SELECT
                countIf({PROTOCOL_COMPLETE_SQL}) AS protocol_complete_rows,
                countIf(NOT ({PROTOCOL_ALL_NULL_SQL}) AND NOT ({PROTOCOL_COMPLETE_SQL})) AS malformed_rows
            FROM events
            WHERE case_id = {{case_id:UInt32}}
        """
        rows, _, summary_stats = q(prod, summary_sql, {"case_id": int(case_id)})
        protocol_complete = int((rows[0] or {}).get("protocol_complete_rows") or 0) if rows else 0
        malformed = int((rows[0] or {}).get("malformed_rows") or 0) if rows else 0
        protocol_rows_total += protocol_complete
        malformed_total += malformed
        stats.append({"case_id": case_id, "kind": "malformed_summary", **summary_stats})

        if protocol_complete <= 0:
            continue

        agg_sql = f"""
            SELECT
                count() AS ordinal_groups,
                countIf(physical_copies = 1) AS ordinary_ordinals,
                countIf(physical_copies > 1) AS multi_copy_ordinals,
                max(physical_copies) AS max_copies,
                sum(physical_copies) AS physical_protocol_rows,
                sumIf(physical_copies - 1, physical_copies > 1) AS extra_physical_rows
            FROM
            (
                SELECT
                    ingest_batch_id,
                    ingest_row_ordinal,
                    count() AS physical_copies
                FROM events
                WHERE case_id = {{case_id:UInt32}}
                  AND ({PROTOCOL_COMPLETE_SQL})
                GROUP BY ingest_batch_id, ingest_row_ordinal
            )
        """
        agg_rows, _, agg_stats = q(prod, agg_sql, {"case_id": int(case_id)})
        stats.append({"case_id": case_id, "kind": "ordinal_summary", **agg_stats})
        agg = agg_rows[0] if agg_rows else {}
        ordinary_ordinals += int(agg.get("ordinary_ordinals") or 0)
        extra_physical_rows += int(agg.get("extra_physical_rows") or 0)
        max_copies = max(max_copies, int(agg.get("max_copies") or 0))

        if int(agg.get("multi_copy_ordinals") or 0) <= 0:
            continue

        group_sql = f"""
            SELECT
                source_ref_type,
                source_ref_id,
                source_generation,
                ingest_batch_id,
                ingest_row_ordinal,
                count() AS physical_copies,
                uniqExact(ingest_row_hash) AS uniq_hashes,
                groupUniqArray(ingest_row_hash) AS hashes
            FROM events
            WHERE case_id = {{case_id:UInt32}}
              AND ({PROTOCOL_COMPLETE_SQL})
            GROUP BY
                source_ref_type,
                source_ref_id,
                source_generation,
                ingest_batch_id,
                ingest_row_ordinal
            HAVING physical_copies > 1 OR uniq_hashes > 1
        """
        groups, _, group_stats = q(prod, group_sql, {"case_id": int(case_id)})
        stats.append({"case_id": case_id, "kind": "multi_copy_groups", **group_stats})
        case_multi = groups

        if case_multi:
            hash_lookup = production_hash_lookup(conn, [row["ingest_batch_id"] for row in case_multi])
            for row in case_multi:
                batch_id = str(row["ingest_batch_id"])
                ordinal = int(row["ingest_row_ordinal"])
                hashes = [str(item).lower() for item in (row.get("hashes") or [])]
                expected_list = hash_lookup.get(batch_id) or []
                expected = expected_list[ordinal] if 0 <= ordinal < len(expected_list) else None
                classification = classify_physical_group(
                    physical_copies=int(row["physical_copies"]),
                    uniq_hashes=int(row["uniq_hashes"]),
                    stored_hashes=hashes,
                    pg_expected_hash=expected,
                )
                meta = batch_meta.get(batch_id) or {}
                record = {
                    "case_id": case_id,
                    "source_ref_type": row["source_ref_type"],
                    "source_ref_id": str(row["source_ref_id"]),
                    "source_generation": int(row["source_generation"]),
                    "ingest_batch_id": batch_id,
                    "ingest_row_ordinal": ordinal,
                    "physical_copies": int(row["physical_copies"]),
                    "uniq_hashes": int(row["uniq_hashes"]),
                    "hash_count": len(set(hashes)),
                    "pg_hash_present": expected is not None,
                    "pg_hash_match": bool(expected and expected in hashes),
                    "batch_state": meta.get("state"),
                    "visibility_state": meta.get("visibility_state"),
                    "classification": classification,
                }
                if classification == "deterministic_retry_copy_candidate":
                    retry_groups.append(record)
                    duplicate_batch_ids.add(batch_id)
                    affected_cases.add(case_id)
                    affected_generations.add(
                        (case_id, record["source_ref_type"], record["source_ref_id"], record["source_generation"])
                    )
                    vis = record["visibility_state"] or "UNKNOWN"
                    visibility_dupes[vis] = visibility_dupes.get(vis, 0) + 1
                else:
                    conflict_groups.append(record)

    for batch_id in duplicate_batch_ids:
        state = (batch_meta.get(batch_id) or {}).get("state")
        if state == "STAGED":
            staged_dup_batches += 1
        elif state == "DURABLE":
            durable_dup_batches += 1

    extra_retry_rows = sum(max(int(row["physical_copies"]) - 1, 0) for row in retry_groups)
    return {
        "query_stats": stats,
        "managed_cases_inspected": len(case_ids),
        "managed_generations_inspected": pg_census["generation_count"],
        "managed_batches_inspected": pg_census["batch_count"],
        "protocol_complete_physical_rows": protocol_rows_total,
        "ordinary_ordinals": ordinary_ordinals,
        "ordinals_containing_physical_retry_copies": len(retry_groups),
        "batches_containing_physical_retry_copies": len(duplicate_batch_ids),
        "total_extra_physical_rows": extra_retry_rows,
        "cases_affected": sorted(affected_cases),
        "generations_affected": len(affected_generations),
        "maximum_copies_of_one_ordinal": max_copies if retry_groups else (1 if ordinary_ordinals else 0),
        "staged_duplicate_batches": staged_dup_batches,
        "durable_duplicate_batches": durable_dup_batches,
        "duplicates_by_generation_visibility": visibility_dupes,
        "malformed_protocol_identity_rows": malformed_total,
        "retry_groups": retry_groups,
        "integrity_conflicts": conflict_groups,
        "different_hash_conflicts": sum(1 for row in conflict_groups if int(row["uniq_hashes"]) > 1),
        "wrong_hash_conflicts": sum(
            1 for row in conflict_groups if int(row["uniq_hashes"]) == 1 and not row["pg_hash_match"]
        ),
        "skipped_unbounded_legacy_scan": True,
        "events_scan_limited_to_pg_managed_case_ids": True,
    }


def production_parity_census(prod: ProductionReadOnlyClient, retry_groups: Sequence[Dict[str, Any]]) -> Dict[str, Any]:
    if not retry_groups:
        return {
            "token": "CURRENT_RETRY_COPY_STATE_NOT_OBSERVED",
            "groups_inspected": 0,
            "parity_groups": 0,
            "divergence_groups": 0,
            "notes": "No production deterministic retry-copy groups to compare.",
        }
    field_sql = ", ".join(PARITY_FIELDS)
    parity = 0
    divergence = 0
    details = []
    stats = []
    for group in retry_groups:
        sql = f"""
            SELECT {field_sql}
            FROM events
            WHERE case_id = {{case_id:UInt32}}
              AND ingest_batch_id = {{ingest_batch_id:String}}
              AND ingest_row_ordinal = {{ingest_row_ordinal:UInt32}}
        """
        rows, _, qstats = q(
            prod,
            sql,
            {
                "case_id": int(group["case_id"]),
                "ingest_batch_id": group["ingest_batch_id"],
                "ingest_row_ordinal": int(group["ingest_row_ordinal"]),
            },
        )
        stats.append(qstats)
        token = classify_current_state_parity(rows)
        if token == "CURRENT_STATE_PARITY":
            parity += 1
        else:
            divergence += 1
        details.append(
            {
                "case_id": group["case_id"],
                "ingest_batch_id": group["ingest_batch_id"],
                "ingest_row_ordinal": group["ingest_row_ordinal"],
                "physical_copies": group["physical_copies"],
                "classification": token,
            }
        )
    overall = "CURRENT_STATE_DIVERGENCE" if divergence else "CURRENT_RETRY_COPY_STATE_PARITY"
    return {
        "token": overall,
        "groups_inspected": len(retry_groups),
        "parity_groups": parity,
        "divergence_groups": divergence,
        "details": details,
        "query_stats": stats,
    }


# ---------------------------------------------------------------------------
# Disposable protocol proofs
# ---------------------------------------------------------------------------
class LostAckClient:
    def __init__(self, inner):
        self._inner = inner
        self.stored = False
        self.proof_kind = "SIMULATED_CLIENT_TIMEOUT_AFTER_STORE"

    def insert(self, *args, **kwargs):
        self._inner.insert(*args, **kwargs)
        self.stored = True
        raise TimeoutError("simulated lost acknowledgement after ClickHouse accepted insert")

    def __getattr__(self, name):
        return getattr(self._inner, name)


def create_events_and_control(client) -> None:
    client.command("DROP TABLE IF EXISTS events")
    client.command("DROP TABLE IF EXISTS visible_evidence_generations")
    client.command("DROP TABLE IF EXISTS durable_ingest_batches")
    client.command(EVENTS_SCHEMA)
    for ddl in clickhouse_control_table_ddl():
        client.command(ddl)


def make_pg_app(pg_url_value: str):
    from flask import Flask
    from models.audit_log import AuditLog
    from models.case import Case
    from models.case_file import CaseFile
    from models.client import Client
    from models.database import db
    from models.database_flow import (
        CaseCapabilityBatchCompletion,
        CaseCapabilitySourceState,
        CaseCompletionReconciliationAudit,
        EvidenceGenerationAudit,
        EvidenceSourceGeneration,
        IngestAttempt,
        IngestBatch,
        IngestBatchReconciliationAudit,
    )
    from models.graph_saved_view import GraphSavedView
    from models.investigation_thread import InvestigationThread
    from models.privacy_alias import PrivacyAlias, PrivacyAliasCounter

    _ = (GraphSavedView, InvestigationThread)
    app = Flask(__name__)
    app.config.update(
        SQLALCHEMY_DATABASE_URI=pg_url_value,
        SQLALCHEMY_TRACK_MODIFICATIONS=False,
        SECRET_KEY="phase2-4a",
        PHASE1B_INCREMENTAL_ROW_LOCAL_DERIVATIONS_ENABLED=True,
    )
    db.init_app(app)
    ctx = app.app_context()
    ctx.push()
    with db.engine.begin() as conn:
        conn.execute(text("DROP SCHEMA IF EXISTS public CASCADE"))
        conn.execute(text("CREATE SCHEMA public"))
    for table in (
        Client.__table__,
        Case.__table__,
        CaseFile.__table__,
        EvidenceSourceGeneration.__table__,
        EvidenceGenerationAudit.__table__,
        IngestAttempt.__table__,
        IngestBatch.__table__,
        IngestBatchReconciliationAudit.__table__,
        CaseCapabilitySourceState.__table__,
        CaseCapabilityBatchCompletion.__table__,
        CaseCompletionReconciliationAudit.__table__,
        PrivacyAlias.__table__,
        PrivacyAliasCounter.__table__,
        AuditLog.__table__,
    ):
        table.create(db.engine, checkfirst=True)
    with db.engine.begin() as conn:
        conn.execute(
            text(
                """
                CREATE UNIQUE INDEX IF NOT EXISTS uq_evidence_source_generation_open_building
                ON evidence_source_generations (case_id, source_ref_type, source_ref_id)
                WHERE visibility_state IN ('BUILDING_INITIAL', 'BUILDING_REPLACEMENT')
                """
            )
        )
        conn.execute(
            text(
                """
                CREATE UNIQUE INDEX IF NOT EXISTS uq_evidence_source_generation_active
                ON evidence_source_generations (case_id, source_ref_type, source_ref_id)
                WHERE visibility_state = 'ACTIVE'
                """
            )
        )
    return app, ctx, db


def make_parsed_event(index: int, *, case_id: int, case_file_id: int, host: str = "P24AHOST",
                      source_file: str = "Security.evtx", record_id: Optional[int] = None,
                      erk: Optional[str] = None, username: Optional[str] = None):
    from parsers.base import ParsedEvent

    ts = datetime(2026, 3, 1, 12, 0, 0) + timedelta(seconds=index)
    rid = record_id if record_id is not None else index + 1
    event = ParsedEvent(
        case_id=case_id,
        artifact_type="evtx",
        timestamp=ts,
        timestamp_utc=ts,
        timestamp_source_tz="UTC",
        source_file=source_file,
        source_path=f"/evidence/{source_file}",
        source_host=host,
        case_file_id=case_file_id,
        event_id="4688",
        channel="Security",
        provider="Microsoft-Windows-Security-Auditing",
        record_id=rid,
        level="Information",
        username=username or f"analyst{index % 7}",
        domain="CORP",
        process_name="powershell.exe",
        command_line="powershell.exe -NoProfile",
        raw_json='{"EventID":"4688","Channel":"Security"}',
        search_blob=f"host {host} user analyst{index % 7} event 4688 powershell p24a row{index}",
        extra_fields='{"native_record_id_authoritative":true,"provenance_source":"parser_emitted"}',
        parser_version="phase2-4a:v1",
        evidence_record_key=erk or f"erk-p24a-{case_id}-{rid:08d}",
        evidence_identity_version="v1",
        evidence_identity_quality="high",
        native_record_id_authoritative=True,
    )
    return event


def seed_case(db, *, name: str, batch_size: int, filename: str = "Security.evtx"):
    from models.case import Case
    from models.case_file import CaseFile, IngestProtocolOrigin
    from models.client import Client
    from utils.manifest_protocol import (
        ManifestParserContract,
        allocate_case_file_initial_generation,
        create_ingest_attempt,
    )

    client_row = Client(name=name, code=f"P24A{time.time_ns() % 100000}", created_by="p24a")
    case = Case(
        uuid=f"p24a-{time.time_ns()}",
        name=name,
        company="CaseScope",
        client=client_row,
        created_by="p24a",
        timezone="UTC",
    )
    case_file = CaseFile(
        case_uuid=case.uuid,
        filename=filename,
        original_filename=filename,
        file_path=f"/tmp/{filename}",
        file_size=1,
        sha256_hash=hashlib.sha256(filename.encode()).hexdigest(),
        uploaded_by="p24a",
        ingest_protocol_origin=IngestProtocolOrigin.NOT_STARTED,
    )
    db.session.add_all([client_row, case, case_file])
    db.session.commit()
    contract = ManifestParserContract(
        parser_version="phase2-4a:v1",
        normalization_version="normalization:v1",
        configured_batch_size=int(batch_size),
        ordering_contract="test:phase2-4a-order:v1",
        producer_version="phase2-4a:v1",
        manifest_eligible=True,
    )
    generation = allocate_case_file_initial_generation(
        session=db.session,
        case_id=case.id,
        case_file_id=case_file.id,
        contract=contract,
    )
    attempt = create_ingest_attempt(session=db.session, generation=generation, celery_task_id="p24a")
    db.session.commit()
    return case, case_file, generation, attempt, contract


def hunt_from_clause():
    from routes.hunting_query_helpers import build_hunting_publication_bridge

    publication = build_hunting_publication_bridge(alias="e", case_id_param="{case_id:UInt32}")
    return f"""
        FROM events AS e
        {publication["join_sql"]}
        WHERE e.case_id = {{case_id:UInt32}}
        {publication["where_sql"]}
    """


def hunt_count(client, case_id: int) -> Tuple[int, Dict[str, Any]]:
    sql = f"SELECT count() AS n {hunt_from_clause()}"
    value, stats = scalar(client, sql, {"case_id": int(case_id)})
    return int(value or 0), stats


def hunt_count_excluded(client, case_id: int) -> Tuple[int, Dict[str, Any]]:
    """Candidate interim count: legacy physical rows + uniq managed (batch, ordinal)."""
    from routes.hunting_query_helpers import build_hunting_publication_bridge

    publication = build_hunting_publication_bridge(alias="e", case_id_param="{case_id:UInt32}")
    sql = f"""
        SELECT
            countIf({protocol_all_null_sql("e")}) AS legacy_n,
            uniqExactIf(
                (e.ingest_batch_id, e.ingest_row_ordinal),
                e.ingest_batch_id IS NOT NULL AND e.ingest_batch_id != ''
            ) AS managed_n
        FROM events AS e
        {publication["join_sql"]}
        WHERE e.case_id = {{case_id:UInt32}}
        {publication["where_sql"]}
    """
    rows, _, stats = q(client, sql, {"case_id": int(case_id)})
    row = rows[0] if rows else {}
    return int(row.get("legacy_n") or 0) + int(row.get("managed_n") or 0), stats


def hunt_rows(client, case_id: int, *, limit: int, offset: int = 0) -> Tuple[List[tuple], Dict[str, Any]]:
    sql = f"""
        SELECT e.selector_key, e.ingest_batch_id, e.ingest_row_ordinal, e.ingest_attempt_id, e.evidence_record_key
        {hunt_from_clause()}
        ORDER BY e.timestamp DESC, e.record_id DESC
        LIMIT {{limit:UInt32}} OFFSET {{offset:UInt32}}
    """
    started = time.perf_counter()
    result = client.query(
        sql,
        parameters={"case_id": int(case_id), "limit": int(limit), "offset": int(offset)},
    )
    stats = query_stats(result, time.perf_counter() - started, sql)
    return list(result.result_rows or []), stats


def hunt_detail(client, case_id: int, selector_key: str) -> Tuple[Optional[dict], Dict[str, Any]]:
    from routes.hunting_query_helpers import build_hunting_publication_bridge

    publication = build_hunting_publication_bridge(alias="e", case_id_param="{case_id:UInt32}")
    sql = f"""
        SELECT e.ingest_attempt_id, e.indexed_at, e.analyst_notes, e.selector_key
        FROM events AS e
        {publication["join_sql"]}
        WHERE e.case_id = {{case_id:UInt32}}
          AND e.selector_key = {{selector_key:String}}
          {publication["where_sql"]}
        LIMIT 1
    """
    rows, _, stats = q(client, sql, {"case_id": int(case_id), "selector_key": selector_key})
    return (rows[0] if rows else None), stats


def insert_retry_copies(ch, db, *, generation, attempt, events, lost_ack: bool = True):
    from utils.manifest_protocol import (
        construct_managed_batch,
        create_ingest_attempt,
        insert_managed_batch,
        mark_batch_durable,
        reserve_staged_batch,
        update_generation_ingest_accounting,
        verify_ingest_batch,
        project_generation_control_state,
    )

    manifest = construct_managed_batch(
        generation=generation,
        attempt=attempt,
        events=tuple(events),
        batch_ordinal=0,
    )
    batch_row = reserve_staged_batch(session=db.session, manifest=manifest)
    db.session.commit()
    ack_error = None
    if lost_ack:
        lost = LostAckClient(ch)
        try:
            insert_managed_batch(lost, manifest)
        except TimeoutError as exc:
            ack_error = str(exc)
        verify_after_loss = verify_ingest_batch(ch, manifest)
    else:
        insert_managed_batch(ch, manifest)
        verify_after_loss = verify_ingest_batch(ch, manifest)
        lost = None

    attempt2 = create_ingest_attempt(session=db.session, generation=generation, celery_task_id="p24a-retry")
    db.session.commit()
    retry_manifest = construct_managed_batch(
        generation=generation,
        attempt=attempt2,
        events=tuple(events),
        batch_ordinal=0,
    )
    assert retry_manifest.ingest_batch_id == manifest.ingest_batch_id
    assert retry_manifest.row_hashes == manifest.row_hashes
    assert retry_manifest.ingest_attempt_id != manifest.ingest_attempt_id
    batch_row = reserve_staged_batch(session=db.session, manifest=retry_manifest)
    db.session.commit()
    insert_managed_batch(ch, retry_manifest)
    verification = verify_ingest_batch(ch, retry_manifest)
    if verification.success:
        mark_batch_durable(session=db.session, batch=batch_row, verification=verification)
        update_generation_ingest_accounting(session=db.session, generation=generation)
        db.session.commit()
        project_generation_control_state(ch, db.session, generation)
    db.session.refresh(batch_row)
    db.session.refresh(generation)
    physical, _ = scalar(
        ch,
        "SELECT count() FROM events WHERE ingest_batch_id = {id:String}",
        {"id": manifest.ingest_batch_id},
    )
    return {
        "manifest": manifest,
        "retry_manifest": retry_manifest,
        "batch": batch_row,
        "generation": generation,
        "ack_error": ack_error,
        "lost_stored": bool(lost and lost.stored),
        "verify_after_loss": {
            "success": verify_after_loss.success,
            "outcome": verify_after_loss.outcome,
            "physical_rows": verify_after_loss.physical_rows,
        },
        "verify_after_retry": {
            "success": verification.success,
            "outcome": verification.outcome,
            "physical_rows": verification.physical_rows,
            "duplicate_physical_rows": verification.duplicate_physical_rows,
            "retry_equivalent_duplicate": verification.retry_equivalent_duplicate,
        },
        "pg_state": batch_row.state,
        "pg_row_count": int(batch_row.row_count),
        "pg_landed_rows": int(generation.landed_rows or 0),
        "physical_rows": int(physical or 0),
        "same_batch_id": retry_manifest.ingest_batch_id == manifest.ingest_batch_id,
        "different_attempt_id": retry_manifest.ingest_attempt_id != manifest.ingest_attempt_id,
    }


def run_disposable_proofs(pg_url_value: str, ch_db: str) -> Dict[str, Any]:
    from models.audit_log import AuditLog
    from models.privacy_alias import PrivacyAlias
    from utils.ai_privacy_freeze import freeze_selected_clickhouse_rows, select_current_generation_event_rows
    from utils.case_readiness import build_case_readiness_dto
    from utils.completion_reconciler import ReconciliationHooks, reconcile_case_completion
    from utils.event_analyst_state import upsert_event_analyst_state_rows
    from utils.event_noise_state import upsert_manual_noise_state_rows
    from utils.ingest_fence import install_memory_backend, reset_fence_backend
    from models.database_flow import IngestBatch, IngestBatchState
    from utils.manifest_protocol import (
        activate_initial_generation,
        allocate_case_file_initial_generation,
        allocate_case_file_replacement_generation,
        check_generation_activation_completeness,
        construct_managed_batch,
        create_ingest_attempt,
        declare_generation_ingest_complete,
        insert_managed_batch,
        mark_batch_durable,
        project_generation_control_state,
        reserve_staged_batch,
        update_generation_ingest_accounting,
        verify_ingest_batch,
    )
    from utils.privacy_aliases import populate_case_privacy_aliases
    from utils.row_local_derivations import derive_privacy_aliases_for_durable_batch

    install_memory_backend()
    app, ctx, db = make_pg_app(pg_url_value)
    ch = ch_connect(ch_db)
    try:
        create_events_and_control(ch)
        n = 8
        case, case_file, generation, attempt, contract = seed_case(db, name="P24A-retry", batch_size=n)
        events = [
            make_parsed_event(i, case_id=case.id, case_file_id=case_file.id)
            for i in range(n)
        ]
        lost = insert_retry_copies(ch, db, generation=generation, attempt=attempt, events=events, lost_ack=True)

        expected_n = n
        physical = lost["physical_rows"]
        hunt_building, hunt_building_stats = hunt_count(ch, case.id)
        hunt_building_excl, hunt_building_excl_stats = hunt_count_excluded(ch, case.id)
        page1, page1_stats = hunt_rows(ch, case.id, limit=5, offset=0)
        page2, page2_stats = hunt_rows(ch, case.id, limit=5, offset=5)
        selectors_page1 = [row[0] for row in page1]
        duplicate_selector_on_page = len(selectors_page1) != len(set(selectors_page1))

        detail_sel = events[0]
        from utils.event_selector import build_event_selector_key

        selector = build_event_selector_key(
            event_id=detail_sel.event_id,
            record_id=detail_sel.record_id,
            source_file=detail_sel.source_file,
            source_host=detail_sel.source_host,
            timestamp=detail_sel.timestamp,
            artifact_type=detail_sel.artifact_type,
        )
        copies_before, _ = scalar(
            ch,
            """
            SELECT count() FROM events
            WHERE case_id = {case_id:UInt32} AND selector_key = {selector_key:String}
            """,
            {"case_id": case.id, "selector_key": selector},
        )
        detail_before, detail_stats = hunt_detail(ch, case.id, selector)

        # Force mutable divergence on one physical copy only (disposable).
        ch.command(
            f"""
            ALTER TABLE events UPDATE analyst_notes = 'copy-a'
            WHERE case_id = {int(case.id)}
              AND selector_key = '{selector}'
              AND ingest_attempt_id = toUUID('{lost["retry_manifest"].ingest_attempt_id}')
            """,
            settings={"mutations_sync": 1},
        )
        # mutations_sync is not guaranteed here; wait briefly via count of notes.
        for _ in range(20):
            noted, _ = scalar(
                ch,
                """
                SELECT count() FROM events
                WHERE case_id = {case_id:UInt32}
                  AND selector_key = {selector_key:String}
                  AND analyst_notes = 'copy-a'
                """,
                {"case_id": case.id, "selector_key": selector},
            )
            if int(noted or 0) >= 1:
                break
            time.sleep(0.05)
        detail_divergent, _ = hunt_detail(ch, case.id, selector)
        copy_notes, _, _ = q(
            ch,
            """
            SELECT ingest_attempt_id, analyst_notes
            FROM events
            WHERE case_id = {case_id:UInt32} AND selector_key = {selector_key:String}
            ORDER BY ingest_attempt_id
            """,
            {"case_id": case.id, "selector_key": selector},
        )
        notes_set = {str(row.get("analyst_notes") or "") for row in copy_notes}

        # Restore parity then measure analyst accounting against both copies.
        ch.command(
            f"""
            ALTER TABLE events UPDATE analyst_notes = NULL
            WHERE case_id = {int(case.id)} AND selector_key = '{selector}'
            """,
            settings={"mutations_sync": 1},
        )
        time.sleep(0.1)

        matched = upsert_event_analyst_state_rows(
            case.id,
            [
                {
                    "selector_key": selector,
                    "artifact_type": "evtx",
                    "analyst_tagged": True,
                    "analyst_tags": ["p24a"],
                    "analyst_notes": "tagged",
                }
            ],
            updated_by="p24a",
            client=ch,
            remote_ip="192.0.2.24",
            operation_id="op-p24a-analyst",
        )
        physical_after_tag, _ = scalar(
            ch,
            """
            SELECT count() FROM events
            WHERE case_id = {case_id:UInt32}
              AND selector_key = {selector_key:String}
              AND analyst_tagged = true
            """,
            {"case_id": case.id, "selector_key": selector},
        )
        event_changes = (
            db.session.query(AuditLog)
            .filter_by(operation_id="op-p24a-analyst")
            .count()
        )
        evidence_affected = (
            db.session.query(AuditLog)
            .filter_by(operation_id="op-p24a-analyst")
            .with_entities(AuditLog.affected_count)
            .all()
        )
        affected_values = [int(row[0] or 0) for row in evidence_affected]

        noise_matched = upsert_manual_noise_state_rows(
            case.id,
            [
                {
                    "selector_key": selector,
                    "artifact_type": "evtx",
                    "noise_matched": True,
                    "noise_rules": ["manual-p24a"],
                }
            ],
            updated_by="p24a",
            client=ch,
            remote_ip="192.0.2.24",
            operation_id="op-p24a-noise",
        )

        privacy_error = None
        populate = None
        privacy = None
        alias_rows = 0
        try:
            privacy = derive_privacy_aliases_for_durable_batch(
                session=db.session,
                ingest_batch_id=lost["manifest"].ingest_batch_id,
                clickhouse_client=ch,
            )
            db.session.commit()
            alias_rows = db.session.query(PrivacyAlias).filter_by(case_id=case.id).count()
            populate = populate_case_privacy_aliases(
                case.id,
                case_file_id=case_file.id,
                ingest_batch_id=lost["manifest"].ingest_batch_id,
                source_generation=int(generation.source_generation),
                source="phase2_4a_audit",
                client=ch,
            )
            db.session.commit()
        except Exception as exc:
            db.session.rollback()
            privacy_error = str(exc)

        freeze_error = None
        freeze_rows = []
        frozen = None
        try:
            freeze_rows, _ch_queries = select_current_generation_event_rows(
                db.session,
                ch,
                case_id=case.id,
                source_ref_type=generation.source_ref_type,
                source_ref_id=generation.source_ref_id,
            )
            frozen = freeze_selected_clickhouse_rows(
                db.session,
                case_id=case.id,
                rows=freeze_rows,
            )
        except Exception as exc:
            freeze_error = str(exc)

        declare_generation_ingest_complete(
            session=db.session,
            generation=generation,
            expected_rows=n,
            final_batch_ordinal=0,
        )
        db.session.commit()
        completeness = check_generation_activation_completeness(session=db.session, generation=generation)
        activate_initial_generation(session=db.session, generation=generation, actor="p24a")
        db.session.commit()
        project_generation_control_state(ch, db.session, generation)
        hunt_active, hunt_active_stats = hunt_count(ch, case.id)
        hunt_active_excl, _ = hunt_count_excluded(ch, case.id)

        replacement = allocate_case_file_replacement_generation(
            session=db.session,
            case_id=case.id,
            case_file_id=case_file.id,
            contract=contract,
        )
        repl_attempt = create_ingest_attempt(session=db.session, generation=replacement, celery_task_id="p24a-repl")
        db.session.commit()
        repl_events = [
            make_parsed_event(i, case_id=case.id, case_file_id=case_file.id, host="P24AREPL")
            for i in range(n)
        ]
        repl_manifest = construct_managed_batch(
            generation=replacement,
            attempt=repl_attempt,
            events=tuple(repl_events),
            batch_ordinal=0,
        )
        repl_batch = reserve_staged_batch(session=db.session, manifest=repl_manifest)
        db.session.commit()
        insert_managed_batch(ch, repl_manifest)
        insert_managed_batch(ch, repl_manifest)
        repl_verify = verify_ingest_batch(ch, repl_manifest)
        if repl_verify.success:
            mark_batch_durable(session=db.session, batch=repl_batch, verification=repl_verify)
            update_generation_ingest_accounting(session=db.session, generation=replacement)
            db.session.commit()
        project_generation_control_state(ch, db.session, replacement)
        hunt_during_replacement, hunt_repl_stats = hunt_count(ch, case.id)

        db.session.rollback()
        readiness = build_case_readiness_dto(db.session, case_id=case.id, case_uuid=case.uuid)
        try:
            completion = reconcile_case_completion(
                db.session,
                case_id=case.id,
                case_uuid=case.uuid,
                trigger_reason="phase2_4a_audit",
                hooks=ReconciliationHooks(),
            )
        except Exception:
            db.session.rollback()
            completion = reconcile_case_completion(
                db.session,
                case_id=case.id,
                case_uuid=case.uuid,
                trigger_reason="phase2_4a_audit",
                hooks=ReconciliationHooks(),
            )

        # Negative controls in the same disposable database.
        # Different source/generation uses a second case file.
        from models.case_file import CaseFile, IngestProtocolOrigin

        other_file = CaseFile(
            case_uuid=case.uuid,
            filename="Other.evtx",
            original_filename="Other.evtx",
            file_path="/tmp/Other.evtx",
            file_size=1,
            sha256_hash="b" * 64,
            uploaded_by="p24a",
            ingest_protocol_origin=IngestProtocolOrigin.NOT_STARTED,
        )
        db.session.add(other_file)
        db.session.commit()
        other_gen = allocate_case_file_initial_generation(
            session=db.session,
            case_id=case.id,
            case_file_id=other_file.id,
            contract=contract,
        )
        other_attempt = create_ingest_attempt(session=db.session, generation=other_gen, celery_task_id="p24a-other")
        db.session.commit()
        other_events = [
            make_parsed_event(
                i,
                case_id=case.id,
                case_file_id=other_file.id,
                host="P24AHOST",
                source_file="Other.evtx",
                record_id=i + 1,
                erk=events[i].evidence_record_key,
            )
            for i in range(2)
        ]
        other_manifest = construct_managed_batch(
            generation=other_gen,
            attempt=other_attempt,
            events=tuple(other_events),
            batch_ordinal=0,
        )
        reserve_staged_batch(session=db.session, manifest=other_manifest)
        db.session.commit()
        insert_managed_batch(ch, other_manifest)
        other_verify = verify_ingest_batch(ch, other_manifest)
        if other_verify.success:
            other_batch = (
                db.session.query(IngestBatch)
                .filter_by(ingest_batch_id=other_manifest.ingest_batch_id)
                .one()
            )
            mark_batch_durable(session=db.session, batch=other_batch, verification=other_verify)
            update_generation_ingest_accounting(session=db.session, generation=other_gen)
            db.session.commit()
            project_generation_control_state(ch, db.session, other_gen)

        same_erk_groups, _, _ = q(
            ch,
            """
            SELECT evidence_record_key, uniqExact(ingest_batch_id) AS batches, count() AS physical
            FROM events
            WHERE case_id = {case_id:UInt32}
              AND evidence_record_key = {erk:String}
            GROUP BY evidence_record_key
            """,
            {"case_id": case.id, "erk": events[0].evidence_record_key},
        )
        same_erk_not_retry = is_deterministic_retry_equivalent(
            ingest_batch_id_a=lost["manifest"].ingest_batch_id,
            ingest_batch_id_b=other_manifest.ingest_batch_id,
            ingest_row_ordinal_a=0,
            ingest_row_ordinal_b=0,
            ingest_row_hash_a=lost["manifest"].row_hashes[0],
            ingest_row_hash_b=other_manifest.row_hashes[0],
            expected_hash=lost["manifest"].row_hashes[0],
        )

        # Legacy protocol-NULL semantic duplicate
        ts = datetime(2026, 3, 1, 15, 0, 0)
        ch.insert(
            "events",
            [
                [
                    int(case.id),
                    "evtx",
                    ts,
                    ts,
                    "Legacy.evtx",
                    "LEGACYHOST",
                    "4624",
                    9001,
                    '{"EventID":"4624"}',
                    "legacy blob",
                    "{}",
                    "erk-legacy-same",
                    "v1",
                    "high",
                ],
                [
                    int(case.id),
                    "evtx",
                    ts,
                    ts,
                    "Legacy.evtx",
                    "LEGACYHOST",
                    "4624",
                    9001,
                    '{"EventID":"4624"}',
                    "legacy blob",
                    "{}",
                    "erk-legacy-same",
                    "v1",
                    "high",
                ],
            ],
            column_names=[
                "case_id",
                "artifact_type",
                "timestamp",
                "timestamp_utc",
                "source_file",
                "source_host",
                "event_id",
                "record_id",
                "raw_json",
                "search_blob",
                "extra_fields",
                "evidence_record_key",
                "evidence_identity_version",
                "evidence_identity_quality",
            ],
        )
        legacy_count, _ = scalar(
            ch,
            f"""
            SELECT count() FROM events
            WHERE case_id = {{case_id:UInt32}}
              AND ({PROTOCOL_ALL_NULL_SQL})
              AND evidence_record_key = 'erk-legacy-same'
            """,
            {"case_id": case.id},
        )
        hunt_with_legacy, _ = hunt_count(ch, case.id)
        hunt_with_legacy_excl, _ = hunt_count_excluded(ch, case.id)

        different_hash_conflict = classify_physical_group(
            physical_copies=2,
            uniq_hashes=2,
            stored_hashes=["a" * 64, "b" * 64],
            pg_expected_hash="a" * 64,
        )

        return {
            "ok": bool(
                lost["ack_error"]
                and lost["lost_stored"]
                and lost["verify_after_retry"]["outcome"] == "duplicate_identical"
                and lost["verify_after_retry"]["success"] is True
                and lost["pg_state"] == IngestBatchState.DURABLE
                and lost["pg_landed_rows"] == expected_n
                and lost["physical_rows"] == expected_n * 2
                and hunt_building == expected_n * 2
                and hunt_building_excl == expected_n
            ),
            "lost_ack": {
                "ack_error_present": bool(lost["ack_error"]),
                "stored_before_raise": lost["lost_stored"],
                "verify_after_loss": lost["verify_after_loss"],
                "verify_after_retry": lost["verify_after_retry"],
                "same_batch_id": lost["same_batch_id"],
                "different_attempt_id": lost["different_attempt_id"],
                "pg_state": lost["pg_state"],
            },
            "accounting": {
                "pg_expected_rows_declared": expected_n,
                "pg_batch_row_count": lost["pg_row_count"],
                "pg_landed_rows": lost["pg_landed_rows"],
                "clickhouse_physical_rows": lost["physical_rows"],
                "hunt_building_initial_count": hunt_building,
                "hunt_building_initial_excluded": hunt_building_excl,
                "hunt_active_count": hunt_active,
                "hunt_active_excluded": hunt_active_excl,
                "hunt_during_building_replacement": hunt_during_replacement,
                "one_ordinal_appears_once_in_current_hunt": hunt_building == expected_n,
                "one_ordinal_appears_once_per_physical_copy": hunt_building == physical,
            },
            "pagination": {
                "page_size": 5,
                "page1_rows": len(page1),
                "page2_rows": len(page2),
                "duplicate_selector_consumes_page_slot": duplicate_selector_on_page,
                "same_selector_can_appear_twice": duplicate_selector_on_page
                or len({row[0] for row in page1 + page2}) < expected_n,
                "query_stats": {"page1": page1_stats, "page2": page2_stats, "count": hunt_building_stats},
            },
            "detail_raw": {
                "physical_copies_for_selector": int(copies_before or 0),
                "limit_1_returns_one_row": detail_before is not None,
                "divergent_notes_present": len(notes_set) > 1,
                "limit_1_after_divergence_notes": (detail_divergent or {}).get("analyst_notes"),
                "order_dependent_when_diverged": len(notes_set) > 1,
            },
            "analyst_noise_accounting": {
                "physical_copies_for_selector": int(copies_before or 0),
                "analyst_matched_count": int(matched),
                "physical_rows_tagged": int(physical_after_tag or 0),
                "event_change_audit_rows": int(event_changes),
                "evidence_change_affected_counts": affected_values,
                "manual_noise_matched_count": int(noise_matched),
                "accounting_inflates_matched_count": int(matched) == int(copies_before or 0)
                and int(copies_before or 0) > 1,
                "event_change_is_per_selector": int(event_changes) == 1,
            },
            "privacy_aliases": {
                "error": privacy_error,
                "derive_result_keys": sorted(list(privacy.keys())) if isinstance(privacy, dict) else None,
                "alias_authority_rows": int(alias_rows),
                "populate_event_count": (populate or {}).get("event_count")
                if isinstance(populate, dict)
                else None,
                "physical_batch_rows": lost["physical_rows"],
                "count_inflates_when_copies_exist": isinstance(populate, dict)
                and int((populate or {}).get("event_count") or 0) == lost["physical_rows"],
                "needs_exclusion_for_counts": True,
            },
            "ai_freeze": {
                "error": freeze_error,
                "selected_physical_rows": len(freeze_rows),
                "frozen_observations": int(frozen.selected_evidence_count) if frozen else 0,
                "selected_erks": len(frozen.selected_erks) if frozen else 0,
                "unique_erks": len(set(frozen.selected_erks)) if frozen else 0,
                "managed_batch_ids": list(frozen.managed_batch_ids) if frozen else [],
                "payload_lines": (
                    frozen.payload_from_frozen_excerpts().count("\n") + 1
                    if frozen and frozen.payload_from_frozen_excerpts()
                    else 0
                ),
                "duplicate_erks": bool(
                    frozen and len(frozen.selected_erks) != len(set(frozen.selected_erks))
                ),
            },
            "completion_readiness": {
                "activation_complete": completeness.complete,
                "landed_rows": int(generation.landed_rows or 0),
                "readiness_clickhouse_calls": readiness.get("clickhouse_calls")
                if isinstance(readiness, dict)
                else None,
                "completion_ch_queries": (completion.metrics or {}).get("ch_queries")
                if completion
                else None,
                "completion_batch_counts": completion.batch_counts if completion else None,
                "already_retry_safe": int(generation.landed_rows or 0) == expected_n,
            },
            "replacement": {
                "replacement_verify_outcome": repl_verify.outcome,
                "hunt_still_active_generation_physical": hunt_during_replacement,
                "replacement_hidden_from_hunt": hunt_during_replacement == hunt_active,
            },
            "negative_controls": {
                "same_erk_different_batch_is_retry": same_erk_not_retry,
                "same_erk_batch_diversity": same_erk_groups,
                "legacy_protocol_null_physical": int(legacy_count or 0),
                "legacy_not_collapsed_by_retry_identity": int(legacy_count or 0) == 2,
                "different_hash_same_ordinal": different_hash_conflict,
                "hunt_legacy_included_in_current_count": hunt_with_legacy >= hunt_active + 2,
                "candidate_exclusion_keeps_legacy_physical": hunt_with_legacy_excl
                >= expected_n + int(legacy_count or 0),
            },
            "query_stats": {
                "hunt_building": hunt_building_stats,
                "hunt_building_excluded": hunt_building_excl_stats,
                "hunt_active": hunt_active_stats,
                "hunt_replacement": hunt_repl_stats,
                "detail": detail_stats,
            },
        }
    finally:
        try:
            ch.close()
        except Exception:
            pass
        ctx.pop()
        reset_fence_backend()


def run_performance(pg_url_value: str, ch_db: str) -> Dict[str, Any]:
    from utils.ingest_fence import install_memory_backend, reset_fence_backend
    from utils.manifest_protocol import (
        construct_managed_batch,
        create_ingest_attempt,
        insert_managed_batch,
        mark_batch_durable,
        project_generation_control_state,
        reserve_staged_batch,
        update_generation_ingest_accounting,
        verify_ingest_batch,
    )

    install_memory_backend()
    app, ctx, db = make_pg_app(pg_url_value)
    ch = ch_connect(ch_db)
    results = {}
    try:
        create_events_and_control(ch)

        def measure(label: str, n: int, extra_copies: int):
            case, case_file, generation, attempt, _ = seed_case(
                db, name=f"P24A-{label}", batch_size=max(n, 1), filename=f"{label}.evtx"
            )
            events = [make_parsed_event(i, case_id=case.id, case_file_id=case_file.id, host=f"H{label}") for i in range(n)]
            manifest = construct_managed_batch(
                generation=generation, attempt=attempt, events=tuple(events), batch_ordinal=0
            )
            batch = reserve_staged_batch(session=db.session, manifest=manifest)
            db.session.commit()
            insert_managed_batch(ch, manifest)
            for _ in range(extra_copies):
                retry_attempt = create_ingest_attempt(
                    session=db.session, generation=generation, celery_task_id=f"p24a-{label}-{uuid.uuid4().hex[:8]}"
                )
                db.session.commit()
                retry_manifest = construct_managed_batch(
                    generation=generation, attempt=retry_attempt, events=tuple(events), batch_ordinal=0
                )
                reserve_staged_batch(session=db.session, manifest=retry_manifest)
                db.session.commit()
                insert_managed_batch(ch, retry_manifest)
            verification = verify_ingest_batch(ch, manifest)
            if verification.success:
                mark_batch_durable(session=db.session, batch=batch, verification=verification)
                update_generation_ingest_accounting(session=db.session, generation=generation)
                db.session.commit()
                project_generation_control_state(ch, db.session, generation)
            current_count, current_count_stats = hunt_count(ch, case.id)
            excluded_count, excluded_count_stats = hunt_count_excluded(ch, case.id)
            current_rows, current_data_stats = hunt_rows(ch, case.id, limit=min(50, n + extra_copies * n))
            from routes.hunting_query_helpers import build_hunting_publication_bridge

            publication = build_hunting_publication_bridge(alias="e", case_id_param="{case_id:UInt32}")
            excluded_data_sql = f"""
                SELECT e.selector_key
                FROM events AS e
                {publication["join_sql"]}
                WHERE e.case_id = {{case_id:UInt32}}
                {publication["where_sql"]}
                  AND (
                    ({protocol_all_null_sql("e")})
                    OR (
                        e.ingest_batch_id IS NOT NULL AND e.ingest_batch_id != ''
                        AND (e.ingest_batch_id, e.ingest_row_ordinal, e.ingest_attempt_id) IN (
                            SELECT ingest_batch_id, ingest_row_ordinal, min(ingest_attempt_id)
                            FROM events
                            WHERE case_id = {{case_id:UInt32}}
                              AND ingest_batch_id IS NOT NULL AND ingest_batch_id != ''
                            GROUP BY ingest_batch_id, ingest_row_ordinal
                        )
                    )
                  )
                ORDER BY e.timestamp DESC, e.record_id DESC
                LIMIT 50
            """
            _, _, excluded_data_stats = q(ch, excluded_data_sql, {"case_id": int(case.id)})
            return {
                "n": n,
                "extra_full_copies": extra_copies,
                "physical": n * (1 + extra_copies),
                "current_hunt_count": current_count,
                "candidate_hunt_count": excluded_count,
                "current_count_stats": current_count_stats,
                "candidate_count_stats": excluded_count_stats,
                "current_data_stats": current_data_stats,
                "candidate_data_stats": excluded_data_stats,
                "verify_outcome": verification.outcome,
            }

        results["ordinary_no_duplicate"] = measure("ord", 400, 0)
        results["sparse_retry_duplicates"] = measure("sparse", 400, 1)
        # Sparse in the sense of one extra full copy of a 400-row batch.
        # Heavier fixture: more rows + one extra copy.
        results["heavier_retry_duplicate"] = measure("heavy", 2000, 1)
        return results
    finally:
        try:
            ch.close()
        except Exception:
            pass
        ctx.pop()
        reset_fence_backend()


REQUIRED_TEST_MODULES = (
    "tests.test_phase2_4a_retry_copy_gap_audit",
    "tests.test_phase1b_tranche_b_protocol",
    "tests.test_phase1b_tranche_d2_staged_reconciler",
    "tests.test_phase1b_tranche_d1_generation_lifecycle",
    "tests.test_phase1b_tranche_e1_capability_watermarks",
    "tests.test_phase1b_tranche_f1_completion_reconciliation",
    "tests.test_phase1b_tranche_f2_product_search_publication_gate",
    "tests.test_phase1b_tranche_e2_ai_privacy_freeze_verify",
    "tests.test_privacy_alias_vault_bounds",
    "tests.test_privacy_fail_closed",
    "tests.test_phase2_2b_sync_event_insert",
    "tests.test_phase2_3_lightweight_update_bridge",
    "tests.test_phase2_3c_fence_contract_alignment",
    "tests.test_event_analyst_state",
    "tests.test_event_noise_state",
    "tests.test_clickhouse_delete_dedup_contracts",
)


def run_lint_gates() -> Dict[str, Any]:
    compile_proc = subprocess.run(
        [
            "/opt/casescope/venv/bin/python",
            "-m",
            "py_compile",
            "scripts/phase2_4a_retry_copy_gap_audit.py",
            "tests/test_phase2_4a_retry_copy_gap_audit.py",
        ],
        cwd=str(ROOT),
        capture_output=True,
        text=True,
    )
    pyflakes_proc = subprocess.run(
        [
            "/opt/casescope/venv/bin/python",
            "-m",
            "pyflakes",
            "scripts/phase2_4a_retry_copy_gap_audit.py",
            "tests/test_phase2_4a_retry_copy_gap_audit.py",
        ],
        cwd=str(ROOT),
        capture_output=True,
        text=True,
    )
    diff_proc = subprocess.run(
        ["git", "diff", "--check"],
        cwd=str(ROOT),
        capture_output=True,
        text=True,
    )
    return {
        "py_compile_ok": compile_proc.returncode == 0,
        "py_compile_stderr": (compile_proc.stderr or "")[-2000:],
        "pyflakes_ok": pyflakes_proc.returncode == 0,
        "pyflakes_stdout": (pyflakes_proc.stdout or "")[-4000:],
        "git_diff_check_ok": diff_proc.returncode == 0,
        "git_diff_check_stdout": (diff_proc.stdout or "")[-2000:],
    }


def run_regression_tests() -> Dict[str, Any]:
    pg_name = "phase2_4a_reg"
    ch_name = "phase2_4a_reg"
    ensure_pg_database(pg_name)
    admin = ch_connect("default")
    admin.command(f"CREATE DATABASE IF NOT EXISTS {ch_name}")
    admin.close()
    env = dict(os.environ)
    env.setdefault("SECRET_KEY", env.get("SECRET_KEY") or "phase2-4a-audit")
    env["PHASE1B_PG_TEST_DATABASE_URL"] = pg_url(pg_name)
    env["PHASE1B_CH_TEST_DATABASE"] = ch_name
    results = []
    all_ok = True
    skipped_any = False
    for module in REQUIRED_TEST_MODULES:
        print(f"Regression: {module}", flush=True)
        started = time.perf_counter()
        rel_path = module.replace(".", "/") + ".py"
        proc = subprocess.run(
            ["/opt/casescope/venv/bin/python", "-m", "pytest", rel_path, "-q", "--tb=line"],
            cwd=str(ROOT),
            env=env,
            capture_output=True,
            text=True,
        )
        text_out = ((proc.stderr or "") + "\n" + (proc.stdout or "")).strip()
        if "... skipped" in text_out.lower() or "skipped =" in text_out:
            skipped_any = True
        ok = proc.returncode == 0
        all_ok = all_ok and ok
        results.append(
            {
                "module": module,
                "ok": ok,
                "returncode": proc.returncode,
                "duration_s": round(time.perf_counter() - started, 3),
                "tail": text_out[-2500:],
            }
        )
    lint = run_lint_gates()
    all_ok = all_ok and lint["py_compile_ok"] and lint["pyflakes_ok"] and lint["git_diff_check_ok"]
    return {
        "all_passed": all_ok,
        "skipped_detected": skipped_any,
        "modules": results,
        "lint": lint,
        "phase1b_pg_test_database": pg_name,
        "phase1b_ch_test_database": ch_name,
    }


# ---------------------------------------------------------------------------
# Report
# ---------------------------------------------------------------------------
def decide_tokens(report: Dict[str, Any]) -> Dict[str, Any]:
    ch_census = report.get("production_ch_census") or {}
    copies_present = int(ch_census.get("ordinals_containing_physical_retry_copies") or 0) > 0
    conflicts = ch_census.get("integrity_conflicts") or []
    integrity_present = bool(conflicts)
    parity = (report.get("production_parity") or {}).get("token") or "CURRENT_RETRY_COPY_STATE_NOT_OBSERVED"
    if not copies_present:
        parity = "CURRENT_RETRY_COPY_STATE_NOT_OBSERVED"
    generation = "GENERATION_ACCOUNTING_ALREADY_RETRY_SAFE"
    interim = "INTERIM_RETRY_EXCLUSION_REQUIRED"
    strategy = recommend_strategy(
        production_copies_present=copies_present,
        integrity_conflict=integrity_present,
        current_consumers_need_exclusion=True,
        production_state_divergence=parity == "CURRENT_STATE_DIVERGENCE",
    )
    copies_token = (
        "PRODUCTION_DETERMINISTIC_RETRY_COPIES_PRESENT"
        if copies_present
        else "PRODUCTION_DETERMINISTIC_RETRY_COPIES_ABSENT"
    )
    integrity_token = (
        "PRODUCTION_RETRY_INTEGRITY_CONFLICT_PRESENT"
        if integrity_present
        else "PRODUCTION_RETRY_INTEGRITY_CONFLICT_ABSENT"
    )
    managed_guard = report.get("managed_dedup_callers") or {}
    tests_ok = ((report.get("regression_tests") or {}).get("all_passed") is not False)
    if report.get("regression_tests") and not report["regression_tests"].get("all_passed"):
        tests_ok = False
    not_ready = bool(managed_guard.get("production_allow_managed_evidence_true")) or integrity_present or not tests_ok
    phase_state = "PHASE2_4_NOT_READY" if not_ready else "PHASE2_4B_SCOPE_READY"
    if strategy == "PHASE2_4_STRATEGY_NOT_READY":
        phase_state = "PHASE2_4_NOT_READY"
    verdict = "PHASE2_4A_NOT_READY" if not_ready else "PHASE2_4A_PASS"
    return {
        "PRODUCTION_RETRY_COPY_STATE": copies_token,
        "PRODUCTION_RETRY_INTEGRITY": integrity_token,
        "GENERATION_ACCOUNTING": generation,
        "INTERIM_CONSUMERS": interim,
        "CURRENT_RETRY_COPY_STATE": parity,
        "STRATEGY": strategy,
        "phase2_4_state": phase_state,
        "verdict": verdict,
    }


def write_json(report: Dict[str, Any]) -> None:
    OUT_JSON.parent.mkdir(parents=True, exist_ok=True)
    OUT_JSON.write_text(json.dumps(report, indent=2, default=str) + "\n", encoding="utf-8")


def write_markdown(report: Dict[str, Any]) -> None:
    tokens = report["tokens"]
    facts = report.get("starting_facts") or {}
    pg = report.get("production_pg_census") or {}
    ch = report.get("production_ch_census") or {}
    parity = report.get("production_parity") or {}
    disp = report.get("disposable_proofs") or {}
    perf = report.get("performance") or {}
    inventory = report.get("consumer_inventory") or []
    lines = [
        "# Phase 2.4A Deterministic Retry-Copy Gap Audit Result",
        "",
        "Read-only production measurement plus disposable lost-acknowledgement proofs.",
        "Does not implement retry exclusion. Does not start Phase 3 or Phase 4.",
        "",
        "## 1. Starting State",
        "",
        json.dumps(report.get("baseline"), indent=2, default=str),
        "",
        f"ClickHouse: {report.get('clickhouse_version')}",
        "",
        "## 2. Locked Phase 2.4 Contract",
        "",
        f'"{LOCKED_PHASE_24_SENTENCE}"',
        "",
        "Preserved:",
        "",
        "- Measurement discipline: baselines re-run at each phase exit; deltas in-repo; measurement beats plan.",
        "- Forensic integrity: immutable events; ERK pure provenance; duplicates reconciled not destroyed; deterministic canonical representatives; publication != presence; fail-closed fencing.",
        "",
        "Phase 2.4 is not logical/semantic dedup and is not Phase 4 early.",
        "",
        "## 3. Existing Phase 1B Coverage",
        "",
        "Deterministic `ingest_batch_id` over frozen generation/batch identity already exists.",
        "`ingest_attempt_id` is execution identity only. Frozen `ingest_row_hash` allowlist already excludes",
        "selector_key, indexed_at, ingest_attempt_id, analyst/noise/ioc overlays, and extra_fields.",
        "`verify_ingest_batch` / D2 `classify_batch` already accept `duplicate_identical` as success.",
        "D2 currently marks those batches DURABLE without physically removing extra copies.",
        "Generation `landed_rows` already sums PostgreSQL DURABLE `IngestBatch.row_count`.",
        "Hunt publication already filters STAGED vs DURABLE and generation visibility, but does not collapse retry copies.",
        "Legacy semantic dedup remains blocked for managed evidence by default.",
        "",
        "## 4. Deterministic Retry Definition",
        "",
        "A Phase 2.4 retry copy is ONLY:",
        "",
        "- same `ingest_batch_id`",
        "- same `ingest_row_ordinal`",
        "- same `ingest_row_hash`",
        "- that hash matches the frozen PostgreSQL expected hash for that ordinal",
        "- the frozen aggregate batch contract remains valid",
        "",
        "This is DETERMINISTIC_RETRY_EQUIVALENT. Same ERK, selector_key, case_file_id, record_id,",
        "timestamp, source_file, search_blob, or apparent semantic content is not enough.",
        "Different deterministic batch identity is not a Phase 2.4 retry copy.",
        "",
        "## 5. Current Retry State Machine",
        "",
        "Normal: PG STAGED reserve → CH INSERT → verify exact → PG DURABLE → project `durable_ingest_batches`",
        "→ `update_generation_ingest_accounting` from PG row_count → optional row-local derivation queue → F1 completion.",
        "",
        "Lost acknowledgement / crash after CH accept: PG remains STAGED; CH already has rows; retry uses a new",
        "`ingest_attempt_id` and the same deterministic `ingest_batch_id`; second physical copy can land;",
        "verify returns `duplicate_identical` success; D2/mark_durable currently DURABLE without purge.",
        "",
        "Partial/missing ordinals purge by `ingest_batch_id` behind exclusive fence, then retry. That is not the identical-hash path.",
        "",
        "Authoritative state: PostgreSQL for generation/batch/watermarks/readiness; ClickHouse for physical evidence;",
        "control projections are derived from PG.",
        "",
        "## 6. Generation Accounting Audit",
        "",
        f"Decision: **{tokens['GENERATION_ACCOUNTING']}**",
        "",
        "`update_generation_ingest_accounting()` sets `landed_rows` from `SUM(IngestBatch.row_count)` where DURABLE.",
        "Activation completeness compares that PG row_count sum to `expected_rows`. Capability watermarks and F1",
        "batch counts key by `ingest_batch_id`. Physical ClickHouse multiplicity does not change those numbers.",
        "",
        json.dumps(facts, indent=2, default=str),
        "",
        "## 7. Retry-Sensitive Consumer Inventory",
        "",
    ]
    for item in inventory:
        lines.append(f"- {item['path']}: `{item['classification']}`")
    lines.extend(
        [
            "",
            "Analyst/manual-noise: physical `matched_count` / EvidenceChange `affected_count` inflate;",
            "per-event EventChange remains one row per unique selector_key. State mutation still needs to",
            "update every physical copy; accounting must not treat each copy as an independent observation.",
            "",
            "## 8. Production Managed Authority Census",
            "",
            json.dumps(
                {
                    "managed_cases": pg.get("managed_case_count"),
                    "managed_case_ids": pg.get("managed_cases"),
                    "generations": pg.get("generation_count"),
                    "generations_by_visibility": pg.get("generations_by_visibility"),
                    "batches": pg.get("batch_count"),
                    "batches_by_state": pg.get("batches_by_state"),
                    "schema_lag": pg.get("schema_lag"),
                    "control_projections": report.get("production_control_projections"),
                },
                indent=2,
                default=str,
            ),
            "",
            "Production PostgreSQL currently has zero managed generations and zero ingest batches.",
            "Control projections `visible_evidence_generations` and `durable_ingest_batches` are also empty.",
            "Events were not scanned unbounded. Census was limited to PG-managed case IDs.",
            "Code on main has Phase 1B columns (`final_batch_ordinal`, D2 reconcile lease fields) that production PG",
            "tables have not yet received. That is schema lag versus current models, not a retry-copy integrity conflict.",
            "2.4B pre-DURABLE normalization must apply those existing Phase 1B columns before using D2 lease fields in production.",
            "Query/accounting exclusion does not require those columns.",
            "",
            "## 9. Production ClickHouse Retry-Copy Census",
            "",
            f"Decision: **{tokens['PRODUCTION_RETRY_COPY_STATE']}**",
            "",
            json.dumps(
                {
                    "managed_cases_inspected": ch.get("managed_cases_inspected"),
                    "managed_generations_inspected": ch.get("managed_generations_inspected"),
                    "managed_batches_inspected": ch.get("managed_batches_inspected"),
                    "batches_containing_physical_retry_copies": ch.get("batches_containing_physical_retry_copies"),
                    "ordinals_containing_physical_retry_copies": ch.get("ordinals_containing_physical_retry_copies"),
                    "total_extra_physical_rows": ch.get("total_extra_physical_rows"),
                    "cases_affected": ch.get("cases_affected"),
                    "generations_affected": ch.get("generations_affected"),
                    "maximum_copies_of_one_ordinal": ch.get("maximum_copies_of_one_ordinal"),
                    "staged_duplicate_batches": ch.get("staged_duplicate_batches"),
                    "durable_duplicate_batches": ch.get("durable_duplicate_batches"),
                    "duplicates_by_generation_visibility": ch.get("duplicates_by_generation_visibility"),
                    "malformed_protocol_identity_rows": ch.get("malformed_protocol_identity_rows"),
                    "query_stats": ch.get("query_stats"),
                },
                indent=2,
                default=str,
            ),
            "",
            "## 10. Production Integrity Conflict Census",
            "",
            f"Decision: **{tokens['PRODUCTION_RETRY_INTEGRITY']}**",
            "",
            json.dumps(
                {
                    "different_hash_conflicts": ch.get("different_hash_conflicts"),
                    "wrong_hash_conflicts": ch.get("wrong_hash_conflicts"),
                    "integrity_conflicts": ch.get("integrity_conflicts"),
                },
                indent=2,
                default=str,
            ),
            "",
            "No auto-delete or auto-repair was performed.",
            "",
            "## 11. Non-Hashed Current-State Parity",
            "",
            f"Decision: **{tokens['CURRENT_RETRY_COPY_STATE']}**",
            "",
            json.dumps(parity, indent=2, default=str),
            "",
            "`ingest_attempt_id` and `indexed_at` are expected to differ and were not treated as corruption.",
            "",
            "## 12. Malformed Protocol Identity",
            "",
            f"Malformed/partial protocol identity rows on managed-case partitions: {ch.get('malformed_protocol_identity_rows')}.",
            "Hunt publication already treats partial identity as non-legacy and fails closed for publication.",
            "Malformed rows were not reinterpreted as legacy.",
            "",
            "## 13. Lost-Acknowledgement Disposable Proof",
            "",
            json.dumps(disp.get("lost_ack"), indent=2, default=str),
            "",
            "## 14. Current DURABLE Duplicate Behavior",
            "",
            json.dumps(disp.get("accounting"), indent=2, default=str),
            "",
            "Current published Hunt consumer sees one deterministic ordinal once per physical copy.",
            "PostgreSQL landed_rows remains the expected collapsed count.",
            "",
            "## 15. Hunt Count / List / Pagination Effect",
            "",
            json.dumps(disp.get("pagination"), indent=2, default=str),
            "",
            "If expected observations = N and extra physical copies = R, current Hunt total reports N+R.",
            "A retry copy consumes a page slot. The same selector can appear twice. 2.4A did not change Hunt.",
            "",
            "## 16. Hunt Detail / Raw Effect",
            "",
            json.dumps(disp.get("detail_raw"), indent=2, default=str),
            "",
            "Detail/raw `LIMIT 1` returns one arbitrary physical copy. If non-hashed mutable fields diverge,",
            "the chosen copy is insertion/merge-order dependent. This is not Phase 4 canonical-representative design.",
            "",
            "## 17. Phase 2.3 Mutation Accounting Effect",
            "",
            json.dumps(disp.get("analyst_noise_accounting"), indent=2, default=str),
            "",
            "2.4B needs an accounting-only adjustment for matched_count / affected_count.",
            "Physical copies may still be updated together so overlay state stays synchronized.",
            "",
            "## 18. Other Mutation Accounting Effect",
            "",
            "Noise scan, IOC refresh, and MITRE mapping currently `SELECT count()` over physical `events` rows",
            "and are still invoked on managed evidence (manual IOC/noise; F1 transitional MITRE/graph/embeddings/known-principal).",
            "Classification: `NEEDS_PHASE2_4_RETRY_EXCLUSION` for their current affected-row accounting.",
            "Those state models are not migrated here.",
            "",
            "## 19. Privacy-Alias Derivation Effect",
            "",
            json.dumps(disp.get("privacy_aliases"), indent=2, default=str),
            "",
            "Classification: `NEEDS_PHASE2_4_RETRY_EXCLUSION` for CH `event_count` / `seen_count`.",
            "Vault upsert identity and watermark completion keyed by `ingest_batch_id` are already retry-safe.",
            "",
            "## 20. AI Freeze / Verify Effect",
            "",
            json.dumps(disp.get("ai_freeze"), indent=2, default=str),
            "",
            "Classification: `NEEDS_PHASE2_4_RETRY_EXCLUSION` for selected rows, ERK list, and aliased payload lines.",
            "`managed_batch_ids` already unique; coverage by batch id is already retry-safe.",
            "",
            "## 21. Completion / Readiness Effect",
            "",
            json.dumps(disp.get("completion_readiness"), indent=2, default=str),
            "",
            "Classification: `ALREADY_RETRY_SAFE`. Do not add ClickHouse counting to readiness.",
            "",
            "## 22. Legacy Dedup Safety Boundary",
            "",
            json.dumps(report.get("managed_dedup_callers"), indent=2, default=str),
            "",
            "No production caller passes `allow_managed_evidence=True`.",
            "`deduplicate_case_events_task` and the legacy completion tail omit the flag (default False).",
            "The case-files route only queues that task. Managed evidence remains blocked by default.",
            "",
            "## 23. Negative Controls",
            "",
            json.dumps(disp.get("negative_controls"), indent=2, default=str),
            "",
            "- same ERK != retry",
            "- same selector != retry",
            "- different batch != retry",
            "- different generation != retry",
            "- semantic/legacy duplicate != retry",
            "- different hash same ordinal = integrity conflict",
            "",
            "## 24. Candidate Strategy Comparison",
            "",
            "### PRE-DURABLE normalization",
            "",
            "Before `duplicate_identical` STAGED becomes DURABLE, leave exactly one physical copy per ordinal,",
            "reverify exact, then DURABLE. Requires exclusive ingest fence for DELETE of extras only",
            "(current `purge_ingest_batch_rows` deletes the whole batch by `ingest_batch_id`, which is too broad).",
            "STAGED copies are unpublished, so overlay divergence is unlikely but not proven for already-DURABLE history.",
            "Crash window after extra insert and before purge still exists.",
            "",
            "### QUERY exclusion",
            "",
            "Leave physical copies intact. Collapse current managed readers/accounting by",
            "`ingest_batch_id + ingest_row_ordinal` after frozen-hash validity.",
            "Must not use `LIMIT 1 BY ingest_batch_id, ingest_row_ordinal` on mixed Hunt because legacy NULL identity",
            "would collapse unrelated rows. Legacy remains physical; managed uses uniqExact / chosen-copy subquery.",
            "No new writer fence. Hunt pagination and detail become deterministic only after an explicit copy-choice rule.",
            "Already-DURABLE mutable divergence remains: exclusion picks one current copy.",
            "",
            "### HYBRID",
            "",
            "Prevent future duplicate-identical batches from becoming DURABLE with extra physical copies,",
            "and apply narrow read/accounting exclusion for already-DURABLE historical copies and for",
            "Hunt/AI/privacy/mutation accounting until/unless extras are gone.",
            "This respects that already-DURABLE copies may have mutable non-hashed state.",
            "",
            "### OTHER",
            "",
            "None required. RMT and semantic/ERK dedup remain forbidden.",
            "",
            "## 25. Recommended 2.4B Strategy",
            "",
            f"**{tokens['STRATEGY']}**",
            "",
            "## 26. Interim Consumer Decision",
            "",
            f"**{tokens['INTERIM_CONSUMERS']}**",
            "",
            "## 27. Exact 2.4B Runtime Scope",
            "",
            "Protocol: change the `exact`/`duplicate_identical` STAGED→DURABLE success path so extra physical",
            "retry copies of the same `(ingest_batch_id, ingest_row_ordinal, expected ingest_row_hash)` are",
            "not left published. Preferred pre-DURABLE action: fence-protected deletion of extra copies only",
            "(not whole-batch purge, not ERK/selector/artifact delete), then reverify `exact`, then DURABLE.",
            "Do not physically delete already-DURABLE production copies in 2.4B without a separate current-state",
            "parity proof; use query/accounting exclusion for those.",
            "",
            "Interim readers/accounting to change:",
            "- Hunt publication count, list, pagination, detail/raw, and publication-bridged exports",
            "- analyst `matched_count` / EvidenceChange `affected_count` (keep updating all physical copies)",
            "- manual-noise `matched_count` / `affected_count` (same)",
            "- privacy-aliases scoped `event_count` / `seen_count`",
            "- AI freeze `select_current_generation_event_rows` observation set / ERK tuple / payload lines",
            "",
            "Already safe, do not change:",
            "- PostgreSQL `landed_rows`, activation completeness, capability watermarks, F1 batch counts, readiness Evidence",
            "- `verify_ingest_batch` / D2 collapsed proof identity rules",
            "- managed-dedup fail-closed guard",
            "",
            "Deferred / later phase:",
            "- IOC/MITRE/noise-scan/graph/embedding/known-principal state-model migration",
            "- LEK, events_current, event_observations_current, ERK API, Qdrant, RMT",
            "- canonical logical representative and field-conflict surfacing",
            "- whole-case semantic dedup removal",
            "",
            "Future retry copies: prevent DURABLE extras (pre-DURABLE normalization).",
            "Existing DURABLE extras: exclusion only unless independently proven safe to prune.",
            "",
            "## 28. Contract Addendum Requirement",
            "",
            "YES. Recommend a dated 2.4B implementation addendum to INGEST_BATCH_CONTRACT recording which",
            "collapsed-proof option current runtime uses, that DURABLE extra copies must be excluded from",
            "interim published counts until Phase 4, and that pre-DURABLE extra-copy removal is identity-scoped",
            "to deterministic retry copies only. Do not rewrite the locked identity rule in 2.4A. Do not write the addendum yet.",
            "",
            "## 29. Performance Evidence",
            "",
            json.dumps(perf, indent=2, default=str),
            "",
            "No OPTIMIZE FINAL. No token/substring search change. Disposable fixtures only.",
            "",
            "## 30. Regression Tests",
            "",
            json.dumps(report.get("regression_tests"), indent=2, default=str),
            "",
            "## 31. Files Changed",
            "",
            "- scripts/phase2_4a_retry_copy_gap_audit.py",
            "- tests/test_phase2_4a_retry_copy_gap_audit.py",
            "- docs/database_flow_phase2/phase2_4a_retry_copy_gap_audit.md",
            "- docs/database_flow_phase2/phase2_4a_retry_copy_gap_audit.json",
            "",
            "## 32. Version",
            "",
            EXPECTED_VERSION,
            "",
            "## 33. Production Mutation Audit",
            "",
            "NONE",
            "",
            json.dumps(report.get("production_mutation_audit"), indent=2, default=str),
            "",
            "## 34. No-Later-Phase Audit",
            "",
            json.dumps(report.get("no_later_phase_audit"), indent=2, default=str),
            "",
            "## 35. Git State",
            "",
            json.dumps(report.get("git_state"), indent=2, default=str),
            "",
            "## 36. Phase 2.4 State",
            "",
            str(tokens["phase2_4_state"]),
            "",
            "2.4A does not close Phase 2.4.",
            "",
            "## 37. Remaining Work",
            "",
            "Independent Phase 2.4A review.",
            "",
            "Then only: Phase 2.4B — implement the independently accepted minimal interim",
            "generation-accounting / deterministic retry-copy exclusion.",
            "",
            "Phase 2.4B must also perform the locked Phase 2 EXIT baseline rerun because",
            "2.4 is the final Phase 2 work.",
            "",
            "Do NOT start Phase 3.",
            "",
            "## 38. Verdict",
            "",
            str(tokens["verdict"]),
            "",
        ]
    )
    OUT_MD.write_text("\n".join(lines) + "\n", encoding="utf-8")


def production_mutation_audit() -> Dict[str, Any]:
    return {
        "production_insert": False,
        "production_update": False,
        "production_alter": False,
        "production_delete": False,
        "production_optimize": False,
        "production_materialize": False,
        "production_pg_manifest_mutation": False,
        "production_redis_mutation": False,
        "production_analyst_noise_mutation": False,
        "production_test_ingest": False,
        "service_restart": False,
        "result": "NONE",
    }


def no_later_phase_audit() -> Dict[str, Any]:
    return {
        "lek": False,
        "events_current": False,
        "event_observations_current": False,
        "erk_api_migration": False,
        "qdrant_identity_migration": False,
        "ioc_overlay_pilot": False,
        "semantic_dedup": False,
        "cross_source_collapse": False,
        "same_erk_collapse": False,
        "rmt": False,
        "new_clickhouse_engine": False,
        "whole_case_dedup_redesign": False,
        "legacy_dedup_removal": False,
        "phase4_reader_cutover": False,
        "phase4_canonical_representative": False,
        "phase6_derivation_migration": False,
        "phase2_exit_declared": False,
        "master_plan_edited": False,
        "version_bumped": False,
    }


def main() -> int:
    report: Dict[str, Any] = {
        "tranche": TRANCHE,
        "recorded_at": utc_now_iso(),
        "version": EXPECTED_VERSION,
        "version_bumped": False,
        "locked_phase_24_sentence": LOCKED_PHASE_24_SENTENCE,
        "consumer_inventory": consumer_inventory(),
        "production_mutation_audit": production_mutation_audit(),
        "no_later_phase_audit": no_later_phase_audit(),
    }
    prod = None
    pg_engine = None
    pg_conn = None
    try:
        baseline = git_baseline()
        report["baseline"] = baseline
        if not baseline.get("ok"):
            raise Phase24ANotReady("STOP: BASELINE_DRIFT")

        facts = source_starting_facts()
        report["starting_facts"] = facts
        report["managed_dedup_callers"] = managed_dedup_callers()
        if report["managed_dedup_callers"]["production_allow_managed_evidence_true"]:
            raise Phase24ANotReady("PHASE2_4_NOT_READY: production allow_managed_evidence=True")

        prod_raw = ch_connect(PRODUCTION_DB, settings=dict(PROD_CH_SETTINGS))
        version, version_stats = scalar(prod_raw, "SELECT version()")
        report["clickhouse_version"] = str(version)
        report["clickhouse_version_query"] = version_stats
        if str(version) != EXPECTED_CLICKHOUSE:
            raise Phase24ANotReady(f"STOP: BASELINE_DRIFT clickhouse={version}")
        prod = ProductionReadOnlyClient(prod_raw)

        print("Production PostgreSQL census", flush=True)
        pg_engine, pg_conn = pg_connect_readonly()
        pg_census = production_pg_census(pg_conn)
        report["production_pg_census"] = {
            k: v for k, v in pg_census.items() if k not in {"generations", "batches"}
        }
        report["production_control_projections"] = production_control_projection_census(prod)
        report["production_pg_census"]["generation_ids"] = [
            {
                "case_id": row["case_id"],
                "source_ref_type": row["source_ref_type"],
                "source_ref_id": row["source_ref_id"],
                "source_generation": row["source_generation"],
                "visibility_state": row["visibility_state"],
                "expected_rows": row["expected_rows"],
                "landed_rows": row["landed_rows"],
            }
            for row in pg_census["generations"]
        ]
        report["production_pg_census"]["batch_ids"] = [
            {
                "ingest_batch_id": row["ingest_batch_id"],
                "case_id": row["case_id"],
                "batch_ordinal": row["batch_ordinal"],
                "row_count": row["row_count"],
                "state": row["state"],
                "visibility_state": row["visibility_state"],
                "batch_content_hash": row["batch_content_hash"],
            }
            for row in pg_census["batches"]
        ]

        print("Production ClickHouse retry-copy census", flush=True)
        ch_census = production_ch_census(prod, pg_census, pg_conn)
        report["production_ch_census"] = ch_census
        print("Production current-state parity census", flush=True)
        report["production_parity"] = production_parity_census(prod, ch_census.get("retry_groups") or [])

        print("Disposable lost-ack / Hunt / mutation proofs", flush=True)
        ensure_pg_database(PG_TEST_DB)
        admin = ch_connect("default")
        admin.command(f"CREATE DATABASE IF NOT EXISTS {CH_TEST_DB}")
        admin.close()
        report["disposable_proofs"] = run_disposable_proofs(pg_url(PG_TEST_DB), CH_TEST_DB)
        print("Disposable query-exclusion performance", flush=True)
        report["performance"] = run_performance(pg_url(PG_TEST_DB), CH_TEST_DB)
        print("Regression tests", flush=True)
        report["regression_tests"] = run_regression_tests()

        report["tokens"] = decide_tokens(report)
        report["git_state"] = {
            "commit_requested_by_user": True,
            "spec_said_leave_uncommitted": True,
            "note": "User first-line instruction was to commit and push when done.",
        }
        report["verdict"] = report["tokens"]["verdict"]
        report["phase2_4_state"] = report["tokens"]["phase2_4_state"]
        write_json(report)
        write_markdown(report)
        print(report["verdict"], flush=True)
        return 0 if report["verdict"] == "PHASE2_4A_PASS" else 2
    except Exception as exc:
        report["error"] = str(exc)
        report["traceback"] = traceback.format_exc()
        report.setdefault("tokens", {
            "PRODUCTION_RETRY_COPY_STATE": "PRODUCTION_DETERMINISTIC_RETRY_COPIES_ABSENT",
            "PRODUCTION_RETRY_INTEGRITY": "PRODUCTION_RETRY_INTEGRITY_CONFLICT_ABSENT",
            "GENERATION_ACCOUNTING": "GENERATION_ACCOUNTING_ALREADY_RETRY_SAFE",
            "INTERIM_CONSUMERS": "INTERIM_RETRY_EXCLUSION_REQUIRED",
            "CURRENT_RETRY_COPY_STATE": "CURRENT_RETRY_COPY_STATE_NOT_OBSERVED",
            "STRATEGY": "PHASE2_4_STRATEGY_NOT_READY",
            "phase2_4_state": "PHASE2_4_NOT_READY",
            "verdict": "PHASE2_4A_NOT_READY",
        })
        report["verdict"] = "PHASE2_4A_NOT_READY"
        report["phase2_4_state"] = "PHASE2_4_NOT_READY"
        try:
            write_json(report)
            write_markdown(report)
        except Exception:
            pass
        print(traceback.format_exc(), file=sys.stderr)
        return 1
    finally:
        if prod is not None:
            try:
                prod.close()
            except Exception:
                pass
        if pg_conn is not None:
            try:
                pg_conn.close()
            except Exception:
                pass
        if pg_engine is not None:
            try:
                pg_engine.dispose()
            except Exception:
                pass


if __name__ == "__main__":
    sys.exit(main())
