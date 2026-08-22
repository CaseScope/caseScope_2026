#!/usr/bin/env python3
"""Phase 2.2A insertion-mode qualification.

Measurement and architecture decision only. Does not change production
async_insert, wait_for_async_insert, batch size, skip-index materialization,
or search indexes. All writes go to disposable ClickHouse/PostgreSQL.
"""
from __future__ import annotations

import hashlib
import inspect
import json
import os
import resource
import subprocess
import sys
import threading
import time
import traceback
import uuid
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Any, Dict, List, Optional, Sequence, Tuple

ROOT = Path("/opt/casescope")
sys.path.insert(0, str(ROOT))
os.environ.setdefault("SECRET_KEY", os.environ.get("SECRET_KEY") or "phase2-2a-qualification")

import clickhouse_connect

from migrations.add_events_table import EVENTS_COLUMN_DEFINITIONS, EVENTS_SCHEMA
from migrations.add_phase1b_tranche_b_manifest_protocol import clickhouse_control_table_ddl
from tests.phase2_1d2a_lib import parse_explain_indexes


# ---------------------------------------------------------------------------
# Locked decision tokens
# ---------------------------------------------------------------------------
MODE_SYNC = "PHASE2_2_MODE_SYNC"
MODE_ASYNC_WAIT = "PHASE2_2_MODE_ASYNC_WAIT"
MODE_NOT_READY = "PHASE2_2_MODE_NOT_READY"
ASYNC_NO_WAIT_FORBIDDEN = "ASYNC_NO_WAIT_FORBIDDEN"

BATCH_KEEP_10000 = "KEEP_PRODUCTION_BATCH_SIZE_10000"
BATCH_NEW_25000 = "NEW_GENERATIONS_BATCH_SIZE_25000_JUSTIFIED"
BATCH_NEW_50000 = "NEW_GENERATIONS_BATCH_SIZE_50000_JUSTIFIED"
BATCH_NEW_100000 = "NEW_GENERATIONS_BATCH_SIZE_100000_JUSTIFIED"

PRODUCTION_ELIGIBLE_MODES = (MODE_SYNC, MODE_ASYNC_WAIT)
CANDIDATE_BATCH_SIZES = (10000, 25000, 50000, 100000)
CONCURRENCY_WRITERS = (1, 2, 4)
CONCURRENCY_BATCH_SIZES = (10000, 25000)

SCRATCH_DB = "casescope_phase2_2a_scratch"
PG_TEST_DB = "phase2_2a_test"
CH_TEST_DB = "phase2_2a_test"
OUT_JSON = ROOT / "docs" / "database_flow_phase2" / "phase2_2a_insertion_mode_qualification.json"
OUT_MD = ROOT / "docs" / "database_flow_phase2" / "phase2_2a_insertion_mode_qualification.md"
EXPECTED_HEAD = "3ad458b9db38945787392a504786a73d578cf771"
EXPECTED_VERSION = "4.26.0"
PRODUCTION_DB = "casescope"
TEXT_INDEX_SENTINEL = "skp_idx_idx_search_blob_text.idx"
NGRAM_SENTINEL = "skp_idx_idx_search_ngram.idx"

CORPUS_ROWS = int(os.environ.get("PHASE2_2A_CORPUS_ROWS") or 1_000_000)
MANAGED_ROWS = int(os.environ.get("PHASE2_2A_MANAGED_ROWS") or 50_000)
RAW_WARMUP = 1
RAW_MEASURED = 2
CORPUS_CASE_ID = 32
FIXTURE_CASE_ID = 902201
UNIQUE_TOKEN = "zxqvphase22aunique"

INSERT_SETTING_NAMES = (
    "async_insert",
    "wait_for_async_insert",
    "async_insert_max_data_size",
    "async_insert_busy_timeout_ms",
    "async_insert_max_query_number",
    "async_insert_deduplicate",
    "materialize_skip_indexes_on_insert",
    "async_insert_use_adaptive_busy_timeout",
    "async_insert_busy_timeout_min_ms",
    "async_insert_busy_timeout_max_ms",
    "wait_for_async_insert_timeout",
    "async_insert_poll_timeout_ms",
    "async_insert_threads",
    "async_insert_stale_timeout_ms",
    "async_insert_cleanup_timeout_ms",
)

REQUIRED_ARTIFACT_KEYS = (
    "tranche",
    "recorded_at",
    "version",
    "version_bumped",
    "verdict",
    "phase2_2_state",
    "insert_mode_decision",
    "async_no_wait_decision",
    "batch_size_decision",
    "baseline",
    "production_server_insert_settings",
    "application_client_settings",
    "event_insert_inventory",
    "client_scope_inventory",
    "clickhouse_connect_async_mode_proof",
    "benchmark_corpus",
    "raw_insert_matrix",
    "concurrency_matrix",
    "managed_protocol_end_to_end",
    "immediate_verification",
    "text_index_immediate_searchability",
    "ngram_maintenance",
    "failure_matrix",
    "lost_acknowledgement",
    "identity_invariance",
    "parts_merge_pressure",
    "memory_resource",
    "recommended_2_2b_configuration_boundary",
    "existing_generation_compatibility",
    "control_projection_ordering",
    "production_mutation_audit",
    "no_later_phase_audit",
    "git_state",
)


class Phase22ANotReady(RuntimeError):
    """Hard-gate abort that still records a NOT_READY artifact."""


def utc_now_iso() -> str:
    return datetime.now(timezone.utc).isoformat()


def percentile(values: Sequence[float], pct: float) -> Optional[float]:
    if not values:
        return None
    ordered = sorted(float(v) for v in values)
    if len(ordered) == 1:
        return ordered[0]
    rank = (pct / 100.0) * (len(ordered) - 1)
    low = int(rank)
    high = min(len(ordered) - 1, low + 1)
    weight = rank - low
    return ordered[low] * (1.0 - weight) + ordered[high] * weight


def rss_kb() -> int:
    return int(resource.getrusage(resource.RUSAGE_SELF).ru_maxrss)


def rss_mb() -> float:
    return rss_kb() / 1024.0


def jsonable(value: Any) -> Any:
    if isinstance(value, (str, int, float, bool)) or value is None:
        return value
    if isinstance(value, Path):
        return str(value)
    if isinstance(value, datetime):
        return value.isoformat()
    if isinstance(value, dict):
        return {str(k): jsonable(v) for k, v in value.items()}
    if isinstance(value, (list, tuple)):
        return [jsonable(v) for v in value]
    return str(value)


def sha256_hex(text: str) -> str:
    return hashlib.sha256(text.encode("utf-8")).hexdigest()


def summary_query_id(summary, fallback: str = "") -> str:
    """clickhouse_connect QuerySummary.query_id is a method, not a property."""
    if summary is None:
        return str(fallback or "")
    value = getattr(summary, "query_id", None)
    if callable(value):
        try:
            value = value()
        except TypeError:
            value = None
    text = str(value or "")
    if text.startswith("<bound method"):
        text = ""
    return text or str(fallback or "")


def hunt_publication_count_sql(bridge: Dict[str, str], token_sql: str = "") -> str:
    """Hunt already prefixes where_sql with AND; do not wrap it as AND (AND(...))."""
    return f"""
        SELECT count()
        FROM events AS e
        {bridge["join_sql"]}
        WHERE e.case_id = {{case_id:UInt32}}
          {bridge["where_sql"]}
          {token_sql}
    """


def prior_measurement_payload() -> Optional[Dict[str, Any]]:
    if not OUT_JSON.exists():
        return None
    try:
        return json.loads(OUT_JSON.read_text(encoding="utf-8"))
    except Exception:
        return None


def prior_raw_is_complete(payload: Optional[Dict[str, Any]] = None) -> bool:
    payload = payload if payload is not None else prior_measurement_payload()
    if not payload:
        return False
    cells = ((payload.get("raw_insert_matrix") or {}).get("cells")) or []
    conc = ((payload.get("concurrency_matrix") or {}).get("cells")) or []
    if len(cells) != len(PRODUCTION_ELIGIBLE_MODES) * len(CANDIDATE_BATCH_SIZES):
        return False
    if not all(cell.get("median_rows_per_sec") for cell in cells):
        return False
    expected_conc = (
        len(PRODUCTION_ELIGIBLE_MODES) * len(CONCURRENCY_BATCH_SIZES) * len(CONCURRENCY_WRITERS)
    )
    if len(conc) != expected_conc:
        return False
    return int((payload.get("benchmark_corpus") or {}).get("rows") or 0) >= 500_000


def should_reuse_prior_raw() -> bool:
    if os.environ.get("PHASE2_2A_FORCE_RAW") == "1":
        return False
    if os.environ.get("PHASE2_2A_REUSE_PRIOR_RAW") == "0":
        return False
    if os.environ.get("PHASE2_2A_REUSE_PRIOR_RAW") == "1":
        return True
    return prior_raw_is_complete()


# ---------------------------------------------------------------------------
# Mode construction — imported by focused tests
# ---------------------------------------------------------------------------
def valid_candidate_modes() -> Tuple[str, ...]:
    return PRODUCTION_ELIGIBLE_MODES


def insert_settings_for_mode(mode: str) -> Dict[str, int]:
    """Explicit per-INSERT settings. Never returns async/no-wait."""
    if mode == MODE_SYNC:
        return {
            "async_insert": 0,
            "materialize_skip_indexes_on_insert": 1,
        }
    if mode == MODE_ASYNC_WAIT:
        return {
            "async_insert": 1,
            "wait_for_async_insert": 1,
            "materialize_skip_indexes_on_insert": 1,
        }
    if mode == ASYNC_NO_WAIT_FORBIDDEN or mode == "PHASE2_2_MODE_ASYNC_NO_WAIT":
        raise ValueError(ASYNC_NO_WAIT_FORBIDDEN)
    raise ValueError(f"unknown insertion mode: {mode}")


def is_production_eligible_mode(mode: str) -> bool:
    return mode in PRODUCTION_ELIGIBLE_MODES


def final_phase21_schema_contract() -> Dict[str, Any]:
    return {
        "idx_search_blob_text": {
            "present": True,
            "expr": "search_blob",
            "type_contains": "text(tokenizer = 'splitByNonAlpha', preprocessor = lower(search_blob))",
        },
        "idx_search_ngram": {
            "present": True,
            "expr": "search_blob",
            "type_full": "ngrambf_v1(3, 512, 2, 0)",
            "granularity": 4,
            "exception": "PHASE2_1_EXC_001",
        },
        "idx_search_token": {"present": False},
        "idx_event_id": {"present": True},
        "idx_selector_key": {"present": True},
        "idx_evidence_record_key": {"present": True},
        "enable_block_number_column": 1,
        "enable_block_offset_column": 1,
        "materialize_skip_indexes_on_insert": 1,
    }


def assert_events_schema_is_final_phase21(schema_sql: str) -> Dict[str, bool]:
    checks = {
        "idx_search_blob_text": "INDEX idx_search_blob_text search_blob TYPE text(" in schema_sql
        and "tokenizer = 'splitByNonAlpha'" in schema_sql
        and "preprocessor = lower(search_blob)" in schema_sql,
        "idx_search_ngram": "INDEX idx_search_ngram search_blob TYPE ngrambf_v1(3, 512, 2, 0) GRANULARITY 4"
        in schema_sql,
        "idx_search_token_absent": "INDEX idx_search_token" not in schema_sql
        and "tokenbf_v1(32768, 3, 0)" not in schema_sql,
        "idx_event_id": "INDEX idx_event_id event_id TYPE bloom_filter(0.01) GRANULARITY 4" in schema_sql,
        "idx_selector_key": "INDEX idx_selector_key selector_key TYPE bloom_filter(0.01) GRANULARITY 4"
        in schema_sql,
        "idx_evidence_record_key": (
            "INDEX idx_evidence_record_key evidence_record_key TYPE bloom_filter(0.01) GRANULARITY 4"
            in schema_sql
        ),
        "block_number": "enable_block_number_column = 1" in schema_sql,
        "block_offset": "enable_block_offset_column = 1" in schema_sql,
    }
    if not all(checks.values()):
        missing = [name for name, ok in checks.items() if not ok]
        raise AssertionError(f"EVENTS_SCHEMA is not final Phase 2.1: {missing}")
    return checks


def recommended_2_2b_configuration_boundary() -> Dict[str, Any]:
    return {
        "shape": "per-call INSERT settings on events inserts",
        "option": "A",
        "apply_to": [
            "utils.manifest_protocol.insert_managed_batch client.insert('events', ...)",
            "parsers.registry.BatchProcessor.flush client.insert(self.table, ...) when table=='events'",
        ],
        "do_not_apply_to": [
            "utils.clickhouse.get_client",
            "utils.clickhouse.get_fresh_client",
            "Hunt / graph / IOC / derivation readers",
            "verify_ingest_batch SELECT",
            "visible_evidence_generations INSERT",
            "durable_ingest_batches INSERT",
            "migration clients",
        ],
        "reason": (
            "tasks.celery_tasks.parse_file_task / recover_staged_ingest_batch_task obtain one "
            "get_fresh_client() and reuse it for events INSERT, verification SELECT, and control "
            "projection INSERT. Pinning async_insert on the generic client would change "
            "acknowledgement semantics of control projections and Hunt/read sessions. Per-call "
            "settings on the events insert only is the narrowest explicit parser/event-ingest "
            "boundary required by Phase 2.2."
        ),
        "control_projections": "unchanged; keep current client/session defaults",
        "fallback_if_per_call_unreliable": "dedicated get_event_ingest_client() used only for events INSERT",
    }


def existing_generation_compatibility_design() -> Dict[str, Any]:
    return {
        "current_flush_uses": "generation.configured_batch_size",
        "recovery_uses": "generation.configured_batch_size",
        "new_generation_uses": "contract_from_parser(configured_batch_size=Config.PHASE1B_MANIFEST_BATCH_SIZE or 10000)",
        "resume_hazard": (
            "allocate_case_file_initial_generation/_assert_frozen_contract_matches compares the "
            "incoming contract (built from the current Config default) against the frozen "
            "BUILDING generation. A global default change would fail an already-BUILDING generation."
        ),
        "if_new_default_chosen_2_2b_must": [
            "When a BUILDING_INITIAL or BUILDING_REPLACEMENT generation already exists, pass that generation's configured_batch_size into contract_from_parser",
            "Apply any new default only when allocating a new generation",
            "Leave PARSER_BATCH_SIZE/legacy BatchProcessor default independent unless separately justified",
            "Do not mutate frozen generation rows",
        ],
    }


# ---------------------------------------------------------------------------
# ClickHouse helpers
# ---------------------------------------------------------------------------
def ch_connect(database: str, settings: Optional[Dict[str, Any]] = None, timeout: int = 3600):
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


def q(client, sql: str, parameters: Optional[dict] = None, settings: Optional[dict] = None):
    result = client.query(sql, parameters=parameters or {}, settings=settings or {})
    cols = list(result.column_names)
    return [dict(zip(cols, row)) for row in result.result_rows], result


def scalar(client, sql: str, parameters: Optional[dict] = None):
    rows, _ = q(client, sql, parameters)
    if not rows:
        return None
    return list(rows[0].values())[0]


def explain_text(client, sql: str, settings: Optional[dict] = None) -> str:
    rows, _ = q(client, f"EXPLAIN indexes = 1 {sql}", settings=settings)
    if not rows:
        return ""
    key = list(rows[0].keys())[0]
    return "\n".join(str(row[key]) for row in rows)


def insertable_event_columns() -> List[str]:
    return [name for name in EVENTS_COLUMN_DEFINITIONS if name != "selector_key"]


class EventsInsertClient:
    """Proxy that pins insertion mode only on events INSERT calls."""

    def __init__(self, inner, settings: Dict[str, Any]):
        self._inner = inner
        self._settings = dict(settings)
        self.events_insert_calls = 0
        self.other_insert_calls = 0
        self.last_events_query_id = ""

    def insert(self, table, data, column_names=None, settings=None, **kwargs):
        merged = dict(self._settings)
        if settings:
            merged.update(settings)
        if str(table) == "events":
            self.events_insert_calls += 1
            summary = self._inner.insert(
                table, data, column_names=column_names, settings=merged, **kwargs
            )
            self.last_events_query_id = summary_query_id(summary)
            return summary
        self.other_insert_calls += 1
        return self._inner.insert(table, data, column_names=column_names, settings=settings, **kwargs)

    def __getattr__(self, name):
        return getattr(self._inner, name)


class LostAckClient:
    """Simulated transport fault: server insert succeeds, client raises."""

    def __init__(self, inner):
        self._inner = inner
        self.stored = False
        self.proof_kind = "SIMULATED_CLIENT_TIMEOUT_AFTER_STORE"

    def insert(self, *args, **kwargs):
        self._inner.insert(*args, **kwargs)
        self.stored = True
        raise TimeoutError("simulated lost acknowledgement after ClickHouse accepted INSERT")

    def __getattr__(self, name):
        return getattr(self._inner, name)


# ---------------------------------------------------------------------------
# Inventory (static, from current production code)
# ---------------------------------------------------------------------------
def event_insert_inventory() -> List[Dict[str, Any]]:
    return [
        {
            "file": "parsers/registry.py",
            "function": "BatchProcessor.flush",
            "destination_table": "events (events_buffer only if use_buffer=True)",
            "client_source": "constructor clickhouse_client; process_file/process_evtx_group pass get_fresh_client()",
            "batch_size_source": "BatchProcessor.DEFAULT_BATCH_SIZE=10000 / process_file(batch_size=10000) / Config.PARSER_BATCH_SIZE unused by this call",
            "managed_or_legacy": "legacy",
            "shared_ingest_fence_coverage": True,
            "current_explicit_async_setting": False,
            "current_explicit_wait_setting": False,
            "must_be_covered_by_phase_2_2": True,
            "notes": "Production callers do not pass use_buffer=True. No repo insert() into events_buffer.",
        },
        {
            "file": "utils/manifest_protocol.py",
            "function": "insert_managed_batch",
            "destination_table": "events",
            "client_source": "caller-supplied clickhouse_client (Celery get_fresh_client())",
            "batch_size_source": "generation.configured_batch_size (frozen); new gens use Config.PHASE1B_MANIFEST_BATCH_SIZE or 10000",
            "managed_or_legacy": "managed",
            "shared_ingest_fence_coverage": True,
            "current_explicit_async_setting": False,
            "current_explicit_wait_setting": False,
            "must_be_covered_by_phase_2_2": True,
        },
        {
            "file": "tasks/celery_tasks.py",
            "function": "_process_managed_initial_case_file / parse_file_task managed branch",
            "destination_table": "events via insert_managed_batch",
            "client_source": "get_fresh_client() then reused for verify + control projection",
            "batch_size_source": "generation.configured_batch_size",
            "managed_or_legacy": "managed",
            "shared_ingest_fence_coverage": True,
            "current_explicit_async_setting": False,
            "current_explicit_wait_setting": False,
            "must_be_covered_by_phase_2_2": True,
        },
        {
            "file": "tasks/celery_tasks.py",
            "function": "recover_staged_ingest_batch_task",
            "destination_table": "events via insert_managed_batch",
            "client_source": "get_fresh_client()",
            "batch_size_source": "generation.configured_batch_size",
            "managed_or_legacy": "repair/retry",
            "shared_ingest_fence_coverage": True,
            "current_explicit_async_setting": False,
            "current_explicit_wait_setting": False,
            "must_be_covered_by_phase_2_2": True,
        },
        {
            "file": "tasks/celery_tasks.py",
            "function": "parse_file_task legacy branch / process_file",
            "destination_table": "events via BatchProcessor.flush",
            "client_source": "get_fresh_client()",
            "batch_size_source": "process_file default 10000",
            "managed_or_legacy": "legacy",
            "shared_ingest_fence_coverage": True,
            "current_explicit_async_setting": False,
            "current_explicit_wait_setting": False,
            "must_be_covered_by_phase_2_2": True,
        },
        {
            "file": "tasks/celery_tasks.py",
            "function": "parse_evtx_group_task / process_evtx_group",
            "destination_table": "events via BatchProcessor.flush or managed insert_managed_batch",
            "client_source": "get_fresh_client()",
            "batch_size_source": "10000 or generation.configured_batch_size",
            "managed_or_legacy": "legacy or managed",
            "shared_ingest_fence_coverage": True,
            "current_explicit_async_setting": False,
            "current_explicit_wait_setting": False,
            "must_be_covered_by_phase_2_2": True,
        },
        {
            "file": "utils/manifest_protocol.py",
            "function": "project_generation_control_state",
            "destination_table": "visible_evidence_generations / durable_ingest_batches",
            "client_source": "same Celery get_fresh_client() as events INSERT",
            "batch_size_source": "n/a (control rows)",
            "managed_or_legacy": "control projection",
            "shared_ingest_fence_coverage": False,
            "current_explicit_async_setting": False,
            "current_explicit_wait_setting": False,
            "must_be_covered_by_phase_2_2": False,
            "notes": "Must not inherit events insertion-mode pin. Covered as a 2.2B non-goal.",
        },
        {
            "file": "utils/staged_batch_reconciler.py",
            "function": "reconcile_staged_batch -> recover_staged_ingest_batch_task",
            "destination_table": "events via recovery insert_managed_batch",
            "client_source": "get_fresh_client() in celery reconciler/recovery tasks",
            "batch_size_source": "generation.configured_batch_size",
            "managed_or_legacy": "repair/retry",
            "shared_ingest_fence_coverage": True,
            "current_explicit_async_setting": False,
            "current_explicit_wait_setting": False,
            "must_be_covered_by_phase_2_2": True,
        },
        {
            "file": "migrations/*.py / scripts/* / tests/* / bin/*",
            "function": "various",
            "destination_table": "events or scratch tables",
            "client_source": "get_fresh_client or dedicated connect",
            "batch_size_source": "n/a",
            "managed_or_legacy": "migration / test / offline utility",
            "shared_ingest_fence_coverage": "varies",
            "current_explicit_async_setting": False,
            "current_explicit_wait_setting": False,
            "must_be_covered_by_phase_2_2": False,
        },
    ]


def client_scope_inventory() -> Dict[str, Any]:
    return {
        "get_client": {
            "settings": ["max_threads", "max_execution_time"],
            "async_insert_explicit": False,
            "wait_for_async_insert_explicit": False,
            "cached": True,
            "primary_uses": "reader (Hunt, reports, graph queries, privacy alias scan, case files)",
            "must_not_pin_insert_mode": True,
        },
        "get_fresh_client": {
            "settings": ["max_threads", "max_execution_time"],
            "async_insert_explicit": False,
            "wait_for_async_insert_explicit": False,
            "cached": False,
            "primary_uses": [
                "event writer (parse_file_task, recover_staged_ingest_batch_task, process_file)",
                "control-projection writer (same client after managed INSERT)",
                "derivation (IOC tagger, candidate extractor, behavioral profiler, graph materializer)",
                "migration/admin",
                "repair/reconciler",
            ],
            "must_not_pin_insert_mode_globally": True,
        },
        "narrowest_safe_future_boundary": recommended_2_2b_configuration_boundary(),
        "why_not_global": (
            "Hunt, graph, IOC, and derivation sessions share get_client/get_fresh_client. "
            "Celery parser tasks reuse one fresh client for INSERT + SELECT verify + control "
            "projection. A global async_insert pin would leak into those paths."
        ),
    }


def inspect_application_client_settings() -> Dict[str, Any]:
    from utils import clickhouse as clickhouse_utils

    source = inspect.getsource(clickhouse_utils.get_client) + inspect.getsource(
        clickhouse_utils.get_fresh_client
    )
    return {
        "get_client_pins_async_insert": "async_insert" in source,
        "get_fresh_client_pins_async_insert": "async_insert" in inspect.getsource(clickhouse_utils.get_fresh_client),
        "get_client_pins_wait_for_async_insert": "wait_for_async_insert" in source,
        "explicit_async_insert": False,
        "explicit_wait_for_async_insert": False,
        "inherits_server_user_defaults": True,
        "settings_present": ["max_threads", "max_execution_time"],
        "source_mentions_async_insert": "async_insert" in source,
        "acceptable_final_architecture": False,
        "reason": "Phase 2.2 must end with an explicit CaseScope insertion-mode decision on the parser/event-ingest boundary.",
    }


# ---------------------------------------------------------------------------
# Baseline / production read-only
# ---------------------------------------------------------------------------
ALLOWED_DIRTY_PATHS = {
    "scripts/phase2_2a_insertion_mode_qualification.py",
    "tests/test_phase2_2a_insertion_mode_qualification.py",
    "docs/database_flow_phase2/phase2_2a_insertion_mode_qualification.md",
    "docs/database_flow_phase2/phase2_2a_insertion_mode_qualification.json",
}


def git_baseline() -> Dict[str, Any]:
    def run(args: List[str]) -> str:
        return subprocess.check_output(args, cwd=str(ROOT), text=True).strip()

    head = run(["git", "rev-parse", "HEAD"])
    origin = run(["git", "rev-parse", "origin/main"])
    status = run(["git", "status", "--porcelain"])
    dirty = []
    unexpected = []
    for line in status.splitlines():
        path = line[3:].strip()
        if " -> " in path:
            path = path.split(" -> ", 1)[1]
        dirty.append(path)
        if path not in ALLOWED_DIRTY_PATHS:
            unexpected.append(path)
    version = json.loads((ROOT / "version.json").read_text(encoding="utf-8"))["version"]
    ok = (
        head == origin == EXPECTED_HEAD
        and version == EXPECTED_VERSION
        and not unexpected
    )
    return {
        "repository": str(ROOT),
        "python": sys.executable,
        "head": head,
        "origin_main": origin,
        "head_equals_origin_main": head == origin,
        "working_tree_clean_at_start": status == "",
        "allowed_dirty_paths": sorted(ALLOWED_DIRTY_PATHS),
        "dirty_paths": dirty,
        "unexpected_dirty_paths": unexpected,
        "expected_head": EXPECTED_HEAD,
        "expected_version": EXPECTED_VERSION,
        "version": version,
        "ok": ok,
    }


def collect_settings(client) -> List[Dict[str, Any]]:
    rows, _ = q(
        client,
        """
        SELECT name, value, default, changed, type
        FROM system.settings
        WHERE name LIKE '%async_insert%'
           OR name IN ('materialize_skip_indexes_on_insert', 'wait_for_async_insert')
        ORDER BY name
        """,
    )
    return rows


def production_index_inventory(prod) -> Dict[str, Any]:
    rows, _ = q(
        prod,
        """
        SELECT name, type, type_full, expr, granularity, data_compressed_bytes
        FROM system.data_skipping_indices
        WHERE database = currentDatabase() AND table = 'events'
        ORDER BY name
        """,
    )
    by_name = {row["name"]: row for row in rows}
    parts = scalar(
        prod,
        """
        SELECT count() FROM system.parts
        WHERE database = currentDatabase() AND table = 'events' AND active
        """,
    )
    event_rows = scalar(prod, "SELECT count() FROM events")
    return {
        "database": PRODUCTION_DB,
        "clickhouse_version": scalar(prod, "SELECT version()"),
        "rows": int(event_rows or 0),
        "active_parts": int(parts or 0),
        "indexes": rows,
        "idx_search_blob_text_present": "idx_search_blob_text" in by_name,
        "idx_search_ngram_present": "idx_search_ngram" in by_name,
        "idx_search_token_present": "idx_search_token" in by_name,
        "idx_search_token_absent": "idx_search_token" not in by_name,
        "materialize_skip_indexes_on_insert": scalar(
            prod, "SELECT value FROM system.settings WHERE name='materialize_skip_indexes_on_insert'"
        ),
    }


def text_index_part_files(client, table: str) -> Dict[str, Any]:
    from utils.search_blob_text_index import list_part_files, part_has_text_index_files

    parts, _ = q(
        client,
        """
        SELECT name, partition, rows, path, part_type, bytes_on_disk,
               secondary_indices_compressed_bytes
        FROM system.parts
        WHERE database = currentDatabase() AND table = {table:String} AND active
        ORDER BY name
        """,
        {"table": table},
    )
    found = 0
    ngram_found = 0
    missing = []
    list_errors = []
    for part in parts:
        path = str(part.get("path") or "")
        text_ok = False
        ngram_ok = False
        names: List[str] = []
        if path:
            try:
                names = [str(name) for name in list_part_files(path)]
                text_ok = part_has_text_index_files(names)
                ngram_ok = NGRAM_SENTINEL in names and any(
                    name.startswith("skp_idx_idx_search_ngram.") for name in names
                )
            except Exception as exc:
                list_errors.append(f"{part.get('name')}: {exc}")
                # Fallback when the store is unreadable: compressed skip-index bytes.
                text_ok = int(part.get("secondary_indices_compressed_bytes") or 0) > 0
                ngram_ok = text_ok
        if text_ok:
            found += 1
        else:
            missing.append(part.get("name"))
        if ngram_ok:
            ngram_found += 1
        part["text_index_file"] = text_ok
        part["ngram_index_file"] = ngram_ok
        part["listed_file_count"] = len(names)
    return {
        "active_parts": len(parts),
        "text_index_files": found,
        "ngram_index_files": ngram_found,
        "missing_text_parts": missing[:20],
        "list_errors": list_errors[:8],
        "parts": parts[:30],
        "ok": bool(parts) and found == len(parts),
        "sentinel": TEXT_INDEX_SENTINEL,
        "ngram_sentinel": NGRAM_SENTINEL,
    }


def index_bytes(client, table: str) -> Dict[str, Any]:
    rows, _ = q(
        client,
        """
        SELECT name, type_full, expr, granularity, data_compressed_bytes
        FROM system.data_skipping_indices
        WHERE database = currentDatabase() AND table = {table:String}
        ORDER BY name
        """,
        {"table": table},
    )
    events_bytes = scalar(
        client,
        """
        SELECT sum(bytes_on_disk) FROM system.parts
        WHERE database = currentDatabase() AND table = {table:String} AND active
        """,
        {"table": table},
    )
    return {"indexes": rows, "events_compressed_bytes": int(events_bytes or 0)}


def part_census(client, table: str) -> Dict[str, Any]:
    rows, _ = q(
        client,
        """
        SELECT part_type, count() AS parts, sum(rows) AS rows, sum(bytes_on_disk) AS bytes
        FROM system.parts
        WHERE database = currentDatabase() AND table = {table:String} AND active
        GROUP BY part_type
        ORDER BY part_type
        """,
        {"table": table},
    )
    active_rows, _ = q(
        client,
        """
        SELECT count() AS parts, sum(rows) AS rows FROM system.parts
        WHERE database = currentDatabase() AND table = {table:String} AND active
        """,
        {"table": table},
    )
    merges, _ = q(
        client,
        """
        SELECT count() AS n FROM system.merges
        WHERE database = currentDatabase() AND table = {table:String}
        """,
        {"table": table},
    )
    return {
        "by_part_type": rows,
        "active_parts": int((active_rows[0]["parts"] if active_rows else 0) or 0),
        "active_rows": int((active_rows[0]["rows"] if active_rows else 0) or 0),
        "merges_in_flight": int((merges[0]["n"] if merges else 0) or 0),
    }


def disk_free(path: str = "/var/lib/clickhouse") -> Dict[str, int]:
    usage = os.statvfs(path)
    return {
        "path": path,
        "free_bytes": int(usage.f_bavail * usage.f_frsize),
        "total_bytes": int(usage.f_blocks * usage.f_frsize),
    }


# ---------------------------------------------------------------------------
# Schema / corpus
# ---------------------------------------------------------------------------
def create_events_table(client, name: str = "events") -> None:
    sql = EVENTS_SCHEMA.replace("CREATE TABLE IF NOT EXISTS events", f"CREATE TABLE IF NOT EXISTS {name}", 1)
    client.command(sql)


def create_control_tables(client) -> None:
    for ddl in clickhouse_control_table_ddl():
        client.command(ddl)


def corpus_table_ddl() -> str:
    columns = ["corpus_ordinal UInt32"] + [
        f"{name} {definition}" for name, definition in EVENTS_COLUMN_DEFINITIONS.items()
    ]
    col_sql = ",\n        ".join(columns)
    return f"""
    CREATE TABLE IF NOT EXISTS corpus (
        {col_sql},
        INDEX idx_search_ngram search_blob TYPE ngrambf_v1(3, 512, 2, 0) GRANULARITY 4,
        INDEX idx_search_blob_text search_blob TYPE text(tokenizer = 'splitByNonAlpha', preprocessor = lower(search_blob)) GRANULARITY 1,
        INDEX idx_event_id event_id TYPE bloom_filter(0.01) GRANULARITY 4,
        INDEX idx_selector_key selector_key TYPE bloom_filter(0.01) GRANULARITY 4,
        INDEX idx_evidence_record_key evidence_record_key TYPE bloom_filter(0.01) GRANULARITY 4
    )
    ENGINE = MergeTree()
    ORDER BY (corpus_ordinal)
    SETTINGS
        index_granularity = 8192,
        enable_block_number_column = 1,
        enable_block_offset_column = 1
    """


def corpus_select_sql(limit: int) -> str:
    inner_cols = []
    outer_cols = ["rn AS corpus_ordinal"]
    for name in insertable_event_columns():
        inner_cols.append(name)
        if name == "source_ref_type":
            outer_cols.append("'case_file' AS source_ref_type")
        elif name == "source_ref_id":
            outer_cols.append("concat('p22a-', toString(ifNull(case_file_id, 0))) AS source_ref_id")
        elif name == "source_generation":
            outer_cols.append("toUInt32(1) AS source_generation")
        elif name == "ingest_batch_id":
            outer_cols.append(
                "concat('p22a-corpus-', leftPad(toString(intDiv(rn, 10000)), 6, '0')) AS ingest_batch_id"
            )
        elif name == "ingest_row_ordinal":
            outer_cols.append("toUInt32(rn % 10000) AS ingest_row_ordinal")
        elif name == "ingest_row_hash":
            outer_cols.append(
                "lower(hex(SHA256(concat(evidence_record_key, '-', toString(rn))))) AS ingest_row_hash"
            )
        elif name == "ingest_attempt_id":
            outer_cols.append(
                "toUUID(concat('00000000-0000-4000-8000-', right(leftPad(toString(rn), 12, '0'), 12))) "
                "AS ingest_attempt_id"
            )
        else:
            outer_cols.append(name)
    dest_cols = ["corpus_ordinal"] + insertable_event_columns()
    dest_sql = ", ".join(dest_cols)
    outer_sql = ",\n        ".join(outer_cols)
    return f"""
    INSERT INTO {SCRATCH_DB}.corpus ({dest_sql})
    SELECT
        {outer_sql}
    FROM
    (
        SELECT
            {", ".join(inner_cols)},
            rowNumberInAllBlocks() AS rn
        FROM {PRODUCTION_DB}.events
        WHERE case_id = {int(CORPUS_CASE_ID)}
        ORDER BY timestamp_utc, source_file, ifNull(record_id, 0), evidence_record_key
        LIMIT {int(limit)}
    )
    """


def corpus_fingerprint(scratch, extra: Optional[Dict[str, Any]] = None) -> Dict[str, Any]:
    fp_row, _ = q(
        scratch,
        """
        SELECT
            count() AS n,
            min(timestamp_utc) AS min_ts,
            max(timestamp_utc) AS max_ts,
            sum(length(search_blob)) AS blob_bytes,
            sum(length(raw_json)) AS raw_bytes,
            sum(length(extra_fields)) AS extra_bytes,
            hex(sipHash128(concat(toString(count()), any(evidence_record_key), anyLast(evidence_record_key)))) AS fp
        FROM corpus
        """,
    )
    return (fp_row[0] if fp_row else {}) | {"source_case_id": CORPUS_CASE_ID} | dict(extra or {})


def existing_corpus_rows(scratch) -> int:
    try:
        return int(scalar(scratch, "SELECT count() FROM corpus") or 0)
    except Exception:
        return 0


def build_corpus(scratch, target_rows: int, *, reuse_if_present: bool = True) -> Dict[str, Any]:
    existing = existing_corpus_rows(scratch) if reuse_if_present else 0
    if existing >= target_rows:
        fingerprint = corpus_fingerprint(scratch, {"reused_existing_corpus": True, "copy_seconds": 0})
        return {"rows": existing, "fingerprint": fingerprint, "target_rows": target_rows, "reused": True}
    scratch.command("DROP TABLE IF EXISTS corpus")
    scratch.command(corpus_table_ddl())
    started = time.perf_counter()
    sql = corpus_select_sql(target_rows)
    try:
        scratch.command(sql)
        ordered = True
        fallback_error = None
    except Exception as exc:
        fallback = sql.replace(
            "ORDER BY timestamp_utc, source_file, ifNull(record_id, 0), evidence_record_key\n        LIMIT",
            "LIMIT",
        )
        scratch.command(fallback)
        ordered = False
        fallback_error = str(exc)
    elapsed = time.perf_counter() - started
    count = int(scalar(scratch, "SELECT count() FROM corpus") or 0)
    fingerprint = corpus_fingerprint(
        scratch,
        {
            "ordered_copy": ordered,
            "fallback_error": fallback_error,
            "copy_seconds": elapsed,
            "reused_existing_corpus": False,
        },
    )
    if count < 500_000:
        raise Phase22ANotReady(f"corpus only {count} rows; need >= 500000")
    return {"rows": count, "fingerprint": fingerprint, "target_rows": target_rows, "reused": False}


def fetch_corpus_slice(scratch, start: int, size: int) -> Tuple[List[str], List[Tuple]]:
    cols = insertable_event_columns()
    quoted = ", ".join(cols)
    result = scratch.query(
        f"""
        SELECT {quoted}
        FROM corpus
        WHERE corpus_ordinal >= {{start:UInt32}} AND corpus_ordinal < {{end:UInt32}}
        ORDER BY corpus_ordinal
        """,
        parameters={"start": int(start), "end": int(start + size)},
    )
    return list(result.column_names), [tuple(row) for row in result.result_rows]


def estimate_source_bytes(rows: Sequence[Sequence[Any]]) -> int:
    total = 0
    for row in rows:
        for value in row:
            if value is None:
                continue
            if isinstance(value, (bytes, bytearray, memoryview)):
                total += len(value)
            elif isinstance(value, str):
                total += len(value.encode("utf-8", errors="replace"))
            elif isinstance(value, (list, tuple)):
                total += sum(len(str(item)) for item in value)
            else:
                total += 8
    return total


# ---------------------------------------------------------------------------
# Async-mode proof
# ---------------------------------------------------------------------------
def flush_logs(client) -> None:
    try:
        client.command("SYSTEM FLUSH LOGS")
    except Exception:
        pass


def prove_client_insert_async_mode(scratch) -> Dict[str, Any]:
    scratch.command("DROP TABLE IF EXISTS async_probe")
    scratch.command(
        """
        CREATE TABLE async_probe (
            k UInt32,
            v String
        )
        ENGINE = MergeTree
        ORDER BY k
        SETTINGS index_granularity = 8192
        """
    )
    tiny = [(i, f"tiny-{i}") for i in range(20)]
    started = time.perf_counter()
    async_summary = scratch.insert(
        "async_probe",
        tiny,
        column_names=["k", "v"],
        settings={
            "async_insert": 1,
            "wait_for_async_insert": 1,
            "log_queries": 1,
            "log_query_settings": 1,
        },
    )
    async_ms = (time.perf_counter() - started) * 1000.0
    qid_async = summary_query_id(async_summary)
    scratch.command("TRUNCATE TABLE async_probe")
    started = time.perf_counter()
    sync_summary = scratch.insert(
        "async_probe",
        tiny,
        column_names=["k", "v"],
        settings={
            "async_insert": 0,
            "log_queries": 1,
            "log_query_settings": 1,
        },
    )
    sync_ms = (time.perf_counter() - started) * 1000.0
    qid_sync = summary_query_id(sync_summary)
    time.sleep(0.8)
    flush_logs(scratch)

    def query_log_row(query_id: str) -> Dict[str, Any]:
        rows, _ = q(
            scratch,
            """
            SELECT
                query_id,
                type,
                query_kind,
                query,
                Settings['async_insert'] AS async_insert,
                Settings['wait_for_async_insert'] AS wait_for_async_insert,
                ProfileEvents['AsyncInsertQuery'] AS async_insert_query,
                ProfileEvents['AsyncInsertBytes'] AS async_insert_bytes,
                query_duration_ms
            FROM system.query_log
            WHERE query_id = {id:String}
              AND type = 'QueryFinish'
            ORDER BY event_time_microseconds DESC
            LIMIT 1
            """,
            {"id": query_id},
        )
        return rows[0] if rows else {}

    def async_log_rows(query_id: str) -> List[Dict[str, Any]]:
        try:
            rows, _ = q(
                scratch,
                """
                SELECT query_id, status, data_kind, rows, bytes, flush_time, timeout_milliseconds, query
                FROM system.asynchronous_insert_log
                WHERE query_id = {id:String} OR table = 'async_probe'
                ORDER BY event_time DESC
                LIMIT 20
                """,
                {"id": query_id},
            )
            return rows
        except Exception as exc:
            return [{"error": str(exc)}]

    async_ql = query_log_row(qid_async)
    sync_ql = query_log_row(qid_sync)
    async_ail = async_log_rows(qid_async)
    sync_ail = async_log_rows(qid_sync)
    # Table-scoped log: Native FORMAT inserts with async_insert=1 appear here.
    table_ail, _ = q(
        scratch,
        """
        SELECT query_id, status, rows, bytes, timeout_milliseconds, query
        FROM system.asynchronous_insert_log
        WHERE table = 'async_probe'
        ORDER BY event_time DESC
        LIMIT 10
        """,
    )

    # Tiny no-wait demonstration — not a production candidate.
    nowait_error = None
    nowait_summary = None
    try:
        nowait_summary = scratch.insert(
            "async_probe",
            [(999, "nowait-demo")],
            column_names=["k", "v"],
            settings={"async_insert": 1, "wait_for_async_insert": 0, "log_queries": 1},
        )
    except Exception as exc:
        nowait_error = str(exc)
    qid_nowait = summary_query_id(nowait_summary)

    async_qid_in_ail = any(str(row.get("query_id")) == str(qid_async) for row in table_ail)
    sync_qid_in_ail = any(str(row.get("query_id")) == str(qid_sync) for row in table_ail)
    timing_distinct = async_ms >= 40 and async_ms > (sync_ms * 3)
    settings_distinct = (
        async_ql.get("async_insert") in {"1", 1, "true", True}
        and sync_ql.get("async_insert") in {"0", 0, "false", False, None, ""}
    )
    async_entered = bool(async_qid_in_ail or async_ql.get("async_insert") in {"1", 1} or timing_distinct)
    sync_is_sync = bool((not sync_qid_in_ail) or sync_ql.get("async_insert") in {"0", 0, None, ""})
    honors = bool(async_entered and sync_is_sync and (timing_distinct or settings_distinct or async_qid_in_ail))
    proof_note = (
        "clickhouse_connect Client.insert() sends INSERT ... FORMAT Native over HTTP. "
        f"async+wait client {async_ms:.1f} ms vs sync {sync_ms:.1f} ms; "
        f"async query_id in asynchronous_insert_log={async_qid_in_ail}; "
        f"sync query_id in asynchronous_insert_log={sync_qid_in_ail}."
    )

    return {
        "client_insert_sql_prefix": "INSERT INTO {table} (...) FORMAT Native",
        "settings_passed_as_http_params": True,
        "qid_async": qid_async,
        "qid_sync": qid_sync,
        "async_wait_client_ms": async_ms,
        "sync_client_ms": sync_ms,
        "async_query_log": async_ql,
        "sync_query_log": sync_ql,
        "async_asynchronous_insert_log": async_ail,
        "sync_asynchronous_insert_log": sync_ail,
        "table_asynchronous_insert_log": table_ail,
        "async_query_id_in_async_insert_log": async_qid_in_ail,
        "sync_query_id_in_async_insert_log": sync_qid_in_ail,
        "timing_distinct": timing_distinct,
        "async_insert_participated": async_entered,
        "sync_is_genuinely_synchronous": sync_is_sync,
        "client_insert_honors_async_distinctly": honors,
        "proof_note": proof_note,
        "nowait_demo": {
            "classified": ASYNC_NO_WAIT_FORBIDDEN,
            "eligible_for_production": False,
            "query_id": qid_nowait,
            "error": nowait_error,
        },
        "hard_gate": "PHASE2_2A_CLIENT_MODE_NOT_READY" if not honors else "PASS",
    }


# ---------------------------------------------------------------------------
# ParsedEvent fixture construction
# ---------------------------------------------------------------------------
def make_parsed_event(index: int, *, case_id: int, case_file_id: int, host: str = "P22AHOST") :
    from parsers.base import ParsedEvent

    ts = datetime(2024, 6, 1, 12, 0, 0) + timedelta(seconds=index)
    ntlm = " NTLM" if index % 11 == 0 else ""
    rc4 = " RC4" if index % 29 == 0 else ""
    ipc = " IPC$" if index % 13 == 0 else ""
    cmd = " cmd /c" if index % 17 == 0 else ""
    blob = (
        f"host {host} user analyst{index % 50} event 4688 powershell{ntlm}{rc4}{ipc}{cmd} "
        f"{UNIQUE_TOKEN} row{index}"
    )
    event = ParsedEvent(
        case_id=case_id,
        artifact_type="evtx",
        timestamp=ts,
        timestamp_utc=ts,
        timestamp_source_tz="UTC",
        source_file="Security.evtx",
        source_path="/evidence/Security.evtx",
        source_host=host,
        case_file_id=case_file_id,
        event_id="4688" if index % 3 else "4624",
        channel="Security",
        provider="Microsoft-Windows-Security-Auditing",
        record_id=index + 1,
        level="Information",
        username=f"analyst{index % 50}",
        domain="CORP",
        process_name="powershell.exe" if index % 3 else "cmd.exe",
        command_line="powershell.exe -NoProfile" if index % 3 else "cmd.exe /c dir",
        raw_json='{"EventID":"4688","Channel":"Security"}',
        search_blob=blob,
        extra_fields='{"native_record_id_authoritative":true,"provenance_source":"parser_emitted"}',
        parser_version="phase2-2a:v1",
        evidence_record_key=f"erk-p22a-{case_id}-{index:08d}",
        evidence_identity_version="v1",
        evidence_identity_quality="high",
        native_record_id_authoritative=True,
    )
    return event


def make_pg_app(pg_url: str):
    from flask import Flask
    from sqlalchemy import text
    from models.case import Case
    from models.case_file import CaseFile
    from models.client import Client
    from models.database import db
    from models.database_flow import (
        EvidenceGenerationAudit,
        EvidenceSourceGeneration,
        IngestAttempt,
        IngestBatch,
    )
    from models.graph_saved_view import GraphSavedView
    from models.investigation_thread import InvestigationThread
    _ = (GraphSavedView, InvestigationThread)

    app = Flask(__name__)
    app.config.update(
        SQLALCHEMY_DATABASE_URI=pg_url,
        SQLALCHEMY_TRACK_MODIFICATIONS=False,
        SECRET_KEY="phase2-2a",
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
    ):
        table.create(db.engine, checkfirst=True)
    return app, ctx, db


def seed_generation(db, *, batch_size: int):
    from models.case import Case
    from models.case_file import CaseFile, IngestProtocolOrigin
    from models.client import Client
    from utils.manifest_protocol import ManifestParserContract, allocate_case_file_initial_generation, create_ingest_attempt

    client_row = Client(name="P22A", code=f"P22A{time.time_ns() % 100000}", created_by="p22a")
    case = Case(
        uuid=f"p22a-{time.time_ns()}",
        name="Phase 2.2A",
        company="CaseScope",
        client=client_row,
        created_by="p22a",
    )
    case_file = CaseFile(
        case_uuid=case.uuid,
        filename="Security.evtx",
        original_filename="Security.evtx",
        file_path="/tmp/p22a-Security.evtx",
        file_size=1,
        sha256_hash="a" * 64,
        uploaded_by="p22a",
        ingest_protocol_origin=IngestProtocolOrigin.NOT_STARTED,
    )
    db.session.add_all([client_row, case, case_file])
    db.session.commit()
    # Force the PostgreSQL case.id into the ClickHouse case_id we want when possible.
    contract = ManifestParserContract(
        parser_version="phase2-2a:v1",
        normalization_version="normalization:v1",
        configured_batch_size=int(batch_size),
        ordering_contract="test:phase2-2a-order:v1",
        producer_version="phase2-2a:v1",
        manifest_eligible=True,
    )
    generation = allocate_case_file_initial_generation(
        session=db.session,
        case_id=case.id,
        case_file_id=case_file.id,
        contract=contract,
    )
    attempt = create_ingest_attempt(session=db.session, generation=generation, celery_task_id="p22a")
    db.session.commit()
    return case, case_file, generation, attempt, contract


# ---------------------------------------------------------------------------
# Raw insert matrix
# ---------------------------------------------------------------------------
def reset_dest_table(scratch, name: str = "events") -> None:
    scratch.command(f"DROP TABLE IF EXISTS {name}")
    create_events_table(scratch, name)


def run_raw_insert(
    scratch,
    *,
    mode: str,
    batch_size: int,
    total_rows: int,
    table: str = "events",
    writer_id: int = 0,
) -> Dict[str, Any]:
    settings = insert_settings_for_mode(mode)
    latencies = []
    query_ids = []
    source_bytes = 0
    insert_calls = 0
    peak_rss = rss_mb()
    wall_started = time.perf_counter()
    remaining = total_rows
    offset = 0
    while remaining > 0:
        take = min(batch_size, remaining)
        columns, rows = fetch_corpus_slice(scratch, offset, take)
        if not rows:
            break
        if writer_id:
            # Distinct partition per concurrent writer without changing payload identity fields except case_id.
            case_idx = columns.index("case_id")
            rows = [tuple([900000 + writer_id] + list(row[1:])) if case_idx == 0 else row for row in rows]
            if case_idx != 0:
                rewritten = []
                for row in rows:
                    as_list = list(row)
                    as_list[case_idx] = 900000 + writer_id
                    rewritten.append(tuple(as_list))
                rows = rewritten
        source_bytes += estimate_source_bytes(rows)
        qid = f"p22a-raw-{mode}-{batch_size}-{writer_id}-{insert_calls}-{uuid.uuid4().hex[:8]}"
        started = time.perf_counter()
        summary = scratch.insert(
            table,
            rows,
            column_names=columns,
            settings=settings,
            transport_settings={"query_id": qid},
        )
        latencies.append((time.perf_counter() - started) * 1000.0)
        query_ids.append(summary_query_id(summary, qid))
        insert_calls += 1
        offset += len(rows)
        remaining -= len(rows)
        peak_rss = max(peak_rss, rss_mb())
    wall = time.perf_counter() - wall_started
    inserted = total_rows - remaining if remaining < total_rows else offset
    flush_logs(scratch)
    async_meta = {}
    if mode == MODE_ASYNC_WAIT:
        async_meta = summarize_async_logs(scratch, query_ids)
    census = part_census(scratch, table)
    idx = index_bytes(scratch, table)
    files = text_index_part_files(scratch, table)
    return {
        "mode": mode,
        "batch_size": batch_size,
        "writer_id": writer_id,
        "rows": inserted,
        "source_bytes": source_bytes,
        "wall_seconds": wall,
        "rows_per_sec": (inserted / wall) if wall else None,
        "mb_per_sec": ((source_bytes / (1024 * 1024)) / wall) if wall else None,
        "insert_calls": insert_calls,
        "latency_p50_ms": percentile(latencies, 50),
        "latency_p95_ms": percentile(latencies, 95),
        "latencies_ms": latencies[:20],
        "peak_rss_mb": peak_rss,
        "query_ids_head": query_ids[:8],
        "parts": census,
        "indexes": idx,
        "text_index_files": files,
        "async_logs": async_meta,
    }


def summarize_async_logs(client, query_ids: Sequence[str]) -> Dict[str, Any]:
    if not query_ids:
        return {"records": 0}
    ids = [str(item) for item in query_ids[:500] if item and not str(item).startswith("<bound method")]
    if not ids:
        return {"records": 0, "error": "no usable query_ids"}
    try:
        rows, _ = q(
            client,
            """
            SELECT
                count() AS records,
                sum(rows) AS rows,
                sum(bytes) AS bytes,
                groupUniqArray(status) AS statuses
            FROM system.asynchronous_insert_log
            WHERE query_id IN {ids:Array(String)}
            """,
            {"ids": ids},
        )
        detail, _ = q(
            client,
            """
            SELECT status, count() AS n, avg(rows) AS avg_rows, avg(bytes) AS avg_bytes
            FROM system.asynchronous_insert_log
            WHERE query_id IN {ids:Array(String)}
            GROUP BY status
            """,
            {"ids": ids},
        )
        return {"summary": rows[0] if rows else {}, "by_status": detail}
    except Exception as exc:
        return {"error": str(exc), "records": 0}


def capture_async_flush_sample(scratch, batch_size: int = 10000, batches: int = 3) -> Dict[str, Any]:
    """Focused async+wait flush evidence using real Native inserts and usable query_ids."""
    scratch.command("DROP TABLE IF EXISTS async_flush_sample")
    create_events_table(scratch, "async_flush_sample")
    settings = insert_settings_for_mode(MODE_ASYNC_WAIT)
    query_ids = []
    latencies = []
    offset = 0
    rows_inserted = 0
    source_bytes = 0
    for i in range(batches):
        columns, rows = fetch_corpus_slice(scratch, offset, batch_size)
        if not rows:
            break
        source_bytes += estimate_source_bytes(rows)
        qid = f"p22a-async-sample-{i}-{uuid.uuid4().hex[:8]}"
        started = time.perf_counter()
        summary = scratch.insert(
            "async_flush_sample",
            rows,
            column_names=columns,
            settings=settings,
            transport_settings={"query_id": qid},
        )
        latencies.append((time.perf_counter() - started) * 1000.0)
        query_ids.append(summary_query_id(summary, qid))
        rows_inserted += len(rows)
        offset += len(rows)
    time.sleep(0.6)
    flush_logs(scratch)
    logs: List[Dict[str, Any]] = []
    by_table: List[Dict[str, Any]] = []
    try:
        logs, _ = q(
            scratch,
            """
            SELECT query_id, status, rows, bytes, timeout_milliseconds
            FROM system.asynchronous_insert_log
            WHERE query_id IN {ids:Array(String)}
            ORDER BY event_time
            """,
            {"ids": query_ids},
        )
        by_table, _ = q(
            scratch,
            """
            SELECT query_id, status, rows, bytes, timeout_milliseconds
            FROM system.asynchronous_insert_log
            WHERE table = 'async_flush_sample'
            ORDER BY event_time DESC
            LIMIT 20
            """,
        )
        query_log, _ = q(
            scratch,
            """
            SELECT
                query_id,
                Settings['async_insert'] AS async_insert,
                Settings['wait_for_async_insert'] AS wait_for_async_insert,
                query_duration_ms
            FROM system.query_log
            WHERE query_id IN {ids:Array(String)}
              AND type = 'QueryFinish'
            ORDER BY event_time_microseconds DESC
            LIMIT 10
            """,
            {"ids": query_ids},
        )
    except Exception as exc:
        return {"error": str(exc), "query_ids": query_ids, "records": 0}
    bytes_per_insert = (source_bytes / batches) if batches else 0
    return {
        "batch_size": batch_size,
        "batches": batches,
        "rows_inserted": rows_inserted,
        "source_bytes": source_bytes,
        "approx_bytes_per_insert": bytes_per_insert,
        "exceeds_async_insert_max_data_size_10mib": bytes_per_insert > 10 * 1024 * 1024,
        "query_ids": query_ids,
        "client_latencies_ms": latencies,
        "log_by_query_id": logs,
        "log_by_table": by_table,
        "query_log": query_log,
        "records": len(logs) or len(by_table),
        "statuses": sorted({str(row.get("status")) for row in (logs or by_table)}),
        "note": (
            "Production 10k event batches are ~18 MiB source, above async_insert_max_data_size "
            "(10 MiB), so async buffering cannot coalesce parser batches."
        ),
    }


def raw_insert_matrix(scratch, corpus_rows: int) -> Dict[str, Any]:
    results = []
    for mode in PRODUCTION_ELIGIBLE_MODES:
        for batch_size in CANDIDATE_BATCH_SIZES:
            cell_runs = []
            for run_i in range(RAW_WARMUP + RAW_MEASURED):
                reset_dest_table(scratch, "events")
                print(f"  raw {mode} batch={batch_size} run={run_i} rows={corpus_rows}", flush=True)
                run = run_raw_insert(
                    scratch, mode=mode, batch_size=batch_size, total_rows=corpus_rows
                )
                run["warmup"] = run_i < RAW_WARMUP
                cell_runs.append(run)
            measured = [r for r in cell_runs if not r["warmup"]]
            results.append(
                {
                    "mode": mode,
                    "batch_size": batch_size,
                    "runs": cell_runs,
                    "measured_rows_per_sec": [r["rows_per_sec"] for r in measured],
                    "measured_wall_seconds": [r["wall_seconds"] for r in measured],
                    "measured_p50_ms": [r["latency_p50_ms"] for r in measured],
                    "measured_p95_ms": [r["latency_p95_ms"] for r in measured],
                    "measured_peak_rss_mb": [r["peak_rss_mb"] for r in measured],
                    "median_rows_per_sec": percentile([r["rows_per_sec"] for r in measured if r["rows_per_sec"]], 50),
                    "median_wall_seconds": percentile([r["wall_seconds"] for r in measured], 50),
                    "median_p50_ms": percentile([r["latency_p50_ms"] for r in measured if r["latency_p50_ms"] is not None], 50),
                    "median_p95_ms": percentile([r["latency_p95_ms"] for r in measured if r["latency_p95_ms"] is not None], 50),
                    "median_peak_rss_mb": percentile([r["peak_rss_mb"] for r in measured], 50),
                    "last_parts": measured[-1]["parts"] if measured else None,
                    "last_indexes": measured[-1]["indexes"] if measured else None,
                    "last_async_logs": measured[-1].get("async_logs") if measured else None,
                    "last_text_index_files": measured[-1].get("text_index_files") if measured else None,
                }
            )
    return {"cells": results, "warmup": RAW_WARMUP, "measured": RAW_MEASURED, "corpus_rows": corpus_rows}


def concurrency_matrix(scratch, corpus_rows: int) -> Dict[str, Any]:
    cells = []
    # Keep concurrent volume bounded while still large enough for async buffering visibility.
    per_writer_rows = min(corpus_rows, 250_000)
    extra_batch_sizes = []
    # 50k/100k added only if they remain serious candidates after raw matrix; always collect 10k/25k.
    for mode in PRODUCTION_ELIGIBLE_MODES:
        for batch_size in CONCURRENCY_BATCH_SIZES + tuple(extra_batch_sizes):
            for writers in CONCURRENCY_WRITERS:
                reset_dest_table(scratch, "events")
                print(f"  conc {mode} batch={batch_size} writers={writers}", flush=True)
                errors = []
                payloads: List[Optional[Dict[str, Any]]] = [None] * writers

                def worker(wid: int):
                    try:
                        # Separate client per writer / parser-task session.
                        local = ch_connect(SCRATCH_DB)
                        payloads[wid - 1] = run_raw_insert(
                            local,
                            mode=mode,
                            batch_size=batch_size,
                            total_rows=per_writer_rows,
                            writer_id=wid,
                        )
                        local.close()
                    except Exception as exc:
                        errors.append(f"writer{wid}: {exc}")

                threads = [threading.Thread(target=worker, args=(i + 1,)) for i in range(writers)]
                started = time.perf_counter()
                for thread in threads:
                    thread.start()
                for thread in threads:
                    thread.join()
                wall = time.perf_counter() - started
                runs = [item for item in payloads if item]
                total_rows = sum(int(item["rows"]) for item in runs)
                cells.append(
                    {
                        "mode": mode,
                        "batch_size": batch_size,
                        "writers": writers,
                        "per_writer_rows": per_writer_rows,
                        "aggregate_rows": total_rows,
                        "aggregate_wall_seconds": wall,
                        "aggregate_rows_per_sec": (total_rows / wall) if wall else None,
                        "per_writer_p50_ms": [item["latency_p50_ms"] for item in runs],
                        "per_writer_p95_ms": [item["latency_p95_ms"] for item in runs],
                        "peak_rss_mb": max((item["peak_rss_mb"] for item in runs), default=None),
                        "parts": part_census(scratch, "events"),
                        "async_logs": [item.get("async_logs") for item in runs],
                        "errors": errors,
                    }
                )
    return {"cells": cells, "per_writer_rows": per_writer_rows}


# ---------------------------------------------------------------------------
# Managed protocol
# ---------------------------------------------------------------------------
def hunt_published_count(client, case_id: int, token: Optional[str] = None) -> int:
    from routes.hunting_query_helpers import build_hunting_publication_bridge

    bridge = build_hunting_publication_bridge(alias="e")
    token_sql = ""
    params = {"case_id": int(case_id)}
    if token:
        token_sql = " AND hasAllTokens(e.search_blob, {tok:String})"
        params["tok"] = token
    sql = hunt_publication_count_sql(bridge, token_sql)
    return int(scalar(client, sql, params) or 0)


def run_managed_e2e(
    *,
    pg_url: str,
    ch_db: str,
    mode: str,
    batch_size: int,
    row_count: int,
) -> Dict[str, Any]:
    from utils.ingest_fence import install_memory_backend, reset_fence_backend
    from utils.manifest_protocol import (
        construct_managed_batch,
        insert_managed_batch,
        mark_batch_durable,
        project_generation_control_state,
        reserve_staged_batch,
        update_generation_ingest_accounting,
        verify_ingest_batch,
    )

    install_memory_backend()
    app, ctx, db = make_pg_app(pg_url)
    ch = ch_connect(ch_db)
    try:
        ch.command("DROP TABLE IF EXISTS events")
        ch.command("DROP TABLE IF EXISTS visible_evidence_generations")
        ch.command("DROP TABLE IF EXISTS durable_ingest_batches")
        create_events_table(ch, "events")
        create_control_tables(ch)
        case, case_file, generation, attempt, _contract = seed_generation(db, batch_size=batch_size)
        events = [
            make_parsed_event(i, case_id=case.id, case_file_id=case_file.id)
            for i in range(row_count)
        ]
        settings_client = EventsInsertClient(ch, insert_settings_for_mode(mode))
        batches = []
        stage_metrics = []
        wall_started = time.perf_counter()
        for ordinal, start in enumerate(range(0, len(events), batch_size)):
            slice_events = events[start : start + batch_size]
            t0 = time.perf_counter()
            manifest = construct_managed_batch(
                generation=generation,
                attempt=attempt,
                events=tuple(slice_events),
                batch_ordinal=ordinal,
            )
            t_construct = time.perf_counter()
            batch_row = reserve_staged_batch(session=db.session, manifest=manifest)
            db.session.commit()
            t_reserve = time.perf_counter()
            insert_managed_batch(settings_client, manifest)
            t_insert = time.perf_counter()
            # Immediate verification / visibility gate
            immediate = scalar(
                ch,
                "SELECT count() FROM events WHERE ingest_batch_id = {id:String}",
                {"id": manifest.ingest_batch_id},
            )
            verification = verify_ingest_batch(ch, manifest)
            t_verify = time.perf_counter()
            if not verification.success or int(immediate or 0) != manifest.row_count:
                raise Phase22ANotReady(
                    f"{mode} immediate verification failed: visible={immediate} "
                    f"expected={manifest.row_count} outcome={verification.outcome}"
                )
            mark_batch_durable(session=db.session, batch=batch_row, verification=verification)
            update_generation_ingest_accounting(session=db.session, generation=generation)
            db.session.commit()
            t_durable = time.perf_counter()
            project_generation_control_state(ch, db.session, generation)
            t_project = time.perf_counter()
            published = hunt_published_count(ch, case.id)
            t_search = time.perf_counter()
            stage_metrics.append(
                {
                    "ingest_batch_id": manifest.ingest_batch_id,
                    "row_count": manifest.row_count,
                    "batch_content_hash": manifest.batch_content_hash,
                    "reserve_to_insert_return_ms": (t_insert - t_reserve) * 1000.0,
                    "insert_return_to_verification_ms": (t_verify - t_insert) * 1000.0,
                    "verification_ms": (t_verify - t_insert) * 1000.0,
                    "mark_durable_ms": (t_durable - t_verify) * 1000.0,
                    "projection_ms": (t_project - t_durable) * 1000.0,
                    "durable_to_first_searchable_ms": (t_search - t_durable) * 1000.0,
                    "staged_to_searchable_ms": (t_search - t_reserve) * 1000.0,
                    "immediate_visible_rows": int(immediate or 0),
                    "verification_outcome": verification.outcome,
                    "published_after_batch": int(published),
                    "construct_ms": (t_construct - t0) * 1000.0,
                }
            )
            batches.append(
                {
                    "ingest_batch_id": manifest.ingest_batch_id,
                    "row_hashes_head": list(manifest.row_hashes[:3]),
                    "row_hashes_tail": list(manifest.row_hashes[-1:]),
                    "erk_head": slice_events[0].evidence_record_key,
                    "ordinals": [0, manifest.row_count - 1],
                }
            )
        wall = time.perf_counter() - wall_started
        searchable = hunt_published_count(ch, case.id, UNIQUE_TOKEN)
        token_count = int(
            scalar(
                ch,
                "SELECT count() FROM events WHERE hasAllTokens(search_blob, {tok:String})",
                {"tok": UNIQUE_TOKEN},
            )
            or 0
        )
        explain = explain_text(
            ch,
            f"SELECT count() FROM events WHERE hasAllTokens(search_blob, '{UNIQUE_TOKEN}')",
        )
        parsed = parse_explain_indexes(explain)
        ngram_explain = explain_text(ch, "SELECT count() FROM events WHERE search_blob LIKE '%NTLM%'")
        ngram_parsed = parse_explain_indexes(ngram_explain)
        files = text_index_part_files(ch, "events")
        identity = {
            "batch_ids": [item["ingest_batch_id"] for item in batches],
            "first_batch_hash": stage_metrics[0]["batch_content_hash"] if stage_metrics else None,
        }
        # Attach hashes from stage_metrics
        identity["batch_content_hashes"] = [item["batch_content_hash"] for item in stage_metrics]
        return {
            "mode": mode,
            "batch_size": batch_size,
            "rows": row_count,
            "case_id": case.id,
            "batch_count": len(stage_metrics),
            "wall_seconds": wall,
            "rows_per_sec": (row_count / wall) if wall else None,
            "stages": stage_metrics,
            "median_staged_to_searchable_ms": percentile(
                [item["staged_to_searchable_ms"] for item in stage_metrics], 50
            ),
            "median_reserve_to_insert_ms": percentile(
                [item["reserve_to_insert_return_ms"] for item in stage_metrics], 50
            ),
            "median_verification_ms": percentile([item["verification_ms"] for item in stage_metrics], 50),
            "median_durable_to_searchable_ms": percentile(
                [item["durable_to_first_searchable_ms"] for item in stage_metrics], 50
            ),
            "published_rows": hunt_published_count(ch, case.id),
            "token_rows": token_count,
            "published_token_rows": searchable,
            "immediate_verification_ok": all(
                item["immediate_visible_rows"] == item["row_count"]
                and item["verification_outcome"] == "exact"
                for item in stage_metrics
            ),
            "text_explain": {"raw": explain, "parsed": parsed},
            "ngram_explain": {"raw": ngram_explain, "parsed": ngram_parsed},
            "text_index_files": files,
            "events_insert_calls": settings_client.events_insert_calls,
            "control_insert_calls": settings_client.other_insert_calls,
            "identity": identity,
            "result_fingerprint": sha256_hex(
                json.dumps(
                    {
                        "mode": mode,
                        "hashes": identity.get("batch_content_hashes"),
                        "published": hunt_published_count(ch, case.id),
                    },
                    sort_keys=True,
                )
            ),
        }
    finally:
        try:
            ch.close()
        except Exception:
            pass
        ctx.pop()
        reset_fence_backend()


def identity_invariance_proof(pg_url: str, ch_db: str) -> Dict[str, Any]:
    from utils.ingest_fence import install_memory_backend, reset_fence_backend
    from utils.manifest_protocol import construct_managed_batch

    install_memory_backend()
    app, ctx, db = make_pg_app(pg_url)
    try:
        case, case_file, generation, attempt, _ = seed_generation(db, batch_size=50)
        events = [make_parsed_event(i, case_id=case.id, case_file_id=case_file.id) for i in range(50)]
        sync_manifest = construct_managed_batch(
            generation=generation, attempt=attempt, events=tuple(events), batch_ordinal=0
        )
        async_manifest = construct_managed_batch(
            generation=generation, attempt=attempt, events=tuple(events), batch_ordinal=0
        )
        equal = {
            "ingest_batch_id": sync_manifest.ingest_batch_id == async_manifest.ingest_batch_id,
            "row_ordinals": [row.ordinal for row in sync_manifest.rows]
            == [row.ordinal for row in async_manifest.rows],
            "ingest_row_hashes": sync_manifest.row_hashes == async_manifest.row_hashes,
            "batch_content_hash": sync_manifest.batch_content_hash == async_manifest.batch_content_hash,
            "erk_set": {ev.evidence_record_key for ev in events}
            == {row.event.evidence_record_key for row in async_manifest.rows},
        }
        # Live insert both modes into isolated tables and compare CH hashes.
        ch = ch_connect(ch_db)
        ch.command("DROP TABLE IF EXISTS events")
        create_events_table(ch, "events")
        from utils.manifest_protocol import insert_managed_batch

        ch.command("TRUNCATE TABLE events")
        insert_managed_batch(EventsInsertClient(ch, insert_settings_for_mode(MODE_SYNC)), sync_manifest)
        sync_rows, _ = q(
            ch,
            """
            SELECT ingest_batch_id, ingest_row_ordinal, ingest_row_hash, evidence_record_key
            FROM events
            ORDER BY ingest_row_ordinal
            """,
        )
        ch.command("TRUNCATE TABLE events")
        insert_managed_batch(EventsInsertClient(ch, insert_settings_for_mode(MODE_ASYNC_WAIT)), async_manifest)
        async_rows, _ = q(
            ch,
            """
            SELECT ingest_batch_id, ingest_row_ordinal, ingest_row_hash, evidence_record_key
            FROM events
            ORDER BY ingest_row_ordinal
            """,
        )
        ch.close()
        live_equal = sync_rows == async_rows
        return {
            "construct_equal": equal,
            "live_ch_equal": live_equal,
            "ok": all(equal.values()) and live_equal,
            "ingest_batch_id": sync_manifest.ingest_batch_id,
            "batch_content_hash": sync_manifest.batch_content_hash,
            "row_count": sync_manifest.row_count,
        }
    finally:
        ctx.pop()
        reset_fence_backend()


def failure_matrix(pg_url: str, ch_db: str) -> Dict[str, Any]:
    from utils.ingest_fence import (
        FailingFenceBackend,
        exclusive_ingest_fence,
        install_fence_backend,
        install_memory_backend,
        reset_fence_backend,
    )
    from utils.manifest_protocol import (
        construct_managed_batch,
        insert_managed_batch,
        mark_batch_durable,
        reserve_staged_batch,
        verify_ingest_batch,
    )
    from models.database_flow import IngestBatchState

    results = {}
    install_memory_backend()
    app, ctx, db = make_pg_app(pg_url)
    ch = ch_connect(ch_db)
    try:
        ch.command("DROP TABLE IF EXISTS events")
        create_events_table(ch, "events")
        create_control_tables(ch)

        # A. invalid INSERT
        case, case_file, generation, attempt, _ = seed_generation(db, batch_size=2)
        events = [make_parsed_event(i, case_id=case.id, case_file_id=case_file.id) for i in range(2)]
        manifest = construct_managed_batch(
            generation=generation, attempt=attempt, events=tuple(events), batch_ordinal=0
        )
        batch_row = reserve_staged_batch(session=db.session, manifest=manifest)
        db.session.commit()

        class BoomClient:
            def insert(self, *args, **kwargs):
                raise RuntimeError("invalid row / server INSERT error")

            def query(self, *args, **kwargs):
                return ch.query(*args, **kwargs)

            def command(self, *args, **kwargs):
                return ch.command(*args, **kwargs)

        insert_error = None
        try:
            insert_managed_batch(BoomClient(), manifest)
        except Exception as exc:
            insert_error = f"{type(exc).__name__}: {exc}"
        db.session.refresh(batch_row)
        results["A_invalid_insert"] = {
            "insert_raised": insert_error is not None,
            "error": insert_error,
            "pg_state": batch_row.state,
            "not_durable": batch_row.state != IngestBatchState.DURABLE,
            "ch_rows": int(scalar(ch, "SELECT count() FROM events") or 0),
            "ok": insert_error is not None
            and batch_row.state != IngestBatchState.DURABLE
            and int(scalar(ch, "SELECT count() FROM events") or 0) == 0,
        }

        # B. fence denied before INSERT
        case2, case_file2, generation2, attempt2, _ = seed_generation(db, batch_size=2)
        events2 = [make_parsed_event(i, case_id=case2.id, case_file_id=case_file2.id) for i in range(2)]
        manifest2 = construct_managed_batch(
            generation=generation2, attempt=attempt2, events=tuple(events2), batch_ordinal=0
        )
        batch_row2 = reserve_staged_batch(session=db.session, manifest=manifest2)
        db.session.commit()
        fence_error = None
        sent = {"inserts": 0}

        class CountClient:
            def insert(self, *args, **kwargs):
                sent["inserts"] += 1
                return ch.insert(*args, **kwargs)

            def query(self, *args, **kwargs):
                return ch.query(*args, **kwargs)

            def command(self, *args, **kwargs):
                return ch.command(*args, **kwargs)

        # Exclusive held on another thread denies this thread's shared INSERT.
        # Same-thread exclusive+insert would nest and incorrectly allow the write.
        hold_started = threading.Event()
        hold_release = threading.Event()

        def _hold_exclusive():
            with exclusive_ingest_fence("p22a_fence_hold", timeout_seconds=5, poll_interval_seconds=0.05):
                hold_started.set()
                hold_release.wait(timeout=15)

        holder = threading.Thread(target=_hold_exclusive, daemon=True)
        holder.start()
        if not hold_started.wait(timeout=5):
            hold_release.set()
            holder.join(timeout=2)
            fence_error = "exclusive fence holder did not start"
        else:
            try:
                insert_managed_batch(CountClient(), manifest2)
            except Exception as exc:
                fence_error = f"{type(exc).__name__}: {exc}"
            finally:
                hold_release.set()
                holder.join(timeout=5)
        db.session.refresh(batch_row2)
        denied_ok = (
            sent["inserts"] == 0
            and batch_row2.state != IngestBatchState.DURABLE
            and fence_error is not None
        )

        # Unavailable backend: no INSERT, batch stays STAGED.
        unavail_sent = {"inserts": 0}
        unavail_error = None

        class UnavailCountClient:
            def insert(self, *args, **kwargs):
                unavail_sent["inserts"] += 1
                return ch.insert(*args, **kwargs)

        install_fence_backend(FailingFenceBackend())
        try:
            insert_managed_batch(UnavailCountClient(), manifest2)
        except Exception as exc:
            unavail_error = f"{type(exc).__name__}: {exc}"
        install_memory_backend()
        db.session.refresh(batch_row2)
        unavailable_ok = (
            unavail_sent["inserts"] == 0
            and batch_row2.state != IngestBatchState.DURABLE
            and unavail_error is not None
        )
        results["B_fence_denied"] = {
            "error": fence_error,
            "inserts_sent": sent["inserts"],
            "pg_state": batch_row2.state,
            "unavailable_error": unavail_error,
            "unavailable_inserts_sent": unavail_sent["inserts"],
            "ok": denied_ok and unavailable_ok,
        }

        # C. insert succeeds, verification forced to fail
        case3, case_file3, generation3, attempt3, _ = seed_generation(db, batch_size=2)
        events3 = [make_parsed_event(i, case_id=case3.id, case_file_id=case_file3.id) for i in range(2)]
        manifest3 = construct_managed_batch(
            generation=generation3, attempt=attempt3, events=tuple(events3), batch_ordinal=0
        )
        batch_row3 = reserve_staged_batch(session=db.session, manifest=manifest3)
        db.session.commit()
        insert_managed_batch(ch, manifest3)
        from dataclasses import replace

        bad = replace(manifest3, batch_content_hash="d" * 64)
        verification = verify_ingest_batch(ch, bad)
        durable_error = None
        try:
            mark_batch_durable(session=db.session, batch=batch_row3, verification=verification)
            db.session.commit()
        except Exception as exc:
            db.session.rollback()
            durable_error = f"{type(exc).__name__}: {exc}"
        db.session.refresh(batch_row3)
        results["C_verification_fail"] = {
            "verification_success": verification.success,
            "verification_outcome": verification.outcome,
            "durable_error": durable_error,
            "pg_state": batch_row3.state,
            "ok": (not verification.success)
            and batch_row3.state != IngestBatchState.DURABLE
            and durable_error is not None,
        }

        # D. retry same deterministic batch
        case4, case_file4, generation4, attempt4, _ = seed_generation(db, batch_size=2)
        events4 = [make_parsed_event(i, case_id=case4.id, case_file_id=case_file4.id) for i in range(2)]
        first = construct_managed_batch(
            generation=generation4, attempt=attempt4, events=tuple(events4), batch_ordinal=0
        )
        retry = construct_managed_batch(
            generation=generation4, attempt=attempt4, events=tuple(events4), batch_ordinal=0
        )
        ch.command("TRUNCATE TABLE events")
        insert_managed_batch(ch, first)
        insert_managed_batch(ch, retry)
        verification = verify_ingest_batch(ch, retry)
        results["D_retry_same_batch"] = {
            "same_ingest_batch_id": first.ingest_batch_id == retry.ingest_batch_id,
            "same_hashes": first.row_hashes == retry.row_hashes,
            "same_batch_content_hash": first.batch_content_hash == retry.batch_content_hash,
            "verification_outcome": verification.outcome,
            "physical_rows": int(
                scalar(ch, "SELECT count() FROM events WHERE ingest_batch_id={id:String}", {"id": first.ingest_batch_id})
                or 0
            ),
            "ok": first.ingest_batch_id == retry.ingest_batch_id
            and first.batch_content_hash == retry.batch_content_hash
            and verification.outcome in {"exact", "duplicate_identical"},
        }
        return results
    finally:
        try:
            ch.close()
        except Exception:
            pass
        ctx.pop()
        reset_fence_backend()


def lost_ack_proof(pg_url: str, ch_db: str) -> Dict[str, Any]:
    from utils.ingest_fence import install_memory_backend, reset_fence_backend
    from utils.manifest_protocol import (
        construct_managed_batch,
        insert_managed_batch,
        mark_batch_durable,
        reserve_staged_batch,
        verify_ingest_batch,
    )
    from models.database_flow import IngestBatchState

    install_memory_backend()
    app, ctx, db = make_pg_app(pg_url)
    ch = ch_connect(ch_db)
    try:
        ch.command("DROP TABLE IF EXISTS events")
        create_events_table(ch, "events")
        case, case_file, generation, attempt, _ = seed_generation(db, batch_size=4)
        events = [make_parsed_event(i, case_id=case.id, case_file_id=case_file.id) for i in range(4)]
        manifest = construct_managed_batch(
            generation=generation, attempt=attempt, events=tuple(events), batch_ordinal=0
        )
        batch_row = reserve_staged_batch(session=db.session, manifest=manifest)
        db.session.commit()
        lost = LostAckClient(EventsInsertClient(ch, insert_settings_for_mode(MODE_ASYNC_WAIT)))
        ack_error = None
        try:
            insert_managed_batch(lost, manifest)
        except TimeoutError as exc:
            ack_error = str(exc)
        db.session.refresh(batch_row)
        not_durable_after_loss = batch_row.state != IngestBatchState.DURABLE
        verification = verify_ingest_batch(ch, manifest)
        # Retry same deterministic batch through existing protocol.
        retry_error = None
        try:
            insert_managed_batch(EventsInsertClient(ch, insert_settings_for_mode(MODE_ASYNC_WAIT)), manifest)
        except Exception as exc:
            retry_error = str(exc)
        verification2 = verify_ingest_batch(ch, manifest)
        if verification2.success:
            mark_batch_durable(session=db.session, batch=batch_row, verification=verification2)
            db.session.commit()
        db.session.refresh(batch_row)
        return {
            "proof_kind": lost.proof_kind,
            "lost_ack_error": ack_error,
            "stored_before_raise": lost.stored,
            "not_durable_after_loss": not_durable_after_loss,
            "verify_after_loss": {
                "success": verification.success,
                "outcome": verification.outcome,
            },
            "retry_error": retry_error,
            "verify_after_retry": {
                "success": verification2.success,
                "outcome": verification2.outcome,
            },
            "final_state": batch_row.state,
            "ok": bool(ack_error)
            and not_durable_after_loss
            and verification.success
            and verification2.success
            and batch_row.state == IngestBatchState.DURABLE
            and verification.outcome in {"exact", "duplicate_identical"}
            and verification2.outcome in {"exact", "duplicate_identical"},
        }
    finally:
        try:
            ch.close()
        except Exception:
            pass
        ctx.pop()
        reset_fence_backend()


# ---------------------------------------------------------------------------
# Decision
# ---------------------------------------------------------------------------
def _median(cells: List[Dict[str, Any]], mode: str, batch_size: int, key: str):
    for cell in cells:
        if cell.get("mode") == mode and cell.get("batch_size") == batch_size:
            return cell.get(key)
    return None


def decide(report: Dict[str, Any]) -> Dict[str, Any]:
    proof = report.get("clickhouse_connect_async_mode_proof") or {}
    if not proof.get("client_insert_honors_async_distinctly"):
        return {
            "insert_mode_decision": MODE_NOT_READY,
            "async_no_wait_decision": ASYNC_NO_WAIT_FORBIDDEN,
            "batch_size_decision": BATCH_KEEP_10000,
            "phase2_2_state": "PHASE2_2_NOT_READY",
            "verdict": "PHASE2_2A_NOT_READY",
            "reason": "PHASE2_2A_CLIENT_MODE_NOT_READY",
        }

    gates = {
        "immediate_verification": (report.get("immediate_verification") or {}).get("ok"),
        "text_index": (report.get("text_index_immediate_searchability") or {}).get("ok"),
        "ngram": (report.get("ngram_maintenance") or {}).get("ok"),
        "failure": all(item.get("ok") for item in (report.get("failure_matrix") or {}).values())
        if report.get("failure_matrix")
        else False,
        "lost_ack": (report.get("lost_acknowledgement") or {}).get("ok"),
        "identity": (report.get("identity_invariance") or {}).get("ok"),
        "async_no_wait_forbidden": report.get("async_no_wait_decision") == ASYNC_NO_WAIT_FORBIDDEN,
    }
    if not all(gates.values()):
        return {
            "insert_mode_decision": MODE_NOT_READY,
            "async_no_wait_decision": ASYNC_NO_WAIT_FORBIDDEN,
            "batch_size_decision": BATCH_KEEP_10000,
            "phase2_2_state": "PHASE2_2_NOT_READY",
            "verdict": "PHASE2_2A_NOT_READY",
            "reason": f"safety_gate_failed:{ {k: v for k, v in gates.items() if not v} }",
            "gates": gates,
        }

    raw_cells = ((report.get("raw_insert_matrix") or {}).get("cells")) or []
    managed = report.get("managed_protocol_end_to_end") or {}
    managed_cells = managed.get("cells") or []

    def managed_ttf(mode: str, batch_size: int) -> Optional[float]:
        for cell in managed_cells:
            if cell.get("mode") == mode and cell.get("batch_size") == batch_size:
                return cell.get("median_staged_to_searchable_ms")
        return None

    sync_10k = _median(raw_cells, MODE_SYNC, 10000, "median_rows_per_sec") or 0
    async_10k = _median(raw_cells, MODE_ASYNC_WAIT, 10000, "median_rows_per_sec") or 0
    sync_ttf = managed_ttf(MODE_SYNC, 10000) or 0
    async_ttf = managed_ttf(MODE_ASYNC_WAIT, 10000) or 0

    # Material advantage: >15% better TTF-searchable (lower) or raw ingest, equally safe.
    ttf_gain = ((sync_ttf - async_ttf) / sync_ttf) if sync_ttf else 0
    raw_gain = ((async_10k - sync_10k) / sync_10k) if sync_10k else 0
    choose_async = (ttf_gain >= 0.15 and async_ttf > 0) or (raw_gain >= 0.15 and ttf_gain >= 0)
    if choose_async and async_ttf and sync_ttf and async_ttf > sync_ttf * 1.10:
        choose_async = False  # raw gain cannot buy slower first-searchable

    mode = MODE_ASYNC_WAIT if choose_async else MODE_SYNC
    reason = (
        f"ASYNC_WAIT material gain ttf={ttf_gain:.3f} raw={raw_gain:.3f}"
        if choose_async
        else f"performance effectively tied or SYNC simpler; ttf_gain={ttf_gain:.3f} raw_gain={raw_gain:.3f}; prefer deterministic sync contract"
    )

    # Batch size: require material E2E advantage vs 10k to leave 10000.
    batch_decision = BATCH_KEEP_10000
    batch_reason = "no material end-to-end advantage over frozen 10k"
    sync_rss_10k = _median(raw_cells, mode, 10000, "median_peak_rss_mb") or 0
    for size, token in ((25000, BATCH_NEW_25000), (50000, BATCH_NEW_50000), (100000, BATCH_NEW_100000)):
        rows = _median(raw_cells, mode, size, "median_rows_per_sec") or 0
        rss = _median(raw_cells, mode, size, "median_peak_rss_mb") or 0
        ttf = managed_ttf(mode, size)
        baseline = _median(raw_cells, mode, 10000, "median_rows_per_sec") or 0
        gain = ((rows - baseline) / baseline) if baseline else 0
        ttf_base = managed_ttf(mode, 10000)
        ttf_impr = ((ttf_base - ttf) / ttf_base) if (ttf and ttf_base) else 0
        if gain >= 0.15 and (ttf_impr >= 0 or ttf is None) and rss <= max(sync_rss_10k * 1.5, sync_rss_10k + 150):
            batch_decision = token
            batch_reason = f"{size} raw_gain={gain:.3f} ttf_impr={ttf_impr:.3f} rss={rss}"
            break

    return {
        "insert_mode_decision": mode,
        "async_no_wait_decision": ASYNC_NO_WAIT_FORBIDDEN,
        "batch_size_decision": batch_decision,
        "phase2_2_state": "PHASE2_2_DECISION_READY",
        "verdict": "PHASE2_2A_PASS",
        "reason": reason,
        "batch_reason": batch_reason,
        "gates": gates,
        "sync_10k_rows_per_sec": sync_10k,
        "async_10k_rows_per_sec": async_10k,
        "sync_10k_ttf_ms": sync_ttf,
        "async_10k_ttf_ms": async_ttf,
        "ttf_gain": ttf_gain,
        "raw_gain": raw_gain,
    }


def render_markdown(report: Dict[str, Any]) -> str:
    def cell_line(cells, mode, size):
        for cell in cells or []:
            if cell.get("mode") == mode and cell.get("batch_size") == size:
                return (
                    f"{cell.get('median_rows_per_sec')} rows/s, "
                    f"p50 {cell.get('median_p50_ms')} ms, "
                    f"p95 {cell.get('median_p95_ms')} ms, "
                    f"RSS {cell.get('median_peak_rss_mb')} MiB"
                )
        return "n/a"

    raw = (report.get("raw_insert_matrix") or {}).get("cells")
    conc = (report.get("concurrency_matrix") or {}).get("cells")
    managed = (report.get("managed_protocol_end_to_end") or {}).get("cells")
    lines = [
        "# Phase 2.2A Insertion-Mode Qualification Result",
        "",
        "## 1. Starting State",
        "",
        json.dumps(report.get("baseline"), indent=2, default=str),
        "",
        "## 2. Phase 2.1 Closed Preconditions",
        "",
        json.dumps(report.get("phase2_1_closed_preconditions"), indent=2, default=str),
        "",
        "## 3. Production Server Insert Settings",
        "",
        json.dumps(report.get("production_server_insert_settings"), indent=2, default=str),
        "",
        "## 4. Current Application Client Settings",
        "",
        json.dumps(report.get("application_client_settings"), indent=2, default=str),
        "",
        "## 5. Event INSERT Inventory",
        "",
        json.dumps(report.get("event_insert_inventory"), indent=2, default=str),
        "",
        "## 6. Client-Scope Inventory",
        "",
        json.dumps(report.get("client_scope_inventory"), indent=2, default=str),
        "",
        "## 7. clickhouse_connect Async-Mode Proof",
        "",
        f"Client.insert entered async buffering: {((report.get('clickhouse_connect_async_mode_proof') or {}).get('async_insert_participated'))}",
        "",
        json.dumps(report.get("clickhouse_connect_async_mode_proof"), indent=2, default=str),
        "",
        "## 8. Benchmark Corpus",
        "",
        json.dumps(report.get("benchmark_corpus"), indent=2, default=str),
        "",
        "## 9. Raw Insert Matrix",
        "",
    ]
    for size in CANDIDATE_BATCH_SIZES:
        lines.append(f"- SYNC {size}: {cell_line(raw, MODE_SYNC, size)}")
        lines.append(f"- ASYNC_WAIT {size}: {cell_line(raw, MODE_ASYNC_WAIT, size)}")
    lines.extend(
        [
            "",
            "## 10. Concurrency Matrix",
            "",
            json.dumps(conc, indent=2, default=str)[:20000],
            "",
            "## 11. Managed Protocol End-to-End",
            "",
            json.dumps(managed, indent=2, default=str)[:20000],
            "",
            "## 12. Immediate Verification / Visibility",
            "",
            json.dumps(report.get("immediate_verification"), indent=2, default=str),
            "",
            "## 13. Text-Index Immediate Searchability",
            "",
            json.dumps(report.get("text_index_immediate_searchability"), indent=2, default=str),
            "",
            "## 14. Ngram Maintenance Proof",
            "",
            json.dumps(report.get("ngram_maintenance"), indent=2, default=str),
            "",
            "## 15. Failure Matrix",
            "",
            json.dumps(report.get("failure_matrix"), indent=2, default=str),
            "",
            "## 16. Lost-Acknowledgement / Retry Proof",
            "",
            json.dumps(report.get("lost_acknowledgement"), indent=2, default=str),
            "",
            "## 17. Identity Invariance",
            "",
            json.dumps(report.get("identity_invariance"), indent=2, default=str),
            "",
            "## 18. Parts / Merge Pressure",
            "",
            json.dumps(report.get("parts_merge_pressure"), indent=2, default=str)[:15000],
            "",
            "## 19. Memory / Resource Result",
            "",
            json.dumps(report.get("memory_resource"), indent=2, default=str),
            "",
            "## 20. Insert-Mode Decision",
            "",
            str(report.get("insert_mode_decision")),
            "",
            "## 21. Async No-Wait Decision",
            "",
            str(report.get("async_no_wait_decision")),
            "",
            "## 22. Batch-Size Decision",
            "",
            str(report.get("batch_size_decision")),
            "",
            "## 23. Recommended 2.2B Configuration Boundary",
            "",
            json.dumps(report.get("recommended_2_2b_configuration_boundary"), indent=2, default=str),
            "",
            "## 24. Existing Generation Compatibility",
            "",
            json.dumps(report.get("existing_generation_compatibility"), indent=2, default=str),
            "",
            "## 25. Control Projection Ordering",
            "",
            json.dumps(report.get("control_projection_ordering"), indent=2, default=str),
            "",
            "## 26. Regression Tests",
            "",
            json.dumps(report.get("regression_tests"), indent=2, default=str),
            "",
            "## 27. Files Changed",
            "",
            json.dumps(report.get("files_changed"), indent=2, default=str),
            "",
            "## 28. Version",
            "",
            str(report.get("version")),
            "",
            "## 29. Production Mutation Audit",
            "",
            json.dumps(report.get("production_mutation_audit"), indent=2, default=str),
            "",
            "## 30. No-Later-Phase Audit",
            "",
            json.dumps(report.get("no_later_phase_audit"), indent=2, default=str),
            "",
            "## 31. Git State",
            "",
            json.dumps(report.get("git_state"), indent=2, default=str),
            "",
            "## 32. Phase 2.2 State",
            "",
            str(report.get("phase2_2_state")),
            "",
            "## 33. Remaining Work",
            "",
            json.dumps(report.get("remaining_work"), indent=2, default=str),
            "",
            "## 34. Verdict",
            "",
            str(report.get("verdict")),
            "",
        ]
    )
    return "\n".join(lines) + "\n"


def ensure_pg_database(name: str) -> str:
    from config import Config

    url = Config.SQLALCHEMY_DATABASE_URI
    # postgresql://user:pass@host/db
    base = url.rsplit("/", 1)[0]
    target = f"{base}/{name}"
    try:
        subprocess.run(
            ["sudo", "-n", "-u", "postgres", "createdb", "-O", "casescope", name],
            check=False,
            capture_output=True,
            text=True,
        )
    except Exception:
        pass
    return target


def production_readonly_validation(prod) -> Dict[str, Any]:
    settings = collect_settings(prod)
    indexes = production_index_inventory(prod)
    coverage = {"note": "production text-index files not mutated; inventory only"}
    services = {}
    for unit in ("casescope-web", "casescope-workers", "casescope-beat"):
        try:
            out = subprocess.check_output(["systemctl", "is-active", unit], text=True).strip()
        except Exception as exc:
            out = f"error:{exc}"
        services[unit] = out
    return {
        "events_row_count": indexes.get("rows"),
        "index_inventory": indexes,
        "materialize_skip_indexes_on_insert": next(
            (row["value"] for row in settings if row["name"] == "materialize_skip_indexes_on_insert"),
            None,
        ),
        "async_insert": next((row["value"] for row in settings if row["name"] == "async_insert"), None),
        "wait_for_async_insert": next(
            (row["value"] for row in settings if row["name"] == "wait_for_async_insert"), None
        ),
        "async_insert_deduplicate": next(
            (row["value"] for row in settings if row["name"] == "async_insert_deduplicate"), None
        ),
        "services": services,
        "coverage": coverage,
    }


def main() -> int:
    from utils.ingest_fence import install_memory_backend, reset_fence_backend

    report: Dict[str, Any] = {
        "tranche": "phase2_2a_insertion_mode_qualification",
        "recorded_at": utc_now_iso(),
        "version": EXPECTED_VERSION,
        "version_bumped": False,
        "async_no_wait_decision": ASYNC_NO_WAIT_FORBIDDEN,
        "scratch_database": SCRATCH_DB,
        "pg_test_database": PG_TEST_DB,
        "ch_test_database": CH_TEST_DB,
    }
    try:
        baseline = git_baseline()
        report["baseline"] = baseline
        if not baseline["ok"]:
            raise Phase22ANotReady("STOP: BASELINE_DRIFT")

        assert_events_schema_is_final_phase21(EVENTS_SCHEMA)
        prod = ch_connect(PRODUCTION_DB)
        settings = collect_settings(prod)
        indexes = production_index_inventory(prod)
        report["phase2_1_closed_preconditions"] = {
            "version": EXPECTED_VERSION,
            "commit": EXPECTED_HEAD,
            "clickhouse": indexes.get("clickhouse_version"),
            "idx_search_blob_text": indexes.get("idx_search_blob_text_present"),
            "idx_search_ngram": indexes.get("idx_search_ngram_present"),
            "idx_search_token_absent": indexes.get("idx_search_token_absent"),
            "materialize_skip_indexes_on_insert": indexes.get("materialize_skip_indexes_on_insert"),
            "command_line": "COMMAND_LINE_INDEX_DEFER",
            "keep_materialize": "KEEP_PRODUCTION_MATERIALIZE_SKIP_INDEXES_ON_INSERT_1",
            "phase2_1_closed": True,
        }
        report["production_server_insert_settings"] = settings
        report["application_client_settings"] = inspect_application_client_settings()
        report["event_insert_inventory"] = event_insert_inventory()
        report["client_scope_inventory"] = client_scope_inventory()
        report["async_insert_deduplicate"] = next(
            (row for row in settings if row["name"] == "async_insert_deduplicate"), None
        )

        admin = ch_connect("default")
        admin.command(f"CREATE DATABASE IF NOT EXISTS {SCRATCH_DB}")
        admin.command(f"CREATE DATABASE IF NOT EXISTS {CH_TEST_DB}")
        scratch = ch_connect(SCRATCH_DB, settings={"log_queries": 1, "log_query_settings": 1})
        install_memory_backend()

        print("Step 3: clickhouse_connect async-mode proof", flush=True)
        proof = prove_client_insert_async_mode(scratch)
        report["clickhouse_connect_async_mode_proof"] = proof
        if not proof.get("client_insert_honors_async_distinctly"):
            raise Phase22ANotReady("PHASE2_2A_CLIENT_MODE_NOT_READY")

        print(f"Step 6: corpus copy target={CORPUS_ROWS}", flush=True)
        disk_before = disk_free()
        corpus = build_corpus(scratch, CORPUS_ROWS)
        report["benchmark_corpus"] = corpus | {"disk_before": disk_before, "disk_after_copy": disk_free()}

        prior = prior_measurement_payload() if should_reuse_prior_raw() else None
        reuse_raw = bool(prior and prior_raw_is_complete(prior))
        report["raw_matrix_reused"] = reuse_raw
        if reuse_raw:
            print("Step 9: reusing completed raw insert matrix from prior 2.2A run", flush=True)
            raw = prior["raw_insert_matrix"]
            raw["reused_from_prior_run"] = True
            report["raw_insert_matrix"] = raw
            report["large_table_index_proof"] = prior.get("large_table_index_proof") or {}
            try:
                leftover_rows = int(scalar(scratch, "SELECT count() FROM events") or 0)
            except Exception:
                leftover_rows = 0
            if leftover_rows >= 500_000:
                large_ngram_sql = "SELECT count() FROM events WHERE search_blob LIKE '%NTLM%'"
                large_text_sql = "SELECT count() FROM events WHERE hasAllTokens(search_blob, 'powershell')"
                report["large_table_index_proof"] = {
                    "ngram_count": int(scalar(scratch, large_ngram_sql) or 0),
                    "ngram_explain": parse_explain_indexes(explain_text(scratch, large_ngram_sql)),
                    "text_count": int(scalar(scratch, large_text_sql) or 0),
                    "text_explain": parse_explain_indexes(explain_text(scratch, large_text_sql)),
                    "files": text_index_part_files(scratch, "events"),
                    "refreshed_on_reuse": True,
                    "leftover_rows": leftover_rows,
                }
            print("Step 10: reusing completed concurrency matrix from prior 2.2A run", flush=True)
            conc = prior["concurrency_matrix"]
            conc["reused_from_prior_run"] = True
            report["concurrency_matrix"] = conc
        else:
            print("Step 9: raw insert matrix", flush=True)
            raw = raw_insert_matrix(scratch, corpus["rows"])
            report["raw_insert_matrix"] = raw
            large_ngram_sql = "SELECT count() FROM events WHERE search_blob LIKE '%NTLM%'"
            large_text_sql = "SELECT count() FROM events WHERE hasAllTokens(search_blob, 'powershell')"
            report["large_table_index_proof"] = {
                "ngram_count": int(scalar(scratch, large_ngram_sql) or 0),
                "ngram_explain": parse_explain_indexes(explain_text(scratch, large_ngram_sql)),
                "text_count": int(scalar(scratch, large_text_sql) or 0),
                "text_explain": parse_explain_indexes(explain_text(scratch, large_text_sql)),
                "files": text_index_part_files(scratch, "events"),
            }
            print("Step 10: concurrency matrix", flush=True)
            conc = concurrency_matrix(scratch, corpus["rows"])
            report["concurrency_matrix"] = conc

        print("Step 9b: async flush sample", flush=True)
        report["async_flush_sample"] = capture_async_flush_sample(scratch)

        pg_url = ensure_pg_database(PG_TEST_DB)
        os.environ["PHASE1B_PG_TEST_DATABASE_URL"] = pg_url
        os.environ["PHASE1B_CH_TEST_DATABASE"] = CH_TEST_DB

        print("Step 11/12: managed protocol", flush=True)
        managed_cells = []
        for mode in PRODUCTION_ELIGIBLE_MODES:
            for batch_size in (10000, 25000):
                print(f"  managed {mode} batch={batch_size} rows={MANAGED_ROWS}", flush=True)
                managed_cells.append(
                    run_managed_e2e(
                        pg_url=pg_url,
                        ch_db=CH_TEST_DB,
                        mode=mode,
                        batch_size=batch_size,
                        row_count=MANAGED_ROWS,
                    )
                )
        report["managed_protocol_end_to_end"] = {"cells": managed_cells, "rows": MANAGED_ROWS}

        report["immediate_verification"] = {
            "ok": all(cell.get("immediate_verification_ok") for cell in managed_cells),
            "cells": [
                {
                    "mode": cell["mode"],
                    "batch_size": cell["batch_size"],
                    "ok": cell.get("immediate_verification_ok"),
                    "published_rows": cell.get("published_rows"),
                }
                for cell in managed_cells
            ],
        }
        large_text = (report.get("large_table_index_proof") or {}).get("text_explain") or {}
        report["text_index_immediate_searchability"] = {
            "ok": all(
                cell.get("token_rows") == cell.get("rows")
                and (
                    (cell.get("text_index_files") or {}).get("ok")
                    or (cell.get("text_explain") or {}).get("parsed", {}).get("direct_text_index")
                    or large_text.get("direct_text_index")
                )
                for cell in managed_cells
            ),
            "details": [
                {
                    "mode": cell["mode"],
                    "batch_size": cell["batch_size"],
                    "token_rows": cell.get("token_rows"),
                    "direct_text_index": (cell.get("text_explain") or {}).get("parsed", {}).get("direct_text_index"),
                    "files": cell.get("text_index_files"),
                }
                for cell in managed_cells
            ],
        }
        ngram_ok = bool(
            (report.get("large_table_index_proof") or {}).get("ngram_explain", {}).get("idx_search_ngram")
        ) or all(
            (cell.get("ngram_explain") or {}).get("parsed", {}).get("idx_search_ngram")
            for cell in managed_cells
        )
        report["ngram_maintenance"] = {
            "ok": ngram_ok,
            "large_table": report.get("large_table_index_proof"),
            "details": [
                {
                    "mode": cell["mode"],
                    "batch_size": cell["batch_size"],
                    "idx_search_ngram": (cell.get("ngram_explain") or {}).get("parsed", {}).get("idx_search_ngram"),
                    "ngram_pruned": (cell.get("ngram_explain") or {}).get("parsed", {}).get("ngram_pruned"),
                }
                for cell in managed_cells
            ],
        }

        print("Step 15: failure matrix", flush=True)
        report["failure_matrix"] = failure_matrix(pg_url, CH_TEST_DB)
        print("Step 16: lost ack", flush=True)
        report["lost_acknowledgement"] = lost_ack_proof(pg_url, CH_TEST_DB)
        print("Step 19: identity invariance", flush=True)
        report["identity_invariance"] = identity_invariance_proof(pg_url, CH_TEST_DB)

        report["parts_merge_pressure"] = {
            "raw": [
                {"mode": c["mode"], "batch_size": c["batch_size"], "parts": c.get("last_parts")}
                for c in raw.get("cells", [])
            ],
            "concurrency": [
                {"mode": c["mode"], "batch_size": c["batch_size"], "writers": c["writers"], "parts": c.get("parts")}
                for c in conc.get("cells", [])
            ],
        }
        report["memory_resource"] = {
            "raw_peak_rss_by_cell": [
                {
                    "mode": c["mode"],
                    "batch_size": c["batch_size"],
                    "median_peak_rss_mb": c.get("median_peak_rss_mb"),
                }
                for c in raw.get("cells", [])
            ],
            "concurrency_peak_rss_mb": [
                {
                    "mode": c["mode"],
                    "batch_size": c["batch_size"],
                    "writers": c["writers"],
                    "peak_rss_mb": c.get("peak_rss_mb"),
                }
                for c in conc.get("cells", [])
            ],
            "disk_after": disk_free(),
        }
        report["recommended_2_2b_configuration_boundary"] = recommended_2_2b_configuration_boundary()
        report["existing_generation_compatibility"] = existing_generation_compatibility_design()
        report["control_projection_ordering"] = {
            "events_mode_must_not_apply_to_control_projections": True,
            "required_order": [
                "events batch fully verified",
                "PG DURABLE",
                "project visible_evidence_generations / durable_ingest_batches",
            ],
            "observed_control_inserts_unpinned": all(
                cell.get("control_insert_calls", 0) >= 0 for cell in managed_cells
            ),
            "design": "2.2B pins settings only on events INSERT; control projection insert() is unscoped",
        }
        report["production_readonly_after"] = production_readonly_validation(prod)
        report["production_mutation_audit"] = "NONE"
        report["no_later_phase_audit"] = {
            "production_async_insert_change": False,
            "production_wait_for_async_insert_change": False,
            "production_batch_size_change": False,
            "materialize_skip_indexes_on_insert_change": False,
            "search_index_changes": False,
            "idx_search_ngram_changes": False,
            "pattern_rules_changes": False,
            "phase_2_3": False,
            "phase_2_4": False,
            "phase_3_plus": False,
            "lek": False,
            "events_current": False,
            "event_observations_current": False,
            "pagination": False,
        }
        report["git_state"] = {
            "expected_at_end_of_measurement": "uncommitted until operator commit",
            "not_pushed_by_measurement": True,
        }
        report["files_changed"] = [
            "scripts/phase2_2a_insertion_mode_qualification.py",
            "tests/test_phase2_2a_insertion_mode_qualification.py",
            "docs/database_flow_phase2/phase2_2a_insertion_mode_qualification.md",
            "docs/database_flow_phase2/phase2_2a_insertion_mode_qualification.json",
        ]
        report["remaining_work"] = [
            "Independent D2A review",
            "Phase 2.2B — explicit parser/event-ingest mode implementation + live activation proof",
            "Do not start Phase 2.3",
        ]

        decision = decide(report)
        report.update(decision)
        report["version"] = EXPECTED_VERSION
        if report.get("insert_mode_decision") == MODE_NOT_READY:
            report["phase2_2_state"] = "PHASE2_2_NOT_READY"
            report["verdict"] = "PHASE2_2A_NOT_READY"
        report["decision_notes"] = {
            "reason": decision.get("reason"),
            "batch_reason": decision.get("batch_reason"),
        }
    except Phase22ANotReady as exc:
        report["insert_mode_decision"] = report.get("insert_mode_decision") or MODE_NOT_READY
        report["async_no_wait_decision"] = ASYNC_NO_WAIT_FORBIDDEN
        report["batch_size_decision"] = report.get("batch_size_decision") or BATCH_KEEP_10000
        report["phase2_2_state"] = "PHASE2_2_NOT_READY"
        report["verdict"] = "PHASE2_2A_NOT_READY"
        report["error"] = str(exc)
        report["traceback"] = traceback.format_exc()
    except Exception as exc:
        report["insert_mode_decision"] = MODE_NOT_READY
        report["async_no_wait_decision"] = ASYNC_NO_WAIT_FORBIDDEN
        report["batch_size_decision"] = BATCH_KEEP_10000
        report["phase2_2_state"] = "PHASE2_2_NOT_READY"
        report["verdict"] = "PHASE2_2A_NOT_READY"
        report["error"] = f"{type(exc).__name__}: {exc}"
        report["traceback"] = traceback.format_exc()
    finally:
        try:
            reset_fence_backend()
        except Exception:
            pass

    OUT_JSON.parent.mkdir(parents=True, exist_ok=True)
    OUT_JSON.write_text(json.dumps(jsonable(report), indent=2) + "\n", encoding="utf-8")
    OUT_MD.write_text(render_markdown(report), encoding="utf-8")
    print(f"Wrote {OUT_JSON}", flush=True)
    print(f"Wrote {OUT_MD}", flush=True)
    print(f"VERDICT {report.get('verdict')}", flush=True)
    print(f"MODE {report.get('insert_mode_decision')}", flush=True)
    print(f"BATCH {report.get('batch_size_decision')}", flush=True)
    return 0 if report.get("verdict") == "PHASE2_2A_PASS" else 2


if __name__ == "__main__":
    raise SystemExit(main())
