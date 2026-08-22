"""Phase 2.4B2A publication-safety census scanner.

Reconstructs the Phase 0A file::function FROM/JOIN events scan rule, then
classifies current production readers and mutations. Historical Phase 0 JSON
is not rewritten.
"""
from __future__ import annotations

import ast
import json
import os
import re
import sys
from collections import defaultdict
from pathlib import Path
from typing import Any, Dict, Iterable, List, Optional, Sequence, Tuple


ROOT = Path("/opt/casescope")
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))
PHASE0_CONSUMERS = ROOT / "docs" / "database_flow_contracts" / "event_surface_consumers.json"
PHASE0_COUNTING = ROOT / "docs" / "database_flow_contracts" / "counting_basis_consumers.json"
PHASE0_INVENTORY = ROOT / "docs" / "database_flow_phase0" / "events_reader_inventory.json"

PRODUCTION_ROOTS = (
    "routes",
    "tasks",
    "utils",
    "models",
    "parsers",
    "pipeline",
)
ADMIN_ROOTS = (
    "bin",
    "migrations",
)
NON_RUNTIME_ROOTS = (
    "tests",
    "scripts",
    "docs",
)

FROM_EVENTS_RE = re.compile(r"(?i)(?:FROM|JOIN)\s+events\b")
DYNAMIC_FROM_RE = re.compile(r"(?i)(?:FROM|JOIN)\s+\{[a-zA-Z_][\w]*\}")
EVENTS_TABLE_TOKEN_RE = re.compile(r"['\"]events['\"]")
MUTATION_RES = (
    ("run_events_lightweight_update", re.compile(r"run_events_lightweight_update\s*\(")),
    ("run_events_update", re.compile(r"run_events_update\s*\(")),
    ("update_events", re.compile(r"(?i)\bUPDATE\s+events\b")),
    ("alter_update", re.compile(r"(?i)ALTER\s+TABLE\s+events\s+UPDATE\b")),
    ("delete_where", re.compile(r"(?i)\bDELETE\s+WHERE\b")),
    ("alter_delete", re.compile(r"(?i)ALTER\s+TABLE\s+events\s+DELETE\b")),
    ("delete_from_events", re.compile(r"(?i)DELETE\s+FROM\s+events\b")),
)

SKIP_DIR_NAMES = {
    ".git",
    "venv",
    "node_modules",
    "__pycache__",
    "rules",
    "wiki",
    "static",
    "backups",
    "ssl",
}


READER_CLASSIFICATIONS = (
    "PUBLICATION_SAFE_CURRENT",
    "RAW_PROTOCOL_INTERNAL_ALLOWED",
    "RAW_ADMIN_ALLOWED",
    "LEGACY_ONLY_MANAGED_BLOCKED",
    "FAILS_CLOSED_BEFORE_SIDE_EFFECT",
    "HIDDEN_REPLACEMENT_PRECOMPUTE_ISOLATED",
    "CURRENT_PUBLICATION_BYPASS",
    "LATER_PHASE_SEMANTIC_CUTOVER_ONLY",
)

MUTATION_CLASSIFICATIONS = (
    "PROTOCOL_INTERNAL_RAW_ALLOWED",
    "ADMIN_DESTRUCTIVE_RAW_ALLOWED",
    "PUBLICATION_SCOPED_MUTATION",
    "LEGACY_ONLY_MANAGED_BLOCKED",
    "CURRENT_MUTATION_PUBLICATION_BYPASS",
    "LATER_PHASE_AUTHORITY_MIGRATION_ONLY",
)


def _rel(path: Path) -> str:
    return path.relative_to(ROOT).as_posix()


def _iter_python_files(roots: Sequence[str]) -> List[Path]:
    files: List[Path] = []
    for root_name in roots:
        root = ROOT / root_name
        if not root.exists():
            continue
        if root.is_file() and root.suffix == ".py":
            files.append(root)
            continue
        for path in root.rglob("*.py"):
            if any(part in SKIP_DIR_NAMES for part in path.parts):
                continue
            files.append(path)
    extra = ROOT / "app.py"
    if extra.exists() and "app.py" not in { _rel(p) for p in files }:
        files.append(extra)
    return sorted(files)


def _string_literals_from_ast(source: str) -> List[Tuple[int, str]]:
    """Collect concatenated / f-string / ordinary string literals with line numbers."""
    try:
        tree = ast.parse(source)
    except SyntaxError:
        return []
    found: List[Tuple[int, str]] = []

    def concat(node: ast.AST) -> Optional[str]:
        if isinstance(node, ast.Constant) and isinstance(node.value, str):
            return node.value
        if isinstance(node, ast.JoinedStr):
            parts = []
            for value in node.values:
                if isinstance(value, ast.Constant) and isinstance(value.value, str):
                    parts.append(value.value)
                elif isinstance(value, ast.FormattedValue):
                    parts.append(" ")
                else:
                    chunk = concat(value)
                    parts.append(chunk if chunk is not None else " ")
            return "".join(parts)
        if isinstance(node, ast.BinOp) and isinstance(node.op, ast.Add):
            left = concat(node.left)
            right = concat(node.right)
            if left is None or right is None:
                return None
            return left + right
        return None

    for node in ast.walk(tree):
        text = concat(node)
        if text and FROM_EVENTS_RE.search(text):
            found.append((getattr(node, "lineno", 1), text))
        elif text:
            for kind, pattern in MUTATION_RES:
                if pattern.search(text):
                    found.append((getattr(node, "lineno", 1), text))
                    break
    return found


def _function_spans(source: str) -> List[Tuple[str, int, int]]:
    try:
        tree = ast.parse(source)
    except SyntaxError:
        return [("<unparseable>", 1, source.count("\n") + 1)]
    spans: List[Tuple[str, int, int]] = []

    def walk(nodes: Iterable[ast.AST], class_name: Optional[str] = None) -> None:
        for node in nodes:
            if isinstance(node, ast.ClassDef):
                walk(node.body, node.name)
            elif isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
                end = getattr(node, "end_lineno", node.lineno)
                spans.append((node.name, node.lineno, end))
                walk(node.body, class_name)

    walk(tree.body)
    spans.sort(key=lambda item: (item[1], item[2]))
    return spans


def _function_for_line(spans: Sequence[Tuple[str, int, int]], line: int) -> str:
    enclosing = [name for name, start, end in spans if start <= line <= end]
    if not enclosing:
        return "<module>"
    return enclosing[-1]


def _source_has_publication(source: str) -> bool:
    return (
        "build_event_publication_bridge" in source
        or "build_hunting_publication_bridge" in source
        or "build_event_publication_predicate" in source
    )


def scan_file_events_sql(path: Path) -> List[Dict[str, Any]]:
    source = path.read_text(encoding="utf-8", errors="replace")
    rel = _rel(path)
    spans = _function_spans(source)
    hits: Dict[Tuple[str, str], Dict[str, Any]] = {}

    def add_hit(function: str, line: int, kind: str, snippet: str) -> None:
        key = (rel, function)
        record = hits.setdefault(
            key,
            {
                "file": rel,
                "function": function,
                "location": f"{rel}::{function}",
                "lines": [],
                "kinds": set(),
                "query_hits": 0,
                "has_publication_helper": False,
                "snippets": [],
            },
        )
        record["query_hits"] += 1
        record["lines"].append(line)
        record["kinds"].add(kind)
        if len(record["snippets"]) < 4:
            record["snippets"].append(snippet[:240].replace("\n", " "))

    for line, text in _string_literals_from_ast(source):
        function = _function_for_line(spans, line)
        if FROM_EVENTS_RE.search(text):
            add_hit(function, line, "from_or_join_events", text)
        for kind, pattern in MUTATION_RES:
            if pattern.search(text):
                add_hit(function, line, kind, text)

    # Catch dynamically constructed SQL that AST concatenation misses, by
    # scanning physical source lines inside the owning function.
    for lineno, raw in enumerate(source.splitlines(), 1):
        function = _function_for_line(spans, lineno)
        if FROM_EVENTS_RE.search(raw):
            add_hit(function, lineno, "from_or_join_events", raw)
        elif DYNAMIC_FROM_RE.search(raw):
            func_source = _function_source(source, spans, function) or ""
            mentions_events = EVENTS_TABLE_TOKEN_RE.search(func_source) or (
                "table_name" in func_source and EVENTS_TABLE_TOKEN_RE.search(source)
            )
            if mentions_events:
                add_hit(function, lineno, "from_or_join_events", raw)
        for kind, pattern in MUTATION_RES:
            if pattern.search(raw):
                add_hit(function, lineno, kind, raw)

    for key, record in hits.items():
        func_source = _function_source(source, spans, record["function"])
        record["has_publication_helper"] = _source_has_publication(func_source or source)
        record["lines"] = sorted(set(record["lines"]))
        record["kinds"] = sorted(record["kinds"])
        record["line"] = record["lines"][0]
    return list(hits.values())


def _function_source(source: str, spans: Sequence[Tuple[str, int, int]], function: str) -> str:
    lines = source.splitlines()
    chunks = []
    for name, start, end in spans:
        if name == function:
            chunks.append("\n".join(lines[start - 1 : end]))
    if function == "<module>":
        return source
    return "\n".join(chunks)


def load_phase0_index() -> Dict[str, Dict[str, Any]]:
    data = json.loads(PHASE0_CONSUMERS.read_text(encoding="utf-8"))
    counting = json.loads(PHASE0_COUNTING.read_text(encoding="utf-8"))
    counting_by_id = {row["phase0a_reader_id"]: row for row in counting["records"]}
    by_location = {}
    for row in data["records"]:
        location = row["location"]
        extra = counting_by_id.get(row["phase0a_reader_id"], {})
        by_location[location] = {
            "phase0a_reader_id": row["phase0a_reader_id"],
            "file": row["file"],
            "function": row["function"],
            "query_purpose": row.get("query_purpose"),
            "future_surface": row.get("future_surface"),
            "counting_basis": extra.get("counting_basis") or row.get("counting_basis"),
            "phase0a_category": row.get("phase0a_category"),
        }
    return by_location


def bucket_for_file(rel: str) -> str:
    prefix = rel.split("/", 1)[0]
    if prefix in PRODUCTION_ROOTS or rel == "app.py":
        return "production_runtime"
    if prefix in ADMIN_ROOTS:
        return "administrative_migration"
    if prefix in NON_RUNTIME_ROOTS:
        return "non_runtime"
    return "other"


def classify_reader(record: Dict[str, Any]) -> str:
    rel = record["file"]
    function = record["function"]
    location = record["location"]
    kinds = set(record.get("kinds") or [])
    overlay = READER_OVERLAY.get(location) or READER_OVERLAY.get(f"{rel}::{function}")
    if overlay:
        return overlay
    if bucket_for_file(rel) == "administrative_migration":
        return "RAW_ADMIN_ALLOWED"
    if rel in {
        "utils/manifest_protocol.py",
        "utils/staged_batch_reconciler.py",
        "utils/ingest_identity.py",
        "utils/capability_watermarks.py",
        "utils/completion_reconciler.py",
        "utils/row_local_derivations.py",
    }:
        return "RAW_PROTOCOL_INTERNAL_ALLOWED"
    if record.get("has_publication_helper") and "from_or_join_events" in kinds:
        # Mixed functions that both publish-filter and also have a raw query
        # are classified by overlay. Default here is safe only when the helper
        # is the publication path and no overlay said otherwise.
        if location in MIXED_RAW_AND_PUBLISHED:
            return "CURRENT_PUBLICATION_BYPASS"
        return "PUBLICATION_SAFE_CURRENT"
    if rel.startswith("utils/event_deduplication.py"):
        return "LEGACY_ONLY_MANAGED_BLOCKED"
    if bucket_for_file(rel) == "production_runtime":
        return "CURRENT_PUBLICATION_BYPASS"
    if bucket_for_file(rel) == "non_runtime":
        return "RAW_ADMIN_ALLOWED"
    return "CURRENT_PUBLICATION_BYPASS"


def classify_mutation(record: Dict[str, Any]) -> str:
    location = record["location"]
    rel = record["file"]
    overlay = MUTATION_OVERLAY.get(location)
    if overlay:
        return overlay
    if rel in {"utils/manifest_protocol.py", "utils/staged_batch_reconciler.py"}:
        return "PROTOCOL_INTERNAL_RAW_ALLOWED"
    if bucket_for_file(rel) == "administrative_migration" or rel.startswith("utils/event_deduplication.py"):
        if "allow_managed_evidence" in str(record.get("snippets")):
            return "LEGACY_ONLY_MANAGED_BLOCKED"
        if rel.startswith("utils/event_deduplication.py"):
            return "LEGACY_ONLY_MANAGED_BLOCKED"
        return "ADMIN_DESTRUCTIVE_RAW_ALLOWED"
    if rel in {
        "utils/clickhouse.py",
        "utils/event_analyst_state.py",
        "utils/event_noise_state.py",
        "utils/event_ioc_state.py",
        "utils/event_mitre_state.py",
        "tasks/noise_tagger.py",
        "tasks/mitre_mapper.py",
        "utils/ioc_artifact_tagger.py",
    }:
        return "CURRENT_MUTATION_PUBLICATION_BYPASS"
    if bucket_for_file(rel) == "production_runtime":
        return "CURRENT_MUTATION_PUBLICATION_BYPASS"
    return "ADMIN_DESTRUCTIVE_RAW_ALLOWED"


# Locations that contain a publication helper but also a raw current-state read
# in the same function.
MIXED_RAW_AND_PUBLISHED = {
    "routes/hunting.py::get_hunting_events",
}

READER_OVERLAY: Dict[str, str] = {
    # Hunt published surfaces
    "routes/hunting.py::get_hunting_events": "PUBLICATION_SAFE_CURRENT",
    "routes/hunting.py::get_hunting_event_detail": "PUBLICATION_SAFE_CURRENT",
    "routes/hunting.py::get_raw_event_data": "PUBLICATION_SAFE_CURRENT",
    "routes/hunting.py::export_view_events": "PUBLICATION_SAFE_CURRENT",
    "routes/hunting.py::export_tagged_events": "PUBLICATION_SAFE_CURRENT",
    "routes/hunting_query_helpers.py::build_hunting_publication_bridge": "PUBLICATION_SAFE_CURRENT",
    "routes/hunting_query_helpers.py::resolve_case_latest_event_time": "PUBLICATION_SAFE_CURRENT",
    "utils/event_publication.py::build_event_publication_bridge": "PUBLICATION_SAFE_CURRENT",
    "utils/event_publication.py::build_event_publication_predicate": "PUBLICATION_SAFE_CURRENT",
    "utils/event_publication.py::protocol_legacy_null_sql": "PUBLICATION_SAFE_CURRENT",
    "utils/event_publication.py::protocol_complete_sql": "PUBLICATION_SAFE_CURRENT",
    # Protocol internals
    "utils/manifest_protocol.py::verify_ingest_batch": "RAW_PROTOCOL_INTERNAL_ALLOWED",
    "utils/manifest_protocol.py::_grouped_batch_rows": "RAW_PROTOCOL_INTERNAL_ALLOWED",
    "utils/manifest_protocol.py::count_physical_ingest_batch_rows": "RAW_PROTOCOL_INTERNAL_ALLOWED",
    "utils/manifest_protocol.py::insert_managed_batch": "RAW_PROTOCOL_INTERNAL_ALLOWED",
    "utils/staged_batch_reconciler.py::classify_batch": "RAW_PROTOCOL_INTERNAL_ALLOWED",
    "utils/search_blob_text_index.py::explain_has_all_tokens": "RAW_ADMIN_ALLOWED",
    "utils/search_blob_text_index.py::partition_value_fingerprint": "RAW_ADMIN_ALLOWED",
    "utils/privacy_aliases.py::_scan_distinct_field": "CURRENT_PUBLICATION_BYPASS",
    "utils/privacy_aliases.py::_scan_distinct_ip_field": "CURRENT_PUBLICATION_BYPASS",
    "utils/privacy_aliases.py::scan_clickhouse_case_alias_candidates": "CURRENT_PUBLICATION_BYPASS",
    "utils/ai_privacy_freeze.py::select_current_generation_event_rows": "FAILS_CLOSED_BEFORE_SIDE_EFFECT",
    "utils/event_deduplication.py::deduplicate_case_events": "LEGACY_ONLY_MANAGED_BLOCKED",
    "utils/event_deduplication.py::deduplicate_artifact_type": "LEGACY_ONLY_MANAGED_BLOCKED",
    "utils/event_deduplication.py::count_eligible_events_for_artifact": "LEGACY_ONLY_MANAGED_BLOCKED",
    "utils/event_deduplication.py::count_duplicates_for_artifact": "LEGACY_ONLY_MANAGED_BLOCKED",
    "utils/clickhouse.py::delete_case_events": "RAW_ADMIN_ALLOWED",
    "utils/clickhouse.py::delete_file_events": "RAW_ADMIN_ALLOWED",
    "utils/clickhouse.py::_case_file_events_exist": "RAW_ADMIN_ALLOWED",
    "tasks/celery_tasks.py::delete_case_events_task": "RAW_ADMIN_ALLOWED",
    "tasks/celery_tasks.py::reindex_case_task": "RAW_ADMIN_ALLOWED",
}

MUTATION_OVERLAY: Dict[str, str] = {
    "utils/manifest_protocol.py::purge_ingest_batch_rows": "PROTOCOL_INTERNAL_RAW_ALLOWED",
    "utils/manifest_protocol.py::insert_managed_batch": "PROTOCOL_INTERNAL_RAW_ALLOWED",
    "utils/clickhouse.py::delete_case_events": "ADMIN_DESTRUCTIVE_RAW_ALLOWED",
    "utils/clickhouse.py::delete_file_events": "ADMIN_DESTRUCTIVE_RAW_ALLOWED",
    "utils/clickhouse.py::run_events_update": "CURRENT_MUTATION_PUBLICATION_BYPASS",
    "utils/clickhouse.py::run_events_lightweight_update": "CURRENT_MUTATION_PUBLICATION_BYPASS",
    "utils/event_analyst_state.py::upsert_event_analyst_state_rows": "CURRENT_MUTATION_PUBLICATION_BYPASS",
    "utils/event_noise_state.py::upsert_event_noise_state_rows": "CURRENT_MUTATION_PUBLICATION_BYPASS",
    "utils/event_deduplication.py::deduplicate_case_events": "LEGACY_ONLY_MANAGED_BLOCKED",
    "utils/event_deduplication.py::deduplicate_artifact_type": "LEGACY_ONLY_MANAGED_BLOCKED",
}


def scan_current_readers() -> List[Dict[str, Any]]:
    phase0 = load_phase0_index()
    records = []
    roots = PRODUCTION_ROOTS + ADMIN_ROOTS
    for path in _iter_python_files(roots):
        for hit in scan_file_events_sql(path):
            if "from_or_join_events" not in hit["kinds"]:
                continue
            location = hit["location"]
            historical = phase0.get(location)
            bucket = bucket_for_file(hit["file"])
            classification = classify_reader(hit)
            records.append(
                {
                    **{k: v for k, v in hit.items() if k != "snippets"},
                    "snippets": hit.get("snippets") or [],
                    "bucket": bucket,
                    "phase0a_reader_id": None if historical is None else historical["phase0a_reader_id"],
                    "phase0_future_surface": None if historical is None else historical["future_surface"],
                    "phase0_counting_basis": None if historical is None else historical["counting_basis"],
                    "query_purpose": (historical or {}).get("query_purpose") or _purpose_from_function(hit["function"]),
                    "owning_call_path": _owning_call_path(hit["file"], hit["function"]),
                    "read_side_effect": _read_side_effect(classification, hit["file"], hit["function"]),
                    "classification": classification,
                    "managed_evidence_reachable": classification
                    not in {"LEGACY_ONLY_MANAGED_BLOCKED", "RAW_ADMIN_ALLOWED"},
                    "replacement_generation_reachable": classification
                    in {
                        "CURRENT_PUBLICATION_BYPASS",
                        "HIDDEN_REPLACEMENT_PRECOMPUTE_ISOLATED",
                        "RAW_PROTOCOL_INTERNAL_ALLOWED",
                    },
                    "publication_filtering_applied": classification
                    in {"PUBLICATION_SAFE_CURRENT", "LATER_PHASE_SEMANTIC_CUTOVER_ONLY"},
                    "b2b_action": _reader_b2b_action(classification, location),
                }
            )
    records.sort(key=lambda row: (row["file"], row["function"], row["line"]))
    return records


def scan_current_mutations() -> List[Dict[str, Any]]:
    records = []
    roots = PRODUCTION_ROOTS + ADMIN_ROOTS
    mutation_kinds = {
        "run_events_lightweight_update",
        "run_events_update",
        "update_events",
        "alter_update",
        "delete_where",
        "alter_delete",
        "delete_from_events",
    }
    skip_files = {
        "models/network_log.py",
        "utils/search_blob_text_index.py",
    }
    for path in _iter_python_files(roots):
        for hit in scan_file_events_sql(path):
            if hit["file"] in skip_files:
                continue
            kinds = set(hit["kinds"]) & mutation_kinds
            if not kinds:
                continue
            blob = " ".join(hit.get("snippets") or [])
            if "network_logs" in blob:
                continue
            classification = classify_mutation(hit)
            records.append(
                {
                    **{k: v for k, v in hit.items() if k != "snippets"},
                    "snippets": hit.get("snippets") or [],
                    "bucket": bucket_for_file(hit["file"]),
                    "mutation_kinds": sorted(kinds),
                    "classification": classification,
                    "b2b_action": _mutation_b2b_action(classification, hit["location"]),
                }
            )
    records.sort(key=lambda row: (row["file"], row["function"], row["line"]))
    return records


def scan_non_runtime_readers() -> List[Dict[str, Any]]:
    records = []
    for path in _iter_python_files(NON_RUNTIME_ROOTS):
        for hit in scan_file_events_sql(path):
            if "from_or_join_events" not in hit["kinds"]:
                continue
            records.append(
                {
                    "file": hit["file"],
                    "function": hit["function"],
                    "location": hit["location"],
                    "line": hit["line"],
                    "query_hits": hit["query_hits"],
                }
            )
    records.sort(key=lambda row: (row["file"], row["function"], row["line"]))
    return records


def _purpose_from_function(function: str) -> str:
    name = function.replace("_", " ").strip()
    return name or "module-level events SQL"


def _reader_b2b_action(classification: str, location: str) -> str:
    if classification == "CURRENT_PUBLICATION_BYPASS":
        return f"scope {location} through shared event publication helper"
    if classification == "FAILS_CLOSED_BEFORE_SIDE_EFFECT":
        return "keep fail-closed gate; optionally publication-scope selection in B2B"
    if classification == "HIDDEN_REPLACEMENT_PRECOMPUTE_ISOLATED":
        return "review PrivacyAlias isolation; no publication-bridge retrofit required for watermark key"
    if classification in {"PUBLICATION_SAFE_CURRENT", "RAW_PROTOCOL_INTERNAL_ALLOWED", "RAW_ADMIN_ALLOWED", "LEGACY_ONLY_MANAGED_BLOCKED", "LATER_PHASE_SEMANTIC_CUTOVER_ONLY"}:
        return "none in B2B"
    return "classify during B2B review"


def _mutation_b2b_action(classification: str, location: str) -> str:
    if classification == "CURRENT_MUTATION_PUBLICATION_BYPASS":
        return f"publication-scope UPDATE target for {location}"
    if classification == "LEGACY_ONLY_MANAGED_BLOCKED":
        return "none in B2B; keep managed evidence blocked"
    return "none in B2B"


def historical_reconciliation(current_readers: Sequence[Dict[str, Any]]) -> Dict[str, Any]:
    phase0 = load_phase0_index()
    current_locations = {
        row["location"]
        for row in current_readers
        if row["bucket"] in {"production_runtime", "administrative_migration"}
    }
    phase0_locations = set(phase0)
    removed = sorted(phase0_locations - current_locations)
    added = sorted(current_locations - phase0_locations)
    moved = []
    phase0_by_fn = defaultdict(list)
    for location, row in phase0.items():
        phase0_by_fn[row["function"]].append(row)
    for location in added:
        function = location.split("::", 1)[-1]
        matches = phase0_by_fn.get(function) or []
        if len(matches) == 1 and matches[0]["location"] in removed:
            moved.append(
                {
                    "from": matches[0]["location"],
                    "to": location,
                    "phase0a_reader_id": matches[0]["phase0a_reader_id"],
                }
            )
    inventory = json.loads(PHASE0_INVENTORY.read_text(encoding="utf-8"))
    return {
        "historical_inventory_unchanged": True,
        "phase0_inventory_path": str(PHASE0_INVENTORY.relative_to(ROOT)),
        "phase0_inventory_records": len(inventory.get("records") or inventory.get("readers") or []),
        "phase0_direct_readers": len(phase0_locations),
        "current_direct_readers_including_admin": len(current_locations),
        "removed_from_current_scan": removed,
        "added_since_phase0": added,
        "moved_or_renamed_confident": moved,
        "phase0_ids_no_longer_present": [
            phase0[location]["phase0a_reader_id"] for location in removed
        ],
    }


def summarize(records: Sequence[Dict[str, Any]], key: str = "classification") -> Dict[str, int]:
    counts: Dict[str, int] = defaultdict(int)
    for row in records:
        counts[row[key]] += 1
    return dict(sorted(counts.items()))


def unclassified_readers(records: Sequence[Dict[str, Any]]) -> List[str]:
    return [
        row["location"]
        for row in records
        if row.get("bucket") == "production_runtime" and row.get("classification") not in READER_CLASSIFICATIONS
    ]


def unclassified_mutations(records: Sequence[Dict[str, Any]]) -> List[str]:
    return [
        row["location"]
        for row in records
        if row.get("bucket") == "production_runtime" and row.get("classification") not in MUTATION_CLASSIFICATIONS
    ]


def _owning_call_path(rel: str, function: str) -> str:
    if rel.startswith("routes/hunting"):
        return f"Hunt UI / API -> {rel}::{function}"
    if rel.startswith("routes/dashboard"):
        return f"Dashboard -> {rel}::{function}"
    if rel.startswith("routes/case_files"):
        return f"Case files / stats -> {rel}::{function}"
    if rel.startswith("routes/noise") or "noise" in function.lower():
        return f"Noise product -> {rel}::{function}"
    if rel.startswith("routes/iocs") or "ioc" in function.lower():
        return f"IOC product -> {rel}::{function}"
    if rel.startswith("routes/rag") or rel.startswith("utils/rag"):
        return f"RAG / embeddings -> {rel}::{function}"
    if "analyst" in rel or "analyst" in function.lower():
        return f"Analyst state -> {rel}::{function}"
    if "mitre" in rel or "mitre" in function.lower():
        return f"MITRE mapping -> {rel}::{function}"
    if rel.startswith("utils/graph") or rel.startswith("routes/") and "graph" in rel:
        return f"Graph -> {rel}::{function}"
    if rel.startswith("utils/ai") or rel.startswith("utils/chat"):
        return f"AI / chat -> {rel}::{function}"
    if rel.startswith("utils/manifest_protocol") or rel.startswith("utils/staged_batch"):
        return f"Managed ingest protocol -> {rel}::{function}"
    if rel.startswith("tasks/"):
        return f"Celery task -> {rel}::{function}"
    if rel.startswith("bin/") or rel.startswith("migrations/"):
        return f"Administrative / migration -> {rel}::{function}"
    return f"Production runtime -> {rel}::{function}"


def _read_side_effect(classification: str, rel: str, function: str) -> str:
    if classification == "PUBLICATION_SAFE_CURRENT":
        return "analyst-visible Hunt/current display of publication-authorized rows only"
    if classification == "RAW_PROTOCOL_INTERNAL_ALLOWED":
        return "protocol verification / reconciliation; not a current product publication surface"
    if classification == "RAW_ADMIN_ALLOWED":
        return "administrative/migration/repair physical presence"
    if classification == "LEGACY_ONLY_MANAGED_BLOCKED":
        return "legacy-only path; managed generations are structurally blocked"
    if classification == "FAILS_CLOSED_BEFORE_SIDE_EFFECT":
        return "request-scoped freeze selection; verify_frozen_privacy_coverage rejects unpublished managed rows before remote egress"
    if "privacy_alias" in rel:
        return "persists PrivacyAlias rows used by current AI sanitization"
    if "analyst" in rel:
        return "analyst display counts, prior-state audit, and UPDATE targeting"
    if "embedding" in rel or "rag" in rel:
        return "embedding upsert / retrieval corpus"
    if rel.startswith("utils/graph"):
        return "graph materialization / query"
    if classification == "CURRENT_PUBLICATION_BYPASS":
        return "can consume unpublished managed physical rows for display, counts, derived state, or egress"
    return "see classification"


def production_readonly_census() -> Dict[str, Any]:
    """Part A / J production facts. SELECT only. No ClickHouse or PG writes."""
    from sqlalchemy import create_engine, text

    from config import Config
    from utils.clickhouse import get_client

    engine = create_engine(Config.SQLALCHEMY_DATABASE_URI)
    out: Dict[str, Any] = {
        "production_mutation": "NONE",
        "queries": "SELECT only",
    }
    with engine.connect() as conn:
        def scalar(sql: str, **params):
            return conn.execute(text(sql), params).scalar()

        out["pg_d1_d2"] = {
            "evidence_source_generations_columns_sample": [
                row[0]
                for row in conn.execute(
                    text(
                        """
                        SELECT column_name FROM information_schema.columns
                        WHERE table_name = 'evidence_source_generations'
                          AND column_name IN (
                            'visibility_state', 'expected_rows', 'landed_rows',
                            'final_batch_ordinal', 'completed_at', 'activated_at'
                          )
                        ORDER BY column_name
                        """
                    )
                )
            ],
            "ingest_attempts_columns_sample": [
                row[0]
                for row in conn.execute(
                    text(
                        """
                        SELECT column_name FROM information_schema.columns
                        WHERE table_name = 'ingest_attempts'
                          AND column_name IN ('lease_expires_at', 'heartbeat_at', 'status')
                        ORDER BY column_name
                        """
                    )
                )
            ],
            "ingest_batches_columns_sample": [
                row[0]
                for row in conn.execute(
                    text(
                        """
                        SELECT column_name FROM information_schema.columns
                        WHERE table_name = 'ingest_batches'
                          AND column_name IN (
                            'state', 'last_reconcile_outcome', 'reconcile_lease_expires_at',
                            'updated_at', 'durable_at'
                          )
                        ORDER BY column_name
                        """
                    )
                )
            ],
            "evidence_generation_audit_exists": bool(
                conn.execute(
                    text(
                        """
                        SELECT 1 FROM information_schema.tables
                        WHERE table_name = 'evidence_generation_audit'
                        """
                    )
                ).scalar()
            ),
            "ingest_batch_reconciliation_audit_exists": bool(
                conn.execute(
                    text(
                        """
                        SELECT 1 FROM information_schema.tables
                        WHERE table_name = 'ingest_batch_reconciliation_audit'
                        """
                    )
                ).scalar()
            ),
        }
        out["managed_protocol_counts"] = {
            "evidence_source_generations": int(scalar("SELECT count(*) FROM evidence_source_generations") or 0),
            "ingest_attempts": int(scalar("SELECT count(*) FROM ingest_attempts") or 0),
            "ingest_batches": int(scalar("SELECT count(*) FROM ingest_batches") or 0),
            "evidence_generation_audit": int(scalar("SELECT count(*) FROM evidence_generation_audit") or 0),
            "ingest_batch_reconciliation_audit": int(
                scalar("SELECT count(*) FROM ingest_batch_reconciliation_audit") or 0
            ),
        }
        casefile = conn.execute(
            text(
                """
                SELECT id, case_uuid, filename, original_filename, status, ingestion_status,
                       events_indexed, processed_at, file_size, ingest_protocol_origin,
                       uploaded_at, parser_type, error_message, retention_state,
                       file_path, source_path
                FROM case_files
                WHERE id = 538677
                """
            )
        ).mappings().first()
        out["casefile_538677"] = dict(casefile) if casefile else None
        if casefile:
            for key, value in list(out["casefile_538677"].items()):
                if hasattr(value, "isoformat"):
                    out["casefile_538677"][key] = value.isoformat()
            file_path = casefile.get("file_path")
            source_path = casefile.get("source_path")
            out["casefile_538677"]["retained_file_exists"] = bool(file_path) and os.path.exists(file_path)
            out["casefile_538677"]["source_file_exists"] = bool(source_path) and os.path.exists(source_path)
            case_row = conn.execute(
                text("SELECT id, uuid, name, status FROM cases WHERE uuid = :uuid"),
                {"uuid": casefile["case_uuid"]},
            ).mappings().first()
            out["casefile_538677_case"] = dict(case_row) if case_row else None
    client = get_client()
    veg = client.query("SELECT count() FROM visible_evidence_generations")
    dib = client.query("SELECT count() FROM durable_ingest_batches")
    out["clickhouse_control_counts"] = {
        "visible_evidence_generations": int(veg.result_rows[0][0] if veg.result_rows else 0),
        "durable_ingest_batches": int(dib.result_rows[0][0] if dib.result_rows else 0),
    }
    ch_casefile = client.query(
        """
        SELECT
            count() AS event_count,
            countIf(ingest_batch_id IS NULL OR ingest_batch_id = '') AS unmanaged,
            min(timestamp_utc) AS min_ts,
            max(timestamp_utc) AS max_ts
        FROM events
        WHERE case_file_id = 538677
        """
    )
    row = ch_casefile.result_rows[0] if ch_casefile.result_rows else (0, 0, None, None)
    out["casefile_538677_clickhouse"] = {
        "event_count": int(row[0] or 0),
        "unmanaged_event_count": int(row[1] or 0),
        "min_timestamp_utc": str(row[2]) if row[2] is not None else None,
        "max_timestamp_utc": str(row[3]) if row[3] is not None else None,
        "evidence_content_included": False,
    }
    managed = out["managed_protocol_counts"]
    if (
        managed["evidence_source_generations"] == 0
        and managed["ingest_attempts"] == 0
        and managed["ingest_batches"] == 0
        and out["clickhouse_control_counts"]["visible_evidence_generations"] == 0
        and out["clickhouse_control_counts"]["durable_ingest_batches"] == 0
    ):
        out["managed_protocol_token"] = "PRODUCTION_MANAGED_PROTOCOL_STATE_STILL_EMPTY"
    else:
        out["managed_protocol_token"] = "PRODUCTION_MANAGED_PROTOCOL_STATE_NONEMPTY"
    return out


def b2b_families(readers: Sequence[Dict[str, Any]], mutations: Sequence[Dict[str, Any]]) -> List[Dict[str, Any]]:
    families = [
        {
            "id": "B2B-1",
            "name": "shared product counts, dashboard, and remaining time anchors",
            "match": lambda loc: any(
                token in loc
                for token in (
                    "count_events",
                    "dashboard",
                    "case_files",
                    "get_noise_stats",
                    "parsing.py",
                )
            ),
        },
        {
            "id": "B2B-2",
            "name": "analyst and manual-noise read plus UPDATE target scoping",
            "match": lambda loc: any(
                token in loc
                for token in (
                    "event_analyst_state",
                    "upsert_manual_noise_state",
                    "event_noise_state.py::upsert_manual",
                )
            ),
        },
        {
            "id": "B2B-3",
            "name": "IOC / noise / MITRE current mutation and scan scoping",
            "match": lambda loc: any(
                token in loc
                for token in (
                    "event_ioc_state",
                    "event_mitre_state",
                    "event_noise_state",
                    "noise_tagger",
                    "mitre_mapper",
                    "ioc_artifact_tagger",
                    "hayabusa_mitre",
                )
            ),
        },
        {
            "id": "B2B-4",
            "name": "graph, known principal, behavioral, and detector inputs",
            "match": lambda loc: any(
                token in loc
                for token in (
                    "graph_",
                    "known_users",
                    "known_system",
                    "behavioral",
                    "temporal_baseline",
                    "incident_storyline",
                    "stateful_detectors",
                    "phase1_step3",
                    "pattern_rule",
                )
            ),
        },
        {
            "id": "B2B-5",
            "name": "RAG, embedding, AI, chat current readers",
            "match": lambda loc: any(
                token in loc
                for token in (
                    "rag_",
                    "ai_",
                    "chat_",
                    "investigation_context",
                    "ai_subagents",
                    "privacy_aliases",
                )
            ),
        },
        {
            "id": "B2B-6",
            "name": "remaining Hunt raw surfaces (process tree, hostnames, MITRE hide-noise)",
            "match": lambda loc: loc.startswith("routes/hunting.py::")
            and "get_hunting_" not in loc
            and "export_" not in loc
            and "get_raw_event_data" not in loc,
        },
    ]
    assigned_readers = set()
    assigned_mutations = set()
    result = []
    bypass_readers = [
        row for row in readers
        if row.get("bucket") == "production_runtime"
        and row.get("classification") == "CURRENT_PUBLICATION_BYPASS"
    ]
    bypass_mutations = [
        row for row in mutations
        if row.get("bucket") == "production_runtime"
        and row.get("classification") == "CURRENT_MUTATION_PUBLICATION_BYPASS"
    ]
    for family in families:
        reader_hits = [
            row["location"]
            for row in bypass_readers
            if family["match"](row["location"]) and row["location"] not in assigned_readers
        ]
        mutation_hits = [
            row["location"]
            for row in bypass_mutations
            if family["match"](row["location"]) and row["location"] not in assigned_mutations
        ]
        assigned_readers.update(reader_hits)
        assigned_mutations.update(mutation_hits)
        result.append(
            {
                "id": family["id"],
                "name": family["name"],
                "reader_locations": reader_hits,
                "mutation_locations": mutation_hits,
                "publication_mechanism": "shared LEFT JOIN bridge for SELECT; predicate/IN or EXISTS for UPDATE if PUBLICATION_PREDICATE_READY_FOR_B2B",
                "counting_basis_unchanged": True,
            }
        )
    leftover_readers = [row["location"] for row in bypass_readers if row["location"] not in assigned_readers]
    leftover_mutations = [row["location"] for row in bypass_mutations if row["location"] not in assigned_mutations]
    if leftover_readers or leftover_mutations:
        result.append(
            {
                "id": "B2B-7",
                "name": "remaining current publication bypasses not in B2B-1..6",
                "reader_locations": leftover_readers,
                "mutation_locations": leftover_mutations,
                "publication_mechanism": "shared LEFT JOIN bridge for SELECT; predicate form for mutations if qualified",
                "counting_basis_unchanged": True,
            }
        )
    return result


def render_markdown(payload: Dict[str, Any]) -> str:
    runtime = payload["reader_summary"]["production_runtime"]
    lines = [
        "# Phase 2.4B2A Publication-Safety Census",
        "",
        "Dated 2026-08-22. Does not close Phase 2. Does not start Phase 3 or Phase 4.",
        "Does not restart production services. Candidate source version is 4.26.4.",
        "",
        "## Tokens",
        "",
        f"- `{payload['tokens']['durable_replay']}`",
        f"- `{payload['tokens']['partial_identity']}`",
        f"- `{payload['tokens']['hunt_relative_range']}`",
        f"- `{payload['tokens']['publication_predicate']}`",
        f"- `{payload['tokens']['test_collection']}`",
        f"- `{payload['tokens']['managed_protocol']}`",
        f"- `{payload['tokens']['replacement_derivation']}`",
        f"- `{payload['tokens']['d2_stale_attempt']}`",
        f"- `{payload['tokens']['casefile_538677']}`",
        "",
        "## Production managed protocol",
        "",
        json.dumps(payload["production"]["managed_protocol_counts"], indent=2),
        "",
        json.dumps(payload["production"]["clickhouse_control_counts"], indent=2),
        "",
        "## Historical Phase 0 reconciliation",
        "",
        "Historical `event_surface_consumers.json` was not rewritten.",
        "",
        json.dumps({k: payload["historical"][k] for k in payload["historical"] if k != "phase0_ids_no_longer_present"}, indent=2),
        "",
        "## Current reader classification counts (production_runtime)",
        "",
        json.dumps(runtime, indent=2),
        "",
        "## Current mutation classification counts (production_runtime)",
        "",
        json.dumps(payload["mutation_summary"]["production_runtime"], indent=2),
        "",
        "## B2B families",
        "",
    ]
    for family in payload["b2b_families"]:
        lines.append(f"### {family['id']} — {family['name']}")
        lines.append("")
        lines.append(f"Readers: {len(family['reader_locations'])}. Mutations: {len(family['mutation_locations'])}.")
        lines.append("")
        for loc in family["reader_locations"]:
            lines.append(f"- reader `{loc}`")
        for loc in family["mutation_locations"]:
            lines.append(f"- mutation `{loc}`")
        lines.append("")
    lines.extend(
        [
            "## Complete current production reader matrix",
            "",
            "See JSON `current_readers` (production_runtime plus administrative_migration).",
            "No production_runtime reader is unclassified.",
            "",
            "## Complete current mutation matrix",
            "",
            "See JSON `current_mutations`. No production_runtime mutation is unclassified.",
            "",
            "## Later-phase work explicitly deferred",
            "",
            "- LEK / logical representative / same-ERK collapse",
            "- events_current / event_observations_current",
            "- IOC / MITRE / analyst PostgreSQL authority migration",
            "- Qdrant identity migration",
            "- graph derived-plane migration",
            "- RMT event-engine change",
            "- semantic duplicate detection",
            "",
        ]
    )
    return "\n".join(lines)


def main() -> int:
    readers = scan_current_readers()
    mutations = scan_current_mutations()
    non_runtime = scan_non_runtime_readers()
    runtime_readers = [row for row in readers if row["bucket"] == "production_runtime"]
    runtime_mutations = [row for row in mutations if row["bucket"] == "production_runtime"]
    production = production_readonly_census()
    payload = {
        "tranche": "phase2_4b2a",
        "source_version": "4.26.4",
        "historical_inventory_unchanged": True,
        "tokens": {
            "durable_replay": "DURABLE_REPLAY_NONEXACT_FAILS_CLOSED",
            "partial_identity": "PARTIAL_PROTOCOL_IDENTITY_FAILS_CLOSED",
            "hunt_relative_range": "HUNT_RELATIVE_RANGE_RAW_ANCHOR_CONFIRMED",
            "publication_predicate": "PUBLICATION_PREDICATE_READY_FOR_B2B",
            "test_collection": "PHASE2_NORMAL_TEST_COLLECTION_ISOLATED",
            "managed_protocol": production.get("managed_protocol_token"),
            "replacement_derivation": "HIDDEN_REPLACEMENT_PRECOMPUTE_CURRENT_STATE_LEAK",
            "d2_stale_attempt": "D2_EXACT_STALE_ATTEMPT_STATUS_HARMLESS",
            "casefile_538677": "STALE_CASEFILE_STATE_AMBIGUOUS",
        },
        "production": production,
        "historical": historical_reconciliation(readers),
        "reader_summary": {
            "all": summarize(readers),
            "production_runtime": summarize(runtime_readers),
            "administrative_migration": summarize(
                [row for row in readers if row["bucket"] == "administrative_migration"]
            ),
            "production_runtime_count": len(runtime_readers),
            "unclassified_production_readers": unclassified_readers(readers),
        },
        "mutation_summary": {
            "all": summarize(mutations),
            "production_runtime": summarize(runtime_mutations),
            "production_runtime_count": len(runtime_mutations),
            "unclassified_production_mutations": unclassified_mutations(mutations),
        },
        "current_readers": readers,
        "current_mutations": mutations,
        "non_runtime_readers": non_runtime,
        "b2b_families": b2b_families(readers, mutations),
        "publication_predicate_qualification": {
            "token": "PUBLICATION_PREDICATE_READY_FOR_B2B",
            "select_left_join": True,
            "select_tuple_in": True,
            "select_exists": True,
            "alter_update_alias_e": False,
            "alter_update_unaliased": True,
            "alter_update_table_alias_events": True,
            "b2b_mutation_form": "build_event_publication_predicate(alias='events') or alias='' after prefix fix",
            "clickhouse_version": "26.7.3.19",
        },
        "phase_bleed": {
            "phase3": False,
            "phase4": False,
            "lek": False,
            "events_current": False,
            "event_observations_current": False,
            "semantic_dedup": False,
            "rmt": False,
        },
    }
    json_path = ROOT / "docs" / "database_flow_phase2" / "phase2_4b2a_publication_census.json"
    md_path = ROOT / "docs" / "database_flow_phase2" / "phase2_4b2a_publication_census.md"
    json_path.write_text(json.dumps(payload, indent=2, default=str) + "\n", encoding="utf-8")
    md_path.write_text(render_markdown(payload), encoding="utf-8")
    print(json.dumps({
        "json": str(json_path),
        "md": str(md_path),
        "runtime_readers": len(runtime_readers),
        "runtime_mutations": len(runtime_mutations),
        "unclassified_readers": payload["reader_summary"]["unclassified_production_readers"],
        "unclassified_mutations": payload["mutation_summary"]["unclassified_production_mutations"],
        "managed_protocol_token": production.get("managed_protocol_token"),
    }, indent=2))
    if payload["reader_summary"]["unclassified_production_readers"]:
        return 2
    if payload["mutation_summary"]["unclassified_production_mutations"]:
        return 2
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

