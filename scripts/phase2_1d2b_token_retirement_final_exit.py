#!/usr/bin/env python3
"""Phase 2.1D2B token-bloom retirement measurement and operator helpers.

Read-only stages never issue DDL. Production DROP is a separate
--apply-production-drop flag that only invokes the dedicated migration.
"""
from __future__ import annotations

import argparse
import json
import os
import sys
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict


import importlib.util

ROOT = Path("/opt/casescope")
sys.path.insert(0, str(ROOT))
os.environ.setdefault("SECRET_KEY", os.environ.get("SECRET_KEY") or "phase2-1d2b")

from tests.phase2_1d2a_lib import classify_consumer, parse_explain_indexes  # noqa: E402

_D2A_PATH = ROOT / "scripts" / "phase2_1d2a_bloom_dependency_resolution.py"
_D2A_SPEC = importlib.util.spec_from_file_location("phase2_1d2a_bloom_dependency_resolution", _D2A_PATH)
d2a = importlib.util.module_from_spec(_D2A_SPEC)
_D2A_SPEC.loader.exec_module(d2a)


TOKEN_FUNCTION_CLASS_QUERIES = (
    {
        "id": "hastoken_10_powershell",
        "fn": "hasToken",
        "case_id": 10,
        "pred": "hasToken(search_blob, 'powershell')",
        "consumer": "bin/database_flow_baseline.py / token class",
        "consumer_path": "bin/database_flow_baseline.py",
    },
    {
        "id": "hastoken_ci_10_powershell",
        "fn": "hasTokenCaseInsensitive",
        "case_id": 10,
        "pred": "hasTokenCaseInsensitive(search_blob, 'powershell')",
        "consumer": "utils/ioc_artifact_tagger.py",
    },
    {
        "id": "hastoken_ci_7_powershell",
        "fn": "hasTokenCaseInsensitive",
        "case_id": 7,
        "pred": "hasTokenCaseInsensitive(search_blob, 'powershell')",
        "consumer": "utils/ioc_artifact_tagger.py",
    },
    {
        "id": "like_10_ntlm",
        "fn": "LIKE",
        "case_id": 10,
        "pred": "search_blob LIKE '%NTLM%'",
        "consumer": "models/pattern_rules.py",
    },
    {
        "id": "like_7_ntlm",
        "fn": "LIKE",
        "case_id": 7,
        "pred": "search_blob LIKE '%NTLM%'",
        "consumer": "models/pattern_rules.py",
    },
    {
        "id": "like_32_ntlm",
        "fn": "LIKE",
        "case_id": 32,
        "pred": "search_blob LIKE '%NTLM%'",
        "consumer": "models/pattern_rules.py",
    },
    {
        "id": "ilike_10_cmdexe",
        "fn": "ILIKE",
        "case_id": 10,
        "pred": "search_blob ILIKE '%cmd.exe%'",
        "consumer": "routes/hunting_query_helpers.py SUBSTRING",
        "consumer_path": "routes/hunting_query_helpers.py",
    },
    {
        "id": "lower_like_10_powershell",
        "fn": "lower(search_blob) LIKE",
        "case_id": 10,
        "pred": "lower(search_blob) LIKE '%powershell%'",
        "consumer": "utils/ioc_artifact_tagger.py / models/rag.py",
        "consumer_path": "utils/ioc_artifact_tagger.py",
    },
    {
        "id": "hasall_14_sonicwall",
        "fn": "hasAllTokens",
        "case_id": 14,
        "pred": "hasAllTokens(search_blob, 'sonicwall')",
        "consumer": "routes/hunting_query_helpers.py TOKEN_SAFE",
    },
    {
        "id": "hasall_10_powershell",
        "fn": "hasAllTokens",
        "case_id": 10,
        "pred": "hasAllTokens(search_blob, 'powershell')",
        "consumer": "routes/hunting_query_helpers.py TOKEN_SAFE",
    },
    {
        "id": "hasany_10_or",
        "fn": "hasAnyTokens",
        "case_id": 10,
        "pred": "hasAnyTokens(search_blob, 'powershell administrator')",
        "consumer": "routes/hunting_query_helpers.py TOKEN_SAFE OR",
        "consumer_path": "routes/hunting_query_helpers.py",
    },
    {
        "id": "noise_hastoken_10",
        "fn": "hasTokenCaseInsensitive",
        "case_id": 10,
        "pred": "hasTokenCaseInsensitive(search_blob, 'powershell')",
        "consumer": "utils/noise_keywords.py",
        "consumer_path": "utils/noise_keywords.py",
    },
)

NGRAM_REPROOF = (
    {"id": "ngram_ntlm", "pred": "search_blob LIKE '%NTLM%'", "cases": (10, 7, 32)},
    {"id": "ngram_rc4", "pred": "search_blob LIKE '%RC4%'", "cases": (10, 7, 32)},
    {"id": "ngram_ipc", "pred": "search_blob LIKE '%IPC$%'", "cases": (10, 7, 32)},
    {"id": "ngram_txt", "pred": "search_blob LIKE '%TXT%'", "cases": (10, 7, 32)},
    {"id": "ngram_cmd_c", "pred": "search_blob LIKE '%cmd /c%'", "cases": (10, 7, 32)},
)

SEMANTIC_MATRIX = (
    {"id": "token_14_sonicwall", "case_id": 14, "kind": "TOKEN_SAFE", "pred": "hasAllTokens(search_blob, 'sonicwall')"},
    {"id": "token_10_powershell", "case_id": 10, "kind": "TOKEN_SAFE", "pred": "hasAllTokens(search_blob, 'powershell')"},
    {"id": "token_7_powershell", "case_id": 7, "kind": "TOKEN_SAFE", "pred": "hasAllTokens(search_blob, 'powershell')"},
    {"id": "token_32_powershell", "case_id": 32, "kind": "TOKEN_SAFE", "pred": "hasAllTokens(search_blob, 'powershell')"},
    {"id": "sub_10_cmdexe", "case_id": 10, "kind": "SUBSTRING", "pred": "search_blob ILIKE '%cmd.exe%'"},
    {"id": "sub_10_ip", "case_id": 10, "kind": "SUBSTRING", "pred": "search_blob ILIKE '%10.0.0.1%'"},
    {"id": "sub_7_ip", "case_id": 7, "kind": "SUBSTRING", "pred": "search_blob ILIKE '%10.0.0.1%'"},
    {"id": "sub_10_winps", "case_id": 10, "kind": "SUBSTRING", "pred": "search_blob ILIKE '%Windows PowerShell%'"},
    {"id": "unicode_10_munchen", "case_id": 10, "kind": "UNICODE", "pred": "search_blob ILIKE '%münchen%'"},
    {"id": "unicode_10_user", "case_id": 10, "kind": "UNICODE", "pred": "search_blob ILIKE '%用户%'"},
    {"id": "struct_10_4688", "case_id": 10, "kind": "STRUCTURED", "pred": "event_id = '4688'"},
    {"id": "struct_7_4688", "case_id": 7, "kind": "STRUCTURED", "pred": "event_id = '4688'"},
    {"id": "excl_14_powershell", "case_id": 14, "kind": "EXCLUSION", "pred": "NOT search_blob ILIKE '%powershell%'"},
    {"id": "pattern_10_ntlm", "case_id": 10, "kind": "PATTERN", "pred": "search_blob LIKE '%NTLM%'"},
    {"id": "pattern_10_rc4", "case_id": 10, "kind": "PATTERN", "pred": "search_blob LIKE '%RC4%'"},
    {"id": "pattern_10_ipc", "case_id": 10, "kind": "PATTERN", "pred": "search_blob LIKE '%IPC$%'"},
    {"id": "pattern_10_txt", "case_id": 10, "kind": "PATTERN", "pred": "search_blob LIKE '%TXT%'"},
    {"id": "pattern_10_cmd_c", "case_id": 10, "kind": "PATTERN", "pred": "search_blob LIKE '%cmd /c%'"},
)

IGNORE_TOKEN = {"ignore_data_skipping_indices": "idx_search_token"}


def utcnow() -> str:
    return datetime.now(timezone.utc).isoformat()


def expected_index_state(state: Dict[str, Any], *, token_present: bool) -> Dict[str, Any]:
    by_name = {item["name"]: item for item in state["indices"]}
    text = by_name.get("idx_search_blob_text") or {}
    ngram = by_name.get("idx_search_ngram") or {}
    token = by_name.get("idx_search_token")
    checks = {
        "clickhouse_version": state.get("clickhouse_version") == "26.7.3.19",
        "text_present": bool(text),
        "text_expr": (text.get("expr") == "search_blob"),
        "text_type": "text(tokenizer = 'splitByNonAlpha', preprocessor = lower(search_blob))"
        in str(text.get("type_full") or "").replace("'", "'"),
        "ngram_present": bool(ngram),
        "ngram_expr": ngram.get("expr") == "search_blob",
        "ngram_type": ngram.get("type_full") == "ngrambf_v1(3, 512, 2, 0)",
        "ngram_granularity": int(ngram.get("granularity") or 0) == 4,
        "token_present": token is not None,
        "idx_event_id": "idx_event_id" in by_name,
        "idx_selector_key": "idx_selector_key" in by_name,
        "idx_evidence_record_key": "idx_evidence_record_key" in by_name,
        "coverage_partial": state.get("coverage_partition_counts", {}).get("PARTIAL") == 0,
        "coverage_unmaterialized": state.get("coverage_partition_counts", {}).get("UNMATERIALIZED") == 0,
        "coverage_unknown": state.get("coverage_partition_counts", {}).get("UNKNOWN") == 0,
        "active_parts_materialized": state.get("active_parts_MATERIALIZED") == state.get("active_parts"),
        "mutations": state.get("mutations_in_progress") == 0,
    }
    text_type_ok = (
        str(text.get("type_full") or "").replace(" ", "").replace("'", "")
        == "text(tokenizer=splitByNonAlpha,preprocessor=lower(search_blob))"
    )
    checks["text_type"] = text_type_ok
    if token_present:
        checks["token_present"] = token is not None
        checks["token_expr"] = (token or {}).get("expr") == "search_blob"
        checks["token_type"] = (token or {}).get("type_full") == "tokenbf_v1(32768, 3, 0)"
        checks["token_granularity"] = int((token or {}).get("granularity") or 0) == 4
    else:
        checks["token_absent"] = token is None
        checks["token_present"] = token is None
    checks["ok"] = all(
        value is True
        for key, value in checks.items()
        if key != "ok" and key != "token_present" or True
    )
    required = [
        "clickhouse_version",
        "text_present",
        "text_expr",
        "text_type",
        "ngram_present",
        "ngram_expr",
        "ngram_type",
        "ngram_granularity",
        "idx_event_id",
        "idx_selector_key",
        "idx_evidence_record_key",
        "coverage_partial",
        "coverage_unmaterialized",
        "coverage_unknown",
        "active_parts_materialized",
        "mutations",
    ]
    if token_present:
        required.extend(["token_present", "token_expr", "token_type", "token_granularity"])
    else:
        required.append("token_absent")
    checks["ok"] = all(checks.get(key) for key in required)
    return {"checks": checks, "by_name": {name: by_name.get(name) for name in (
        "idx_search_blob_text",
        "idx_search_ngram",
        "idx_search_token",
        "idx_event_id",
        "idx_selector_key",
        "idx_evidence_record_key",
    )}}


def case_fingerprint(client, case_id: int) -> Dict[str, Any]:
    row = d2a.run_query(
        client,
        """
        SELECT count() AS n,
               sum(cityHash64(evidence_record_key)) AS erk_fp,
               sum(cityHash64(search_blob)) AS blob_fp
        FROM events WHERE case_id = {case_id:UInt32}
        """,
        parameters={"case_id": case_id},
    ).result_rows[0]
    return {"n": int(row[0] or 0), "erk_fp": str(row[1] or 0), "blob_fp": str(row[2] or 0)}


RETAINED_CONSUMER_CLASSES = frozenset({"production-required", "background-derivation"})


def token_safety(client, *, samples: int = 3) -> Dict[str, Any]:
    results = []
    blocking = []
    notes = []
    for item in TOKEN_FUNCTION_CLASS_QUERIES:
        consumer_path = item.get("consumer_path") or item.get("consumer") or ""
        consumer_class = classify_consumer(consumer_path)
        retained = consumer_class in RETAINED_CONSUMER_CLASSES
        sql = (
            f"SELECT count() FROM events WHERE case_id = {int(item['case_id'])} "
            f"AND ({item['pred']})"
        )
        explain_a = parse_explain_indexes(d2a.explain_text(client, sql))
        explain_b = parse_explain_indexes(d2a.explain_text(client, sql, settings=IGNORE_TOKEN))
        ident_a = d2a.capture_identity(client, item["pred"], item["case_id"])
        ident_b = d2a.capture_identity(client, item["pred"], item["case_id"], settings=IGNORE_TOKEN)
        timed_a = d2a.time_identity(
            client, item["pred"], item["case_id"], warmup=1, samples=samples
        )
        timed_b = d2a.time_identity(
            client,
            item["pred"],
            item["case_id"],
            settings=IGNORE_TOKEN,
            warmup=1,
            samples=samples,
        )
        same_n = ident_a["n"] == ident_b["n"]
        same_erk = ident_a["erk_fp"] == ident_b["erk_fp"]
        read_rows_delta = None
        if timed_a.get("read_rows_p50") is not None and timed_b.get("read_rows_p50") is not None:
            read_rows_delta = int(timed_b["read_rows_p50"]) - int(timed_a["read_rows_p50"])
        token_independent_prune = bool(explain_a.get("token_pruned"))
        ngram_ok = explain_a.get("ngram_pruned") == explain_b.get("ngram_pruned")
        text_ok = explain_a.get("direct_text_index") == explain_b.get("direct_text_index")
        material_rows = read_rows_delta is not None and read_rows_delta > 0
        identity_ok = same_n and same_erk
        if not identity_ok and not retained:
            notes.append(
                f"{item['id']}: idx_search_token changes {item['fn']} counts "
                f"{ident_a['n']} -> {ident_b['n']} (skip-index false negatives). "
                f"Consumer class {consumer_class} is not a retained current reader."
            )
            row_ok = ngram_ok and text_ok
        elif not identity_ok and retained:
            row_ok = False
        else:
            row_ok = ngram_ok and text_ok and not (
                retained and token_independent_prune and material_rows
            )
        row = {
            **item,
            "consumer_class": consumer_class,
            "retained_current_reader": retained,
            "explain_a": explain_a,
            "explain_b": explain_b,
            "ident_a": ident_a,
            "ident_b": ident_b,
            "timed_a": timed_a,
            "timed_b": timed_b,
            "same_n": same_n,
            "same_erk": same_erk,
            "read_rows_delta": read_rows_delta,
            "token_pruned_in_a": token_independent_prune,
            "ngram_prune_unchanged": ngram_ok,
            "text_path_unchanged": text_ok,
            "ok": row_ok,
        }
        results.append(row)
        if not row["ok"]:
            blocking.append(item["id"])
    return {
        "results": results,
        "blocking": blocking,
        "notes": notes,
        "ok": not blocking,
        "decision": "TOKEN_BLOOM_REDUNDANT" if not blocking else "PHASE2_1D2B_TOKEN_RETIREMENT_NOT_READY",
    }


def ngram_reproof(client) -> Dict[str, Any]:
    results = []
    blocking = []
    for item in NGRAM_REPROOF:
        for case_id in item["cases"]:
            count = int(
                d2a.run_query(
                    client,
                    f"SELECT count() FROM events WHERE case_id = {{case_id:UInt32}} AND ({item['pred']})",
                    parameters={"case_id": case_id},
                ).result_rows[0][0]
            )
            if count == 0:
                results.append(
                    {
                        "id": f"{item['id']}_{case_id}",
                        "case_id": case_id,
                        "pred": item["pred"],
                        "n": 0,
                        "skipped_no_matches": True,
                        "ok": True,
                    }
                )
                continue
            sql = (
                f"SELECT count() FROM events WHERE case_id = {int(case_id)} "
                f"AND ({item['pred']})"
            )
            parsed = parse_explain_indexes(d2a.explain_text(client, sql))
            ok = bool(parsed.get("idx_search_ngram") and parsed.get("ngram_pruned"))
            row = {
                "id": f"{item['id']}_{case_id}",
                "case_id": case_id,
                "pred": item["pred"],
                "n": count,
                "explain": parsed,
                "ngram_present": parsed.get("idx_search_ngram"),
                "ngram_pruned": parsed.get("ngram_pruned"),
                "ok": ok,
            }
            results.append(row)
            if not ok:
                blocking.append(row["id"])
    return {"results": results, "blocking": blocking, "ok": not blocking}


def semantic_matrix(client, *, samples: int = 3) -> Dict[str, Any]:
    results = []
    for item in SEMANTIC_MATRIX:
        ident = d2a.capture_identity(client, item["pred"], item["case_id"])
        timed = d2a.time_identity(
            client, item["pred"], item["case_id"], warmup=1, samples=samples
        )
        sql = (
            f"SELECT count() FROM events WHERE case_id = {int(item['case_id'])} "
            f"AND ({item['pred']})"
        )
        parsed = parse_explain_indexes(d2a.explain_text(client, sql))
        results.append({**item, "identity": ident, "timed": timed, "explain": parsed})
    return results


def storage_snapshot(state: Dict[str, Any]) -> Dict[str, Any]:
    bytes_by = state.get("index_bytes") or {}
    def _bytes(name):
        item = bytes_by.get(name) or {}
        return item.get("data_compressed_bytes")
    return {
        "idx_search_token_compressed_bytes": _bytes("idx_search_token"),
        "idx_search_ngram_compressed_bytes": _bytes("idx_search_ngram"),
        "idx_search_blob_text_compressed_bytes": _bytes("idx_search_blob_text"),
        "events_compressed_bytes": (state.get("parts_summary") or {}).get("compressed_bytes"),
        "disk_path": state.get("disk_path"),
        "disk_free_bytes": state.get("disk_free_bytes"),
    }


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--pre-drop-gates", action="store_true")
    parser.add_argument("--post-drop-proof", action="store_true")
    parser.add_argument("--apply-production-drop", action="store_true")
    parser.add_argument("--out", default=str(ROOT / "docs/database_flow_phase2/phase2_1d2b_token_retirement_final_exit.json"))
    args = parser.parse_args(argv)
    client = d2a.connect("casescope")
    payload: Dict[str, Any] = {"recorded_at": utcnow(), "tranche": "phase2_1d2b_token_retirement_final_exit"}
    if args.pre_drop_gates:
        state = d2a.index_state(client)
        expected = expected_index_state(state, token_present=True)
        consumers = d2a.walk_consumers()
        fingerprints = {str(cid): case_fingerprint(client, cid) for cid in (14, 10, 7, 32)}
        safety = token_safety(client)
        ngram = ngram_reproof(client)
        semantics = semantic_matrix(client)
        payload.update(
            {
                "index_state": state,
                "expected_index_state": expected,
                "consumers": consumers,
                "fingerprints": fingerprints,
                "token_safety": {
                    "blocking": safety["blocking"],
                    "ok": safety["ok"],
                    "decision": safety["decision"],
                    "notes": safety.get("notes") or [],
                    "results": [
                        {
                            "id": row["id"],
                            "fn": row["fn"],
                            "case_id": row["case_id"],
                            "pred": row["pred"],
                            "consumer": row["consumer"],
                            "consumer_class": row.get("consumer_class"),
                            "retained_current_reader": row.get("retained_current_reader"),
                            "same_n": row["same_n"],
                            "same_erk": row["same_erk"],
                            "n_a": row["ident_a"]["n"],
                            "n_b": row["ident_b"]["n"],
                            "erk_fp_a": row["ident_a"]["erk_fp"],
                            "erk_fp_b": row["ident_b"]["erk_fp"],
                            "read_rows_delta": row["read_rows_delta"],
                            "p50_a_ms": row["timed_a"]["p50_ms"],
                            "p50_b_ms": row["timed_b"]["p50_ms"],
                            "p95_a_ms": row["timed_a"]["p95_ms"],
                            "p95_b_ms": row["timed_b"]["p95_ms"],
                            "read_rows_a": row["timed_a"]["read_rows_p50"],
                            "read_rows_b": row["timed_b"]["read_rows_p50"],
                            "token_pruned_in_a": row["token_pruned_in_a"],
                            "ngram_prune_unchanged": row["ngram_prune_unchanged"],
                            "text_path_unchanged": row["text_path_unchanged"],
                            "skip_names_a": row["explain_a"]["skip_names"],
                            "skip_names_b": row["explain_b"]["skip_names"],
                            "ngram_granules_a": row["explain_a"].get("ngram_granules"),
                            "ok": row["ok"],
                        }
                        for row in safety["results"]
                    ],
                },
                "ngram_reproof": ngram,
                "pre_drop_semantics": [
                    {
                        "id": row["id"],
                        "case_id": row["case_id"],
                        "kind": row["kind"],
                        "pred": row["pred"],
                        "n": row["identity"]["n"],
                        "erk_fp": row["identity"]["erk_fp"],
                        "p50_ms": row["timed"]["p50_ms"],
                        "p95_ms": row["timed"]["p95_ms"],
                        "read_rows": row["timed"]["read_rows_p50"],
                        "read_bytes": row["timed"]["read_bytes_p50"],
                        "skip_names": row["explain"]["skip_names"],
                        "ngram_pruned": row["explain"].get("ngram_pruned"),
                        "direct_text": row["explain"].get("direct_text_index"),
                    }
                    for row in semantics
                ],
                "pre_drop_storage": storage_snapshot(state),
            }
        )
        if not expected["checks"]["ok"]:
            payload["verdict"] = "PHASE2_1D2B_NOT_READY"
            payload["stop_reason"] = "production_index_state"
        elif not safety["ok"]:
            payload["verdict"] = "PHASE2_1D2B_TOKEN_RETIREMENT_NOT_READY"
            payload["stop_reason"] = "token_bloom_still_required"
        elif not ngram["ok"]:
            payload["verdict"] = "PHASE2_1D2B_NOT_READY"
            payload["stop_reason"] = "ngram_exception_stale"
        else:
            payload["verdict"] = "PRE_DROP_GATES_PASS"
        Path(args.out).write_text(json.dumps(payload, indent=2, default=str) + "\n")
        print(json.dumps({"verdict": payload["verdict"], "out": args.out, "token_blocking": safety["blocking"], "ngram_blocking": ngram["blocking"]}, indent=2))
        return 0 if payload.get("verdict") == "PRE_DROP_GATES_PASS" else 2

    if args.apply_production_drop:
        from migrations.drop_events_search_token_bloom import drop_events_search_token_bloom

        result = drop_events_search_token_bloom(client, allow_production=True)
        print(result)
        return 0

    if args.post_drop_proof:
        state = d2a.index_state(client)
        expected = expected_index_state(state, token_present=False)
        fingerprints = {str(cid): case_fingerprint(client, cid) for cid in (14, 10, 7, 32)}
        ngram = ngram_reproof(client)
        semantics = semantic_matrix(client)
        payload.update(
            {
                "index_state_after": state,
                "expected_index_state_after": expected,
                "fingerprints_after": fingerprints,
                "ngram_reproof_after": ngram,
                "post_drop_semantics": [
                    {
                        "id": row["id"],
                        "case_id": row["case_id"],
                        "kind": row["kind"],
                        "pred": row["pred"],
                        "n": row["identity"]["n"],
                        "erk_fp": row["identity"]["erk_fp"],
                        "p50_ms": row["timed"]["p50_ms"],
                        "p95_ms": row["timed"]["p95_ms"],
                        "read_rows": row["timed"]["read_rows_p50"],
                        "read_bytes": row["timed"]["read_bytes_p50"],
                        "skip_names": row["explain"]["skip_names"],
                        "ngram_pruned": row["explain"].get("ngram_pruned"),
                        "direct_text": row["explain"].get("direct_text_index"),
                    }
                    for row in semantics
                ],
                "post_drop_storage": storage_snapshot(state),
            }
        )
        Path(args.out).write_text(json.dumps(payload, indent=2, default=str) + "\n")
        print(json.dumps({"expected_ok": expected["checks"]["ok"], "ngram_ok": ngram["ok"], "out": args.out}, indent=2))
        return 0 if expected["checks"]["ok"] and ngram["ok"] else 2

    parser.error("choose --pre-drop-gates, --apply-production-drop, or --post-drop-proof")
    return 2


if __name__ == "__main__":
    raise SystemExit(main())
