#!/usr/bin/env python3
"""Phase 1 Step 4 capture, tool probe, parity, and paired benchmark.

Part A/B run BEFORE production parser orchestration changes:

    /opt/casescope/venv/bin/python scripts/phase1_step4_run.py probe
    /opt/casescope/venv/bin/python scripts/phase1_step4_run.py capture-legacy

Later:

    /opt/casescope/venv/bin/python scripts/phase1_step4_run.py parity
    /opt/casescope/venv/bin/python scripts/phase1_step4_run.py benchmark
"""
from __future__ import annotations

import argparse
import ast
import hashlib
import json
import logging
import os
import shutil
import statistics
import subprocess
import sys
import tempfile
import time
from collections import Counter, defaultdict
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, Iterable, List, Optional, Tuple

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

CORPUS_DIR = Path("/opt/casescope-benchmark/phase0a_evtx")
OUT_DIR = ROOT / "docs" / "database_flow_phase1"
HAYABUSA_BIN = "/opt/casescope/bin/hayabusa"
EVTXECMD_BIN = "/opt/casescope/bin/evtxecmd"
HAYABUSA_RULES = "/opt/casescope/rules/hayabusa-rules"
HAYABUSA_PROFILE = "all-field-info-verbose"
EVTXECMD_MAPS = "/opt/casescope/bin/EvtxECmd/EvtxeCmd/Maps"

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


def _utc_now() -> str:
    return datetime.now(timezone.utc).isoformat()


def _sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def _sha256_text(value: Any) -> str:
    payload = value if isinstance(value, str) else json.dumps(value, sort_keys=True, default=str)
    return hashlib.sha256(payload.encode("utf-8")).hexdigest()


def _json_dump(path: Path, payload: Any) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(payload, indent=2, default=str) + "\n", encoding="utf-8")


def _corpus_files() -> List[Path]:
    files = sorted(CORPUS_DIR.glob("*.evtx"))
    if len(files) != 8:
        raise SystemExit(f"Expected 8 EVTX files in {CORPUS_DIR}, found {len(files)}")
    mismatches = []
    for path in files:
        digest = _sha256_file(path)
        expected = APPROVED_SHA256.get(path.name)
        if digest != expected:
            mismatches.append(f"{path.name}: {digest} != {expected}")
    if mismatches:
        raise SystemExit("Corpus SHA256 mismatch:\n" + "\n".join(mismatches))
    return files


def _hayabusa_cmd(output_path: str, extra: List[str]) -> List[str]:
    cmd = [
        HAYABUSA_BIN, "json-timeline",
        *extra,
        "-o", output_path,
        "-L",
        "-w",
        "-q",
        "-C",
        "--no-color",
        "-p", HAYABUSA_PROFILE,
        "--min-level", "informational",
        "-U",
    ]
    if os.path.isdir(HAYABUSA_RULES):
        cmd.extend(["-r", HAYABUSA_RULES])
    return cmd


def _run(cmd: List[str], timeout: int = 3600, cwd: Optional[str] = None) -> Dict[str, Any]:
    started = time.perf_counter()
    try:
        result = subprocess.run(
            cmd,
            capture_output=True,
            text=True,
            timeout=timeout,
            cwd=cwd or str(ROOT),
        )
        return {
            "cmd": cmd,
            "returncode": result.returncode,
            "stdout_tail": (result.stdout or "")[-2000:],
            "stderr_tail": (result.stderr or "")[-2000:],
            "wall_seconds": round(time.perf_counter() - started, 3),
            "timeout": False,
        }
    except subprocess.TimeoutExpired:
        return {
            "cmd": cmd,
            "returncode": None,
            "stdout_tail": "",
            "stderr_tail": "TIMEOUT",
            "wall_seconds": round(time.perf_counter() - started, 3),
            "timeout": True,
        }


def _load_jsonl(path: Path, limit: Optional[int] = None) -> List[Dict[str, Any]]:
    rows: List[Dict[str, Any]] = []
    if not path.exists() or path.stat().st_size == 0:
        return rows
    with path.open("r", encoding="utf-8-sig", errors="replace") as handle:
        for line in handle:
            line = line.strip()
            if not line:
                continue
            try:
                rows.append(json.loads(line))
            except json.JSONDecodeError:
                rows.append({"_unparsed": True, "_line": line[:200]})
            if limit is not None and len(rows) >= limit:
                break
    return rows


def _count_jsonl(path: Path) -> int:
    if not path.exists() or path.stat().st_size == 0:
        return 0
    count = 0
    with path.open("r", encoding="utf-8-sig", errors="replace") as handle:
        for line in handle:
            if line.strip():
                count += 1
    return count


def _field_inventory(rows: List[Dict[str, Any]]) -> Dict[str, Any]:
    keys = Counter()
    nonempty = Counter()
    samples: Dict[str, Any] = {}
    for row in rows:
        if not isinstance(row, dict):
            continue
        for key, value in row.items():
            keys[key] += 1
            if value not in (None, "", [], {}):
                nonempty[key] += 1
                if key not in samples:
                    samples[key] = value if not isinstance(value, (dict, list)) else (
                        value if len(str(value)) < 300 else type(value).__name__
                    )
    return {
        "row_count": len(rows),
        "keys": dict(keys),
        "nonempty_keys": dict(nonempty),
        "sample_values": {k: samples[k] for k in sorted(samples)},
    }


def cmd_probe(args: argparse.Namespace) -> int:
    files = _corpus_files()
    small = [p for p in files if p.name.startswith("Microsoft-Windows-TaskScheduler")][0]
    mid_a = [p for p in files if "TerminalServices" in p.name][0]
    mid_b = [p for p in files if "WMI-Activity" in p.name][0]
    app = [p for p in files if p.name == "Application.evtx"][0]
    system = [p for p in files if p.name == "System.evtx"][0]

    work = Path(tempfile.mkdtemp(prefix="phase1_step4_probe_", dir=str(OUT_DIR)))
    report: Dict[str, Any] = {
        "captured_at": _utc_now(),
        "hayabusa_bin": HAYABUSA_BIN,
        "evtxecmd_bin": EVTXECMD_BIN,
        "work_dir": str(work),
    }

    hayabusa_help = subprocess.run(
        [HAYABUSA_BIN, "help"], capture_output=True, text=True, timeout=30
    )
    hayabusa_jt = subprocess.run(
        [HAYABUSA_BIN, "json-timeline", "-h"], capture_output=True, text=True, timeout=30
    )
    evtx_help = subprocess.run(
        [EVTXECMD_BIN, "--help"], capture_output=True, text=True, timeout=30
    )
    evtx_ver = subprocess.run(
        [EVTXECMD_BIN, "--version"], capture_output=True, text=True, timeout=30
    )
    report["hayabusa"] = {
        "help_head": (hayabusa_help.stdout or hayabusa_help.stderr or "")[:500],
        "json_timeline_has_directory": "-d, --directory" in (hayabusa_jt.stdout or ""),
        "json_timeline_help": hayabusa_jt.stdout or hayabusa_jt.stderr,
    }
    report["evtxecmd"] = {
        "version": (evtx_ver.stdout or evtx_ver.stderr or "").strip(),
        "help": evtx_help.stdout or evtx_help.stderr,
        "has_directory": "-d <d>" in (evtx_help.stdout or "") or "-- " in (evtx_help.stdout or ""),
        "directory_help_line": next(
            (line.strip() for line in (evtx_help.stdout or "").splitlines() if line.strip().startswith("-d")),
            "",
        ),
        "json_flags": ["--json", "--jsonf", "--fj"],
        "recursive_documented": "recursively" in (evtx_help.stdout or "").lower(),
        "dedupe_flag": "--dedupe" in (evtx_help.stdout or ""),
    }

    # --- Hayabusa single file ---
    single_out = work / "hayabusa_single.jsonl"
    single_run = _run(_hayabusa_cmd(str(single_out), ["-f", str(mid_a)]))
    single_rows = _load_jsonl(single_out, limit=20)
    all_single = _load_jsonl(single_out)
    report["hayabusa_single_file"] = {
        "input": str(mid_a),
        "run": {k: v for k, v in single_run.items() if k != "cmd"},
        "cmd": single_run["cmd"],
        "output_bytes": single_out.stat().st_size if single_out.exists() else 0,
        "row_count": len(all_single),
        "inventory": _field_inventory(all_single[:50] or single_rows),
        "evtxfile_values": sorted({str(r.get("EvtxFile")) for r in all_single if isinstance(r, dict)}),
        "channel_values": sorted({str(r.get("Channel")) for r in all_single if isinstance(r, dict)})[:20],
        "record_id_sample": [r.get("RecordID") for r in all_single[:10] if isinstance(r, dict)],
        "has_evtxfile": any(isinstance(r, dict) and r.get("EvtxFile") for r in all_single),
        "has_channel": any(isinstance(r, dict) and r.get("Channel") for r in all_single),
        "has_rule_id": any(isinstance(r, dict) and r.get("RuleID") for r in all_single),
        "has_all_field_info": any(isinstance(r, dict) and r.get("AllFieldInfo") for r in all_single),
    }

    # --- Hayabusa directory, unique basenames ---
    dir_unique = work / "dir_unique"
    dir_unique.mkdir()
    shutil.copy2(mid_a, dir_unique / mid_a.name)
    shutil.copy2(mid_b, dir_unique / mid_b.name)
    dir_out = work / "hayabusa_dir_unique.jsonl"
    dir_run = _run(_hayabusa_cmd(str(dir_out), ["-d", str(dir_unique)]))
    dir_rows = _load_jsonl(dir_out)
    report["hayabusa_directory_unique"] = {
        "input_dir": str(dir_unique),
        "run": {k: v for k, v in dir_run.items() if k != "cmd"},
        "row_count": len(dir_rows),
        "evtxfile_values": sorted({str(r.get("EvtxFile")) for r in dir_rows if isinstance(r, dict)}),
        "evtxfile_is_basename": all(
            os.path.basename(str(r.get("EvtxFile") or "")) == str(r.get("EvtxFile") or "")
            for r in dir_rows if isinstance(r, dict) and r.get("EvtxFile")
        ),
        "evtxfile_is_abspath": all(
            os.path.isabs(str(r.get("EvtxFile") or ""))
            for r in dir_rows if isinstance(r, dict) and r.get("EvtxFile")
        ),
        "sample_row_keys": sorted(dir_rows[0].keys()) if dir_rows and isinstance(dir_rows[0], dict) else [],
        "sample_evtxfile": dir_rows[0].get("EvtxFile") if dir_rows and isinstance(dir_rows[0], dict) else None,
    }

    # --- Hayabusa recursive nested ---
    dir_nested = work / "dir_nested"
    (dir_nested / "sub").mkdir(parents=True)
    shutil.copy2(small, dir_nested / small.name)
    shutil.copy2(mid_a, dir_nested / "sub" / mid_a.name)
    nested_out = work / "hayabusa_nested.jsonl"
    nested_run = _run(_hayabusa_cmd(str(nested_out), ["-d", str(dir_nested)]))
    nested_rows = _load_jsonl(nested_out)
    nested_files = sorted({str(r.get("EvtxFile")) for r in nested_rows if isinstance(r, dict)})
    report["hayabusa_recursive"] = {
        "input_dir": str(dir_nested),
        "run": {k: v for k, v in nested_run.items() if k != "cmd"},
        "row_count": len(nested_rows),
        "evtxfile_values": nested_files,
        "saw_nested_file": any("TerminalServices" in name for name in nested_files),
        "saw_top_level_file": any("TaskScheduler" in name for name in nested_files),
    }

    # --- Hayabusa duplicate basenames ---
    dir_dup = work / "dir_dup"
    (dir_dup / "hostA").mkdir(parents=True)
    (dir_dup / "hostB").mkdir(parents=True)
    shutil.copy2(app, dir_dup / "hostA" / "Security.evtx")
    shutil.copy2(system, dir_dup / "hostB" / "Security.evtx")
    dup_out = work / "hayabusa_dup.jsonl"
    dup_run = _run(_hayabusa_cmd(str(dup_out), ["-d", str(dir_dup)]))
    dup_rows = _load_jsonl(dup_out)
    dup_files = sorted({str(r.get("EvtxFile")) for r in dup_rows if isinstance(r, dict)})
    report["hayabusa_duplicate_basename"] = {
        "input_dir": str(dir_dup),
        "run": {k: v for k, v in dup_run.items() if k != "cmd"},
        "row_count": len(dup_rows),
        "evtxfile_values": dup_files,
        "unique_evtxfile_count": len(dup_files),
        "basename_only": all(os.path.basename(v) == v for v in dup_files),
        "collision_unsafe_if_basename_only": len(dup_files) <= 1,
        "sample_paths": [str(r.get("EvtxFile")) for r in dup_rows[:5] if isinstance(r, dict)],
    }

    # --- Hayabusa one corrupt among valid ---
    dir_bad = work / "dir_bad"
    dir_bad.mkdir()
    shutil.copy2(small, dir_bad / small.name)
    bad_path = dir_bad / "corrupt.evtx"
    bad_path.write_bytes(b"NOT_AN_EVTX_FILE" + os.urandom(64))
    bad_out = work / "hayabusa_bad.jsonl"
    bad_run = _run(_hayabusa_cmd(str(bad_out), ["-d", str(dir_bad)]))
    bad_rows = _load_jsonl(bad_out)
    report["hayabusa_malformed_member"] = {
        "input_dir": str(dir_bad),
        "run": {k: v for k, v in bad_run.items() if k != "cmd"},
        "row_count": len(bad_rows),
        "evtxfile_values": sorted({str(r.get("EvtxFile")) for r in bad_rows if isinstance(r, dict)}),
        "aborted_entire_run": bad_run["returncode"] not in (0, None) and len(bad_rows) == 0,
        "produced_output_for_valid_file": any(
            "TaskScheduler" in str(r.get("EvtxFile") or "") for r in bad_rows if isinstance(r, dict)
        ),
    }

    # --- EvtxECmd single file JSON keys ---
    evtx_single_dir = work / "evtx_single"
    evtx_single_dir.mkdir()
    evtx_single_run = _run([
        EVTXECMD_BIN, "-f", str(mid_a),
        "--json", str(evtx_single_dir),
        "--jsonf", "single.json",
        "--maps", EVTXECMD_MAPS,
    ])
    evtx_single_path = evtx_single_dir / "single.json"
    evtx_single_rows = _load_jsonl(evtx_single_path, limit=5)
    evtx_single_count = _count_jsonl(evtx_single_path)
    report["evtxecmd_single_file"] = {
        "input": str(mid_a),
        "run": {k: v for k, v in evtx_single_run.items() if k != "cmd"},
        "row_count": evtx_single_count,
        "inventory": _field_inventory(evtx_single_rows),
        "sample_keys": sorted(evtx_single_rows[0].keys()) if evtx_single_rows else [],
        "source_like_fields": {
            key: evtx_single_rows[0].get(key)
            for key in (evtx_single_rows[0].keys() if evtx_single_rows else [])
            if any(token in key.lower() for token in ("file", "path", "source", "log", "channel"))
        } if evtx_single_rows else {},
    }

    # --- EvtxECmd directory unique ---
    evtx_dir_out = work / "evtx_dir"
    evtx_dir_out.mkdir()
    evtx_dir_run = _run([
        EVTXECMD_BIN, "-d", str(dir_unique),
        "--json", str(evtx_dir_out),
        "--jsonf", "dir.json",
        "--maps", EVTXECMD_MAPS,
    ])
    evtx_dir_path = evtx_dir_out / "dir.json"
    evtx_dir_sample = _load_jsonl(evtx_dir_path, limit=30)
    evtx_dir_count = _count_jsonl(evtx_dir_path)
    source_fields = []
    if evtx_dir_sample:
        source_fields = [
            key for key in evtx_dir_sample[0].keys()
            if any(token in key.lower() for token in ("file", "path", "source", "payload"))
        ]
    unique_source_values = set()
    for row in evtx_dir_sample:
        for key in ("SourceFile", "source_file", "LogFile", "PayloadFile", "FileName", "MapDescription"):
            if row.get(key):
                unique_source_values.add(f"{key}={row.get(key)}")
        # Scan all string fields for original basenames
        for key, value in row.items():
            if isinstance(value, str) and (mid_a.name in value or mid_b.name in value):
                unique_source_values.add(f"{key} contains {os.path.basename(value) if os.sep in value else value[:80]}")
    report["evtxecmd_directory_unique"] = {
        "input_dir": str(dir_unique),
        "run": {k: v for k, v in evtx_dir_run.items() if k != "cmd"},
        "row_count": evtx_dir_count,
        "sample_keys": sorted(evtx_dir_sample[0].keys()) if evtx_dir_sample else [],
        "source_like_keys_in_sample": source_fields,
        "source_attribution_hits_in_first_30": sorted(unique_source_values),
        "channel_values_sample": sorted({str(r.get("Channel")) for r in evtx_dir_sample})[:10],
        "record_fields": {
            "EventRecordId": evtx_dir_sample[0].get("EventRecordId") if evtx_dir_sample else None,
            "RecordNumber": evtx_dir_sample[0].get("RecordNumber") if evtx_dir_sample else None,
            "Channel": evtx_dir_sample[0].get("Channel") if evtx_dir_sample else None,
            "Computer": evtx_dir_sample[0].get("Computer") if evtx_dir_sample else None,
        },
    }

    # Full scan of EvtxECmd directory JSON for any filename attribution
    attribution_keys = Counter()
    if evtx_dir_path.exists() and evtx_dir_path.stat().st_size:
        with evtx_dir_path.open("r", encoding="utf-8-sig", errors="replace") as handle:
            for i, line in enumerate(handle):
                if i >= 200:
                    break
                line = line.strip()
                if not line:
                    continue
                try:
                    row = json.loads(line)
                except json.JSONDecodeError:
                    continue
                for key, value in row.items():
                    text = str(value)
                    if mid_a.name in text or mid_b.name in text or ".evtx" in text.lower():
                        attribution_keys[key] += 1
    report["evtxecmd_directory_unique"]["filename_hits_first_200_rows"] = dict(attribution_keys)

    # --- EvtxECmd duplicate basename ---
    evtx_dup_out = work / "evtx_dup"
    evtx_dup_out.mkdir()
    evtx_dup_run = _run([
        EVTXECMD_BIN, "-d", str(dir_dup),
        "--json", str(evtx_dup_out),
        "--jsonf", "dup.json",
        "--maps", EVTXECMD_MAPS,
    ])
    evtx_dup_path = evtx_dup_out / "dup.json"
    evtx_dup_sample = _load_jsonl(evtx_dup_path, limit=20)
    evtx_dup_count = _count_jsonl(evtx_dup_path)
    report["evtxecmd_duplicate_basename"] = {
        "run": {k: v for k, v in evtx_dup_run.items() if k != "cmd"},
        "row_count": evtx_dup_count,
        "sample_keys": sorted(evtx_dup_sample[0].keys()) if evtx_dup_sample else [],
        "filename_in_first_20": False,
    }
    if evtx_dup_sample:
        report["evtxecmd_duplicate_basename"]["filename_in_first_20"] = any(
            "Security.evtx" in str(v) or "hostA" in str(v) or "hostB" in str(v)
            for row in evtx_dup_sample for v in row.values()
        )

    # --- EvtxECmd malformed member ---
    evtx_bad_out = work / "evtx_bad"
    evtx_bad_out.mkdir()
    evtx_bad_run = _run([
        EVTXECMD_BIN, "-d", str(dir_bad),
        "--json", str(evtx_bad_out),
        "--jsonf", "bad.json",
        "--maps", EVTXECMD_MAPS,
    ])
    evtx_bad_path = evtx_bad_out / "bad.json"
    report["evtxecmd_malformed_member"] = {
        "run": {k: v for k, v in evtx_bad_run.items() if k != "cmd"},
        "row_count": _count_jsonl(evtx_bad_path),
        "output_exists": evtx_bad_path.exists(),
        "aborted_entire_run": evtx_bad_run["returncode"] not in (0, None) and not (
            evtx_bad_path.exists() and evtx_bad_path.stat().st_size > 0
        ),
    }

    # --- EvtxECmd --fj extra fields ---
    evtx_fj_out = work / "evtx_fj"
    evtx_fj_out.mkdir()
    evtx_fj_run = _run([
        EVTXECMD_BIN, "-d", str(dir_unique),
        "--json", str(evtx_fj_out),
        "--jsonf", "fj.json",
        "--fj",
        "--maps", EVTXECMD_MAPS,
    ])
    evtx_fj_sample = _load_jsonl(evtx_fj_out / "fj.json", limit=3)
    fj_keys = sorted(evtx_fj_sample[0].keys()) if evtx_fj_sample else []
    fj_hits = []
    for row in evtx_fj_sample:
        for key, value in row.items():
            if isinstance(value, str) and (".evtx" in value.lower() or mid_a.name in value or mid_b.name in value):
                fj_hits.append({key: value[:200]})
    report["evtxecmd_full_json_fj"] = {
        "run": {k: v for k, v in evtx_fj_run.items() if k != "cmd"},
        "sample_keys": fj_keys,
        "filename_hits": fj_hits,
        "extra_keys_vs_default": sorted(set(fj_keys) - set(report["evtxecmd_single_file"]["sample_keys"])),
    }

    _json_dump(OUT_DIR / "phase1_step4_tool_probe.json", report)
    print(json.dumps({
        "wrote": str(OUT_DIR / "phase1_step4_tool_probe.json"),
        "hayabusa_evtxfile_single": report["hayabusa_single_file"]["evtxfile_values"][:5],
        "hayabusa_evtxfile_dir": report["hayabusa_directory_unique"]["evtxfile_values"][:5],
        "hayabusa_dup_evtxfile": report["hayabusa_duplicate_basename"]["evtxfile_values"][:5],
        "hayabusa_recursive_saw_nested": report["hayabusa_recursive"]["saw_nested_file"],
        "evtxecmd_dir_filename_hits": report["evtxecmd_directory_unique"]["filename_hits_first_200_rows"],
        "evtxecmd_fj_filename_hits": report["evtxecmd_full_json_fj"]["filename_hits"],
        "evtxecmd_malformed_aborted": report["evtxecmd_malformed_member"]["aborted_entire_run"],
        "hayabusa_malformed_aborted": report["hayabusa_malformed_member"]["aborted_entire_run"],
    }, indent=2))
    return 0


def _canonical_detection(entry: Dict[str, Any]) -> Dict[str, Any]:
    return {
        "rule_title": entry.get("rule_title") or "",
        "rule_level": entry.get("rule_level") or "",
        "rule_file": entry.get("rule_file") or "",
        "mitre_tactics": list(entry.get("mitre_tactics") or []),
        "mitre_tags": list(entry.get("mitre_tags") or []),
    }


def cmd_capture_legacy(args: argparse.Namespace) -> int:
    os.environ.setdefault("SECRET_KEY", "phase1-step4-legacy-capture")
    files = _corpus_files()
    from parsers.evtx_parser import EvtxECmdParser

    events_path = OUT_DIR / "phase1_step4_legacy_events.jsonl"
    detections_path = OUT_DIR / "phase1_step4_legacy_detections.jsonl"
    summary_path = OUT_DIR / "phase1_step4_legacy_per_file.json"

    record_ids: List[Tuple[str, str, int]] = []  # source_file, channel, record_id
    file_summaries = []
    total_events = 0
    total_detections = 0
    started = time.perf_counter()

    with events_path.open("w", encoding="utf-8") as events_out, detections_path.open("w", encoding="utf-8") as det_out:
        for index, path in enumerate(files, start=1):
            file_started = time.perf_counter()
            parser = EvtxECmdParser(
                case_id=1,
                source_host=path.stem,
                case_file_id=index,
                case_tz="UTC",
            )
            channels = Counter()
            detection_count = 0
            event_count = 0
            attached_erks = []
            for event in parser.parse(str(path)):
                event.to_clickhouse_row()
                event_count += 1
                total_events += 1
                extra = {}
                try:
                    extra = json.loads(event.extra_fields or "{}")
                except json.JSONDecodeError:
                    extra = {}
                detections = extra.get("hayabusa_detections") or []
                if not isinstance(detections, list):
                    detections = []
                record_id = int(event.record_id or 0)
                channel = event.channel or ""
                source_file = event.source_file or path.name
                record_ids.append((source_file, channel, record_id))
                channels[channel or "(empty)"] += 1
                compact = {
                    "source_path": str(path.resolve()),
                    "source_file": source_file,
                    "case_file_id": event.case_file_id,
                    "source_host": event.source_host,
                    "record_id": record_id,
                    "event_id": event.event_id,
                    "channel": channel,
                    "timestamp": str(event.timestamp or ""),
                    "erk": event.evidence_record_key,
                    "parser_version": event.parser_version,
                    "raw_json_sha256": _sha256_text(event.raw_json or ""),
                    "search_blob_sha256": _sha256_text(event.search_blob or ""),
                    "extra_fields_sha256": _sha256_text(event.extra_fields or ""),
                    "rule_title": event.rule_title or "",
                    "rule_level": event.rule_level or "",
                    "rule_file": event.rule_file or "",
                    "mitre_tactics": list(event.mitre_tactics or []),
                    "mitre_tags": list(event.mitre_tags or []),
                    "mitre_mapping_max_confidence": event.mitre_mapping_max_confidence,
                    "has_detection": bool(detections),
                    "attached_detections": [_canonical_detection(d) for d in detections],
                }
                events_out.write(json.dumps(compact, default=str) + "\n")
                for det in detections:
                    detection_count += 1
                    total_detections += 1
                    identity = {
                        "source_path": str(path.resolve()),
                        "source_file": source_file,
                        "case_file_id": event.case_file_id,
                        "record_id": record_id,
                        "event_id": event.event_id,
                        "channel": channel,
                        "erk": event.evidence_record_key,
                        **_canonical_detection(det),
                        "confidence": parser._hayabusa_confidence(det.get("rule_level")),
                    }
                    det_out.write(json.dumps(identity, default=str) + "\n")
                    attached_erks.append(event.evidence_record_key)

            file_summaries.append({
                "source_absolute_path": str(path.resolve()),
                "source_basename": path.name,
                "sha256": APPROVED_SHA256[path.name],
                "size_bytes": path.stat().st_size,
                "case_file_id": index,
                "source_host": path.stem,
                "channels": dict(channels),
                "primary_channel": channels.most_common(1)[0][0] if channels else None,
                "evtxecmd_row_count": event_count,
                "hayabusa_detection_count": detection_count,
                "events_with_detections": len(set(attached_erks)),
                "parser_errors": list(parser.errors),
                "parser_warnings_count": len(parser.warnings),
                "wall_seconds": round(time.perf_counter() - file_started, 3),
            })
            print(f"captured {path.name}: events={event_count} detections={detection_count}", flush=True)

    by_record: Dict[int, set] = defaultdict(set)
    by_channel_record: Dict[Tuple[str, int], set] = defaultdict(set)
    by_file_record: Dict[Tuple[str, int], int] = Counter()
    for source_file, channel, record_id in record_ids:
        by_record[record_id].add(source_file)
        by_channel_record[(channel, record_id)].add(source_file)
        by_file_record[(source_file, record_id)] += 1

    cross_record = {rid: sorted(files_) for rid, files_ in by_record.items() if len(files_) > 1}
    cross_channel = {
        f"{channel}|{rid}": sorted(files_)
        for (channel, rid), files_ in by_channel_record.items()
        if len(files_) > 1
    }
    intra_file_dups = {
        f"{source_file}|{rid}": count
        for (source_file, rid), count in by_file_record.items()
        if count > 1
    }

    summary = {
        "dataset": "LEGACY_PER_FILE",
        "captured_at": _utc_now(),
        "corpus_dir": str(CORPUS_DIR),
        "file_count": len(files),
        "total_bytes": sum(p.stat().st_size for p in files),
        "total_parsed_events": total_events,
        "total_hayabusa_detection_attachments": total_detections,
        "wall_seconds": round(time.perf_counter() - started, 3),
        "files": file_summaries,
        "collision_analysis": {
            "total_record_id_values_seen": len(record_ids),
            "unique_record_ids": len(by_record),
            "cross_file_duplicate_record_ids": len(cross_record),
            "cross_file_duplicate_channel_record_id": len(cross_channel),
            "cross_file_duplicate_source_file_record_id": 0,
            "intra_file_duplicate_source_file_record_id": len(intra_file_dups),
            "cross_file_record_id_examples": [
                {"record_id": rid, "source_files": files_}
                for rid, files_ in sorted(cross_record.items(), key=lambda item: -len(item[1]))[:25]
            ],
            "cross_file_channel_record_id_examples": [
                {"channel_record_id": key, "source_files": files_}
                for key, files_ in list(cross_channel.items())[:25]
            ],
            "intra_file_duplicate_examples": dict(list(intra_file_dups.items())[:25]),
        },
        "events_jsonl": str(events_path),
        "detections_jsonl": str(detections_path),
    }
    _json_dump(summary_path, summary)
    print(json.dumps({
        "wrote": str(summary_path),
        "total_events": total_events,
        "total_detections": total_detections,
        "cross_file_duplicate_record_ids": summary["collision_analysis"]["cross_file_duplicate_record_ids"],
        "cross_file_duplicate_channel_record_id": summary["collision_analysis"]["cross_file_duplicate_channel_record_id"],
        "unique_record_ids": summary["collision_analysis"]["unique_record_ids"],
    }, indent=2))
    return 0


def _load_legacy_events() -> Dict[str, Dict[str, Any]]:
    path = OUT_DIR / "phase1_step4_legacy_events.jsonl"
    by_erk = {}
    with path.open("r", encoding="utf-8") as handle:
        for line in handle:
            rec = json.loads(line)
            by_erk[rec["erk"]] = rec
    return by_erk


def _load_legacy_detections() -> List[Dict[str, Any]]:
    path = OUT_DIR / "phase1_step4_legacy_detections.jsonl"
    rows = []
    with path.open("r", encoding="utf-8") as handle:
        for line in handle:
            rows.append(json.loads(line))
    return rows


def _event_compact(event, parser) -> Dict[str, Any]:
    event.to_clickhouse_row()
    extra = {}
    try:
        extra = json.loads(event.extra_fields or "{}")
    except json.JSONDecodeError:
        extra = {}
    detections = extra.get("hayabusa_detections") or []
    if not isinstance(detections, list):
        detections = []
    return {
        "source_file": event.source_file,
        "case_file_id": event.case_file_id,
        "source_host": event.source_host,
        "record_id": int(event.record_id or 0),
        "event_id": event.event_id,
        "channel": event.channel or "",
        "timestamp": str(event.timestamp or ""),
        "erk": event.evidence_record_key,
        "parser_version": event.parser_version,
        "raw_json_sha256": _sha256_text(event.raw_json or ""),
        "search_blob_sha256": _sha256_text(event.search_blob or ""),
        "extra_fields_sha256": _sha256_text(event.extra_fields or ""),
        "rule_title": event.rule_title or "",
        "rule_level": event.rule_level or "",
        "rule_file": event.rule_file or "",
        "mitre_tactics": list(event.mitre_tactics or []),
        "mitre_tags": list(event.mitre_tags or []),
        "mitre_mapping_max_confidence": event.mitre_mapping_max_confidence,
        "has_detection": bool(detections),
        "attached_detections": [_canonical_detection(d) for d in detections],
    }


def cmd_parity(args: argparse.Namespace) -> int:
    os.environ.setdefault("SECRET_KEY", "phase1-step4-parity")
    files = _corpus_files()
    from parsers.evtx_parser import EvtxECmdParser
    from utils.evtx_directory_mode import EvtxGroupMember

    legacy_events = _load_legacy_events()
    legacy_dets = _load_legacy_detections()
    members = [
        EvtxGroupMember(
            file_path=str(path),
            case_file_id=index,
            source_host=path.stem,
        )
        for index, path in enumerate(files, start=1)
    ]
    parser = EvtxECmdParser(case_id=1, source_host="", case_file_id=None, case_tz="UTC")
    started = time.perf_counter()
    first_event_s = None
    directory_events = []
    directory_dets = []
    cross_file = 0
    for event in parser.parse_directory_group(members):
        if first_event_s is None:
            first_event_s = time.perf_counter() - started
        compact = _event_compact(event, parser)
        directory_events.append(compact)
        for det in compact["attached_detections"]:
            directory_dets.append({
                "source_file": compact["source_file"],
                "case_file_id": compact["case_file_id"],
                "record_id": compact["record_id"],
                "event_id": compact["event_id"],
                "channel": compact["channel"],
                "erk": compact["erk"],
                **det,
                "confidence": EvtxECmdParser._hayabusa_confidence(det.get("rule_level")),
            })
            if det and compact["source_file"] not in (
                next((m.source_file for m in members if m.case_file_id == compact["case_file_id"]), ""),
            ):
                cross_file += 1
    wall = time.perf_counter() - started

    dir_by_erk = {rec["erk"]: rec for rec in directory_events}
    legacy_erk = set(legacy_events)
    dir_erk = set(dir_by_erk)
    field_diffs = 0
    compare_fields = [
        "source_file", "case_file_id", "source_host", "record_id", "event_id",
        "channel", "parser_version", "raw_json_sha256", "search_blob_sha256",
        "extra_fields_sha256", "rule_title", "rule_level", "rule_file",
        "mitre_tactics", "mitre_tags", "mitre_mapping_max_confidence",
        "attached_detections",
    ]
    examples = []
    for erk in sorted(legacy_erk & dir_erk):
        left = legacy_events[erk]
        right = dir_by_erk[erk]
        mismatched = [name for name in compare_fields if left.get(name) != right.get(name)]
        if mismatched:
            field_diffs += 1
            if len(examples) < 10:
                examples.append({"erk": erk, "fields": mismatched, "source_file": left.get("source_file")})

    def _det_key(row):
        return (
            row.get("erk"),
            row.get("source_file"),
            row.get("record_id"),
            row.get("rule_title"),
            row.get("rule_file"),
            row.get("rule_level"),
            tuple(row.get("mitre_tactics") or []),
            tuple(row.get("mitre_tags") or []),
        )

    legacy_det_keys = Counter(_det_key(row) for row in legacy_dets)
    dir_det_keys = Counter(_det_key(row) for row in directory_dets)
    missing_dets = sum((legacy_det_keys - dir_det_keys).values())
    extra_dets = sum((dir_det_keys - legacy_det_keys).values())

    report = {
        "captured_at": _utc_now(),
        "directory_wall_seconds": round(wall, 3),
        "first_parsed_event_seconds": None if first_event_s is None else round(first_event_s, 3),
        "legacy_events": len(legacy_events),
        "directory_events": len(directory_events),
        "legacy_detections": len(legacy_dets),
        "directory_detections": len(directory_dets),
        "erk_legacy_minus_directory": len(legacy_erk - dir_erk),
        "erk_directory_minus_legacy": len(dir_erk - legacy_erk),
        "events_with_field_differences": field_diffs,
        "field_diff_examples": examples,
        "legacy_detections_minus_directory": missing_dets,
        "directory_detections_minus_legacy": extra_dets,
        "incorrect_cross_file_attachments": cross_file,
        "parser_errors": list(parser.errors),
        "parser_warnings_count": len(parser.warnings),
        "event_parity": len(legacy_events) == len(directory_events)
            and not (legacy_erk - dir_erk)
            and not (dir_erk - legacy_erk)
            and field_diffs == 0,
        "detection_parity": missing_dets == 0 and extra_dets == 0 and cross_file == 0,
    }
    _json_dump(OUT_DIR / "phase1_step4_parity.json", report)
    print(json.dumps(report, indent=2))
    return 0 if report["event_parity"] and report["detection_parity"] else 1


def _attach_metric_collector():
    class _Collector(logging.Handler):
        def __init__(self):
            super().__init__(level=logging.INFO)
            self.metrics: List[Dict[str, Any]] = []

        def emit(self, record: logging.LogRecord) -> None:
            if record.msg != "database_flow_phase0a_metric %s" or not record.args:
                return
            payload = record.args[0] if isinstance(record.args, tuple) else record.args
            if isinstance(payload, dict):
                self.metrics.append(dict(payload))
                return
            try:
                self.metrics.append(ast.literal_eval(str(payload)))
            except Exception:
                pass

    collector = _Collector()
    metric_logger = logging.getLogger("casescope.database_flow.ingest")
    metric_logger.addHandler(collector)
    metric_logger.setLevel(logging.INFO)
    return collector


def _tool_stage_summary(metrics: List[Dict[str, Any]]) -> Dict[str, Any]:
    hayabusa = [m for m in metrics if m.get("stage") == "hayabusa_process"]
    evtxecmd = [m for m in metrics if m.get("stage") == "evtxecmd_process"]
    jsonl = [m for m in metrics if m.get("stage") == "evtx_jsonl_consume"]
    return {
        "hayabusa_launches": len(hayabusa),
        "hayabusa_wall_seconds": round(sum(float(m.get("duration_ms") or 0) for m in hayabusa) / 1000.0, 3),
        "evtxecmd_launches": len(evtxecmd),
        "evtxecmd_wall_seconds": round(sum(float(m.get("duration_ms") or 0) for m in evtxecmd) / 1000.0, 3),
        "jsonl_consume_seconds": round(sum(float(m.get("duration_ms") or 0) for m in jsonl) / 1000.0, 3),
    }


def cmd_parser_bench(args: argparse.Namespace) -> int:
    os.environ.setdefault("SECRET_KEY", "phase1-step4-parser-bench")
    files = _corpus_files()
    from parsers.evtx_parser import EvtxECmdParser
    from utils.evtx_directory_mode import EvtxGroupMember

    collector = _attach_metric_collector()

    def _snapshot_metrics(before: int) -> Dict[str, Any]:
        return _tool_stage_summary(collector.metrics[before:])

    def run_per_file():
        started = time.perf_counter()
        first = None
        count = 0
        metric_at = len(collector.metrics)
        parser = EvtxECmdParser(case_id=1, source_host="", case_file_id=None, case_tz="UTC")
        for index, path in enumerate(files, start=1):
            parser.case_file_id = index
            parser.source_host = path.stem
            for event in parser.parse(str(path)):
                if first is None:
                    first = time.perf_counter() - started
                count += 1
        tools = _snapshot_metrics(metric_at)
        return {
            "mode": "per_file",
            "wall_seconds": round(time.perf_counter() - started, 3),
            "events": count,
            "first_event_seconds": None if first is None else round(first, 3),
            "errors": list(parser.errors),
            **tools,
        }

    def run_directory():
        started = time.perf_counter()
        first = None
        count = 0
        metric_at = len(collector.metrics)
        members = [
            EvtxGroupMember(file_path=str(path), case_file_id=index, source_host=path.stem)
            for index, path in enumerate(files, start=1)
        ]
        parser = EvtxECmdParser(case_id=1, source_host="", case_file_id=None, case_tz="UTC")
        for event in parser.parse_directory_group(members):
            if first is None:
                first = time.perf_counter() - started
            count += 1
        tools = _snapshot_metrics(metric_at)
        return {
            "mode": "directory",
            "wall_seconds": round(time.perf_counter() - started, 3),
            "events": count,
            "first_event_seconds": None if first is None else round(first, 3),
            "errors": list(parser.errors),
            **tools,
        }

    pairs = []
    for i in range(int(args.pairs)):
        a = run_per_file()
        b = run_directory()
        pairs.append({"index": i + 1, "per_file": a, "directory": b})
        print(json.dumps({"pair": i + 1, "per_file": a, "directory": b}), flush=True)

    per_walls = [p["per_file"]["wall_seconds"] for p in pairs]
    dir_walls = [p["directory"]["wall_seconds"] for p in pairs]
    per_first = [p["per_file"]["first_event_seconds"] for p in pairs]
    dir_first = [p["directory"]["first_event_seconds"] for p in pairs]
    report = {
        "captured_at": _utc_now(),
        "pairs": pairs,
        "per_file_median_wall": statistics.median(per_walls),
        "directory_median_wall": statistics.median(dir_walls),
        "per_file_median_first_event": statistics.median(per_first),
        "directory_median_first_event": statistics.median(dir_first),
        "first_event_delta_seconds": round(
            statistics.median(dir_first) - statistics.median(per_first), 3
        ),
        "first_event_delta_percent": round(
            100.0 * (statistics.median(dir_first) - statistics.median(per_first)) / statistics.median(per_first),
            2,
        ) if statistics.median(per_first) else None,
        "throughput_multiplier": round(
            statistics.median(per_walls) / statistics.median(dir_walls), 3
        ) if statistics.median(dir_walls) else None,
    }
    _json_dump(OUT_DIR / "phase1_step4_parser_benchmark.json", report)
    print(json.dumps({k: v for k, v in report.items() if k != "pairs"}, indent=2))
    return 0


def main() -> int:
    parser = argparse.ArgumentParser(description="Phase 1 Step 4 runner")
    sub = parser.add_subparsers(dest="cmd", required=True)
    sub.add_parser("probe", help="Inspect installed Hayabusa/EvtxECmd directory-mode behavior")
    sub.add_parser("capture-legacy", help="Capture LEGACY_PER_FILE from current per-file parser")
    sub.add_parser("parity", help="Compare directory-mode parse against LEGACY_PER_FILE")
    bench = sub.add_parser("parser-bench", help="Paired per-file vs directory parser wall times")
    bench.add_argument("--pairs", type=int, default=2)
    args = parser.parse_args()
    if args.cmd == "probe":
        return cmd_probe(args)
    if args.cmd == "capture-legacy":
        return cmd_capture_legacy(args)
    if args.cmd == "parity":
        return cmd_parity(args)
    if args.cmd == "parser-bench":
        return cmd_parser_bench(args)
    raise SystemExit(f"unknown command {args.cmd}")


if __name__ == "__main__":
    raise SystemExit(main())
