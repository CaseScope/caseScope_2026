#!/usr/bin/env python3
"""Phase 1 Step 4 latency-closure study.

Parser-only and disposable ingest measurements for grouping policies.
Does not wait for later uploads. Does not change source-aware correlation.
"""
from __future__ import annotations

import argparse
import ast
import hashlib
import json
import logging
import os
import resource
import statistics
import subprocess
import sys
import time
from collections import Counter
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, List, Optional
from urllib.parse import urlparse, urlunparse

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

CORPUS_DIR = Path("/opt/casescope-benchmark/phase0a_evtx")
OUT_DIR = ROOT / "docs" / "database_flow_phase1"

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

PARSER_POLICIES = [
    {"name": "g1_per_file", "eager_first": False, "target_files": 1, "order": "queue"},
    {"name": "g2", "eager_first": False, "target_files": 2, "order": "queue"},
    {"name": "g4", "eager_first": False, "target_files": 4, "order": "queue"},
    {"name": "g8_current", "eager_first": False, "target_files": 8, "order": "queue"},
    {"name": "eager1_rest7", "eager_first": True, "target_files": 8, "order": "queue"},
    {"name": "eager1_g2", "eager_first": True, "target_files": 2, "order": "queue"},
    {"name": "eager1_g4", "eager_first": True, "target_files": 4, "order": "queue"},
    {"name": "small_first_g8", "eager_first": False, "target_files": 8, "order": "smallest"},
    {"name": "small_first_eager1_rest", "eager_first": True, "target_files": 8, "order": "smallest"},
]


def _utc_now() -> str:
    return datetime.now(timezone.utc).isoformat()


def _sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


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


def _cpu_seconds() -> Dict[str, float]:
    self_usage = resource.getrusage(resource.RUSAGE_SELF)
    child_usage = resource.getrusage(resource.RUSAGE_CHILDREN)
    return {
        "self": self_usage.ru_utime + self_usage.ru_stime,
        "children": child_usage.ru_utime + child_usage.ru_stime,
        "rss_mb": self_usage.ru_maxrss / 1024.0,
    }


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
    return {
        "hayabusa_launches": len(hayabusa),
        "hayabusa_wall_seconds": round(sum(float(m.get("duration_ms") or 0) for m in hayabusa) / 1000.0, 3),
        "evtxecmd_launches": len(evtxecmd),
        "evtxecmd_wall_seconds": round(sum(float(m.get("duration_ms") or 0) for m in evtxecmd) / 1000.0, 3),
    }


def _describe_plan(files: List[Path], policy: Dict[str, Any]) -> List[Dict[str, Any]]:
    from utils.evtx_directory_mode import EvtxGroupMember, plan_evtx_parse_units

    members = [
        EvtxGroupMember(
            file_path=str(path),
            case_file_id=index,
            source_host=path.stem,
            source_file=path.name,
            size_bytes=path.stat().st_size,
        )
        for index, path in enumerate(files, start=1)
    ]
    units = plan_evtx_parse_units(
        members,
        eager_first=bool(policy["eager_first"]),
        target_files=int(policy["target_files"]),
        order=str(policy["order"]),
    )
    return [
        {
            "mode": unit.mode,
            "files": [member.source_file for member in unit.members],
            "bytes": unit.size_bytes,
        }
        for unit in units
    ]


def cmd_parser_study(args: argparse.Namespace) -> int:
    os.environ.setdefault("SECRET_KEY", "phase1-step4-latency-parser")
    files = _corpus_files()
    from parsers.evtx_parser import EvtxECmdParser
    from utils.evtx_directory_mode import EvtxGroupMember, plan_evtx_parse_units

    collector = _attach_metric_collector()
    policies = list(PARSER_POLICIES)
    if args.policies:
        wanted = {name.strip() for name in args.policies.split(",") if name.strip()}
        policies = [item for item in policies if item["name"] in wanted]
        missing = wanted - {item["name"] for item in policies}
        if missing:
            raise SystemExit(f"Unknown policies: {sorted(missing)}")

    group_bytes = {item["name"]: _describe_plan(files, item) for item in policies}
    pairs = []
    for pair_index in range(int(args.pairs)):
        rotated = policies[pair_index % len(policies):] + policies[: pair_index % len(policies)]
        pair_runs = []
        for policy in rotated:
            members = [
                EvtxGroupMember(
                    file_path=str(path),
                    case_file_id=index,
                    source_host=path.stem,
                    source_file=path.name,
                    size_bytes=path.stat().st_size,
                )
                for index, path in enumerate(files, start=1)
            ]
            units = plan_evtx_parse_units(
                members,
                eager_first=bool(policy["eager_first"]),
                target_files=int(policy["target_files"]),
                order=str(policy["order"]),
            )
            metric_at = len(collector.metrics)
            cpu_before = _cpu_seconds()
            started = time.perf_counter()
            first_event = None
            count = 0
            timeline = []
            parser_errors = []
            for unit_index, unit in enumerate(units):
                unit_started = time.perf_counter()
                unit_first = None
                parser = EvtxECmdParser(case_id=1, source_host="", case_file_id=None, case_tz="UTC")
                if unit.mode == "per_file":
                    member = unit.members[0]
                    parser.case_file_id = member.case_file_id
                    parser.source_host = member.source_host
                    event_iter = parser.parse(member.file_path)
                else:
                    event_iter = parser.parse_directory_group(list(unit.members))
                unit_count = 0
                for _event in event_iter:
                    now = time.perf_counter() - started
                    if first_event is None:
                        first_event = now
                    if unit_first is None:
                        unit_first = now
                    count += 1
                    unit_count += 1
                parser_errors.extend(list(parser.errors))
                timeline.append({
                    "unit_index": unit_index,
                    "mode": unit.mode,
                    "files": [member.source_file for member in unit.members],
                    "bytes": unit.size_bytes,
                    "events": unit_count,
                    "first_event_seconds": None if unit_first is None else round(unit_first, 3),
                    "complete_seconds": round(time.perf_counter() - started, 3),
                    "unit_wall_seconds": round(time.perf_counter() - unit_started, 3),
                })
            cpu_after = _cpu_seconds()
            tools = _tool_stage_summary(collector.metrics[metric_at:])
            run = {
                "policy": policy["name"],
                "eager_first": policy["eager_first"],
                "target_files": policy["target_files"],
                "order": policy["order"],
                "wall_seconds": round(time.perf_counter() - started, 3),
                "events": count,
                "first_event_seconds": None if first_event is None else round(first_event, 3),
                "second_group_searchable_seconds": (
                    timeline[1]["first_event_seconds"] if len(timeline) > 1 else None
                ),
                "completion_tail_seconds": (
                    None if first_event is None
                    else round((time.perf_counter() - started) - first_event, 3)
                ),
                "peak_rss_mb": round(cpu_after["rss_mb"], 2),
                "cpu_self_seconds": round(cpu_after["self"] - cpu_before["self"], 3),
                "cpu_children_seconds": round(cpu_after["children"] - cpu_before["children"], 3),
                "errors": parser_errors,
                "timeline": timeline,
                **tools,
            }
            pair_runs.append(run)
            print(json.dumps({"pair": pair_index + 1, "policy": policy["name"], "summary": {
                k: run[k] for k in (
                    "wall_seconds", "first_event_seconds", "events",
                    "hayabusa_launches", "evtxecmd_launches",
                )
            }}), flush=True)
        pairs.append({"index": pair_index + 1, "runs": pair_runs})

    by_policy: Dict[str, List[Dict[str, Any]]] = {item["name"]: [] for item in policies}
    for pair in pairs:
        for run in pair["runs"]:
            by_policy[run["policy"]].append(run)

    def _median(values: List[Optional[float]]) -> Optional[float]:
        present = [float(v) for v in values if v is not None]
        return None if not present else round(statistics.median(present), 3)

    summary = []
    for policy in policies:
        runs = by_policy[policy["name"]]
        summary.append({
            "policy": policy["name"],
            "eager_first": policy["eager_first"],
            "target_files": policy["target_files"],
            "order": policy["order"],
            "groups": group_bytes[policy["name"]],
            "median_wall": _median([run["wall_seconds"] for run in runs]),
            "median_first_event": _median([run["first_event_seconds"] for run in runs]),
            "median_second_group_searchable": _median([run["second_group_searchable_seconds"] for run in runs]),
            "median_completion_tail": _median([run["completion_tail_seconds"] for run in runs]),
            "median_rss_mb": _median([run["peak_rss_mb"] for run in runs]),
            "median_cpu_self": _median([run["cpu_self_seconds"] for run in runs]),
            "median_cpu_children": _median([run["cpu_children_seconds"] for run in runs]),
            "hayabusa_launches": runs[0]["hayabusa_launches"] if runs else None,
            "evtxecmd_launches": runs[0]["evtxecmd_launches"] if runs else None,
            "events": runs[0]["events"] if runs else None,
        })
    report = {
        "captured_at": _utc_now(),
        "kind": "parser_latency_study",
        "pairs": int(args.pairs),
        "corpus_files": [{"name": path.name, "bytes": path.stat().st_size} for path in files],
        "group_fill_window_seconds": 0,
        "summary": summary,
        "pairs_detail": pairs,
    }
    out_path = Path(args.output) if args.output else OUT_DIR / "phase1_step4_latency_parser.json"
    _json_dump(out_path, report)
    print(json.dumps({"output": str(out_path), "summary": summary}, indent=2))
    return 0


def _rewrite_database_url(url: str, db_name: str) -> str:
    parsed = urlparse(url)
    return urlunparse(parsed._replace(path="/" + db_name))


def _drop_clickhouse(db_name: str, env: Dict[str, str]) -> None:
    import clickhouse_connect

    client = clickhouse_connect.get_client(
        host=env.get("CLICKHOUSE_HOST", "localhost"),
        port=int(env.get("CLICKHOUSE_PORT", "8123")),
        database="default",
        username=env.get("CLICKHOUSE_USER", "default"),
        password=env.get("CLICKHOUSE_PASSWORD", ""),
    )
    client.command(f"DROP DATABASE IF EXISTS `{db_name}`")


def _compact_ingest(path: Path) -> Dict[str, Any]:
    payload = json.loads(path.read_text(encoding="utf-8"))
    summary = payload.get("metric_summary") or {}
    hayabusa = summary.get("hayabusa_process") or {}
    evtxecmd = summary.get("evtxecmd_process") or {}
    return {
        "output": str(path),
        "wall_time_seconds": payload.get("wall_time_seconds"),
        "events_inserted": payload.get("events_inserted"),
        "events_per_second": payload.get("events_per_second"),
        "first_searchable": payload.get("time_to_first_current_searchable_event_seconds"),
        "first_physical": payload.get("time_to_first_physical_row_seconds"),
        "second_group_searchable": payload.get("second_group_searchable_seconds"),
        "completion_tail_seconds": payload.get("completion_tail_seconds"),
        "peak_rss_mb": payload.get("peak_rss_mb"),
        "cpu_self_seconds": payload.get("cpu_self_seconds"),
        "cpu_children_seconds": payload.get("cpu_children_seconds"),
        "erk": (payload.get("erk_after_dedup") or {}).get("sha256"),
        "hayabusa_launches": hayabusa.get("count"),
        "hayabusa_wall_seconds": round((hayabusa.get("duration_ms_total") or 0) / 1000.0, 3),
        "evtxecmd_launches": evtxecmd.get("count"),
        "evtxecmd_wall_seconds": round((evtxecmd.get("duration_ms_total") or 0) / 1000.0, 3),
        "group_timeline": payload.get("group_timeline"),
        "evtx_plan": payload.get("evtx_plan"),
        "errors": payload.get("errors") or [],
    }


def _default_ingest_summary_inputs() -> List[Path]:
    return sorted(OUT_DIR.glob("phase1_step4_latency_ingest_P*.json"))


def cmd_summarize_ingests(args: argparse.Namespace) -> int:
    inputs = [Path(item) for item in args.inputs] if args.inputs else _default_ingest_summary_inputs()
    if not inputs:
        raise SystemExit("No Phase 1 Step 4 latency ingest JSON artifacts found")
    output = Path(args.output) if args.output else OUT_DIR / "phase1_step4_latency_ingest_summary.jsonl"
    output.parent.mkdir(parents=True, exist_ok=True)
    with output.open("w", encoding="utf-8") as handle:
        for path in inputs:
            compact = _compact_ingest(path)
            compact["label"] = path.stem.replace("phase1_step4_latency_ingest_", "")
            compact["source_artifact"] = str(path)
            handle.write(json.dumps(compact, sort_keys=True, default=str) + "\n")
    print(json.dumps({"output": str(output), "records": len(inputs)}, sort_keys=True))
    return 0


def _sha256_text(value: Any) -> str:
    payload = value if isinstance(value, str) else json.dumps(value, sort_keys=True, default=str)
    return hashlib.sha256(payload.encode("utf-8")).hexdigest()


def _load_legacy_events() -> Dict[str, Dict[str, Any]]:
    path = OUT_DIR / "phase1_step4_legacy_events.jsonl"
    rows: Dict[str, Dict[str, Any]] = {}
    with path.open("r", encoding="utf-8") as handle:
        for line in handle:
            rec = json.loads(line)
            rows[rec["erk"]] = rec
    return rows


def _load_legacy_detections() -> List[Dict[str, Any]]:
    path = OUT_DIR / "phase1_step4_legacy_detections.jsonl"
    rows = []
    with path.open("r", encoding="utf-8") as handle:
        for line in handle:
            rows.append(json.loads(line))
    return rows


def _canonical_detection(det: Dict[str, Any]) -> Dict[str, Any]:
    return {
        "rule_title": det.get("rule_title") or det.get("RuleTitle") or "",
        "rule_level": det.get("rule_level") or det.get("Level") or "",
        "rule_file": det.get("rule_file") or det.get("RuleFile") or "",
        "mitre_tactics": list(det.get("mitre_tactics") or det.get("MitreTactics") or []),
        "mitre_tags": list(det.get("mitre_tags") or det.get("MitreTags") or []),
    }


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


def cmd_selected_parity(args: argparse.Namespace) -> int:
    os.environ.setdefault("SECRET_KEY", "phase1-step4-selected-parity")
    files = _corpus_files()
    from parsers.evtx_parser import EvtxECmdParser
    from utils.evtx_directory_mode import EvtxGroupMember, plan_evtx_parse_units

    legacy_events = _load_legacy_events()
    legacy_dets = _load_legacy_detections()
    members = [
        EvtxGroupMember(
            file_path=str(path),
            case_file_id=index,
            source_host=path.stem,
            source_file=path.name,
            size_bytes=path.stat().st_size,
        )
        for index, path in enumerate(files, start=1)
    ]
    units = plan_evtx_parse_units(members)
    started = time.perf_counter()
    first_event_s = None
    selected_events = []
    selected_dets = []
    cross_file = 0
    errors: List[str] = []
    warnings = 0
    for unit in units:
        parser = EvtxECmdParser(case_id=1, source_host="", case_file_id=None, case_tz="UTC")
        if unit.mode == "per_file":
            member = unit.members[0]
            parser.case_file_id = member.case_file_id
            parser.source_host = member.source_host
            event_iter = parser.parse(member.file_path)
        else:
            event_iter = parser.parse_directory_group(list(unit.members))
        for event in event_iter:
            if first_event_s is None:
                first_event_s = time.perf_counter() - started
            compact = _event_compact(event, parser)
            selected_events.append(compact)
            for det in compact["attached_detections"]:
                selected_dets.append({
                    "source_file": compact["source_file"],
                    "case_file_id": compact["case_file_id"],
                    "record_id": compact["record_id"],
                    "event_id": compact["event_id"],
                    "channel": compact["channel"],
                    "erk": compact["erk"],
                    **det,
                    "confidence": EvtxECmdParser._hayabusa_confidence(det.get("rule_level")),
                })
                expected_source = next(
                    (m.source_file for m in members if m.case_file_id == compact["case_file_id"]),
                    "",
                )
                if det and compact["source_file"] != expected_source:
                    cross_file += 1
        errors.extend(list(parser.errors))
        warnings += len(parser.warnings)
    wall = time.perf_counter() - started

    selected_by_erk = {rec["erk"]: rec for rec in selected_events}
    legacy_erk = set(legacy_events)
    selected_erk = set(selected_by_erk)
    compare_fields = [
        "source_file", "case_file_id", "source_host", "record_id", "event_id",
        "channel", "parser_version", "raw_json_sha256", "search_blob_sha256",
        "extra_fields_sha256", "rule_title", "rule_level", "rule_file",
        "mitre_tactics", "mitre_tags", "mitre_mapping_max_confidence",
        "attached_detections",
    ]
    field_diffs = 0
    examples = []
    for erk in sorted(legacy_erk & selected_erk):
        left = legacy_events[erk]
        right = selected_by_erk[erk]
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
    selected_det_keys = Counter(_det_key(row) for row in selected_dets)
    missing_dets = sum((legacy_det_keys - selected_det_keys).values())
    extra_dets = sum((selected_det_keys - legacy_det_keys).values())
    report = {
        "captured_at": _utc_now(),
        "policy": "eager_first_target_8_files_128MiB_max_32_files_512MiB",
        "selected_wall_seconds": round(wall, 3),
        "first_parsed_event_seconds": None if first_event_s is None else round(first_event_s, 3),
        "plan": [
            {
                "mode": unit.mode,
                "files": [member.source_file for member in unit.members],
                "bytes": unit.size_bytes,
            }
            for unit in units
        ],
        "legacy_events": len(legacy_events),
        "selected_events": len(selected_events),
        "legacy_detections": len(legacy_dets),
        "selected_detections": len(selected_dets),
        "erk_legacy_minus_selected": len(legacy_erk - selected_erk),
        "erk_selected_minus_legacy": len(selected_erk - legacy_erk),
        "events_with_field_differences": field_diffs,
        "field_diff_examples": examples,
        "legacy_detections_minus_selected": missing_dets,
        "selected_detections_minus_legacy": extra_dets,
        "incorrect_cross_file_attachments": cross_file,
        "parser_errors": errors,
        "parser_warnings_count": warnings,
        "event_parity": len(legacy_events) == len(selected_events)
            and not (legacy_erk - selected_erk)
            and not (selected_erk - legacy_erk)
            and field_diffs == 0,
        "detection_parity": missing_dets == 0 and extra_dets == 0 and cross_file == 0,
    }
    _json_dump(OUT_DIR / "phase1_step4_selected_parity.json", report)
    print(json.dumps(report, indent=2))
    return 0 if report["event_parity"] and report["detection_parity"] else 1


def cmd_ingest_one(args: argparse.Namespace) -> int:
    files = _corpus_files()
    env_file = Path("/etc/casescope/casescope.env")
    env = dict(os.environ)
    if env_file.exists():
        for line in env_file.read_text(encoding="utf-8").splitlines():
            line = line.strip()
            if not line or line.startswith("#") or "=" not in line:
                continue
            key, value = line.split("=", 1)
            env.setdefault(key.strip(), value.strip().strip('"').strip("'"))
    run_id = args.run_id or f"phase0a_ingest_{time.strftime('%Y%m%d%H%M%S')}_{args.label}"
    if not run_id.startswith("phase0a_ingest_"):
        raise SystemExit("run id must start with phase0a_ingest_")
    createdb = subprocess.run(
        ["sudo", "-n", "-u", "postgres", "createdb", "-O", "casescope", run_id],
        capture_output=True,
        text=True,
    )
    if createdb.returncode != 0:
        raise SystemExit(f"createdb failed: {createdb.stderr}")
    storage = Path(f"/tmp/{run_id}_storage")
    output = Path(args.output) if args.output else OUT_DIR / f"phase1_step4_latency_{args.label}.json"
    child_env = dict(env)
    child_env["DATABASE_URL"] = _rewrite_database_url(env["DATABASE_URL"], run_id)
    child_env["CLICKHOUSE_DATABASE"] = run_id
    child_env["SECRET_KEY"] = child_env.get("SECRET_KEY") or "phase1-step4-latency-ingest"
    cmd = [
        "/opt/casescope/venv/bin/python",
        str(ROOT / "scripts" / "phase0a_ingest_benchmark.py"),
        "--corpus-dir", str(CORPUS_DIR),
        "--output-json", str(output),
        "--storage-root", str(storage),
        "--batch-size", "10000",
    ]
    if args.per_file:
        pass
    else:
        cmd.append("--evtx-group-mode")
        if args.eager_first:
            cmd.append("--evtx-eager-first")
        if args.target_files:
            cmd.extend(["--evtx-target-files", str(args.target_files)])
        if args.order:
            cmd.extend(["--evtx-order", args.order])
    try:
        proc = subprocess.run(cmd, env=child_env, cwd=str(ROOT))
        rc = proc.returncode
        compact = _compact_ingest(output) if output.exists() else {"error": "no output"}
        compact["label"] = args.label
        compact["run_id"] = run_id
        compact["returncode"] = rc
        print(json.dumps(compact, sort_keys=True, default=str))
        return rc
    finally:
        subprocess.run(["sudo", "-n", "-u", "postgres", "dropdb", "--if-exists", run_id], check=False)
        try:
            _drop_clickhouse(run_id, child_env)
        except Exception as exc:
            print(f"clickhouse drop failed for {run_id}: {exc}", file=sys.stderr)
        subprocess.run(["rm", "-rf", str(storage)], check=False)


def cmd_describe(args: argparse.Namespace) -> int:
    files = _corpus_files()
    payload = {
        "captured_at": _utc_now(),
        "corpus_files": [{"name": path.name, "bytes": path.stat().st_size} for path in files],
        "policies": [
            {"policy": item["name"], "groups": _describe_plan(files, item), **item}
            for item in PARSER_POLICIES
        ],
        "group_fill_window_seconds": 0,
        "group_fill_window_needed": False,
        "reason": "queue_case_files_for_parsing already has the queued set; grouping is immediate.",
    }
    _json_dump(OUT_DIR / "phase1_step4_latency_groups.json", payload)
    print(json.dumps(payload, indent=2))
    return 0


def main() -> int:
    parser = argparse.ArgumentParser(description="Phase 1 Step 4 latency-closure study")
    sub = parser.add_subparsers(dest="cmd", required=True)
    describe = sub.add_parser("describe-groups")
    study = sub.add_parser("parser-study")
    study.add_argument("--pairs", type=int, default=2)
    study.add_argument("--policies", default="")
    study.add_argument("--output", default="")
    ingest = sub.add_parser("ingest-one")
    ingest.add_argument("--label", required=True)
    ingest.add_argument("--run-id", default="")
    ingest.add_argument("--output", default="")
    ingest.add_argument("--per-file", action="store_true")
    ingest.add_argument("--eager-first", action="store_true")
    ingest.add_argument("--target-files", type=int, default=8)
    ingest.add_argument("--order", choices=["queue", "smallest"], default="queue")
    summarize = sub.add_parser("summarize-ingests")
    summarize.add_argument("--output", default="")
    summarize.add_argument("inputs", nargs="*")
    sub.add_parser("selected-parity")
    args = parser.parse_args()
    if args.cmd == "describe-groups":
        return cmd_describe(args)
    if args.cmd == "parser-study":
        return cmd_parser_study(args)
    if args.cmd == "ingest-one":
        return cmd_ingest_one(args)
    if args.cmd == "summarize-ingests":
        return cmd_summarize_ingests(args)
    if args.cmd == "selected-parity":
        return cmd_selected_parity(args)
    raise SystemExit(f"unknown command {args.cmd}")


if __name__ == "__main__":
    raise SystemExit(main())
