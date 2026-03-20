"""Evaluate IOC extraction models against the curated holdout set."""

import importlib.util
import json
import os
import urllib.error
import urllib.request
from typing import Dict, List, Tuple

_ioc_contract_spec = importlib.util.spec_from_file_location(
    "ioc_contract_shared",
    os.path.join(os.path.dirname(__file__), "ioc_contract.py"),
)
_ioc_contract = importlib.util.module_from_spec(_ioc_contract_spec)
_ioc_contract_spec.loader.exec_module(_ioc_contract)


def _load_jsonl(path: str) -> List[Dict]:
    rows = []
    with open(path, "r", encoding="utf-8") as handle:
        for line in handle:
            line = line.strip()
            if line:
                rows.append(json.loads(line))
    return rows


def _required_top_level_keys() -> List[str]:
    return sorted(_ioc_contract.build_empty_ioc_extraction().keys())


def _clean_text(value) -> str:
    """Normalize optional JSON values into comparable lowercase strings."""
    if value is None:
        return ""
    return str(value).strip().lower()


def _as_list(value) -> List:
    """Normalize optional JSON values into iterable lists."""
    if value is None:
        return []
    if isinstance(value, list):
        return value
    return [value]


def _as_dict(value) -> Dict:
    """Return dict values as-is and collapse invalid section shapes."""
    return value if isinstance(value, dict) else {}


def _flatten_items(extraction: Dict) -> Dict[str, set]:
    flat = {
        "affected_hosts": set(),
        "affected_users": set(),
        "ipv4": set(),
        "domains": set(),
        "urls": set(),
        "hashes": set(),
        "file_paths": set(),
        "file_names": set(),
        "commands": set(),
        "registry": set(),
        "services": set(),
        "scheduled_tasks": set(),
        "cves": set(),
        "screenconnect_ids": set(),
    }

    extraction = _as_dict(extraction)
    network_iocs = _as_dict(extraction.get("network_iocs", {}))
    file_iocs = _as_dict(extraction.get("file_iocs", {}))
    process_iocs = _as_dict(extraction.get("process_iocs", {}))
    persistence_iocs = _as_dict(extraction.get("persistence_iocs", {}))
    vulnerability_iocs = _as_dict(extraction.get("vulnerability_iocs", {}))
    raw_artifacts = _as_dict(extraction.get("raw_artifacts", {}))

    for host in _as_list(extraction.get("affected_hosts", [])):
        value = _clean_text(host)
        if value:
            flat["affected_hosts"].add(value)

    for user in _as_list(extraction.get("affected_users", [])):
        if isinstance(user, dict):
            username = _clean_text(user.get("username", ""))
            sid = _clean_text(user.get("sid", ""))
            if username or sid:
                flat["affected_users"].add(f"{username}|{sid}")

    for item in _as_list(network_iocs.get("ipv4", [])):
        value = _clean_text(item.get("value", "")) if isinstance(item, dict) else _clean_text(item)
        if value:
            flat["ipv4"].add(value)

    for key in ("domains", "urls"):
        for item in _as_list(network_iocs.get(key, [])):
            value = _clean_text(item.get("value", "")) if isinstance(item, dict) else _clean_text(item)
            if value:
                flat[key].add(value)

    for item in _as_list(file_iocs.get("hashes", [])):
        if isinstance(item, dict):
            value = _clean_text(item.get("value", ""))
            htype = _clean_text(item.get("type", ""))
            if value:
                flat["hashes"].add(f"{htype}:{value}")
        else:
            value = _clean_text(item)
            if value:
                flat["hashes"].add(value)

    for item in _as_list(file_iocs.get("file_paths", [])):
        value = _clean_text(item.get("value", "")) if isinstance(item, dict) else _clean_text(item)
        if value:
            flat["file_paths"].add(value)

    for item in _as_list(file_iocs.get("file_names", [])):
        value = _clean_text(item)
        if value:
            flat["file_names"].add(value)

    for item in _as_list(process_iocs.get("commands", [])):
        if isinstance(item, dict):
            value = _clean_text(item.get("full_command", ""))
        else:
            value = _clean_text(item)
        if value:
            flat["commands"].add(value)

    for item in _as_list(persistence_iocs.get("registry", [])):
        if isinstance(item, dict):
            key = _clean_text(item.get("key", ""))
            value_name = _clean_text(item.get("value_name", ""))
            if key or value_name:
                flat["registry"].add(f"{key}|{value_name}")
        else:
            value = _clean_text(item)
            if value:
                flat["registry"].add(value)

    for item in _as_list(process_iocs.get("services", [])):
        if isinstance(item, dict):
            value = _clean_text(item.get("name", ""))
        else:
            value = _clean_text(item)
        if value:
            flat["services"].add(value)

    for item in _as_list(process_iocs.get("scheduled_tasks", [])):
        if isinstance(item, dict):
            value = _clean_text(item.get("name", ""))
        else:
            value = _clean_text(item)
        if value:
            flat["scheduled_tasks"].add(value)

    for item in _as_list(vulnerability_iocs.get("cves", [])):
        value = _clean_text(item)
        if value:
            flat["cves"].add(value)

    for item in _as_list(raw_artifacts.get("screenconnect_ids", [])):
        value = _clean_text(item)
        if value:
            flat["screenconnect_ids"].add(value)

    return flat


def _precision_recall_f1(expected: set, actual: set) -> Dict[str, float]:
    tp = len(expected & actual)
    fp = len(actual - expected)
    fn = len(expected - actual)
    precision = tp / (tp + fp) if tp + fp else 1.0
    recall = tp / (tp + fn) if tp + fn else 1.0
    f1 = (2 * precision * recall / (precision + recall)) if precision + recall else 0.0
    return {
        "expected": len(expected),
        "actual": len(actual),
        "tp": tp,
        "fp": fp,
        "fn": fn,
        "precision": round(precision, 4),
        "recall": round(recall, 4),
        "f1": round(f1, 4),
    }


def _schema_metrics(extraction: Dict) -> Dict[str, bool]:
    keys = set(extraction.keys())
    required = set(_required_top_level_keys())
    return {
        "top_level_only": keys.issubset(_ioc_contract.IOC_ALLOWED_TOP_LEVEL_KEYS),
        "required_keys_present": required.issubset(keys),
    }


def _call_ollama(model: str, system_prompt: str, user_prompt: str, api_url: str) -> Tuple[bool, Dict]:
    payload = json.dumps(
        {
            "model": model,
            "system": system_prompt,
            "prompt": user_prompt,
            "stream": False,
            "format": "json",
            "options": {"temperature": 0},
        }
    ).encode("utf-8")
    request = urllib.request.Request(
        api_url.rstrip("/") + "/api/generate",
        data=payload,
        headers={"Content-Type": "application/json"},
        method="POST",
    )
    try:
        with urllib.request.urlopen(request, timeout=180) as response:
            body = json.loads(response.read().decode("utf-8"))
    except urllib.error.HTTPError as exc:
        return False, {"error": f"http {exc.code}: {exc.read().decode('utf-8', errors='replace')}"}
    except Exception as exc:  # noqa: BLE001
        return False, {"error": str(exc)}

    raw = body.get("response", "")
    if not raw:
        return False, {"error": "empty response"}

    try:
        return True, json.loads(raw)
    except json.JSONDecodeError as exc:
        return False, {"error": f"invalid json: {exc}", "raw_response": raw[:500]}


def evaluate_ollama_model(model: str, dataset_path: str, api_url: str = "http://127.0.0.1:11434") -> Dict:
    rows = _load_jsonl(dataset_path)
    per_type_totals: Dict[str, Dict[str, float]] = {}
    sample_results = []
    valid_json_count = 0
    schema_ok_count = 0

    for row in rows:
        conversations = row.get("conversations", [])
        system_prompt = next((item["value"] for item in conversations if item.get("from") == "system"), "")
        user_prompt = next((item["value"] for item in conversations if item.get("from") == "human"), "")
        expected = json.loads(next(item["value"] for item in conversations if item.get("from") == "gpt"))

        success, actual_or_error = _call_ollama(model, system_prompt, user_prompt, api_url)
        if success:
            valid_json_count += 1
            schema_metrics = _schema_metrics(actual_or_error)
            if schema_metrics["top_level_only"] and schema_metrics["required_keys_present"]:
                schema_ok_count += 1
            expected_flat = _flatten_items(expected)
            actual_flat = _flatten_items(actual_or_error)
            type_scores = {
                key: _precision_recall_f1(expected_flat[key], actual_flat[key])
                for key in expected_flat.keys()
            }
            sample_results.append(
                {
                    "ok": True,
                    "schema": schema_metrics,
                    "type_scores": type_scores,
                }
            )
            for key, score in type_scores.items():
                totals = per_type_totals.setdefault(
                    key,
                    {"expected": 0, "actual": 0, "tp": 0, "fp": 0, "fn": 0},
                )
                for metric in ("expected", "actual", "tp", "fp", "fn"):
                    totals[metric] += score[metric]
        else:
            sample_results.append({"ok": False, "error": actual_or_error})

    per_type_metrics = {}
    for key, totals in per_type_totals.items():
        precision = totals["tp"] / (totals["tp"] + totals["fp"]) if totals["tp"] + totals["fp"] else 1.0
        recall = totals["tp"] / (totals["tp"] + totals["fn"]) if totals["tp"] + totals["fn"] else 1.0
        f1 = (2 * precision * recall / (precision + recall)) if precision + recall else 0.0
        per_type_metrics[key] = {
            **totals,
            "precision": round(precision, 4),
            "recall": round(recall, 4),
            "f1": round(f1, 4),
        }

    macro_f1_values = [metrics["f1"] for metrics in per_type_metrics.values()]
    macro_f1 = round(sum(macro_f1_values) / len(macro_f1_values), 4) if macro_f1_values else 0.0
    return {
        "model": model,
        "samples": len(rows),
        "valid_json_rate": round(valid_json_count / len(rows), 4) if rows else 0.0,
        "schema_compliance_rate": round(schema_ok_count / len(rows), 4) if rows else 0.0,
        "macro_f1": macro_f1,
        "per_type_metrics": per_type_metrics,
        "failures": [item for item in sample_results if not item["ok"]],
    }
