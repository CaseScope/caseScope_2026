"""Evaluate IOC extraction models against the curated holdout set."""

import importlib.util
import json
import os
import urllib.error
import urllib.request
from collections import defaultdict
from typing import Any, Dict, List, Tuple

_ioc_contract_spec = importlib.util.spec_from_file_location(
    "ioc_contract_shared",
    os.path.join(os.path.dirname(__file__), "ioc_contract.py"),
)
_ioc_contract = importlib.util.module_from_spec(_ioc_contract_spec)
_ioc_contract_spec.loader.exec_module(_ioc_contract)

_ioc_extractor_spec = importlib.util.spec_from_file_location(
    "ioc_extractor_runtime_eval",
    os.path.join(os.path.dirname(__file__), "ioc_extractor.py"),
)
_ioc_extractor = importlib.util.module_from_spec(_ioc_extractor_spec)
_ioc_extractor_spec.loader.exec_module(_ioc_extractor)


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


class _RuntimeEvalProvider:
    """Minimal provider shim that mirrors local runtime JSON calls."""

    def __init__(self, model: str, api_url: str):
        self.model = model
        self.api_url = api_url

    def get_batch_config(self) -> Dict[str, int]:
        try:
            ai_provider_spec = importlib.util.spec_from_file_location(
                "ioc_eval_ai_providers",
                os.path.join(os.path.dirname(__file__), "ai_providers.py"),
            )
            ai_providers = importlib.util.module_from_spec(ai_provider_spec)
            ai_provider_spec.loader.exec_module(ai_providers)
            return ai_providers.get_model_profile(self.model)
        except Exception:  # noqa: BLE001
            return {"context_window": 16384, "max_tokens": 4000}

    def generate_json(
        self,
        *,
        prompt: str,
        system: str = None,
        temperature: float = 0.0,
        max_tokens: int = 4000,
    ) -> Dict:
        payload = json.dumps(
            {
                "model": self.model,
                "system": system,
                "prompt": prompt,
                "stream": False,
                "format": "json",
                "options": {
                    "temperature": temperature,
                    "num_predict": max_tokens,
                },
            }
        ).encode("utf-8")
        request = urllib.request.Request(
            self.api_url.rstrip("/") + "/api/generate",
            data=payload,
            headers={"Content-Type": "application/json"},
            method="POST",
        )
        try:
            with urllib.request.urlopen(request, timeout=180) as response:
                body = json.loads(response.read().decode("utf-8"))
        except urllib.error.HTTPError as exc:
            return {"success": False, "error": f"http {exc.code}: {exc.read().decode('utf-8', errors='replace')}"}
        except Exception as exc:  # noqa: BLE001
            return {"success": False, "error": str(exc)}

        raw = body.get("response", "")
        if not raw:
            return {"success": False, "error": "empty response"}
        try:
            return {"success": True, "data": json.loads(raw), "model": body.get("model", self.model)}
        except json.JSONDecodeError as exc:
            return {"success": False, "error": f"invalid json: {exc}", "raw_response": raw[:500]}


def _runtime_extraction_to_contract(extraction: Dict) -> Dict:
    """Convert the live normalized extraction shape into the contract schema."""
    contract = _ioc_contract.build_empty_ioc_extraction()
    summary = extraction.get("extraction_summary", {}) or {}
    iocs = extraction.get("iocs", {}) or {}
    raw_artifacts = extraction.get("raw_artifacts", {}) or {}

    contract["affected_hosts"] = list(summary.get("affected_hosts", []) or [])
    contract["affected_users"] = list(summary.get("affected_users", []) or [])

    for item in iocs.get("ip_addresses", []):
        if not isinstance(item, dict):
            continue
        target = "ipv6" if item.get("type") == "ipv6" or ":" in str(item.get("value", "")) else "ipv4"
        contract["network_iocs"][target].append(
            {
                "value": item.get("value", ""),
                "port": item.get("port"),
                "context": item.get("context", ""),
            }
        )
    contract["network_iocs"]["domains"] = [
        item if isinstance(item, dict) else {"value": str(item), "context": ""}
        for item in iocs.get("domains", [])
    ]
    contract["network_iocs"]["urls"] = [
        item if isinstance(item, dict) else {"value": str(item), "context": ""}
        for item in iocs.get("urls", [])
    ]

    contract["file_iocs"]["hashes"] = [
        item if isinstance(item, dict) else {"value": str(item), "type": "sha256", "filename": "", "context": ""}
        for item in iocs.get("hashes", [])
    ]
    contract["file_iocs"]["file_paths"] = [
        item if isinstance(item, dict) else {"value": str(item), "context": ""}
        for item in iocs.get("file_paths", [])
    ]
    contract["file_iocs"]["file_names"] = list(iocs.get("file_names", []) or [])

    contract["process_iocs"]["commands"] = [
        {
            "full_command": item.get("value", ""),
            "executable": item.get("executable", ""),
            "parent_process": item.get("parent", ""),
            "user": item.get("user", ""),
            "pid": item.get("pid", ""),
        }
        for item in iocs.get("commands", [])
        if isinstance(item, dict)
    ]
    contract["process_iocs"]["services"] = [
        item if isinstance(item, dict) else {"name": str(item), "path": "", "action": ""}
        for item in iocs.get("services", [])
    ]
    contract["process_iocs"]["scheduled_tasks"] = [
        item if isinstance(item, dict) else {"name": str(item), "path": "", "command": ""}
        for item in iocs.get("scheduled_tasks", [])
    ]

    contract["persistence_iocs"]["registry"] = [
        {
            "key": item.get("value", ""),
            "value_name": item.get("value_name", ""),
            "value_data": item.get("value_data", ""),
            "action": item.get("action", ""),
        }
        for item in iocs.get("registry_keys", [])
        if isinstance(item, dict)
    ]

    contract["authentication_iocs"]["compromised_users"] = [
        {
            "username": item.get("value", ""),
            "sid": item.get("sid", ""),
        }
        for item in iocs.get("users", [])
        if isinstance(item, dict)
    ]
    contract["authentication_iocs"]["passwords_observed"] = [
        {
            "username": item.get("username", ""),
            "password": item.get("value", ""),
        }
        for item in iocs.get("credentials", [])
        if isinstance(item, dict)
    ]

    contract["vulnerability_iocs"]["cves"] = list(iocs.get("cves", []) or [])
    contract["raw_artifacts"]["encoded_powershell"] = list(raw_artifacts.get("encoded_powershell", []) or [])
    contract["raw_artifacts"]["vnc_connection_ids"] = list(raw_artifacts.get("vnc_connection_ids", []) or [])
    contract["raw_artifacts"]["screenconnect_ids"] = list(raw_artifacts.get("screenconnect_ids", []) or [])
    return contract


def _run_runtime_extraction(
    report_text: str,
    model: str,
    api_url: str,
    pipeline_mode: str = "semantic",
) -> Tuple[bool, Dict]:
    """Run the live deterministic + semantic extraction flow for evaluation."""
    provider = _RuntimeEvalProvider(model, api_url)
    extraction, _used_ai = _ioc_extractor.run_ioc_pipeline_with_provider(  # noqa: SLF001
        report_text,
        provider,
        pipeline_mode=pipeline_mode,
        model_name=model,
    )
    return True, _runtime_extraction_to_contract(extraction)


def _sample_metadata(row: Dict[str, Any]) -> Dict[str, str]:
    return {
        "vendor": str(row.get("vendor") or "unknown"),
        "source_type": str(row.get("source_type") or "unknown"),
        "report_id": str(row.get("report_id") or ""),
    }


def _summarize_sample_scores(sample_results: List[Dict[str, Any]]) -> Dict[str, Any]:
    grouped: Dict[Tuple[str, str], Dict[str, Any]] = defaultdict(
        lambda: {"samples": 0, "ok": 0, "macro_f1_total": 0.0}
    )
    for sample in sample_results:
        metadata = sample.get("metadata", {})
        key = (metadata.get("vendor", "unknown"), metadata.get("source_type", "unknown"))
        grouped[key]["samples"] += 1
        if sample.get("ok"):
            grouped[key]["ok"] += 1
            type_scores = sample.get("type_scores", {})
            if type_scores:
                grouped[key]["macro_f1_total"] += (
                    sum(score["f1"] for score in type_scores.values()) / len(type_scores)
                )

    breakdown = []
    for (vendor, source_type), values in sorted(grouped.items()):
        ok = values["ok"]
        breakdown.append(
            {
                "vendor": vendor,
                "source_type": source_type,
                "samples": values["samples"],
                "success_rate": round(ok / values["samples"], 4) if values["samples"] else 0.0,
                "macro_f1": round(values["macro_f1_total"] / ok, 4) if ok else 0.0,
            }
        )
    return {"vendor_source_breakdown": breakdown}


def evaluate_ollama_model(
    model: str,
    dataset_path: str,
    api_url: str = "http://127.0.0.1:11434",
    pipeline_mode: str = "semantic",
) -> Dict:
    rows = _load_jsonl(dataset_path)
    per_type_totals: Dict[str, Dict[str, float]] = {}
    sample_results = []
    valid_json_count = 0
    schema_ok_count = 0

    for row in rows:
        conversations = row.get("conversations", [])
        expected = row.get("expected_extraction")
        if expected is None:
            expected = json.loads(next(item["value"] for item in conversations if item.get("from") == "gpt"))

        report_text = row.get("report_text", "")
        if report_text:
            success, actual_or_error = _run_runtime_extraction(report_text, model, api_url, pipeline_mode=pipeline_mode)
        else:
            system_prompt = next((item["value"] for item in conversations if item.get("from") == "system"), "")
            user_prompt = next((item["value"] for item in conversations if item.get("from") == "human"), "")
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
                    "metadata": _sample_metadata(row),
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
            sample_results.append({"ok": False, "metadata": _sample_metadata(row), "error": actual_or_error})

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
    result = {
        "model": model,
        "pipeline_mode": pipeline_mode,
        "samples": len(rows),
        "valid_json_rate": round(valid_json_count / len(rows), 4) if rows else 0.0,
        "schema_compliance_rate": round(schema_ok_count / len(rows), 4) if rows else 0.0,
        "macro_f1": macro_f1,
        "per_type_metrics": per_type_metrics,
        "failures": [item for item in sample_results if not item["ok"]],
    }
    result.update(_summarize_sample_scores(sample_results))
    return result


def evaluate_model_matrix(
    models: List[str],
    dataset_path: str,
    api_url: str = "http://127.0.0.1:11434",
    pipeline_mode: str = "semantic",
) -> Dict[str, Any]:
    """Run the same dataset through multiple models for side-by-side comparison."""
    return {
        "pipeline_mode": pipeline_mode,
        "dataset_path": dataset_path,
        "results": [
            evaluate_ollama_model(
                model,
                dataset_path,
                api_url=api_url,
                pipeline_mode=pipeline_mode,
            )
            for model in models
        ],
    }
