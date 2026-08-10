"""Targeted semantic IOC extraction task planning and execution."""

from __future__ import annotations

import importlib.util
import os
from typing import Any, Callable, Dict, List, Set

from utils.ai.router import invoke_json


def _load_local_module(name: str, filename: str):
    spec = importlib.util.spec_from_file_location(
        name,
        os.path.join(os.path.dirname(__file__), filename),
    )
    module = importlib.util.module_from_spec(spec)
    assert spec.loader is not None
    spec.loader.exec_module(module)
    return module


_ioc_contract = _load_local_module("semantic_ioc_contract_shared", "ioc_contract.py")
_report_normalizer = _load_local_module("semantic_report_normalizer_shared", "report_normalizer.py")

SEMANTIC_TASK_KEYWORDS = {
    "semantic_identity_and_auth": (
        "user",
        "account",
        "sid",
        "identity",
        "login",
        "logon",
        "credential",
        "password",
        "auth",
        "infostealer",
        "stealer",
    ),
    "semantic_process_relationships": (
        "process",
        "execution",
        "command",
        "powershell",
        "parent",
        "child",
        "script",
        "cmd",
        "wscript",
        "rundll32",
        "service",
        "scheduled task",
        "taskname",
    ),
    "semantic_persistence_actions": (
        "registry",
        "startup",
        "persistence",
        "autorun",
        "run key",
        "webshell",
        "credential theft",
    ),
}

SEMANTIC_FIELD_DEPENDENCIES = {
    "semantic_identity_and_auth": ("users", "sids", "credentials"),
    "semantic_process_relationships": ("commands", "services", "scheduled_tasks"),
    "semantic_persistence_actions": ("registry_keys", "file_paths"),
}


def _section_text(section: Dict[str, Any]) -> str:
    return f"{section.get('name', '')}\n{'-' * 12}\n{section.get('body', '')}".strip()


def _has_keyword_match(section: Dict[str, Any], keywords: tuple[str, ...]) -> bool:
    haystack = f"{section.get('name', '')}\n{section.get('body', '')}".lower()
    return any(keyword in haystack for keyword in keywords)


def _field_has_values(extraction: Dict[str, Any], field_names: tuple[str, ...]) -> bool:
    iocs = extraction.get("iocs", {}) or {}
    return any(bool(iocs.get(field)) for field in field_names)


def build_semantic_task_plan(
    report_text: str,
    deterministic_extraction: Dict[str, Any],
) -> List[Dict[str, Any]]:
    """Build targeted semantic extraction tasks from normalized report sections."""
    sections = [
        {"name": name, "body": body}
        for name, body in _report_normalizer.split_report_sections(report_text)
    ]
    if not sections:
        stripped = (report_text or "").strip()
        if stripped:
            sections = [{"name": "Full Report", "body": stripped}]

    used_indexes: Set[int] = set()
    planned_tasks: List[Dict[str, Any]] = []

    for task_name, keywords in SEMANTIC_TASK_KEYWORDS.items():
        matching_indexes = [
            idx for idx, section in enumerate(sections)
            if _has_keyword_match(section, keywords)
        ]
        if not matching_indexes and _field_has_values(
            deterministic_extraction,
            SEMANTIC_FIELD_DEPENDENCIES.get(task_name, ()),
        ):
            continue
        if not matching_indexes:
            continue

        for idx in matching_indexes:
            used_indexes.add(idx)

        task_sections = [sections[idx] for idx in matching_indexes]
        planned_tasks.append(
            {
                "task_name": task_name,
                "prompt_template": _ioc_contract.IOC_SEMANTIC_TASK_PROMPTS[task_name],
                "sections": task_sections,
                "section_names": [section["name"] for section in task_sections],
            }
        )

    residual_sections = [
        section for idx, section in enumerate(sections)
        if idx not in used_indexes
    ]
    if residual_sections:
        planned_tasks.append(
            {
                "task_name": "semantic_residual_review",
                "prompt_template": _ioc_contract.IOC_SEMANTIC_TASK_PROMPTS["semantic_residual_review"],
                "sections": residual_sections,
                "section_names": [section["name"] for section in residual_sections],
            }
        )

    return planned_tasks


def _render_task_text(task: Dict[str, Any]) -> str:
    section_text = "\n\n".join(_section_text(section) for section in task.get("sections", []))
    return task["prompt_template"].format(section_text.strip())


def _nullable(value: Any) -> Any:
    if value is None:
        return None
    if isinstance(value, str) and not value.strip():
        return None
    return value


def _as_list(value: Any) -> List[Any]:
    if value is None:
        return []
    if isinstance(value, list):
        return value
    return [value]


def _canonical_from_task_payload(task_name: str, payload: Any) -> Dict[str, Any]:
    """Project a task-scoped semantic response into the canonical IOC shape."""
    canonical = _ioc_contract.build_empty_ioc_extraction()
    payload = payload if isinstance(payload, dict) else {}
    canonical_keys = set(_ioc_contract.build_empty_ioc_extraction().keys())
    if canonical_keys.intersection(payload.keys()):
        return payload

    if task_name == "semantic_identity_and_auth":
        canonical["affected_users"] = _as_list(payload.get("affected_users"))
        auth = canonical["authentication_iocs"]
        auth["credential_exposure_users"] = _as_list(payload.get("credential_exposure_users"))
        auth["compromised_users"] = _as_list(payload.get("compromised_users"))
        auth["created_users"] = _as_list(payload.get("created_users"))
        auth["passwords_observed"] = _as_list(payload.get("passwords_observed"))
        return canonical

    if task_name == "semantic_process_relationships":
        process = canonical["process_iocs"]
        for command in _as_list(payload.get("commands")):
            if isinstance(command, dict):
                item = dict(command)
                item["full_command"] = _nullable(
                    item.get("full_command") or item.get("command") or item.get("value")
                )
                item["executable"] = _nullable(item.get("executable"))
                item["parent_process"] = _nullable(item.get("parent_process") or item.get("parent"))
                item["user"] = _nullable(item.get("user"))
                item["pid"] = _nullable(item.get("pid"))
                process["commands"].append(item)
            elif command:
                process["commands"].append({"full_command": str(command)})
        for service in _as_list(payload.get("services")):
            if isinstance(service, dict):
                item = dict(service)
                item["name"] = _nullable(item.get("name") or item.get("value"))
                item["path"] = _nullable(item.get("path"))
                item["action"] = _nullable(item.get("action"))
                process["services"].append(item)
            elif service:
                process["services"].append({"name": str(service), "path": None, "action": None})
        for task in _as_list(payload.get("scheduled_tasks")):
            if isinstance(task, dict):
                item = dict(task)
                item["name"] = _nullable(item.get("name") or item.get("value"))
                item["path"] = _nullable(item.get("path"))
                item["command"] = _nullable(item.get("command"))
                item["action"] = _nullable(item.get("action"))
                process["scheduled_tasks"].append(item)
            elif task:
                process["scheduled_tasks"].append({"name": str(task), "path": None, "command": None})
        return canonical

    if task_name == "semantic_persistence_actions":
        persistence = canonical["persistence_iocs"]
        persistence["registry"] = _as_list(payload.get("registry"))
        persistence["credential_theft_indicators"] = _as_list(payload.get("credential_theft_indicators"))
        canonical["vulnerability_iocs"]["webshells"] = _as_list(payload.get("webshells"))
        return canonical

    if task_name == "semantic_residual_review":
        canonical.setdefault("threat_intel", {})["threat_names"] = _as_list(payload.get("threat_names"))
        return canonical

    return payload


def _count_semantic_candidates(payload: Dict[str, Any]) -> int:
    total = 0

    def _walk(value: Any) -> None:
        nonlocal total
        if isinstance(value, list):
            total += len([item for item in value if item])
            return
        if isinstance(value, dict):
            for child in value.values():
                _walk(child)

    _walk(payload)
    return total


def run_semantic_stage(
    provider: Any,
    report_text: str,
    deterministic_extraction: Dict[str, Any],
    *,
    max_chunk_chars: int,
    max_response_tokens: int,
    validate_result: Callable[[Dict[str, Any]], Any],
    prepare_payload: Callable[..., Any],
    filter_payload_for_task: Callable[[str, Dict[str, Any]], Dict[str, Any]],
    normalize_extraction: Callable[..., Dict[str, Any]],
    privacy_context: Any = None,
) -> Dict[str, Any]:
    """Run targeted semantic extraction prompts plus a residual review pass."""
    planned_tasks = build_semantic_task_plan(report_text, deterministic_extraction)
    normalized_results: List[Dict[str, Any]] = []
    task_failures: List[Dict[str, Any]] = []
    task_provenance: List[Dict[str, Any]] = []
    schema_reviews = 0

    for task in planned_tasks:
        task_name = task["task_name"]
        task_text = _render_task_text(task)
        task_chunks = _report_normalizer.chunk_report_for_ai_with_metadata(
            task_text,
            max_chunk_chars,
        )
        for chunk_meta in task_chunks:
            chunk_label = (
                f"[Semantic task: {task_name} | sections: "
                f"{', '.join(task.get('section_names') or ['Full Report'])}]\n\n"
            )
            prompt = chunk_label + chunk_meta.get("text", "")
            ai_result = invoke_json(
                function="ioc_extraction",
                prompt=prompt,
                system=_ioc_contract.IOC_SEMANTIC_SYSTEM_PROMPT,
                temperature=0.0,
                max_tokens=max_response_tokens,
                provider=provider,
                privacy_context=privacy_context,
            )
            if not ai_result.get("success"):
                task_failures.append(
                    {
                        "task": task_name,
                        "sections": list(task.get("section_names") or []),
                        "chunk": chunk_meta.get("chunk_index"),
                        "error": ai_result.get("error"),
                    }
                )
                continue

            validation_error = validate_result(ai_result)
            if validation_error:
                task_failures.append(
                    {
                        "task": task_name,
                        "sections": list(task.get("section_names") or []),
                        "chunk": chunk_meta.get("chunk_index"),
                        "error": validation_error,
                    }
                )
                continue

            prepared_payload, payload_meta = prepare_payload(
                provider,
                _canonical_from_task_payload(task_name, ai_result["data"]),
                max_tokens=max_response_tokens,
                task_name=task_name,
            )
            if payload_meta.get("review_applied"):
                schema_reviews += 1
            filter_result = filter_payload_for_task(task_name, prepared_payload)
            if isinstance(filter_result, tuple) and len(filter_result) == 2:
                filtered_payload, filter_meta = filter_result
            else:
                filtered_payload, filter_meta = filter_result, {}
            normalized = normalize_extraction(filtered_payload, report_text)
            normalized.setdefault("extraction_summary", {})
            normalized["extraction_summary"]["semantic_task"] = task_name
            normalized["extraction_summary"]["semantic_sections"] = list(task.get("section_names") or [])
            normalized["extraction_summary"]["response_repaired"] = bool(ai_result.get("response_repaired"))
            normalized["extraction_summary"]["repair_reason"] = ai_result.get("repair_reason")
            normalized["extraction_summary"]["semantic_prompt_chars"] = len(prompt)
            normalized["extraction_summary"]["semantic_candidate_count"] = _count_semantic_candidates(filtered_payload)
            route_warnings = [
                f"Removed disallowed field {field} from {task_name}"
                for field in filter_meta.get("stripped_fields", [])
            ]
            if route_warnings:
                normalized["extraction_summary"]["validation_warnings"] = route_warnings
                normalized["extraction_summary"]["route_filter"] = filter_meta
            normalized_results.append(normalized)
            task_provenance.append(
                {
                    "task": task_name,
                    "sections": list(task.get("section_names") or []),
                    "chunk": chunk_meta.get("chunk_index"),
                    "chunk_count": chunk_meta.get("chunk_count"),
                    "route_filter": filter_meta,
                    "prompt_chars": len(prompt),
                    "prompt_tokens": (ai_result.get("runtime", {}).get("metrics", {}) or {}).get("input_tokens", 0),
                    "completion_tokens": (ai_result.get("runtime", {}).get("metrics", {}) or {}).get("output_tokens", 0),
                    "elapsed_ms": (ai_result.get("runtime", {}) or {}).get("duration_ms", 0),
                    "model": ai_result.get("model") or getattr(provider, "model", ""),
                    "success": True,
                    "response_repaired": bool(ai_result.get("response_repaired")),
                    "candidate_count": normalized["extraction_summary"]["semantic_candidate_count"],
                    "accepted_candidate_count": _count_semantic_candidates(normalized),
                }
            )

    return {
        "normalized_results": normalized_results,
        "task_failures": task_failures,
        "task_provenance": task_provenance,
        "schema_reviews": schema_reviews,
        "planned_tasks": [task["task_name"] for task in planned_tasks],
    }
