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
    "semantic_users_and_accounts": (
        "user",
        "account",
        "sid",
        "identity",
        "login",
        "logon",
        "credential",
        "password",
        "auth",
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
    ),
    "semantic_persistence_actions": (
        "registry",
        "startup",
        "service",
        "scheduled task",
        "persistence",
        "autorun",
        "run key",
        "webshell",
    ),
    "semantic_credentials_and_auth": (
        "credential",
        "password",
        "auth",
        "user",
        "account",
        "login",
        "logon",
        "token",
    ),
}

SEMANTIC_FIELD_DEPENDENCIES = {
    "semantic_users_and_accounts": ("users", "sids", "hostnames"),
    "semantic_process_relationships": ("commands", "services", "scheduled_tasks"),
    "semantic_persistence_actions": ("registry_keys", "file_paths"),
    "semantic_credentials_and_auth": ("credentials", "users"),
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
                system=_ioc_contract.IOC_SYSTEM_PROMPT,
                temperature=0.0,
                max_tokens=max_response_tokens,
                provider=provider,
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
                ai_result["data"],
                max_tokens=max_response_tokens,
                task_name=task_name,
            )
            if payload_meta.get("review_applied"):
                schema_reviews += 1
            filtered_payload, filter_meta = filter_payload_for_task(task_name, prepared_payload)
            normalized = normalize_extraction(filtered_payload, report_text)
            normalized.setdefault("extraction_summary", {})
            normalized["extraction_summary"]["semantic_task"] = task_name
            normalized["extraction_summary"]["semantic_sections"] = list(task.get("section_names") or [])
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
                }
            )

    return {
        "normalized_results": normalized_results,
        "task_failures": task_failures,
        "task_provenance": task_provenance,
        "schema_reviews": schema_reviews,
        "planned_tasks": [task["task_name"] for task in planned_tasks],
    }
