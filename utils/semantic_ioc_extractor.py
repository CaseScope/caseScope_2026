"""Targeted semantic IOC extraction task planning and execution."""

from __future__ import annotations

import importlib.util
import os
from typing import Any, Callable, Dict, List

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
        "autorun",
        "run key",
        "runmru",
        "hkcu",
        "hklm",
        "hkey_current_user",
        "hkey_local_machine",
        "webshell",
        "web shell",
        "credential theft",
        "credential-theft",
        "lsass",
        "sam database",
        "ntds.dit",
    ),
}

SEMANTIC_FIELD_DEPENDENCIES = {
    "semantic_identity_and_auth": ("users", "sids", "credentials"),
    "semantic_process_relationships": ("commands", "services", "scheduled_tasks"),
    "semantic_persistence_actions": ("registry_keys",),
}

SEMANTIC_SECTION_TYPES = {
    "semantic_identity_and_auth": ("identity", "host"),
    "semantic_process_relationships": ("process",),
    "semantic_persistence_actions": ("persistence", "registry"),
}

PERSISTENCE_STRONG_TERMS = (
    "registry",
    "autorun",
    "run key",
    "runonce",
    "runmru",
    "hkcu",
    "hklm",
    "hkey_current_user",
    "hkey_local_machine",
    "webshell",
    "web shell",
    "credential theft",
    "credential-theft",
    "lsass",
    "sam database",
    "ntds.dit",
)


def _section_text(section: Dict[str, Any]) -> str:
    return f"{section.get('name', '')}\n{'-' * 12}\n{section.get('body', '')}".strip()


def _has_keyword_match(section: Dict[str, Any], keywords: tuple[str, ...]) -> bool:
    haystack = f"{section.get('name', '')}\n{section.get('body', '')}".lower()
    return any(keyword in haystack for keyword in keywords)


def _has_strong_persistence_evidence(section: Dict[str, Any]) -> bool:
    haystack = f"{section.get('name', '')}\n{section.get('body', '')}".lower()
    return any(term in haystack for term in PERSISTENCE_STRONG_TERMS)


def _section_matches_task(section: Dict[str, Any], task_name: str, keywords: tuple[str, ...]) -> bool:
    canonical_type = str(section.get("canonical_type") or "").lower()
    evidence_classes = {
        str(item or "").lower()
        for item in section.get("evidence_classes", []) or []
        if item
    }
    task_classes = set(SEMANTIC_SECTION_TYPES.get(task_name, ()))
    if evidence_classes.intersection(task_classes):
        if task_name != "semantic_persistence_actions":
            return True
        return _has_strong_persistence_evidence(section)
    if canonical_type in SEMANTIC_SECTION_TYPES.get(task_name, ()):
        if task_name != "semantic_persistence_actions":
            return True
        return _has_strong_persistence_evidence(section)
    if task_name == "semantic_persistence_actions":
        return _has_strong_persistence_evidence(section)
    return _has_keyword_match(section, keywords)


def _field_has_values(extraction: Dict[str, Any], field_names: tuple[str, ...]) -> bool:
    iocs = extraction.get("iocs", {}) or {}
    return any(bool(iocs.get(field)) for field in field_names)


def build_semantic_task_plan(
    report_text: str,
    deterministic_extraction: Dict[str, Any],
    *,
    canonical_report: Any = None,
) -> List[Dict[str, Any]]:
    """Build targeted semantic extraction tasks from normalized report sections."""
    if canonical_report is not None:
        sections = [
            {
                "name": section.source_section_name,
                "body": section.text_for_extraction(),
                "canonical_type": section.canonical_type,
                "evidence_classes": list(getattr(section, "evidence_classes", []) or []),
                "source_section_name": section.source_section_name,
                "raw_text": section.raw_text,
                "source_type": getattr(canonical_report, "source_type", ""),
                "source_product": getattr(canonical_report, "source_product", ""),
                "source_report_id": getattr(canonical_report, "source_report_id", ""),
            }
            for section in canonical_report.sections
            if section.text_for_extraction()
        ]
    else:
        sections = _report_normalizer.canonical_sections_for_report(report_text)
    if not sections:
        stripped = (report_text or "").strip()
        if stripped:
            sections = [{"name": "Full Report", "body": stripped, "canonical_type": "raw"}]

    planned_tasks: List[Dict[str, Any]] = []

    for task_name, keywords in SEMANTIC_TASK_KEYWORDS.items():
        matching_indexes = [
            idx for idx, section in enumerate(sections)
            if _section_matches_task(section, task_name, keywords)
        ]
        deterministic_signal = _field_has_values(
            deterministic_extraction,
            SEMANTIC_FIELD_DEPENDENCIES.get(task_name, ()),
        )
        if not matching_indexes and deterministic_signal:
            matching_indexes = list(range(len(sections))) or [0]
        if not matching_indexes:
            continue

        task_sections = [sections[idx] for idx in matching_indexes]
        planned_tasks.append(
            {
                "task_name": task_name,
                "prompt_template": _ioc_contract.IOC_SEMANTIC_TASK_PROMPTS[task_name],
                "sections": task_sections,
                "section_names": [section["name"] for section in task_sections],
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


EVIDENCE_ORIGINS = {"observed", "reported_finding", "remediation"}
TASK_ACTIONS = {"create", "delete", None}


def _is_non_empty_string(value: Any) -> bool:
    return isinstance(value, str) and bool(value.strip())


def _is_string_or_null(value: Any) -> bool:
    return value is None or isinstance(value, str)


def _is_string_int_or_null(value: Any) -> bool:
    return value is None or isinstance(value, (str, int))


def _item_error(path: str, message: str) -> str:
    return f"{path}: {message}"


def _validate_identity_item(path: str, item: Any, *, password_item: bool = False, created_user: bool = False) -> str | None:
    if not isinstance(item, dict):
        return _item_error(path, "item must be an object")
    if not password_item and not _is_non_empty_string(item.get("username")):
        return _item_error(path, "username must be a non-empty string")
    if password_item and item.get("username") is not None and not isinstance(item.get("username"), str):
        return _item_error(path, "username must be a string or null")
    if password_item and not _is_non_empty_string(item.get("password")):
        return _item_error(path, "password must be a non-empty string")
    if not _is_string_or_null(item.get("sid")):
        return _item_error(path, "sid must be a string or null")
    if created_user:
        if item.get("password") is not None and not isinstance(item.get("password"), str):
            return _item_error(path, "password must be a string or null")
        if "groups" in item and not isinstance(item.get("groups"), list):
            return _item_error(path, "groups must be an array")
    if not _is_non_empty_string(item.get("evidence")):
        return _item_error(path, "evidence must be a non-empty string")
    return None


def _validate_process_item(path: str, item: Any, *, item_type: str) -> str | None:
    if not isinstance(item, dict):
        return _item_error(path, "item must be an object")
    if not _is_non_empty_string(item.get("evidence")):
        return _item_error(path, "evidence must be a non-empty string")
    if item.get("evidence_origin") not in EVIDENCE_ORIGINS:
        return _item_error(path, "evidence_origin must be observed, reported_finding, or remediation")
    if item_type == "commands":
        for key in ("full_command", "executable", "parent_process", "user"):
            if not _is_string_or_null(item.get(key)):
                return _item_error(path, f"{key} must be a string or null")
        if not _is_string_int_or_null(item.get("pid")):
            return _item_error(path, "pid must be a string, integer, or null")
        if not (item.get("full_command") or item.get("executable")):
            return _item_error(path, "command item must include full_command or executable")
        return None
    if item_type == "services":
        for key in ("name", "path"):
            if not _is_string_or_null(item.get(key)):
                return _item_error(path, f"{key} must be a string or null")
        if item.get("action") not in TASK_ACTIONS:
            return _item_error(path, "action must be create, delete, or null")
        if not (item.get("name") or item.get("path")):
            return _item_error(path, "service item must include name or path")
        return None
    if item_type == "scheduled_tasks":
        for key in ("name", "path", "command"):
            if not _is_string_or_null(item.get(key)):
                return _item_error(path, f"{key} must be a string or null")
        if item.get("action") not in TASK_ACTIONS:
            return _item_error(path, "action must be create, delete, or null")
        if not (item.get("name") or item.get("path") or item.get("command")):
            return _item_error(path, "scheduled task item must include name, path, or command")
        return None
    return None


def _validate_persistence_item(path: str, item: Any, *, item_type: str) -> str | None:
    if not isinstance(item, dict):
        return _item_error(path, "item must be an object")
    if not _is_non_empty_string(item.get("evidence")):
        return _item_error(path, "evidence must be a non-empty string")
    if item.get("evidence_origin") not in EVIDENCE_ORIGINS:
        return _item_error(path, "evidence_origin must be observed, reported_finding, or remediation")
    if item_type == "registry":
        for key in ("key", "value_name", "value_data"):
            if not _is_string_or_null(item.get(key)):
                return _item_error(path, f"{key} must be a string or null")
        if item.get("action") not in TASK_ACTIONS:
            return _item_error(path, "action must be create, delete, or null")
        if not (item.get("key") or item.get("value_name") or item.get("value_data")):
            return _item_error(path, "registry item must include key, value_name, or value_data")
        return None
    if item_type == "credential_theft_indicators":
        for key in ("registry_key", "value", "data"):
            if not _is_string_or_null(item.get(key)):
                return _item_error(path, f"{key} must be a string or null")
        if not (item.get("registry_key") or item.get("value") or item.get("data")):
            return _item_error(path, "credential theft item must include registry_key, value, or data")
        return None
    if item_type == "webshells":
        if not _is_string_or_null(item.get("path")):
            return _item_error(path, "path must be a string or null")
        if not item.get("path"):
            return _item_error(path, "webshell item must include path")
        return None
    return None


def _validate_task_items(task_name: str, payload: Dict[str, Any]) -> str | None:
    if task_name == "semantic_identity_and_auth":
        for field in ("affected_users", "credential_exposure_users", "compromised_users"):
            for index, item in enumerate(payload.get(field) or []):
                error = _validate_identity_item(f"{field}[{index}]", item)
                if error:
                    return error
        for index, item in enumerate(payload.get("created_users") or []):
            error = _validate_identity_item(f"created_users[{index}]", item, created_user=True)
            if error:
                return error
        for index, item in enumerate(payload.get("passwords_observed") or []):
            error = _validate_identity_item(f"passwords_observed[{index}]", item, password_item=True)
            if error:
                return error
        return None
    if task_name == "semantic_process_relationships":
        for field in ("commands", "services", "scheduled_tasks"):
            for index, item in enumerate(payload.get(field) or []):
                error = _validate_process_item(f"{field}[{index}]", item, item_type=field)
                if error:
                    return error
        return None
    if task_name == "semantic_persistence_actions":
        for field in ("registry", "credential_theft_indicators", "webshells"):
            for index, item in enumerate(payload.get(field) or []):
                error = _validate_persistence_item(f"{field}[{index}]", item, item_type=field)
                if error:
                    return error
        return None
    return None


def _normalize_evidence_text(value: Any) -> str:
    return " ".join(str(value or "").lower().split())


def _matching_sections_for_evidence(evidence: str, sections: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
    normalized_evidence = _normalize_evidence_text(evidence)
    if not normalized_evidence:
        return []
    matches: List[Dict[str, Any]] = []
    for section in sections or []:
        body = _normalize_evidence_text(section.get("body") or section.get("raw_text") or "")
        if normalized_evidence and normalized_evidence in body:
            matches.append(section)
    return matches


def _attach_item_provenance(item: Dict[str, Any], sections: List[Dict[str, Any]]) -> None:
    evidence = item.get("evidence") or item.get("evidence_excerpt") or item.get("context") or ""
    matches = _matching_sections_for_evidence(evidence, sections)
    if not matches:
        return
    refs = []
    for section in matches:
        section_name = section.get("source_section_name") or section.get("name") or ""
        refs.append(
            {
                "source_section": section_name,
                "section": section_name,
                "canonical_section": section.get("canonical_type") or "",
                "evidence_classes": list(section.get("evidence_classes") or []),
                "source_type": section.get("source_type") or "",
                "source_product": section.get("source_product") or "",
                "source_report_id": section.get("source_report_id") or "",
                "evidence": evidence,
            }
        )
    item["evidence_refs"] = refs
    if len(refs) == 1:
        item["evidence_source_section"] = refs[0]["source_section"]
        item["canonical_section"] = refs[0]["canonical_section"]
        item["evidence_classes"] = refs[0]["evidence_classes"]


def _annotate_task_payload_provenance(task_name: str, payload: Any, sections: List[Dict[str, Any]]) -> Any:
    if not isinstance(payload, dict) or _is_canonical_payload(payload):
        return payload
    for field in _ioc_contract.IOC_SEMANTIC_TASK_SCHEMAS.get(task_name, {}):
        for item in payload.get(field) or []:
            if isinstance(item, dict):
                _attach_item_provenance(item, sections)
    return payload


def _canonical_from_task_payload(task_name: str, payload: Any) -> Dict[str, Any]:
    """Project a task-scoped semantic response into the canonical IOC shape."""
    canonical = _ioc_contract.build_empty_ioc_extraction()
    payload = payload if isinstance(payload, dict) else {}

    canonical_nested_keys = {
        "authentication_iocs",
        "process_iocs",
        "persistence_iocs",
        "network_iocs",
        "file_iocs",
        "vulnerability_iocs",
        "raw_artifacts",
        "iocs",
    }
    if canonical_nested_keys.intersection(payload.keys()):
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

    return payload


def _is_canonical_payload(payload: Any) -> bool:
    if not isinstance(payload, dict):
        return False
    canonical_nested_keys = {
        "authentication_iocs",
        "process_iocs",
        "persistence_iocs",
        "network_iocs",
        "file_iocs",
        "vulnerability_iocs",
        "raw_artifacts",
        "iocs",
    }
    return bool(canonical_nested_keys.intersection(payload.keys()))


def _validate_task_payload_schema(task_name: str, payload: Any) -> str | None:
    """Validate the task-scoped response shape before canonical coercion."""
    if not isinstance(payload, dict):
        return "semantic task response was not a JSON object"
    if _is_canonical_payload(payload):
        return None

    expected = _ioc_contract.IOC_SEMANTIC_TASK_SCHEMAS.get(task_name, {})
    if not expected:
        return None

    missing = [key for key in expected if key not in payload]
    if missing:
        return f"semantic task response missing keys: {', '.join(missing)}"

    wrong_type = [
        key for key in expected
        if key in payload and not isinstance(payload.get(key), list)
    ]
    if wrong_type:
        return f"semantic task response fields must be arrays: {', '.join(wrong_type)}"

    item_error = _validate_task_items(task_name, payload)
    if item_error:
        return f"semantic task response item validation failed: {item_error}"

    return None


def _provider_model(provider: Any, ai_result: Dict[str, Any] | None = None) -> str:
    ai_result = ai_result if isinstance(ai_result, dict) else {}
    return str(ai_result.get("model") or getattr(provider, "model", "") or "")


def _response_text(ai_result: Dict[str, Any]) -> str:
    raw = ai_result.get("raw_response")
    if raw is None:
        raw = ai_result.get("response")
    return "" if raw is None else str(raw)


def _failure_attempt_meta(
    provider: Any,
    ai_result: Dict[str, Any],
    *,
    attempt: int,
    error: str,
) -> Dict[str, Any]:
    response_text = _response_text(ai_result)
    return {
        "attempt": attempt,
        "error": error,
        "model": _provider_model(provider, ai_result),
        "finish_reason": ai_result.get("finish_reason"),
        "empty_content": not response_text.strip(),
        "json_valid_initially": ai_result.get("json_valid_initially"),
        "json_repair_applied": bool(ai_result.get("json_repair_applied") or ai_result.get("response_repaired")),
        "json_repair_reason": ai_result.get("json_repair_reason") or ai_result.get("repair_reason"),
        "json_repair_error": ai_result.get("json_repair_error"),
        "repair_succeeded": bool(ai_result.get("response_repaired")),
        "reasoning_present": bool(ai_result.get("reasoning_present")),
        "prompt_tokens": (ai_result.get("runtime", {}).get("metrics", {}) or {}).get("input_tokens", 0),
        "completion_tokens": (ai_result.get("runtime", {}).get("metrics", {}) or {}).get("output_tokens", 0),
        "elapsed_ms": (ai_result.get("runtime", {}) or {}).get("duration_ms", 0),
    }


def _retry_max_tokens(provider: Any, max_response_tokens: int) -> int:
    ceiling = 8000
    try:
        ceiling = int((provider.get_batch_config() or {}).get("max_tokens") or ceiling)
    except Exception:
        pass
    return min(ceiling, max(2000, int(max_response_tokens * 1.5)))


def _retry_prompt(prompt: str) -> str:
    return (
        "Retry this same semantic IOC task. Return one compact JSON object only. "
        "No markdown, no analysis, no prose, and no extra wrapper text. Empty result arrays are valid "
        "when supported evidence is absent.\n\n"
        f"{prompt}"
    )


def _count_semantic_candidates(payload: Dict[str, Any]) -> int:
    """Count IOC-bearing candidate lists, excluding metadata arrays."""
    if not isinstance(payload, dict):
        return 0

    def _count_list(value: Any) -> int:
        return len([item for item in _as_list(value) if item])

    total = 0
    total += _count_list(payload.get("affected_users"))

    iocs = payload.get("iocs") if isinstance(payload.get("iocs"), dict) else {}
    for field in (
        "hashes",
        "ip_addresses",
        "domains",
        "urls",
        "file_paths",
        "file_names",
        "users",
        "sids",
        "registry_keys",
        "commands",
        "credentials",
        "hostnames",
        "email_addresses",
        "services",
        "scheduled_tasks",
        "cves",
        "threat_names",
    ):
        total += _count_list(iocs.get(field))

    for section_name, fields in (
        ("network_iocs", ("ipv4", "ipv6", "domains", "urls", "cloudflare_tunnels")),
        ("file_iocs", ("hashes", "file_paths", "file_names")),
        ("process_iocs", ("commands", "services", "scheduled_tasks")),
        ("persistence_iocs", ("registry", "credential_theft_indicators")),
        ("authentication_iocs", ("credential_exposure_users", "compromised_users", "created_users", "passwords_observed")),
        ("vulnerability_iocs", ("cves", "webshells")),
        ("raw_artifacts", ("encoded_powershell", "vnc_connection_ids", "screenconnect_ids")),
    ):
        section = payload.get(section_name) if isinstance(payload.get(section_name), dict) else {}
        for field in fields:
            total += _count_list(section.get(field))

    return total


def _invoke_semantic_attempt(
    provider: Any,
    *,
    task_name: str,
    prompt: str,
    max_tokens: int,
    validate_result: Callable[[Dict[str, Any]], Any],
    privacy_context: Any,
) -> tuple[Dict[str, Any], str | None]:
    ai_result = invoke_json(
        function="ioc_extraction",
        prompt=prompt,
        system=_ioc_contract.IOC_SEMANTIC_SYSTEM_PROMPT,
        temperature=0.0,
        max_tokens=max_tokens,
        provider=provider,
        privacy_context=privacy_context,
    )
    if not ai_result.get("success"):
        return ai_result, ai_result.get("error") or "semantic provider call failed"

    validation_error = validate_result(ai_result)
    if validation_error:
        return ai_result, validation_error

    schema_error = _validate_task_payload_schema(task_name, ai_result.get("data"))
    if schema_error:
        return ai_result, schema_error

    return ai_result, None


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
    max_retries: int = 1,
    canonical_report: Any = None,
) -> Dict[str, Any]:
    """Run targeted semantic extraction prompts."""
    planned_tasks = build_semantic_task_plan(
        report_text,
        deterministic_extraction,
        canonical_report=canonical_report,
    )
    source_provenance = (
        canonical_report.provenance_summary()
        if canonical_report is not None and hasattr(canonical_report, "provenance_summary")
        else {}
    )
    normalized_results: List[Dict[str, Any]] = []
    task_failures: List[Dict[str, Any]] = []
    task_provenance: List[Dict[str, Any]] = []
    schema_reviews = 0

    for task in planned_tasks:
        task_name = task["task_name"]
        task_text = _render_task_text(task)
        first_section = (task.get("sections") or [{}])[0]
        task_chunks = _report_normalizer.chunk_sections_for_ai_with_metadata(
            task.get("sections") or [],
            max_chunk_chars,
            source_type=first_section.get("source_type") or source_provenance.get("source_type") or "",
            source_product=first_section.get("source_product") or source_provenance.get("source_product") or "",
            source_report_id=first_section.get("source_report_id") or source_provenance.get("source_report_id") or "",
        )
        for chunk_meta in task_chunks:
            chunk_label = (
                f"[Semantic task: {task_name} | sections: "
                f"{', '.join(task.get('section_names') or ['Full Report'])}]\n\n"
            )
            prompt = chunk_label + task["prompt_template"].format(chunk_meta.get("text", "").strip())
            attempt_records: List[Dict[str, Any]] = []
            ai_result: Dict[str, Any] = {}
            validation_error: str | None = None
            attempts_allowed = max(1, int(max_retries or 0) + 1)

            for attempt in range(1, attempts_allowed + 1):
                attempt_prompt = prompt if attempt == 1 else _retry_prompt(prompt)
                attempt_tokens = max_response_tokens if attempt == 1 else _retry_max_tokens(provider, max_response_tokens)
                ai_result, validation_error = _invoke_semantic_attempt(
                    provider,
                    task_name=task_name,
                    prompt=attempt_prompt,
                    max_tokens=attempt_tokens,
                    validate_result=validate_result,
                    privacy_context=privacy_context,
                )
                if not validation_error:
                    break
                attempt_records.append(
                    _failure_attempt_meta(
                        provider,
                        ai_result,
                        attempt=attempt,
                        error=str(validation_error),
                    )
                )

            retry_count = max(0, len(attempt_records) if not validation_error else len(attempt_records) - 1)
            if validation_error:
                final_attempt = attempt_records[-1] if attempt_records else {}
                task_failures.append(
                    {
                        "task": task_name,
                        "sections": list(task.get("section_names") or []),
                        "chunk": chunk_meta.get("chunk_index"),
                        "error": validation_error,
                        "model": final_attempt.get("model") or _provider_model(provider, ai_result),
                        "finish_reason": final_attempt.get("finish_reason"),
                        "empty_content": final_attempt.get("empty_content"),
                        "json_valid_initially": final_attempt.get("json_valid_initially"),
                        "json_repair_applied": final_attempt.get("json_repair_applied"),
                        "json_repair_reason": final_attempt.get("json_repair_reason"),
                        "json_repair_error": final_attempt.get("json_repair_error"),
                        "repair_succeeded": final_attempt.get("repair_succeeded"),
                        "retry_count": max(0, attempts_allowed - 1),
                        "attempts": attempt_records,
                        "final_success": False,
                    }
                )
                task_provenance.append(
                    {
                        "task": task_name,
                        "sections": list(task.get("section_names") or []),
                        "chunk": chunk_meta.get("chunk_index"),
                        "chunk_count": chunk_meta.get("chunk_count"),
                        "model": _provider_model(provider, ai_result),
                        "success": False,
                        "retry_count": max(0, attempts_allowed - 1),
                        "attempts": attempt_records,
                    }
                )
                continue

            prepared_payload, payload_meta = prepare_payload(
                provider,
                _canonical_from_task_payload(
                    task_name,
                    _annotate_task_payload_provenance(
                        task_name,
                        ai_result["data"],
                        task.get("sections") or [],
                    ),
                ),
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
            if source_provenance:
                task_section_names = set(task.get("section_names") or [])
                task_source_provenance = dict(source_provenance)
                task_source_provenance["sections"] = [
                    section
                    for section in source_provenance.get("sections", [])
                    if section.get("source_section") in task_section_names
                ] or source_provenance.get("sections", [])
                normalized["extraction_summary"]["source_provenance"] = task_source_provenance
            normalized["extraction_summary"]["response_repaired"] = bool(ai_result.get("response_repaired"))
            normalized["extraction_summary"]["repair_reason"] = ai_result.get("repair_reason")
            normalized["extraction_summary"]["json_valid_initially"] = ai_result.get("json_valid_initially")
            normalized["extraction_summary"]["json_repair_applied"] = bool(
                ai_result.get("json_repair_applied") or ai_result.get("response_repaired")
            )
            normalized["extraction_summary"]["json_repair_reason"] = (
                ai_result.get("json_repair_reason") or ai_result.get("repair_reason")
            )
            normalized["extraction_summary"]["semantic_retry_count"] = retry_count
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
                    "source_provenance": normalized["extraction_summary"].get("source_provenance", {}),
                    "chunk": chunk_meta.get("chunk_index"),
                    "chunk_count": chunk_meta.get("chunk_count"),
                    "route_filter": filter_meta,
                    "prompt_chars": len(prompt),
                    "prompt_tokens": (ai_result.get("runtime", {}).get("metrics", {}) or {}).get("input_tokens", 0),
                    "completion_tokens": (ai_result.get("runtime", {}).get("metrics", {}) or {}).get("output_tokens", 0),
                    "elapsed_ms": (ai_result.get("runtime", {}) or {}).get("duration_ms", 0),
                    "model": ai_result.get("model") or getattr(provider, "model", ""),
                    "success": True,
                    "finish_reason": ai_result.get("finish_reason"),
                    "json_valid_initially": ai_result.get("json_valid_initially"),
                    "json_repair_applied": bool(ai_result.get("json_repair_applied") or ai_result.get("response_repaired")),
                    "json_repair_reason": ai_result.get("json_repair_reason") or ai_result.get("repair_reason"),
                    "response_repaired": bool(ai_result.get("response_repaired")),
                    "retry_count": retry_count,
                    "attempts": attempt_records,
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
