"""Local adapter catalog and compatibility helpers for AI routes."""

from __future__ import annotations

from typing import Any, Dict, List, Optional

ADAPTER_CATALOG_VERSION = "2026.04.04.1"

AI_FUNCTION_LABELS = {
    "pattern_matching": "Pattern Matching",
    "chat": "Chat",
    "case_review": "Case Review",
    "report": "DFIR Reports",
    "timeline": "Timelines",
    "ioc_extraction": "IOC Extraction",
}

_FUNCTION_SUFFIXES = {
    "pattern_matching": "pattern",
    "chat": "chat",
    "case_review": "review",
    "report": "report",
    "timeline": "timeline",
    "ioc_extraction": "ioc",
}

_FAMILY_DEFINITIONS = {
    "qwen2.5": {
        "label": "Qwen 2.5",
        "target_prefix": "casescope-qwen25",
        "aliases": ("qwen2.5", "qwen25", "qwen-2.5", "qwen_2.5"),
    },
    "gpt-oss": {
        "label": "GPT-OSS",
        "target_prefix": "casescope-gptoss",
        "aliases": ("gpt-oss", "gptoss", "gpt_oss", "oss-20b"),
    },
    "qwen3": {
        "label": "Qwen 3",
        "target_prefix": "casescope-qwen3",
        "aliases": ("qwen3", "qwen-3", "qwen_3"),
    },
}


def _build_builtin_local_adapters() -> List[Dict[str, Any]]:
    adapters: List[Dict[str, Any]] = []
    for family, family_meta in _FAMILY_DEFINITIONS.items():
        for function_name, suffix in _FUNCTION_SUFFIXES.items():
            adapters.append({
                "id": f"{family.replace('.', '').replace('-', '')}-{suffix}-v1",
                "label": f"CaseScope {family_meta['label']} {AI_FUNCTION_LABELS[function_name]} v1",
                "provider_scope": "local",
                "base_model_family": family,
                "supported_functions": [function_name],
                "target_name": f"{family_meta['target_prefix']}-{suffix}",
                "contract_version": ADAPTER_CATALOG_VERSION,
                "notes": (
                    f"Tuned {AI_FUNCTION_LABELS[function_name].lower()} adapter "
                    f"for the {family_meta['label']} family."
                ),
            })
    return adapters


BUILTIN_LOCAL_ADAPTERS = _build_builtin_local_adapters()


def get_model_family(model_name: str) -> str:
    """Infer a stable model family identifier from a base or adapter target."""
    lowered = (model_name or "").strip().lower()
    if not lowered:
        return ""

    for family, family_meta in _FAMILY_DEFINITIONS.items():
        if any(alias in lowered for alias in family_meta["aliases"]):
            return family
        if lowered.startswith(family_meta["target_prefix"]):
            return family

    return ""


def get_builtin_local_adapter_catalog(
    *,
    function_name: str | None = None,
    base_model_family: str | None = None,
) -> List[Dict[str, Any]]:
    """Return builtin local adapters, optionally filtered by function or family."""
    catalog = BUILTIN_LOCAL_ADAPTERS
    if function_name:
        catalog = [
            entry for entry in catalog
            if function_name in entry.get("supported_functions", [])
        ]
    if base_model_family:
        catalog = [
            entry for entry in catalog
            if entry.get("base_model_family") == base_model_family
        ]
    return [dict(entry) for entry in catalog]


def get_builtin_local_adapter_targets() -> set[str]:
    """Return all builtin adapter target names."""
    return {
        entry["target_name"].strip().lower()
        for entry in BUILTIN_LOCAL_ADAPTERS
    }


def get_builtin_local_adapter_by_target(target_name: str) -> Optional[Dict[str, Any]]:
    """Return builtin adapter metadata when the target matches a catalog entry."""
    lowered = (target_name or "").strip().lower()
    if not lowered:
        return None
    for entry in BUILTIN_LOCAL_ADAPTERS:
        if entry["target_name"].strip().lower() == lowered:
            return dict(entry)
    return None


def split_saved_adapter_targets(
    adapter_targets: Dict[str, str] | None,
) -> Dict[str, Dict[str, str]]:
    """Split saved adapter targets into builtin and custom maps for UI rendering."""
    builtin_targets = get_builtin_local_adapter_targets()
    builtin: Dict[str, str] = {}
    custom: Dict[str, str] = {}

    for function_name, target_name in (adapter_targets or {}).items():
        cleaned = (target_name or "").strip()
        if not cleaned:
            continue
        if cleaned.lower() in builtin_targets:
            builtin[function_name] = cleaned
        else:
            custom[function_name] = cleaned

    return {
        "builtin": builtin,
        "custom": custom,
    }


def resolve_local_adapter_target(
    function_name: str,
    base_model: str,
    adapter_target: str,
) -> Dict[str, Any]:
    """Validate and resolve an optional local adapter target for one function."""
    cleaned_target = (adapter_target or "").strip()
    base_family = get_model_family(base_model)

    resolution = {
        "resolved_model": (base_model or "").strip(),
        "used_adapter": False,
        "adapter_target": "",
        "base_model_family": base_family,
        "adapter_family": "",
        "source": "",
        "status": "base_only",
        "reason": "",
        "adapter": None,
    }

    if not cleaned_target:
        return resolution

    builtin = get_builtin_local_adapter_by_target(cleaned_target)
    adapter_family = (
        builtin.get("base_model_family", "")
        if builtin else get_model_family(cleaned_target)
    )

    if builtin and function_name not in builtin.get("supported_functions", []):
        resolution["status"] = "fallback_base"
        resolution["reason"] = (
            f"Adapter '{cleaned_target}' is not configured for {function_name}."
        )
        resolution["adapter"] = builtin
        resolution["adapter_family"] = adapter_family
        return resolution

    if base_family and adapter_family and base_family != adapter_family:
        resolution["status"] = "fallback_base"
        resolution["reason"] = (
            f"Adapter family '{adapter_family}' does not match base model family "
            f"'{base_family}'."
        )
        resolution["adapter"] = builtin
        resolution["adapter_family"] = adapter_family
        return resolution

    resolution.update({
        "resolved_model": cleaned_target,
        "used_adapter": True,
        "adapter_target": cleaned_target,
        "adapter_family": adapter_family,
        "source": "builtin" if builtin else "custom",
        "status": "adapter_selected",
        "reason": "Resolved builtin adapter target." if builtin else "Resolved custom adapter target.",
        "adapter": builtin,
    })
    return resolution
