"""Shared local adapter contracts and Modelfile helpers for CaseScope."""

from __future__ import annotations

from config import Config

GLOBAL_ADAPTER_VERSION = "2026.04.02.1"

GLOBAL_CASESCOPE_SYSTEM_PROMPT = """You are the shared CaseScope DFIR model.
You assist analysts across chat, case analysis, pattern matching, timeline generation,
IOC extraction, and DFIR reporting workloads.

Global rules:
- Be evidence-first and never invent facts.
- If evidence is ambiguous, preserve uncertainty explicitly.
- Prefer concise, analyst-friendly language over generic narrative filler.
- Follow the required output schema exactly when a route expects JSON.
- Treat all user-facing timeline reasoning in the case time zone supplied by the caller.
- Separate observed facts from interpretation and recommended next steps.
- Use provider or route tools only when needed and avoid unnecessary output."""

LOCAL_MODEL_TARGETS = {
    "base": Config.AI_LOCAL_BASE_MODEL,
    "global": Config.AI_LOCAL_GLOBAL_ADAPTER_MODEL,
    "pattern_matching": Config.AI_LOCAL_PATTERN_MODEL,
    "chat": Config.AI_LOCAL_CHAT_MODEL,
    "case_review": Config.AI_LOCAL_CASE_REVIEW_MODEL,
    "report": Config.AI_LOCAL_REPORT_MODEL,
    "timeline": Config.AI_LOCAL_TIMELINE_MODEL,
    "ioc_extraction": Config.AI_LOCAL_IOC_MODEL,
}

LOCAL_ROUTE_DEFAULT_STRATEGIES = {
    "pattern_matching": "task",
    "chat": "global",
    "case_review": "global",
    "report": "task",
    "timeline": "task",
    "ioc_extraction": "task",
}

TASK_ROUTE_PROMPTS = {
    "pattern_matching": (
        "Route tag: pattern_matching\n"
        "Focus on attack-pattern evidence, confidence calibration, and false-positive control."
    ),
    "chat": (
        "Route tag: chat\n"
        "Focus on concise case-aware assistance, tool discipline, and grounded investigation help."
    ),
    "case_review": (
        "Route tag: case_review\n"
        "Focus on triage, synthesis, anomaly review, investigation prioritization, and evidence-grounded case assessment."
    ),
    "report": (
        "Route tag: report\n"
        "Focus on professional DFIR prose, factual precision, and client-safe wording."
    ),
    "timeline": (
        "Route tag: timeline\n"
        "Focus on chronological clarity, event grouping, and analyst-friendly summaries."
    ),
    "ioc_extraction": (
        "Route tag: ioc_extraction\n"
        "Focus on strict JSON extraction, normalization, and zero hallucinated indicators."
    ),
}


def build_role_system_prompt(route_name: str, extra_instructions: str = "") -> str:
    """Build a shared system prompt for a CaseScope AI role."""
    route_prompt = TASK_ROUTE_PROMPTS.get(route_name, "").strip()
    sections = [GLOBAL_CASESCOPE_SYSTEM_PROMPT]
    if route_prompt:
        sections.append(route_prompt)
    if extra_instructions and extra_instructions.strip():
        sections.append(extra_instructions.strip())
    return "\n\n".join(section for section in sections if section)


def render_global_modelfile(base_model: str | None = None, adapter_path: str = "$ADAPTER_PATH") -> str:
    """Render a reusable Ollama Modelfile for the shared CaseScope adapter."""
    return (
        f"FROM {base_model or Config.AI_LOCAL_BASE_MODEL}\n"
        f"ADAPTER {adapter_path}\n"
        "PARAMETER temperature 0.2\n"
        "PARAMETER top_p 0.9\n"
        "PARAMETER num_ctx 8192\n"
        "PARAMETER num_predict 4096\n"
        f'SYSTEM """{GLOBAL_CASESCOPE_SYSTEM_PROMPT}"""\n'
    )


def render_task_modelfile(
    route_name: str,
    adapter_path: str = "$ADAPTER_PATH",
    base_model: str | None = None,
) -> str:
    """Render a route-specific Modelfile that layers on the shared prompt."""
    system_prompt = build_role_system_prompt(route_name)
    return (
        f"FROM {base_model or Config.AI_LOCAL_BASE_MODEL}\n"
        f"ADAPTER {adapter_path}\n"
        "PARAMETER temperature 0.1\n"
        "PARAMETER top_p 0.9\n"
        "PARAMETER num_ctx 8192\n"
        "PARAMETER num_predict 4096\n"
        f'SYSTEM """{system_prompt}"""\n'
    )
