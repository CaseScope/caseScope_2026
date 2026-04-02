"""Lightweight review helpers for AI-generated CaseScope content."""

from __future__ import annotations

import json
from typing import Any

from utils.ai_training import build_role_system_prompt


def _strip_markdown_fences(text: str) -> str:
    stripped = text.strip()
    if stripped.startswith("```"):
        first_newline = stripped.find("\n")
        if first_newline != -1:
            stripped = stripped[first_newline + 1:]
        if stripped.endswith("```"):
            stripped = stripped[:-3].rstrip()
    return stripped


def sanitize_review_payload(value: Any) -> Any:
    """Recursively normalize lightweight formatting artifacts in structured output."""
    if isinstance(value, dict):
        return {key: sanitize_review_payload(item) for key, item in value.items()}
    if isinstance(value, list):
        return [sanitize_review_payload(item) for item in value]
    if isinstance(value, str):
        return _strip_markdown_fences(value).strip()
    return value


def review_text_output(
    provider: Any,
    *,
    function: str,
    draft: str,
    review_focus: str,
    max_tokens: int = 2000,
) -> str:
    """Run a lightweight second-pass review over analyst-facing text output."""
    if not draft or draft.startswith("[Error generating content:"):
        return draft

    review_prompt = (
        "Review and lightly revise the following CaseScope draft.\n\n"
        "Requirements:\n"
        "- Preserve the same facts, scope, and structure unless a claim is unsupported.\n"
        "- Remove markdown, filler, unsupported certainty, and duplicated statements.\n"
        "- Keep the writing concise, analyst-friendly, and evidence-grounded.\n"
        "- Return only the revised draft text.\n\n"
        f"DRAFT:\n{draft}"
    )
    system_prompt = build_role_system_prompt(function, review_focus)

    try:
        result = provider.generate(
            prompt=review_prompt,
            system=system_prompt,
            temperature=0.0,
            max_tokens=max_tokens,
        )
    except Exception:
        return draft

    if not result.get("success"):
        return draft

    reviewed = (result.get("response") or "").strip()
    if not reviewed:
        return draft
    return reviewed


def review_structured_output(
    provider: Any,
    *,
    function: str,
    payload: dict[str, Any],
    review_focus: str,
    max_tokens: int = 3000,
) -> dict[str, Any]:
    """Run a low-temperature review pass over structured JSON output."""
    if not payload:
        return payload

    review_prompt = (
        "Review the following structured CaseScope output.\n\n"
        "Requirements:\n"
        "- Preserve the same schema and top-level keys.\n"
        "- Remove unsupported certainty, markdown, or filler.\n"
        "- Keep the content evidence-grounded and concise.\n"
        "- Return valid JSON only.\n\n"
        f"JSON:\n{json.dumps(payload, ensure_ascii=True)}"
    )
    system_prompt = build_role_system_prompt(function, review_focus)

    try:
        result = provider.generate_json(
            prompt=review_prompt,
            system=system_prompt,
            temperature=0.0,
            max_tokens=max_tokens,
        )
    except Exception:
        return sanitize_review_payload(payload)

    if not result.get("success") or not result.get("data"):
        return sanitize_review_payload(payload)
    return sanitize_review_payload(result["data"])
