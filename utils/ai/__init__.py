"""Shared AI runtime surfaces."""

from .router import (
    get_ai_runtime_metrics,
    invoke_json,
    invoke_text,
)

__all__ = [
    "get_ai_runtime_metrics",
    "invoke_json",
    "invoke_text",
]
