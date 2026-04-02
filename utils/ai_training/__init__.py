"""Committed AI training and packaging assets for CaseScope."""

from .global_adapter import (
    build_role_system_prompt,
    GLOBAL_ADAPTER_VERSION,
    GLOBAL_CASESCOPE_SYSTEM_PROMPT,
    LOCAL_MODEL_TARGETS,
    LOCAL_ROUTE_DEFAULT_STRATEGIES,
    render_global_modelfile,
    render_task_modelfile,
)

__all__ = [
    "build_role_system_prompt",
    "GLOBAL_ADAPTER_VERSION",
    "GLOBAL_CASESCOPE_SYSTEM_PROMPT",
    "LOCAL_MODEL_TARGETS",
    "LOCAL_ROUTE_DEFAULT_STRATEGIES",
    "render_global_modelfile",
    "render_task_modelfile",
]
