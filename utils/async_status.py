"""Shared envelope helpers for async task status routes."""

from typing import Any, Callable, Dict, Optional, Tuple


def _canonical_state(raw_state: str) -> str:
    state = (raw_state or "").upper()
    if state == "PENDING":
        return "pending"
    if state in {"PROGRESS", "PROCESSING", "STARTED"}:
        return "processing"
    if state == "SUCCESS":
        return "completed"
    if state == "FAILURE":
        return "failed"
    return state.lower() if state else "unknown"


def build_async_status_response(
    task: Any,
    *,
    task_id: Optional[str] = None,
    pending_builder: Optional[Callable[[Any], Dict[str, Any]]] = None,
    progress_builder: Optional[Callable[[Any], Dict[str, Any]]] = None,
    success_builder: Optional[Callable[[Any], Dict[str, Any]]] = None,
    failure_builder: Optional[Callable[[Any], Dict[str, Any]]] = None,
    other_builder: Optional[Callable[[Any], Dict[str, Any]]] = None,
) -> Tuple[Dict[str, Any], int]:
    """Return one canonical async-status envelope plus route-specific fields."""
    state = _canonical_state(getattr(task, "state", ""))
    ready = bool(task.ready()) if hasattr(task, "ready") else state in {"completed", "failed"}
    payload: Dict[str, Any] = {
        "success": True,
        "state": state,
        "ready": ready,
    }
    if task_id is not None:
        payload["task_id"] = task_id

    if state == "pending":
        extra = pending_builder(task) if pending_builder else {}
    elif state == "processing":
        extra = progress_builder(task) if progress_builder else {}
    elif state == "completed":
        extra = success_builder(task) if success_builder else {}
    elif state == "failed":
        extra = failure_builder(task) if failure_builder else {}
    else:
        extra = other_builder(task) if other_builder else {}

    if extra:
        payload.update(extra)
    return payload, 200
