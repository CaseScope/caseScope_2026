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


def canonical_progress_payload(
    meta: Optional[Dict[str, Any]],
    *,
    default_percent: int = 0,
    default_message: str = "",
) -> Dict[str, Any]:
    """Normalize task progress metadata into one AI/RAG progress contract."""
    meta = meta if isinstance(meta, dict) else {}
    percent = meta.get("percent", meta.get("progress", default_percent))
    try:
        percent = max(0, min(100, int(percent or 0)))
    except (TypeError, ValueError):
        percent = default_percent

    stage = meta.get("stage") or meta.get("phase") or meta.get("current_phase") or ""
    message = meta.get("message") or meta.get("status") or meta.get("status_message") or default_message
    current = meta.get("current") or meta.get("current_item") or meta.get("current_index")
    total = meta.get("total") or meta.get("total_items") or meta.get("patterns_total") or meta.get("total_events")
    warnings = meta.get("warning_count") or meta.get("warnings") or 0
    if isinstance(warnings, list):
        warnings = len(warnings)

    return {
        "progress": percent,
        "percent": percent,
        "stage": stage,
        "stage_name": stage,
        "status": "processing",
        "message": message,
        "current_item": meta.get("current_item") or meta.get("item") or "",
        "current": current,
        "total": total,
        "total_items": total,
        "warning_count": warnings,
        "partial_results_available": bool(meta.get("partial_results_available", False)),
        "meta": meta,
    }


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
        extra = pending_builder(task) if pending_builder else canonical_progress_payload(
            {},
            default_percent=0,
            default_message="Waiting to start...",
        )
    elif state == "processing":
        extra = progress_builder(task) if progress_builder else canonical_progress_payload(
            getattr(task, "info", None),
            default_percent=0,
            default_message="Processing...",
        )
    elif state == "completed":
        extra = success_builder(task) if success_builder else {
            "progress": 100,
            "percent": 100,
            "status": "completed",
            "result": getattr(task, "result", None),
        }
    elif state == "failed":
        extra = failure_builder(task) if failure_builder else {
            "progress": 100,
            "percent": 100,
            "status": "failed",
            "error": str(getattr(task, "info", "")),
        }
    else:
        extra = other_builder(task) if other_builder else {}

    if extra:
        payload.update(extra)
    return payload, 200
