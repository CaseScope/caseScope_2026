"""Thin API compatibility helper exports for Phase 3 route decomposition."""

from routes import hunting_query_helpers, route_helpers


def _remember_task_access(*args, **kwargs):
    return route_helpers._remember_task_access(*args, **kwargs)


def _task_access_allowed(*args, **kwargs):
    return route_helpers._task_access_allowed(*args, **kwargs)


def _build_sigma_alert_condition(*args, **kwargs):
    return hunting_query_helpers._build_sigma_alert_condition(*args, **kwargs)


