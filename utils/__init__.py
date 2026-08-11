"""CaseScope Utilities.

Package exports stay lazy so administrative modules can import submodules like
``utils.clickhouse`` without pulling in Flask-only configuration at import time.
"""

__all__ = [
    'admin_required',
    'analyst_required',
    'can_delete',
    'case_access_required',
    'clickhouse',
]


def __getattr__(name):
    if name in {'admin_required', 'analyst_required', 'can_delete', 'case_access_required'}:
        from utils.decorators import admin_required, analyst_required, can_delete, case_access_required

        exports = {
            'admin_required': admin_required,
            'analyst_required': analyst_required,
            'can_delete': can_delete,
            'case_access_required': case_access_required,
        }
        return exports[name]
    if name == 'clickhouse':
        from importlib import import_module

        return import_module('utils.clickhouse')
    raise AttributeError(f"module 'utils' has no attribute {name!r}")
