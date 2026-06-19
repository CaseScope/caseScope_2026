"""sys.modules isolation helpers for unittest-based tests."""

from __future__ import annotations

import sys
import unittest
from types import ModuleType
from typing import Dict


_MISSING = object()
_ORIGINAL_TESTCASE_RUN = None
_ORIGINAL_FIND_TEST_PATH = None

_SENSITIVE_ROOTS = (
    "celery",
    "config",
    "flask_login",
    "models",
    "pipeline",
    "routes",
    "sqlalchemy",
    "tasks",
    "utils",
)


def snapshot_sys_modules() -> Dict[str, ModuleType]:
    """Capture the current import table."""

    return dict(sys.modules)


def restore_sys_modules(snapshot: Dict[str, ModuleType]) -> None:
    """Restore fake/sensitive sys.modules mutations to a prior snapshot."""

    for name in list(sys.modules):
        if name not in snapshot and _should_remove_added_module(name, sys.modules[name]):
            sys.modules.pop(name, None)

    for name, module in snapshot.items():
        current = sys.modules.get(name)
        if current is not module and _should_restore_changed_module(name, current, module):
            sys.modules[name] = module


def _is_sensitive_name(name: str) -> bool:
    return name in _SENSITIVE_ROOTS or name.startswith(tuple(f"{root}." for root in _SENSITIVE_ROOTS))


def _is_fake_module(module) -> bool:
    if module is None:
        return True
    if not isinstance(module, ModuleType):
        return True
    return getattr(module, "__file__", None) is None


def _should_remove_added_module(name: str, module) -> bool:
    return _is_sensitive_name(name) and _is_fake_module(module)


def _should_restore_changed_module(name: str, current, previous) -> bool:
    if name in ("tests", "tests._support", "tests._support.isolation", "tests._support.stubs"):
        return False
    return _is_sensitive_name(name) and (_is_fake_module(current) or _is_fake_module(previous))


def install_unittest_sys_modules_isolation() -> None:
    """Restore sys.modules after each TestCase method.

    Several legacy tests install whole-package fakes into sys.modules. Keeping
    cleanup at the TestCase boundary prevents those fakes from leaking into
    later tests while preserving normal module-level imports during collection.
    """

    global _ORIGINAL_TESTCASE_RUN
    if _ORIGINAL_TESTCASE_RUN is not None:
        return

    _ORIGINAL_TESTCASE_RUN = unittest.TestCase.run

    def isolated_run(self, result=None):
        snapshot = snapshot_sys_modules()
        try:
            return _ORIGINAL_TESTCASE_RUN(self, result)
        finally:
            restore_sys_modules(snapshot)

    unittest.TestCase.run = isolated_run


def install_discovery_sys_modules_isolation() -> None:
    """Restore sys.modules after each test module is imported by discovery."""

    global _ORIGINAL_FIND_TEST_PATH
    if _ORIGINAL_FIND_TEST_PATH is not None:
        return

    _ORIGINAL_FIND_TEST_PATH = unittest.loader.TestLoader._find_test_path

    def isolated_find_test_path(self, full_path, pattern):
        snapshot = snapshot_sys_modules()
        try:
            return _ORIGINAL_FIND_TEST_PATH(self, full_path, pattern)
        finally:
            restore_sys_modules(snapshot)

    unittest.loader.TestLoader._find_test_path = isolated_find_test_path


def restore_named_modules(snapshot):
    """Restore a sparse name -> module snapshot."""

    for name, previous in snapshot.items():
        if previous is _MISSING:
            sys.modules.pop(name, None)
        else:
            sys.modules[name] = previous


def snapshot_named_modules(names):
    """Capture selected sys.modules entries."""

    return {name: sys.modules.get(name, _MISSING) for name in names}
