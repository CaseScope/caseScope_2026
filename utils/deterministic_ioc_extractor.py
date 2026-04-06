"""Deterministic IOC extraction stage helpers."""

from __future__ import annotations

import importlib.util
import os
from typing import Any, Dict, Type


def _load_local_module(name: str, filename: str):
    spec = importlib.util.spec_from_file_location(
        name,
        os.path.join(os.path.dirname(__file__), filename),
    )
    module = importlib.util.module_from_spec(spec)
    assert spec.loader is not None
    spec.loader.exec_module(module)
    return module


_ioc_schema = _load_local_module("deterministic_ioc_schema_shared", "ioc_schema.py")


def run_deterministic_stage(report_text: str, extractor_cls: Type[Any]) -> Dict[str, Any]:
    """Run the deterministic extraction stage and attach internal records."""
    extractor = extractor_cls()
    extraction = extractor.extract(report_text)
    extraction["_ioc_records"] = _ioc_schema.records_from_extraction(
        extraction,
        source="regex",
        trust_tier=_ioc_schema.TRUST_HIGH,
    )
    return extraction
