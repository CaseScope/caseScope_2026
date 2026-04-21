"""Shared IOC alias-generation helpers."""

from __future__ import annotations

import importlib.util
import os
import re
from typing import Any, Dict


def _load_local_module(name: str, filename: str):
    spec = importlib.util.spec_from_file_location(
        name,
        os.path.join(os.path.dirname(__file__), filename),
    )
    module = importlib.util.module_from_spec(spec)
    assert spec.loader is not None
    spec.loader.exec_module(module)
    return module


_ioc_text = _load_local_module("ioc_aliasing_text_shared", "ioc_text.py")


def generate_ioc_with_aliases(value: str, ioc_type: str) -> Dict[str, Any]:
    """Generate the searchable IOC value and contextual aliases."""
    result = {
        "primary_value": value,
        "primary_type": ioc_type,
        "aliases": [],
        "original_value": value,
    }

    if not value:
        return result

    value_clean = value.strip()

    if ioc_type == "Command Line":
        aliases = [value_clean.lower()]
        path_stripped = re.sub(
            r'[A-Za-z]:\\(?:[^\\/:*?"<>|\s]+\\)*([^\\/:*?"<>|\s]+\.(?:exe|bat|cmd|ps1|vbs|dll|msi))',
            lambda match: match.group(1),
            value_clean,
            flags=re.IGNORECASE,
        )

        if path_stripped.lower() != value_clean.lower():
            aliases.append(path_stripped.lower())

        first_exe_match = re.search(
            r'(?:^|[\\\/\s"])([a-zA-Z0-9_\-\.]+\.(?:exe|bat|cmd|ps1|vbs|dll|msi))',
            value_clean,
            re.IGNORECASE,
        )

        if first_exe_match:
            result["primary_value"] = first_exe_match.group(1).lower()
            result["primary_type"] = "File Name"
        else:
            first_token = value_clean.split()[0].strip('"\'') if value_clean.split() else value_clean
            first_token_name = os.path.basename(first_token.replace("\\", "/"))
            if first_token_name:
                result["primary_value"] = first_token_name.lower()
                result["primary_type"] = "File Name"

        result["aliases"] = list(set(aliases))
        return result

    if ioc_type in ("File Path", "Process Path"):
        normalized_path, _ = _ioc_text._normalize_extracted_file_path(value_clean)
        if normalized_path:
            value_clean = normalized_path
        filename = os.path.basename(value_clean.replace("\\", "/"))

        if filename:
            result["primary_value"] = filename.lower()
            result["primary_type"] = "File Name"
            result["aliases"] = [value_clean.lower()]
        return result

    if ioc_type == "File Name":
        result["primary_value"] = value_clean.lower()
        return result

    result["primary_value"] = value_clean
    return result
