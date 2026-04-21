"""Helpers for IOC import-entry creation and case-scoped duplicate checks."""

from __future__ import annotations

from typing import Any, Dict, List, Optional


def create_ioc_entry(
    value: str,
    ioc_type: str,
    category: str,
    context: str,
    case_id: int,
) -> Optional[Dict[str, Any]]:
    """Create one IOC import entry with case-scoped duplicate metadata."""
    from models.ioc import IOC, detect_match_type, get_match_type_recommendation

    if not value:
        return None

    existing_ioc = IOC.find_by_value(value, ioc_type, case_id=case_id)
    detected_match_type = detect_match_type(value, ioc_type)
    match_info = get_match_type_recommendation(value, ioc_type)

    entry = {
        "value": value,
        "ioc_type": ioc_type,
        "category": category,
        "context": context,
        "is_new": existing_ioc is None,
        "match_type": detected_match_type,
        "match_type_reason": match_info.get("reason", ""),
    }

    if existing_ioc:
        entry["existing_ioc_id"] = existing_ioc.id
        entry["existing_notes"] = existing_ioc.notes
        entry["existing_match_type"] = existing_ioc.get_effective_match_type()
        entry["already_linked"] = True

    return entry


def create_ioc_entry_with_type_awareness(
    primary_value: str,
    primary_type: str,
    aliases: List[str],
    original_type: str,
    category: str,
    context: str,
    case_id: int,
) -> Optional[Dict[str, Any]]:
    """Create one IOC import entry while preserving file-vs-command semantics."""
    from models.ioc import IOC, detect_match_type, get_match_type_recommendation

    if not primary_value:
        return None

    existing_filename = IOC.find_by_value(primary_value, "File Name", case_id=case_id)
    existing_command = IOC.find_by_value(primary_value, "Command Line", case_id=case_id)
    detected_match_type = detect_match_type(primary_value, primary_type)
    match_info = get_match_type_recommendation(primary_value, primary_type)

    entry = {
        "value": primary_value,
        "ioc_type": primary_type,
        "category": category,
        "context": context,
        "aliases": aliases,
        "is_new": True,
        "merge_into_existing": False,
        "match_type": detected_match_type,
        "match_type_reason": match_info.get("reason", ""),
    }

    if original_type == "Command Line":
        if existing_command:
            entry["existing_ioc_id"] = existing_command.id
            entry["existing_notes"] = existing_command.notes
            entry["ioc_type"] = "Command Line"
            entry["category"] = "Process"
            entry["is_new"] = False
            entry["merge_into_existing"] = True
            entry["already_linked"] = True
        elif existing_filename:
            entry["ioc_type"] = "Command Line"
            entry["category"] = "Process"
            entry["is_new"] = True
            entry["preserve_filename_ioc"] = True
        else:
            entry["ioc_type"] = "Command Line"
            entry["category"] = "Process"
            entry["is_new"] = True
        return entry

    if original_type == "File Path":
        if existing_filename:
            entry["existing_ioc_id"] = existing_filename.id
            entry["existing_notes"] = existing_filename.notes
            entry["ioc_type"] = "File Name"
            entry["is_new"] = False
            entry["merge_into_existing"] = True
            entry["already_linked"] = True
        else:
            entry["ioc_type"] = "File Name"
            entry["category"] = "File"
            entry["is_new"] = True
        return entry

    existing_same_type = IOC.find_by_value(primary_value, primary_type, case_id=case_id)
    if existing_same_type:
        entry["existing_ioc_id"] = existing_same_type.id
        entry["existing_notes"] = existing_same_type.notes
        entry["is_new"] = False
        entry["merge_into_existing"] = True
        entry["already_linked"] = True
        return entry

    entry["is_new"] = True
    return entry
