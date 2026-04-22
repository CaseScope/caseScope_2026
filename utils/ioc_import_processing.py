"""Helpers for converting extracted IOC payloads into import-ready actions."""

from __future__ import annotations

import importlib.util
import os
from typing import Any, Callable, Dict, List, Optional, Tuple


def _load_local_module(name: str, filename: str):
    spec = importlib.util.spec_from_file_location(
        name,
        os.path.join(os.path.dirname(__file__), filename),
    )
    module = importlib.util.module_from_spec(spec)
    assert spec.loader is not None
    spec.loader.exec_module(module)
    return module


_ioc_schema = _load_local_module("ioc_schema_for_import_processing", "ioc_schema.py")
_ioc_aliasing = _load_local_module("ioc_aliasing_for_import_processing", "ioc_aliasing.py")
_ioc_import_entries = _load_local_module(
    "ioc_import_entries_for_import_processing",
    "ioc_import_entries.py",
)
_ioc_known_entities = _load_local_module(
    "ioc_known_entities_for_import_processing",
    "ioc_known_entities.py",
)
_ioc_regex_catalog = _load_local_module(
    "ioc_regex_catalog_for_import_processing",
    "ioc_regex_catalog.py",
)

IOC_TYPE_MAP = _ioc_regex_catalog.IOC_TYPE_MAP
IOC_CATEGORY_MAP = _ioc_regex_catalog.IOC_CATEGORY_MAP


def _create_ioc_entry(
    value: str,
    ioc_type: str,
    category: str,
    context: str,
    case_id: int,
) -> Optional[Dict[str, Any]]:
    return _ioc_import_entries.create_ioc_entry(
        value=value,
        ioc_type=ioc_type,
        category=category,
        context=context,
        case_id=case_id,
    )


def _create_ioc_entry_with_type_awareness(
    primary_value: str,
    primary_type: str,
    aliases: List[str],
    original_type: str,
    category: str,
    context: str,
    case_id: int,
) -> Optional[Dict[str, Any]]:
    return _ioc_import_entries.create_ioc_entry_with_type_awareness(
        primary_value=primary_value,
        primary_type=primary_type,
        aliases=aliases,
        original_type=original_type,
        category=category,
        context=context,
        case_id=case_id,
    )


def _process_known_system(
    hostname: str,
    case_id: int,
    username: str,
) -> Optional[Dict[str, Any]]:
    return _ioc_known_entities.process_known_system(
        hostname=hostname,
        case_id=case_id,
        username=username,
    )


def _process_known_user(
    username_val: str,
    sid: str,
    case_id: int,
    changed_by: str,
    context: str = "",
) -> Optional[Dict[str, Any]]:
    return _ioc_known_entities.process_known_user(
        username_val=username_val,
        sid=sid,
        case_id=case_id,
        changed_by=changed_by,
        context=context,
    )


def _dedupe_known_results(
    results: List[Dict[str, Any]],
    *,
    key_builder: Callable[[Dict[str, Any]], Any],
) -> List[Dict[str, Any]]:
    deduped: List[Dict[str, Any]] = []
    seen = set()
    for result in results:
        if not isinstance(result, dict):
            continue
        key = key_builder(result)
        if not key or key in seen:
            continue
        seen.add(key)
        deduped.append(result)
    return deduped


def process_extraction_for_import(
    extraction: Dict[str, Any],
    case_id: int,
    username: str,
) -> Dict[str, Any]:
    """Convert extraction output into IOC/known-entity import actions."""
    iocs_to_import: List[Dict[str, Any]] = []
    known_systems_results: List[Dict[str, Any]] = []
    known_users_results: List[Dict[str, Any]] = []
    seen_values = set()

    iocs_data = extraction.get("iocs", {})
    record_list = extraction.get("_ioc_records")
    if not isinstance(record_list, list):
        record_list = _ioc_schema.records_from_extraction(
            extraction,
            source="merged",
            trust_tier=_ioc_schema.TRUST_HIGH,
        )
    record_lookup = _ioc_schema.build_record_lookup(record_list)

    def _annotate_entry(
        entry: Optional[Dict[str, Any]],
        lookup_type: str,
        lookup_value: str,
    ) -> Optional[Dict[str, Any]]:
        if not entry:
            return entry
        return _ioc_schema.annotate_import_entry(
            entry,
            record_lookup,
            lookup_type=lookup_type,
            lookup_value=lookup_value,
        )

    def _seen_key(namespace: str, value: Any) -> Tuple[str, str]:
        return (namespace, str(value or "").strip().lower())

    def _has_seen(namespace: str, value: Any) -> bool:
        key = _seen_key(namespace, value)
        return bool(key[1]) and key in seen_values

    def _mark_seen(namespace: str, value: Any) -> bool:
        key = _seen_key(namespace, value)
        if not key[1]:
            return False
        seen_values.add(key)
        return True

    for hash_item in iocs_data.get("hashes", []):
        value = hash_item.get("value", "").strip().lower()
        hash_type = hash_item.get("type", "sha256").lower()
        ioc_type = IOC_TYPE_MAP.get(hash_type, "SHA256 Hash")
        category = IOC_CATEGORY_MAP.get(hash_type, "File")
        if not value or _has_seen(ioc_type, value):
            continue
        _mark_seen(ioc_type, value)

        context = hash_item.get("context", "")
        if hash_item.get("filename"):
            context = (
                f"Filename: {hash_item['filename']} | {context}"
                if context
                else f"Filename: {hash_item['filename']}"
            )

        ioc_entry = _create_ioc_entry(
            value=value,
            ioc_type=ioc_type,
            category=category,
            context=context,
            case_id=case_id,
        )
        if ioc_entry:
            iocs_to_import.append(_annotate_entry(ioc_entry, ioc_type, value))

    for ip_item in iocs_data.get("ip_addresses", []):
        value = ip_item.get("value", "").strip()
        ip_type = ip_item.get("type", "ipv4")
        ioc_type = "IP Address (IPv6)" if ip_type == "ipv6" or ":" in value else "IP Address (IPv4)"
        if not value or _has_seen(ioc_type, value):
            continue
        _mark_seen(ioc_type, value)

        context_parts = []
        if ip_item.get("port"):
            context_parts.append(f"Port: {ip_item['port']}")
        if ip_item.get("direction"):
            context_parts.append(f"Direction: {ip_item['direction']}")
        if ip_item.get("context"):
            context_parts.append(ip_item["context"])

        ioc_entry = _create_ioc_entry(
            value=value,
            ioc_type=ioc_type,
            category="Network",
            context=" | ".join(context_parts),
            case_id=case_id,
        )
        if ioc_entry:
            iocs_to_import.append(_annotate_entry(ioc_entry, ioc_type, value))

    for domain_item in iocs_data.get("domains", []):
        if isinstance(domain_item, dict):
            value = domain_item.get("value", "").strip().lower()
            context = domain_item.get("context", "")
        else:
            value = str(domain_item).strip().lower()
            context = ""

        if not value or _has_seen("Domain", value):
            continue
        _mark_seen("Domain", value)

        ioc_entry = _create_ioc_entry(
            value=value,
            ioc_type="Domain",
            category="Network",
            context=context,
            case_id=case_id,
        )
        if ioc_entry:
            iocs_to_import.append(_annotate_entry(ioc_entry, "Domain", value))

    for url_item in iocs_data.get("urls", []):
        if isinstance(url_item, dict):
            value = url_item.get("value", "").strip()
            url_type = url_item.get("type", "unknown")
            context = url_item.get("context", "")
        else:
            value = str(url_item).strip()
            url_type = "unknown"
            context = ""

        if not value or _has_seen("URL", value):
            continue
        _mark_seen("URL", value)

        if url_type == "report" or "huntress.io" in value.lower():
            continue

        context_with_type = f"Type: {url_type}" + (f" | {context}" if context else "")
        ioc_entry = _create_ioc_entry(
            value=value,
            ioc_type="URL",
            category="Network",
            context=context_with_type,
            case_id=case_id,
        )
        if ioc_entry:
            iocs_to_import.append(_annotate_entry(ioc_entry, "URL", value))

    for fp_item in iocs_data.get("file_paths", []):
        if isinstance(fp_item, dict):
            value = fp_item.get("value", "").strip()
            action = fp_item.get("action", "")
            context = fp_item.get("context", "")
        else:
            value = str(fp_item).strip()
            action = ""
            context = ""

        if not value or _has_seen("file_path_raw", value):
            continue
        _mark_seen("file_path_raw", value)

        alias_result = _ioc_aliasing.generate_ioc_with_aliases(value, "File Path")
        primary_value = alias_result["primary_value"]
        aliases = alias_result["aliases"]

        if _has_seen(alias_result["primary_type"], primary_value):
            for entry in iocs_to_import:
                if (
                    entry.get("ioc_type") == alias_result["primary_type"]
                    and entry.get("value", "").lower() == primary_value.lower()
                ):
                    existing_aliases = entry.get("aliases", [])
                    entry["aliases"] = list(set(existing_aliases + aliases))
                    break
            continue
        _mark_seen(alias_result["primary_type"], primary_value)

        context_with_action = f"Action: {action}" if action else ""
        if context:
            context_with_action += f" | {context}" if context_with_action else context
        context_with_action += f" | Path: {value}"

        ioc_entry = _create_ioc_entry_with_type_awareness(
            primary_value=primary_value,
            primary_type=alias_result["primary_type"],
            aliases=aliases,
            original_type="File Path",
            category="File",
            context=context_with_action,
            case_id=case_id,
        )
        if ioc_entry:
            iocs_to_import.append(_annotate_entry(ioc_entry, "file_paths", value))

    for fn in iocs_data.get("file_names", []):
        value = str(fn).strip() if fn else ""
        if not value or _has_seen("File Name", value):
            continue
        _mark_seen("File Name", value)

        ioc_entry = _create_ioc_entry(
            value=value,
            ioc_type="File Name",
            category="File",
            context="",
            case_id=case_id,
        )
        if ioc_entry:
            iocs_to_import.append(_annotate_entry(ioc_entry, "File Name", value))

    for reg_item in iocs_data.get("registry_keys", []):
        if isinstance(reg_item, dict):
            value = reg_item.get("value", "").strip()
            action = reg_item.get("action", "")
            context = reg_item.get("context", "")
            value_name = reg_item.get("value_name", "")
            value_data = reg_item.get("value_data", "")
        else:
            value = str(reg_item).strip()
            action = ""
            context = ""
            value_name = ""
            value_data = ""

        if not value or _has_seen("Registry Key", value):
            continue
        _mark_seen("Registry Key", value)

        context_parts = []
        if action:
            context_parts.append(f"Action: {action}")
        if value_name:
            context_parts.append(f"Value: {value_name}")
        if value_data:
            value_text = str(value_data)
            context_parts.append(f"Data: {value_text[:200]}..." if len(value_text) > 200 else f"Data: {value_text}")
        if context:
            context_parts.append(context)

        ioc_entry = _create_ioc_entry(
            value=value,
            ioc_type="Registry Key",
            category="Registry",
            context=" | ".join(context_parts),
            case_id=case_id,
        )
        if ioc_entry:
            iocs_to_import.append(_annotate_entry(ioc_entry, "Registry Key", value))

    for svc_item in iocs_data.get("services", []):
        if isinstance(svc_item, dict):
            value = svc_item.get("name", "").strip()
            action = svc_item.get("action", "")
            context = svc_item.get("context", "")
            path = svc_item.get("path", "")
        else:
            value = str(svc_item).strip()
            action = ""
            context = ""
            path = ""

        if not value or _has_seen("Service Name", value):
            continue
        _mark_seen("Service Name", value)

        context_parts = []
        if action:
            context_parts.append(f"Action: {action}")
        if path:
            context_parts.append(f"Path: {path}")
        if context:
            context_parts.append(context)

        ioc_entry = _create_ioc_entry(
            value=value,
            ioc_type="Service Name",
            category="Process",
            context=" | ".join(context_parts),
            case_id=case_id,
        )
        if ioc_entry:
            iocs_to_import.append(_annotate_entry(ioc_entry, "Service Name", value))

    for task_item in iocs_data.get("scheduled_tasks", []):
        if isinstance(task_item, dict):
            value = task_item.get("name", "") or task_item.get("path", "")
            value = value.strip()
            action = task_item.get("action", "")
            context = task_item.get("context", "")
        else:
            value = str(task_item).strip()
            action = ""
            context = ""

        if not value or _has_seen("Scheduled Task", value):
            continue
        _mark_seen("Scheduled Task", value)

        ioc_entry = _create_ioc_entry(
            value=value,
            ioc_type="Scheduled Task",
            category="Process",
            context=f"Action: {action} | {context}" if action else context,
            case_id=case_id,
        )
        if ioc_entry:
            iocs_to_import.append(_annotate_entry(ioc_entry, "Scheduled Task", value))

    for cmd_item in iocs_data.get("commands", []):
        if isinstance(cmd_item, dict):
            value = cmd_item.get("value", "").strip()
            executable = cmd_item.get("executable", "")
            context = cmd_item.get("context", "")
            parent = cmd_item.get("parent", "")
            user = cmd_item.get("user", "")
        else:
            value = str(cmd_item).strip()
            executable = ""
            context = ""
            parent = ""
            user = ""

        if not value or _has_seen("command_raw", value):
            continue
        _mark_seen("command_raw", value)

        alias_result = _ioc_aliasing.generate_ioc_with_aliases(value, "Command Line")
        primary_value = alias_result["primary_value"]
        aliases = alias_result["aliases"]

        existing_command_entry = None
        for entry in iocs_to_import:
            if (
                entry.get("value", "").lower() == primary_value.lower()
                and entry.get("ioc_type") == "Command Line"
            ):
                existing_command_entry = entry
                break

        if existing_command_entry:
            existing_aliases = existing_command_entry.get("aliases", [])
            existing_command_entry["aliases"] = list(set(existing_aliases + aliases))
            for entry in iocs_to_import:
                if entry is existing_command_entry and context:
                    existing_context = entry.get("context", "")
                    if context and context not in existing_context:
                        entry["context"] = f"{existing_context} | {context}" if existing_context else context
            continue

        context_parts = []
        if executable:
            context_parts.append(f"Executable: {executable}")
        if parent:
            context_parts.append(f"Parent: {parent}")
        if user:
            context_parts.append(f"User: {user}")
        if context:
            context_parts.append(context)
        context_parts.append(
            f"Full command: {value[:500]}..." if len(value) > 500 else f"Full command: {value}"
        )

        ioc_entry = _create_ioc_entry_with_type_awareness(
            primary_value=primary_value,
            primary_type=alias_result["primary_type"],
            aliases=aliases,
            original_type="Command Line",
            category="File",
            context=" | ".join(context_parts),
            case_id=case_id,
        )
        if ioc_entry:
            iocs_to_import.append(_annotate_entry(ioc_entry, "commands", value))

    for cred_item in iocs_data.get("credentials", []):
        cred_type = cred_item.get("type", "password")
        cred_value = cred_item.get("value", "").strip()
        cred_user = cred_item.get("username", "")
        context = cred_item.get("context", "")
        ioc_type = IOC_TYPE_MAP.get(cred_type, "Password")

        if not cred_value or _has_seen(ioc_type, cred_value):
            continue
        _mark_seen(ioc_type, cred_value)

        context_with_user = f"Username: {cred_user}" if cred_user else ""
        if context:
            context_with_user += f" | {context}" if context_with_user else context

        ioc_entry = _create_ioc_entry(
            value=cred_value,
            ioc_type=ioc_type,
            category="Authentication",
            context=context_with_user,
            case_id=case_id,
        )
        if ioc_entry:
            iocs_to_import.append(_annotate_entry(ioc_entry, ioc_type, cred_value))

    for cve in iocs_data.get("cves", []):
        value = str(cve).strip().upper()
        if not value or _has_seen("CVE", value):
            continue
        _mark_seen("CVE", value)

        ioc_entry = _create_ioc_entry(
            value=value,
            ioc_type="CVE",
            category="Vulnerability",
            context="",
            case_id=case_id,
        )
        if ioc_entry:
            iocs_to_import.append(_annotate_entry(ioc_entry, "CVE", value))

    for threat_name in iocs_data.get("threat_names", []):
        value = str(threat_name).strip()
        if not value or _has_seen("Threat Name", value):
            continue
        _mark_seen("Threat Name", value)

        ioc_entry = _create_ioc_entry(
            value=value,
            ioc_type="Threat Name",
            category="Threat Intel",
            context="",
            case_id=case_id,
        )
        if ioc_entry:
            iocs_to_import.append(_annotate_entry(ioc_entry, "Threat Name", value))

    for email in iocs_data.get("email_addresses", []):
        value = str(email).strip().lower() if email else ""
        if not value or _has_seen("Email Address", value):
            continue
        _mark_seen("Email Address", value)

        ioc_entry = _create_ioc_entry(
            value=value,
            ioc_type="Email Address",
            category="Email",
            context="",
            case_id=case_id,
        )
        if ioc_entry:
            iocs_to_import.append(_annotate_entry(ioc_entry, "Email Address", value))

    for user_item in iocs_data.get("users", []):
        if isinstance(user_item, dict):
            username_val = user_item.get("value", "").strip()
            sid = user_item.get("sid", "")
            context = user_item.get("context", "")
        else:
            username_val = str(user_item).strip()
            sid = ""
            context = ""

        if not username_val:
            continue

        user_result = _process_known_user(username_val, sid, case_id, username, context)
        if user_result:
            known_users_results.append(user_result)

    for hostname in iocs_data.get("hostnames", []):
        if isinstance(hostname, dict):
            hostname_val = hostname.get("value", "")
            context = hostname.get("context", "")
            fqdn = hostname.get("fqdn", "")
        else:
            hostname_val = str(hostname)
            context = ""
            fqdn = ""
        hostname_val = hostname_val.strip()

        if not hostname_val or _has_seen("Hostname", hostname_val):
            continue
        _mark_seen("Hostname", hostname_val)

        ioc_entry = _create_ioc_entry(
            value=hostname_val,
            ioc_type="Hostname",
            category="Network",
            context=f"FQDN: {fqdn}" if fqdn else context,
            case_id=case_id,
        )
        if ioc_entry:
            iocs_to_import.append(_annotate_entry(ioc_entry, "Hostname", hostname_val))

        system_result = _process_known_system(hostname_val, case_id, username)
        if system_result:
            known_systems_results.append(system_result)

    summary = extraction.get("extraction_summary", {})
    for host in summary.get("affected_hosts", []):
        if host and host.strip():
            system_result = _process_known_system(host.strip(), case_id, username)
            if system_result:
                known_systems_results.append(system_result)

    for user in summary.get("affected_users", []):
        if isinstance(user, dict):
            username_val = user.get("username", "").strip()
            sid = user.get("sid", "")
        else:
            username_val = str(user).strip()
            sid = ""

        if username_val:
            user_result = _process_known_user(
                username_val,
                sid,
                case_id,
                username,
                "From extraction summary",
            )
            if user_result:
                known_users_results.append(user_result)

    known_systems_results = _dedupe_known_results(
        known_systems_results,
        key_builder=lambda result: (
            str(result.get("hostname") or "").strip().lower(),
            str(result.get("system_id") or "").strip().lower(),
        ),
    )
    known_users_results = _dedupe_known_results(
        known_users_results,
        key_builder=lambda result: (
            str(result.get("username") or "").strip().lower(),
            str(result.get("sid") or "").strip().lower(),
        ),
    )

    return {
        "iocs_to_import": iocs_to_import,
        "known_systems_results": known_systems_results,
        "known_users_results": known_users_results,
        "extraction_summary": extraction.get("extraction_summary", {}),
        "deterministic_extraction": extraction.get("deterministic_extraction"),
        "audit_overlay": extraction.get("audit_overlay"),
        "mitre_indicators": iocs_data.get("mitre_indicators", []),
        "raw_artifacts": extraction.get("raw_artifacts", {}),
    }
