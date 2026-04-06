"""Internal IOC record helpers for staged extraction provenance."""

from __future__ import annotations

from typing import Any, Dict, Iterable, List, Tuple

TRUST_HIGH = "high"
TRUST_LOW = "low"


def build_ioc_record(
    *,
    value: str,
    ioc_type: str,
    category: str,
    source: str,
    trust_tier: str,
    field: str,
    context: str = "",
    section: str = "",
    raw_value: str = "",
) -> Dict[str, Any]:
    """Build a normalized internal IOC record."""
    return {
        "value": (value or "").strip(),
        "ioc_type": ioc_type,
        "category": category,
        "source": source,
        "trust_tier": trust_tier,
        "field": field,
        "context": context or "",
        "section": section or "",
        "raw_value": raw_value or (value or "").strip(),
    }


def _append_record(records: List[Dict[str, Any]], **kwargs) -> None:
    record = build_ioc_record(**kwargs)
    if record["value"]:
        records.append(record)


def records_from_extraction(
    extraction: Dict[str, Any],
    *,
    source: str,
    trust_tier: str,
) -> List[Dict[str, Any]]:
    """Flatten extraction results into a DTO-style record list."""
    records: List[Dict[str, Any]] = []
    iocs = extraction.get("iocs", {}) or {}
    summary = extraction.get("extraction_summary", {}) or {}
    section = ", ".join(summary.get("semantic_sections", []) or [])

    for item in iocs.get("hashes", []):
        if not isinstance(item, dict):
            continue
        hash_type = str(item.get("type") or "sha256").lower()
        ioc_type = {
            "md5": "MD5 Hash",
            "sha1": "SHA1 Hash",
            "sha256": "SHA256 Hash",
        }.get(hash_type, "SHA256 Hash")
        context = item.get("context", "")
        if item.get("filename"):
            context = f"Filename: {item['filename']} | {context}" if context else f"Filename: {item['filename']}"
        _append_record(
            records,
            value=item.get("value", ""),
            ioc_type=ioc_type,
            category="File",
            source=source,
            trust_tier=trust_tier,
            field="hashes",
            context=context,
            section=section,
            raw_value=item.get("value", ""),
        )

    for item in iocs.get("ip_addresses", []):
        if not isinstance(item, dict):
            continue
        value = item.get("value", "")
        ip_type = item.get("type", "ipv4")
        ioc_type = "IP Address (IPv6)" if ip_type == "ipv6" or ":" in str(value) else "IP Address (IPv4)"
        context_parts = []
        if item.get("port"):
            context_parts.append(f"Port: {item['port']}")
        if item.get("direction"):
            context_parts.append(f"Direction: {item['direction']}")
        if item.get("context"):
            context_parts.append(str(item["context"]))
        _append_record(
            records,
            value=value,
            ioc_type=ioc_type,
            category="Network",
            source=source,
            trust_tier=trust_tier,
            field="ip_addresses",
            context=" | ".join(context_parts),
            section=section,
            raw_value=value,
        )

    simple_map = [
        ("domains", "Domain", "Network"),
        ("urls", "URL", "Network"),
        ("file_names", "File Name", "File"),
        ("cves", "CVE", "Vulnerability"),
        ("threat_names", "Threat Name", "Threat Intel"),
        ("email_addresses", "Email Address", "Email"),
    ]
    for field, ioc_type, category in simple_map:
        for item in iocs.get(field, []):
            if isinstance(item, dict):
                value = item.get("value", "") or item.get("name", "") or item.get("path", "")
                context = item.get("context", "")
            else:
                value = str(item)
                context = ""
            _append_record(
                records,
                value=value,
                ioc_type=ioc_type,
                category=category,
                source=source,
                trust_tier=trust_tier,
                field=field,
                context=context,
                section=section,
                raw_value=value,
            )

    for item in iocs.get("registry_keys", []):
        if not isinstance(item, dict):
            value = str(item)
            context = ""
        else:
            value = item.get("value", "")
            parts = []
            if item.get("action"):
                parts.append(f"Action: {item['action']}")
            if item.get("value_name"):
                parts.append(f"Value: {item['value_name']}")
            if item.get("value_data"):
                parts.append(f"Data: {item['value_data']}")
            if item.get("context"):
                parts.append(str(item["context"]))
            context = " | ".join(parts)
        _append_record(
            records,
            value=value,
            ioc_type="Registry Key",
            category="Registry",
            source=source,
            trust_tier=trust_tier,
            field="registry_keys",
            context=context,
            section=section,
            raw_value=value,
        )

    for item in iocs.get("services", []):
        if isinstance(item, dict):
            value = item.get("name", "")
            parts = []
            if item.get("action"):
                parts.append(f"Action: {item['action']}")
            if item.get("path"):
                parts.append(f"Path: {item['path']}")
            if item.get("context"):
                parts.append(str(item["context"]))
            context = " | ".join(parts)
        else:
            value = str(item)
            context = ""
        _append_record(
            records,
            value=value,
            ioc_type="Service Name",
            category="Process",
            source=source,
            trust_tier=trust_tier,
            field="services",
            context=context,
            section=section,
            raw_value=value,
        )

    for item in iocs.get("scheduled_tasks", []):
        if isinstance(item, dict):
            value = item.get("name", "") or item.get("path", "")
            context = item.get("context", "")
        else:
            value = str(item)
            context = ""
        _append_record(
            records,
            value=value,
            ioc_type="Scheduled Task",
            category="Process",
            source=source,
            trust_tier=trust_tier,
            field="scheduled_tasks",
            context=context,
            section=section,
            raw_value=value,
        )

    for item in iocs.get("commands", []):
        if not isinstance(item, dict):
            value = str(item)
            context = ""
        else:
            value = item.get("value", "")
            parts = []
            if item.get("executable"):
                parts.append(f"Executable: {item['executable']}")
            if item.get("parent"):
                parts.append(f"Parent: {item['parent']}")
            if item.get("user"):
                parts.append(f"User: {item['user']}")
            if item.get("context"):
                parts.append(str(item["context"]))
            parts.append(f"Full command: {value}")
            context = " | ".join(part for part in parts if part)
        _append_record(
            records,
            value=value,
            ioc_type="Command Line",
            category="Process",
            source=source,
            trust_tier=trust_tier,
            field="commands",
            context=context,
            section=section,
            raw_value=value,
        )

    for item in iocs.get("credentials", []):
        if not isinstance(item, dict):
            continue
        context = f"Username: {item.get('username', '')}".strip()
        if item.get("context"):
            context = f"{context} | {item['context']}" if context else str(item["context"])
        _append_record(
            records,
            value=item.get("value", ""),
            ioc_type="Password",
            category="Authentication",
            source=source,
            trust_tier=trust_tier,
            field="credentials",
            context=context,
            section=section,
            raw_value=item.get("value", ""),
        )

    for item in iocs.get("users", []):
        if isinstance(item, dict):
            value = item.get("value", "")
            context = item.get("context", "")
        else:
            value = str(item)
            context = ""
        _append_record(
            records,
            value=value,
            ioc_type="Username",
            category="Authentication",
            source=source,
            trust_tier=trust_tier,
            field="users",
            context=context,
            section=section,
            raw_value=value,
        )

    for item in iocs.get("hostnames", []):
        if isinstance(item, dict):
            value = item.get("value", "")
            fqdn = item.get("fqdn", "")
            context = item.get("context", "")
            if fqdn:
                context = f"FQDN: {fqdn}" if not context else f"FQDN: {fqdn} | {context}"
        else:
            value = str(item)
            context = ""
        _append_record(
            records,
            value=value,
            ioc_type="Hostname",
            category="Network",
            source=source,
            trust_tier=trust_tier,
            field="hostnames",
            context=context,
            section=section,
            raw_value=value,
        )

    for host in summary.get("affected_hosts", []):
        _append_record(
            records,
            value=str(host),
            ioc_type="Hostname",
            category="Network",
            source=source,
            trust_tier=trust_tier,
            field="affected_hosts",
            context="From extraction summary",
            section=section,
            raw_value=str(host),
        )

    for user in summary.get("affected_users", []):
        if isinstance(user, dict):
            value = user.get("username", "")
        else:
            value = str(user)
        _append_record(
            records,
            value=value,
            ioc_type="Username",
            category="Authentication",
            source=source,
            trust_tier=trust_tier,
            field="affected_users",
            context="From extraction summary",
            section=section,
            raw_value=value,
        )

    return records


def _record_index_keys(record: Dict[str, Any]) -> Iterable[Tuple[str, str]]:
    value = str(record.get("value") or "").strip().lower()
    if not value:
        return []
    ioc_type = str(record.get("ioc_type") or "").strip().lower()
    field = str(record.get("field") or "").strip().lower()
    aliases = {(ioc_type, value)}
    if field:
        aliases.add((field, value))
    return aliases


def build_record_lookup(records: List[Dict[str, Any]]) -> Dict[Tuple[str, str], Dict[str, Any]]:
    """Build a loose lookup keyed by both IOC type and source field."""
    lookup: Dict[Tuple[str, str], Dict[str, Any]] = {}
    for record in records or []:
        for key in _record_index_keys(record):
            lookup.setdefault(key, record)
    return lookup


def annotate_import_entry(
    entry: Dict[str, Any],
    lookup: Dict[Tuple[str, str], Dict[str, Any]],
    *,
    lookup_type: str,
    lookup_value: str,
) -> Dict[str, Any]:
    """Attach provenance metadata from the internal record lookup."""
    key = ((lookup_type or "").strip().lower(), (lookup_value or "").strip().lower())
    record = lookup.get(key)
    if not record:
        return entry

    entry["provenance_source"] = record.get("source", "")
    entry["trust_tier"] = record.get("trust_tier", "")
    entry["provenance_field"] = record.get("field", "")
    entry["provenance_section"] = record.get("section", "")
    return entry
