"""Internal IOC record helpers for staged extraction provenance."""

from __future__ import annotations

import hashlib
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
    normalized_value: str = "",
    evidence: str = "",
    evidence_origin: str = "",
    extraction_method: str = "",
    semantic_route: str = "",
) -> Dict[str, Any]:
    """Build a normalized internal IOC record."""
    normalized = (normalized_value or value or "").strip()
    raw = raw_value if raw_value not in (None, "") else (value or "").strip()
    evidence_excerpt = evidence or context or ""
    record_id_seed = "|".join([
        source or "",
        field or "",
        ioc_type or "",
        normalized.lower(),
        evidence_excerpt[:500],
    ])
    record_id = "ioc_candidate_" + hashlib.sha256(record_id_seed.encode("utf-8")).hexdigest()[:16]
    return {
        "candidate_id": record_id,
        "value": (value or "").strip(),
        "normalized_value": normalized,
        "ioc_type": ioc_type,
        "category": category,
        "source": source,
        "trust_tier": trust_tier,
        "field": field,
        "context": context or "",
        "section": section or "",
        "raw_value": raw,
        "evidence": evidence_excerpt,
        "evidence_origin": evidence_origin or "",
        "extraction_method": extraction_method or source,
        "semantic_route": semantic_route or "",
        "evidence_refs": [
            {
                "candidate_id": record_id,
                "source": source,
                "section": section or "",
                "field": field,
                "raw_value": raw,
                "normalized_value": normalized,
                "evidence": evidence_excerpt,
                "evidence_origin": evidence_origin or "",
                "extraction_method": extraction_method or source,
                "semantic_route": semantic_route or "",
            }
        ],
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
    semantic_route = str(summary.get("semantic_task") or "")

    def _item_meta(item: Any) -> Dict[str, str]:
        if not isinstance(item, dict):
            return {}
        return {
            "raw_value": item.get("raw_value", ""),
            "normalized_value": item.get("normalized_value", item.get("value", "")),
            "evidence": item.get("evidence") or item.get("evidence_excerpt") or item.get("context", ""),
            "evidence_origin": item.get("evidence_origin", ""),
            "semantic_route": item.get("semantic_route", semantic_route),
        }

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
            normalized_value=item.get("normalized_value", item.get("value", "")),
            evidence=item.get("evidence") or context,
            evidence_origin=item.get("evidence_origin", ""),
            extraction_method=source,
            semantic_route=semantic_route,
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
            normalized_value=item.get("normalized_value", value),
            evidence=item.get("evidence") or item.get("context", ""),
            evidence_origin=item.get("evidence_origin", ""),
            extraction_method=source,
            semantic_route=semantic_route,
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
                meta = _item_meta(item)
            else:
                value = str(item)
                context = ""
                meta = {}
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
                raw_value=meta.get("raw_value", value),
                normalized_value=meta.get("normalized_value", value),
                evidence=meta.get("evidence", context),
                evidence_origin=meta.get("evidence_origin", ""),
                extraction_method=source,
                semantic_route=meta.get("semantic_route", semantic_route),
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
            normalized_value=item.get("normalized_value", value) if isinstance(item, dict) else value,
            evidence=item.get("evidence") or context if isinstance(item, dict) else context,
            evidence_origin=item.get("evidence_origin", "") if isinstance(item, dict) else "",
            extraction_method=source,
            semantic_route=semantic_route,
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
            normalized_value=item.get("normalized_value", value) if isinstance(item, dict) else value,
            evidence=item.get("evidence") or context if isinstance(item, dict) else context,
            evidence_origin=item.get("evidence_origin", "") if isinstance(item, dict) else "",
            extraction_method=source,
            semantic_route=semantic_route,
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
            normalized_value=item.get("normalized_value", value) if isinstance(item, dict) else value,
            evidence=item.get("evidence") or context if isinstance(item, dict) else context,
            evidence_origin=item.get("evidence_origin", "") if isinstance(item, dict) else "",
            extraction_method=source,
            semantic_route=semantic_route,
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
            normalized_value=item.get("normalized_value", value) if isinstance(item, dict) else value,
            evidence=item.get("evidence") or context if isinstance(item, dict) else context,
            evidence_origin=item.get("evidence_origin", "") if isinstance(item, dict) else "",
            extraction_method=source,
            semantic_route=semantic_route,
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
            normalized_value=item.get("normalized_value", item.get("value", "")),
            evidence=item.get("evidence") or context,
            evidence_origin=item.get("evidence_origin", ""),
            extraction_method=source,
            semantic_route=semantic_route,
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
            normalized_value=item.get("normalized_value", value) if isinstance(item, dict) else value,
            evidence=item.get("evidence") or context if isinstance(item, dict) else context,
            evidence_origin=item.get("evidence_origin", "") if isinstance(item, dict) else "",
            extraction_method=source,
            semantic_route=semantic_route,
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
            normalized_value=item.get("normalized_value", value) if isinstance(item, dict) else value,
            evidence=item.get("evidence") or context if isinstance(item, dict) else context,
            evidence_origin=item.get("evidence_origin", "") if isinstance(item, dict) else "",
            extraction_method=source,
            semantic_route=semantic_route,
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
    entry["candidate_id"] = record.get("candidate_id")
    entry["raw_value"] = record.get("raw_value", "")
    entry["normalized_value"] = record.get("normalized_value", "")
    entry["evidence"] = record.get("evidence", "")
    entry["evidence_origin"] = record.get("evidence_origin", "")
    entry["extraction_method"] = record.get("extraction_method", "")
    entry["semantic_route"] = record.get("semantic_route", "")
    entry["evidence_refs"] = record.get("evidence_refs", [])
    return entry
