"""Persistence helpers for saving extracted IOC results."""

from __future__ import annotations

import logging
from datetime import datetime, timezone
from typing import Any, Dict, List


logger = logging.getLogger(__name__)


PROVENANCE_SOURCE_ENGINE_MAP = {
    "regex": "deterministic_regex",
    "llm": "ai_semantic",
    "llm_audit": "ai_audit",
}


def _source_engine_for_entry(ioc_entry: Dict[str, Any]) -> str:
    source_engine = str(ioc_entry.get("source_engine") or "").strip()
    if source_engine:
        return source_engine
    provenance_source = str(ioc_entry.get("provenance_source") or "").strip().lower()
    if provenance_source:
        return PROVENANCE_SOURCE_ENGINE_MAP.get(provenance_source, provenance_source)
    legacy_source = str(ioc_entry.get("source") or "").strip()
    return legacy_source or "manual"


def _build_source_contribution(
    ioc_entry: Dict[str, Any],
    *,
    case_id: int,
    contribution_type: str,
) -> Dict[str, Any]:
    warnings = ioc_entry.get("validation_warnings") or []
    if not isinstance(warnings, list):
        warnings = [str(warnings)]
    source_engine = _source_engine_for_entry(ioc_entry)
    return {
        "source_engine": source_engine,
        "source_route": ioc_entry.get("source_route") or "manual",
        "case_id": ioc_entry.get("source_case_id") or case_id,
        "report_index": ioc_entry.get("source_report_index"),
        "extraction_run_id": ioc_entry.get("extraction_run_id"),
        "task_id": ioc_entry.get("extraction_task_id") or ioc_entry.get("task_id"),
        "contribution_type": contribution_type,
        "review_result": ioc_entry.get("review_result") or "accepted",
        "validation_status": ioc_entry.get("validation_status") or ("warning" if warnings else "accepted"),
        "validation_warnings": warnings,
        "created_at": datetime.now(timezone.utc).isoformat().replace("+00:00", "Z"),
    }


def save_extracted_iocs(
    iocs_data: List[Dict[str, Any]],
    case_id: int,
    username: str,
    known_systems: List[Dict[str, Any]] = None,
    known_users: List[Dict[str, Any]] = None,
) -> Dict[str, int]:
    """Persist prepared IOC and known-entity actions."""
    from models.ioc import IOC, IOCAudit, get_category_for_type
    from models.known_system import KnownSystem, KnownSystemAudit
    from models.known_user import KnownUser, KnownUserAudit
    from models.database import db
    from utils.opencti import maybe_auto_enrich_iocs

    created_count = 0
    updated_count = 0
    existing_count = 0
    systems_created = 0
    systems_updated = 0
    users_created = 0
    users_updated = 0
    created_iocs = []

    try:
        for ioc_entry in iocs_data:
            if ioc_entry.get("skip", False):
                continue

            if ioc_entry.get("existing_ioc_id"):
                existing_ioc = IOC.query.get(ioc_entry["existing_ioc_id"])
                if existing_ioc:
                    existing_count += 1
                    contribution = _build_source_contribution(
                        ioc_entry,
                        case_id=case_id,
                        contribution_type="confirmed_or_enriched",
                    )
                    if hasattr(existing_ioc, "add_source_metadata"):
                        existing_ioc.add_source_metadata(contribution)
                    elif hasattr(existing_ioc, "source_metadata"):
                        current_metadata = existing_ioc.source_metadata or []
                        existing_ioc.source_metadata = [*current_metadata, contribution]
                    if hasattr(existing_ioc, "add_source"):
                        existing_ioc.add_source(_source_engine_for_entry(ioc_entry))
                    if ioc_entry.get("context"):
                        if existing_ioc.notes:
                            existing_ioc.notes += f"\n\nExtracted context: {ioc_entry['context']}"
                        else:
                            existing_ioc.notes = f"Extracted context: {ioc_entry['context']}"
                        updated_count += 1

                    if ioc_entry.get("aliases"):
                        for alias in ioc_entry["aliases"]:
                            existing_ioc.add_alias(alias)
            else:
                value = ioc_entry["value"]
                ioc_type = ioc_entry["ioc_type"]
                category = ioc_entry["category"]
                aliases = ioc_entry.get("aliases", [])
                match_type = ioc_entry.get("match_type")
                contribution = _build_source_contribution(
                    ioc_entry,
                    case_id=case_id,
                    contribution_type="created",
                )
                source_engine = contribution["source_engine"]

                try:
                    ioc, created = IOC.get_or_create(
                        value=value,
                        ioc_type=ioc_type,
                        category=category,
                        created_by=username,
                        case_id=case_id,
                        aliases=aliases,
                        match_type=match_type,
                        source=source_engine,
                        source_metadata=contribution,
                    )

                    if created:
                        created_count += 1
                        created_iocs.append(ioc)
                        if ioc_entry.get("context"):
                            ioc.notes = f"Extracted context: {ioc_entry['context']}"

                        IOCAudit.log_change(
                            ioc_id=ioc.id,
                            changed_by=username,
                            field_name="ioc",
                            action="create",
                            new_value=f"{ioc_type}: {value} (match: {ioc.get_effective_match_type()})",
                        )

                        if aliases:
                            IOCAudit.log_change(
                                ioc_id=ioc.id,
                                changed_by=username,
                                field_name="aliases",
                                action="create",
                                new_value=f"{len(aliases)} aliases added",
                            )
                    else:
                        existing_count += 1

                except ValueError as exc:
                    logger.warning("Failed to create IOC %s: %s - %s", ioc_type, value, exc)

        if known_systems:
            for sys_result in known_systems:
                if sys_result.get("skip", False):
                    continue

                action = sys_result.get("action")
                hostname = sys_result.get("hostname")

                def create_hostname_ioc(hostname_value):
                    try:
                        hostname_ioc, created = IOC.get_or_create(
                            value=hostname_value,
                            ioc_type="Hostname",
                            category=get_category_for_type("Hostname"),
                            created_by=username,
                            case_id=case_id,
                            source="ai_extraction",
                        )
                        if created:
                            created_iocs.append(hostname_ioc)
                            logger.info(
                                "Created Hostname IOC for compromised system: %s",
                                hostname_value,
                            )
                    except ValueError as exc:
                        logger.debug("Hostname IOC error: %s", exc)

                if action == "create_new":
                    netbios, fqdn = KnownSystem.extract_netbios_name(hostname)
                    target_hostname = netbios or hostname

                    existing_system, _ = KnownSystem.find_by_hostname_or_alias(
                        target_hostname,
                        case_id=case_id,
                    )
                    if existing_system:
                        if not existing_system.compromised:
                            existing_system.compromised = True
                            systems_updated += 1
                        create_hostname_ioc(target_hostname)
                        continue

                    try:
                        new_system = KnownSystem(
                            case_id=case_id,
                            hostname=target_hostname,
                            compromised=True,
                            notes=f"Created from EDR report extraction by {username}",
                        )
                        db.session.add(new_system)
                        db.session.flush()

                        if fqdn and fqdn != target_hostname:
                            new_system.add_alias(fqdn)
                    except Exception as exc:
                        db.session.rollback()
                        logger.warning(
                            "Race condition creating system %s: %s",
                            target_hostname,
                            exc,
                        )
                        KnownSystem.find_by_hostname_or_alias(target_hostname, case_id=case_id)
                        create_hostname_ioc(target_hostname)
                        continue

                    create_hostname_ioc(target_hostname)

                    KnownSystemAudit.log_change(
                        system_id=new_system.id,
                        changed_by=username,
                        field_name="system",
                        action="create",
                        new_value=f"{target_hostname} (from EDR extraction)",
                    )
                    systems_created += 1

                elif action == "mark_compromised":
                    system = KnownSystem.query.get(sys_result.get("system_id"))
                    if system and not system.compromised:
                        system.compromised = True
                        if system.notes:
                            system.notes += f"\n\nMarked compromised from EDR report extraction by {username}"
                        else:
                            system.notes = f"Marked compromised from EDR report extraction by {username}"

                        create_hostname_ioc(system.hostname)

                        KnownSystemAudit.log_change(
                            system_id=system.id,
                            changed_by=username,
                            field_name="compromised",
                            action="update",
                            old_value="False",
                            new_value="True",
                        )
                        systems_updated += 1

                elif action == "already_compromised":
                    system = KnownSystem.query.get(sys_result.get("system_id"))
                    if system:
                        create_hostname_ioc(system.hostname)

        if known_users:
            for user_result in known_users:
                if user_result.get("skip", False):
                    continue

                action = user_result.get("action")
                username_val = user_result.get("username")
                sid = user_result.get("sid")

                def create_username_ioc(username_value, user_sid=None):
                    user_aliases = [user_sid] if user_sid else None
                    try:
                        user_ioc, created = IOC.get_or_create(
                            value=username_value,
                            ioc_type="Username",
                            category=get_category_for_type("Username"),
                            created_by=username,
                            case_id=case_id,
                            aliases=user_aliases,
                            source="ai_extraction",
                        )
                        if created:
                            created_iocs.append(user_ioc)
                            logger.info(
                                "Created Username IOC for compromised user: %s",
                                username_value,
                            )
                    except ValueError as exc:
                        logger.debug("Username IOC error: %s", exc)

                if action == "create_new":
                    normalized, _domain = KnownUser.normalize_username(username_val)
                    target_username = normalized or username_val

                    existing_user, _ = KnownUser.find_by_username_sid_alias_or_email(
                        username=target_username,
                        sid=sid if sid else None,
                        case_id=case_id,
                    )
                    if existing_user:
                        if not existing_user.compromised:
                            existing_user.compromised = True
                            users_updated += 1
                        create_username_ioc(target_username, sid)
                        continue

                    try:
                        new_user = KnownUser(
                            case_id=case_id,
                            username=target_username,
                            sid=sid if sid else None,
                            compromised=True,
                            added_by=username,
                            notes="Created from EDR report extraction",
                        )
                        db.session.add(new_user)
                        db.session.flush()

                        if username_val.upper() != target_username.upper():
                            new_user.add_alias(username_val)
                    except Exception as exc:
                        db.session.rollback()
                        logger.warning(
                            "Race condition creating user %s: %s",
                            target_username,
                            exc,
                        )
                        KnownUser.find_by_username_sid_alias_or_email(
                            username=target_username,
                            sid=sid if sid else None,
                            case_id=case_id,
                        )
                        create_username_ioc(target_username, sid)
                        continue

                    create_username_ioc(target_username, sid)

                    KnownUserAudit.log_change(
                        user_id=new_user.id,
                        changed_by=username,
                        field_name="user",
                        action="create",
                        new_value=f"{target_username} (from EDR extraction)",
                    )
                    users_created += 1

                elif action == "mark_compromised":
                    user = KnownUser.query.get(user_result.get("user_id"))
                    if user and not user.compromised:
                        user.compromised = True
                        if user.notes:
                            user.notes += f"\n\nMarked compromised from EDR report extraction by {username}"
                        else:
                            user.notes = f"Marked compromised from EDR report extraction by {username}"

                        user_sid = sid or user.sid
                        create_username_ioc(user.username, user_sid)

                        KnownUserAudit.log_change(
                            user_id=user.id,
                            changed_by=username,
                            field_name="compromised",
                            action="update",
                            old_value="False",
                            new_value="True",
                        )
                        users_updated += 1

                        if user_result.get("add_sid") and sid:
                            user.sid = sid
                            KnownUserAudit.log_change(
                                user_id=user.id,
                                changed_by=username,
                                field_name="sid",
                                action="update",
                                new_value=sid,
                            )

                elif action == "already_compromised":
                    user = KnownUser.query.get(user_result.get("user_id"))
                    if user:
                        user_sid = sid or user.sid
                        create_username_ioc(user.username, user_sid)

        db.session.commit()
        auto_enrichment = maybe_auto_enrich_iocs(created_iocs)

        return {
            "iocs_created": created_count,
            "iocs_updated": updated_count,
            "iocs_existing": existing_count,
            "iocs_linked": 0,
            "systems_created": systems_created,
            "systems_updated": systems_updated,
            "users_created": users_created,
            "users_updated": users_updated,
            "auto_enrichment": auto_enrichment,
        }

    except Exception:
        db.session.rollback()
        logger.exception("Failed to save extracted IOCs")
        raise
