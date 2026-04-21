"""Helpers for case-scoped Known System/User IOC side effects."""

from __future__ import annotations

from typing import Any, Dict, Optional


def process_known_system(
    hostname: str,
    case_id: int,
    username: str,
) -> Optional[Dict[str, Any]]:
    """Return the case-scoped known-system action implied by one hostname."""
    from models.known_system import KnownSystem

    if not hostname:
        return None

    system, _match_type = KnownSystem.find_by_hostname_or_alias(hostname, case_id=case_id)
    result = {
        "hostname": hostname,
        "action": None,
        "system_id": None,
        "was_compromised": False,
        "now_compromised": True,
    }

    if system:
        result["system_id"] = system.id
        result["was_compromised"] = system.compromised
        result["action"] = "mark_compromised" if not system.compromised else "already_compromised"
        system.link_to_case(case_id)
    else:
        result["action"] = "create_new"

    return result


def process_known_user(
    username_val: str,
    sid: str,
    case_id: int,
    changed_by: str,
    context: str = "",
) -> Optional[Dict[str, Any]]:
    """Return the case-scoped known-user action implied by one user IOC."""
    from models.known_user import KnownUser

    if not username_val:
        return None

    user, _match_type = KnownUser.find_by_username_sid_alias_or_email(
        username=username_val,
        sid=sid if sid else None,
        case_id=case_id,
    )
    result = {
        "username": username_val,
        "sid": sid,
        "context": context,
        "action": None,
        "user_id": None,
        "was_compromised": False,
        "now_compromised": True,
    }

    if user:
        result["user_id"] = user.id
        result["was_compromised"] = user.compromised
        result["action"] = "mark_compromised" if not user.compromised else "already_compromised"
        user.link_to_case(case_id)
        if sid and not user.sid:
            result["add_sid"] = True
    else:
        result["action"] = "create_new"

    return result
