"""Service helpers for analyst case work time tracking."""
import json
import logging
from datetime import datetime

from models.case import Case
from models.case_work import (
    CaseWorkActivity,
    CaseWorkActivityType,
    CaseWorkSession,
    CaseWorkSessionStatus,
)
from models.database import db

logger = logging.getLogger(__name__)


def _user_display_name(user):
    return getattr(user, "full_name", None) or getattr(user, "username", None) or "Unknown analyst"


def get_active_work_session(user_id):
    """Return a user's active work session, if one exists."""
    if not user_id:
        return None
    return (
        CaseWorkSession.query.filter_by(user_id=user_id, status=CaseWorkSessionStatus.ACTIVE)
        .order_by(CaseWorkSession.started_at.desc())
        .first()
    )


def begin_work_session(case, user, start_note=None):
    """Start a case work session for a user, enforcing one active session at a time."""
    active_session = get_active_work_session(user.id)
    if active_session:
        if active_session.case_uuid == case.uuid:
            return active_session, False
        raise ValueError(
            f"Active work session already exists for case {active_session.case.name if active_session.case else active_session.case_uuid}"
        )

    session = CaseWorkSession(
        case_id=case.id,
        case_uuid=case.uuid,
        client_id=case.client_id,
        user_id=user.id,
        username=user.username,
        analyst_name=_user_display_name(user),
        start_note=start_note or None,
    )
    db.session.add(session)
    db.session.flush()

    activity = CaseWorkActivity(
        work_session_id=session.id,
        case_id=case.id,
        case_uuid=case.uuid,
        user_id=user.id,
        username=user.username,
        activity_type=CaseWorkActivityType.WORK_STARTED,
        summary="Began work on case",
        details=json.dumps(
            {
                "client_name": case.client.name if case.client else case.company,
                "case_name": case.name,
                "case_uuid": case.uuid,
                "case_number": case.id,
                "analyst_name": _user_display_name(user),
                "start_note": start_note or None,
            }
        ),
    )
    db.session.add(activity)
    db.session.commit()
    return session, True


def end_work_session(user, case_uuid=None, end_note=None):
    """End the active work session for a user."""
    active_session = get_active_work_session(user.id)
    if not active_session:
        return None
    if case_uuid and active_session.case_uuid != case_uuid:
        raise ValueError("Active work session belongs to a different case")

    active_session.complete(end_note=end_note)
    db.session.flush()

    db.session.add(
        CaseWorkActivity(
            work_session_id=active_session.id,
            case_id=active_session.case_id,
            case_uuid=active_session.case_uuid,
            user_id=user.id,
            username=user.username,
            activity_type=CaseWorkActivityType.WORK_ENDED,
            summary="Ended work on case",
            details=json.dumps(
                {
                    "duration_seconds": active_session.duration_seconds,
                    "end_note": end_note or None,
                    "ended_at": active_session.ended_at.isoformat() if active_session.ended_at else None,
                }
            ),
        )
    )
    db.session.commit()
    return active_session


def log_case_work_activity(
    case_uuid,
    activity_type,
    summary,
    details=None,
    work_session_uuid=None,
    user_id=None,
    username=None,
):
    """Append activity to an explicit or active work session.

    Returns the activity row when one is written. If no matching session exists,
    returns None so instrumentation can remain best-effort.
    """
    session = None
    if work_session_uuid:
        session = CaseWorkSession.query.filter_by(uuid=work_session_uuid).first()
    elif user_id:
        session = (
            CaseWorkSession.query.filter_by(
                user_id=user_id,
                case_uuid=case_uuid,
                status=CaseWorkSessionStatus.ACTIVE,
            )
            .order_by(CaseWorkSession.started_at.desc())
            .first()
        )
    else:
        session = (
            CaseWorkSession.query.filter_by(
                case_uuid=case_uuid,
                status=CaseWorkSessionStatus.ACTIVE,
            )
            .order_by(CaseWorkSession.started_at.desc())
            .first()
        )

    if not session:
        return None

    case = Case.get_by_uuid_unchecked(case_uuid)
    if not case:
        return None

    activity = CaseWorkActivity(
        work_session_id=session.id,
        case_id=case.id,
        case_uuid=case_uuid,
        user_id=user_id or session.user_id,
        username=username or session.username,
        activity_type=activity_type,
        summary=summary[:500],
        details=json.dumps(details or {}, default=str) if details is not None else None,
        timestamp=datetime.utcnow(),
    )
    db.session.add(activity)
    db.session.commit()
    return activity


def safe_log_case_work_activity(*args, **kwargs):
    """Best-effort activity logging that never interrupts the calling workflow."""
    try:
        return log_case_work_activity(*args, **kwargs)
    except Exception as exc:  # noqa: BLE001
        db.session.rollback()
        logger.warning("Case work activity logging failed: %s", exc)
        return None
