"""Known users API routes extracted from the monolithic API module."""

import csv
import io

from flask import Blueprint, Response, jsonify, request
from flask_login import current_user, login_required

from models.case import Case
from models.database import db
from routes.route_helpers import _require_case_write_access

known_users_bp = Blueprint("known_users", __name__, url_prefix="/api")


@known_users_bp.route("/known-users/list/<case_uuid>")
@login_required
def get_known_users(case_uuid):
    """Get known users for a case."""
    try:
        from utils.known_users_discovery import get_users_for_case

        case = Case.get_by_uuid(case_uuid)
        if not case:
            return jsonify({"success": False, "error": "Case not found"}), 404

        users = get_users_for_case(case.id)

        all_sources = set()
        for user in users:
            sources = user.get("sources", [])
            if sources:
                all_sources.update(sources)

        return jsonify(
            {
                "success": True,
                "case_uuid": case_uuid,
                "users": users,
                "total": len(users),
                "aggregate_sources": sorted(list(all_sources)),
            }
        )

    except Exception as e:
        return jsonify({"success": False, "error": str(e)}), 500


@known_users_bp.route("/known-users/discover/<case_uuid>", methods=["POST"])
@login_required
def discover_users(case_uuid):
    """Start async discovery of known users from artifacts."""
    try:
        from tasks.celery_tasks import discover_known_users_task
        from utils.known_users_discovery import get_user_discovery_progress

        case = Case.get_by_uuid(case_uuid)
        if not case:
            return jsonify({"success": False, "error": "Case not found"}), 404

        write_error = _require_case_write_access(current_user)
        if write_error:
            return write_error

        progress = get_user_discovery_progress(case_uuid)
        if progress and progress.get("status") == "running":
            return jsonify(
                {
                    "success": True,
                    "status": "already_running",
                    "progress": progress,
                }
            )

        task = discover_known_users_task.delay(
            case_id=case.id,
            case_uuid=case_uuid,
            username=current_user.username,
        )

        return jsonify(
            {
                "success": True,
                "status": "started",
                "task_id": task.id,
            }
        )

    except Exception as e:
        return jsonify({"success": False, "error": str(e)}), 500


@known_users_bp.route("/known-users/discover-progress/<case_uuid>")
@login_required
def get_user_discovery_status(case_uuid):
    """Get discovery progress for users in a case."""
    try:
        from utils.known_users_discovery import get_user_discovery_progress

        case = Case.get_by_uuid(case_uuid)
        if not case:
            return jsonify({"success": False, "error": "Case not found"}), 404

        progress = get_user_discovery_progress(case_uuid)

        return jsonify(
            {
                "success": True,
                "progress": progress,
            }
        )

    except Exception as e:
        return jsonify({"success": False, "error": str(e)}), 500


@known_users_bp.route("/known-users/<int:user_id>")
@login_required
def get_known_user(user_id):
    """Get details for a specific known user."""
    try:
        from models.known_user import KnownUser

        user = KnownUser.query.get(user_id)
        if not user:
            return jsonify({"success": False, "error": "User not found"}), 404

        return jsonify(
            {
                "success": True,
                "user": user.to_dict(),
            }
        )

    except Exception as e:
        return jsonify({"success": False, "error": str(e)}), 500


@known_users_bp.route("/known-users/<int:user_id>/update", methods=["POST"])
@login_required
def update_known_user(user_id):
    """Update a known user field."""
    try:
        from models.known_user import KnownUser
        from utils.known_users_discovery import update_user_field

        write_error = _require_case_write_access(current_user)
        if write_error:
            return write_error

        data = request.get_json()
        field_name = data.get("field")
        new_value = data.get("value")

        if not field_name:
            return jsonify({"success": False, "error": "Field name required"}), 400

        if field_name == "compromised":
            new_value = bool(new_value)

        success = update_user_field(
            user_id=user_id,
            field_name=field_name,
            new_value=new_value,
            changed_by=current_user.username,
        )

        if success:
            user = KnownUser.query.get(user_id)
            return jsonify(
                {
                    "success": True,
                    "user": user.to_dict(),
                }
            )
        return jsonify({"success": False, "error": "Update failed"}), 400

    except Exception as e:
        return jsonify({"success": False, "error": str(e)}), 500


@known_users_bp.route("/known-users/<int:user_id>/add-alias", methods=["POST"])
@login_required
def add_user_alias(user_id):
    """Add an alias to a known user."""
    try:
        from models.known_user import KnownUser
        from utils.known_users_discovery import add_alias_to_user

        write_error = _require_case_write_access(current_user)
        if write_error:
            return write_error

        data = request.get_json()
        alias = data.get("alias", "").strip()

        if not alias:
            return jsonify({"success": False, "error": "Alias required"}), 400

        success = add_alias_to_user(
            user_id=user_id,
            alias=alias,
            changed_by=current_user.username,
        )

        user = KnownUser.query.get(user_id)
        return jsonify(
            {
                "success": success,
                "user": user.to_dict() if user else None,
            }
        )

    except Exception as e:
        return jsonify({"success": False, "error": str(e)}), 500


@known_users_bp.route("/known-users/<int:user_id>/add-email", methods=["POST"])
@login_required
def add_user_email(user_id):
    """Add an email to a known user."""
    try:
        from models.known_user import KnownUser
        from utils.known_users_discovery import add_email_to_user

        write_error = _require_case_write_access(current_user)
        if write_error:
            return write_error

        data = request.get_json()
        email = data.get("email", "").strip()

        if not email:
            return jsonify({"success": False, "error": "Email required"}), 400

        success = add_email_to_user(
            user_id=user_id,
            email=email,
            changed_by=current_user.username,
        )

        user = KnownUser.query.get(user_id)
        return jsonify(
            {
                "success": success,
                "user": user.to_dict() if user else None,
            }
        )

    except Exception as e:
        return jsonify({"success": False, "error": str(e)}), 500


@known_users_bp.route("/known-users/<int:user_id>/audit")
@login_required
def get_user_audit(user_id):
    """Get audit history for a known user."""
    try:
        from models.known_user import KnownUser
        from utils.known_users_discovery import get_user_audit_history

        user = KnownUser.query.get(user_id)
        if not user:
            return jsonify({"success": False, "error": "User not found"}), 404

        history = get_user_audit_history(user_id)

        return jsonify(
            {
                "success": True,
                "user_id": user_id,
                "username": user.username,
                "audit_history": history,
            }
        )

    except Exception as e:
        return jsonify({"success": False, "error": str(e)}), 500


@known_users_bp.route("/known-users/upload/<case_uuid>", methods=["POST"])
@login_required
def upload_known_users_csv(case_uuid):
    """Upload a CSV file to import known users."""
    from models.known_user import KnownUser, KnownUserAudit

    try:
        case = Case.get_by_uuid(case_uuid)
        if not case:
            return jsonify({"success": False, "error": "Case not found"}), 404

        write_error = _require_case_write_access(current_user)
        if write_error:
            return write_error

        if "file" not in request.files:
            return jsonify({"success": False, "error": "No file uploaded"}), 400

        file = request.files["file"]
        if file.filename == "":
            return jsonify({"success": False, "error": "No file selected"}), 400

        if not file.filename.lower().endswith(".csv"):
            return jsonify({"success": False, "error": "File must be a CSV"}), 400

        content = file.read().decode("utf-8-sig")
        reader = csv.DictReader(io.StringIO(content))

        if reader.fieldnames:
            reader.fieldnames = [h.lower().strip() for h in reader.fieldnames]

        if not reader.fieldnames or "username" not in reader.fieldnames:
            return jsonify({"success": False, "error": 'CSV must have a "username" column'}), 400

        created_count = 0
        updated_count = 0
        skipped_count = 0

        rows = list(reader)

        for row in rows:
            username = row.get("username", "").strip()
            if not username:
                continue

            sid = row.get("sid", "").strip() or None
            email = row.get("email", "").strip() or None
            notes = row.get("notes", "").strip() or None

            compromised_str = row.get("compromised", "").strip().lower()
            compromised = compromised_str in ("true", "yes", "1", "y")

            try:
                existing_user, match_type = KnownUser.find_by_username_sid_alias_or_email(
                    username=username,
                    sid=sid,
                    email=email,
                    case_id=case.id,
                )

                if existing_user:
                    updated = False

                    if sid and existing_user.sid != sid:
                        sid_exists = KnownUser.query.filter(
                            KnownUser.sid == sid,
                            KnownUser.id != existing_user.id,
                        ).first()
                        if not sid_exists:
                            existing_user.sid = sid
                            updated = True

                    if email and existing_user.email != email.lower():
                        existing_user.email = email.lower()
                        updated = True

                    if notes and existing_user.notes != notes:
                        existing_user.notes = notes
                        updated = True

                    if compromised and not existing_user.compromised:
                        existing_user.compromised = True
                        updated = True

                    existing_user.link_to_case(case.id)
                    existing_user.add_source("csv_import")

                    if updated:
                        updated_count += 1
                        KnownUserAudit.log_change(
                            existing_user.id,
                            current_user.username,
                            "csv_import",
                            "update",
                            None,
                            "Updated from CSV upload",
                        )

                    db.session.commit()
                else:
                    if sid:
                        sid_exists = KnownUser.query.filter(
                            KnownUser.sid == sid,
                            KnownUser.case_id == case.id,
                        ).first()
                        if sid_exists:
                            sid_exists.add_alias(username)

                            if email and sid_exists.email != email.lower():
                                sid_exists.email = email.lower()
                            if notes and sid_exists.notes != notes:
                                sid_exists.notes = notes
                            if compromised and not sid_exists.compromised:
                                sid_exists.compromised = True

                            sid_exists.add_source("csv_import")
                            db.session.commit()
                            updated_count += 1
                            continue

                    new_user = KnownUser(
                        case_id=case.id,
                        username=username.upper(),
                        sid=sid,
                        email=email.lower() if email else None,
                        notes=notes,
                        compromised=compromised,
                        added_by=current_user.username,
                        sources=["csv_import"],
                    )
                    db.session.add(new_user)
                    db.session.commit()

                    KnownUserAudit.log_change(
                        new_user.id,
                        current_user.username,
                        "user",
                        "create",
                        None,
                        f"Created from CSV upload: {username}",
                    )
                    db.session.commit()
                    created_count += 1

            except Exception:
                db.session.rollback()
                skipped_count += 1
                continue

        return jsonify(
            {
                "success": True,
                "created": created_count,
                "updated": updated_count,
                "skipped": skipped_count,
            }
        )

    except Exception as e:
        db.session.rollback()
        return jsonify({"success": False, "error": str(e)}), 500


@known_users_bp.route("/known-users/download/<case_uuid>")
@login_required
def download_known_users_csv(case_uuid):
    """Download all known users for a case as CSV."""
    from utils.known_users_discovery import get_users_for_case

    try:
        case = Case.get_by_uuid(case_uuid)
        if not case:
            return jsonify({"success": False, "error": "Case not found"}), 404

        users = get_users_for_case(case.id)

        output = io.StringIO()
        writer = csv.writer(output)

        writer.writerow(
            [
                "username",
                "sid",
                "email",
                "compromised",
                "notes",
                "aliases",
                "sources",
                "artifacts_with_user",
                "last_seen",
            ]
        )

        for user in users:
            aliases = ";".join(user.get("aliases", []))
            sources = ";".join(user.get("sources", []))

            writer.writerow(
                [
                    user.get("username", ""),
                    user.get("sid", ""),
                    user.get("email", ""),
                    "true" if user.get("compromised") else "false",
                    user.get("notes", ""),
                    aliases,
                    sources,
                    user.get("artifacts_with_user", 0),
                    user.get("last_seen", ""),
                ]
            )

        output.seek(0)

        safe_name = "".join(c for c in case.name if c.isalnum() or c in (" ", "-", "_")).strip()
        filename = f"known_users_{safe_name}_{case_uuid[:8]}.csv"

        return Response(
            output.getvalue(),
            mimetype="text/csv",
            headers={"Content-Disposition": f'attachment; filename="{filename}"'},
        )

    except Exception as e:
        return jsonify({"success": False, "error": str(e)}), 500


@known_users_bp.route("/known-users/bulk-update", methods=["POST"])
@login_required
def bulk_update_known_users():
    """Bulk update multiple known users."""
    from models.known_user import KnownUser, KnownUserAudit

    try:
        write_error = _require_case_write_access(current_user)
        if write_error:
            return write_error

        data = request.get_json()
        user_ids = data.get("user_ids", [])
        updates = data.get("updates", {})

        if not user_ids:
            return jsonify({"success": False, "error": "No user IDs provided"}), 400

        if not updates:
            return jsonify({"success": False, "error": "No updates provided"}), 400

        updated_count = 0

        for user_id in user_ids:
            user = KnownUser.query.get(user_id)
            if not user:
                continue

            if "compromised" in updates:
                old_value = user.compromised
                new_value = updates["compromised"]
                if old_value != new_value:
                    user.compromised = new_value
                    KnownUserAudit.log_change(
                        user_id=user.id,
                        changed_by=current_user.username,
                        field_name="compromised",
                        action="update",
                        old_value=str(old_value),
                        new_value=str(new_value),
                    )
                    updated_count += 1

        db.session.commit()

        return jsonify(
            {
                "success": True,
                "updated": updated_count,
            }
        )

    except Exception as e:
        db.session.rollback()
        return jsonify({"success": False, "error": str(e)}), 500


@known_users_bp.route("/known-users/bulk-delete", methods=["POST"])
@login_required
def bulk_delete_known_users():
    """Bulk delete multiple known users."""
    from models.known_user import KnownUser, KnownUserAudit

    try:
        write_error = _require_case_write_access(current_user)
        if write_error:
            return write_error

        data = request.get_json()
        user_ids = data.get("user_ids", [])

        if not user_ids:
            return jsonify({"success": False, "error": "No user IDs provided"}), 400

        deleted_count = 0

        for user_id in user_ids:
            user = KnownUser.query.get(user_id)
            if not user:
                continue

            KnownUserAudit.log_change(
                user_id=user.id,
                changed_by=current_user.username,
                field_name="user",
                action="delete",
                old_value=user.username or user.sid or f"ID:{user.id}",
                new_value=None,
            )

            db.session.delete(user)
            deleted_count += 1

        db.session.commit()

        return jsonify(
            {
                "success": True,
                "deleted": deleted_count,
            }
        )

    except Exception as e:
        db.session.rollback()
        return jsonify({"success": False, "error": str(e)}), 500
