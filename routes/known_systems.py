"""Known systems API routes extracted from the monolithic API module."""

import csv
import io

from flask import Blueprint, Response, jsonify, request
from flask_login import current_user, login_required

from models.case import Case
from models.database import db

known_systems_bp = Blueprint("known_systems", __name__, url_prefix="/api")


@known_systems_bp.route("/known-systems/list/<case_uuid>")
@login_required
def get_known_systems(case_uuid):
    """Get known systems for a case."""
    try:
        from utils.known_systems_discovery import get_systems_for_case

        case = Case.get_by_uuid(case_uuid)
        if not case:
            return jsonify({"success": False, "error": "Case not found"}), 404

        systems = get_systems_for_case(case.id)

        all_sources = set()
        for system in systems:
            sources = system.get("sources", [])
            if sources:
                all_sources.update(sources)

        return jsonify(
            {
                "success": True,
                "case_uuid": case_uuid,
                "systems": systems,
                "total": len(systems),
                "aggregate_sources": sorted(list(all_sources)),
            }
        )

    except Exception as e:
        return jsonify({"success": False, "error": str(e)}), 500


@known_systems_bp.route("/known-systems/discover/<case_uuid>", methods=["POST"])
@login_required
def discover_systems(case_uuid):
    """Start async discovery of known systems from artifacts."""
    try:
        from tasks.celery_tasks import discover_known_systems_task
        from utils.known_systems_discovery import get_discovery_progress

        case = Case.get_by_uuid(case_uuid)
        if not case:
            return jsonify({"success": False, "error": "Case not found"}), 404

        progress = get_discovery_progress(case_uuid)
        if progress and progress.get("status") == "running":
            return jsonify(
                {
                    "success": True,
                    "status": "already_running",
                    "progress": progress,
                }
            )

        task = discover_known_systems_task.delay(
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


@known_systems_bp.route("/known-systems/discover-progress/<case_uuid>")
@login_required
def get_discovery_status(case_uuid):
    """Get discovery progress for a case."""
    try:
        from utils.known_systems_discovery import get_discovery_progress

        case = Case.get_by_uuid(case_uuid)
        if not case:
            return jsonify({"success": False, "error": "Case not found"}), 404

        progress = get_discovery_progress(case_uuid)

        return jsonify(
            {
                "success": True,
                "progress": progress,
            }
        )

    except Exception as e:
        return jsonify({"success": False, "error": str(e)}), 500


@known_systems_bp.route("/known-systems/<int:system_id>")
@login_required
def get_known_system(system_id):
    """Get details for a specific known system."""
    try:
        from models.known_system import KnownSystem

        system = KnownSystem.query.get(system_id)
        if not system:
            return jsonify({"success": False, "error": "System not found"}), 404

        return jsonify(
            {
                "success": True,
                "system": system.to_dict(),
            }
        )

    except Exception as e:
        return jsonify({"success": False, "error": str(e)}), 500


@known_systems_bp.route("/known-systems/<int:system_id>/update", methods=["POST"])
@login_required
def update_known_system(system_id):
    """Update a known system field."""
    try:
        from models.known_system import KnownSystem, OSType, SystemType
        from utils.known_systems_discovery import update_system_field

        data = request.get_json()
        field_name = data.get("field")
        new_value = data.get("value")

        if not field_name:
            return jsonify({"success": False, "error": "Field name required"}), 400

        if field_name == "os_type" and new_value and new_value not in OSType.all():
            return jsonify({"success": False, "error": f"Invalid os_type: {new_value}"}), 400

        if field_name == "system_type" and new_value and new_value not in SystemType.all():
            return jsonify({"success": False, "error": f"Invalid system_type: {new_value}"}), 400

        if field_name == "compromised":
            new_value = bool(new_value)

        success = update_system_field(
            system_id=system_id,
            field_name=field_name,
            new_value=new_value,
            username=current_user.username,
        )

        if success:
            system = KnownSystem.query.get(system_id)
            return jsonify(
                {
                    "success": True,
                    "system": system.to_dict(),
                }
            )
        return jsonify({"success": False, "error": "Update failed"}), 400

    except Exception as e:
        return jsonify({"success": False, "error": str(e)}), 500


@known_systems_bp.route("/known-systems/<int:system_id>/add-ip", methods=["POST"])
@login_required
def add_system_ip(system_id):
    """Add an IP address to a known system."""
    try:
        from models.known_system import KnownSystem
        from utils.known_systems_discovery import add_ip_to_system

        data = request.get_json()
        ip_address = data.get("ip_address", "").strip()

        if not ip_address:
            return jsonify({"success": False, "error": "IP address required"}), 400

        success = add_ip_to_system(
            system_id=system_id,
            ip_address=ip_address,
            username=current_user.username,
        )

        system = KnownSystem.query.get(system_id)
        return jsonify(
            {
                "success": success,
                "system": system.to_dict() if system else None,
            }
        )

    except Exception as e:
        return jsonify({"success": False, "error": str(e)}), 500


@known_systems_bp.route("/known-systems/<int:system_id>/add-share", methods=["POST"])
@login_required
def add_system_share(system_id):
    """Add a share to a known system."""
    try:
        from models.known_system import KnownSystem
        from utils.known_systems_discovery import add_share_to_system

        data = request.get_json()
        share_name = data.get("share_name", "").strip()
        share_path = data.get("share_path", "").strip()

        if not share_name:
            return jsonify({"success": False, "error": "Share name required"}), 400

        success = add_share_to_system(
            system_id=system_id,
            share_name=share_name,
            share_path=share_path if share_path else None,
            username=current_user.username,
        )

        system = KnownSystem.query.get(system_id)
        return jsonify(
            {
                "success": success,
                "system": system.to_dict() if system else None,
            }
        )

    except Exception as e:
        return jsonify({"success": False, "error": str(e)}), 500


@known_systems_bp.route("/known-systems/<int:system_id>/audit")
@login_required
def get_system_audit(system_id):
    """Get audit history for a known system."""
    try:
        from models.known_system import KnownSystem
        from utils.known_systems_discovery import get_system_audit_history

        system = KnownSystem.query.get(system_id)
        if not system:
            return jsonify({"success": False, "error": "System not found"}), 404

        history = get_system_audit_history(system_id)

        return jsonify(
            {
                "success": True,
                "system_id": system_id,
                "hostname": system.hostname,
                "audit_history": history,
            }
        )

    except Exception as e:
        return jsonify({"success": False, "error": str(e)}), 500


@known_systems_bp.route("/known-systems/upload/<case_uuid>", methods=["POST"])
@login_required
def upload_known_systems_csv(case_uuid):
    """Upload a CSV file to import known systems."""
    from models.known_system import KnownSystem, KnownSystemAudit

    try:
        case = Case.get_by_uuid(case_uuid)
        if not case:
            return jsonify({"success": False, "error": "Case not found"}), 404

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

        if not reader.fieldnames or "hostname" not in reader.fieldnames:
            return jsonify({"success": False, "error": 'CSV must have a "hostname" column'}), 400

        created_count = 0
        updated_count = 0
        skipped_count = 0

        valid_system_types = ["workstation", "server", "router", "switch", "printer", "other"]
        valid_os_types = ["windows", "linux", "mac", "other"]

        rows = list(reader)

        for row in rows:
            hostname = row.get("hostname", "").strip()
            if not hostname:
                continue

            netbios_name, full_hostname = KnownSystem.extract_netbios_name(hostname)
            if not netbios_name:
                continue

            system_type = row.get("system_type", "").strip()
            os_type = row.get("os_type", "").strip()
            os_version = row.get("os_version", "").strip() or None
            notes = row.get("notes", "").strip() or None
            ip_addresses_str = row.get("ip_addresses", "").strip()

            if system_type and system_type.lower() in valid_system_types:
                system_type = system_type.capitalize()
            else:
                system_type = None

            if os_type and os_type.lower() in valid_os_types:
                os_type = os_type.capitalize()
            else:
                os_type = None

            compromised_str = row.get("compromised", "").strip().lower()
            compromised = compromised_str in ("true", "yes", "1", "y")

            ip_addresses = []
            if ip_addresses_str:
                ip_addresses = [ip.strip() for ip in ip_addresses_str.split(";") if ip.strip()]

            try:
                existing_system, _ = KnownSystem.find_by_hostname_or_alias(netbios_name, case_id=case.id)

                if existing_system:
                    updated = False

                    if system_type and existing_system.system_type != system_type:
                        existing_system.system_type = system_type
                        updated = True

                    if os_type and existing_system.os_type != os_type:
                        existing_system.os_type = os_type
                        updated = True

                    if os_version and existing_system.os_version != os_version:
                        existing_system.os_version = os_version
                        updated = True

                    if notes and existing_system.notes != notes:
                        existing_system.notes = notes
                        updated = True

                    if compromised and not existing_system.compromised:
                        existing_system.compromised = True
                        updated = True

                    for ip in ip_addresses:
                        existing_system.add_ip(ip)

                    if full_hostname and full_hostname != netbios_name:
                        existing_system.add_alias(full_hostname)

                    existing_system.link_to_case(case.id)
                    existing_system.add_source("csv_import")

                    if updated:
                        updated_count += 1
                        KnownSystemAudit.log_change(
                            existing_system.id,
                            current_user.username,
                            "csv_import",
                            "update",
                            None,
                            "Updated from CSV upload",
                        )

                    db.session.commit()
                else:
                    new_system = KnownSystem(
                        case_id=case.id,
                        hostname=netbios_name,
                        system_type=system_type,
                        os_type=os_type,
                        os_version=os_version,
                        notes=notes,
                        compromised=compromised,
                        sources=["csv_import"],
                    )
                    db.session.add(new_system)
                    db.session.commit()

                    for ip in ip_addresses:
                        new_system.add_ip(ip)

                    if full_hostname and full_hostname != netbios_name:
                        new_system.add_alias(full_hostname)

                    KnownSystemAudit.log_change(
                        new_system.id,
                        current_user.username,
                        "system",
                        "create",
                        None,
                        f"Created from CSV upload: {netbios_name}",
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


@known_systems_bp.route("/known-systems/download/<case_uuid>")
@login_required
def download_known_systems_csv(case_uuid):
    """Download all known systems for a case as CSV."""
    from utils.known_systems_discovery import get_systems_for_case

    try:
        case = Case.get_by_uuid(case_uuid)
        if not case:
            return jsonify({"success": False, "error": "Case not found"}), 404

        systems = get_systems_for_case(case.id)

        output = io.StringIO()
        writer = csv.writer(output)

        writer.writerow(
            [
                "hostname",
                "system_type",
                "os_type",
                "os_version",
                "compromised",
                "notes",
                "ip_addresses",
                "aliases",
                "sources",
                "artifacts_with_hostname",
                "last_seen",
            ]
        )

        for system in systems:
            ip_addresses = ";".join(system.get("ip_addresses", []))
            aliases = ";".join(system.get("aliases", []))
            sources = ";".join(system.get("sources", []))

            writer.writerow(
                [
                    system.get("hostname", ""),
                    system.get("system_type", ""),
                    system.get("os_type", ""),
                    system.get("os_version", ""),
                    "true" if system.get("compromised") else "false",
                    system.get("notes", ""),
                    ip_addresses,
                    aliases,
                    sources,
                    system.get("artifacts_with_hostname", 0),
                    system.get("last_seen", ""),
                ]
            )

        output.seek(0)

        safe_name = "".join(c for c in case.name if c.isalnum() or c in (" ", "-", "_")).strip()
        filename = f"known_systems_{safe_name}_{case_uuid[:8]}.csv"

        return Response(
            output.getvalue(),
            mimetype="text/csv",
            headers={"Content-Disposition": f'attachment; filename="{filename}"'},
        )

    except Exception as e:
        return jsonify({"success": False, "error": str(e)}), 500


@known_systems_bp.route("/known-systems/bulk-update", methods=["POST"])
@login_required
def bulk_update_known_systems():
    """Bulk update multiple known systems."""
    from models.known_system import KnownSystem, KnownSystemAudit

    try:
        data = request.get_json()
        system_ids = data.get("system_ids", [])
        updates = data.get("updates", {})

        if not system_ids:
            return jsonify({"success": False, "error": "No system IDs provided"}), 400

        if not updates:
            return jsonify({"success": False, "error": "No updates provided"}), 400

        updated_count = 0

        for system_id in system_ids:
            system = KnownSystem.query.get(system_id)
            if not system:
                continue

            changed = False

            if "system_type" in updates:
                old_value = system.system_type
                new_value = updates["system_type"]
                if old_value != new_value:
                    system.system_type = new_value
                    KnownSystemAudit.log_change(
                        system_id=system.id,
                        changed_by=current_user.username,
                        field_name="system_type",
                        action="update",
                        old_value=old_value,
                        new_value=new_value,
                    )
                    changed = True

            if "os_type" in updates:
                old_value = system.os_type
                new_value = updates["os_type"]
                if old_value != new_value:
                    system.os_type = new_value
                    KnownSystemAudit.log_change(
                        system_id=system.id,
                        changed_by=current_user.username,
                        field_name="os_type",
                        action="update",
                        old_value=old_value,
                        new_value=new_value,
                    )
                    changed = True

            if "compromised" in updates:
                old_value = system.compromised
                new_value = updates["compromised"]
                if old_value != new_value:
                    system.compromised = new_value
                    KnownSystemAudit.log_change(
                        system_id=system.id,
                        changed_by=current_user.username,
                        field_name="compromised",
                        action="update",
                        old_value=str(old_value),
                        new_value=str(new_value),
                    )
                    changed = True

            if changed:
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


@known_systems_bp.route("/known-systems/bulk-delete", methods=["POST"])
@login_required
def bulk_delete_known_systems():
    """Bulk delete multiple known systems."""
    from models.known_system import KnownSystem, KnownSystemAudit

    try:
        data = request.get_json()
        system_ids = data.get("system_ids", [])

        if not system_ids:
            return jsonify({"success": False, "error": "No system IDs provided"}), 400

        deleted_count = 0

        for system_id in system_ids:
            system = KnownSystem.query.get(system_id)
            if not system:
                continue

            KnownSystemAudit.log_change(
                system_id=system.id,
                changed_by=current_user.username,
                field_name="system",
                action="delete",
                old_value=system.hostname,
                new_value=None,
            )

            db.session.delete(system)
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
