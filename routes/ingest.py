"""Upload and ingest API routes."""

import hashlib
import json
import logging
import os
import re
import shutil
import zipfile
from datetime import datetime

from flask import Blueprint, Response, jsonify, request, stream_with_context
from flask_login import current_user, login_required

from config import Config
from models.audit_log import AuditAction, AuditEntityType, AuditLog
from models.case import Case
from models.case_file import CaseFile, ExtractionStatus
from models.case_work import CaseWorkActivityType
from models.database import db
from routes.route_helpers import _default_upload_type_label, _get_parser_hints_for_case_file
from utils.case_work import safe_log_case_work_activity
from utils.artifact_paths import (
    copy_to_directory,
    ensure_case_artifact_paths,
    ensure_case_originals_subdir,
    is_within_any_root,
)
from utils.archive_extraction import extract_zip_archive

logger = logging.getLogger(__name__)

ingest_bp = Blueprint("ingest", __name__, url_prefix="/api")


KAPE_TIMESTAMP_HOST_RE = re.compile(r"^\d{4}-\d{2}-\d{2}T\d{6}_([^_./\\]+)")


def _log_case_file_audit(action: str, case_uuid: str, entity_name: str, details: dict):
    """Write a summarized case-file audit record without breaking the request."""
    try:
        AuditLog.log(
            entity_type=AuditEntityType.CASE_FILE,
            entity_id=case_uuid,
            entity_name=entity_name,
            action=action,
            case_uuid=case_uuid,
            details=details,
        )
    except Exception as e:
        logger.warning("Failed to write case file audit log (%s) for %s: %s", action, case_uuid, e)


def _derive_upload_hostname(file_info: dict) -> str:
    """Normalize common acquisition filenames into a case host name."""
    file_info = file_info or {}
    candidates = [
        file_info.get("host"),
        file_info.get("hostname"),
        file_info.get("name"),
        os.path.basename(str(file_info.get("path") or "")),
    ]
    for candidate in candidates:
        value = str(candidate or "").strip()
        if not value:
            continue
        match = KAPE_TIMESTAMP_HOST_RE.match(value)
        if match:
            return match.group(1).upper()
    host = str(file_info.get("host") or file_info.get("hostname") or "").strip()
    return host.upper() if host else ""


def _normalize_upload_file_info(file_info: dict) -> dict:
    """Return a file-info payload with a canonical upload type label."""
    from parsers.catalog import resolve_upload_type_selection

    normalized = resolve_upload_type_selection((file_info or {}).get("type", ""))
    normalized_file_info = dict(file_info or {})
    normalized_file_info["type"] = normalized["label"]
    normalized_file_info["host"] = _derive_upload_hostname(normalized_file_info)
    normalized_file_info["parser_hints"] = list(normalized.get("parser_hints", []))
    normalized_file_info["is_archive_hint"] = bool(normalized.get("is_archive"))
    return normalized_file_info


def _upload_file_hash_key(file_info: dict) -> str:
    """Return a stable lookup key for preflight hash reuse."""
    file_info = file_info or {}
    queue_id = file_info.get("id")
    if queue_id is not None and str(queue_id).strip():
        return f"queue:{str(queue_id).strip()}"

    source = (file_info.get("source") or "web").strip().lower()
    if source == "folder":
        source_path = (file_info.get("path") or "").strip()
        if source_path:
            return f"folder:{source_path}"

    filename = (file_info.get("name") or "").strip()
    return f"{source}:{filename}"


def _lookup_preflight_hash(file_info: dict, file_hashes: dict):
    """Resolve the best available preflight hash for an upload entry."""
    file_hashes = file_hashes or {}
    lookup_key = _upload_file_hash_key(file_info)
    if lookup_key in file_hashes:
        return file_hashes.get(lookup_key)

    # Backward compatibility for older clients that still key by bare filename.
    filename = (file_info or {}).get("name")
    if filename in file_hashes:
        return file_hashes.get(filename)

    return None


def _move_to_originals(file_path: str, case_uuid: str, filename: str) -> str:
    """Move an original uploaded file into the retained originals tree."""
    if not file_path or not os.path.exists(file_path):
        return None

    originals_dir = ensure_case_originals_subdir(case_uuid)
    dest_path = os.path.join(originals_dir, filename)

    try:
        os.makedirs(originals_dir, exist_ok=True)
        try:
            shutil.chown(originals_dir, user="casescope", group="casescope")
        except (PermissionError, LookupError):
            pass

        if os.path.exists(dest_path):
            base, ext = os.path.splitext(filename)
            counter = 1
            while os.path.exists(dest_path):
                dest_path = os.path.join(originals_dir, f"{base}_{counter}{ext}")
                counter += 1

        shutil.move(file_path, dest_path)

        try:
            shutil.chown(dest_path, user="casescope", group="casescope")
        except (PermissionError, LookupError):
            pass

        logger.info("Moved original file to originals: %s -> %s", file_path, dest_path)
        return dest_path

    except Exception as e:
        logger.error("Failed to move original file to originals: %s: %s", file_path, e)
        return None


def _copy_to_staging(source_path: str, staging_dir: str, filename: str) -> str:
    """Copy a retained original into staging for transient processing."""
    if not source_path or not os.path.exists(source_path):
        return None

    try:
        return copy_to_directory(source_path, staging_dir, filename)
    except Exception as e:
        logger.error("Failed to copy original into staging: %s: %s", source_path, e)
        return None


def _remove_file_if_present(file_path: str):
    """Best-effort removal for transient files."""
    if not file_path or not os.path.exists(file_path):
        return
    try:
        os.remove(file_path)
    except IsADirectoryError:
        shutil.rmtree(file_path, ignore_errors=True)
    except OSError:
        pass


WEB_UPLOAD_DIR = "/opt/casescope/uploads/web"
SFTP_UPLOAD_DIR = "/opt/casescope/uploads/sftp"
CHUNK_TEMP_DIR = "/opt/casescope/uploads/temp"
STAGING_DIR = "/opt/casescope/staging"


def ensure_upload_dirs(case_uuid):
    """Ensure upload directories exist for a case."""
    paths = ensure_case_artifact_paths(case_uuid)
    web_path = paths["web_upload"]
    sftp_path = paths["sftp_upload"]
    staging_path = paths["staging"]
    os.makedirs(CHUNK_TEMP_DIR, exist_ok=True)
    return web_path, sftp_path, staging_path


def _viewer_upload_error():
    return jsonify({"success": False, "error": "Viewers cannot modify uploaded artifacts"}), 403


def _allowed_case_upload_roots(case_uuid):
    paths = ensure_case_artifact_paths(case_uuid)
    return [paths["web_upload"], paths["sftp_upload"], paths["staging"], paths["storage"]]


@ingest_bp.route("/upload/scan/<case_uuid>")
@login_required
def scan_upload_folder(case_uuid):
    """Scan the SFTP folder for uploaded files."""
    try:
        case = Case.get_by_uuid(case_uuid)
        if not case:
            return jsonify({"success": False, "error": "Case not found"}), 404

        _, sftp_path, _ = ensure_upload_dirs(case_uuid)

        files = []
        if os.path.exists(sftp_path):
            for filename in os.listdir(sftp_path):
                filepath = os.path.join(sftp_path, filename)
                if os.path.isfile(filepath):
                    stat = os.stat(filepath)
                    files.append(
                        {
                            "name": filename,
                            "path": filepath,
                            "size": stat.st_size,
                            "modified": datetime.fromtimestamp(stat.st_mtime).isoformat(),
                        }
                    )

        return jsonify({"success": True, "path": sftp_path, "files": files})

    except Exception as e:
        return jsonify({"success": False, "error": str(e)}), 500


@ingest_bp.route("/upload/chunk", methods=["POST"])
@login_required
def upload_chunk():
    """Handle chunked file upload."""
    import fcntl

    try:
        if current_user.permission_level == "viewer":
            return _viewer_upload_error()

        chunk = request.files.get("chunk")
        chunk_index = int(request.form.get("chunkIndex", 0))
        total_chunks = int(request.form.get("totalChunks", 1))
        upload_id = (request.form.get("uploadId") or "").strip()
        filename = os.path.basename((request.form.get("filename") or "").strip())
        case_uuid = (request.form.get("caseUuid") or "").strip()

        if not all([chunk, upload_id, filename, case_uuid]):
            return jsonify({"success": False, "error": "Missing required fields"}), 400

        case = Case.get_by_uuid(case_uuid)
        if not case:
            return jsonify({"success": False, "error": "Case not found"}), 404

        web_path, _, _ = ensure_upload_dirs(case_uuid)
        temp_dir = os.path.join(CHUNK_TEMP_DIR, upload_id)
        os.makedirs(temp_dir, exist_ok=True)

        chunk_path = os.path.join(temp_dir, f"chunk_{chunk_index:06d}")
        chunk.save(chunk_path)

        existing_chunks = len([f for f in os.listdir(temp_dir) if f.startswith("chunk_")])

        if existing_chunks >= total_chunks:
            lock_file_path = os.path.join(temp_dir, ".combine_lock")
            try:
                with open(lock_file_path, "w") as lock_file:
                    fcntl.flock(lock_file.fileno(), fcntl.LOCK_EX | fcntl.LOCK_NB)

                    existing_chunks = len([f for f in os.listdir(temp_dir) if f.startswith("chunk_")])
                    if existing_chunks < total_chunks:
                        return jsonify({"success": True, "complete": False, "chunksReceived": existing_chunks})

                    final_path = os.path.join(web_path, filename)
                    if os.path.exists(final_path):
                        base, ext = os.path.splitext(filename)
                        counter = 1
                        while os.path.exists(final_path):
                            final_path = os.path.join(web_path, f"{base}_{counter}{ext}")
                            counter += 1

                    with open(final_path, "wb") as outfile:
                        for i in range(total_chunks):
                            chunk_file = os.path.join(temp_dir, f"chunk_{i:06d}")
                            with open(chunk_file, "rb") as infile:
                                outfile.write(infile.read())

                    try:
                        shutil.chown(final_path, user="casescope", group="casescope")
                    except (PermissionError, LookupError):
                        pass

                    shutil.rmtree(temp_dir, ignore_errors=True)

                    return jsonify({"success": True, "complete": True, "path": final_path})

            except BlockingIOError:
                return jsonify(
                    {
                        "success": True,
                        "complete": False,
                        "chunksReceived": existing_chunks,
                        "combining": True,
                    }
                )

        return jsonify({"success": True, "complete": False, "chunksReceived": existing_chunks})

    except Exception as e:
        return jsonify({"success": False, "error": str(e)}), 500


@ingest_bp.route("/upload/preflight", methods=["POST"])
@login_required
def preflight_check():
    """Check for duplicate files before ingestion."""
    try:
        data = request.get_json()
        case_uuid = data.get("caseUuid")
        files = data.get("files", [])

        if not case_uuid:
            return jsonify({"success": False, "error": "Case UUID required"}), 400

        if not files:
            return jsonify({"success": False, "error": "No files to check"}), 400

        case = Case.get_by_uuid(case_uuid)
        if not case:
            return jsonify({"success": False, "error": "Case not found"}), 404

        if current_user.permission_level == "viewer":
            return _viewer_upload_error()

        web_path, sftp_path, _ = ensure_upload_dirs(case_uuid)
        allowed_roots = _allowed_case_upload_roots(case_uuid)

        duplicates = []
        file_hashes = {}
        hash_errors = []

        for file_info in files:
            filename = file_info.get("name")
            source = file_info.get("source", "web")
            lookup_key = _upload_file_hash_key(file_info)

            if source == "folder":
                source_path = file_info.get("path")
            else:
                source_path = os.path.join(web_path, filename)

            if source_path and not is_within_any_root(source_path, allowed_roots):
                continue

            if not source_path or not os.path.exists(source_path):
                continue

            try:
                file_hash = CaseFile.calculate_sha256(source_path)
                file_hashes[lookup_key] = file_hash
                existing = CaseFile.find_by_hash(file_hash, case_uuid=case_uuid)
                if existing:
                    duplicates.append(
                        {
                            "new_file": filename,
                            "new_hash": file_hash,
                            "existing_file": existing.filename,
                            "existing_hash": existing.sha256_hash,
                            "existing_case": existing.case_uuid,
                            "uploaded_at": existing.uploaded_at.strftime("%Y-%m-%d %H:%M:%S"),
                            "source": source,
                        }
                    )
            except Exception as exc:
                logger.warning("Preflight hashing failed for %s (%s): %s", filename, lookup_key, exc)
                hash_errors.append(
                    {
                        "file": filename,
                        "lookup_key": lookup_key,
                        "source": source,
                        "error": str(exc),
                    }
                )

        _log_case_file_audit(
            action=AuditAction.PREFLIGHT,
            case_uuid=case_uuid,
            entity_name="Case file preflight",
            details={
                "requested_files": len(files),
                "duplicate_count": len(duplicates),
                "hash_error_count": len(hash_errors),
                "duplicate_samples": [d["new_file"] for d in duplicates[:10]],
                "sources": sorted({(f.get("source") or "web") for f in files}),
            },
        )

        return jsonify(
            {
                "success": True,
                "duplicates": duplicates,
                "file_hashes": file_hashes,
                "hash_errors": hash_errors,
                "has_duplicates": len(duplicates) > 0,
            }
        )

    except Exception as e:
        return jsonify({"success": False, "error": str(e)}), 500


@ingest_bp.route("/upload/ingest", methods=["POST"])
@login_required
def ingest_files():
    """Process and ingest files with streaming progress updates."""
    data = request.get_json()
    case_uuid = data.get("caseUuid")
    files = data.get("files", [])
    skip_files = data.get("skipFiles", [])
    file_hashes = data.get("fileHashes", {})
    uploaded_by = current_user.username

    if not case_uuid:
        return jsonify({"success": False, "error": "Case UUID required"}), 400

    if not files:
        return jsonify({"success": False, "error": "No files to ingest"}), 400

    if current_user.permission_level == "viewer":
        return _viewer_upload_error()

    case = Case.get_by_uuid(case_uuid)
    if not case:
        return jsonify({"success": False, "error": "Case not found"}), 404
    case_id = case.id

    def generate_progress():
        import time as _time

        HEARTBEAT_INTERVAL = 10

        web_path, sftp_path, staging_path = ensure_upload_dirs(case_uuid)
        allowed_roots = _allowed_case_upload_roots(case_uuid)

        ingested_count = 0
        extracted_count = 0
        duplicates_skipped = 0
        duplicates_deleted = 0
        archived_count = 0
        duplicate_true_count = 0
        duplicate_hash_only_count = 0
        queued_count_total = 0
        extraction_failures = []
        errors = []
        processed_files = []
        zip_files = []
        zip_records = {}
        non_zip_files = []

        _log_case_file_audit(
            action=AuditAction.UPLOADED,
            case_uuid=case_uuid,
            entity_name="Case file ingest started",
            details={
                "requested_files": len(files),
                "skip_files": len(skip_files),
                "sources": sorted({(f.get("source") or "web") for f in files}),
            },
        )
        safe_log_case_work_activity(
            case_uuid,
            CaseWorkActivityType.UPLOAD_STARTED,
            "Started case file ingest",
            details={
                "requested_files": len(files),
                "skip_files": len(skip_files),
                "sources": sorted({(f.get("source") or "web") for f in files}),
                "file_names": [f.get("name") for f in files[:25]],
                "file_name_count": len(files),
            },
            user_id=getattr(current_user, "id", None),
            username=getattr(current_user, "username", "system"),
        )

        for file_info in files:
            file_info = _normalize_upload_file_info(file_info)
            filename = file_info.get("name")
            source = file_info.get("source", "web")

            if filename in skip_files:
                duplicates_skipped += 1
                continue

            if source == "folder":
                source_path = file_info.get("path")
            else:
                source_path = os.path.join(web_path, filename)

            if source_path and not is_within_any_root(source_path, allowed_roots):
                errors.append(f"Invalid source path for {filename}")
                continue

            if not source_path or not os.path.exists(source_path):
                errors.append(f"File not found: {filename}")
                continue

            is_zip = CaseFile.is_zip_file(source_path)
            file_data = {
                "name": filename,
                "source_path": source_path,
                "file_info": file_info,
                "is_zip": is_zip,
                "hash": _lookup_preflight_hash(file_info, file_hashes),
            }

            if is_zip:
                zip_files.append(file_data)
            else:
                non_zip_files.append(file_data)

        if zip_files:
            total_zips = len(zip_files)
            for idx, zf in enumerate(zip_files):
                yield json.dumps(
                    {
                        "stage": "extract",
                        "current": idx + 1,
                        "total": total_zips,
                        "filename": zf["name"],
                        "detail": "Preparing archive...",
                    }
                ) + "\n"

                source_path = zf["source_path"]
                filename = zf["name"]
                file_info = zf["file_info"]

                zip_hash = zf.get("hash")
                if not zip_hash:
                    yield json.dumps(
                        {
                            "stage": "extract",
                            "current": idx + 1,
                            "total": total_zips,
                            "filename": zf["name"],
                            "detail": "Preflight hash unavailable; hashing archive before extract...",
                        }
                    ) + "\n"
                    try:
                        hasher = hashlib.sha256()
                        last_heartbeat = _time.monotonic()
                        with open(source_path, "rb") as hf:
                            while True:
                                chunk = hf.read(1048576)
                                if not chunk:
                                    break
                                hasher.update(chunk)
                                now = _time.monotonic()
                                if now - last_heartbeat >= HEARTBEAT_INTERVAL:
                                    last_heartbeat = now
                                    yield json.dumps(
                                        {
                                            "stage": "extract",
                                            "current": idx + 1,
                                            "total": total_zips,
                                            "filename": zf["name"],
                                            "detail": "Hashing archive...",
                                        }
                                    ) + "\n"
                        zip_hash = hasher.hexdigest()
                    except Exception as e:
                        errors.append(f"Error hashing {filename}: {str(e)}")
                        continue

                zip_size = os.path.getsize(source_path)
                hash_prefix = zip_hash[:8] if zip_hash else str(int(datetime.utcnow().timestamp()))
                unique_zip_key = f"{filename}_{hash_prefix}"
                extract_dir = os.path.join(staging_path, unique_zip_key)
                os.makedirs(extract_dir, exist_ok=True)

                try:
                    shutil.chown(extract_dir, user="casescope", group="casescope")
                except (PermissionError, LookupError):
                    pass

                extraction_status = ExtractionStatus.FAIL
                extracted_file_count = 0
                extraction_details = {}

                try:
                    yield json.dumps(
                        {
                            "stage": "extract",
                            "current": idx + 1,
                            "total": total_zips,
                            "filename": zf["name"],
                            "detail": "Extracting archive...",
                        }
                    ) + "\n"
                    extraction_details = extract_zip_archive(
                        source_path,
                        extract_dir,
                        max_members=50000,
                        max_uncompressed_bytes=Config.ARCHIVE_MAX_UNCOMPRESSED_BYTES,
                    )
                    logger.info(
                        "Extracted upload archive %s with %s (methods=%s, members=%s)",
                        filename,
                        extraction_details.get("extraction_method"),
                        extraction_details.get("methods"),
                        extraction_details.get("member_count"),
                    )
                    extraction_status = ExtractionStatus.FULL

                    for root, dirs, extracted_files_list in os.walk(extract_dir):
                        for extracted_name in extracted_files_list:
                            extracted_path = os.path.join(root, extracted_name)
                            rel_path = os.path.relpath(extracted_path, extract_dir)
                            processed_files.append(
                                {
                                    "path": extracted_path,
                                    "filename": rel_path,
                                    "original_filename": extracted_name,
                                    "file_info": file_info,
                                    "is_archive": CaseFile.is_zip_file(extracted_path),
                                    "is_extracted": True,
                                    "parent_zip": unique_zip_key,
                                    "parent_zip_name": filename,
                                    "retained_original_path": None,
                                }
                            )
                            extracted_file_count += 1

                except zipfile.BadZipFile:
                    extraction_status = ExtractionStatus.FAIL
                    extraction_failures.append(f"{filename}: Invalid ZIP file")
                    non_zip_files.append(zf)
                except Exception as e:
                    extracted_count_check = sum(1 for walk_result in os.walk(extract_dir) for _ in walk_result[2])
                    if extracted_count_check > 0:
                        extraction_status = ExtractionStatus.PARTIAL
                        extraction_failures.append(f"{filename}: Partial extraction - {str(e)}")
                    else:
                        extraction_status = ExtractionStatus.FAIL
                        extraction_failures.append(f"{filename}: {str(e)}")

                zip_record = CaseFile(
                    case_uuid=case_uuid,
                    parent_id=None,
                    filename=filename,
                    original_filename=filename,
                    file_path=None,
                    source_path=source_path,
                    file_size=zip_size,
                    sha256_hash=zip_hash,
                    hostname=file_info.get("host", ""),
                    file_type=file_info.get("type", _default_upload_type_label()),
                    upload_source=file_info.get("source", "web"),
                    is_archive=True,
                    is_extracted=False,
                    extraction_status=extraction_status,
                    status="new",
                    retention_state="archived",
                    uploaded_by=uploaded_by,
                )
                db.session.add(zip_record)
                db.session.flush()
                zip_records[unique_zip_key] = {
                    "record": zip_record,
                    "source_path": source_path,
                    "filename": filename,
                }
                if extraction_status in (ExtractionStatus.FULL, ExtractionStatus.PARTIAL):
                    from utils.acquisition_events import emit_cylr_acquisition_event

                    emit_cylr_acquisition_event(
                        case_id=case_id,
                        case_file_id=zip_record.id,
                        archive_name=filename,
                        source_path=source_path,
                        source_host=file_info.get("host", ""),
                        file_type=file_info.get("type", _default_upload_type_label()),
                        upload_source=file_info.get("source", "web"),
                        extraction_status=extraction_status,
                        extracted_file_count=extracted_file_count,
                        extraction_details=extraction_details,
                    )
                ingested_count += 1

        if non_zip_files:
            total_non_zip = len(non_zip_files)
            for idx, nzf in enumerate(non_zip_files):
                yield json.dumps(
                    {
                        "stage": "move",
                        "current": idx + 1,
                        "total": total_non_zip,
                        "filename": nzf["name"],
                    }
                ) + "\n"

                try:
                    source_path = nzf["source_path"]
                    filename = nzf["name"]
                    file_info = nzf["file_info"]
                    retained_original = _move_to_originals(source_path, case_uuid, filename)
                    if not retained_original:
                        raise RuntimeError("Failed to retain original upload")

                    dest_path = _copy_to_staging(retained_original, staging_path, filename)
                    if not dest_path:
                        raise RuntimeError("Failed to create staging copy from retained original")

                    processed_files.append(
                        {
                            "path": dest_path,
                            "filename": os.path.basename(dest_path),
                            "original_filename": filename,
                            "file_info": file_info,
                            "is_archive": False,
                            "is_extracted": False,
                            "parent_zip": None,
                            "parent_zip_name": None,
                            "hash": nzf.get("hash"),
                            "retained_original_path": retained_original,
                        }
                    )
                    ingested_count += 1

                except Exception as e:
                    errors.append(f'Error moving {nzf["name"]}: {str(e)}')

        total_processed = len(processed_files)
        hash_batch_commit_size = 500
        last_progress_yield = _time.monotonic()

        existing_by_hash = {}
        existing_by_name = {}
        existing_records = CaseFile.query.filter_by(case_uuid=case_uuid).all()
        for er in existing_records:
            if er.sha256_hash:
                existing_by_hash[er.sha256_hash] = er
            if er.original_filename:
                existing_by_name[er.original_filename] = er

        for idx, pf in enumerate(processed_files):
            now = _time.monotonic()
            if idx == 0 or (now - last_progress_yield) >= 0.5 or (idx + 1) % 200 == 0 or idx == total_processed - 1:
                last_progress_yield = now
                yield json.dumps(
                    {
                        "stage": "hash",
                        "current": idx + 1,
                        "total": total_processed,
                        "filename": pf["filename"],
                    }
                ) + "\n"

            try:
                file_path = pf["path"]
                file_size = os.path.getsize(file_path)

                sha256_hash = pf.get("hash")
                if not sha256_hash:
                    hasher = hashlib.sha256()
                    last_heartbeat = _time.monotonic()
                    with open(file_path, "rb") as hf:
                        while True:
                            chunk = hf.read(1048576)
                            if not chunk:
                                break
                            hasher.update(chunk)
                            now = _time.monotonic()
                            if now - last_heartbeat >= HEARTBEAT_INTERVAL:
                                last_heartbeat = now
                                yield json.dumps(
                                    {
                                        "stage": "hash",
                                        "current": idx + 1,
                                        "total": total_processed,
                                        "filename": pf["filename"],
                                        "detail": "Hashing large file...",
                                    }
                                ) + "\n"
                    sha256_hash = hasher.hexdigest()

                original_name = pf["original_filename"]
                dup_type, existing = None, None
                hash_match = existing_by_hash.get(sha256_hash)
                if hash_match:
                    if hash_match.original_filename == original_name:
                        dup_type, existing = "true", hash_match
                    else:
                        dup_type, existing = "hash_only", hash_match
                else:
                    name_match = existing_by_name.get(original_name)
                    if name_match:
                        dup_type, existing = "name_only", name_match

                parent_id = None
                parent_zip_key = pf.get("parent_zip")
                parent_zip_name = pf.get("parent_zip_name")
                if parent_zip_key and parent_zip_key in zip_records:
                    parent_id = zip_records[parent_zip_key]["record"].id

                display_filename = pf["filename"]
                if parent_zip_name:
                    display_filename = f"{parent_zip_name}/{pf['filename']}"

                if dup_type == "true":
                    duplicate_true_count += 1
                    try:
                        duplicate_record = CaseFile(
                            case_uuid=case_uuid,
                            parent_id=parent_id,
                            duplicate_of_id=existing.id,
                            filename=display_filename,
                            original_filename=original_name,
                            file_path=pf.get("retained_original_path"),
                            source_path=pf.get("retained_original_path"),
                            file_size=file_size,
                            sha256_hash=sha256_hash,
                            hostname=pf["file_info"].get("host", ""),
                            file_type=pf["file_info"].get("type", _default_upload_type_label()),
                            upload_source=pf["file_info"].get("source", "web"),
                            is_archive=pf["is_archive"],
                            is_extracted=pf["is_extracted"],
                            extraction_status=ExtractionStatus.NA,
                            status="duplicate",
                            ingestion_status="not_done",
                            retention_state="duplicate_retained",
                            uploaded_by=uploaded_by,
                        )
                        db.session.add(duplicate_record)
                        db.session.flush()
                    except Exception as e:
                        logger.warning("Failed to retain duplicate %s: %s", display_filename, e)
                        errors.append(f"Could not retain duplicate {display_filename}: {str(e)}")
                    _remove_file_if_present(file_path)
                    continue

                elif dup_type == "hash_only":
                    duplicate_hash_only_count += 1
                    case_file = CaseFile(
                        case_uuid=case_uuid,
                        parent_id=parent_id,
                        duplicate_of_id=existing.id,
                        filename=display_filename,
                        original_filename=original_name,
                        file_path=pf.get("retained_original_path"),
                        source_path=pf.get("retained_original_path"),
                        file_size=file_size,
                        sha256_hash=sha256_hash,
                        hostname=pf["file_info"].get("host", ""),
                        file_type=pf["file_info"].get("type", _default_upload_type_label()),
                        upload_source=pf["file_info"].get("source", "web"),
                        is_archive=pf["is_archive"],
                        is_extracted=pf["is_extracted"],
                        extraction_status=ExtractionStatus.NA,
                        status="duplicate",
                        ingestion_status="not_done",
                        retention_state="duplicate_retained",
                        uploaded_by=uploaded_by,
                    )
                    db.session.add(case_file)
                    db.session.flush()
                    _remove_file_if_present(file_path)
                    continue

                case_file = CaseFile(
                    case_uuid=case_uuid,
                    parent_id=parent_id,
                    filename=display_filename,
                    original_filename=pf["original_filename"],
                    file_path=file_path,
                    source_path=pf.get("retained_original_path"),
                    file_size=file_size,
                    sha256_hash=sha256_hash,
                    hostname=pf["file_info"].get("host", ""),
                    file_type=pf["file_info"].get("type", _default_upload_type_label()),
                    upload_source=pf["file_info"].get("source", "web"),
                    is_archive=pf["is_archive"],
                    is_extracted=pf["is_extracted"],
                    extraction_status=ExtractionStatus.NA,
                    status="new",
                    retention_state="retained",
                    uploaded_by=uploaded_by,
                )

                db.session.add(case_file)
                db.session.flush()

                if sha256_hash:
                    existing_by_hash[sha256_hash] = case_file
                if original_name:
                    existing_by_name[original_name] = case_file

                if parent_zip_key:
                    extracted_count += 1

                if (idx + 1) % hash_batch_commit_size == 0:
                    try:
                        db.session.commit()
                    except Exception as ce:
                        db.session.rollback()
                        errors.append(f"Batch commit error at file {idx + 1}: {str(ce)}")

            except Exception as e:
                errors.append(f'Error hashing {pf["filename"]}: {str(e)}')
                try:
                    parent_id = None
                    parent_zip_key = pf.get("parent_zip")
                    parent_zip_name = pf.get("parent_zip_name")
                    if parent_zip_key and parent_zip_key in zip_records:
                        parent_id = zip_records[parent_zip_key]["record"].id

                    display_filename = pf["filename"]
                    if parent_zip_name:
                        display_filename = f"{parent_zip_name}/{pf['filename']}"

                    case_file = CaseFile(
                        case_uuid=case_uuid,
                        parent_id=parent_id,
                        filename=display_filename,
                        original_filename=pf["original_filename"],
                        file_path=pf["path"],
                        source_path=pf.get("retained_original_path"),
                        file_size=0,
                        sha256_hash=None,
                        hostname=pf["file_info"].get("host", ""),
                        file_type=pf["file_info"].get("type", _default_upload_type_label()),
                        upload_source=pf["file_info"].get("source", "web"),
                        is_archive=pf.get("is_archive", False),
                        is_extracted=pf.get("is_extracted", False),
                        extraction_status=ExtractionStatus.NA,
                        status="error",
                        ingestion_status="error",
                        retention_state="failed_retained",
                        uploaded_by=uploaded_by,
                    )
                    db.session.add(case_file)
                    db.session.flush()
                except Exception as inner_e:
                    logger.warning("Failed to create error record for %s: %s", pf["filename"], inner_e)

        yield json.dumps({"stage": "cleanup"}) + "\n"

        try:
            for unique_key, zr_data in zip_records.items():
                source_path = zr_data["source_path"]
                filename = zr_data["filename"]
                record = zr_data["record"]

                if source_path and os.path.exists(source_path):
                    originals_path = _move_to_originals(source_path, case_uuid, filename)
                    if originals_path:
                        record.file_path = originals_path
                        record.source_path = originals_path
                        record.status = "done"
                        record.ingestion_status = "no_parser"
                        record.retention_state = "archived"
                        record.processed_at = datetime.utcnow()
                        CaseFile.query.filter_by(parent_id=record.id).update({"source_path": originals_path}, synchronize_session=False)
                        archived_count += 1
                        logger.info("Retained original ZIP: %s -> %s", filename, originals_path)
                    else:
                        record.file_path = source_path
                        record.source_path = source_path
                        record.status = "error"
                        record.ingestion_status = "error"
                        record.retention_state = "failed_retained"
                        record.error_message = "Failed to move to originals retention"
                        errors.append(f"Failed to retain original: {filename}")
                        logger.warning("ZIP file kept in uploads for recovery: %s", source_path)
        except Exception as e:
            errors.append(f"Cleanup error: {str(e)}")

        try:
            db.session.commit()
        except Exception as e:
            db.session.rollback()
            errors.append(f"Database error: {str(e)}")

        _log_case_file_audit(
            action=AuditAction.EXTRACTED,
            case_uuid=case_uuid,
            entity_name="Case file extraction summary",
            details={
                "archives_detected": len(zip_files),
                "archives_archived": archived_count,
                "extracted_files": extracted_count,
                "extraction_failures": len(extraction_failures),
                "extraction_failure_samples": extraction_failures[:10],
            },
        )

        if duplicate_true_count or duplicate_hash_only_count or duplicates_skipped:
            _log_case_file_audit(
                action=AuditAction.DUPLICATE_SKIPPED,
                case_uuid=case_uuid,
                entity_name="Case file duplicate summary",
                details={
                    "skipped_by_user": duplicates_skipped,
                    "true_duplicates_retained": duplicate_true_count,
                    "hash_only_duplicates_retained": duplicate_hash_only_count,
                },
            )

        try:
            if os.path.isdir(staging_path):
                db_paths_check = {
                    record.file_path
                    for record in CaseFile.query.filter_by(case_uuid=case_uuid).with_entities(CaseFile.file_path).all()
                    if record.file_path
                }
                orphan_count = 0
                for root, dirs, staging_files_check in os.walk(staging_path):
                    for sf_name in staging_files_check:
                        sf_path = os.path.join(root, sf_name)
                        if sf_path not in db_paths_check:
                            try:
                                sf_size = os.path.getsize(sf_path)
                                sf_rel = os.path.relpath(sf_path, staging_path)
                                sf_hash = hashlib.sha256()
                                with open(sf_path, "rb") as hf:
                                    while True:
                                        chunk = hf.read(1048576)
                                        if not chunk:
                                            break
                                        sf_hash.update(chunk)
                                orphan_record = CaseFile(
                                    case_uuid=case_uuid,
                                    filename=sf_rel,
                                    original_filename=sf_name,
                                    file_path=sf_path,
                                    source_path=sf_path,
                                    file_size=sf_size,
                                    sha256_hash=sf_hash.hexdigest(),
                                    hostname="",
                                    file_type=_default_upload_type_label(),
                                    upload_source="staging_import",
                                    is_extracted=True,
                                    status="new",
                                    retention_state="retained",
                                    uploaded_by=uploaded_by,
                                )
                                db.session.add(orphan_record)
                                orphan_count += 1
                            except Exception as oe:
                                logger.warning("Failed to register staging orphan %s: %s", sf_path, oe)
                if orphan_count > 0:
                    db.session.commit()
                    logger.info("Registered %s staging orphan files for case %s", orphan_count, case_uuid)
        except Exception as e:
            logger.warning("Staging validation error: %s", e)

        yield json.dumps({"stage": "parsing", "message": "Queuing files for parsing..."}) + "\n"

        try:
            from tasks.celery_tasks import parse_file_task
            from utils.progress import init_progress

            case = Case.get_by_uuid(case_uuid)
            if case:
                pending_files = (
                    CaseFile.query.filter_by(case_uuid=case_uuid, status="new")
                    .filter(CaseFile.is_archive == False)
                    .all()
                )

                files_to_queue = [cf for cf in pending_files if cf.file_path and os.path.exists(cf.file_path)]

                if files_to_queue:
                    init_progress(case_uuid, len(files_to_queue))

                queued_count = 0
                for cf in files_to_queue:
                    cf.status = "queued"
                    db.session.flush()

                    parse_file_task.delay(
                        file_path=cf.file_path,
                        case_id=case.id,
                        source_host=cf.hostname or "",
                        case_file_id=cf.id,
                        parser_hints=_get_parser_hints_for_case_file(cf),
                    )
                    queued_count += 1
                queued_count_total = queued_count

                nested_archives = CaseFile.query.filter_by(
                    case_uuid=case_uuid,
                    status="new",
                    is_archive=True,
                    is_extracted=True,
                ).all()

                nested_archive_count = 0
                for cf in nested_archives:
                    if cf.file_path and os.path.exists(cf.file_path):
                        _remove_file_if_present(cf.file_path)
                    cf.file_path = None
                    cf.status = "done"
                    cf.ingestion_status = "no_parser"
                    cf.processed_at = datetime.utcnow()
                    nested_archive_count += 1

                if nested_archive_count > 0:
                    logger.info("Removed %s nested archive staging files for case %s", nested_archive_count, case_uuid)

                db.session.commit()
                _log_case_file_audit(
                    action=AuditAction.QUEUED,
                    case_uuid=case_uuid,
                    entity_name="Case file ingest queued",
                    details={
                        "queued_files": queued_count_total,
                        "nested_archives_retained": nested_archive_count,
                        "ingested_records": ingested_count,
                        "errors": len(errors),
                    },
                )
                safe_log_case_work_activity(
                    case_uuid,
                    CaseWorkActivityType.INGEST_QUEUED,
                    "Queued files for parsing",
                    details={
                        "queued_files": queued_count_total,
                        "nested_archives_retained": nested_archive_count,
                        "ingested_records": ingested_count,
                        "extracted_files": extracted_count,
                        "errors": len(errors),
                        "error_samples": errors[:10],
                    },
                    user_id=getattr(current_user, "id", None),
                    username=getattr(current_user, "username", "system"),
                )
                yield json.dumps({"stage": "parsing_queued", "queued_count": queued_count}) + "\n"
        except Exception as e:
            yield json.dumps({"stage": "parsing_error", "error": str(e)}) + "\n"

        yield json.dumps(
            {
                "stage": "complete",
                "ingested": ingested_count,
                "extracted": extracted_count,
                "duplicates_skipped": duplicates_skipped,
                "duplicates_deleted": duplicates_deleted,
                "extraction_failures": extraction_failures,
                "errors": errors,
            }
        ) + "\n"

    return Response(
        stream_with_context(generate_progress()),
        mimetype="application/x-ndjson",
        headers={"Cache-Control": "no-cache", "X-Accel-Buffering": "no"},
    )
