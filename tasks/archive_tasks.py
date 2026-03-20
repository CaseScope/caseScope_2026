"""Archive/Restore Celery Tasks for CaseScope

Handles case archiving (compression) and restoration with progress tracking.
Uses ZIP with LZMA compression for optimal compression ratios.
"""
import os
import json
import shutil
import zipfile
import threading
from datetime import datetime
from celery import shared_task
import redis
import logging

from config import Config
from utils.artifact_paths import get_case_originals_root

logger = logging.getLogger(__name__)

# Cached Flask app instance
_flask_app = None
_flask_app_lock = threading.Lock()


def get_flask_app():
    """Get or create a shared Flask app instance for Celery tasks (thread-safe)"""
    global _flask_app
    if _flask_app is None:
        with _flask_app_lock:
            if _flask_app is None:
                from app import create_app
                _flask_app = create_app()
    return _flask_app


# Cached Redis client
_redis_client = None
_redis_lock = threading.Lock()


def get_redis_client():
    """Get Redis client for progress tracking (thread-safe)"""
    global _redis_client
    if _redis_client is None:
        with _redis_lock:
            if _redis_client is None:
                _redis_client = redis.Redis(
                    host=Config.REDIS_HOST,
                    port=Config.REDIS_PORT,
                    db=Config.REDIS_DB
                )
    return _redis_client


def update_archive_progress(job_id: int, stage: str = None, current_file: int = 0,
                            total_files: int = 0, filename: str = None, status: str = None):
    """Update archive job progress in Redis for real-time tracking"""
    r = get_redis_client()
    key = f"archive_job:{job_id}"
    data = {
        'updated_at': datetime.utcnow().isoformat()
    }
    if stage:
        data['stage'] = stage
    if current_file is not None:
        data['current_file'] = current_file
    if total_files is not None:
        data['total_files'] = total_files
    if filename:
        data['filename'] = filename
    if status:
        data['status'] = status
    r.hset(key, mapping=data)
    r.expire(key, 3600)  # 1 hour TTL


def get_archive_progress(job_id: int) -> dict:
    """Get archive job progress from Redis"""
    r = get_redis_client()
    key = f"archive_job:{job_id}"
    data = r.hgetall(key)
    if data:
        return {k.decode(): v.decode() for k, v in data.items()}
    return {}


def get_folder_file_list(folder_path: str) -> list:
    """Get list of all files in a folder recursively"""
    files = []
    if os.path.exists(folder_path):
        for root, _, filenames in os.walk(folder_path):
            for filename in filenames:
                filepath = os.path.join(root, filename)
                files.append(filepath)
    return files


def get_folder_size(folder_path: str) -> int:
    """Get total size of a folder in bytes"""
    total_size = 0
    if os.path.exists(folder_path):
        for root, _, filenames in os.walk(folder_path):
            for filename in filenames:
                filepath = os.path.join(root, filename)
                try:
                    total_size += os.path.getsize(filepath)
                except OSError:
                    pass
    return total_size


def compress_folder_to_zip(source_folder: str, zip_path: str, job_id: int,
                           stage: str, base_path: str = None) -> tuple:
    """
    Compress a folder to a ZIP file with LZMA compression.
    
    Args:
        source_folder: Path to folder to compress
        zip_path: Output ZIP file path
        job_id: Archive job ID for progress updates
        stage: Current stage name for progress updates
        base_path: Base path to strip from archived paths (defaults to source_folder)
    
    Returns:
        Tuple of (success, file_count, compressed_size)
    """
    from models.database import db
    from models.archive_job import ArchiveJob
    
    if not os.path.exists(source_folder):
        return True, 0, 0  # Nothing to compress
    
    app = get_flask_app()
    
    files = get_folder_file_list(source_folder)
    total_files = len(files)
    
    if total_files == 0:
        return True, 0, 0
    
    if base_path is None:
        base_path = source_folder
    
    # Update job with file counts
    with app.app_context():
        job = ArchiveJob.query.get(job_id)
        if job:
            job.update_stage(stage, 0, total_files)
            db.session.commit()
    
    update_archive_progress(job_id, stage=stage, current_file=0, total_files=total_files)
    
    try:
        with zipfile.ZipFile(zip_path, 'w', zipfile.ZIP_LZMA) as zf:
            for idx, filepath in enumerate(files):
                # Calculate relative path for archive
                rel_path = os.path.relpath(filepath, base_path)
                
                # Add file to archive
                zf.write(filepath, rel_path)
                
                # Update progress every 10 files or on last file
                if idx % 10 == 0 or idx == total_files - 1:
                    filename = os.path.basename(filepath)
                    update_archive_progress(
                        job_id, stage=stage, current_file=idx + 1,
                        total_files=total_files, filename=filename
                    )
                    
                    with app.app_context():
                        job = ArchiveJob.query.get(job_id)
                        if job:
                            job.update_file_progress(idx + 1, total_files, filename)
                            db.session.commit()
        
        compressed_size = os.path.getsize(zip_path)
        return True, total_files, compressed_size
    
    except Exception as e:
        logger.error(f"Compression failed: {e}")
        # Clean up partial file
        if os.path.exists(zip_path):
            os.remove(zip_path)
        raise


def verify_zip_integrity(zip_path: str) -> tuple:
    """
    Verify ZIP file integrity.
    
    Returns:
        Tuple of (is_valid, error_message)
    """
    if not os.path.exists(zip_path):
        return True, None  # File doesn't exist, nothing to verify
    
    try:
        with zipfile.ZipFile(zip_path, 'r') as zf:
            # Test archive integrity
            bad_file = zf.testzip()
            if bad_file:
                return False, f"Corrupted file in archive: {bad_file}"
        return True, None
    except zipfile.BadZipFile as e:
        return False, f"Invalid ZIP file: {str(e)}"
    except Exception as e:
        return False, f"Verification error: {str(e)}"


def extract_zip_to_folder(zip_path: str, dest_folder: str, job_id: int, stage: str) -> tuple:
    """
    Extract a ZIP file to a destination folder with progress tracking.
    
    Returns:
        Tuple of (success, file_count)
    """
    from models.database import db
    from models.archive_job import ArchiveJob
    
    if not os.path.exists(zip_path):
        return True, 0  # Nothing to extract
    
    app = get_flask_app()
    
    try:
        with zipfile.ZipFile(zip_path, 'r') as zf:
            members = zf.namelist()
            total_files = len(members)
            
            if total_files == 0:
                return True, 0
            
            # Update job with file counts
            with app.app_context():
                job = ArchiveJob.query.get(job_id)
                if job:
                    job.update_stage(stage, 0, total_files)
                    db.session.commit()
            
            update_archive_progress(job_id, stage=stage, current_file=0, total_files=total_files)
            
            for idx, member in enumerate(members):
                zf.extract(member, dest_folder)
                
                # Update progress every 10 files or on last file
                if idx % 10 == 0 or idx == total_files - 1:
                    filename = os.path.basename(member)
                    update_archive_progress(
                        job_id, stage=stage, current_file=idx + 1,
                        total_files=total_files, filename=filename
                    )
                    
                    with app.app_context():
                        job = ArchiveJob.query.get(job_id)
                        if job:
                            job.update_file_progress(idx + 1, total_files, filename)
                            db.session.commit()
            
            return True, total_files
    
    except Exception as e:
        logger.error(f"Extraction failed: {e}")
        raise


def validate_disk_requirements(path_requirements: list[tuple[str, int]]) -> Optional[str]:
    """Validate free space across one or more destination filesystems."""
    grouped: dict[int, dict[str, int | str]] = {}

    for path, required_bytes in path_requirements:
        if not path or required_bytes <= 0:
            continue

        existing_path = path
        while existing_path and not os.path.exists(existing_path):
            parent = os.path.dirname(existing_path)
            if parent == existing_path:
                break
            existing_path = parent
        if not existing_path or not os.path.exists(existing_path):
            existing_path = '/'

        stat_info = os.stat(existing_path)
        entry = grouped.setdefault(
            stat_info.st_dev,
            {'path': existing_path, 'required': 0},
        )
        entry['required'] += required_bytes

    for entry in grouped.values():
        stat = os.statvfs(entry['path'])
        free_space = stat.f_bavail * stat.f_frsize
        required_space = int(entry['required'])
        if free_space < required_space:
            return (
                f"Insufficient disk space at {entry['path']}. "
                f"Need {required_space / (1024**3):.2f} GB, have {free_space / (1024**3):.2f} GB"
            )

    return None


@shared_task(bind=True, max_retries=0, time_limit=14400, soft_time_limit=14100)
def archive_case_task(self, job_id: int):
    """
    Archive a case: compress storage and evidence folders to ZIP files.
    
    Extended timeout: 4 hours hard limit, ~3.9 hours soft limit for large cases.
    
    Args:
        job_id: ID of the ArchiveJob record
    """
    from models.database import db
    from models.archive_job import ArchiveJob, ArchiveStage
    from models.case import Case, CaseStatus
    from models.system_settings import SystemSettings, SettingKeys
    
    app = get_flask_app()
    
    with app.app_context():
        job = ArchiveJob.query.get(job_id)
        if not job:
            return {'success': False, 'error': 'Job not found'}
        
        case = Case.query.get(job.case_id)
        if not case:
            job.mark_failed('Case not found')
            db.session.commit()
            return {'success': False, 'error': 'Case not found'}
        
        try:
            # Update status to running
            job.status = 'running'
            job.started_at = datetime.utcnow()
            job.celery_task_id = self.request.id
            job.original_status = case.status
            db.session.commit()
            update_archive_progress(job_id, status='running')
            
            # Stage 1: Validate archive path
            job.update_stage(ArchiveStage.VALIDATING.value)
            db.session.commit()
            update_archive_progress(job_id, stage=ArchiveStage.VALIDATING.value)
            
            archive_base = SystemSettings.get(SettingKeys.ARCHIVE_PATH, '/archive')
            
            if not os.path.exists(archive_base):
                job.mark_failed(f'Archive path does not exist: {archive_base}', ArchiveStage.VALIDATING.value)
                db.session.commit()
                return {'success': False, 'error': f'Archive path does not exist: {archive_base}'}
            
            if not os.access(archive_base, os.W_OK):
                job.mark_failed(f'Archive path is not writable: {archive_base}', ArchiveStage.VALIDATING.value)
                db.session.commit()
                return {'success': False, 'error': f'Archive path is not writable: {archive_base}'}
            
            # Create case archive folder
            archive_folder = os.path.join(archive_base, case.uuid)
            os.makedirs(archive_folder, exist_ok=True)
            job.archive_path = archive_base
            job.archive_folder = archive_folder
            
            # Calculate sizes
            storage_folder = os.path.join(Config.STORAGE_FOLDER, case.uuid)
            evidence_folder = os.path.join(Config.EVIDENCE_FOLDER, case.uuid)
            originals_folder = get_case_originals_root(case.uuid)
            
            storage_size = get_folder_size(storage_folder)
            evidence_size = get_folder_size(evidence_folder)
            originals_size = get_folder_size(originals_folder)
            storage_files = get_folder_file_list(storage_folder)
            evidence_files = get_folder_file_list(evidence_folder)
            originals_files = get_folder_file_list(originals_folder)
            
            job.storage_size_bytes = storage_size
            job.evidence_size_bytes = evidence_size
            job.storage_file_count = len(storage_files)
            job.evidence_file_count = len(evidence_files)
            db.session.commit()
            
            # Check disk space (need roughly equal to original size for compression)
            try:
                disk_error = validate_disk_requirements([
                    (archive_base, storage_size + evidence_size + originals_size),
                ])
                if disk_error:
                    job.mark_failed(disk_error, ArchiveStage.VALIDATING.value)
                    db.session.commit()
                    return {'success': False, 'error': disk_error}
            except Exception as e:
                logger.warning(f"Could not check disk space: {e}")
            
            # Stage 2: Compress storage folder
            storage_zip = os.path.join(archive_folder, 'storage.zip')
            total_compressed = 0
            
            if os.path.exists(storage_folder) and len(storage_files) > 0:
                success, count, compressed = compress_folder_to_zip(
                    storage_folder, storage_zip, job_id,
                    ArchiveStage.COMPRESSING_STORAGE.value, storage_folder
                )
                total_compressed += compressed
            
            # Stage 3: Compress evidence folder
            evidence_zip = os.path.join(archive_folder, 'evidence.zip')
            
            if os.path.exists(evidence_folder) and len(evidence_files) > 0:
                success, count, compressed = compress_folder_to_zip(
                    evidence_folder, evidence_zip, job_id,
                    ArchiveStage.COMPRESSING_EVIDENCE.value, evidence_folder
                )
                total_compressed += compressed

            originals_zip = os.path.join(archive_folder, 'originals.zip')
            if os.path.exists(originals_folder) and len(originals_files) > 0:
                success, count, compressed = compress_folder_to_zip(
                    originals_folder, originals_zip, job_id,
                    ArchiveStage.COMPRESSING_EVIDENCE.value, originals_folder
                )
                total_compressed += compressed
            
            job.compressed_size_bytes = total_compressed
            db.session.commit()
            
            # Stage 4: Create manifest
            job.update_stage(ArchiveStage.CREATING_MANIFEST.value)
            db.session.commit()
            update_archive_progress(job_id, stage=ArchiveStage.CREATING_MANIFEST.value)
            
            manifest = {
                'case_uuid': case.uuid,
                'case_name': case.name,
                'company': case.company,
                'description': case.description,
                'timezone': case.timezone,
                'archived_at': datetime.utcnow().isoformat(),
                'archived_by': job.created_by,
                'original_status': job.original_status,
                'storage_size_bytes': storage_size,
                'evidence_size_bytes': evidence_size,
                'originals_size_bytes': originals_size,
                'storage_file_count': len(storage_files),
                'evidence_file_count': len(evidence_files),
                'originals_file_count': len(originals_files),
                'compressed_size_bytes': total_compressed,
                'compression_ratio': round((storage_size + evidence_size + originals_size) / total_compressed, 2) if total_compressed > 0 else 0,
                'casescope_version': get_casescope_version(),
            }
            
            manifest_path = os.path.join(archive_folder, 'manifest.json')
            with open(manifest_path, 'w') as f:
                json.dump(manifest, f, indent=2)
            
            # Stage 5: Verify archive integrity
            job.update_stage(ArchiveStage.VERIFYING.value)
            db.session.commit()
            update_archive_progress(job_id, stage=ArchiveStage.VERIFYING.value)
            
            if os.path.exists(storage_zip):
                is_valid, error = verify_zip_integrity(storage_zip)
                if not is_valid:
                    job.mark_failed(f'Storage archive verification failed: {error}', ArchiveStage.VERIFYING.value)
                    db.session.commit()
                    return {'success': False, 'error': error}
            
            if os.path.exists(evidence_zip):
                is_valid, error = verify_zip_integrity(evidence_zip)
                if not is_valid:
                    job.mark_failed(f'Evidence archive verification failed: {error}', ArchiveStage.VERIFYING.value)
                    db.session.commit()
                    return {'success': False, 'error': error}

            if os.path.exists(originals_zip):
                is_valid, error = verify_zip_integrity(originals_zip)
                if not is_valid:
                    job.mark_failed(f'Originals archive verification failed: {error}', ArchiveStage.VERIFYING.value)
                    db.session.commit()
                    return {'success': False, 'error': error}
            
            # Stage 6: Cleanup original folders
            job.update_stage(ArchiveStage.CLEANUP.value)
            db.session.commit()
            update_archive_progress(job_id, stage=ArchiveStage.CLEANUP.value)
            
            if os.path.exists(storage_folder):
                shutil.rmtree(storage_folder)
                logger.info(f"Removed storage folder: {storage_folder}")
            
            if os.path.exists(evidence_folder):
                shutil.rmtree(evidence_folder)
                logger.info(f"Removed evidence folder: {evidence_folder}")

            if os.path.exists(originals_folder):
                shutil.rmtree(originals_folder)
                logger.info(f"Removed originals folder: {originals_folder}")
            
            # Also remove staging folder if exists
            staging_folder = os.path.join(Config.STAGING_FOLDER, case.uuid)
            if os.path.exists(staging_folder):
                shutil.rmtree(staging_folder)
                logger.info(f"Removed staging folder: {staging_folder}")
            
            # Update case status to archived
            case.status = CaseStatus.ARCHIVED
            
            # Mark job complete
            job.mark_completed()
            db.session.commit()
            
            update_archive_progress(job_id, stage=ArchiveStage.COMPLETE.value, status='completed')
            
            logger.info(f"Case {case.uuid} archived successfully to {archive_folder}")
            
            return {
                'success': True,
                'archive_folder': archive_folder,
                'storage_compressed': os.path.exists(storage_zip),
                'evidence_compressed': os.path.exists(evidence_zip),
                'originals_compressed': os.path.exists(originals_zip),
                'original_size': storage_size + evidence_size + originals_size,
                'compressed_size': total_compressed,
            }
            
        except Exception as e:
            logger.exception(f"Archive task failed: {e}")
            job.mark_failed(str(e))
            db.session.commit()
            return {'success': False, 'error': str(e)}


@shared_task(bind=True, max_retries=0, time_limit=14400, soft_time_limit=14100)
def restore_case_task(self, job_id: int):
    """
    Restore an archived case: extract ZIP files back to storage and evidence folders.
    
    Extended timeout: 4 hours hard limit, ~3.9 hours soft limit for large cases.
    
    Args:
        job_id: ID of the ArchiveJob record
    """
    from models.database import db
    from models.archive_job import ArchiveJob, ArchiveStage
    from models.case import Case, CaseStatus
    from models.system_settings import SystemSettings, SettingKeys
    
    app = get_flask_app()
    
    with app.app_context():
        job = ArchiveJob.query.get(job_id)
        if not job:
            return {'success': False, 'error': 'Job not found'}
        
        case = Case.query.get(job.case_id)
        if not case:
            job.mark_failed('Case not found')
            db.session.commit()
            return {'success': False, 'error': 'Case not found'}
        
        try:
            # Update status to running
            job.status = 'running'
            job.started_at = datetime.utcnow()
            job.celery_task_id = self.request.id
            db.session.commit()
            update_archive_progress(job_id, status='running')
            
            # Stage 1: Validate archive exists
            job.update_stage(ArchiveStage.VALIDATING.value)
            db.session.commit()
            update_archive_progress(job_id, stage=ArchiveStage.VALIDATING.value)
            
            archive_base = SystemSettings.get(SettingKeys.ARCHIVE_PATH, '/archive')
            archive_folder = os.path.join(archive_base, case.uuid)
            
            if not os.path.exists(archive_folder):
                job.mark_failed(f'Archive folder not found: {archive_folder}', ArchiveStage.VALIDATING.value)
                db.session.commit()
                return {'success': False, 'error': f'Archive folder not found: {archive_folder}'}
            
            job.archive_path = archive_base
            job.archive_folder = archive_folder
            
            storage_zip = os.path.join(archive_folder, 'storage.zip')
            evidence_zip = os.path.join(archive_folder, 'evidence.zip')
            originals_zip = os.path.join(archive_folder, 'originals.zip')
            manifest_path = os.path.join(archive_folder, 'manifest.json')
            
            # Load manifest for metadata
            manifest = {}
            if os.path.exists(manifest_path):
                with open(manifest_path, 'r') as f:
                    manifest = json.load(f)
                job.storage_size_bytes = manifest.get('storage_size_bytes', 0)
                job.evidence_size_bytes = manifest.get('evidence_size_bytes', 0)
                job.storage_file_count = manifest.get('storage_file_count', 0)
                job.evidence_file_count = manifest.get('evidence_file_count', 0)
                db.session.commit()
            
            # Check disk space for extraction
            try:
                disk_error = validate_disk_requirements([
                    (Config.STORAGE_FOLDER, job.storage_size_bytes),
                    (Config.EVIDENCE_FOLDER, job.evidence_size_bytes),
                    (get_case_originals_root(case.uuid), manifest.get('originals_size_bytes', 0)),
                ])
                if disk_error:
                    job.mark_failed(disk_error, ArchiveStage.VALIDATING.value)
                    db.session.commit()
                    return {'success': False, 'error': disk_error}
            except Exception as e:
                logger.warning(f"Could not check disk space: {e}")
            
            # Stage 2: Extract storage
            storage_folder = os.path.join(Config.STORAGE_FOLDER, case.uuid)
            
            if os.path.exists(storage_zip):
                os.makedirs(storage_folder, exist_ok=True)
                success, count = extract_zip_to_folder(
                    storage_zip, storage_folder, job_id,
                    ArchiveStage.EXTRACTING_STORAGE.value
                )
            
            # Stage 3: Extract evidence
            evidence_folder = os.path.join(Config.EVIDENCE_FOLDER, case.uuid)
            
            if os.path.exists(evidence_zip):
                os.makedirs(evidence_folder, exist_ok=True)
                success, count = extract_zip_to_folder(
                    evidence_zip, evidence_folder, job_id,
                    ArchiveStage.EXTRACTING_EVIDENCE.value
                )

            originals_folder = get_case_originals_root(case.uuid)
            if os.path.exists(originals_zip):
                os.makedirs(originals_folder, exist_ok=True)
                success, count = extract_zip_to_folder(
                    originals_zip, originals_folder, job_id,
                    ArchiveStage.EXTRACTING_EVIDENCE.value
                )
            
            # Stage 4: Verify extraction
            job.update_stage(ArchiveStage.VERIFYING_EXTRACTION.value)
            db.session.commit()
            update_archive_progress(job_id, stage=ArchiveStage.VERIFYING_EXTRACTION.value)
            
            # Basic verification: check folders exist and have files
            if os.path.exists(storage_zip):
                extracted_files = get_folder_file_list(storage_folder)
                if len(extracted_files) == 0:
                    job.mark_failed('Storage extraction failed: no files extracted', ArchiveStage.VERIFYING_EXTRACTION.value)
                    db.session.commit()
                    return {'success': False, 'error': 'Storage extraction failed'}
            
            # Set folder permissions
            try:
                import pwd
                import grp
                uid = pwd.getpwnam('casescope').pw_uid
                gid = grp.getgrnam('casescope').gr_gid
                
                for folder in [storage_folder, evidence_folder, originals_folder]:
                    if os.path.exists(folder):
                        for root, dirs, files in os.walk(folder):
                            os.chown(root, uid, gid)
                            os.chmod(root, 0o2775)
                            for d in dirs:
                                path = os.path.join(root, d)
                                os.chown(path, uid, gid)
                                os.chmod(path, 0o2775)
                            for f in files:
                                path = os.path.join(root, f)
                                os.chown(path, uid, gid)
                                os.chmod(path, 0o0664)
            except Exception as e:
                logger.warning(f"Could not set permissions: {e}")
            
            # Stage 5: Delete archive if requested
            if job.delete_archive_after_restore:
                job.update_stage(ArchiveStage.DELETING_ARCHIVE.value)
                db.session.commit()
                update_archive_progress(job_id, stage=ArchiveStage.DELETING_ARCHIVE.value)
                
                shutil.rmtree(archive_folder)
                logger.info(f"Deleted archive folder: {archive_folder}")
            
            # Stage 6: Cleanup - update case status
            job.update_stage(ArchiveStage.CLEANUP.value)
            db.session.commit()
            update_archive_progress(job_id, stage=ArchiveStage.CLEANUP.value)
            
            # Set case status to in_progress
            case.status = CaseStatus.IN_PROGRESS
            
            # Mark job complete
            job.mark_completed()
            db.session.commit()
            
            update_archive_progress(job_id, stage=ArchiveStage.COMPLETE.value, status='completed')
            
            logger.info(f"Case {case.uuid} restored successfully")
            
            return {
                'success': True,
                'storage_restored': os.path.exists(storage_folder),
                'evidence_restored': os.path.exists(evidence_folder),
                'originals_restored': os.path.exists(originals_folder),
                'archive_deleted': job.delete_archive_after_restore,
            }
            
        except Exception as e:
            logger.exception(f"Restore task failed: {e}")
            job.mark_failed(str(e))
            db.session.commit()
            return {'success': False, 'error': str(e)}


def get_casescope_version() -> str:
    """Get current CaseScope version from version.json"""
    try:
        version_file = os.path.join(Config.BASE_DIR, 'version.json')
        if os.path.exists(version_file):
            with open(version_file, 'r') as f:
                data = json.load(f)
                return data.get('version', 'unknown')
    except Exception:
        pass
    return 'unknown'
