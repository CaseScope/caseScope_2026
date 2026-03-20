"""PCAP File API routes for CaseScope

Provides endpoints for:
- Uploading PCAP files (web and folder-based)
- Scanning upload folder for PCAP files
- ZIP extraction support
- Managing PCAP file list
- Triggering Zeek processing (future)
"""
import os
import re
import json
import shutil
import zipfile
import hashlib
import logging
from datetime import datetime
from flask import Blueprint, request, jsonify, Response, stream_with_context
from flask_login import login_required, current_user

from models.database import db
from models.case import Case
from models.pcap_file import PcapFile, PcapFileStatus
from config import Config
from utils.artifact_paths import (
    copy_to_directory,
    ensure_case_artifact_paths,
    ensure_case_originals_subdir,
    ensure_case_subdir,
    is_within_any_root,
    move_to_directory,
)

logger = logging.getLogger(__name__)

pcap_bp = Blueprint('pcap', __name__, url_prefix='/api/pcap')


def ensure_pcap_upload_dir(case_uuid):
    """Ensure the PCAP upload directory exists for a case
    
    Upload path: /opt/casescope/uploads/pcap/{case_uuid}
    """
    return ensure_case_artifact_paths(case_uuid)['pcap_upload']


def ensure_pcap_storage_dir(case_uuid):
    """Ensure the PCAP storage directory exists for a case
    
    Storage path: /opt/casescope/storage/{case_uuid}/pcap
    """
    return ensure_case_artifact_paths(case_uuid)['pcap_storage']


def ensure_pcap_staging_dir(case_uuid):
    """Ensure the transient PCAP staging directory exists for a case."""
    return ensure_case_artifact_paths(case_uuid)['pcap_staging']


def ensure_pcap_originals_dir(case_uuid, *parts):
    """Ensure the retained originals directory exists for PCAP uploads."""
    return ensure_case_originals_subdir(case_uuid, 'pcap', *parts)


def _remove_file_if_present(file_path: str):
    """Best-effort removal for transient PCAP working files."""
    if not file_path or not os.path.exists(file_path):
        return
    try:
        os.remove(file_path)
    except IsADirectoryError:
        shutil.rmtree(file_path, ignore_errors=True)
    except OSError:
        pass


def _viewer_write_error():
    return jsonify({'success': False, 'error': 'Viewers cannot modify PCAP artifacts'}), 403


def _get_pcap_for_user(pcap_id: int):
    """Load a PCAP file and enforce case access."""
    pcap_file = db.session.get(PcapFile, pcap_id)
    if not pcap_file:
        return None

    case = Case.query.filter_by(uuid=pcap_file.case_uuid).first()
    if not case:
        return None

    if not current_user.can_access_case(case.id):
        return False

    return pcap_file


def detect_hostname_from_filename(filename: str) -> str:
    """Try to extract hostname from filename patterns"""
    patterns = [
        r'^([A-Za-z0-9_-]+?)[-_](?:pcap|capture|network|\d{8})',
        r'^([A-Za-z0-9_-]+?)[-_]\d{4}[-_]\d{2}',
        r'^([A-Za-z0-9_-]+?)_',
        r'^([A-Za-z0-9-]+)\.',
    ]
    
    for pattern in patterns:
        match = re.match(pattern, filename, re.IGNORECASE)
        if match:
            hostname = match.group(1).upper()
            # Filter out common non-hostname prefixes
            if hostname.lower() not in ['pcap', 'capture', 'network', 'dump', 'traffic']:
                return hostname
    
    return ''


@pcap_bp.route('/folder/<case_uuid>', methods=['GET'])
@login_required
def get_pcap_folder(case_uuid):
    """Get the PCAP upload folder path for a case"""
    try:
        case = Case.get_by_uuid(case_uuid)
        if not case:
            return jsonify({'success': False, 'error': 'Case not found'}), 404
        
        folder_path = ensure_pcap_upload_dir(case_uuid)
        
        return jsonify({
            'success': True,
            'folder_path': folder_path
        })
    except Exception as e:
        return jsonify({'success': False, 'error': str(e)}), 500


@pcap_bp.route('/scan/<case_uuid>', methods=['GET'])
@login_required
def scan_pcap_folder(case_uuid):
    """Scan the PCAP upload folder for files"""
    try:
        case = Case.get_by_uuid(case_uuid)
        if not case:
            return jsonify({'success': False, 'error': 'Case not found'}), 404
        
        folder_path = ensure_pcap_upload_dir(case_uuid)
        
        files = []
        if os.path.exists(folder_path):
            for root, dirs, filenames in os.walk(folder_path):
                for filename in filenames:
                    filepath = os.path.join(root, filename)
                    try:
                        stat = os.stat(filepath)
                        rel_path = os.path.relpath(filepath, folder_path)
                        
                        # Detect file type
                        is_pcap = PcapFile.is_pcap_file(filepath)
                        is_zip = PcapFile.is_zip_file(filepath)
                        pcap_type = PcapFile.detect_pcap_type(filepath)
                        
                        files.append({
                            'name': filename,
                            'path': filepath,
                            'relative_path': rel_path,
                            'size': stat.st_size,
                            'modified': datetime.fromtimestamp(stat.st_mtime).isoformat(),
                            'is_pcap': is_pcap,
                            'is_zip': is_zip,
                            'pcap_type': pcap_type,
                            'detected_hostname': detect_hostname_from_filename(filename)
                        })
                    except (OSError, IOError):
                        continue
        
        # Sort by name
        files.sort(key=lambda x: x['name'].lower())
        
        return jsonify({
            'success': True,
            'files': files,
            'folder_path': folder_path,
            'total_count': len(files)
        })
    except Exception as e:
        return jsonify({'success': False, 'error': str(e)}), 500


@pcap_bp.route('/clear/<case_uuid>', methods=['POST'])
@login_required
def clear_pcap_folder(case_uuid):
    """Clear all files from the PCAP upload folder"""
    if current_user.permission_level == 'viewer':
        return _viewer_write_error()

    try:
        case = Case.get_by_uuid(case_uuid)
        if not case:
            return jsonify({'success': False, 'error': 'Case not found'}), 404
        
        folder_path = ensure_pcap_upload_dir(case_uuid)
        
        retained_count = 0
        errors = []
        retained_dir = ensure_pcap_originals_dir(case_uuid, 'cleared_uploads')
        
        if os.path.exists(folder_path):
            for root, dirs, filenames in os.walk(folder_path, topdown=False):
                for filename in filenames:
                    filepath = os.path.join(root, filename)
                    try:
                        retained_name = f"cleared_{datetime.utcnow().strftime('%Y%m%d_%H%M%S_%f')}_{filename}"
                        if move_to_directory(filepath, retained_dir, retained_name):
                            retained_count += 1
                        else:
                            errors.append(f"{filename}: failed to retain file")
                    except Exception as e:
                        errors.append(f"{filename}: {str(e)}")
                
                # Remove empty directories (but not the case root)
                for dirname in dirs:
                    dirpath = os.path.join(root, dirname)
                    try:
                        os.rmdir(dirpath)
                    except:
                        pass
        
        return jsonify({
            'success': True,
            'deleted_count': retained_count,
            'retained_count': retained_count,
            'errors': errors
        })
    except Exception as e:
        return jsonify({'success': False, 'error': str(e)}), 500


@pcap_bp.route('/list/<case_uuid>', methods=['GET'])
@login_required
def list_pcap_files(case_uuid):
    """List all PCAP files for a case from database"""
    try:
        case = Case.get_by_uuid(case_uuid)
        if not case:
            return jsonify({'success': False, 'error': 'Case not found'}), 404
        
        page = request.args.get('page', 1, type=int)
        per_page = request.args.get('per_page', 50, type=int)
        search = request.args.get('search', '').strip().lower()
        
        # Build query
        query = PcapFile.query.filter_by(case_uuid=case_uuid, is_archive=False)
        
        if search:
            query = query.filter(
                db.or_(
                    PcapFile.filename.ilike(f'%{search}%'),
                    PcapFile.hostname.ilike(f'%{search}%'),
                    PcapFile.description.ilike(f'%{search}%')
                )
            )
        
        # Get total count
        total = query.count()
        
        # Paginate
        files = query.order_by(PcapFile.uploaded_at.desc())\
            .offset((page - 1) * per_page)\
            .limit(per_page)\
            .all()
        
        return jsonify({
            'success': True,
            'files': [f.to_dict() for f in files],
            'page': page,
            'per_page': per_page,
            'total': total,
            'total_pages': (total + per_page - 1) // per_page
        })
    except Exception as e:
        return jsonify({'success': False, 'error': str(e)}), 500


@pcap_bp.route('/stats/<case_uuid>', methods=['GET'])
@login_required
def get_pcap_stats(case_uuid):
    """Get PCAP file statistics for a case"""
    try:
        case = Case.get_by_uuid(case_uuid)
        if not case:
            return jsonify({'success': False, 'error': 'Case not found'}), 404
        
        stats = PcapFile.get_stats(case_uuid)
        stats['success'] = True
        
        return jsonify(stats)
    except Exception as e:
        return jsonify({'success': False, 'error': str(e)}), 500


@pcap_bp.route('/ingest/<case_uuid>', methods=['POST'])
@login_required
def ingest_pcap_files(case_uuid):
    """Ingest PCAP files from upload folder into storage and database
    
    This endpoint:
    1. Scans the upload folder
    2. Extracts ZIP files if found
    3. Moves files to storage
    4. Creates database records
    5. Cleans up upload folder
    
    Returns a streaming response with progress updates.
    """
    try:
        if current_user.permission_level == 'viewer':
            return _viewer_write_error()

        case = Case.get_by_uuid(case_uuid)
        if not case:
            return jsonify({'success': False, 'error': 'Case not found'}), 404
        
        data = request.get_json() or {}
        selected_files = data.get('files', [])  # List of file info from scan
        
        def generate():
            try:
                case_paths = ensure_case_artifact_paths(case_uuid)
                upload_path = case_paths['pcap_upload']
                staging_path = case_paths['pcap_staging']
                
                ingested = 0
                extracted = 0
                errors = []
                extraction_failures = []
                
                # If no specific files provided, scan the folder
                if not selected_files:
                    all_files = []
                    for root, dirs, filenames in os.walk(upload_path):
                        for filename in filenames:
                            filepath = os.path.join(root, filename)
                            all_files.append({
                                'name': filename,
                                'path': filepath,
                                'hostname': detect_hostname_from_filename(filename)
                            })
                else:
                    all_files = selected_files
                
                total_files = len(all_files)
                
                # Separate ZIP files from PCAP files
                zip_files = []
                pcap_files = []
                
                real_upload_path = os.path.realpath(upload_path)
                for f in all_files:
                    filepath = f.get('path') or os.path.join(upload_path, f['name'])
                    if not os.path.realpath(filepath).startswith(real_upload_path + os.sep):
                        continue
                    if os.path.exists(filepath):
                        if PcapFile.is_zip_file(filepath):
                            zip_files.append(f)
                        else:
                            pcap_files.append(f)
                
                # Stage 1: Extract ZIP files
                if zip_files:
                    yield json.dumps({'stage': 'extract', 'current': 0, 'total': len(zip_files), 'filename': ''}) + '\n'
                    
                    for idx, zf in enumerate(zip_files):
                        filepath = zf.get('path') or os.path.join(upload_path, zf['name'])
                        filename = zf['name']
                        hostname = zf.get('hostname', '')
                        
                        yield json.dumps({'stage': 'extract', 'current': idx + 1, 'total': len(zip_files), 'filename': filename}) + '\n'
                        
                        try:
                            # Calculate hash of archive
                            archive_hash = PcapFile.calculate_sha256(filepath)
                            archive_size = os.path.getsize(filepath)
                            
                            # Create archive record
                            archive_record = PcapFile(
                                case_uuid=case_uuid,
                                filename=filename,
                                original_filename=filename,
                                file_path=None,
                                source_path=filepath,
                                file_size=archive_size,
                                sha256_hash=archive_hash,
                                hostname=hostname,
                                upload_source='folder',
                                is_archive=True,
                                extraction_status='pending',
                                status=PcapFileStatus.NEW,
                                retention_state='archived',
                                uploaded_by=current_user.username
                            )
                            db.session.add(archive_record)
                            db.session.flush()
                            
                            # Extract ZIP
                            extract_dir = os.path.join(staging_path, f'_extract_{archive_record.id}')
                            os.makedirs(extract_dir, exist_ok=True)
                            
                            extracted_count = 0
                            extracted_members = []
                            real_extract_dir = os.path.realpath(extract_dir)
                            with zipfile.ZipFile(filepath, 'r') as zf_handle:
                                members = zf_handle.infolist()
                                if len(members) > 50000:
                                    raise ValueError('Archive contains too many members')
                                if sum(member.file_size for member in members) > 20 * 1024 * 1024 * 1024:
                                    raise ValueError('Archive exceeds uncompressed size limit')
                                for member_info in members:
                                    member = member_info.filename
                                    if member.endswith('/'):
                                        continue  # Skip directories
                                    
                                    target_path = os.path.realpath(os.path.join(extract_dir, member))
                                    if not target_path.startswith(real_extract_dir + os.sep):
                                        extraction_failures.append(f"{filename}/{member}: path traversal blocked")
                                        continue
                                    
                                    # Extract file
                                    try:
                                        extracted_path = zf_handle.extract(member, extract_dir)
                                        member_name = os.path.basename(member)
                                        
                                        # Check if it's a PCAP file
                                        if PcapFile.is_pcap_file(extracted_path):
                                            extracted_members.append({
                                                'name': member_name,
                                                'path': extracted_path,
                                                'hostname': hostname or detect_hostname_from_filename(member_name),
                                                'parent_id': archive_record.id,
                                            })
                                            extracted_count += 1
                                            extracted += 1
                                    except Exception as e:
                                        extraction_failures.append(f"{filename}/{member}: {str(e)}")
                            
                            # Update archive status
                            if extracted_count > 0:
                                archive_record.extraction_status = 'full'
                            else:
                                archive_record.extraction_status = 'partial' if extraction_failures else 'full'

                            archive_dest = move_to_directory(
                                filepath,
                                ensure_pcap_originals_dir(case_uuid, 'archives'),
                                filename
                            )
                            if archive_dest:
                                archive_record.file_path = archive_dest
                                archive_record.source_path = archive_dest
                                for extracted_member in extracted_members:
                                    extracted_member['retained_original_path'] = archive_dest
                                    pcap_files.append(extracted_member)
                            else:
                                archive_record.status = PcapFileStatus.ERROR
                                archive_record.error_message = 'Failed to retain archive in originals'
                            
                            db.session.commit()
                            
                        except Exception as e:
                            extraction_failures.append(f"{filename}: {str(e)}")
                            logger.error(f"Failed to extract {filename}: {e}")
                
                # Stage 2: Retain originals and process transient staging copies
                if pcap_files:
                    yield json.dumps({'stage': 'move', 'current': 0, 'total': len(pcap_files), 'filename': ''}) + '\n'
                    
                    for idx, pf in enumerate(pcap_files):
                        filepath = pf.get('path')
                        filename = pf['name']
                        hostname = pf.get('hostname', '')
                        parent_id = pf.get('parent_id')
                        
                        yield json.dumps({'stage': 'move', 'current': idx + 1, 'total': len(pcap_files), 'filename': filename}) + '\n'
                        
                        try:
                            if not os.path.exists(filepath):
                                errors.append(f"{filename}: File not found")
                                continue

                            retained_original = pf.get('retained_original_path')
                            working_path = filepath
                            if parent_id is None:
                                retained_original = move_to_directory(
                                    filepath,
                                    ensure_pcap_originals_dir(case_uuid),
                                    filename,
                                )
                                if not retained_original:
                                    errors.append(f"{filename}: Failed to retain original upload")
                                    continue
                                working_path = copy_to_directory(retained_original, staging_path, filename)
                                if not working_path:
                                    errors.append(f"{filename}: Failed to create staging copy from retained original")
                                    continue
                            
                            # Calculate hash
                            file_hash = PcapFile.calculate_sha256(working_path)
                            file_size = os.path.getsize(working_path)
                            pcap_type = PcapFile.detect_pcap_type(working_path)
                            
                            # Check for duplicates
                            existing = PcapFile.find_by_hash(file_hash, case_uuid)
                            if existing:
                                pcap_record = PcapFile(
                                    case_uuid=case_uuid,
                                    parent_id=parent_id,
                                    duplicate_of_id=existing.id,
                                    filename=filename,
                                    original_filename=filename,
                                    file_path=retained_original if parent_id is None else None,
                                    source_path=retained_original,
                                    file_size=file_size,
                                    sha256_hash=file_hash,
                                    hostname=hostname,
                                    upload_source='folder',
                                    is_archive=False,
                                    is_extracted=parent_id is not None,
                                    pcap_type=pcap_type,
                                    status=PcapFileStatus.DUPLICATE,
                                    retention_state='duplicate_retained',
                                    error_message=f'Duplicate of PCAP #{existing.id}',
                                    uploaded_by=current_user.username
                                )
                                db.session.add(pcap_record)
                                ingested += 1
                                _remove_file_if_present(working_path)
                                continue
                            
                            # Create database record
                            pcap_record = PcapFile(
                                case_uuid=case_uuid,
                                parent_id=parent_id,
                                filename=os.path.basename(working_path),
                                original_filename=filename,
                                file_path=working_path,
                                source_path=retained_original,
                                file_size=file_size,
                                sha256_hash=file_hash,
                                hostname=hostname,
                                upload_source='folder',
                                is_archive=False,
                                is_extracted=parent_id is not None,
                                pcap_type=pcap_type,
                                status=PcapFileStatus.NEW,
                                retention_state='retained',
                                uploaded_by=current_user.username
                            )
                            db.session.add(pcap_record)
                            ingested += 1
                            
                        except Exception as e:
                            errors.append(f"{filename}: {str(e)}")
                            logger.error(f"Failed to process {filename}: {e}")
                    
                    db.session.commit()
                
                # Stage 3: Cleanup
                yield json.dumps({'stage': 'cleanup'}) + '\n'
                
                # Clean up extraction temp directories only.
                for item in os.listdir(staging_path):
                    item_path = os.path.join(staging_path, item)
                    try:
                        if os.path.isdir(item_path) and item.startswith('_extract_'):
                            shutil.rmtree(item_path)
                    except Exception as e:
                        logger.warning(f"Cleanup failed for {item}: {e}")
                
                # Complete
                yield json.dumps({
                    'stage': 'complete',
                    'ingested': ingested,
                    'extracted': extracted,
                    'errors': errors,
                    'extraction_failures': extraction_failures
                }) + '\n'
                
            except Exception as e:
                logger.exception("Ingestion error")
                yield json.dumps({'stage': 'error', 'message': str(e)}) + '\n'
        
        return Response(
            stream_with_context(generate()),
            mimetype='application/x-ndjson'
        )
        
    except Exception as e:
        return jsonify({'success': False, 'error': str(e)}), 500


@pcap_bp.route('/<int:pcap_id>/delete', methods=['POST'])
@login_required
def delete_pcap_file(pcap_id):
    """Delete a PCAP file and all associated data (admin only)
    
    This endpoint:
    - Deletes all network logs from ClickHouse for this file
    - Deletes child files (extracted from archives) and their logs
    - Removes the Zeek output directory
    - Removes the file from disk
    - Removes the PcapFile record from PostgreSQL
    """
    if current_user.permission_level != 'administrator':
        return jsonify({'success': False, 'error': 'Administrator access required'}), 403
    
    try:
        from models.network_log import delete_pcap_logs
        from models.case import Case
        import shutil
        
        pcap_file = _get_pcap_for_user(pcap_id)
        if pcap_file is False:
            return jsonify({'success': False, 'error': 'Access denied'}), 403
        if not pcap_file:
            return jsonify({'success': False, 'error': 'PCAP file not found'}), 404
        
        # Get case for case_id needed by ClickHouse
        case = Case.get_by_uuid(pcap_file.case_uuid)
        case_id = case.id if case else None
        
        filename = pcap_file.filename
        file_path = pcap_file.file_path
        zeek_output = pcap_file.zeek_output_path
        
        deleted_stats = {
            'pcap_id': pcap_id,
            'filename': filename,
            'logs_deleted': pcap_file.logs_indexed or 0,
            'child_files_deleted': 0,
            'zeek_output_deleted': False,
            'disk_file_deleted': False
        }
        
        # Delete network logs from ClickHouse for this PCAP
        if case_id:
            try:
                delete_pcap_logs(pcap_id, case_id)
                logger.info(f"Deleted ClickHouse network logs for pcap_id={pcap_id}")
            except Exception as e:
                logger.error(f"Failed to delete ClickHouse logs for pcap_id={pcap_id}: {e}")
        
        # Delete extracted files if this is an archive
        if pcap_file.is_archive:
            for child in pcap_file.extracted_files:
                # Delete child's ClickHouse logs
                if case_id:
                    try:
                        delete_pcap_logs(child.id, case_id)
                        logger.info(f"Deleted ClickHouse logs for child pcap_id={child.id}")
                    except Exception as e:
                        logger.warning(f"Failed to delete ClickHouse logs for child {child.id}: {e}")
                
                # Delete child's Zeek output directory
                if child.zeek_output_path and os.path.isdir(child.zeek_output_path):
                    try:
                        shutil.rmtree(child.zeek_output_path)
                        logger.info(f"Deleted child Zeek output: {child.zeek_output_path}")
                    except Exception as e:
                        logger.warning(f"Failed to delete child Zeek output {child.zeek_output_path}: {e}")
                
                # Delete child file from disk
                if child.file_path and os.path.exists(child.file_path):
                    try:
                        os.remove(child.file_path)
                    except Exception as e:
                        logger.warning(f"Failed to delete child file {child.file_path}: {e}")
                
                db.session.delete(child)
                deleted_stats['child_files_deleted'] += 1
        
        # Delete Zeek output directory
        if zeek_output and os.path.isdir(zeek_output):
            try:
                shutil.rmtree(zeek_output)
                deleted_stats['zeek_output_deleted'] = True
                logger.info(f"Deleted Zeek output directory: {zeek_output}")
            except Exception as e:
                logger.error(f"Failed to delete Zeek output {zeek_output}: {e}")
        
        # Delete physical PCAP file
        if file_path and os.path.exists(file_path):
            try:
                os.remove(file_path)
                deleted_stats['disk_file_deleted'] = True
                logger.info(f"Deleted PCAP file from disk: {file_path}")
            except Exception as e:
                logger.error(f"Failed to delete PCAP file {file_path}: {e}")
        
        # Delete database record
        db.session.delete(pcap_file)
        db.session.commit()
        
        logger.info(f"PCAP file {pcap_id} ({filename}) fully deleted by {current_user.username}")
        
        return jsonify({
            'success': True,
            'message': f'PCAP file "{filename}" deleted successfully',
            **deleted_stats
        })
        
    except Exception as e:
        logger.error(f"Error deleting PCAP file {pcap_id}: {e}")
        db.session.rollback()
        return jsonify({'success': False, 'error': str(e)}), 500


@pcap_bp.route('/<int:pcap_id>/edit', methods=['POST'])
@login_required
def edit_pcap_file(pcap_id):
    """Edit PCAP file metadata"""
    if current_user.permission_level == 'viewer':
        return _viewer_write_error()
    
    try:
        pcap_file = _get_pcap_for_user(pcap_id)
        if pcap_file is False:
            return jsonify({'success': False, 'error': 'Access denied'}), 403
        if not pcap_file:
            return jsonify({'success': False, 'error': 'PCAP file not found'}), 404
        
        data = request.get_json()
        
        if 'hostname' in data:
            pcap_file.hostname = data['hostname'].strip().upper() if data['hostname'] else None
        
        if 'description' in data:
            pcap_file.description = data['description'].strip() if data['description'] else None
        
        db.session.commit()
        
        return jsonify({'success': True, 'message': 'PCAP file updated'})
        
    except Exception as e:
        db.session.rollback()
        return jsonify({'success': False, 'error': str(e)}), 500


# =============================================================================
# WEB UPLOAD ENDPOINTS
# =============================================================================

@pcap_bp.route('/upload/chunk', methods=['POST'])
@login_required
def upload_chunk():
    """Handle chunked file upload for PCAP files"""
    import fcntl

    try:
        if current_user.permission_level == 'viewer':
            return _viewer_write_error()

        chunk = request.files.get('chunk')
        chunk_index = request.form.get('chunkIndex', type=int)
        total_chunks = request.form.get('totalChunks', type=int)
        upload_id = request.form.get('uploadId')
        filename = os.path.basename(request.form.get('filename') or '')
        case_uuid = request.form.get('caseUuid')
        
        if not all([chunk, chunk_index is not None, total_chunks, upload_id, filename, case_uuid]):
            return jsonify({'success': False, 'error': 'Missing required fields'}), 400
        
        # Verify case exists
        case = Case.get_by_uuid(case_uuid)
        if not case:
            return jsonify({'success': False, 'error': 'Case not found'}), 404
        
        # Create upload directory
        upload_path = ensure_pcap_upload_dir(case_uuid)
        temp_dir = os.path.join(upload_path, f'.temp_{upload_id}')
        os.makedirs(temp_dir, exist_ok=True)
        
        # Save chunk
        chunk_path = os.path.join(temp_dir, f'chunk_{chunk_index:06d}')
        chunk.save(chunk_path)
        
        # Check if all chunks received
        received_chunks = len([f for f in os.listdir(temp_dir) if f.startswith('chunk_')])
        
        if received_chunks >= total_chunks:
            lock_path = os.path.join(temp_dir, '.combine_lock')
            try:
                with open(lock_path, 'w') as lock_file:
                    fcntl.flock(lock_file.fileno(), fcntl.LOCK_EX | fcntl.LOCK_NB)

                    received_chunks = len([f for f in os.listdir(temp_dir) if f.startswith('chunk_')])
                    if received_chunks < total_chunks:
                        return jsonify({
                            'success': True,
                            'complete': False,
                            'received': received_chunks,
                            'total': total_chunks
                        })

                    final_path = os.path.join(upload_path, filename)
                    if os.path.exists(final_path):
                        base, ext = os.path.splitext(filename)
                        counter = 1
                        while os.path.exists(final_path):
                            final_path = os.path.join(upload_path, f'{base}_{counter}{ext}')
                            counter += 1

                    with open(final_path, 'wb') as outfile:
                        for i in range(total_chunks):
                            chunk_file = os.path.join(temp_dir, f'chunk_{i:06d}')
                            with open(chunk_file, 'rb') as infile:
                                outfile.write(infile.read())

                    try:
                        shutil.chown(final_path, user='casescope', group='casescope')
                    except (PermissionError, LookupError):
                        pass

                    shutil.rmtree(temp_dir, ignore_errors=True)

                    return jsonify({
                        'success': True,
                        'complete': True,
                        'filename': os.path.basename(final_path),
                        'path': final_path
                    })
            except BlockingIOError:
                return jsonify({
                    'success': True,
                    'complete': False,
                    'received': received_chunks,
                    'total': total_chunks,
                    'combining': True
                })
        
        return jsonify({
            'success': True,
            'complete': False,
            'received': received_chunks,
            'total': total_chunks
        })
        
    except Exception as e:
        logger.exception("Chunk upload error")
        return jsonify({'success': False, 'error': str(e)}), 500


# =============================================================================
# ZEEK PROCESSING ENDPOINTS
# =============================================================================

@pcap_bp.route('/<int:pcap_id>/process', methods=['POST'])
@login_required
def process_pcap(pcap_id):
    """Queue a single PCAP file for Zeek processing"""
    if current_user.permission_level == 'viewer':
        return _viewer_write_error()
    
    try:
        pcap_file = _get_pcap_for_user(pcap_id)
        if pcap_file is False:
            return jsonify({'success': False, 'error': 'Access denied'}), 403
        if not pcap_file:
            return jsonify({'success': False, 'error': 'PCAP file not found'}), 404
        
        if pcap_file.is_archive:
            return jsonify({'success': False, 'error': 'Cannot process archive files directly'}), 400
        
        # Update status to queued
        pcap_file.status = PcapFileStatus.QUEUED
        db.session.commit()
        
        # Queue a combined processing + indexing task.
        from tasks.pcap_tasks import process_and_index_pcap
        task = process_and_index_pcap.delay(pcap_id)
        
        return jsonify({
            'success': True,
            'pcap_id': pcap_id,
            'task_id': task.id,
            'message': 'Queued for Zeek processing and network indexing'
        })
        
    except Exception as e:
        logger.exception(f"Error queuing PCAP {pcap_id}")
        return jsonify({'success': False, 'error': str(e)}), 500


@pcap_bp.route('/<int:pcap_id>/rebuild', methods=['POST'])
@login_required
def rebuild_pcap(pcap_id):
    """Rebuild a PCAP from retained originals."""
    if current_user.permission_level == 'viewer':
        return _viewer_write_error()

    try:
        pcap_file = _get_pcap_for_user(pcap_id)
        if pcap_file is False:
            return jsonify({'success': False, 'error': 'Access denied'}), 403
        if not pcap_file:
            return jsonify({'success': False, 'error': 'PCAP file not found'}), 404

        from tasks.pcap_tasks import rebuild_pcap_from_originals

        task = rebuild_pcap_from_originals.delay(pcap_id=pcap_id, username=current_user.username)
        return jsonify({
            'success': True,
            'pcap_id': pcap_id,
            'task_id': task.id,
            'message': 'Originals-based PCAP rebuild queued',
        })
    except Exception as e:
        logger.exception(f"Error queuing PCAP rebuild {pcap_id}")
        return jsonify({'success': False, 'error': str(e)}), 500


@pcap_bp.route('/process-all/<case_uuid>', methods=['POST'])
@login_required
def process_all_pcaps(case_uuid):
    """Queue all pending PCAP files for a case for Zeek processing"""
    if current_user.permission_level == 'viewer':
        return _viewer_write_error()
    
    try:
        case = Case.get_by_uuid(case_uuid)
        if not case:
            return jsonify({'success': False, 'error': 'Case not found'}), 404
        
        # Get pending PCAP files
        pending = PcapFile.query.filter(
            PcapFile.case_uuid == case_uuid,
            PcapFile.is_archive == False,
            PcapFile.status == PcapFileStatus.NEW
        ).all()
        
        if not pending:
            return jsonify({'success': False, 'error': 'No pending PCAP files to process'}), 400
        
        # Queue each for processing + indexing
        from tasks.pcap_tasks import process_and_index_pcap
        queued = []
        
        for pcap in pending:
            pcap.status = PcapFileStatus.QUEUED
            db.session.commit()
            
            task = process_and_index_pcap.delay(pcap.id)
            queued.append({
                'pcap_id': pcap.id,
                'filename': pcap.filename,
                'task_id': task.id
            })
        
        return jsonify({
            'success': True,
            'queued_count': len(queued),
            'queued': queued
        })
        
    except Exception as e:
        logger.exception(f"Error queuing PCAPs for case {case_uuid}")
        return jsonify({'success': False, 'error': str(e)}), 500


@pcap_bp.route('/rebuild-all/<case_uuid>', methods=['POST'])
@login_required
def rebuild_all_pcaps(case_uuid):
    """Rebuild all retained PCAPs for a case."""
    if current_user.permission_level == 'viewer':
        return _viewer_write_error()

    try:
        case = Case.get_by_uuid(case_uuid)
        if not case:
            return jsonify({'success': False, 'error': 'Case not found'}), 404

        from tasks.pcap_tasks import rebuild_case_pcaps_from_originals

        task = rebuild_case_pcaps_from_originals.delay(case_uuid=case_uuid, username=current_user.username)
        return jsonify({
            'success': True,
            'case_uuid': case_uuid,
            'task_id': task.id,
            'message': 'Originals-based PCAP case rebuild queued',
        })
    except Exception as e:
        logger.exception(f"Error queuing PCAP case rebuild {case_uuid}")
        return jsonify({'success': False, 'error': str(e)}), 500


@pcap_bp.route('/<int:pcap_id>/logs', methods=['GET'])
@login_required
def get_pcap_logs(pcap_id):
    """Get list of Zeek log files for a processed PCAP"""
    try:
        pcap_file = _get_pcap_for_user(pcap_id)
        if pcap_file is False:
            return jsonify({'success': False, 'error': 'Access denied'}), 403
        if not pcap_file:
            return jsonify({'success': False, 'error': 'PCAP file not found'}), 404
        
        if not pcap_file.zeek_output_path or not os.path.exists(pcap_file.zeek_output_path):
            return jsonify({
                'success': True,
                'pcap_id': pcap_id,
                'logs': [],
                'message': 'No Zeek output available'
            })
        
        logs = []
        for item in os.listdir(pcap_file.zeek_output_path):
            if item.endswith('.log'):
                log_path = os.path.join(pcap_file.zeek_output_path, item)
                stat = os.stat(log_path)
                
                # Count lines (excluding headers)
                line_count = 0
                with open(log_path, 'r') as f:
                    for line in f:
                        if not line.startswith('#'):
                            line_count += 1
                
                logs.append({
                    'name': item,
                    'size': stat.st_size,
                    'lines': line_count,
                    'modified': datetime.fromtimestamp(stat.st_mtime).isoformat()
                })
        
        # Sort by name
        logs.sort(key=lambda x: x['name'])
        
        return jsonify({
            'success': True,
            'pcap_id': pcap_id,
            'filename': pcap_file.filename,
            'output_path': pcap_file.zeek_output_path,
            'logs': logs,
            'total_logs': len(logs)
        })
        
    except Exception as e:
        logger.exception(f"Error getting logs for PCAP {pcap_id}")
        return jsonify({'success': False, 'error': str(e)}), 500


@pcap_bp.route('/<int:pcap_id>/log/<log_name>', methods=['GET'])
@login_required
def get_log_content(pcap_id, log_name):
    """Get content of a specific Zeek log file"""
    try:
        pcap_file = _get_pcap_for_user(pcap_id)
        if pcap_file is False:
            return jsonify({'success': False, 'error': 'Access denied'}), 403
        if not pcap_file:
            return jsonify({'success': False, 'error': 'PCAP file not found'}), 404
        
        if not pcap_file.zeek_output_path:
            return jsonify({'success': False, 'error': 'No Zeek output available'}), 404
        
        # Sanitize log_name to prevent path traversal
        if '/' in log_name or '..' in log_name:
            return jsonify({'success': False, 'error': 'Invalid log name'}), 400
        
        log_path = os.path.join(pcap_file.zeek_output_path, log_name)
        if not os.path.exists(log_path):
            return jsonify({'success': False, 'error': f'Log file {log_name} not found'}), 404
        
        # Get query params
        limit = request.args.get('limit', 500, type=int)
        offset = request.args.get('offset', 0, type=int)
        columns = request.args.get('columns', '')
        
        # Parse headers and content
        headers = []
        types = []
        lines = []
        total_lines = 0
        
        with open(log_path, 'r') as f:
            for line in f:
                line = line.strip()
                
                if line.startswith('#'):
                    # Parse header metadata
                    if line.startswith('#fields'):
                        headers = line.replace('#fields\t', '').split('\t')
                    elif line.startswith('#types'):
                        types = line.replace('#types\t', '').split('\t')
                    continue
                
                total_lines += 1
                
                if total_lines > offset and len(lines) < limit:
                    lines.append(line.split('\t'))
        
        return jsonify({
            'success': True,
            'pcap_id': pcap_id,
            'log_name': log_name,
            'headers': headers,
            'types': types,
            'lines': lines,
            'offset': offset,
            'limit': limit,
            'returned': len(lines),
            'total_lines': total_lines
        })
        
    except Exception as e:
        logger.exception(f"Error reading log {log_name} for PCAP {pcap_id}")
        return jsonify({'success': False, 'error': str(e)}), 500


@pcap_bp.route('/<int:pcap_id>/status', methods=['GET'])
@login_required
def get_pcap_status(pcap_id):
    """Get processing status of a PCAP file"""
    try:
        pcap_file = _get_pcap_for_user(pcap_id)
        if pcap_file is False:
            return jsonify({'success': False, 'error': 'Access denied'}), 403
        if not pcap_file:
            return jsonify({'success': False, 'error': 'PCAP file not found'}), 404
        
        return jsonify({
            'success': True,
            'pcap_id': pcap_id,
            'filename': pcap_file.filename,
            'status': pcap_file.status,
            'logs_generated': pcap_file.logs_generated,
            'processed_at': pcap_file.processed_at.isoformat() if pcap_file.processed_at else None,
            'error_message': pcap_file.error_message
        })
        
    except Exception as e:
        return jsonify({'success': False, 'error': str(e)}), 500
