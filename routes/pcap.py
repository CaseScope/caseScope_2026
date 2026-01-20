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

logger = logging.getLogger(__name__)

pcap_bp = Blueprint('pcap', __name__, url_prefix='/api/pcap')


def ensure_pcap_upload_dir(case_uuid):
    """Ensure the PCAP upload directory exists for a case
    
    Upload path: /opt/casescope/uploads/pcap/{case_uuid}
    """
    pcap_upload_path = os.path.join(Config.PCAP_UPLOAD_FOLDER, case_uuid)
    os.makedirs(pcap_upload_path, exist_ok=True)
    
    # Set proper permissions for upload access
    try:
        os.chmod(pcap_upload_path, 0o2775)
        shutil.chown(pcap_upload_path, user='casescope', group='casescope')
    except (PermissionError, LookupError):
        pass
    
    return pcap_upload_path


def ensure_pcap_storage_dir(case_uuid):
    """Ensure the PCAP storage directory exists for a case
    
    Storage path: /opt/casescope/storage/{case_uuid}/pcap
    """
    pcap_storage_path = os.path.join(Config.PCAP_STORAGE_FOLDER, case_uuid, 'pcap')
    os.makedirs(pcap_storage_path, exist_ok=True)
    
    try:
        shutil.chown(pcap_storage_path, user='casescope', group='casescope')
    except (PermissionError, LookupError):
        pass
    
    return pcap_storage_path


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
    try:
        case = Case.get_by_uuid(case_uuid)
        if not case:
            return jsonify({'success': False, 'error': 'Case not found'}), 404
        
        folder_path = ensure_pcap_upload_dir(case_uuid)
        
        deleted_count = 0
        errors = []
        
        if os.path.exists(folder_path):
            for root, dirs, filenames in os.walk(folder_path, topdown=False):
                for filename in filenames:
                    filepath = os.path.join(root, filename)
                    try:
                        os.remove(filepath)
                        deleted_count += 1
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
            'deleted_count': deleted_count,
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
        case = Case.get_by_uuid(case_uuid)
        if not case:
            return jsonify({'success': False, 'error': 'Case not found'}), 404
        
        data = request.get_json() or {}
        selected_files = data.get('files', [])  # List of file info from scan
        
        def generate():
            try:
                upload_path = ensure_pcap_upload_dir(case_uuid)
                storage_path = ensure_pcap_storage_dir(case_uuid)
                
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
                
                for f in all_files:
                    filepath = f.get('path') or os.path.join(upload_path, f['name'])
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
                                file_path=filepath,
                                file_size=archive_size,
                                sha256_hash=archive_hash,
                                hostname=hostname,
                                upload_source='folder',
                                is_archive=True,
                                extraction_status='pending',
                                status=PcapFileStatus.NEW,
                                uploaded_by=current_user.username
                            )
                            db.session.add(archive_record)
                            db.session.flush()
                            
                            # Extract ZIP
                            extract_dir = os.path.join(upload_path, f'_extract_{archive_record.id}')
                            os.makedirs(extract_dir, exist_ok=True)
                            
                            extracted_count = 0
                            with zipfile.ZipFile(filepath, 'r') as zf_handle:
                                for member in zf_handle.namelist():
                                    if member.endswith('/'):
                                        continue  # Skip directories
                                    
                                    # Extract file
                                    try:
                                        extracted_path = zf_handle.extract(member, extract_dir)
                                        member_name = os.path.basename(member)
                                        
                                        # Check if it's a PCAP file
                                        if PcapFile.is_pcap_file(extracted_path):
                                            pcap_files.append({
                                                'name': member_name,
                                                'path': extracted_path,
                                                'hostname': hostname or detect_hostname_from_filename(member_name),
                                                'parent_id': archive_record.id
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
                            
                            db.session.commit()
                            
                        except Exception as e:
                            extraction_failures.append(f"{filename}: {str(e)}")
                            logger.error(f"Failed to extract {filename}: {e}")
                
                # Stage 2: Move files to storage
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
                            
                            # Calculate hash
                            file_hash = PcapFile.calculate_sha256(filepath)
                            file_size = os.path.getsize(filepath)
                            pcap_type = PcapFile.detect_pcap_type(filepath)
                            
                            # Check for duplicates
                            existing = PcapFile.find_by_hash(file_hash, case_uuid)
                            if existing:
                                # Skip duplicate
                                try:
                                    os.remove(filepath)
                                except:
                                    pass
                                continue
                            
                            # Move to storage
                            dest_path = os.path.join(storage_path, filename)
                            
                            # Handle filename collision
                            if os.path.exists(dest_path):
                                base, ext = os.path.splitext(filename)
                                counter = 1
                                while os.path.exists(dest_path):
                                    dest_path = os.path.join(storage_path, f"{base}_{counter}{ext}")
                                    counter += 1
                            
                            shutil.move(filepath, dest_path)
                            
                            # Create database record
                            pcap_record = PcapFile(
                                case_uuid=case_uuid,
                                parent_id=parent_id,
                                filename=os.path.basename(dest_path),
                                original_filename=filename,
                                file_path=dest_path,
                                file_size=file_size,
                                sha256_hash=file_hash,
                                hostname=hostname,
                                upload_source='folder',
                                is_archive=False,
                                is_extracted=parent_id is not None,
                                pcap_type=pcap_type,
                                status=PcapFileStatus.NEW,
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
                
                # Clean up extracted directories and original ZIP files
                for item in os.listdir(upload_path):
                    item_path = os.path.join(upload_path, item)
                    try:
                        if os.path.isdir(item_path) and item.startswith('_extract_'):
                            shutil.rmtree(item_path)
                        elif os.path.isfile(item_path):
                            os.remove(item_path)
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
    """Delete a PCAP file (admin only)"""
    if current_user.permission_level != 'administrator':
        return jsonify({'success': False, 'error': 'Administrator access required'}), 403
    
    try:
        pcap_file = db.session.get(PcapFile, pcap_id)
        if not pcap_file:
            return jsonify({'success': False, 'error': 'PCAP file not found'}), 404
        
        filename = pcap_file.filename
        file_path = pcap_file.file_path
        
        # Delete physical file
        if file_path and os.path.exists(file_path):
            os.remove(file_path)
        
        # Delete extracted files if this is an archive
        if pcap_file.is_archive:
            for child in pcap_file.extracted_files:
                if child.file_path and os.path.exists(child.file_path):
                    os.remove(child.file_path)
                db.session.delete(child)
        
        # Delete database record
        db.session.delete(pcap_file)
        db.session.commit()
        
        logger.info(f"PCAP file {pcap_id} ({filename}) deleted by {current_user.username}")
        
        return jsonify({'success': True, 'message': 'PCAP file deleted'})
        
    except Exception as e:
        logger.error(f"Error deleting PCAP file {pcap_id}: {e}")
        db.session.rollback()
        return jsonify({'success': False, 'error': str(e)}), 500


@pcap_bp.route('/<int:pcap_id>/edit', methods=['POST'])
@login_required
def edit_pcap_file(pcap_id):
    """Edit PCAP file metadata"""
    if current_user.permission_level == 'viewer':
        return jsonify({'success': False, 'error': 'Viewers cannot edit files'}), 403
    
    try:
        pcap_file = db.session.get(PcapFile, pcap_id)
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
    try:
        chunk = request.files.get('chunk')
        chunk_index = request.form.get('chunkIndex', type=int)
        total_chunks = request.form.get('totalChunks', type=int)
        upload_id = request.form.get('uploadId')
        filename = request.form.get('filename')
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
        
        if received_chunks == total_chunks:
            # Combine chunks
            final_path = os.path.join(upload_path, filename)
            
            with open(final_path, 'wb') as outfile:
                for i in range(total_chunks):
                    chunk_file = os.path.join(temp_dir, f'chunk_{i:06d}')
                    with open(chunk_file, 'rb') as infile:
                        outfile.write(infile.read())
            
            # Cleanup temp directory
            shutil.rmtree(temp_dir)
            
            return jsonify({
                'success': True,
                'complete': True,
                'filename': filename,
                'path': final_path
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
