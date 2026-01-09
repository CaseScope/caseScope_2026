"""API routes for CaseScope"""
import os
import json
import platform
import subprocess
import shutil
import zipfile
from datetime import datetime
from flask import Blueprint, jsonify, request, Response, stream_with_context
from flask_login import login_required, current_user
from models.database import db
from models.user import User
from models.case import Case
from models.case_file import CaseFile, ExtractionStatus
from config import Config

api_bp = Blueprint('api', __name__, url_prefix='/api')


def get_folder_size_gb(path):
    """Get folder size in GB"""
    try:
        if not os.path.exists(path):
            return 0.0
        total = 0
        for dirpath, dirnames, filenames in os.walk(path):
            for f in filenames:
                fp = os.path.join(dirpath, f)
                try:
                    total += os.path.getsize(fp)
                except (OSError, FileNotFoundError):
                    pass
        return round(total / (1024 ** 3), 2)
    except Exception:
        return 0.0


def get_software_version(command):
    """Get software version from command"""
    try:
        result = subprocess.run(
            command, 
            shell=True, 
            capture_output=True, 
            text=True, 
            timeout=5
        )
        version = result.stdout.strip().split('\n')[0] if result.stdout else 'Not installed'
        return version if version else 'Not installed'
    except Exception:
        return 'Not installed'


@api_bp.route('/dashboard/stats')
@login_required
def dashboard_stats():
    """Get dashboard statistics"""
    try:
        import psutil
        
        # System info
        hostname = platform.node()
        os_info = f"{platform.system()} {platform.release()}"
        
        # CPU
        cpu_percent = psutil.cpu_percent(interval=0.1)
        cpu_cores = psutil.cpu_count()
        
        # RAM
        ram = psutil.virtual_memory()
        ram_total_gb = round(ram.total / (1024 ** 3), 2)
        ram_used_gb = round(ram.used / (1024 ** 3), 2)
        
        # Disks
        disks = []
        for partition in psutil.disk_partitions():
            if partition.device.startswith('/dev/') and not partition.mountpoint.startswith('/snap'):
                try:
                    usage = psutil.disk_usage(partition.mountpoint)
                    disks.append({
                        'device': partition.device,
                        'mountpoint': partition.mountpoint,
                        'total_gb': round(usage.total / (1024 ** 3), 2),
                        'used_gb': round(usage.used / (1024 ** 3), 2),
                        'percent': usage.percent
                    })
                except PermissionError:
                    pass
        
        # Case storage
        live_gb = get_folder_size_gb(Config.STORAGE_FOLDER)
        archive_gb = get_folder_size_gb(os.path.join(Config.BASE_DIR, 'archive'))
        
        # Software versions
        software = {
            'python': platform.python_version(),
            'flask': get_software_version("pip show flask | grep Version | cut -d' ' -f2"),
            'postgresql': get_software_version("psql --version | head -1"),
            'casescope': '3.1.0'
        }
        
        # Case statistics (placeholder until cases are implemented)
        total_cases = 0
        total_events = 0
        total_users = User.query.count()
        
        return jsonify({
            'timestamp': datetime.utcnow().isoformat(),
            'system': {
                'hostname': hostname,
                'os': os_info,
                'cpu': {
                    'usage_percent': cpu_percent,
                    'cores': cpu_cores
                },
                'ram': {
                    'total_gb': ram_total_gb,
                    'used_gb': ram_used_gb,
                    'percent': ram.percent
                },
                'disks': disks,
                'case_storage': {
                    'live_gb': live_gb,
                    'archive_gb': archive_gb
                }
            },
            'cases': {
                'total_cases': total_cases,
                'total_events': total_events,
                'total_users': total_users
            },
            'software': software
        })
        
    except Exception as e:
        return jsonify({'error': str(e)}), 500


# ============================================
# File Upload API Endpoints
# ============================================

# Upload directories
WEB_UPLOAD_DIR = '/opt/casescope/uploads/web'
SFTP_UPLOAD_DIR = '/opt/casescope/uploads/sftp'
CHUNK_TEMP_DIR = '/opt/casescope/uploads/temp'
STAGING_DIR = '/opt/casescope/staging'


def ensure_upload_dirs(case_uuid):
    """Ensure upload directories exist for a case"""
    web_path = os.path.join(WEB_UPLOAD_DIR, case_uuid)
    sftp_path = os.path.join(SFTP_UPLOAD_DIR, case_uuid)
    staging_path = os.path.join(STAGING_DIR, case_uuid)
    
    os.makedirs(web_path, exist_ok=True)
    os.makedirs(sftp_path, exist_ok=True)
    os.makedirs(staging_path, exist_ok=True)
    os.makedirs(CHUNK_TEMP_DIR, exist_ok=True)
    
    # Set permissions to casescope user
    for path in [web_path, sftp_path, staging_path]:
        try:
            shutil.chown(path, user='casescope', group='casescope')
        except (PermissionError, LookupError):
            pass  # May not have permission to chown
    
    return web_path, sftp_path, staging_path


@api_bp.route('/upload/scan/<case_uuid>')
@login_required
def scan_upload_folder(case_uuid):
    """Scan the SFTP folder for uploaded files"""
    try:
        # Verify case exists
        case = Case.get_by_uuid(case_uuid)
        if not case:
            return jsonify({'success': False, 'error': 'Case not found'}), 404
        
        _, sftp_path, _ = ensure_upload_dirs(case_uuid)
        
        files = []
        if os.path.exists(sftp_path):
            for filename in os.listdir(sftp_path):
                filepath = os.path.join(sftp_path, filename)
                if os.path.isfile(filepath):
                    stat = os.stat(filepath)
                    files.append({
                        'name': filename,
                        'path': filepath,
                        'size': stat.st_size,
                        'modified': datetime.fromtimestamp(stat.st_mtime).isoformat()
                    })
        
        return jsonify({
            'success': True,
            'path': sftp_path,
            'files': files
        })
        
    except Exception as e:
        return jsonify({'success': False, 'error': str(e)}), 500


@api_bp.route('/upload/chunk', methods=['POST'])
@login_required
def upload_chunk():
    """Handle chunked file upload"""
    try:
        chunk = request.files.get('chunk')
        chunk_index = int(request.form.get('chunkIndex', 0))
        total_chunks = int(request.form.get('totalChunks', 1))
        upload_id = request.form.get('uploadId')
        filename = request.form.get('filename')
        case_uuid = request.form.get('caseUuid')
        
        if not all([chunk, upload_id, filename, case_uuid]):
            return jsonify({'success': False, 'error': 'Missing required fields'}), 400
        
        # Verify case exists
        case = Case.get_by_uuid(case_uuid)
        if not case:
            return jsonify({'success': False, 'error': 'Case not found'}), 404
        
        # Ensure directories exist
        web_path, _, _ = ensure_upload_dirs(case_uuid)
        
        # Create temp directory for this upload
        temp_dir = os.path.join(CHUNK_TEMP_DIR, upload_id)
        os.makedirs(temp_dir, exist_ok=True)
        
        # Save chunk
        chunk_path = os.path.join(temp_dir, f'chunk_{chunk_index:06d}')
        chunk.save(chunk_path)
        
        # Check if all chunks are uploaded
        existing_chunks = len([f for f in os.listdir(temp_dir) if f.startswith('chunk_')])
        
        if existing_chunks >= total_chunks:
            # Combine chunks
            final_path = os.path.join(web_path, filename)
            
            # Avoid filename collisions
            if os.path.exists(final_path):
                base, ext = os.path.splitext(filename)
                counter = 1
                while os.path.exists(final_path):
                    final_path = os.path.join(web_path, f'{base}_{counter}{ext}')
                    counter += 1
            
            with open(final_path, 'wb') as outfile:
                for i in range(total_chunks):
                    chunk_file = os.path.join(temp_dir, f'chunk_{i:06d}')
                    with open(chunk_file, 'rb') as infile:
                        outfile.write(infile.read())
            
            # Clean up temp directory
            shutil.rmtree(temp_dir, ignore_errors=True)
            
            # Set file ownership
            try:
                shutil.chown(final_path, user='casescope', group='casescope')
            except (PermissionError, LookupError):
                pass
            
            return jsonify({
                'success': True,
                'complete': True,
                'path': final_path
            })
        
        return jsonify({
            'success': True,
            'complete': False,
            'chunksReceived': existing_chunks
        })
        
    except Exception as e:
        return jsonify({'success': False, 'error': str(e)}), 500


@api_bp.route('/upload/preflight', methods=['POST'])
@login_required
def preflight_check():
    """Check for duplicate files before ingestion
    
    Calculates hashes for all files and checks against existing records.
    Returns list of duplicates for user confirmation.
    """
    try:
        data = request.get_json()
        case_uuid = data.get('caseUuid')
        files = data.get('files', [])
        
        if not case_uuid:
            return jsonify({'success': False, 'error': 'Case UUID required'}), 400
        
        if not files:
            return jsonify({'success': False, 'error': 'No files to check'}), 400
        
        case = Case.get_by_uuid(case_uuid)
        if not case:
            return jsonify({'success': False, 'error': 'Case not found'}), 404
        
        web_path, sftp_path, _ = ensure_upload_dirs(case_uuid)
        
        duplicates = []
        file_hashes = {}  # Map filename -> hash for later use
        
        for file_info in files:
            filename = file_info.get('name')
            source = file_info.get('source', 'web')
            
            # Determine source path
            if source == 'folder':
                source_path = file_info.get('path')
            else:
                source_path = os.path.join(web_path, filename)
            
            if not source_path or not os.path.exists(source_path):
                continue
            
            # Calculate hash
            try:
                file_hash = CaseFile.calculate_sha256(source_path)
                file_hashes[filename] = file_hash
                
                # Check for existing file with same hash
                existing = CaseFile.find_by_hash(file_hash)
                if existing:
                    duplicates.append({
                        'new_file': filename,
                        'new_hash': file_hash,
                        'existing_file': existing.filename,
                        'existing_hash': existing.sha256_hash,
                        'existing_case': existing.case_uuid,
                        'uploaded_at': existing.uploaded_at.strftime('%Y-%m-%d %H:%M:%S'),
                        'source': source
                    })
            except Exception as e:
                # Hash calculation failed - will handle during ingestion
                pass
        
        return jsonify({
            'success': True,
            'duplicates': duplicates,
            'file_hashes': file_hashes,
            'has_duplicates': len(duplicates) > 0
        })
        
    except Exception as e:
        return jsonify({'success': False, 'error': str(e)}), 500


@api_bp.route('/upload/ingest', methods=['POST'])
@login_required
def ingest_files():
    """Process and ingest files with streaming progress updates"""
    # Get request data before entering generator (request context needed)
    data = request.get_json()
    case_uuid = data.get('caseUuid')
    files = data.get('files', [])
    skip_files = data.get('skipFiles', [])  # Files user chose not to reingest
    file_hashes = data.get('fileHashes', {})  # Pre-calculated hashes from preflight
    uploaded_by = current_user.username
    
    # Validate upfront
    if not case_uuid:
        return jsonify({'success': False, 'error': 'Case UUID required'}), 400
    
    if not files:
        return jsonify({'success': False, 'error': 'No files to ingest'}), 400
    
    case = Case.get_by_uuid(case_uuid)
    if not case:
        return jsonify({'success': False, 'error': 'Case not found'}), 404
    
    def generate_progress():
        """Generator that yields NDJSON progress updates"""
        from flask import current_app
        
        web_path, sftp_path, staging_path = ensure_upload_dirs(case_uuid)
        
        ingested_count = 0
        extracted_count = 0
        duplicates_skipped = 0
        duplicates_deleted = 0
        extraction_failures = []
        errors = []
        processed_files = []  # Track files for hash stage
        zip_files = []  # Track zip files for extraction stage
        zip_records = {}  # Map zip filename -> CaseFile record
        non_zip_files = []  # Track non-zip files for move stage
        
        # =============================================
        # PHASE 1: Identify files and check existence
        # =============================================
        for file_info in files:
            filename = file_info.get('name')
            source = file_info.get('source', 'web')
            
            # Skip files user chose not to reingest
            if filename in skip_files:
                duplicates_skipped += 1
                continue
            
            if source == 'folder':
                source_path = file_info.get('path')
            else:
                source_path = os.path.join(web_path, filename)
            
            if not source_path or not os.path.exists(source_path):
                errors.append(f'File not found: {filename}')
                continue
            
            # Check if it's a zip file
            is_zip = CaseFile.is_zip_file(source_path)
            
            file_data = {
                'name': filename,
                'source_path': source_path,
                'file_info': file_info,
                'is_zip': is_zip,
                'hash': file_hashes.get(filename)  # May be None if not pre-calculated
            }
            
            if is_zip:
                zip_files.append(file_data)
            else:
                non_zip_files.append(file_data)
        
        # =============================================
        # PHASE 2: Extract ZIP files directly to staging
        # =============================================
        if zip_files:
            total_zips = len(zip_files)
            for idx, zf in enumerate(zip_files):
                yield json.dumps({
                    'stage': 'extract',
                    'current': idx + 1,
                    'total': total_zips,
                    'filename': zf['name']
                }) + '\n'
                
                source_path = zf['source_path']
                filename = zf['name']
                file_info = zf['file_info']
                
                # Calculate hash if not already done
                zip_hash = zf.get('hash')
                if not zip_hash:
                    try:
                        zip_hash = CaseFile.calculate_sha256(source_path)
                    except Exception as e:
                        errors.append(f'Error hashing {filename}: {str(e)}')
                        continue
                
                # Get file size before extraction
                zip_size = os.path.getsize(source_path)
                
                # Create extraction directory: staging/case_uuid/zipname/
                extract_dir = os.path.join(staging_path, filename)
                os.makedirs(extract_dir, exist_ok=True)
                
                try:
                    shutil.chown(extract_dir, user='casescope', group='casescope')
                except (PermissionError, LookupError):
                    pass
                
                # Attempt extraction
                extraction_status = ExtractionStatus.FAIL
                extracted_file_count = 0
                
                try:
                    with zipfile.ZipFile(source_path, 'r') as zfile:
                        zfile.extractall(extract_dir)
                    extraction_status = ExtractionStatus.FULL
                    
                    # Track extracted files
                    for root, dirs, extracted_files_list in os.walk(extract_dir):
                        for extracted_name in extracted_files_list:
                            extracted_path = os.path.join(root, extracted_name)
                            rel_path = os.path.relpath(extracted_path, extract_dir)
                            processed_files.append({
                                'path': extracted_path,
                                'filename': rel_path,
                                'original_filename': extracted_name,
                                'file_info': file_info,
                                'is_archive': CaseFile.is_zip_file(extracted_path),
                                'is_extracted': True,
                                'parent_zip': filename
                            })
                            extracted_file_count += 1
                    
                except zipfile.BadZipFile:
                    extraction_status = ExtractionStatus.FAIL
                    extraction_failures.append(f'{filename}: Invalid ZIP file')
                    # Treat as regular file
                    non_zip_files.append(zf)
                except Exception as e:
                    # Check if partial extraction occurred
                    extracted_count_check = sum(1 for _ in os.walk(extract_dir) for _ in _[2])
                    if extracted_count_check > 0:
                        extraction_status = ExtractionStatus.PARTIAL
                        extraction_failures.append(f'{filename}: Partial extraction - {str(e)}')
                    else:
                        extraction_status = ExtractionStatus.FAIL
                        extraction_failures.append(f'{filename}: {str(e)}')
                
                # Record ZIP file in database (even if extraction failed)
                zip_record = CaseFile(
                    case_uuid=case_uuid,
                    parent_id=None,
                    filename=filename,
                    original_filename=filename,
                    file_path=None,  # ZIP is deleted after extraction
                    file_size=zip_size,
                    sha256_hash=zip_hash,
                    hostname=file_info.get('host', ''),
                    file_type=file_info.get('type', 'Other'),
                    upload_source=file_info.get('source', 'web'),
                    is_archive=True,
                    is_extracted=False,
                    extraction_status=extraction_status,
                    status='pending',
                    uploaded_by=uploaded_by
                )
                db.session.add(zip_record)
                db.session.flush()
                zip_records[filename] = zip_record
                ingested_count += 1
        
        # =============================================
        # PHASE 3: Move non-zip files to staging
        # =============================================
        if non_zip_files:
            total_non_zip = len(non_zip_files)
            for idx, nzf in enumerate(non_zip_files):
                yield json.dumps({
                    'stage': 'move',
                    'current': idx + 1,
                    'total': total_non_zip,
                    'filename': nzf['name']
                }) + '\n'
                
                try:
                    source_path = nzf['source_path']
                    filename = nzf['name']
                    file_info = nzf['file_info']
                    
                    dest_path = os.path.join(staging_path, filename)
                    
                    # Handle collisions
                    if os.path.exists(dest_path):
                        base, ext = os.path.splitext(filename)
                        counter = 1
                        while os.path.exists(dest_path):
                            dest_path = os.path.join(staging_path, f'{base}_{counter}{ext}')
                            counter += 1
                    
                    shutil.move(source_path, dest_path)
                    
                    try:
                        shutil.chown(dest_path, user='casescope', group='casescope')
                    except (PermissionError, LookupError):
                        pass
                    
                    processed_files.append({
                        'path': dest_path,
                        'filename': os.path.basename(dest_path),
                        'original_filename': filename,
                        'file_info': file_info,
                        'is_archive': False,
                        'is_extracted': False,
                        'parent_zip': None,
                        'hash': nzf.get('hash')
                    })
                    
                    ingested_count += 1
                    
                except Exception as e:
                    errors.append(f'Error moving {nzf["name"]}: {str(e)}')
        
        # =============================================
        # PHASE 4: Calculate hashes and record metadata
        # =============================================
        total_processed = len(processed_files)
        
        for idx, pf in enumerate(processed_files):
            yield json.dumps({
                'stage': 'hash',
                'current': idx + 1,
                'total': total_processed,
                'filename': pf['filename']
            }) + '\n'
            
            try:
                file_path = pf['path']
                file_size = os.path.getsize(file_path)
                
                # Use pre-calculated hash or calculate now
                sha256_hash = pf.get('hash')
                if not sha256_hash:
                    sha256_hash = CaseFile.calculate_sha256(file_path)
                
                # Check for duplicate
                existing = CaseFile.find_by_hash(sha256_hash)
                if existing:
                    # Duplicate found - delete the file and skip recording
                    os.remove(file_path)
                    duplicates_deleted += 1
                    continue
                
                # Get parent ZIP record if this is an extracted file
                parent_id = None
                parent_zip = pf.get('parent_zip')
                if parent_zip and parent_zip in zip_records:
                    parent_id = zip_records[parent_zip].id
                
                # Build filename with zip prefix for extracted files
                display_filename = pf['filename']
                if parent_zip:
                    display_filename = f"{parent_zip}/{pf['filename']}"
                
                case_file = CaseFile(
                    case_uuid=case_uuid,
                    parent_id=parent_id,
                    filename=display_filename,
                    original_filename=pf['original_filename'],
                    file_path=file_path,
                    file_size=file_size,
                    sha256_hash=sha256_hash,
                    hostname=pf['file_info'].get('host', ''),
                    file_type=pf['file_info'].get('type', 'Other'),
                    upload_source=pf['file_info'].get('source', 'web'),
                    is_archive=pf['is_archive'],
                    is_extracted=pf['is_extracted'],
                    extraction_status=ExtractionStatus.NA,
                    status='pending',
                    uploaded_by=uploaded_by
                )
                
                db.session.add(case_file)
                db.session.flush()
                
                if parent_zip:
                    extracted_count += 1
                    
            except Exception as e:
                errors.append(f'Error hashing {pf["filename"]}: {str(e)}')
        
        # =============================================
        # PHASE 5: Cleanup upload directories
        # =============================================
        yield json.dumps({'stage': 'cleanup'}) + '\n'
        
        try:
            # Clean up web upload directory
            for f in os.listdir(web_path):
                fpath = os.path.join(web_path, f)
                if os.path.isfile(fpath):
                    os.remove(fpath)
            
            # Clean up sftp upload directory
            for f in os.listdir(sftp_path):
                fpath = os.path.join(sftp_path, f)
                if os.path.isfile(fpath):
                    os.remove(fpath)
        except Exception as e:
            errors.append(f'Cleanup error: {str(e)}')
        
        # Commit all database changes
        try:
            db.session.commit()
        except Exception as e:
            db.session.rollback()
            errors.append(f'Database error: {str(e)}')
        
        # =============================================
        # COMPLETE
        # =============================================
        yield json.dumps({
            'stage': 'complete',
            'ingested': ingested_count,
            'extracted': extracted_count,
            'duplicates_skipped': duplicates_skipped,
            'duplicates_deleted': duplicates_deleted,
            'extraction_failures': extraction_failures,
            'errors': errors
        }) + '\n'
    
    return Response(
        stream_with_context(generate_progress()),
        mimetype='application/x-ndjson',
        headers={
            'Cache-Control': 'no-cache',
            'X-Accel-Buffering': 'no'
        }
    )
