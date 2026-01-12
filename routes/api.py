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
        
        # Software versions - all pulled live from system
        # CaseScope version from version.json
        casescope_version = 'Unknown'
        try:
            with open(os.path.join(Config.BASE_DIR, 'version.json'), 'r') as f:
                casescope_version = json.load(f).get('version', 'Unknown')
        except Exception:
            pass
        
        # Get software versions using importlib.metadata (gunicorn restricts shell commands)
        from importlib.metadata import version as pkg_version
        
        # Hayabusa version from file (shell commands blocked by gunicorn caps)
        hayabusa_ver = 'v3.7.0'
        try:
            with open('/opt/casescope/bin/hayabusa_version.txt', 'r') as f:
                hayabusa_ver = f.read().strip()
        except Exception:
            pass
        
        # ClickHouse server version via Python client
        clickhouse_ver = 'Unknown'
        try:
            import clickhouse_connect
            ch_client = clickhouse_connect.get_client(host='localhost')
            result = ch_client.query("SELECT version()")
            clickhouse_ver = result.result_rows[0][0]
        except Exception:
            pass
        
        software = {
            'casescope': casescope_version,
            'python': platform.python_version(),
            'flask': pkg_version('flask'),
            'celery': pkg_version('celery'),
            'gunicorn': pkg_version('gunicorn'),
            'clickhouse': clickhouse_ver,
            'redis': pkg_version('redis'),
            'hayabusa': hayabusa_ver,
            'dissect': pkg_version('dissect.util'),
            'sqlalchemy': pkg_version('sqlalchemy'),
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
                    status='new',
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
                    status='new',
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
        # PHASE 6: Trigger parsing for all staged files
        # =============================================
        yield json.dumps({'stage': 'parsing', 'message': 'Queuing files for parsing...'}) + '\n'
        
        try:
            from tasks.celery_tasks import parse_file_task
            from models.case import Case
            from utils.progress import init_progress
            
            case = Case.get_by_uuid(case_uuid)
            if case:
                # Get all pending files for this case
                pending_files = CaseFile.query.filter_by(
                    case_uuid=case_uuid,
                    status='new'
                ).filter(
                    CaseFile.is_archive == False  # Don't parse ZIP files themselves
                ).all()
                
                # Count files to be queued
                files_to_queue = [cf for cf in pending_files if cf.file_path and os.path.exists(cf.file_path)]
                
                # Initialize Redis progress tracking for this batch
                if files_to_queue:
                    init_progress(case_uuid, len(files_to_queue))
                
                queued_count = 0
                for cf in files_to_queue:
                    cf.status = 'queued'
                    db.session.flush()
                    
                    parse_file_task.delay(
                        file_path=cf.file_path,
                        case_id=case.id,
                        source_host=cf.hostname or '',
                        case_file_id=cf.id,
                    )
                    queued_count += 1
                
                db.session.commit()
                yield json.dumps({
                    'stage': 'parsing_queued',
                    'queued_count': queued_count
                }) + '\n'
        except Exception as e:
            yield json.dumps({
                'stage': 'parsing_error',
                'error': str(e)
            }) + '\n'
        
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


# ============================================
# File Management API Endpoints
# ============================================

@api_bp.route('/files/stats/<case_uuid>')
@login_required
def get_file_stats(case_uuid):
    """Get file statistics for a case"""
    try:
        # Verify case exists
        case = Case.get_by_uuid(case_uuid)
        if not case:
            return jsonify({'success': False, 'error': 'Case not found'}), 404
        
        stats = CaseFile.get_stats(case_uuid)
        stats['success'] = True
        stats['case_uuid'] = case_uuid
        
        return jsonify(stats)
        
    except Exception as e:
        return jsonify({'success': False, 'error': str(e)}), 500


@api_bp.route('/files/list/<case_uuid>')
@login_required
def get_file_list(case_uuid):
    """Get paginated file list for a case"""
    try:
        # Verify case exists
        case = Case.get_by_uuid(case_uuid)
        if not case:
            return jsonify({'success': False, 'error': 'Case not found'}), 404
        
        # Pagination parameters
        page = request.args.get('page', 1, type=int)
        per_page = request.args.get('per_page', 25, type=int)
        search = request.args.get('search', '', type=str).strip()
        
        # Limit per_page to reasonable values
        per_page = min(max(per_page, 10), 200)
        
        # Build query
        query = CaseFile.query.filter_by(case_uuid=case_uuid)
        
        # Apply search filter
        if search:
            search_filter = f'%{search}%'
            query = query.filter(
                db.or_(
                    CaseFile.filename.ilike(search_filter),
                    CaseFile.hostname.ilike(search_filter),
                    CaseFile.file_type.ilike(search_filter),
                    CaseFile.uploaded_by.ilike(search_filter),
                    CaseFile.parser_type.ilike(search_filter)
                )
            )
        
        # Order by uploaded_at desc
        query = query.order_by(CaseFile.uploaded_at.desc())
        
        # Get total count before pagination
        total = query.count()
        
        # Apply pagination
        files = query.offset((page - 1) * per_page).limit(per_page).all()
        
        # Build file list with parent filename lookup
        file_list = []
        parent_cache = {}
        
        for cf in files:
            # Get parent filename if exists
            parent_filename = None
            if cf.parent_id:
                if cf.parent_id not in parent_cache:
                    parent = CaseFile.query.get(cf.parent_id)
                    parent_cache[cf.parent_id] = parent.filename if parent else None
                parent_filename = parent_cache[cf.parent_id]
            
            file_list.append({
                'id': cf.id,
                'parent_filename': parent_filename,
                'filename': cf.filename,
                'file_size': cf.file_size,
                'hostname': cf.hostname or '-',
                'file_type': cf.file_type or '-',
                'upload_source': cf.upload_source,
                'uploaded_by': cf.uploaded_by,
                'uploaded_at': cf.uploaded_at.strftime('%Y-%m-%d %H:%M') if cf.uploaded_at else '-',
                'status': cf.status,
                'ingestion_status': cf.ingestion_status,
                'parser_type': cf.parser_type or '-',
                'events_indexed': cf.events_indexed,
                'error_message': cf.error_message
            })
        
        return jsonify({
            'success': True,
            'case_uuid': case_uuid,
            'files': file_list,
            'total': total,
            'page': page,
            'per_page': per_page,
            'total_pages': (total + per_page - 1) // per_page
        })
        
    except Exception as e:
        return jsonify({'success': False, 'error': str(e)}), 500


@api_bp.route('/files/progress/<case_uuid>')
@login_required
def get_processing_progress(case_uuid):
    """Get processing progress for a case"""
    try:
        from tasks.celery_tasks import celery_app
        from utils.progress import get_progress
        
        # Verify case exists
        case = Case.get_by_uuid(case_uuid)
        if not case:
            return jsonify({'success': False, 'error': 'Case not found'}), 404
        
        # Get progress from Redis (tracks current batch)
        progress = get_progress(case_uuid)
        
        if progress:
            # Active batch in progress
            total_files = progress.get('total', 0)
            processed_files = progress.get('completed', 0)
            is_processing = progress.get('status') == 'processing'
        else:
            # No active batch - idle state
            total_files = 0
            processed_files = 0
            is_processing = False
        
        # Get active workers processing this case
        workers = []
        try:
            # Get active tasks
            inspect = celery_app.control.inspect()
            active = inspect.active() or {}
            
            for worker_name, tasks in active.items():
                for task in tasks:
                    if task.get('name') == 'tasks.parse_file':
                        args = task.get('args', [])
                        kwargs = task.get('kwargs', {})
                        
                        # Check if this task is for our case
                        case_file_id = kwargs.get('case_file_id') or (args[3] if len(args) > 3 else None)
                        if case_file_id:
                            cf = CaseFile.query.get(case_file_id)
                            if cf and cf.case_uuid == case_uuid:
                                workers.append({
                                    'worker': worker_name.split('@')[-1],
                                    'file': cf.filename,
                                    'task_id': task.get('id')
                                })
        except Exception:
            # Celery inspect may fail if no workers
            pass
        
        return jsonify({
            'success': True,
            'case_uuid': case_uuid,
            'total_files': total_files,
            'processed_files': processed_files,
            'workers': workers,
            'is_processing': is_processing
        })
        
    except Exception as e:
        return jsonify({'success': False, 'error': str(e)}), 500


# ============================================
# Hunting API Endpoints
# ============================================

@api_bp.route('/hunting/events/<int:case_id>')
@login_required
def get_hunting_events(case_id):
    """Get paginated events for hunting page"""
    try:
        from utils.clickhouse import get_client
        
        # Verify case exists
        case = Case.query.get(case_id)
        if not case:
            return jsonify({'success': False, 'error': 'Case not found'}), 404
        
        # Pagination parameters
        page = request.args.get('page', 1, type=int)
        per_page = request.args.get('per_page', 50, type=int)
        search = request.args.get('search', '', type=str).strip()
        artifact_types = request.args.get('types', '', type=str).strip()
        alert_mode = request.args.get('alert_mode', 'all', type=str).strip()
        sigma_filter_param = request.args.get('sigma_filter', '', type=str).strip()
        ioc_filter_param = request.args.get('ioc_filter', '', type=str).strip()
        severity_levels_param = request.args.get('severity_levels', '', type=str).strip()
        
        # Limit per_page to reasonable values
        per_page = min(max(per_page, 10), 500)
        offset = (page - 1) * per_page
        
        client = get_client()
        
        # Build artifact type filter
        type_filter = ""
        if artifact_types:
            # Split comma-separated types and build IN clause
            types_list = [t.strip() for t in artifact_types.split(',') if t.strip()]
            if types_list:
                # Use tuple format for ClickHouse IN clause
                quoted_types = "', '".join(types_list)
                type_filter = f" AND artifact_type IN ('{quoted_types}')"
        
        # Build sigma/alert filter based on mode
        # 'all' mode: show all events, 'exclude' hides sigma hits
        # 'only' mode: 'only' shows only sigma hits, 'exclude_all' shows nothing with alerts
        sigma_filter = ""
        if sigma_filter_param == 'exclude':
            # Hide events with SIGMA hits (All Events mode, SIGMA unchecked)
            sigma_filter = " AND (rule_level IS NULL OR rule_level = '')"
        elif sigma_filter_param == 'only':
            # Show only events with SIGMA hits (Only These mode, SIGMA checked)
            sigma_filter = " AND (rule_level IS NOT NULL AND rule_level != '')"
        elif sigma_filter_param == 'exclude_all':
            # Only These mode with nothing checked - show no alert events
            # This effectively means show only non-alert events
            sigma_filter = " AND (rule_level IS NULL OR rule_level = '')"
        
        # Build IOC filter based on mode
        ioc_filter = ""
        if ioc_filter_param == 'exclude':
            # Hide events with IOC matches (All Events mode, IOC unchecked)
            ioc_filter = " AND length(ioc_types) = 0"
        elif ioc_filter_param == 'only':
            # Show only events with IOC matches (Only These mode, IOC checked)
            ioc_filter = " AND length(ioc_types) > 0"
        elif ioc_filter_param == 'exclude_all':
            # Only These mode with nothing checked - show no IOC events
            ioc_filter = " AND length(ioc_types) = 0"
        
        # Build severity level filter
        # This filters which SIGMA severity levels to show/hide
        severity_filter = ""
        if severity_levels_param:
            levels_list = [l.strip().lower() for l in severity_levels_param.split(',') if l.strip()]
            if levels_list:
                # Build filter: show events with no rule_level OR rule_level in the allowed list
                quoted_levels = "', '".join(levels_list)
                severity_filter = f" AND (rule_level IS NULL OR rule_level = '' OR lower(rule_level) IN ('{quoted_levels}'))"
        
        # Build query with optional search and type filter
        # All columns to fetch for event details modal
        event_columns = """
            timestamp, artifact_type, source_file, source_path, source_host,
            event_id, channel, provider, record_id, level,
            username, domain, sid, logon_type,
            process_name, process_path, process_id, parent_process, parent_pid, command_line,
            target_path, file_hash_md5, file_hash_sha1, file_hash_sha256, file_size,
            src_ip, dst_ip, src_port, dst_port,
            reg_key, reg_value, reg_data,
            rule_title, rule_level, rule_file, mitre_tactics, mitre_tags,
            search_blob, extra_fields, ioc_types
        """
        
        if search:
            # Search in search_blob field
            count_query = f"""
                SELECT count() FROM events 
                WHERE case_id = {{case_id:UInt32}} 
                  AND search_blob LIKE {{pattern:String}}{type_filter}{sigma_filter}{ioc_filter}{severity_filter}
            """
            data_query = f"""
                SELECT {event_columns}
                FROM events 
                WHERE case_id = {{case_id:UInt32}} 
                  AND search_blob LIKE {{pattern:String}}{type_filter}{sigma_filter}{ioc_filter}{severity_filter}
                ORDER BY timestamp DESC
                LIMIT {{limit:UInt32}} OFFSET {{offset:UInt32}}
            """
            params = {
                'case_id': case_id,
                'pattern': f'%{search}%',
                'limit': per_page,
                'offset': offset
            }
        else:
            count_query = f"SELECT count() FROM events WHERE case_id = {{case_id:UInt32}}{type_filter}{sigma_filter}{ioc_filter}{severity_filter}"
            data_query = f"""
                SELECT {event_columns}
                FROM events 
                WHERE case_id = {{case_id:UInt32}}{type_filter}{sigma_filter}{ioc_filter}{severity_filter}
                ORDER BY timestamp DESC
                LIMIT {{limit:UInt32}} OFFSET {{offset:UInt32}}
            """
            params = {
                'case_id': case_id,
                'limit': per_page,
                'offset': offset
            }
        
        # Get total count
        count_result = client.query(count_query, parameters=params)
        total = count_result.result_rows[0][0] if count_result.result_rows else 0
        
        # Get events
        data_result = client.query(data_query, parameters=params)
        
        events = []
        for row in data_result.result_rows:
            (timestamp, artifact_type, source_file, source_path, source_host,
             event_id, channel, provider, record_id, level,
             username, domain, sid, logon_type,
             process_name, process_path, process_id, parent_process, parent_pid, command_line,
             target_path, file_hash_md5, file_hash_sha1, file_hash_sha256, file_size,
             src_ip, dst_ip, src_port, dst_port,
             reg_key, reg_value, reg_data,
             rule_title, rule_level, rule_file, mitre_tactics, mitre_tags,
             search_blob, extra_fields, ioc_types) = row
            
            # Build description from available fields
            description = build_event_description(
                artifact_type, channel, provider, username, 
                process_name, command_line, target_path, search_blob
            )
            
            events.append({
                # Display fields (for table)
                'timestamp': timestamp.strftime('%Y-%m-%d %H:%M:%S') if timestamp else '-',
                'artifact_type': artifact_type or '-',
                'source_host': source_host or '-',
                'description': description,
                'rule_level': rule_level or '',
                
                # Full details (for modal)
                'source_file': source_file or '',
                'source_path': source_path or '',
                'event_id': event_id or '',
                'channel': channel or '',
                'provider': provider or '',
                'record_id': record_id,
                'level': level or '',
                'username': username or '',
                'domain': domain or '',
                'sid': sid or '',
                'logon_type': logon_type,
                'process_name': process_name or '',
                'process_path': process_path or '',
                'process_id': process_id,
                'parent_process': parent_process or '',
                'parent_pid': parent_pid,
                'command_line': command_line or '',
                'target_path': target_path or '',
                'file_hash_md5': file_hash_md5 or '',
                'file_hash_sha1': file_hash_sha1 or '',
                'file_hash_sha256': file_hash_sha256 or '',
                'file_size': file_size,
                'src_ip': str(src_ip) if src_ip else '',
                'dst_ip': str(dst_ip) if dst_ip else '',
                'src_port': src_port,
                'dst_port': dst_port,
                'reg_key': reg_key or '',
                'reg_value': reg_value or '',
                'reg_data': reg_data or '',
                'rule_title': rule_title or '',
                'rule_file': rule_file or '',
                'mitre_tactics': list(mitre_tactics) if mitre_tactics else [],
                'mitre_tags': list(mitre_tags) if mitre_tags else [],
                'search_blob': search_blob or '',
                'extra_fields': extra_fields or '{}',
                'ioc_types': list(ioc_types) if ioc_types else []
            })
        
        total_pages = (total + per_page - 1) // per_page if total > 0 else 1
        
        return jsonify({
            'success': True,
            'case_id': case_id,
            'events': events,
            'total': total,
            'page': page,
            'per_page': per_page,
            'total_pages': total_pages
        })
        
    except Exception as e:
        return jsonify({'success': False, 'error': str(e)}), 500


def build_event_description(artifact_type, channel, provider, username, process_name, command_line, target_path, search_blob):
    """Build a human-readable description for an event"""
    parts = []
    
    # Add channel/provider for EVTX
    if artifact_type == 'evtx':
        if channel:
            parts.append(f"[{channel}]")
        if provider:
            parts.append(provider)
    
    # Add username if present
    if username and username != '-':
        parts.append(f"User: {username}")
    
    # Add process info if present
    if process_name and process_name != '-':
        parts.append(f"Process: {process_name}")
    
    # Add command line (truncated) if present
    if command_line and command_line != '-':
        cmd = command_line[:100] + '...' if len(command_line) > 100 else command_line
        parts.append(cmd)
    
    # Add target path if present and no command line
    if target_path and target_path != '-' and not command_line:
        parts.append(target_path)
    
    # If still empty, use first part of search_blob
    if not parts and search_blob:
        blob_preview = search_blob[:150] + '...' if len(search_blob) > 150 else search_blob
        return blob_preview
    
    return ' | '.join(parts) if parts else '-'


# ============================================
# Known Systems API Endpoints
# ============================================

@api_bp.route('/known-systems/list/<case_uuid>')
@login_required
def get_known_systems(case_uuid):
    """Get known systems for a case"""
    try:
        from utils.known_systems_discovery import get_systems_for_case
        
        # Verify case exists
        case = Case.get_by_uuid(case_uuid)
        if not case:
            return jsonify({'success': False, 'error': 'Case not found'}), 404
        
        systems = get_systems_for_case(case.id)
        
        return jsonify({
            'success': True,
            'case_uuid': case_uuid,
            'systems': systems,
            'total': len(systems)
        })
        
    except Exception as e:
        return jsonify({'success': False, 'error': str(e)}), 500


@api_bp.route('/known-systems/discover/<case_uuid>', methods=['POST'])
@login_required
def discover_systems(case_uuid):
    """Start async discovery of known systems from artifacts"""
    try:
        from tasks.celery_tasks import discover_known_systems_task
        
        # Verify case exists
        case = Case.get_by_uuid(case_uuid)
        if not case:
            return jsonify({'success': False, 'error': 'Case not found'}), 404
        
        # Check if discovery is already running
        from utils.known_systems_discovery import get_discovery_progress
        progress = get_discovery_progress(case_uuid)
        if progress and progress.get('status') == 'running':
            return jsonify({
                'success': True,
                'status': 'already_running',
                'progress': progress
            })
        
        # Start async discovery task
        task = discover_known_systems_task.delay(
            case_id=case.id,
            case_uuid=case_uuid,
            username=current_user.username
        )
        
        return jsonify({
            'success': True,
            'status': 'started',
            'task_id': task.id
        })
        
    except Exception as e:
        return jsonify({'success': False, 'error': str(e)}), 500


@api_bp.route('/known-systems/discover-progress/<case_uuid>')
@login_required
def get_discovery_status(case_uuid):
    """Get discovery progress for a case"""
    try:
        from utils.known_systems_discovery import get_discovery_progress
        
        # Verify case exists
        case = Case.get_by_uuid(case_uuid)
        if not case:
            return jsonify({'success': False, 'error': 'Case not found'}), 404
        
        progress = get_discovery_progress(case_uuid)
        
        return jsonify({
            'success': True,
            'progress': progress
        })
        
    except Exception as e:
        return jsonify({'success': False, 'error': str(e)}), 500


@api_bp.route('/known-systems/<int:system_id>')
@login_required
def get_known_system(system_id):
    """Get details for a specific known system"""
    try:
        from models.known_system import KnownSystem
        
        system = KnownSystem.query.get(system_id)
        if not system:
            return jsonify({'success': False, 'error': 'System not found'}), 404
        
        return jsonify({
            'success': True,
            'system': system.to_dict()
        })
        
    except Exception as e:
        return jsonify({'success': False, 'error': str(e)}), 500


@api_bp.route('/known-systems/<int:system_id>/update', methods=['POST'])
@login_required
def update_known_system(system_id):
    """Update a known system field"""
    try:
        from utils.known_systems_discovery import update_system_field
        from models.known_system import KnownSystem, OSType, SystemType
        
        data = request.get_json()
        field_name = data.get('field')
        new_value = data.get('value')
        
        if not field_name:
            return jsonify({'success': False, 'error': 'Field name required'}), 400
        
        # Validate enum values
        if field_name == 'os_type' and new_value and new_value not in OSType.all():
            return jsonify({'success': False, 'error': f'Invalid os_type: {new_value}'}), 400
        
        if field_name == 'system_type' and new_value and new_value not in SystemType.all():
            return jsonify({'success': False, 'error': f'Invalid system_type: {new_value}'}), 400
        
        # Handle boolean for compromised
        if field_name == 'compromised':
            new_value = bool(new_value)
        
        success = update_system_field(
            system_id=system_id,
            field_name=field_name,
            new_value=new_value,
            username=current_user.username
        )
        
        if success:
            system = KnownSystem.query.get(system_id)
            return jsonify({
                'success': True,
                'system': system.to_dict()
            })
        else:
            return jsonify({'success': False, 'error': 'Update failed'}), 400
        
    except Exception as e:
        return jsonify({'success': False, 'error': str(e)}), 500


@api_bp.route('/known-systems/<int:system_id>/add-ip', methods=['POST'])
@login_required
def add_system_ip(system_id):
    """Add an IP address to a known system"""
    try:
        from utils.known_systems_discovery import add_ip_to_system
        from models.known_system import KnownSystem
        
        data = request.get_json()
        ip_address = data.get('ip_address', '').strip()
        
        if not ip_address:
            return jsonify({'success': False, 'error': 'IP address required'}), 400
        
        success = add_ip_to_system(
            system_id=system_id,
            ip_address=ip_address,
            username=current_user.username
        )
        
        system = KnownSystem.query.get(system_id)
        return jsonify({
            'success': success,
            'system': system.to_dict() if system else None
        })
        
    except Exception as e:
        return jsonify({'success': False, 'error': str(e)}), 500


@api_bp.route('/known-systems/<int:system_id>/add-share', methods=['POST'])
@login_required
def add_system_share(system_id):
    """Add a share to a known system"""
    try:
        from utils.known_systems_discovery import add_share_to_system
        from models.known_system import KnownSystem
        
        data = request.get_json()
        share_name = data.get('share_name', '').strip()
        share_path = data.get('share_path', '').strip()
        
        if not share_name:
            return jsonify({'success': False, 'error': 'Share name required'}), 400
        
        success = add_share_to_system(
            system_id=system_id,
            share_name=share_name,
            share_path=share_path if share_path else None,
            username=current_user.username
        )
        
        system = KnownSystem.query.get(system_id)
        return jsonify({
            'success': success,
            'system': system.to_dict() if system else None
        })
        
    except Exception as e:
        return jsonify({'success': False, 'error': str(e)}), 500


@api_bp.route('/known-systems/<int:system_id>/audit')
@login_required
def get_system_audit(system_id):
    """Get audit history for a known system"""
    try:
        from utils.known_systems_discovery import get_system_audit_history
        from models.known_system import KnownSystem
        
        system = KnownSystem.query.get(system_id)
        if not system:
            return jsonify({'success': False, 'error': 'System not found'}), 404
        
        history = get_system_audit_history(system_id)
        
        return jsonify({
            'success': True,
            'system_id': system_id,
            'hostname': system.hostname,
            'audit_history': history
        })
        
    except Exception as e:
        return jsonify({'success': False, 'error': str(e)}), 500


# ============================================
# Known Users API Endpoints
# ============================================

@api_bp.route('/known-users/list/<case_uuid>')
@login_required
def get_known_users(case_uuid):
    """Get known users for a case"""
    try:
        from utils.known_users_discovery import get_users_for_case
        
        # Verify case exists
        case = Case.get_by_uuid(case_uuid)
        if not case:
            return jsonify({'success': False, 'error': 'Case not found'}), 404
        
        users = get_users_for_case(case.id)
        
        return jsonify({
            'success': True,
            'case_uuid': case_uuid,
            'users': users,
            'total': len(users)
        })
        
    except Exception as e:
        return jsonify({'success': False, 'error': str(e)}), 500


@api_bp.route('/known-users/discover/<case_uuid>', methods=['POST'])
@login_required
def discover_users(case_uuid):
    """Start async discovery of known users from artifacts"""
    try:
        from tasks.celery_tasks import discover_known_users_task
        
        # Verify case exists
        case = Case.get_by_uuid(case_uuid)
        if not case:
            return jsonify({'success': False, 'error': 'Case not found'}), 404
        
        # Check if discovery is already running
        from utils.known_users_discovery import get_user_discovery_progress
        progress = get_user_discovery_progress(case_uuid)
        if progress and progress.get('status') == 'running':
            return jsonify({
                'success': True,
                'status': 'already_running',
                'progress': progress
            })
        
        # Start async discovery task
        task = discover_known_users_task.delay(
            case_id=case.id,
            case_uuid=case_uuid,
            username=current_user.username
        )
        
        return jsonify({
            'success': True,
            'status': 'started',
            'task_id': task.id
        })
        
    except Exception as e:
        return jsonify({'success': False, 'error': str(e)}), 500


@api_bp.route('/known-users/discover-progress/<case_uuid>')
@login_required
def get_user_discovery_status(case_uuid):
    """Get discovery progress for users in a case"""
    try:
        from utils.known_users_discovery import get_user_discovery_progress
        
        # Verify case exists
        case = Case.get_by_uuid(case_uuid)
        if not case:
            return jsonify({'success': False, 'error': 'Case not found'}), 404
        
        progress = get_user_discovery_progress(case_uuid)
        
        return jsonify({
            'success': True,
            'progress': progress
        })
        
    except Exception as e:
        return jsonify({'success': False, 'error': str(e)}), 500


@api_bp.route('/known-users/<int:user_id>')
@login_required
def get_known_user(user_id):
    """Get details for a specific known user"""
    try:
        from models.known_user import KnownUser
        
        user = KnownUser.query.get(user_id)
        if not user:
            return jsonify({'success': False, 'error': 'User not found'}), 404
        
        return jsonify({
            'success': True,
            'user': user.to_dict()
        })
        
    except Exception as e:
        return jsonify({'success': False, 'error': str(e)}), 500


@api_bp.route('/known-users/<int:user_id>/update', methods=['POST'])
@login_required
def update_known_user(user_id):
    """Update a known user field"""
    try:
        from utils.known_users_discovery import update_user_field
        from models.known_user import KnownUser
        
        data = request.get_json()
        field_name = data.get('field')
        new_value = data.get('value')
        
        if not field_name:
            return jsonify({'success': False, 'error': 'Field name required'}), 400
        
        # Handle boolean for compromised
        if field_name == 'compromised':
            new_value = bool(new_value)
        
        success = update_user_field(
            user_id=user_id,
            field_name=field_name,
            new_value=new_value,
            changed_by=current_user.username
        )
        
        if success:
            user = KnownUser.query.get(user_id)
            return jsonify({
                'success': True,
                'user': user.to_dict()
            })
        else:
            return jsonify({'success': False, 'error': 'Update failed'}), 400
        
    except Exception as e:
        return jsonify({'success': False, 'error': str(e)}), 500


@api_bp.route('/known-users/<int:user_id>/add-alias', methods=['POST'])
@login_required
def add_user_alias(user_id):
    """Add an alias to a known user"""
    try:
        from utils.known_users_discovery import add_alias_to_user
        from models.known_user import KnownUser
        
        data = request.get_json()
        alias = data.get('alias', '').strip()
        
        if not alias:
            return jsonify({'success': False, 'error': 'Alias required'}), 400
        
        success = add_alias_to_user(
            user_id=user_id,
            alias=alias,
            changed_by=current_user.username
        )
        
        user = KnownUser.query.get(user_id)
        return jsonify({
            'success': success,
            'user': user.to_dict() if user else None
        })
        
    except Exception as e:
        return jsonify({'success': False, 'error': str(e)}), 500


@api_bp.route('/known-users/<int:user_id>/add-email', methods=['POST'])
@login_required
def add_user_email(user_id):
    """Add an email to a known user"""
    try:
        from utils.known_users_discovery import add_email_to_user
        from models.known_user import KnownUser
        
        data = request.get_json()
        email = data.get('email', '').strip()
        
        if not email:
            return jsonify({'success': False, 'error': 'Email required'}), 400
        
        success = add_email_to_user(
            user_id=user_id,
            email=email,
            changed_by=current_user.username
        )
        
        user = KnownUser.query.get(user_id)
        return jsonify({
            'success': success,
            'user': user.to_dict() if user else None
        })
        
    except Exception as e:
        return jsonify({'success': False, 'error': str(e)}), 500


@api_bp.route('/known-users/<int:user_id>/audit')
@login_required
def get_user_audit(user_id):
    """Get audit history for a known user"""
    try:
        from utils.known_users_discovery import get_user_audit_history
        from models.known_user import KnownUser
        
        user = KnownUser.query.get(user_id)
        if not user:
            return jsonify({'success': False, 'error': 'User not found'}), 404
        
        history = get_user_audit_history(user_id)
        
        return jsonify({
            'success': True,
            'user_id': user_id,
            'username': user.username,
            'audit_history': history
        })
        
    except Exception as e:
        return jsonify({'success': False, 'error': str(e)}), 500


# ============================================
# IOC Management API Endpoints
# ============================================

@api_bp.route('/iocs/types')
@login_required
def get_ioc_types():
    """Get all IOC types organized by category"""
    try:
        from models.ioc import get_ioc_types_by_category, IOCCategory
        
        types_by_category = get_ioc_types_by_category()
        icons = IOCCategory.icons()
        
        return jsonify({
            'success': True,
            'types_by_category': types_by_category,
            'category_icons': icons,
            'categories': IOCCategory.all()
        })
        
    except Exception as e:
        return jsonify({'success': False, 'error': str(e)}), 500


@api_bp.route('/iocs/values/<int:case_id>')
@login_required
def get_ioc_values_for_case(case_id):
    """Get just IOC values for a case (for highlighting in event modal)"""
    try:
        from models.ioc import IOC, IOCCase
        
        # Verify case exists
        case = Case.query.get(case_id)
        if not case:
            return jsonify({'success': False, 'error': 'Case not found'}), 404
        
        # Get all IOC values linked to this case (excluding false positives)
        ioc_links = IOCCase.query.filter_by(case_id=case_id).all()
        ioc_ids = [link.ioc_id for link in ioc_links]
        
        if not ioc_ids:
            return jsonify({'success': True, 'values': []})
        
        iocs = IOC.query.filter(
            IOC.id.in_(ioc_ids),
            IOC.false_positive == False,
            IOC.active == True
        ).all()
        
        # Extract searchable values (filenames from paths, etc.)
        from utils.ioc_artifact_tagger import extract_searchable_terms
        
        values = set()
        for ioc in iocs:
            terms = extract_searchable_terms(ioc.value, ioc.ioc_type)
            # terms is a list of (term, is_filename) tuples - extract just the term strings
            for term, _ in terms:
                if term:
                    values.add(term)
        
        return jsonify({
            'success': True,
            'values': list(values)
        })
        
    except Exception as e:
        return jsonify({'success': False, 'error': str(e)}), 500


@api_bp.route('/iocs/list/<case_uuid>')
@login_required
def get_iocs_for_case(case_uuid):
    """Get IOCs for a case with pagination and filtering"""
    try:
        from models.ioc import IOC, IOCCase, IOCCategory
        
        # Verify case exists
        case = Case.get_by_uuid(case_uuid)
        if not case:
            return jsonify({'success': False, 'error': 'Case not found'}), 404
        
        # Pagination and filter parameters
        page = request.args.get('page', 1, type=int)
        per_page = request.args.get('per_page', 50, type=int)
        search = request.args.get('search', '', type=str).strip()
        category = request.args.get('category', '', type=str).strip()
        ioc_type = request.args.get('type', '', type=str).strip()
        malicious_only = request.args.get('malicious', 'false', type=str).lower() == 'true'
        
        per_page = min(max(per_page, 10), 200)
        
        # Build query - IOCs linked to this case
        query = db.session.query(IOC).join(IOCCase).filter(IOCCase.case_id == case.id)
        
        # Apply filters
        if search:
            search_filter = f'%{search}%'
            query = query.filter(IOC.value.ilike(search_filter))
        
        if category:
            query = query.filter(IOC.category == category)
        
        if ioc_type:
            query = query.filter(IOC.ioc_type == ioc_type)
        
        if malicious_only:
            query = query.filter(IOC.malicious == True)
        
        # Exclude false positives by default
        query = query.filter(IOC.false_positive == False)
        
        # Order by last seen (most recent first)
        query = query.order_by(IOC.last_seen_in_artifacts.desc().nullslast(), IOC.created_at.desc())
        
        # Get total count before pagination
        total = query.count()
        
        # Apply pagination
        iocs = query.offset((page - 1) * per_page).limit(per_page).all()
        
        # Get stats
        stats = {
            'total': total,
            'by_category': {}
        }
        
        for cat in IOCCategory.all():
            cat_count = db.session.query(IOC).join(IOCCase).filter(
                IOCCase.case_id == case.id,
                IOC.category == cat,
                IOC.false_positive == False
            ).count()
            stats['by_category'][cat] = cat_count
        
        return jsonify({
            'success': True,
            'case_uuid': case_uuid,
            'iocs': [ioc.to_dict() for ioc in iocs],
            'total': total,
            'page': page,
            'per_page': per_page,
            'total_pages': (total + per_page - 1) // per_page if total > 0 else 1,
            'stats': stats
        })
        
    except Exception as e:
        return jsonify({'success': False, 'error': str(e)}), 500


@api_bp.route('/iocs/create/<case_uuid>', methods=['POST'])
@login_required
def create_ioc(case_uuid):
    """Create a new IOC and link to case"""
    try:
        from models.ioc import IOC, IOCAudit, get_category_for_type
        
        # Verify case exists
        case = Case.get_by_uuid(case_uuid)
        if not case:
            return jsonify({'success': False, 'error': 'Case not found'}), 404
        
        data = request.get_json()
        ioc_type = data.get('ioc_type', '').strip()
        value = data.get('value', '').strip()
        notes = data.get('notes', '').strip()
        malicious = data.get('malicious', False)
        
        if not ioc_type:
            return jsonify({'success': False, 'error': 'IOC type required'}), 400
        
        if not value:
            return jsonify({'success': False, 'error': 'IOC value required'}), 400
        
        # Get category for this type
        category = get_category_for_type(ioc_type)
        if not category:
            return jsonify({'success': False, 'error': f'Unknown IOC type: {ioc_type}'}), 400
        
        # Validate the value
        is_valid, error = IOC.validate_value(value, ioc_type)
        if not is_valid:
            return jsonify({'success': False, 'error': error}), 400
        
        # Get or create IOC
        ioc, created = IOC.get_or_create(
            value=value,
            ioc_type=ioc_type,
            category=category,
            created_by=current_user.username
        )
        
        # Update fields if provided
        if notes:
            ioc.notes = notes
        if malicious:
            ioc.malicious = malicious
        
        # Link to case
        ioc.link_to_case(case.id)
        
        # Log creation
        if created:
            IOCAudit.log_change(
                ioc_id=ioc.id,
                changed_by=current_user.username,
                field_name='ioc',
                action='create',
                new_value=f'{ioc_type}: {value}'
            )
        
        db.session.commit()
        
        return jsonify({
            'success': True,
            'created': created,
            'ioc': ioc.to_dict()
        })
        
    except ValueError as e:
        return jsonify({'success': False, 'error': str(e)}), 400
    except Exception as e:
        db.session.rollback()
        return jsonify({'success': False, 'error': str(e)}), 500


@api_bp.route('/iocs/<int:ioc_id>')
@login_required
def get_ioc(ioc_id):
    """Get details for a specific IOC"""
    try:
        from models.ioc import IOC
        
        ioc = IOC.query.get(ioc_id)
        if not ioc:
            return jsonify({'success': False, 'error': 'IOC not found'}), 404
        
        return jsonify({
            'success': True,
            'ioc': ioc.to_dict()
        })
        
    except Exception as e:
        return jsonify({'success': False, 'error': str(e)}), 500


@api_bp.route('/iocs/<int:ioc_id>/update', methods=['POST'])
@login_required
def update_ioc(ioc_id):
    """Update an IOC field"""
    try:
        from models.ioc import IOC, IOCAudit
        
        ioc = IOC.query.get(ioc_id)
        if not ioc:
            return jsonify({'success': False, 'error': 'IOC not found'}), 404
        
        data = request.get_json()
        field_name = data.get('field')
        new_value = data.get('value')
        
        if not field_name:
            return jsonify({'success': False, 'error': 'Field name required'}), 400
        
        # Allowed fields to update
        allowed_fields = ['notes', 'malicious', 'false_positive', 'active', 'aliases']
        if field_name not in allowed_fields:
            return jsonify({'success': False, 'error': f'Cannot update field: {field_name}'}), 400
        
        old_value = getattr(ioc, field_name)
        
        # Handle boolean fields
        if field_name in ['malicious', 'false_positive', 'active']:
            new_value = bool(new_value)
        
        # Handle aliases field (list of strings)
        if field_name == 'aliases':
            if not isinstance(new_value, list):
                return jsonify({'success': False, 'error': 'Aliases must be a list'}), 400
            # Normalize aliases (lowercase, deduplicate)
            new_value = list(set([str(a).lower().strip() for a in new_value if a]))
        
        setattr(ioc, field_name, new_value)
        
        # Log change
        IOCAudit.log_change(
            ioc_id=ioc.id,
            changed_by=current_user.username,
            field_name=field_name,
            action='update',
            old_value=old_value,
            new_value=new_value
        )
        
        db.session.commit()
        
        return jsonify({
            'success': True,
            'ioc': ioc.to_dict()
        })
        
    except Exception as e:
        db.session.rollback()
        return jsonify({'success': False, 'error': str(e)}), 500


@api_bp.route('/iocs/<int:ioc_id>/systems')
@login_required
def get_ioc_systems(ioc_id):
    """Get all systems where this IOC was found"""
    try:
        from models.ioc import IOC, IOCSystemSighting
        
        ioc = IOC.query.get(ioc_id)
        if not ioc:
            return jsonify({'success': False, 'error': 'IOC not found'}), 404
        
        sightings = ioc.system_sightings.all()
        
        return jsonify({
            'success': True,
            'ioc_id': ioc_id,
            'systems': [s.to_dict() for s in sightings]
        })
        
    except Exception as e:
        return jsonify({'success': False, 'error': str(e)}), 500


@api_bp.route('/iocs/<int:ioc_id>/audit')
@login_required
def get_ioc_audit(ioc_id):
    """Get audit history for an IOC"""
    try:
        from models.ioc import IOC, IOCAudit
        
        ioc = IOC.query.get(ioc_id)
        if not ioc:
            return jsonify({'success': False, 'error': 'IOC not found'}), 404
        
        audits = IOCAudit.query.filter_by(ioc_id=ioc_id).order_by(
            IOCAudit.changed_on.desc()
        ).all()
        
        return jsonify({
            'success': True,
            'ioc_id': ioc_id,
            'ioc_value': ioc.value,
            'audit_history': [a.to_dict() for a in audits]
        })
        
    except Exception as e:
        return jsonify({'success': False, 'error': str(e)}), 500


@api_bp.route('/iocs/<int:ioc_id>/delete', methods=['POST'])
@login_required
def delete_ioc_from_case(ioc_id):
    """Remove an IOC from a case (does not delete the IOC itself)"""
    try:
        from models.ioc import IOC, IOCCase, IOCAudit
        
        data = request.get_json()
        case_uuid = data.get('case_uuid')
        
        if not case_uuid:
            return jsonify({'success': False, 'error': 'Case UUID required'}), 400
        
        case = Case.get_by_uuid(case_uuid)
        if not case:
            return jsonify({'success': False, 'error': 'Case not found'}), 404
        
        ioc = IOC.query.get(ioc_id)
        if not ioc:
            return jsonify({'success': False, 'error': 'IOC not found'}), 404
        
        # Remove from case
        link = IOCCase.query.filter_by(ioc_id=ioc_id, case_id=case.id).first()
        if link:
            db.session.delete(link)
            
            IOCAudit.log_change(
                ioc_id=ioc_id,
                changed_by=current_user.username,
                field_name='case',
                action='delete',
                old_value=case.name
            )
            
            db.session.commit()
        
        return jsonify({'success': True})
        
    except Exception as e:
        db.session.rollback()
        return jsonify({'success': False, 'error': str(e)}), 500


@api_bp.route('/iocs/bulk-create/<case_uuid>', methods=['POST'])
@login_required
def bulk_create_iocs(case_uuid):
    """Bulk create IOCs from a list"""
    try:
        from models.ioc import IOC, IOCAudit, get_category_for_type
        
        # Verify case exists
        case = Case.get_by_uuid(case_uuid)
        if not case:
            return jsonify({'success': False, 'error': 'Case not found'}), 404
        
        data = request.get_json()
        iocs_data = data.get('iocs', [])
        
        if not iocs_data:
            return jsonify({'success': False, 'error': 'No IOCs provided'}), 400
        
        created_count = 0
        linked_count = 0
        errors = []
        
        for item in iocs_data:
            ioc_type = item.get('ioc_type', '').strip()
            value = item.get('value', '').strip()
            
            if not ioc_type or not value:
                errors.append(f'Missing type or value: {item}')
                continue
            
            category = get_category_for_type(ioc_type)
            if not category:
                errors.append(f'Unknown type: {ioc_type}')
                continue
            
            try:
                ioc, created = IOC.get_or_create(
                    value=value,
                    ioc_type=ioc_type,
                    category=category,
                    created_by=current_user.username
                )
                
                if created:
                    created_count += 1
                    IOCAudit.log_change(
                        ioc_id=ioc.id,
                        changed_by=current_user.username,
                        field_name='ioc',
                        action='create',
                        new_value=f'{ioc_type}: {value}'
                    )
                
                if ioc.link_to_case(case.id):
                    linked_count += 1
                    
            except ValueError as e:
                errors.append(f'{ioc_type}: {value} - {str(e)}')
        
        db.session.commit()
        
        return jsonify({
            'success': True,
            'created': created_count,
            'linked': linked_count,
            'errors': errors
        })
        
    except Exception as e:
        db.session.rollback()
        return jsonify({'success': False, 'error': str(e)}), 500


# ============================================
# AI Settings API
# ============================================

@api_bp.route('/settings/detect-gpu', methods=['GET'])
@login_required
def detect_gpu():
    """Detect GPU(s), drivers, and Ollama installation"""
    try:
        result = {
            'success': True,
            'gpus': [],
            'recommended_gpu': None,
            'drivers': [],
            'ollama': {
                'installed': False,
                'version': None,
                'models': []
            }
        }
        
        # Detect NVIDIA GPUs using nvidia-smi
        cuda_version = None
        try:
            # First get CUDA version from nvidia-smi main output
            cuda_check = subprocess.run(['nvidia-smi'], capture_output=True, text=True, timeout=10)
            if cuda_check.returncode == 0:
                import re
                cuda_match = re.search(r'CUDA Version:\s*(\d+\.\d+)', cuda_check.stdout)
                if cuda_match:
                    cuda_version = cuda_match.group(1)
            
            # Query GPU details
            nvidia_output = subprocess.run(
                ['nvidia-smi', '--query-gpu=index,name,memory.total,memory.free,driver_version', 
                 '--format=csv,noheader,nounits'],
                capture_output=True, text=True, timeout=10
            )
            
            if nvidia_output.returncode == 0 and nvidia_output.stdout.strip():
                for line in nvidia_output.stdout.strip().split('\n'):
                    parts = [p.strip() for p in line.split(',')]
                    if len(parts) >= 5:
                        gpu = {
                            'index': int(parts[0]),
                            'name': parts[1],
                            'vram_total_mb': int(float(parts[2])),
                            'vram_free_mb': int(float(parts[3])),
                            'driver_version': parts[4],
                            'cuda_version': cuda_version,
                            'type': 'NVIDIA'
                        }
                        result['gpus'].append(gpu)
                        
                        # Add driver info
                        driver_info = f"NVIDIA Driver {parts[4]}"
                        if driver_info not in [d['name'] for d in result['drivers']]:
                            result['drivers'].append({
                                'name': driver_info,
                                'cuda': f"CUDA {cuda_version}" if cuda_version else None
                            })
        except FileNotFoundError:
            pass  # nvidia-smi not available
        except Exception as e:
            pass
        
        # Try lspci for additional GPU detection (AMD, Intel, or NVIDIA not found by nvidia-smi)
        # Skip if we already have NVIDIA GPUs from nvidia-smi (more accurate data)
        has_nvidia_from_smi = any(g['type'] == 'NVIDIA' and g['vram_total_mb'] for g in result['gpus'])
        
        try:
            lspci_output = subprocess.run(
                ['lspci', '-v'],
                capture_output=True, text=True, timeout=10
            )
            if lspci_output.returncode == 0:
                import re
                # Look for VGA/3D controllers
                vga_pattern = re.compile(r'(VGA compatible controller|3D controller):\s*(.+)', re.IGNORECASE)
                for match in vga_pattern.finditer(lspci_output.stdout):
                    gpu_name = match.group(2).strip()
                    
                    # Determine GPU type
                    if 'NVIDIA' in gpu_name.upper():
                        gpu_type = 'NVIDIA'
                        # Skip NVIDIA from lspci if we already have it from nvidia-smi
                        if has_nvidia_from_smi:
                            continue
                    elif 'AMD' in gpu_name.upper() or 'RADEON' in gpu_name.upper():
                        gpu_type = 'AMD'
                    elif 'INTEL' in gpu_name.upper():
                        gpu_type = 'Intel'
                    else:
                        gpu_type = 'Other'
                    
                    # Check if this GPU type is already in our list
                    already_found = any(g['type'] == gpu_type for g in result['gpus'])
                    
                    if not already_found:
                        result['gpus'].append({
                            'index': len(result['gpus']),
                            'name': gpu_name,
                            'vram_total_mb': None,
                            'vram_free_mb': None,
                            'driver_version': None,
                            'cuda_version': None,
                            'type': gpu_type
                        })
        except Exception:
            pass
        
        # If we have NVIDIA GPU but no driver info, try to get it separately
        has_nvidia = any(g['type'] == 'NVIDIA' for g in result['gpus'])
        if has_nvidia and not result['drivers']:
            try:
                # Get CUDA version from nvidia-smi main output
                fallback_cuda = None
                cuda_check = subprocess.run(['nvidia-smi'], capture_output=True, text=True, timeout=10)
                if cuda_check.returncode == 0:
                    import re
                    cuda_match = re.search(r'CUDA Version:\s*(\d+\.\d+)', cuda_check.stdout)
                    if cuda_match:
                        fallback_cuda = cuda_match.group(1)
                
                # Try nvidia-smi just for driver version
                driver_check = subprocess.run(
                    ['nvidia-smi', '--query-gpu=driver_version', '--format=csv,noheader,nounits'],
                    capture_output=True, text=True, timeout=10
                )
                if driver_check.returncode == 0 and driver_check.stdout.strip():
                    driver_ver = driver_check.stdout.strip().split('\n')[0].strip()
                    result['drivers'].append({
                        'name': f"NVIDIA Driver {driver_ver}",
                        'cuda': f"CUDA {fallback_cuda}" if fallback_cuda else None
                    })
                    # Update GPU records with driver info
                    for gpu in result['gpus']:
                        if gpu['type'] == 'NVIDIA':
                            gpu['driver_version'] = driver_ver
                            gpu['cuda_version'] = fallback_cuda
            except Exception:
                pass
        
        # Try to get NVIDIA VRAM info if missing
        for gpu in result['gpus']:
            if gpu['type'] == 'NVIDIA' and gpu['vram_total_mb'] is None:
                try:
                    vram_check = subprocess.run(
                        ['nvidia-smi', '--query-gpu=memory.total,memory.free', '--format=csv,noheader,nounits'],
                        capture_output=True, text=True, timeout=10
                    )
                    if vram_check.returncode == 0 and vram_check.stdout.strip():
                        parts = [p.strip() for p in vram_check.stdout.strip().split('\n')[0].split(',')]
                        if len(parts) >= 2:
                            try:
                                gpu['vram_total_mb'] = int(float(parts[0]))
                                gpu['vram_free_mb'] = int(float(parts[1]))
                            except ValueError:
                                pass
                except Exception:
                    pass
        
        # Select recommended GPU (prefer NVIDIA with most VRAM)
        if result['gpus']:
            nvidia_gpus = [g for g in result['gpus'] if g['type'] == 'NVIDIA']
            if nvidia_gpus:
                # Sort by VRAM (descending)
                nvidia_gpus.sort(key=lambda x: x['vram_total_mb'] or 0, reverse=True)
                result['recommended_gpu'] = nvidia_gpus[0]
            else:
                result['recommended_gpu'] = result['gpus'][0]
        
        # Detect Ollama
        try:
            ollama_version = subprocess.run(
                ['ollama', '--version'],
                capture_output=True, text=True, timeout=5
            )
            if ollama_version.returncode == 0:
                result['ollama']['installed'] = True
                version_text = ollama_version.stdout.strip() or ollama_version.stderr.strip()
                # Extract version number (format: "ollama version is X.X.X")
                if 'version' in version_text.lower():
                    import re
                    version_match = re.search(r'(\d+\.\d+\.\d+)', version_text)
                    if version_match:
                        result['ollama']['version'] = version_match.group(1)
                    else:
                        result['ollama']['version'] = version_text
                else:
                    result['ollama']['version'] = version_text
                
                # Get installed models
                try:
                    ollama_list = subprocess.run(
                        ['ollama', 'list'],
                        capture_output=True, text=True, timeout=10
                    )
                    if ollama_list.returncode == 0 and ollama_list.stdout.strip():
                        lines = ollama_list.stdout.strip().split('\n')
                        for line in lines[1:]:  # Skip header
                            parts = line.split()
                            if len(parts) >= 2:
                                model_name = parts[0]
                                model_size = parts[2] if len(parts) >= 3 else 'Unknown'
                                result['ollama']['models'].append({
                                    'name': model_name,
                                    'size': model_size
                                })
                except Exception:
                    pass
        except FileNotFoundError:
            result['ollama']['installed'] = False
        except Exception:
            pass
        
        # Add AI model configuration based on detected GPU
        from models.system_settings import get_ai_model_config, AI_FUNCTION_DESCRIPTIONS, SystemSettings, SettingKeys
        
        recommended_vram = None
        if result['recommended_gpu'] and result['recommended_gpu'].get('vram_total_mb'):
            recommended_vram = result['recommended_gpu']['vram_total_mb']
        
        model_config = get_ai_model_config(recommended_vram)
        if model_config:
            tier = '16gb' if recommended_vram and recommended_vram >= 14000 else '8gb'
            result['model_config'] = {
                'tier': tier,
                'functions': {}
            }
            for func_key, model_name in model_config.items():
                result['model_config']['functions'][func_key] = {
                    'model': model_name,
                    'description': AI_FUNCTION_DESCRIPTIONS.get(func_key, func_key)
                }
            
            # Store the GPU tier for use by AI functions
            SystemSettings.set(
                SettingKeys.AI_GPU_TIER,
                tier,
                value_type='string',
                updated_by='system'
            )
        else:
            result['model_config'] = None
        
        return jsonify(result)
        
    except Exception as e:
        return jsonify({'success': False, 'error': str(e)}), 500


@api_bp.route('/settings/ai', methods=['GET'])
@login_required
def get_ai_settings():
    """Get AI settings including enabled state"""
    try:
        from models.system_settings import SystemSettings, SettingKeys
        
        ai_enabled = SystemSettings.get(SettingKeys.AI_ENABLED, False)
        ai_model = SystemSettings.get(SettingKeys.AI_DEFAULT_MODEL, None)
        
        return jsonify({
            'success': True,
            'ai_enabled': ai_enabled,
            'ai_default_model': ai_model
        })
        
    except Exception as e:
        return jsonify({'success': False, 'error': str(e)}), 500


@api_bp.route('/settings/ai', methods=['POST'])
@login_required
def set_ai_settings():
    """Set AI settings"""
    try:
        # Check admin permission
        if not current_user.is_administrator:
            return jsonify({'success': False, 'error': 'Administrator access required'}), 403
        
        from models.system_settings import SystemSettings, SettingKeys
        
        data = request.get_json()
        
        if 'ai_enabled' in data:
            SystemSettings.set(
                SettingKeys.AI_ENABLED, 
                data['ai_enabled'], 
                value_type='bool',
                updated_by=current_user.username
            )
        
        if 'ai_default_model' in data:
            SystemSettings.set(
                SettingKeys.AI_DEFAULT_MODEL,
                data['ai_default_model'],
                value_type='string',
                updated_by=current_user.username
            )
        
        return jsonify({'success': True})
        
    except Exception as e:
        return jsonify({'success': False, 'error': str(e)}), 500


# ============================================
# IOC Extraction from EDR Reports API
# ============================================

@api_bp.route('/iocs/extraction/check/<case_uuid>')
@login_required
def check_edr_reports(case_uuid):
    """Check if case has EDR reports available for extraction"""
    try:
        case = Case.get_by_uuid(case_uuid)
        if not case:
            return jsonify({'success': False, 'error': 'Case not found'}), 404
        
        from utils.ioc_extractor import split_edr_reports, get_report_preview
        
        has_reports = bool(case.edr_report and case.edr_report.strip())
        report_count = 0
        report_previews = []
        
        if has_reports:
            reports = split_edr_reports(case.edr_report)
            report_count = len(reports)
            report_previews = [
                {'index': i, 'preview': get_report_preview(r, 150), 'length': len(r)}
                for i, r in enumerate(reports)
            ]
        
        return jsonify({
            'success': True,
            'has_reports': has_reports,
            'report_count': report_count,
            'report_previews': report_previews
        })
        
    except Exception as e:
        return jsonify({'success': False, 'error': str(e)}), 500


@api_bp.route('/iocs/extraction/extract/<case_uuid>', methods=['POST'])
@login_required
def extract_iocs_from_report(case_uuid):
    """Extract IOCs from a specific EDR report"""
    try:
        case = Case.get_by_uuid(case_uuid)
        if not case:
            return jsonify({'success': False, 'error': 'Case not found'}), 404
        
        if not case.edr_report or not case.edr_report.strip():
            return jsonify({'success': False, 'error': 'No EDR reports available'}), 400
        
        data = request.get_json()
        report_index = data.get('report_index', 0)
        
        from utils.ioc_extractor import (
            split_edr_reports, extract_iocs_with_ai, 
            process_extraction_for_import, get_report_preview
        )
        
        reports = split_edr_reports(case.edr_report)
        
        if report_index < 0 or report_index >= len(reports):
            return jsonify({'success': False, 'error': 'Invalid report index'}), 400
        
        report_text = reports[report_index]
        
        # Extract IOCs
        extraction, used_ai = extract_iocs_with_ai(report_text)
        
        # Process for import (deduplication, known systems/users matching)
        processed = process_extraction_for_import(
            extraction=extraction,
            case_id=case.id,
            username=current_user.username
        )
        
        return jsonify({
            'success': True,
            'report_index': report_index,
            'total_reports': len(reports),
            'report_preview': get_report_preview(report_text, 200),
            'used_ai': used_ai,
            'extraction_summary': processed.get('extraction_summary', {}),
            'iocs_to_import': processed.get('iocs_to_import', []),
            'known_systems': processed.get('known_systems_results', []),
            'known_users': processed.get('known_users_results', []),
            'mitre_indicators': processed.get('mitre_indicators', [])
        })
        
    except Exception as e:
        import traceback
        traceback.print_exc()
        return jsonify({'success': False, 'error': str(e)}), 500


@api_bp.route('/iocs/extraction/save/<case_uuid>', methods=['POST'])
@login_required
def save_extracted_iocs_api(case_uuid):
    """Save selected extracted IOCs to the database"""
    try:
        case = Case.get_by_uuid(case_uuid)
        if not case:
            return jsonify({'success': False, 'error': 'Case not found'}), 404
        
        data = request.get_json()
        iocs_data = data.get('iocs', [])
        known_systems = data.get('known_systems', [])
        known_users = data.get('known_users', [])
        
        from utils.ioc_extractor import save_extracted_iocs
        
        results = save_extracted_iocs(
            iocs_data=iocs_data,
            case_id=case.id,
            username=current_user.username,
            known_systems=known_systems,
            known_users=known_users
        )
        
        return jsonify({
            'success': True,
            'results': results
        })
        
    except Exception as e:
        import traceback
        traceback.print_exc()
        return jsonify({'success': False, 'error': str(e)}), 500


@api_bp.route('/iocs/tag-artifacts/<case_uuid>', methods=['POST'])
@login_required
def tag_artifacts_for_case(case_uuid):
    """Search all artifacts in case for IOC matches and update artifact counts.
    
    This performs case-insensitive partial matching for:
    - File paths: matches filename (e.g., "winscp.exe" matches "c:\\windows\\winscp.exe")
    - Hashes: exact match
    - IPs: exact match
    - Commands: extracts executables and matches those
    - Registry: partial match
    """
    try:
        case = Case.get_by_uuid(case_uuid)
        if not case:
            return jsonify({'success': False, 'error': 'Case not found'}), 404
        
        from utils.ioc_artifact_tagger import tag_all_iocs_globally
        
        # Search all IOCs against this case's artifacts
        results = tag_all_iocs_globally(case.id)
        
        return jsonify({
            'success': results.get('success', False),
            'total_iocs_searched': results.get('total_iocs', 0),
            'iocs_with_matches': results.get('iocs_with_matches', 0),
            'new_links_created': results.get('new_links_created', 0),
            'total_artifact_matches': results.get('total_artifact_matches', 0),
            'details': results.get('details', []),
            'error': results.get('error')
        })
        
    except Exception as e:
        import traceback
        traceback.print_exc()
        return jsonify({'success': False, 'error': str(e)}), 500
