"""
ZIP-Centric File Upload Processing
==================================
New architecture (Phase 1-3):
- ZIP files: Extract → Parse → Index → Compress → Delete extracted (keep ZIP)
- Standalone files: Parse → Index → Compress
- Virtual file tracking for ZIP contents
- Multi-index routing (case_X, case_X_browser, case_X_devices, etc.)
- Intelligent GZIP compression (keep everything, zero deletion)
"""

import os
import shutil
import zipfile
import gzip
import hashlib
import logging
import sys
from datetime import datetime
from celery import Task
from pathlib import Path

# Add app directory to Python path
app_dir = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
if app_dir not in sys.path:
    sys.path.insert(0, app_dir)

logger = logging.getLogger(__name__)

# Import celery instance
from celery_app import celery

# Valid file extensions (case-insensitive)
VALID_EXTENSIONS = [
    '.zip', '.evtx', '.ndjson', '.json', '.jsonl', '.log', '.csv',
    '.edb', '.sdb', '.db', '.sqlite', '.pf'  # Phase 2/3: ESE, SQLite, Prefetch
]

# Base paths
BASE_UPLOAD_PATH = '/opt/casescope/bulk_upload'
BASE_STAGING_PATH = '/opt/casescope/staging'
BASE_STORAGE_PATH = '/opt/casescope/storage'

# Artifact type detection patterns (for multi-index routing)
ARTIFACT_PATTERNS = {
    'browser': ['history', 'webcachev01.dat', 'webcachev24.dat', 'places.sqlite', 'cookies', 'downloads', 'formhistory'],
    'devices': ['setupapi.dev.log', 'setupapi'],
    'execution': ['.pf', 'prefetch', 'amcache', 'shimcache'],
    'network': ['srudb.dat', 'srum']
}

# Browser-specific file patterns (path-based detection for extensionless files)
BROWSER_FILE_PATTERNS = [
    '/chrome/user data/',
    '/google/chrome/',
    '/mozilla/firefox/',
    '/microsoft/edge/',
    '/windows/webcache/',
    'history',  # Chrome/Edge History (no extension)
    'cookies',  # Chrome/Edge Cookies (no extension)
    'webcachev01.dat',
    'webcachev24.dat',
    'places.sqlite',  # Firefox
    'formhistory.sqlite',  # Firefox
    'downloads.sqlite',  # Firefox
]

def is_valid_file(filename, full_path=''):
    """
    Check if file has a valid extension or matches browser patterns
    
    Args:
        filename: The base filename
        full_path: The full path within the ZIP (optional, for browser detection)
    """
    ext = os.path.splitext(filename)[1].lower()
    
    # Check standard extensions
    if ext in VALID_EXTENSIONS:
        return True
    
    # Check browser-specific patterns (for extensionless files like Chrome History)
    filename_lower = filename.lower()
    full_path_lower = full_path.lower() if full_path else ''
    
    for pattern in BROWSER_FILE_PATTERNS:
        if pattern in filename_lower or pattern in full_path_lower:
            # Additional validation: must be in a browser-related path
            browser_indicators = ['/chrome/', '/firefox/', '/edge/', '/webcache/']
            if any(indicator in full_path_lower for indicator in browser_indicators):
                logger.debug(f"Detected browser file (no ext): {filename} in {full_path}")
                return True
    
    return False

def detect_artifact_type(file_path):
    """
    Detect artifact type for multi-index routing
    Returns: ('browser'|'devices'|'execution'|'network'|'event')
    """
    filename = os.path.basename(file_path).lower()
    
    for artifact_type, patterns in ARTIFACT_PATTERNS.items():
        for pattern in patterns:
            if pattern.lower() in filename:
                return artifact_type
    
    # Default: main event index
    return 'event'

def extract_username_from_path(file_path):
    """
    Extract Windows username from file path
    Examples:
      C/Users/jdoe/... → jdoe
      C:\\Users\\jdoe\\... → jdoe
      /Users/jdoe/... → jdoe (macOS)
    Returns: username or None
    """
    if not file_path:
        return None
    
    # Normalize path separators
    normalized_path = file_path.replace('\\', '/')
    
    # Windows paths
    if '/Users/' in normalized_path:
        parts = normalized_path.split('/Users/')
        if len(parts) > 1:
            username = parts[1].split('/')[0]
            if username and username not in ['Public', 'Default', 'All Users']:
                return username
    
    # Windows system profile
    if '/systemprofile/' in normalized_path or '/config/systemprofile/' in normalized_path:
        return 'SYSTEM'
    
    return None

def calculate_file_hash(file_path):
    """Calculate SHA256 hash of a file"""
    hash_obj = hashlib.sha256()
    try:
        with open(file_path, 'rb') as f:
            while chunk := f.read(8388608):  # 8MB chunks
                hash_obj.update(chunk)
        return hash_obj.hexdigest()
    except Exception as e:
        logger.error(f"Error calculating hash for {file_path}: {e}")
        return None

def compress_file_gzip(source_path, keep_original=False):
    """
    Compress file with GZIP
    Returns: (compressed_path, original_size, compressed_size, ratio)
    """
    try:
        original_size = os.path.getsize(source_path)
        compressed_path = source_path + '.gz'
        
        with open(source_path, 'rb') as f_in:
            with gzip.open(compressed_path, 'wb', compresslevel=6) as f_out:
                shutil.copyfileobj(f_in, f_out)
        
        compressed_size = os.path.getsize(compressed_path)
        ratio = compressed_size / original_size if original_size > 0 else 0
        
        # Delete original if requested
        if not keep_original:
            os.remove(source_path)
        
        logger.info(f"Compressed {source_path}: {original_size} → {compressed_size} bytes ({ratio:.2%})")
        return compressed_path, original_size, compressed_size, ratio
    except Exception as e:
        logger.error(f"Error compressing {source_path}: {e}")
        return None, None, None, None


@celery.task(bind=True, name='tasks.process_uploaded_files', queue='file_processing')
def process_uploaded_files(self, case_id, files_list, source_dir='bulk_upload'):
    """
    NEW ZIP-CENTRIC WORKFLOW
    ========================
    1. Check each uploaded file
       - ZIP? → Move to storage, create container record, queue extraction
       - NOT ZIP? → Move to staging, create standalone record, queue parsing
    2. Cleanup upload folder
    3. Return summary
    
    Args:
        case_id: Case ID
        files_list: List of filenames
        source_dir: Source directory name ('bulk_upload' for SFTP, 'staging' for web uploads)
    
    Returns:
        dict: Processing results
    """
    # Determine source path based on source_dir parameter
    if source_dir == 'bulk_upload':
        upload_path = os.path.join(BASE_UPLOAD_PATH, str(case_id))
    elif source_dir == 'staging':
        upload_path = os.path.join(BASE_STAGING_PATH, str(case_id))
    else:
        upload_path = os.path.join(BASE_UPLOAD_PATH, str(case_id))  # Default to bulk_upload
    
    storage_path = os.path.join(BASE_STORAGE_PATH, f'case_{case_id}')
    staging_path = os.path.join(BASE_STAGING_PATH, str(case_id))
    
    # Ensure directories exist
    os.makedirs(storage_path, exist_ok=True)
    os.makedirs(staging_path, exist_ok=True)
    
    results = {
        'case_id': case_id,
        'total_files': len(files_list),
        'zips_queued': 0,
        'standalone_queued': 0,
        'duplicates': [],
        'errors': []
    }
    
    try:
        self.update_state(
            state='PROCESSING',
            meta={
                'current': 0,
                'total': len(files_list),
                'status': 'Processing uploaded files...'
            }
        )
        
        for idx, filename in enumerate(files_list):
            try:
                file_path = os.path.join(upload_path, filename)
                
                if not os.path.exists(file_path):
                    logger.warning(f"File not found: {file_path}")
                    results['errors'].append(f"File not found: {filename}")
                    continue
                
                # Calculate hash for deduplication
                logger.info(f"Processing {filename}...")
                file_hash = calculate_file_hash(file_path)
                
                if not file_hash:
                    results['errors'].append(f"Could not hash {filename}")
                    continue
                
                # Check for duplicate (ZIP-level only)
                from main import app, db
                from models import CaseFile
                
                with app.app_context():
                    duplicate = CaseFile.query.filter_by(
                        case_id=case_id,
                        file_hash=file_hash
                    ).first()
                    
                    if duplicate:
                        logger.warning(f"Duplicate detected: {filename} (matches {duplicate.original_filename})")
                        results['duplicates'].append({
                            'filename': filename,
                            'existing_filename': duplicate.original_filename,
                            'uploaded_at': duplicate.uploaded_at.isoformat() if duplicate.uploaded_at else None
                        })
                        # TODO: Show user dialog (Replace/Keep Both/Cancel)
                        # For now, skip duplicate
                        os.remove(file_path)
                        continue
                
                # Handle ZIP files
                if filename.lower().endswith('.zip'):
                    logger.info(f"ZIP file detected: {filename}")
                    
                    # Move ZIP to storage immediately (with collision protection)
                    storage_file_path = os.path.join(storage_path, filename)
                    
                    # If file already exists in storage, add timestamp to avoid collision
                    if os.path.exists(storage_file_path):
                        base_name = os.path.splitext(filename)[0]
                        ext = os.path.splitext(filename)[1]
                        timestamp_suffix = datetime.utcnow().strftime('%Y%m%d_%H%M%S_%f')
                        filename = f"{base_name}_{timestamp_suffix}{ext}"
                        storage_file_path = os.path.join(storage_path, filename)
                        logger.warning(f"File exists in storage, renamed to: {filename}")
                    
                    shutil.move(file_path, storage_file_path)
                    file_size = os.path.getsize(storage_file_path)
                    
                    # Count files in ZIP (for progress tracking)
                    try:
                        with zipfile.ZipFile(storage_file_path, 'r') as zf:
                            zip_file_count = len([f for f in zf.namelist() if not f.endswith('/')])
                    except Exception as e:
                        logger.error(f"Error reading ZIP {filename}: {e}")
                        zip_file_count = 0
                    
                    # Create container record
                    with app.app_context():
                        case_file = CaseFile(
                            case_id=case_id,
                            filename=filename,
                            original_filename=filename,
                            file_type='zip',
                            file_size=file_size,
                            file_path=storage_file_path,
                            file_hash=file_hash,
                            is_container=True,  # This is a ZIP container
                            is_virtual=False,   # Physical file in storage
                            parent_file_id=None,
                            uploaded_by=1,  # TODO: Get from session
                            uploaded_at=datetime.utcnow(),
                            status='extracting',
                            extraction_status='pending',
                            event_count=zip_file_count  # Track file count in ZIP
                        )
                        db.session.add(case_file)
                        db.session.commit()
                        
                        container_id = case_file.id
                    
                    # Queue extraction task
                    extract_and_process_zip.delay(case_id, container_id, storage_file_path, filename)
                    results['zips_queued'] += 1
                    logger.info(f"Queued ZIP for extraction: {filename} (container_id={container_id})")
                
                # Handle standalone files
                elif is_valid_file(filename):
                    logger.info(f"Standalone file detected: {filename}")
                    
                    # Move to staging (only if not already there)
                    if source_dir == 'staging':
                        # Already in staging, no move needed
                        staging_file_path = file_path
                    else:
                        # Move from bulk_upload to staging (with collision protection)
                        staging_file_path = os.path.join(staging_path, filename)
                        
                        # If file already exists in staging, add timestamp to avoid collision
                        if os.path.exists(staging_file_path):
                            base_name = os.path.splitext(filename)[0]
                            ext = os.path.splitext(filename)[1]
                            timestamp_suffix = datetime.utcnow().strftime('%Y%m%d_%H%M%S_%f')
                            new_filename = f"{base_name}_{timestamp_suffix}{ext}"
                            staging_file_path = os.path.join(staging_path, new_filename)
                            logger.warning(f"File exists in staging, renamed to: {new_filename}")
                        
                        shutil.move(file_path, staging_file_path)
                    file_size = os.path.getsize(staging_file_path)
                    
                    # Detect artifact type
                    artifact_type = detect_artifact_type(staging_file_path)
                    target_index = f"case_{case_id}" if artifact_type == 'event' else f"case_{case_id}_{artifact_type}"
                    
                    # Create standalone file record
                    with app.app_context():
                        case_file = CaseFile(
                            case_id=case_id,
                            filename=filename,
                            original_filename=filename,
                            file_type=os.path.splitext(filename)[1].lower().lstrip('.'),
                            file_size=file_size,
                            file_path=staging_file_path,  # Still in staging
                            file_hash=file_hash,
                            is_container=False,  # Not a ZIP
                            is_virtual=False,    # Physical file
                            parent_file_id=None,
                            target_index=target_index,
                            uploaded_by=1,
                            uploaded_at=datetime.utcnow(),
                            status='parsing',
                            parsing_status='pending'
                        )
                        db.session.add(case_file)
                        db.session.commit()
                        
                        file_id = case_file.id
                    
                    # Queue parsing task
                    parse_and_index_file.delay(case_id, file_id, staging_file_path, target_index)
                    results['standalone_queued'] += 1
                    logger.info(f"Queued standalone for parsing: {filename} (file_id={file_id})")
                
                else:
                    logger.warning(f"Invalid file type: {filename}")
                    results['errors'].append(f"Invalid file type: {filename}")
                    os.remove(file_path)
                
                # Update progress
                self.update_state(
                    state='PROCESSING',
                    meta={
                        'current': idx + 1,
                        'total': len(files_list),
                        'status': f'Processing {filename}...',
                        'zips': results['zips_queued'],
                        'standalone': results['standalone_queued']
                    }
                )
                
            except Exception as e:
                error_msg = f"Error processing {filename}: {str(e)}"
                logger.error(error_msg)
                results['errors'].append(error_msg)
                import traceback
                traceback.print_exc()
        
        # Cleanup upload folder (but NOT if source is staging, as files are still being parsed there)
        if source_dir != 'staging':
            logger.info(f"Cleaning up upload folder: {upload_path}")
            if os.path.exists(upload_path):
                for remaining_file in os.listdir(upload_path):
                    try:
                        os.remove(os.path.join(upload_path, remaining_file))
                    except Exception as e:
                        logger.error(f"Error removing {remaining_file}: {e}")
        else:
            logger.info(f"Skipping cleanup of staging directory (files still being parsed)")

        
        results['status'] = 'completed'
        results['message'] = f"Queued {results['zips_queued']} ZIPs, {results['standalone_queued']} files. {len(results['duplicates'])} duplicates skipped."
        return results
        
    except Exception as e:
        logger.error(f"Fatal error in file upload processing: {e}")
        import traceback
        traceback.print_exc()
        results['status'] = 'failed'
        results['message'] = str(e)
        return results


@celery.task(bind=True, name='tasks.extract_and_process_zip', queue='file_processing')
def extract_and_process_zip(self, case_id, container_id, zip_path, zip_filename):
    """
    PHASE 1: Extract ZIP contents to staging
    ==========================================
    1. Extract all valid files from ZIP to staging
    2. Create virtual file records for each extracted file
    3. Queue each file for parsing (Phase 2)
    4. Update container status
    
    Args:
        case_id: Case ID
        container_id: CaseFile.id of the ZIP container
        zip_path: Full path to ZIP in storage
        zip_filename: Original ZIP filename
    """
    from main import app, db
    from models import CaseFile
    
    # Create unique extraction directory using container_id to avoid multi-user collisions
    staging_path = os.path.join(BASE_STAGING_PATH, str(case_id), f'extract_{container_id}')
    os.makedirs(staging_path, exist_ok=True)
    
    extracted_files = []
    errors = []
    
    try:
        logger.info(f"Extracting ZIP: {zip_filename} (container_id={container_id})")
        
        # Update container status
        with app.app_context():
            container = CaseFile.query.get(container_id)
            container.extraction_status = 'in_progress'
            db.session.commit()
        
        # Extract ZIP
        with zipfile.ZipFile(zip_path, 'r') as zf:
            file_list = [f for f in zf.namelist() if not f.endswith('/')]
            total_files = len(file_list)
            
            logger.info(f"ZIP contains {total_files} files")
            
            for idx, zip_member in enumerate(file_list):
                try:
                    filename = os.path.basename(zip_member)
                    
                    # Skip hidden/system files
                    if filename.startswith('.') or not filename:
                        continue
                    
                    # Check if valid file type (pass full path for browser detection)
                    if not is_valid_file(filename, full_path=zip_member):
                        logger.debug(f"Skipping invalid file type: {filename} (path: {zip_member})")
                        continue
                    
                    # Extract username from full path
                    source_user = extract_username_from_path(zip_member)
                    
                    # Extract to staging with unique name
                    timestamp = datetime.utcnow().strftime('%Y%m%d_%H%M%S_%f')
                    safe_filename = f"{timestamp}_{filename}"
                    extract_path = os.path.join(staging_path, safe_filename)
                    
                    # Extract file
                    with zf.open(zip_member) as source:
                        with open(extract_path, 'wb') as target:
                            shutil.copyfileobj(source, target)
                    
                    # Calculate hash
                    file_hash = calculate_file_hash(extract_path)
                    file_size = os.path.getsize(extract_path)
                    
                    # Detect artifact type
                    artifact_type = detect_artifact_type(extract_path)
                    target_index = f"case_{case_id}" if artifact_type == 'event' else f"case_{case_id}_{artifact_type}"
                    
                    # Create virtual file record
                    with app.app_context():
                        virtual_file = CaseFile(
                            case_id=case_id,
                            filename=safe_filename,
                            original_filename=zip_member,  # Store FULL path from ZIP
                            file_type=os.path.splitext(filename)[1].lower().lstrip('.'),
                            file_size=file_size,
                            file_path=extract_path,  # Staging path
                            file_hash=file_hash,
                            is_container=False,
                            is_virtual=True,  # Virtual file (from ZIP)
                            parent_file_id=container_id,  # Link to ZIP container
                            target_index=target_index,
                            source_user=source_user,  # Store extracted username
                            uploaded_by=1,
                            uploaded_at=datetime.utcnow(),
                            status='parsing',
                            extraction_status='completed',
                            parsing_status='pending'
                        )
                        db.session.add(virtual_file)
                        db.session.commit()
                        
                        virtual_file_id = virtual_file.id
                    
                    # Queue for parsing
                    parse_and_index_file.delay(case_id, virtual_file_id, extract_path, target_index)
                    extracted_files.append(filename)
                    
                    logger.info(f"Extracted {filename} from ZIP ({idx+1}/{total_files})")
                    
                    # Update progress
                    self.update_state(
                        state='EXTRACTING',
                        meta={
                            'current': idx + 1,
                            'total': total_files,
                            'status': f'Extracting {filename}...',
                            'extracted': len(extracted_files)
                        }
                    )
                    
                except Exception as e:
                    logger.error(f"Error extracting {zip_member}: {e}")
                    errors.append(f"{zip_member}: {str(e)}")
        
        # Update container record
        with app.app_context():
            container = CaseFile.query.get(container_id)
            container.extraction_status = 'completed'
            container.status = 'parsing'  # Now waiting for files to parse
            container.files_failed = len(errors)
            if errors:
                container.error_details = '\n'.join(errors[:10])  # First 10 errors
            db.session.commit()
        
        logger.info(f"Extraction complete: {len(extracted_files)} files from {zip_filename}")
        return {
            'status': 'success',
            'extracted': len(extracted_files),
            'errors': len(errors)
        }
        
    except Exception as e:
        logger.error(f"Fatal error extracting ZIP {zip_filename}: {e}")
        import traceback
        traceback.print_exc()
        
        # Update container with error
        with app.app_context():
            container = CaseFile.query.get(container_id)
            container.extraction_status = 'failed'
            container.status = 'failed'
            container.error_message = str(e)
            db.session.commit()
        
        return {
            'status': 'failed',
            'error': str(e)
        }


@celery.task(bind=True, name='tasks.parse_and_index_file', queue='ingestion')
def parse_and_index_file(self, case_id, file_id, file_path, target_index):
    """
    PHASE 2 & 3: Parse artifact → Index to OpenSearch → Compress
    ==============================================================
    1. Parse file based on type (EVTX, NDJSON, Chrome, WebCache, etc.)
    2. Index parsed events to appropriate OpenSearch index
    3. Compress original file (GZIP)
    4. Update file record with results
    5. Clean up staging
    
    Args:
        case_id: Case ID
        file_id: CaseFile.id
        file_path: Path to file in staging
        target_index: OpenSearch index name (case_X, case_X_browser, etc.)
    """
    from main import app, db
    from models import CaseFile
    from opensearch_indexer import OpenSearchIndexer
    from config import (OPENSEARCH_HOST, OPENSEARCH_PORT, OPENSEARCH_USE_SSL,
                       OPENSEARCH_BULK_CHUNK_SIZE)
    
    logger.info(f"Parsing file_id={file_id}, target_index={target_index}")
    
    try:
        # Update file status
        with app.app_context():
            case_file = CaseFile.query.get(file_id)
            case_file.parsing_status = 'in_progress'
            case_file.status = 'parsing'
            db.session.commit()
        
        # Determine parser based on file type
        filename = os.path.basename(file_path)
        file_ext = os.path.splitext(filename)[1].lower()
        
        total_indexed = 0
        total_failed = 0
        source_system = None
        
        # Initialize OpenSearch indexer
        indexer = OpenSearchIndexer(
            host=OPENSEARCH_HOST,
            port=OPENSEARCH_PORT,
            use_ssl=OPENSEARCH_USE_SSL
        )
        
        # PHASE 2: PARSE based on file type
        if file_ext == '.evtx':
            # EVTX Parser (Phase 1)
            from parsers.evtx_parser import parse_evtx_file, EVTX_AVAILABLE
            
            if not EVTX_AVAILABLE:
                raise ImportError("evtx library not available")
            
            logger.info(f"Parsing EVTX: {filename}")
            
            # Parse and index in chunks
            chunk = []
            chunk_size = 5000
            
            for event in parse_evtx_file(file_path):
                chunk.append(event)
                
                # Capture source system
                if not source_system:
                    source_system = (event.get('computer') or event.get('Computer') or 
                                   event.get('system', {}).get('computer'))
                
                # Index chunk
                if len(chunk) >= chunk_size:
                    stats = indexer.bulk_index(
                        index_name=target_index,
                        events=iter(chunk),
                        chunk_size=OPENSEARCH_BULK_CHUNK_SIZE,
                        case_id=case_id,
                        source_file=filename,
                        file_type='EVTX'
                    )
                    total_indexed += stats['indexed']
                    total_failed += stats.get('failed', 0)
                    chunk = []
            
            # Index remaining
            if chunk:
                stats = indexer.bulk_index(
                    index_name=target_index,
                    events=iter(chunk),
                    chunk_size=OPENSEARCH_BULK_CHUNK_SIZE,
                    case_id=case_id,
                    source_file=filename,
                    file_type='EVTX'
                )
                total_indexed += stats['indexed']
                total_failed += stats.get('failed', 0)
        
        elif file_ext in ['.json', '.ndjson', '.jsonl']:
            # NDJSON Parser (Phase 1)
            from parsers.ndjson_parser import parse_ndjson_file
            
            logger.info(f"Parsing NDJSON: {filename}")
            
            chunk = []
            chunk_size = 5000
            
            for event in parse_ndjson_file(file_path):
                chunk.append(event)
                
                if not source_system:
                    source_system = event.get('normalized_computer') or event.get('host', {}).get('hostname')
                
                if len(chunk) >= chunk_size:
                    stats = indexer.bulk_index(
                        index_name=target_index,
                        events=iter(chunk),
                        chunk_size=OPENSEARCH_BULK_CHUNK_SIZE,
                        case_id=case_id,
                        source_file=filename,
                        file_type='NDJSON'
                    )
                    total_indexed += stats['indexed']
                    total_failed += stats.get('failed', 0)
                    chunk = []
            
            if chunk:
                stats = indexer.bulk_index(
                    index_name=target_index,
                    events=iter(chunk),
                    chunk_size=OPENSEARCH_BULK_CHUNK_SIZE,
                    case_id=case_id,
                    source_file=filename,
                    file_type='NDJSON'
                )
                total_indexed += stats['indexed']
                total_failed += stats.get('failed', 0)
        
        elif file_ext == '.csv':
            # CSV/Firewall Parser (Phase 1)
            from parsers.firewall_csv_parser import parse_firewall_csv
            
            logger.info(f"Parsing CSV/Firewall: {filename}")
            
            chunk = []
            chunk_size = 5000
            
            for event in parse_firewall_csv(file_path):
                chunk.append(event)
                
                # Try to extract source system from normalized fields or geo data
                if not source_system:
                    source_system = (
                        event.get('normalized_computer') or 
                        event.get('src_name') or 
                        event.get('dst_name') or
                        'Firewall'
                    )
                
                if len(chunk) >= chunk_size:
                    stats = indexer.bulk_index(
                        index_name=target_index,
                        events=iter(chunk),
                        chunk_size=OPENSEARCH_BULK_CHUNK_SIZE,
                        case_id=case_id,
                        source_file=filename,
                        file_type='CSV'
                    )
                    total_indexed += stats['indexed']
                    total_failed += stats.get('failed', 0)
                    chunk = []
            
            # Index remaining chunk
            if chunk:
                stats = indexer.bulk_index(
                    index_name=target_index,
                    events=iter(chunk),
                    chunk_size=OPENSEARCH_BULK_CHUNK_SIZE,
                    case_id=case_id,
                    source_file=filename,
                    file_type='CSV'
                )
                total_indexed += stats['indexed']
                total_failed += stats.get('failed', 0)
        
        # PHASE 2: Browser History Parser
        elif 'history' in filename.lower() or (file_ext in ['.sqlite', '.db'] and ('history' in filename.lower() or 'places.sqlite' in filename.lower())):
            # Chrome/Firefox History Parser (Phase 2)
            from parsers.browser_history_parser import parse_browser_history_file
            
            logger.info(f"Parsing browser history: {filename}")
            
            chunk = []
            chunk_size = 5000
            
            for event in parse_browser_history_file(file_path):
                chunk.append(event)
                
                if not source_system and 'computer' in event:
                    source_system = event.get('computer')
                
                if len(chunk) >= chunk_size:
                    stats = indexer.bulk_index(
                        index_name=target_index,
                        events=iter(chunk),
                        chunk_size=OPENSEARCH_BULK_CHUNK_SIZE,
                        case_id=case_id,
                        source_file=filename,
                        file_type='BrowserHistory'
                    )
                    total_indexed += stats['indexed']
                    total_failed += stats.get('failed', 0)
                    chunk = []
            
            if chunk:
                stats = indexer.bulk_index(
                    index_name=target_index,
                    events=iter(chunk),
                    chunk_size=OPENSEARCH_BULK_CHUNK_SIZE,
                    case_id=case_id,
                    source_file=filename,
                    file_type='BrowserHistory'
                )
                total_indexed += stats['indexed']
                total_failed += stats.get('failed', 0)
        
        elif 'webcache' in filename.lower() or file_ext in ['.edb', '.dat']:
            # WebCache ESE Parser (Phase 2)
            from parsers.webcache_parser import parse_webcache_file, ESE_AVAILABLE
            
            if not ESE_AVAILABLE:
                raise ImportError("pyesedb not available for WebCache parsing")
            
            logger.info(f"Parsing WebCache ESE: {filename}")
            
            chunk = []
            chunk_size = 5000
            
            for event in parse_webcache_file(file_path):
                chunk.append(event)
                
                if len(chunk) >= chunk_size:
                    stats = indexer.bulk_index(
                        index_name=target_index,
                        events=iter(chunk),
                        chunk_size=OPENSEARCH_BULK_CHUNK_SIZE,
                        case_id=case_id,
                        source_file=filename,
                        file_type='WebCache'
                    )
                    total_indexed += stats['indexed']
                    total_failed += stats.get('failed', 0)
                    chunk = []
            
            if chunk:
                stats = indexer.bulk_index(
                    index_name=target_index,
                    events=iter(chunk),
                    chunk_size=OPENSEARCH_BULK_CHUNK_SIZE,
                    case_id=case_id,
                    source_file=filename,
                    file_type='WebCache'
                )
                total_indexed += stats['indexed']
                total_failed += stats.get('failed', 0)
        
        elif file_ext == '.pf':
            # Prefetch Parser (Phase 3)
            from parsers.prefetch_parser import parse_prefetch_file, SCCA_AVAILABLE
            
            if not SCCA_AVAILABLE:
                raise ImportError("pyscca not available for Prefetch parsing")
            
            logger.info(f"Parsing Prefetch: {filename}")
            
            for event in parse_prefetch_file(file_path):
                chunk = [event]
                stats = indexer.bulk_index(
                    index_name=target_index,
                    events=iter(chunk),
                    chunk_size=OPENSEARCH_BULK_CHUNK_SIZE,
                    case_id=case_id,
                    source_file=filename,
                    file_type='Prefetch'
                )
                total_indexed += stats['indexed']
                total_failed += stats.get('failed', 0)
        
        elif 'srudb.dat' in filename.lower():
            # SRUM Parser (Phase 3)
            from parsers.srum_parser import parse_srum_file, ESE_AVAILABLE
            
            if not ESE_AVAILABLE:
                raise ImportError("pyesedb not available for SRUM parsing")
            
            logger.info(f"Parsing SRUM: {filename}")
            
            chunk = []
            chunk_size = 5000
            
            for event in parse_srum_file(file_path):
                chunk.append(event)
                
                if len(chunk) >= chunk_size:
                    stats = indexer.bulk_index(
                        index_name=target_index,
                        events=iter(chunk),
                        chunk_size=OPENSEARCH_BULK_CHUNK_SIZE,
                        case_id=case_id,
                        source_file=filename,
                        file_type='SRUM'
                    )
                    total_indexed += stats['indexed']
                    total_failed += stats.get('failed', 0)
                    chunk = []
            
            if chunk:
                stats = indexer.bulk_index(
                    index_name=target_index,
                    events=iter(chunk),
                    chunk_size=OPENSEARCH_BULK_CHUNK_SIZE,
                    case_id=case_id,
                    source_file=filename,
                    file_type='SRUM'
                )
                total_indexed += stats['indexed']
                total_failed += stats.get('failed', 0)
        
        elif 'setupapi.dev.log' in filename.lower():
            # setupapi.dev.log Parser (Phase 3)
            from parsers.setupapi_parser import parse_setupapi_file
            
            logger.info(f"Parsing setupapi.dev.log: {filename}")
            
            chunk = []
            chunk_size = 1000
            
            for event in parse_setupapi_file(file_path):
                chunk.append(event)
                
                if len(chunk) >= chunk_size:
                    stats = indexer.bulk_index(
                        index_name=target_index,
                        events=iter(chunk),
                        chunk_size=OPENSEARCH_BULK_CHUNK_SIZE,
                        case_id=case_id,
                        source_file=filename,
                        file_type='DeviceLog'
                    )
                    total_indexed += stats['indexed']
                    total_failed += stats.get('failed', 0)
                    chunk = []
            
            if chunk:
                stats = indexer.bulk_index(
                    index_name=target_index,
                    events=iter(chunk),
                    chunk_size=OPENSEARCH_BULK_CHUNK_SIZE,
                    case_id=case_id,
                    source_file=filename,
                    file_type='DeviceLog'
                )
                total_indexed += stats['indexed']
                total_failed += stats.get('failed', 0)
        
        else:
            logger.warning(f"No parser available for: {filename}")
            raise ValueError(f"Unsupported file type: {file_ext}")
        
        # PHASE 3: Compress original file (GZIP)
        logger.info(f"Compressing {filename}...")
        compressed_path, orig_size, comp_size, ratio = compress_file_gzip(file_path, keep_original=False)
        
        # Move compressed file to storage (if standalone) or delete (if virtual)
        storage_path = os.path.join(BASE_STORAGE_PATH, f'case_{case_id}')
        os.makedirs(storage_path, exist_ok=True)
        
        with app.app_context():
            case_file = CaseFile.query.get(file_id)
            
            if case_file.is_virtual:
                # Virtual file: Delete compressed (ZIP is source)
                if compressed_path and os.path.exists(compressed_path):
                    os.remove(compressed_path)
                    logger.info(f"Deleted compressed virtual file: {compressed_path}")
                final_path = None
            else:
                # Standalone file: Move compressed to storage
                if compressed_path:
                    final_compressed_path = os.path.join(storage_path, os.path.basename(compressed_path))
                    shutil.move(compressed_path, final_compressed_path)
                    final_path = final_compressed_path
                else:
                    final_path = None
            
            # Update file record
            case_file.parsing_status = 'completed'
            case_file.indexing_status = 'completed'
            case_file.status = 'indexed'
            case_file.file_path = final_path
            case_file.source_system = source_system
            case_file.event_count = total_indexed
            case_file.indexed_at = datetime.utcnow()
            db.session.commit()
        
        logger.info(f"Indexed {total_indexed} events from {filename} to {target_index}")
        
        return {
            'status': 'success',
            'indexed': total_indexed,
            'failed': total_failed
        }
        
    except Exception as e:
        logger.error(f"Error parsing file_id={file_id}: {e}")
        import traceback
        traceback.print_exc()
        
        # Update with error
        with app.app_context():
            case_file = CaseFile.query.get(file_id)
            case_file.parsing_status = 'failed'
            case_file.status = 'failed'
            case_file.error_message = str(e)
            case_file.retry_count = (case_file.retry_count or 0) + 1
            db.session.commit()
        
        return {
            'status': 'failed',
            'error': str(e)
        }


# LEGACY TASK: Keep for backward compatibility
@celery.task(name='tasks.ingest_staged_file', queue='ingestion')
def ingest_staged_file(case_id, file_path, file_hash=None):
    """
    DEPRECATED: Legacy task for backward compatibility
    Use parse_and_index_file instead
    """
    logger.warning("ingest_staged_file is deprecated, use parse_and_index_file")
    # For now, just call the old logic (if needed)
    return {'status': 'deprecated'}
