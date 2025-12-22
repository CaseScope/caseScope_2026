"""
File Upload Processing Task
Handles file uploads, ZIP extraction, staging, and ingestion
"""

import os
import shutil
import zipfile
import logging
import sys
from datetime import datetime
from celery import Task

# Add app directory to Python path for imports
app_dir = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
if app_dir not in sys.path:
    sys.path.insert(0, app_dir)

logger = logging.getLogger(__name__)

# Import celery instance
from celery_app import celery

# Valid file extensions (case-insensitive)
VALID_EXTENSIONS = ['.zip', '.evtx', '.ndjson', '.json', '.jsonl', '.log', '.csv']

# Base paths
BASE_UPLOAD_PATH = '/opt/casescope/bulk_upload'
BASE_STAGING_PATH = '/opt/casescope/staging'
BASE_STORAGE_PATH = '/opt/casescope/storage'


def is_valid_file(filename):
    """Check if file has a valid extension"""
    ext = os.path.splitext(filename)[1].lower()
    return ext in VALID_EXTENSIONS


def extract_zip_recursive(zip_path, extract_to, case_id):
    """
    Recursively extract ZIP files and collect valid files
    Returns list of extracted valid files
    """
    extracted_files = []
    temp_extract = os.path.join(extract_to, '_temp_extract')
    
    try:
        os.makedirs(temp_extract, exist_ok=True)
        
        # Extract ZIP
        with zipfile.ZipFile(zip_path, 'r') as zip_ref:
            zip_ref.extractall(temp_extract)
        
        # Walk through extracted files
        for root, dirs, files in os.walk(temp_extract):
            for filename in files:
                file_path = os.path.join(root, filename)
                
                # If it's a valid file type
                if is_valid_file(filename):
                    # If it's another ZIP, extract it recursively
                    if filename.lower().endswith('.zip'):
                        nested_files = extract_zip_recursive(file_path, extract_to, case_id)
                        extracted_files.extend(nested_files)
                    else:
                        # Move valid file to staging
                        dest_filename = f"{datetime.utcnow().strftime('%Y%m%d_%H%M%S')}_{filename}"
                        dest_path = os.path.join(extract_to, dest_filename)
                        shutil.move(file_path, dest_path)
                        extracted_files.append(dest_path)
                        logger.info(f"Extracted valid file: {filename} -> {dest_filename}")
        
        # Cleanup temp extraction folder
        if os.path.exists(temp_extract):
            shutil.rmtree(temp_extract)
            
    except zipfile.BadZipFile:
        logger.error(f"Bad ZIP file: {zip_path}")
    except Exception as e:
        logger.error(f"Error extracting ZIP {zip_path}: {e}")
    
    return extracted_files


@celery.task(bind=True, name='tasks.process_uploaded_files', queue='file_processing')
def process_uploaded_files(self, case_id, files_list):
    """
    Process uploaded files for a case
    
    Workflow:
    1. Check each file - is it a ZIP?
       - YES: Extract valid files recursively to staging
       - NO: Move directly to staging
    2. Cleanup upload folder
    3. Queue files in staging for ingestion
    4. After ingestion, files are moved to storage
    
    Args:
        case_id: Case ID
        files_list: List of filenames in the upload folder
    
    Returns:
        dict: Processing results
    """
    upload_path = os.path.join(BASE_UPLOAD_PATH, str(case_id))
    staging_path = os.path.join(BASE_STAGING_PATH, str(case_id))
    
    # Ensure staging directory exists
    os.makedirs(staging_path, exist_ok=True)
    
    results = {
        'case_id': case_id,
        'total_files': len(files_list),
        'processed': 0,
        'staged_files': [],
        'errors': []
    }
    
    try:
        # Update task state
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
                    continue
                
                # Check if it's a ZIP file
                if filename.lower().endswith('.zip'):
                    logger.info(f"Processing ZIP file: {filename}")
                    
                    # Extract ZIP recursively
                    extracted = extract_zip_recursive(file_path, staging_path, case_id)
                    results['staged_files'].extend(extracted)
                    results['processed'] += len(extracted)
                    
                    logger.info(f"Extracted {len(extracted)} valid files from {filename}")
                    
                elif is_valid_file(filename):
                    # Valid non-ZIP file - move directly to staging
                    timestamp = datetime.utcnow().strftime('%Y%m%d_%H%M%S')
                    dest_filename = f"{timestamp}_{filename}"
                    dest_path = os.path.join(staging_path, dest_filename)
                    
                    shutil.move(file_path, dest_path)
                    results['staged_files'].append(dest_path)
                    results['processed'] += 1
                    
                    logger.info(f"Moved valid file to staging: {filename}")
                    
                else:
                    # Invalid file type
                    logger.warning(f"Invalid file type, skipping: {filename}")
                    results['errors'].append(f"Invalid file type: {filename}")
                
                # Update progress
                self.update_state(
                    state='PROCESSING',
                    meta={
                        'current': idx + 1,
                        'total': len(files_list),
                        'status': f'Processing {filename}...',
                        'processed': results['processed']
                    }
                )
                
            except Exception as e:
                error_msg = f"Error processing {filename}: {str(e)}"
                logger.error(error_msg)
                results['errors'].append(error_msg)
        
        # Step 2: Cleanup upload folder
        logger.info(f"Cleaning up upload folder: {upload_path}")
        if os.path.exists(upload_path):
            # Remove any remaining files
            for remaining_file in os.listdir(upload_path):
                try:
                    os.remove(os.path.join(upload_path, remaining_file))
                except Exception as e:
                    logger.error(f"Error removing {remaining_file}: {e}")
        
        # Step 3: Queue files for ingestion
        # TODO: Trigger ingestion tasks for staged files
        # For now, just log the staged files
        logger.info(f"Files ready for ingestion in {staging_path}: {len(results['staged_files'])}")
        
        results['status'] = 'completed'
        results['message'] = f"Processed {results['processed']} files. {len(results['errors'])} errors."
        
        return results
        
    except Exception as e:
        logger.error(f"Fatal error in file upload processing: {e}")
        results['status'] = 'failed'
        results['message'] = str(e)
        return results


@celery.task(name='tasks.ingest_staged_file', queue='ingestion')
def ingest_staged_file(case_id, file_path):
    """
    Ingest a single staged file
    After successful ingestion, move to storage
    
    Args:
        case_id: Case ID
        file_path: Full path to staged file
    
    Returns:
        dict: Ingestion results
    """
    from parsers.evtx_parser import parse_evtx_file, EVTX_AVAILABLE
    from opensearch_indexer import OpenSearchIndexer
    from config import (OPENSEARCH_HOST, OPENSEARCH_PORT, OPENSEARCH_USE_SSL,
                       OPENSEARCH_BULK_CHUNK_SIZE, OPENSEARCH_INDEX_PREFIX)
    
    storage_path = os.path.join(BASE_STORAGE_PATH, f'case_{case_id}')
    os.makedirs(storage_path, exist_ok=True)
    
    filename = os.path.basename(file_path)
    file_ext = os.path.splitext(filename)[1].lower()
    
    results = {
        'status': 'unknown',
        'file': filename,
        'case_id': case_id,
        'events_indexed': 0,
        'errors': []
    }
    
    try:
        logger.info(f"Ingesting file: {filename} for case {case_id}")
        
        # Handle ZIP files - extract and queue individual files for ingestion
        if file_ext == '.zip':
            logger.info(f"Extracting ZIP file: {filename}")
            staging_path = os.path.join(BASE_STAGING_PATH, str(case_id))
            
            # Extract ZIP recursively
            extracted_files = extract_zip_recursive(file_path, staging_path, case_id)
            
            logger.info(f"Extracted {len(extracted_files)} files from {filename}")
            
            # Queue each extracted file for ingestion
            for extracted_file in extracted_files:
                ingest_staged_file.delay(case_id, extracted_file)
            
            # Move the original ZIP to storage
            storage_file_path = os.path.join(storage_path, filename)
            shutil.move(file_path, storage_file_path)
            
            results['status'] = 'success'
            results['message'] = f'Extracted {len(extracted_files)} files from ZIP'
            results['extracted_files'] = len(extracted_files)
            results['storage_path'] = storage_file_path
            
            return results
        
        # Determine file type and parse
        elif file_ext == '.evtx':
            if not EVTX_AVAILABLE:
                raise ImportError("evtx library not available")
            
            # Parse EVTX file with MEMORY-SAFE chunking
            logger.info(f"Parsing EVTX file: {filename}")
            
            # Index into OpenSearch with chunked processing
            index_name = f"{OPENSEARCH_INDEX_PREFIX}{case_id}"
            indexer = OpenSearchIndexer(
                host=OPENSEARCH_HOST,
                port=OPENSEARCH_PORT,
                use_ssl=OPENSEARCH_USE_SSL
            )
            
            # MEMORY-SAFE: Process in chunks to avoid OOM on systems with 16-32GB RAM
            chunk = []
            chunk_size = 5000  # Process 5000 events at a time (~12-15MB in memory)
            total_indexed = 0
            total_failed = 0
            source_system = None  # Track computer name
            
            logger.info(f"Processing events in chunks of {chunk_size}...")
            
            for event in parse_evtx_file(file_path):
                chunk.append(event)
                
                # Capture source system from first event that has it
                # Try multiple fields: computer, Computer, ComputerName
                if source_system is None:
                    source_system = (
                        event.get('computer') or 
                        event.get('Computer') or 
                        event.get('computer_name') or 
                        event.get('system', {}).get('computer') if isinstance(event.get('system'), dict) else None
                    )
                    if source_system:
                        logger.info(f"Detected source system: {source_system}")
                
                # When chunk is full, index it
                if len(chunk) >= chunk_size:
                    stats = indexer.bulk_index(
                        index_name=index_name,
                        events=iter(chunk),  # Iterator from list
                        chunk_size=OPENSEARCH_BULK_CHUNK_SIZE,
                        case_id=case_id,
                        source_file=filename
                    )
                    total_indexed += stats['indexed']
                    total_failed += stats.get('failed', 0)
                    
                    # Clear chunk to free memory
                    chunk = []
                    
                    logger.info(f"Indexed {total_indexed} events so far...")
            
            # Index any remaining events
            if chunk:
                stats = indexer.bulk_index(
                    index_name=index_name,
                    events=iter(chunk),
                    chunk_size=OPENSEARCH_BULK_CHUNK_SIZE,
                    case_id=case_id,
                    source_file=filename
                )
                total_indexed += stats['indexed']
                total_failed += stats.get('failed', 0)
            
            # Move to storage after successful ingestion
            storage_file_path = os.path.join(storage_path, filename)
            shutil.move(file_path, storage_file_path)
            
            results['events_indexed'] = total_indexed
            results['events_failed'] = total_failed
            results['source_system'] = source_system
            results['storage_path'] = storage_file_path
            results['status'] = 'success'
            
            logger.info(f"Indexed {total_indexed} events from {filename} (memory-safe chunking)")
            
            # Create CaseFile record
            try:
                import sys
                import os as os_sys
                # Add app dir to path if not already there
                app_dir = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
                if app_dir not in sys.path:
                    sys.path.insert(0, app_dir)
                
                from main import app, db
                from models import CaseFile
                
                # Get Flask app context
                with app.app_context():
                    case_file = CaseFile(
                        case_id=case_id,
                        filename=filename,
                        original_filename=filename,
                        file_type='evtx',
                        file_size=os.path.getsize(storage_file_path),
                        file_path=storage_file_path,
                        source_system=source_system,
                        event_count=total_indexed,
                        uploaded_by=1,  # TODO: Get from session/context
                        status='indexed',
                        indexed_at=datetime.utcnow()
                    )
                    db.session.add(case_file)
                    db.session.commit()
                    logger.info(f"Created CaseFile record for {filename}")
            except Exception as e:
                logger.error(f"Failed to create CaseFile record: {e}")
                import traceback
                traceback.print_exc()
            
        elif file_ext in ['.json', '.ndjson', '.jsonl']:
            # TODO: Implement JSON parsing
            results['status'] = 'skipped'
            results['message'] = 'JSON parsing not yet implemented'
            return results
            
        elif file_ext == '.csv':
            # TODO: Implement CSV parsing
            results['status'] = 'skipped'
            results['message'] = 'CSV parsing not yet implemented'
            return results
            
        elif file_ext == '.log':
            # TODO: Implement LOG parsing
            results['status'] = 'skipped'
            results['message'] = 'LOG parsing not yet implemented'
            return results
        else:
            results['status'] = 'unsupported'
            results['message'] = f'Unsupported file type: {file_ext}'
            return results
        
        # Move to storage after successful ingestion
        storage_file_path = os.path.join(storage_path, filename)
        shutil.move(file_path, storage_file_path)
        
        results['status'] = 'success'
        results['storage_path'] = storage_file_path
        logger.info(f"File ingested and moved to storage: {storage_file_path}")
        
    except Exception as e:
        logger.error(f"Error ingesting file {file_path}: {e}")
        import traceback
        traceback.print_exc()
        results['status'] = 'error'
        results['error'] = str(e)
    
    return results


@celery.task(name='tasks.ingest_all_staged_files', queue='ingestion')
def ingest_all_staged_files(case_id):
    """
    Ingest all files in the staging folder for a case
    
    Args:
        case_id: Case ID
    
    Returns:
        dict: Ingestion results
    """
    staging_path = os.path.join(BASE_STAGING_PATH, str(case_id))
    
    if not os.path.exists(staging_path):
        return {
            'status': 'error',
            'message': 'Staging folder does not exist'
        }
    
    staged_files = [f for f in os.listdir(staging_path) if os.path.isfile(os.path.join(staging_path, f))]
    
    results = {
        'case_id': case_id,
        'total_files': len(staged_files),
        'ingested': 0,
        'errors': []
    }
    
    for filename in staged_files:
        file_path = os.path.join(staging_path, filename)
        result = ingest_staged_file(case_id, file_path)
        
        if result['status'] == 'success':
            results['ingested'] += 1
        else:
            results['errors'].append(result.get('error', 'Unknown error'))
    
    results['status'] = 'completed'
    results['message'] = f"Ingested {results['ingested']}/{results['total_files']} files"
    
    return results
