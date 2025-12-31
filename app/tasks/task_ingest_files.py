"""
File Ingestion Task - NEW_FILE_UPLOAD.ND Implementation
========================================================
Complete redesign of file upload/storage architecture

FLOW:
1. Pre-processing review (failed file moves)
2. Staging (ZIP extraction to subfolders or direct move)
3. SHA256 duplicate detection with storage verification
4. Indexing (using existing parsers with parser_type auto-detection)
5. Move to storage (all-or-nothing with validation)
6. Cleanup (staging and uploads)

Uses ingestion_progress table for resumable operations.
"""

import os
import sys
import logging
from datetime import datetime
from celery import Task

# Add app directory to path
app_dir = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
if app_dir not in sys.path:
    sys.path.insert(0, app_dir)

logger = logging.getLogger(__name__)

from celery_app import celery
from utils.file_ingestion import (
    scan_upload_folder,
    stage_file,
    calculate_sha256,
    check_duplicate_file,
    get_parser_type_from_file,
    determine_file_status,
    move_file_to_storage,
    cleanup_staging,
    cleanup_uploads,
    get_or_create_ingestion_progress,
    update_ingestion_progress
)


@celery.task(name='tasks.ingest_files', bind=True)
def ingest_files(self, case_id: int, user_id: int, upload_type: str = 'web', 
                 resume: bool = False):
    """
    Main file ingestion task following NEW_FILE_UPLOAD.ND flow
    
    Args:
        case_id: Case ID
        user_id: User ID who started ingestion
        upload_type: 'web' or 'sftp'
        resume: Whether to resume previous ingestion
    
    Returns:
        Dict with ingestion results
    """
    from main import app, db
    from models import Case, CaseFile, IngestionProgress
    from audit_logger import log_action
    
    with app.app_context():
        try:
            # Get or create ingestion progress record
            progress_id = get_or_create_ingestion_progress(case_id, user_id)
            
            # Update progress: Starting
            update_ingestion_progress(
                progress_id,
                status='in_progress',
                current_step='staging'
            )
            
            self.update_state(
                state='PROGRESS',
                meta={
                    'status': 'Scanning upload folder...',
                    'progress': 0,
                    'current_step': 'staging'
                }
            )
            
            # STEP 1: Scan upload folder
            files_to_process = scan_upload_folder(case_id, upload_type)
            
            if not files_to_process:
                update_ingestion_progress(
                    progress_id,
                    status='completed',
                    current_step='cleanup',
                    completed_at=datetime.utcnow(),
                    error_message='No files found in upload folder'
                )
                
                return {
                    'success': False,
                    'message': 'No files found in upload folder',
                    'files_processed': 0
                }
            
            total_files = len(files_to_process)
            update_ingestion_progress(progress_id, total_files=total_files)
            
            # STEP 2: Stage files (extract ZIPs or move directly)
            staged_files = []
            processing_errors = []
            
            for idx, file_info in enumerate(files_to_process):
                progress_pct = int((idx / total_files) * 30)  # Staging = 0-30%
                
                self.update_state(
                    state='PROGRESS',
                    meta={
                        'status': f'Staging {file_info["filename"]}...',
                        'progress': progress_pct,
                        'current_step': 'staging',
                        'files_processed': idx,
                        'total_files': total_files
                    }
                )
                
                # Stage the file
                stage_result = stage_file(
                    file_info['path'],
                    case_id,
                    is_zip=file_info['is_zip']
                )
                
                if stage_result['success']:
                    for staged_file_path in stage_result['staged_files']:
                        staged_files.append({
                            'path': staged_file_path,
                            'original_name': file_info['filename'],
                            'is_from_zip': stage_result['is_zip'],
                            'zip_folder': stage_result.get('extraction_folder')
                        })
                else:
                    processing_errors.append({
                        'file': file_info['filename'],
                        'step': 'staging',
                        'error': stage_result.get('error', 'Unknown error')
                    })
                
                update_ingestion_progress(
                    progress_id,
                    processed_files=idx + 1,
                    last_file_processed=file_info['filename']
                )
            
            # STEP 3: Calculate hashes and check duplicates
            update_ingestion_progress(progress_id, current_step='hashing')
            
            files_to_index = []
            duplicates_skipped = 0
            
            for idx, staged_info in enumerate(staged_files):
                progress_pct = 30 + int((idx / len(staged_files)) * 20)  # Hashing = 30-50%
                
                self.update_state(
                    state='PROGRESS',
                    meta={
                        'status': f'Hashing {os.path.basename(staged_info["path"])}...',
                        'progress': progress_pct,
                        'current_step': 'hashing',
                        'duplicates_skipped': duplicates_skipped
                    }
                )
                
                # Calculate SHA256
                try:
                    file_hash = calculate_sha256(staged_info['path'])
                except Exception as e:
                    processing_errors.append({
                        'file': os.path.basename(staged_info['path']),
                        'step': 'hashing',
                        'error': str(e)
                    })
                    continue
                
                # Check for duplicate
                duplicate_info = check_duplicate_file(case_id, file_hash)
                
                if duplicate_info and duplicate_info['file_exists_on_disk']:
                    # Duplicate found and verified - skip this file
                    duplicates_skipped += 1
                    
                    # Delete staging copy
                    try:
                        os.remove(staged_info['path'])
                        
                        log_action(
                            action='file_duplicate_skipped',
                            resource_type='file',
                            details={
                                'case_id': case_id,
                                'filename': os.path.basename(staged_info['path']),
                                'hash': file_hash,
                                'existing_file_id': duplicate_info['file_id'],
                                'existing_path': duplicate_info['file_path']
                            },
                            status='success'
                        )
                    except Exception as e:
                        logger.error(f"Error deleting duplicate staging file: {e}")
                    
                    continue
                
                # Not a duplicate (or storage file was lost) - mark for indexing
                staged_info['hash'] = file_hash
                files_to_index.append(staged_info)
            
            # STEP 4A: Create all file records first (so they all appear in UI immediately)
            update_ingestion_progress(progress_id, current_step='creating_records')
            
            file_records = []
            for file_info in files_to_index:
                filename = os.path.basename(file_info['path'])
                file_ext = os.path.splitext(filename)[1].lower()
                parser_type = get_parser_type_from_file(filename)
                
                file_record = CaseFile(
                    case_id=case_id,
                    filename=filename,
                    original_filename=file_info['original_name'],
                    file_type=file_ext.lstrip('.'),
                    file_size=os.path.getsize(file_info['path']),
                    file_path=file_info['path'],
                    file_hash=file_info['hash'],
                    parser_type=parser_type,
                    status='New',
                    uploaded_by=user_id,
                    uploaded_at=datetime.utcnow()
                )
                db.session.add(file_record)
                file_records.append({
                    'record': file_record,
                    'info': file_info
                })
            
            db.session.commit()  # Commit all at once so all files appear in UI
            
            # STEP 4B: Now parse and index each file
            update_ingestion_progress(progress_id, current_step='indexing')
            
            indexed_count = 0
            failed_count = 0
            
            # Import parsers and utilities
            from parsers.evtx_parser import parse_evtx_file, EVTX_AVAILABLE
            from parsers.ndjson_parser import parse_ndjson_file
            from parsers.firewall_csv_parser import parse_firewall_csv
            from opensearch_indexer import OpenSearchIndexer
            from config import Config
            from utils.event_normalization import normalize_event_computer
            
            indexer = OpenSearchIndexer()
            index_name = f'case_{case_id}'
            
            for idx, file_data in enumerate(file_records):
                file_record = file_data['record']
                file_info = file_data['info']
                progress_pct = 50 + int((idx / max(len(file_records), 1)) * 40)  # Indexing = 50-90%
                
                file_path = file_data['info']['path']
                filename = os.path.basename(file_path)
                file_ext = os.path.splitext(filename)[1].lower()
                
                self.update_state(
                    state='PROGRESS',
                    meta={
                        'status': f'Parsing {filename}...',
                        'progress': progress_pct,
                        'current_step': 'indexing',
                        'indexed': indexed_count,
                        'failed': failed_count
                    }
                )
                
                try:
                    event_count = 0
                    parse_success = False
                    source_system = None  # Initialize before parsing
                    
                    # Now parse and index
                    if file_ext == '.evtx' and EVTX_AVAILABLE:
                        # Parse EVTX (returns iterator of events)
                        events = list(parse_evtx_file(file_path))
                        
                        # Extract computer name from first event using normalization utility
                        source_system = None
                        if events:
                            source_system = normalize_event_computer(events[0])
                        
                        # Index to OpenSearch in chunks
                        chunk_size = 500
                        for i in range(0, len(events), chunk_size):
                            chunk = events[i:i + chunk_size]
                            indexer.bulk_index(
                                index_name=index_name,
                                events=iter(chunk),
                                chunk_size=chunk_size,
                                case_id=case_id,
                                source_file=filename
                            )
                        
                        event_count = len(events)
                        parse_success = True
                        
                    elif file_ext in ['.json', '.ndjson', '.jsonl']:
                        # Parse NDJSON (returns iterator of events)
                        events = list(parse_ndjson_file(file_path))
                        
                        # Extract computer name from first event using normalization utility
                        source_system = None
                        if events:
                            source_system = normalize_event_computer(events[0])
                        
                        # Index to OpenSearch in chunks
                        chunk_size = 500
                        for i in range(0, len(events), chunk_size):
                            chunk = events[i:i + chunk_size]
                            indexer.bulk_index(
                                index_name=index_name,
                                events=iter(chunk),
                                chunk_size=chunk_size,
                                case_id=case_id,
                                source_file=filename
                            )
                        
                        event_count = len(events)
                        parse_success = True
                    
                    elif file_ext == '.csv':
                        # Parse CSV/Firewall logs
                        events = list(parse_firewall_csv(file_path))
                        
                        # Extract computer name from first event using normalization utility
                        if events:
                            source_system = normalize_event_computer(events[0])
                        
                        # Index to OpenSearch in chunks
                        chunk_size = 500
                        for i in range(0, len(events), chunk_size):
                            chunk = events[i:i + chunk_size]
                            indexer.bulk_index(
                                index_name=index_name,
                                events=iter(chunk),
                                chunk_size=chunk_size,
                                case_id=case_id,
                                source_file=filename
                            )
                        
                        event_count = len(events)
                        parse_success = True
                    
                    # Update file record with results (fetch fresh from DB by ID)
                    file_id = file_record.id
                    file_record = CaseFile.query.get(file_id)
                    
                    if parse_success:
                        if event_count == 0:
                            file_record.status = 'ZeroEvents'
                        else:
                            file_record.status = 'Indexed'
                            file_record.indexed_at = datetime.utcnow()
                    else:
                        file_record.status = 'ParseFail'
                    
                    file_record.event_count = event_count
                    file_record.source_system = source_system
                    db.session.commit()
                    
                    if file_record.status == 'Indexed':
                        indexed_count += 1
                    else:
                        failed_count += 1
                    
                except Exception as e:
                    logger.error(f"Error processing {filename}: {e}", exc_info=True)
                    
                    # Update existing record with error (fetch fresh from DB)
                    file_id = file_record.id
                    file_record = CaseFile.query.get(file_id)
                    file_record.status = 'Error'
                    file_record.error_message = str(e)
                    db.session.commit()
                    
                    failed_count += 1
                    processing_errors.append({
                        'file': filename,
                        'step': 'parsing',
                        'error': str(e)
                    })
            
            # STEP 5: Move to storage
            # Note: In full implementation, this happens after parsing
            # For now, files stay in staging for parser to access
            
            # STEP 6: Cleanup uploads folder
            update_ingestion_progress(progress_id, current_step='cleanup')
            cleanup_uploads(case_id, upload_type)
            
            # Mark ingestion as complete
            update_ingestion_progress(
                progress_id,
                status='completed',
                current_step='cleanup',
                processed_files=total_files,
                failed_files=failed_count,
                completed_at=datetime.utcnow()
            )
            
            # Log completion
            log_action(
                action='file_ingestion_completed',
                resource_type='case',
                details={
                    'case_id': case_id,
                    'total_files': total_files,
                    'indexed': indexed_count,
                    'duplicates_skipped': duplicates_skipped,
                    'failed': failed_count,
                    'upload_type': upload_type
                },
                status='success'
            )
            
            return {
                'success': True,
                'total_files': total_files,
                'indexed': indexed_count,
                'duplicates_skipped': duplicates_skipped,
                'failed': failed_count,
                'errors': processing_errors
            }
            
        except Exception as e:
            logger.error(f"Fatal error in ingestion task: {e}", exc_info=True)
            
            # Update progress with error
            try:
                update_ingestion_progress(
                    progress_id,
                    status='failed',
                    error_message=str(e),
                    completed_at=datetime.utcnow()
                )
            except:
                pass
            
            return {
                'success': False,
                'error': str(e)
            }


# Export for Celery autodiscovery
__all__ = ['ingest_files']

