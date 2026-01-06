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
            zip_containers_created = 0
            
            for idx, file_info in enumerate(files_to_process):
                progress_pct = int((idx / total_files) * 30)  # Staging = 0-30%
                
                # Determine step based on file type
                step_name = 'extracting' if file_info['is_zip'] else 'staging'
                step_verb = 'Extracting' if file_info['is_zip'] else 'Staging'
                
                self.update_state(
                    state='PROGRESS',
                    meta={
                        'status': f'{step_verb} {file_info["filename"]}...',
                        'progress': progress_pct,
                        'current_step': step_name,
                        'files_processed': idx,
                        'total_files': total_files,
                        'zip_containers_created': zip_containers_created
                    }
                )
                
                # NEW: For ZIP files, track container and check for duplicates BEFORE extraction
                zip_container_id = None
                if file_info['is_zip']:
                    # Calculate ZIP hash before extraction
                    try:
                        zip_hash = calculate_sha256(file_info['path'])
                        zip_size = os.path.getsize(file_info['path'])
                        
                        # Check if this ZIP was already uploaded (duplicate detection)
                        duplicate_zip = CaseFile.query.filter_by(
                            case_id=case_id,
                            file_hash=zip_hash,
                            parser_type='zipcontainer'
                        ).first()
                        
                        if duplicate_zip:
                            logger.info(f"Duplicate ZIP detected: {file_info['filename']} (hash: {zip_hash[:16]}...)")
                            processing_errors.append({
                                'file': file_info['filename'],
                                'step': 'duplicate_check',
                                'error': f'Duplicate ZIP - already uploaded on {duplicate_zip.uploaded_at}'
                            })
                            # Skip extraction
                            continue
                        
                        # Create container record for ZIP
                        zip_container = CaseFile(
                            case_id=case_id,
                            filename=file_info['filename'],
                            original_filename=file_info['filename'],
                            file_type='zip',
                            file_size=zip_size,
                            file_path=None,  # Not storing ZIP file
                            file_hash=zip_hash,
                            parser_type='zipcontainer',
                            status='Extracting',
                            event_count=0,  # Containers don't have events
                            is_hidden=False,
                            uploaded_by=user_id,
                            uploaded_at=datetime.utcnow()
                        )
                        db.session.add(zip_container)
                        db.session.commit()  # Commit so it appears in UI during extraction
                        
                        zip_container_id = zip_container.id
                        zip_containers_created += 1
                        logger.info(f"Created ZIP container record for {file_info['filename']} (ID: {zip_container_id})")
                        
                    except Exception as e:
                        logger.error(f"Error checking ZIP duplicate: {e}")
                        # Continue with extraction even if container tracking fails
                
                # Stage the file
                stage_result = stage_file(
                    file_info['path'],
                    case_id,
                    is_zip=file_info['is_zip']
                )
                
                # Update ZIP container status based on extraction result
                if file_info['is_zip'] and zip_container_id:
                    try:
                        zip_container = CaseFile.query.get(zip_container_id)
                        if zip_container:
                            if stage_result['success']:
                                # Check if extraction was partial (had errors but got some files)
                                if stage_result.get('partial', False):
                                    zip_container.status = 'Extracted'  # Still mark as extracted
                                    error_count = len(stage_result.get('errors', []))
                                    zip_container.error_message = f'Partial extraction: {error_count} file(s) had errors'
                                    logger.warning(f"Partial extraction for {file_info['filename']}: {error_count} errors")
                                else:
                                    zip_container.status = 'Extracted'
                                zip_container.event_count = stage_result.get('files_extracted', 0)  # Store count of extracted files
                            else:
                                zip_container.status = 'ExtractionFail'
                                zip_container.error_message = stage_result.get('error', 'Unknown extraction error')
                            db.session.commit()
                    except Exception as e:
                        logger.error(f"Error updating ZIP container status: {e}")
                
                if stage_result['success']:
                    for staged_file_path in stage_result['staged_files']:
                        staged_files.append({
                            'path': staged_file_path,
                            'original_name': file_info['filename'],
                            'is_from_zip': stage_result['is_zip'],
                            'zip_folder': stage_result.get('extraction_folder'),
                            'zip_container_id': zip_container_id  # Link to container
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
                
                # Determine if this file came from a ZIP
                is_from_zip = file_info.get('is_from_zip', False)
                
                # For files from ZIP: store ZIP name in original_filename
                # For standalone files: original_filename = filename
                if is_from_zip:
                    original_name = file_info['original_name']  # This is the ZIP filename
                else:
                    original_name = filename
                
                file_record = CaseFile(
                    case_id=case_id,
                    filename=filename,
                    original_filename=original_name,
                    file_type=file_ext.lstrip('.'),
                    file_size=os.path.getsize(file_info['path']),
                    file_path=file_info['path'],
                    file_hash=file_info['hash'],
                    parser_type=parser_type,
                    status='New',
                    is_hidden=False,  # Show all files in main view
                    uploaded_by=user_id,
                    uploaded_at=datetime.utcnow()
                )
                db.session.add(file_record)
                file_records.append({
                    'record': file_record,
                    'info': file_info
                })
            
            db.session.commit()  # Commit all at once so all files appear in UI
            
            # STEP 4B: Queue all files for parallel processing
            update_ingestion_progress(progress_id, current_step='indexing')
            
            from tasks.task_process_file_v2 import process_individual_file_v2
            
            # Queue all files as separate tasks (parallel processing!)
            queued_tasks = []
            for file_data in file_records:
                file_record = file_data['record']
                file_path = file_data['info']['path']
                
                # Queue task for this file (using V2 with parser factory)
                task = process_individual_file_v2.delay(case_id, file_record.id, file_path)
                queued_tasks.append(task)
                logger.info(f"Queued {os.path.basename(file_path)} for parallel processing (task: {task.id[:8]})")
            
            logger.info(f"Queued {len(queued_tasks)} files for parallel processing across 8 workers")
            
            # CLEANUP: Remove upload folder contents (files are now staged)
            logger.info("Cleaning up upload folder...")
            cleanup_uploads(case_id, upload_type)
            
            # Mark ingestion as completed (parallel tasks will update file records)
            update_ingestion_progress(
                progress_id,
                status='completed',
                current_step='parallel_processing',
                processed_files=len(file_records),
                completed_at=datetime.utcnow()
            )
            
            # Log completion
            log_action(
                action='file_ingestion_queued',
                resource_type='case',
                details={
                    'case_id': case_id,
                    'total_files': len(file_records),
                    'queued_tasks': len(queued_tasks),
                    'upload_type': upload_type
                },
                status='success'
            )
            
            # Return immediately - parallel tasks handle the rest
            return {
                'success': True,
                'total_files': len(file_records),
                'queued_for_processing': len(queued_tasks),
                'zip_containers_created': zip_containers_created,
                'duplicates_skipped': duplicates_skipped,
                'processing_errors': len(processing_errors),
                'errors': processing_errors[:10] if processing_errors else [],  # First 10 errors for display
                'message': 'Files queued for parallel processing'
            }
            
            # LEGACY SEQUENTIAL CODE BELOW - Disabled
            if False:
                indexed_count = 0
                failed_count = 0
            
                # Import parsers and utilities
            # Try EZ Tools parsers first (better data), fall back to Python parsers
            try:
                from parsers.eztools_lnk_parser import parse_lnk_file as parse_lnk_eztools, LECMD_AVAILABLE
                parse_lnk_file = parse_lnk_eztools if LECMD_AVAILABLE else None
            except:
                from parsers.lnk_parser import parse_lnk_file, LNK_AVAILABLE
                LECMD_AVAILABLE = False
            
            try:
                from parsers.eztools_evtx_parser import parse_evtx_file as parse_evtx_eztools, EVTXECMD_AVAILABLE
                if EVTXECMD_AVAILABLE:
                    parse_evtx_eztools_fn = parse_evtx_eztools
                else:
                    parse_evtx_eztools_fn = None
            except:
                EVTXECMD_AVAILABLE = False
            
            from parsers.evtx_parser import parse_evtx_file as parse_evtx_python, EVTX_AVAILABLE
            from parsers.ndjson_parser import parse_ndjson_file
            from parsers.firewall_csv_parser import parse_firewall_csv
            from parsers.prefetch_parser_dissect import parse_prefetch_file as parse_prefetch_dissect, DISSECT_AVAILABLE as PREFETCH_AVAILABLE
            from parsers.eztools_jumplist_parser import parse_jumplist_file, JLECMD_AVAILABLE
            from parsers.eztools_mft_parser import parse_mft_file as parse_mft_eztools, MFTECMD_AVAILABLE
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
                    # Use EZ Tools if available (better normalization), otherwise Python parsers
                    if file_ext == '.evtx':
                        # Try EvtxECmd first (453 normalization maps), fall back to Python
                        if EVTXECMD_AVAILABLE:
                            logger.info(f"Using EvtxECmd for {filename}")
                            events = list(parse_evtx_eztools_fn(file_path))
                        elif EVTX_AVAILABLE:
                            logger.info(f"Using Python EVTX parser for {filename}")
                            events = list(parse_evtx_python(file_path))
                        else:
                            raise ImportError("No EVTX parser available")
                        
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
                                source_file=filename,
                                source_system=source_system
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
                                source_file=filename,
                                source_system=source_system
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
                                source_file=filename,
                                source_system=source_system
                            )
                        
                        event_count = len(events)
                        parse_success = True
                    
                    elif file_ext == '.pf':
                        # Parse Prefetch files (dissect.util handles Win10/11 compression!)
                        if not PREFETCH_AVAILABLE:
                            raise ImportError("dissect.util not available for Prefetch parsing")
                        
                        events = list(parse_prefetch_dissect(file_path))
                        
                        # Extract computer name if available
                        if events:
                            source_system = normalize_event_computer(events[0])
                        
                        # Index to case_X_execution
                        execution_index = f'case_{case_id}_execution'
                        chunk_size = 100
                        for i in range(0, len(events), chunk_size):
                            chunk = events[i:i + chunk_size]
                            indexer.bulk_index(
                                index_name=execution_index,
                                events=iter(chunk),
                                chunk_size=chunk_size,
                                case_id=case_id,
                                source_file=filename,
                                source_system=source_system
                            )
                        
                        event_count = len(events)
                        parse_success = True
                    
                    elif file_ext == '.lnk':
                        # LNK Parser - Use EZ Tools LECmd (better data)
                        if LECMD_AVAILABLE and parse_lnk_file:
                            logger.info(f"Using LECmd for {filename}")
                            events = list(parse_lnk_file(file_path))
                        else:
                            logger.info(f"Using Python LNK parser for {filename}")
                            from parsers.lnk_parser import parse_lnk_file as parse_lnk_python
                            events = list(parse_lnk_python(file_path))
                        
                        if events:
                            source_system = events[0].get('machine_id') or normalize_event_computer(events[0])
                        
                        # Index to case_X_execution
                        execution_index = f'case_{case_id}_execution'
                        chunk_size = 100
                        for i in range(0, len(events), chunk_size):
                            chunk = events[i:i + chunk_size]
                            indexer.bulk_index(
                                index_name=execution_index,
                                events=iter(chunk),
                                chunk_size=chunk_size,
                                case_id=case_id,
                                source_file=filename,
                                source_system=source_system
                            )
                        
                        event_count = len(events)
                        parse_success = True
                    
                    elif filename.lower().endswith('destinations-ms'):
                        # JumpList Parser - EZ Tools JLECmd (NEW)
                        if not JLECMD_AVAILABLE:
                            logger.warning(f"JLECmd not available for {filename}")
                            continue
                        
                        logger.info(f"Using JLECmd for {filename}")
                        events = list(parse_jumplist_file(file_path))
                        
                        if events:
                            source_system = events[0].get('machine_id') or normalize_event_computer(events[0])
                        
                        # Index to case_X_execution
                        execution_index = f'case_{case_id}_execution'
                        chunk_size = 100
                        for i in range(0, len(events), chunk_size):
                            chunk = events[i:i + chunk_size]
                            indexer.bulk_index(
                                index_name=execution_index,
                                events=iter(chunk),
                                chunk_size=chunk_size,
                                case_id=case_id,
                                source_file=filename,
                                source_system=source_system
                            )
                        
                        event_count = len(events)
                        parse_success = True
                    
                    elif filename in ['$MFT', '$MFT.gz'] or filename.startswith('$MFT'):
                        # MFT Parser - EZ Tools MFTECmd (NEW)
                        if not MFTECMD_AVAILABLE:
                            logger.warning(f"MFTECmd not available for {filename}")
                            continue
                        
                        logger.info(f"Using MFTECmd for {filename} - processing filesystem timeline")
                        events = list(parse_mft_eztools(file_path))
                        
                        # Extract hostname from first event
                        if events:
                            source_system = events[0].get('computer') or normalize_event_computer(events[0])
                            if source_system:
                                logger.info(f"MFT hostname: {source_system}")
                        
                        # Index to case_X_filesystem (NEW index type)
                        filesystem_index = f'case_{case_id}_filesystem'
                        chunk_size = 500
                        for i in range(0, len(events), chunk_size):
                            chunk = events[i:i + chunk_size]
                            indexer.bulk_index(
                                index_name=filesystem_index,
                                events=iter(chunk),
                                chunk_size=chunk_size,
                                case_id=case_id,
                                source_file=filename,
                                source_system=source_system
                            )
                            if i % 50000 == 0 and i > 0:
                                logger.info(f"MFT progress: {i}/{len(events)} entries indexed")
                        
                        event_count = len(events)
                        parse_success = True
                    
                    elif 'history' in filename.lower() or 'places.sqlite' in filename.lower() or (file_ext in ['.sqlite', '.db'] and 'history' in filename.lower()):
                        # Parse Browser History (Chrome/Firefox)
                        from parsers.browser_history_parser import parse_browser_history_file
                        
                        events = list(parse_browser_history_file(file_path))
                        
                        # Extract computer name if available
                        if events:
                            source_system = normalize_event_computer(events[0])
                        
                        # Index to case_X_browser
                        browser_index = f'case_{case_id}_browser'
                        chunk_size = 500
                        for i in range(0, len(events), chunk_size):
                            chunk = events[i:i + chunk_size]
                            indexer.bulk_index(
                                index_name=browser_index,
                                events=iter(chunk),
                                chunk_size=chunk_size,
                                case_id=case_id,
                                source_file=filename,
                                source_system=source_system
                            )
                        
                        event_count = len(events)
                        parse_success = True
                    
                    elif 'webcache' in filename.lower() and file_ext in ['.dat', '.edb']:
                        # Parse WebCache ESE database
                        from parsers.webcache_parser import parse_webcache_file, ESE_AVAILABLE
                        
                        if not ESE_AVAILABLE:
                            raise ImportError("pyesedb library not available for WebCache parsing")
                        
                        events = list(parse_webcache_file(file_path))
                        
                        # Extract computer name if available
                        if events:
                            source_system = normalize_event_computer(events[0])
                        
                        # Index to case_X_browser
                        browser_index = f'case_{case_id}_browser'
                        chunk_size = 500
                        for i in range(0, len(events), chunk_size):
                            chunk = events[i:i + chunk_size]
                            indexer.bulk_index(
                                index_name=browser_index,
                                events=iter(chunk),
                                chunk_size=chunk_size,
                                case_id=case_id,
                                source_file=filename,
                                source_system=source_system
                            )
                        
                        event_count = len(events)
                        parse_success = True
                    
                    elif 'srudb' in filename.lower() and file_ext == '.dat':
                        # Parse SRUM database
                        from parsers.srum_parser import parse_srum_file, ESE_AVAILABLE
                        
                        if not ESE_AVAILABLE:
                            raise ImportError("pyesedb library not available for SRUM parsing")
                        
                        events = list(parse_srum_file(file_path))
                        
                        # Extract computer name if available
                        if events:
                            source_system = normalize_event_computer(events[0])
                        
                        # Index to case_X_network
                        network_index = f'case_{case_id}_network'
                        chunk_size = 500
                        for i in range(0, len(events), chunk_size):
                            chunk = events[i:i + chunk_size]
                            indexer.bulk_index(
                                index_name=network_index,
                                events=iter(chunk),
                                chunk_size=chunk_size,
                                case_id=case_id,
                                source_file=filename,
                                source_system=source_system
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
                    
                except OSError as e:
                    # OSError typically means file can't be opened (corrupt, locked, etc.)
                    logger.warning(f"Unable to parse {filename}: {e}")
                    
                    # Update existing record with UnableToParse status
                    file_id = file_record.id
                    file_record = CaseFile.query.get(file_id)
                    file_record.status = 'UnableToParse'
                    file_record.error_message = str(e)[:500]  # Truncate long error messages
                    db.session.commit()
                    
                    failed_count += 1
                    processing_errors.append({
                        'file': filename,
                        'step': 'parsing',
                        'error': 'Unable to open/read file (may be corrupt or in-use)'
                    })
                    
                except Exception as e:
                    # Other exceptions are parsing errors
                    logger.error(f"Error processing {filename}: {e}", exc_info=True)
                    
                    # Update existing record with error (fetch fresh from DB)
                    file_id = file_record.id
                    file_record = CaseFile.query.get(file_id)
                    file_record.status = 'ParseFail'
                    file_record.error_message = str(e)
                    db.session.commit()
                    
                    failed_count += 1
                    processing_errors.append({
                        'file': filename,
                        'step': 'parsing',
                        'error': str(e)
                    })
            
            # STEP 5: Move indexed files to storage (compress and relocate)
            update_ingestion_progress(progress_id, current_step='storage')
            
            import gzip
            import shutil
            storage_path = f'/opt/casescope/storage/case_{case_id}'
            os.makedirs(storage_path, exist_ok=True)
            
            for idx, file_data in enumerate(file_records):
                file_record = file_data['record']
                file_info = file_data['info']
                file_path = file_info['path']
                
                # Only move successfully indexed files
                if file_record.status == 'Indexed' and os.path.exists(file_path):
                    try:
                        filename = os.path.basename(file_path)
                        
                        # Compress with GZIP
                        compressed_filename = filename + '.gz'
                        compressed_path = os.path.join(storage_path, compressed_filename)
                        
                        with open(file_path, 'rb') as f_in:
                            with gzip.open(compressed_path, 'wb', compresslevel=6) as f_out:
                                shutil.copyfileobj(f_in, f_out)
                        
                        # Update file record with new path
                        file_record.file_path = compressed_path
                        db.session.commit()
                        
                        # Delete original from staging
                        os.remove(file_path)
                        
                        logger.info(f"Moved to storage: {filename} → {compressed_filename}")
                        
                    except Exception as e:
                        logger.error(f"Error moving {filename} to storage: {e}")
            
            # STEP 6: Cleanup staging and uploads folders
            update_ingestion_progress(progress_id, current_step='cleanup')
            cleanup_staging(case_id)
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

